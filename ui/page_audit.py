"""
ui/page_audit.py · LOZARUS KIT TOOL

Página ESCANEO DE VECTORES: auditoría de puertos en escucha (motor real del plugin 04_puertos) y
diagnóstico completo con todos los plugins de modulos/, ambos en segundo plano y en solo lectura.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from typing import TYPE_CHECKING, Optional, Tuple

import subprocess

import psutil
from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QButtonGroup, QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QProgressBar, QPushButton,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from modulos._base import ADMIN_NAME, CRITICAL, INFO, IS_WINDOWS, PASS, SKIP, WARNING, AuditContext, Report
from modulos._inicio import RUN_KEYS
from modulos._utilidades import run_cmd

from ui.theme import COLORS, SEVERITY_COLORS, SEVERITY_ORDER, badge_qss
from ui.widgets import (BentoCard, Page, _emit_event, frozen, icon, make_card, make_table, repolish,
                        set_busy, stat_chip, with_icon)
from ui.chrome import Toast
from ui.dialogs import ConfirmDialog
from ui.page_monitor import PROTECTED_PROCS, _control_process, _same_process

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

# Orden de la telemetría de puertos: lo peligroso arriba, lo solo-local al final.
PORT_RISK_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2, PASS: 3}

# Filtros rápidos de la telemetría: (clave, texto del chip).
FILTERS = (("all", "TODOS"), ("critical", "CRITICAL"), ("warning", "WARNING"), ("exposed", "PUERTOS EXPUESTOS"))

# Inspector de puertos: por qué un puerto en escucha es un vector de riesgo (texto defensivo).
RISK_EXPOSED = ("Un puerto expuesto es una puerta abierta: cualquier equipo de la red (o de Internet, si el router "
                "lo reenvía) puede conectarse, probar contraseñas por fuerza bruta o explotar una vulnerabilidad "
                "del proceso que lo atiende para ejecutar código con sus privilegios. Cada servicio expuesto que "
                "no necesitas amplía la superficie de ataque: ciérralo o bloquéalo en el firewall.")
RISK_LOCAL = ("Solo escucha en loopback: otros equipos no lo alcanzan, pero un programa malicioso que ya corra "
              "en este equipo sí puede usarlo para escalar privilegios o moverse entre procesos.")

# Inspector de hallazgos: qué protege cada directiva de Windows y por qué conviene endurecerla.
DEFENSE = {
    "pslog": "El registro de bloques de script (evento 4104) guarda el código PowerShell que se ejecuta, aunque "
             "llegue ofuscado o solo exista en memoria. Es la principal evidencia forense frente al malware sin "
             "fichero y a los ataques «living off the land».",
    "run": "Las claves Run/RunOnce lanzan programas en cada inicio de sesión: es la técnica de persistencia más "
           "usada por el malware (MITRE T1547.001). Eliminar la entrada no borra el ejecutable, y su valor queda "
           "guardado antes en la Caja Negra para poder restaurarlo.",
    "firewall": "El Firewall de Windows descarta las conexiones entrantes no solicitadas. Sin él, cualquier "
                "servicio en escucha queda expuesto a gusanos, fuerza bruta y movimiento lateral desde la red.",
    "hvci": "La Integridad de memoria (HVCI) usa el hipervisor para que en el núcleo solo se ejecute código "
            "firmado y verificado: bloquea rootkits y drivers vulnerables o sin firma (BYOVD). Requiere reiniciar.",
    "admin": f"Esta comprobación no pudo ejecutarse sin privilegios de {ADMIN_NAME}: un hallazgo omitido es un "
             "punto ciego. Relanza Lozarus elevado y repite el diagnóstico.",
}
PS_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
HVCI_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
FIREWALL_ON = ["netsh", "advfirewall", "set", "allprofiles", "state", "on"]


def _hive(name: str):
    import winreg  # solo Windows: se importa al aplicar la acción
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[name]


def set_dword(subkey: str, name: str, value: int = 1) -> dict:
    """Escribe un DWORD en HKLM (vista de 64 bits), creando la clave si no existe."""
    import winreg
    with winreg.CreateKeyEx(_hive("HKLM"), subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
    return {"registry": f"HKLM\\{subkey}", "value": name, "data": value}


def read_run_value(hive: str, subkey: str, name: str) -> dict:
    """Copia de seguridad de una entrada de arranque (se guarda en la Caja Negra antes de borrarla)."""
    import winreg
    with winreg.OpenKey(_hive(hive), subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        data, kind = winreg.QueryValueEx(key, name)
    return {"registry": f"{hive}\\{subkey}", "value": name, "data": str(data), "type": kind}


def delete_run_value(hive: str, subkey: str, name: str) -> dict:
    import winreg
    with winreg.OpenKey(_hive(hive), subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
        winreg.DeleteValue(key, name)
    return {"registry": f"{hive}\\{subkey}", "deleted": name}


def netsh(cmd: list) -> dict:
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        raise OSError((out or err).strip() or f"netsh devolvió {rc}")
    return {"command": subprocess.list2cmdline(cmd)}


def finding_fix(f) -> Optional[dict]:
    """
    Acción de endurecimiento para un hallazgo: kind, label, icon, what (lo que se aplicará, exacto),
    admin, group (acciones idénticas se ejecutan una vez), fn (segundo plano), backup y how.
    """
    if f.severity is SKIP:
        needs = ADMIN_NAME in f.detail or "denegado" in f.detail.lower()
        return {"kind": "admin", "label": "Relanzar como Administrador", "icon": "fa5s.user-shield"} if needs else None
    if f.severity not in (CRITICAL, WARNING):
        return None
    if f.check == "check_powershell_logging":
        return {"kind": "pslog", "label": "Activar Registro PowerShell", "icon": "fa5s.terminal", "admin": True,
                "what": f"HKLM\\{PS_KEY}\\EnableScriptBlockLogging = 1 (DWORD)", "group": "pslog",
                "fn": lambda: set_dword(PS_KEY, "EnableScriptBlockLogging"),
                "how": "registro de bloques de script de PowerShell activado"}
    if f.key.startswith("persist:run:"):
        origin, _, name = f.key[len("persist:run:"):].partition(":")
        hive, subkey = next(((h, k) for label, h, k in RUN_KEYS if label == origin), (None, None))
        if hive is None or not name:
            return None
        return {"kind": "run", "label": "Eliminar Entrada de Arranque", "icon": "fa5s.trash-alt",
                "admin": hive == "HKLM", "what": f"{hive}\\{subkey}\\{name} (se elimina el valor)",
                "group": f.key, "backup": lambda: read_run_value(hive, subkey, name),
                "fn": lambda: delete_run_value(hive, subkey, name), "how": f"entrada de arranque «{name}» eliminada"}
    if f.key.startswith("firewall:") and "desactivado" in f.title.lower():
        return {"kind": "firewall", "label": "Activar Firewall", "icon": "fa5s.shield-alt", "admin": True,
                "what": subprocess.list2cmdline(FIREWALL_ON), "group": "firewall",
                "fn": lambda: netsh(FIREWALL_ON), "how": "Firewall de Windows activado en todos los perfiles"}
    if f.key in ("hardening:hvci", "persist:drivers:unsigned"):
        return {"kind": "hvci", "label": "Activar Integridad de Memoria (HVCI)", "icon": "fa5s.microchip",
                "admin": True, "what": f"HKLM\\{HVCI_KEY}\\Enabled = 1 (DWORD)", "group": "hvci",
                "fn": lambda: set_dword(HVCI_KEY, "Enabled"),
                "how": "Integridad de memoria (HVCI) activada (efectiva tras reiniciar)"}
    return None


def ports_backend(modules) -> Optional[object]:
    """Motor REAL del plugin de puertos (modulos/04_puertos.py) tal como lo cargó el cargador."""
    for cls in modules:
        if getattr(cls, "key", "") == "puertos":
            return sys.modules.get(cls.__module__)
    try:
        return importlib.import_module("modulos.04_puertos")
    except Exception:  # noqa: BLE001  (plugin ausente o roto: la auditoría de puertos se desactiva)
        return None


def audit_ports(backend) -> list:
    """
    Inventario de puertos en escucha (psutil; netstat/ss como alternativa) clasificado con la
    tabla RISKY_PORTS del plugin: expuesto + servicio de riesgo → su severidad; expuesto sin
    riesgo conocido → INFO (revisar); solo loopback → PASS. Solo lectura.
    """
    rows = []
    for sock in backend.get_listening_sockets():
        rule = backend.RISKY_PORTS.get(sock.port)
        risky = rule is not None and sock.proto in rule.protos
        service = rule.service if rule else backend.COMMON_SERVICES.get(sock.port, "—")
        if not sock.exposed:
            severity, why = PASS, "Solo accesible desde este equipo (loopback)."
        elif risky:
            severity, why = rule.severity, f"{rule.reason}\n➜ {rule.advice}"
        else:
            severity, why = INFO, "Escucha en la red. Si no reconoces el proceso, revisa si lo necesitas."
        rows.append({"severity": severity, "proto": sock.proto, "ip": sock.ip, "port": sock.port,
                     "service": service, "process": sock.process, "pid": sock.pid,
                     "exposed": sock.exposed, "why": why})
    rows.sort(key=lambda r: (PORT_RISK_ORDER.get(r["severity"], 9), r["port"], r["proto"]))
    return rows


# --- Utilidades rápidas (uso técnico en equipos ajenos / modo pendrive) --------------------------
REQUIREMENTS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "requirements.txt")
NETWORK_RESCUE_STEPS = (
    ("Caché DNS vaciada", ["ipconfig", "/flushdns"]),
    ("Caché ARP vaciada", ["arp", "-d", "*"]),
    ("Winsock restablecido (efectivo tras reiniciar)", ["netsh", "winsock", "reset"]),
)


def install_requirements(path: str = REQUIREMENTS_PATH) -> dict:
    """`python -m pip install -r requirements.txt` sin shell. Devuelve {ok, summary}. No lanza."""
    if getattr(sys, "frozen", False):
        return {"ok": False, "summary": "Ejecutable empaquetado: las dependencias ya van incluidas."}
    if not os.path.isfile(path):
        return {"ok": False, "summary": f"No se encontró {os.path.basename(path)}."}
    try:
        code, out, err = run_cmd([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                                  "-r", path], timeout=600)
    except Exception as exc:  # noqa: BLE001  (pip ausente, sin red, tiempo agotado…)
        return {"ok": False, "summary": f"{type(exc).__name__}: {exc}"}
    lines = [ln.strip() for ln in (out + "\n" + err).splitlines() if ln.strip()]
    installed = next((ln for ln in lines if ln.startswith("Successfully installed")), "")
    if code == 0:
        return {"ok": True, "summary": installed or "Todas las dependencias ya estaban instaladas."}
    return {"ok": False, "summary": (lines[-1] if lines else f"pip terminó con código {code}")[:300]}


def network_rescue() -> list:
    """Ejecuta los pasos de rescate de red uno a uno (un fallo no detiene los demás). [(etiqueta, ok, msg)]."""
    results = []
    for label, cmd in NETWORK_RESCUE_STEPS:
        try:
            code, out, err = run_cmd(cmd, timeout=60)
            msg = (err or out).strip().splitlines()[-1:] if code else []
            results.append((label, code == 0, msg[0] if msg else ""))
        except Exception as exc:  # noqa: BLE001
            results.append((label, False, f"{type(exc).__name__}: {exc}"))
    return results


class AuditWorker(QThread):
    """
    Ejecuta los plugins de auditoría (solo lectura) en segundo plano y publica el progreso y cada
    hallazgo por señales, que Qt entrega al hilo de la interfaz de forma segura. Reutiliza el mismo
    motor que auditor.py (Report + AuditContext + AuditModule).
    """
    progress = Signal(int, int, str)   # (índice, total, título del módulo)
    found = Signal(object)             # un Finding
    report_ready = Signal(object)      # el Report final
    failed = Signal(str)

    def __init__(self, modules, admin: bool):
        super().__init__()
        self.modules = list(modules)
        self.admin = admin

    def run(self) -> None:
        worker = self

        class Bridge:  # «consola» del motor: solo necesita check_started() y finding()
            def check_started(self, module_title, label):
                pass

            def finding(self, finding):
                worker.found.emit(finding)

        try:
            report = Report(Bridge())
            ctx = AuditContext(args=argparse.Namespace(escanear=None, timeout=0.5),
                               report=report, is_admin=self.admin)
            for index, module_cls in enumerate(self.modules, 1):
                self.progress.emit(index, len(self.modules), module_cls.title)
                module_cls(ctx).run()  # AuditModule.run convierte los errores en [SKIP]
            self.report_ready.emit(report)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class AuditPage(Page):
    """
    Escáner de vectores: métricas en BentoCard, panel de control con la Auditoría de Puertos como
    acción principal y telemetría debajo; el diagnóstico completo (todos los plugins) en su pestaña.
    """

    def __init__(self, app: "MainWindow"):
        super().__init__("Escaneo de Vectores",
                         f"Auditoría de puertos en escucha y diagnóstico completo con los {len(app.modules)} "
                         "plugins de modulos/. Todo en solo lectura.",
                         "fa5s.shield-alt")
        self.app = app
        self.findings = []
        self.worker = None
        self.last_result: Optional[Tuple[int, int, int]] = None  # (puntuación, CRITICAL, WARNING)
        self._ports_backend = ports_backend(app.modules)
        self._port_rows: Optional[list] = None
        self._ports_busy = False

        # --- Métricas (BentoCard en el cuerpo de la página: aura y rim light propios) -----------
        metrics = QHBoxLayout()
        metrics.setSpacing(16)
        self._metric_cards = [
            BentoCard("fa5s.plug", "Puertos en escucha", "Sockets TCP/UDP abiertos en este equipo.",
                      self._status_listening, lambda: self.tabs.setCurrentIndex(0)),
            BentoCard("fa5s.globe", "Expuestos a la red", "Escuchan fuera de 127.0.0.1 / ::1.",
                      self._status_exposed, lambda: self.tabs.setCurrentIndex(0)),
            BentoCard("fa5s.exclamation-triangle", "Servicios de riesgo",
                      "Protocolos inseguros o muy atacados expuestos.", self._status_risky,
                      lambda: self.tabs.setCurrentIndex(0)),
            BentoCard("fa5s.shield-alt", "Puntuación del sistema", "Del último diagnóstico completo.",
                      self._status_score, lambda: self.tabs.setCurrentIndex(1)),
        ]
        for card in self._metric_cards:
            metrics.addWidget(card, 1)
        self.root.addLayout(metrics)

        # --- Panel de control -------------------------------------------------------------------
        panel, lay = make_card("Panel de control",
                               "La Auditoría de Puertos inventaría lo que escucha en este equipo y lo cruza "
                               "con la lista de servicios de riesgo. El diagnóstico completo ejecuta todos "
                               "los plugins de auditoría.")
        # Tres acciones principales, cada una con su contador en vivo (píldora a la derecha).
        actions = QHBoxLayout()
        actions.setSpacing(12)
        self.run_btn, self._diag_badge = self._action(
            actions, f"Diagnóstico Completo ({len(app.modules)} Módulos)", "fa5s.shield-alt", "Primary",
            "Hallazgos del último diagnóstico completo")
        self.run_btn.clicked.connect(self.start)
        self.ports_btn, self._ports_badge = self._action(
            actions, "Auditoría de Puertos en Vivo", "fa5s.satellite-dish", "Primary",
            "Puertos expuestos a la red en la última auditoría")
        self.ports_btn.clicked.connect(self.audit_ports)
        self.fix_btn, self._fix_badge = self._action(
            actions, "Mitigar Riesgos Detectados", "fa5s.magic", "Danger",
            "Riesgos WARNING / CRITICAL pendientes (hallazgos + puertos de riesgo)")
        self.fix_btn.setEnabled(False)
        self.fix_btn.clicked.connect(self.mitigate_all)
        self._fixed = {}  # id(Finding) -> cómo se mitigó
        self._fixing = False
        actions.addStretch(1)
        lay.addLayout(actions)
        self.status = QLabel("Listo para analizar")
        self.status.setObjectName("StatusMuted")
        lay.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        lay.addWidget(self.progress)
        tools = QHBoxLayout()
        tools.setSpacing(8)
        tcap = QLabel("UTILIDADES")
        tcap.setObjectName("ChipCap")
        self.deps_btn = QPushButton("Verificar / Instalar Dependencias")
        self.deps_btn.setObjectName("Mini")
        self.deps_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        with_icon(self.deps_btn, "fa5s.box-open", COLORS["muted"], 13)
        self.deps_btn.setToolTip("Ejecuta «pip install -r requirements.txt» con este mismo Python (necesita internet).")
        self.deps_btn.clicked.connect(self.install_dependencies)
        self.netfix_btn = QPushButton("Rescate de Red (Flush DNS / Winsock)")
        self.netfix_btn.setObjectName("Mini")
        self.netfix_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        with_icon(self.netfix_btn, "fa5s.first-aid", COLORS["muted"], 13)
        self.netfix_btn.setToolTip("ipconfig /flushdns · arp -d * · netsh winsock reset (requiere Administrador).")
        self.netfix_btn.clicked.connect(self.rescue_network)
        if not IS_WINDOWS:
            self.netfix_btn.setEnabled(False)
            self.netfix_btn.setToolTip("Solo disponible en Windows.")
        for w in (tcap, self.deps_btn, self.netfix_btn):
            tools.addWidget(w)
        tools.addStretch(1)
        lay.addLayout(tools)
        if self._ports_backend is None:
            self.ports_btn.setEnabled(False)
            self.ports_btn.setToolTip("El plugin de puertos (modulos/04_puertos.py) no está disponible.")
        self.root.addWidget(panel)

        # --- Filtros rápidos por severidad (sobre la telemetría) ------------------------------------
        filters = QHBoxLayout()
        filters.setSpacing(8)
        cap = QLabel("FILTRAR")
        cap.setObjectName("ChipCap")
        filters.addWidget(cap)
        self._filter = "all"
        self._filter_group = QButtonGroup(self)
        self._filter_group.setExclusive(True)
        self._filter_btns = {}
        for key, text in FILTERS:
            chip = QPushButton(text)
            chip.setObjectName("Chiplet")
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.clicked.connect(lambda _=False, k=key: self._set_filter(k))
            self._filter_group.addButton(chip)
            self._filter_btns[key] = chip
            filters.addWidget(chip)
        self._filter_btns["all"].setChecked(True)
        filters.addStretch(1)
        self.root.addLayout(filters)

        # --- Telemetría -------------------------------------------------------------------------
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_ports_tab(), icon("fa5s.satellite-dish"), "Telemetría de puertos")
        self.tabs.addTab(self._build_diag_tab(), icon("fa5s.shield-alt"), "Diagnóstico completo")
        self.root.addWidget(self.tabs, 1)
        self._update_counters()

    @staticmethod
    def _action(row, text: str, icon_name: str, kind: str, badge_tip: str):
        """Botón de acción principal con su contador (píldora) pegado a la derecha."""
        button = QPushButton(text)
        button.setObjectName(kind)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        with_icon(button, icon_name, COLORS["danger"] if kind == "Danger" else None)
        badge = QLabel("—")
        badge.setToolTip(badge_tip)
        badge.setStyleSheet(badge_qss(COLORS["faint"], 11))
        badge.setProperty("lz_count", None)
        row.addWidget(button)
        row.addWidget(badge)
        row.addSpacing(10)
        return button, badge

    @staticmethod
    def _set_badge(badge: QLabel, count: Optional[int], color: str) -> None:
        """Actualiza el contador; solo re-estiliza si cambia (cada setStyleSheet fuerza un re-polish)."""
        if badge.property("lz_count") == (count, color):
            return
        badge.setProperty("lz_count", (count, color))
        badge.setText("—" if count is None else str(count))
        badge.setStyleSheet(badge_qss(color, 11))

    # --- Contadores y filtros --------------------------------------------------------------------
    def _counts(self) -> dict:
        ports = self._port_rows or []
        ports = [r for r in ports if not r.get("mitigated")]
        live = [f for f in self.findings if id(f) not in self._fixed]
        crit = sum(1 for r in ports if r["severity"] is CRITICAL) + sum(1 for f in live if f.severity is CRITICAL)
        warn = sum(1 for r in ports if r["severity"] is WARNING) + sum(1 for f in live if f.severity is WARNING)
        return {"all": len(self._port_rows or []) + len(self.findings), "critical": crit, "warning": warn,
                "exposed": sum(1 for r in ports if r["exposed"])}

    def _update_counters(self) -> None:
        counts = self._counts()
        for key, text in FILTERS:
            label = f"{text} · {counts[key]}"
            if self._filter_btns[key].text() != label:
                self._filter_btns[key].setText(label)
        diag = len(self.findings) if (self.findings or self.last_result is not None) else None
        self._set_badge(self._diag_badge, diag, COLORS["text"] if diag else COLORS["faint"])
        exposed = counts["exposed"] if self._port_rows is not None else None
        self._set_badge(self._ports_badge, exposed, COLORS["warn"] if exposed else COLORS["faint"])
        risks = counts["critical"] + counts["warning"]
        known = self._port_rows is not None or self.findings or self.last_result is not None
        self._set_badge(self._fix_badge, risks if known else None,
                        COLORS["danger"] if counts["critical"] else COLORS["warn"] if risks else COLORS["faint"])
        pending = len(self._pending_fixes())
        self.fix_btn.setEnabled(bool(pending) and not self._fixing)
        self.fix_btn.setToolTip(f"{pending} mitigaciones automáticas disponibles" if pending
                                else "No hay riesgos WARNING / CRITICAL con remediación automática.")

    def _set_filter(self, key: str) -> None:
        self._filter = key
        if key == "exposed":
            self.tabs.setCurrentIndex(0)  # el filtro de puertos expuestos vive en la telemetría de puertos
        self._apply_filter()

    def _port_visible(self, row: dict) -> bool:
        f = self._filter
        return (f == "all" or (f == "critical" and row["severity"] is CRITICAL)
                or (f == "warning" and row["severity"] is WARNING) or (f == "exposed" and row["exposed"]))

    def _finding_visible(self, finding) -> bool:
        f = self._filter
        return (f == "all" or (f == "critical" and finding.severity is CRITICAL)
                or (f == "warning" and finding.severity is WARNING)
                or (f == "exposed" and finding.module == "puertos"))

    def _apply_filter(self) -> None:
        """Oculta/muestra filas sin rehacer las tablas (setRowHidden: sin re-render completo)."""
        for r, row in enumerate(self._port_rows or []):
            self.port_table.setRowHidden(r, not self._port_visible(row))
        for r, finding in enumerate(self.findings):
            self.table.setRowHidden(r, not self._finding_visible(finding))

    def _build_ports_tab(self) -> QWidget:
        host = QWidget()
        host.setObjectName("Content")
        lay = QVBoxLayout(host)
        lay.setContentsMargins(0, 10, 0, 0)
        lay.setSpacing(8)
        self.port_table = make_table(["", "Riesgo", "Proto", "Dirección local", "Puerto", "Servicio",
                                      "Proceso", "PID"], widths=[34, 96, 64, 170, 74, 150, 190],
                                     empty="Pulsa «Lanzar Auditoría de Puertos» para inventariar los puertos "
                                           "en escucha de este equipo.", empty_icon="fa5s.satellite-dish")
        self.port_table.setMinimumHeight(260)
        self.port_table.itemSelectionChanged.connect(self._show_port_detail)
        self.port_detail = QLabel("Selecciona un puerto para ver por qué se clasifica así y qué hacer.")
        self.port_detail.setObjectName("CardText")
        self.port_detail.setWordWrap(True)
        self.port_detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.port_table, 1)
        lay.addWidget(self._build_port_inspector())
        return host

    @staticmethod
    def _inspector(captions, left, right) -> QFrame:
        """Tarjeta inferior de dos columnas (rim light de #Card); oculta hasta seleccionar una fila."""
        card = QFrame()
        card.setObjectName("Card")
        row = QHBoxLayout(card)
        row.setContentsMargins(16, 12, 16, 12)
        row.setSpacing(18)
        for caption, widgets, stretch in zip(captions, (left, right), (3, 2)):
            col = QVBoxLayout()
            col.setSpacing(8)
            cap = QLabel(caption)
            cap.setObjectName("ChipCap")
            col.addWidget(cap)
            for widget in widgets:
                col.addWidget(widget)
            col.addStretch(1)
            row.addLayout(col, stretch)
        card.setVisible(False)
        return card

    def _build_port_inspector(self) -> QFrame:
        """Inspector del puerto seleccionado: explicación defensiva (izq.) y acciones reales (der.)."""
        self.block_btn = QPushButton("Bloquear Puerto en Firewall")
        self.kill_btn = QPushButton("Finalizar Proceso Propietario")
        for button, icon_name, slot in ((self.block_btn, "fa5s.ban", self._block_port),
                                        (self.kill_btn, "fa5s.times-circle", self._kill_owner)):
            button.setObjectName("Danger")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            with_icon(button, icon_name, COLORS["danger"])
            button.clicked.connect(slot)
        self.inspector = self._inspector(("POR QUÉ ES UN VECTOR DE RIESGO", "ACCIONES"), [self.port_detail],
                                         [self.block_btn, self.kill_btn])
        return self.inspector

    def _build_diag_tab(self) -> QWidget:
        host = QWidget()
        host.setObjectName("Content")
        lay = QVBoxLayout(host)
        lay.setContentsMargins(0, 10, 0, 0)
        lay.setSpacing(10)
        chips = QHBoxLayout()
        chips.setSpacing(10)
        self.counts = {}
        for sev in SEVERITY_ORDER:
            chip, val = stat_chip(sev.value)
            val.setText("0")
            val.setStyleSheet(f"color: {SEVERITY_COLORS[sev]};")
            self.counts[sev] = val
            chips.addWidget(chip)
        chip, self.score = stat_chip("PUNTUACIÓN")
        chips.addWidget(chip)
        lay.addLayout(chips)
        self.table = make_table(["Nivel", "Módulo", "Hallazgo"], widths=[100, 220],
                                empty="Pulsa «Diagnóstico completo» para auditar los vectores de "
                                      "este equipo (solo lectura).", empty_icon="fa5s.shield-alt")
        self.table.setMinimumHeight(220)
        self.table.itemSelectionChanged.connect(self._show_detail)
        lay.addWidget(self.table, 2)
        self.detail = QPlainTextEdit()
        self.detail.setObjectName("Detail")
        self.detail.setReadOnly(True)
        self.detail.setFixedHeight(150)
        self.harden_btn = QPushButton()
        self.harden_btn.setObjectName("Danger")
        self.harden_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.harden_btn.clicked.connect(self._harden_selected)
        self.harden_note = QLabel()
        self.harden_note.setObjectName("CardText")
        self.harden_note.setWordWrap(True)
        self.finding_inspector = self._inspector(("INTELIGENCIA DEFENSIVA", "ACCIONES DE ENDURECIMIENTO"),
                                                 [self.detail], [self.harden_btn, self.harden_note])
        lay.addWidget(self.finding_inspector)
        return host

    # --- Métricas (status_fn de las BentoCard) ----------------------------------------------------
    def _status_listening(self):
        rows = self._port_rows
        if rows is None:
            return (False, "Sin auditar todavía", "—")
        tcp = sum(1 for r in rows if r["proto"] == "TCP")
        return (True, f"TCP {tcp} · UDP {len(rows) - tcp}", str(len(rows)))

    def _status_exposed(self):
        rows = self._port_rows
        if rows is None:
            return (False, "Sin auditar todavía", "—")
        exposed = sum(1 for r in rows if r["exposed"])
        return (COLORS["warn"] if exposed else COLORS["ok"],
                "Accesibles desde otros equipos" if exposed else "Nada escucha fuera de este equipo",
                str(exposed))

    def _status_risky(self):
        rows = self._port_rows
        if rows is None:
            return (False, "Sin auditar todavía", "—")
        rows = [r for r in rows if not r.get("mitigated")]
        crit = sum(1 for r in rows if r["severity"] is CRITICAL)
        warn = sum(1 for r in rows if r["severity"] is WARNING)
        color = COLORS["danger"] if crit else COLORS["warn"] if warn else COLORS["ok"]
        return (color, f"{crit} críticos · {warn} avisos" if crit + warn else "Ninguno expuesto",
                str(crit + warn))

    def _status_score(self):
        if self.last_result is None:
            return (False, "Sin diagnóstico completo aún", "—")
        score, crit, warn = self.last_result
        color = COLORS["ok"] if score >= 80 else COLORS["warn"] if score >= 60 else COLORS["danger"]
        return (color, f"{crit} CRITICAL · {warn} WARNING", f"{score}/100")

    def _refresh_metrics(self) -> None:
        for card in self._metric_cards:
            card.refresh()

    # --- Auditoría de puertos -------------------------------------------------------------------
    def audit_ports(self) -> None:
        if self._ports_busy or self._ports_backend is None:
            return
        self._ports_busy = True
        set_busy(self.ports_btn, True, "Auditando puertos…")
        self.status.setText("Inventariando puertos en escucha…")
        self.status.setObjectName("StatusMuted")
        repolish(self.status)
        self.tabs.setCurrentIndex(0)
        self.app.log_tactical("Auditoría de puertos iniciada (solo lectura)")
        backend = self._ports_backend
        self.app.run_task(lambda emit: audit_ports(backend), self._ports_done)

    def _ports_done(self, ok: bool, rows) -> None:
        self._ports_busy = False
        set_busy(self.ports_btn, False)
        if not ok or not isinstance(rows, list):
            self.status.setText(f"Auditoría de puertos: {rows}")
            self.app.console.log("x", f"Auditoría de puertos: {rows}")
            Toast.notify(self.app, "x", "Auditoría de puertos", f"No se pudo completar: {rows}",
                         "fa5s.satellite-dish")
            return
        self._port_rows = rows
        table = self.port_table
        if not rows:
            table.set_empty_text("No hay ningún puerto en escucha en este equipo.", "fa5s.check-circle")
        with frozen(table):
            table.setRowCount(len(rows))
            for r, row in enumerate(rows):
                color = QColor(SEVERITY_COLORS[row["severity"]])
                dot = QTableWidgetItem("●")
                dot.setForeground(color)
                dot.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                risk = QTableWidgetItem(row["severity"].value)
                risk.setForeground(color)
                cells = [dot, risk] + [QTableWidgetItem(v) for v in (
                    row["proto"], row["ip"], str(row["port"]), row["service"], row["process"],
                    str(row["pid"]) if row["pid"] is not None else "—")]
                for c, item in enumerate(cells):
                    table.setItem(r, c, item)
        crit = sum(1 for r in rows if r["severity"] is CRITICAL)
        warn = sum(1 for r in rows if r["severity"] is WARNING)
        exposed = sum(1 for r in rows if r["exposed"])
        text = (f"{len(rows)} puertos en escucha · {exposed} expuestos · "
                f"{crit} críticos · {warn} avisos")
        self.status.setText(f"Auditoría de puertos: {text}")
        self.status.setObjectName("StatusWarn" if crit + warn else "StatusOk")
        repolish(self.status)
        self._refresh_metrics()
        self._apply_filter()
        self._update_counters()
        self.app.console.log("!" if crit + warn else "*", f"Auditoría de puertos: {text}")
        _emit_event(self.app, source="vectores:puertos", event_type="audit.ports",
                    payload={"listening": len(rows), "exposed": exposed, "critical": crit, "warning": warn})
        Toast.notify(self.app, "x" if crit else "!" if warn else "*", "Auditoría de puertos", text,
                     "fa5s.satellite-dish")

    def _selected_port(self) -> Optional[dict]:
        r = self.port_table.currentRow()
        return self._port_rows[r] if self._port_rows and 0 <= r < len(self._port_rows) else None

    @staticmethod
    def _protected(row: dict) -> bool:
        """Misma regla que el Monitor en Vivo: nunca finalizar procesos críticos de Windows ni Lozarus."""
        return row["pid"] in (0, 4, os.getpid()) or (row["process"] or "").lower() in PROTECTED_PROCS

    def _show_port_detail(self) -> None:
        row = self._selected_port()
        self.inspector.setVisible(row is not None)
        if row is None:
            return
        where = "expuesto en la red" if row["exposed"] else "solo local"
        state = row["severity"].value if not row.get("mitigated") else "MITIGADO"
        text = (f"{state} · {row['proto']} {row['ip']}:{row['port']} ({row['service']}) · {row['process']} · "
                f"{where}\n{row['why']}\n\n{RISK_EXPOSED if row['exposed'] else RISK_LOCAL}")
        if row.get("mitigated"):
            text += f"\n\n✔ Mitigado: {row['mitigated']}."
        self.port_detail.setText(text)
        done = bool(row.get("mitigated"))
        self.block_btn.setEnabled(not done and not self._fixing)
        killable = row["pid"] is not None and not self._protected(row)
        self.kill_btn.setEnabled(killable and not done)
        self.kill_btn.setToolTip("" if killable else "Proceso protegido del sistema o PID desconocido.")

    @staticmethod
    def _port_fix(row: dict) -> dict:
        """Regla de entrada REAL en el Firewall de Windows (netsh advfirewall) para un puerto."""
        rule = f"Lozarus - Bloqueo {row['proto']} {row['port']}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule}", "dir=in", "action=block",
               f"protocol={row['proto']}", f"localport={row['port']}"]
        return {"kind": "port", "label": "Bloquear Puerto en Firewall", "admin": True,
                "what": subprocess.list2cmdline(cmd), "group": f"port:{row['proto']}:{row['port']}",
                "fn": lambda: netsh(cmd), "how": f"bloqueado en el firewall (regla «{rule}»)"}

    def _block_port(self) -> None:
        row = self._selected_port()
        if row is not None and not row.get("mitigated"):
            self._run_fixes([(row, self._port_fix(row))])

    def _pending_fixes(self) -> list:
        """(objetivo, acción) pendientes: puertos de riesgo expuestos y hallazgos con endurecimiento."""
        out = [(r, self._port_fix(r)) for r in self._port_rows or []
               if r["exposed"] and r["severity"] in (CRITICAL, WARNING) and not r.get("mitigated")]
        for f in self.findings:
            spec = finding_fix(f) if id(f) not in self._fixed else None
            if spec and spec["kind"] != "admin":
                out.append((f, spec))
        return out

    def mitigate_all(self) -> None:
        self._run_fixes(self._pending_fixes())

    def _run_fixes(self, targets: list) -> None:
        """Elevación, una única confirmación, copias de seguridad y ejecución en segundo plano."""
        if not targets or self._fixing:
            return
        if not IS_WINDOWS:
            Toast.notify(self.app, "!", "Mitigación", "Las acciones de endurecimiento solo existen en Windows.",
                         "fa5s.magic")
            return
        if any(spec["admin"] for _, spec in targets) and not getattr(self.app, "admin", False):
            if ConfirmDialog.ask(self.app, "Se requiere Administrador",
                                 "Estas acciones modifican el registro HKLM o el firewall y exigen privilegios de "
                                 "Administrador. ¿Relanzar Lozarus elevado (UAC)?",
                                 confirm_text="Relanzar como Administrador"):
                self.app.relaunch_as_admin()
            return
        jobs = {}
        for _, spec in targets:
            jobs.setdefault(spec["group"], spec)
        lines = [f"• {spec['label']}: {spec['what']}" for spec in jobs.values()]
        if len(targets) == 1:
            title, intro = targets[0][1]["label"], "Se aplicará exactamente:"
        else:
            title, intro = "Mitigar Riesgos Detectados", f"Se aplicarán {len(jobs)} mitigaciones en lote " \
                                                         f"({len(targets)} riesgos):"
        more = f"\n… y {len(lines) - 8} más" if len(lines) > 8 else ""
        if not ConfirmDialog.ask(self.app, title, f"{intro}\n" + "\n".join(lines[:8]) + more + "\n\n¿Continuar?",
                                 confirm_text="Aplicar", danger=True):
            return
        for group, spec in list(jobs.items()):  # copia de seguridad ANTES de borrar nada
            if "backup" not in spec:
                continue
            try:
                spec["saved"] = spec["backup"]()
            except OSError as exc:
                spec["saved"] = {"error": str(exc)}
            _emit_event(self.app, source="vectores:hallazgos", event_type="finding.backup",
                        payload={"action": spec["label"], **spec["saved"]})
            if "error" in spec["saved"]:
                del jobs[group]  # sin copia de seguridad no se borra
        self._fixing = True
        self.app.log_tactical(f"Mitigación: aplicando {len(jobs)} acciones")
        set_busy(self.fix_btn, True, "Mitigando…")
        self._update_counters()
        work = [(group, spec["fn"]) for group, spec in jobs.items()]

        def run(emit):
            results = {}
            for group, fn in work:
                try:
                    results[group] = (True, fn())
                except Exception as exc:  # noqa: BLE001  (cada fallo se informa por separado)
                    results[group] = (False, f"{type(exc).__name__}: {exc}")
            return results

        self.app.run_task(run, lambda ok, res: self._fixes_done(targets, ok, res))

    def _fixes_done(self, targets: list, ok: bool, results) -> None:
        self._fixing = False
        set_busy(self.fix_btn, False)
        if not ok or not isinstance(results, dict):
            Toast.notify(self.app, "x", "Mitigación", f"No se pudo completar: {results}", "fa5s.magic")
            results = {}
        done, failed = 0, []
        for target, spec in targets:
            good, info = results.get(spec["group"], (False, "sin copia de seguridad: no se aplicó"))
            port = isinstance(target, dict)
            payload = {"action": spec["label"], "what": spec["what"], "ok": good,
                       "detail": info, **spec.get("saved", {})}
            if port:
                payload.update(port=target["port"], proto=target["proto"])
            else:
                payload.update(module=target.module, title=target.title, key=target.key)
            _emit_event(self.app, source="vectores:puertos" if port else "vectores:hallazgos",
                        event_type="firewall.block" if port else "finding.mitigated", payload=payload)
            self.app.console.log("*" if good else "x", f"{spec['label']}: {spec['how'] if good else info}")
            if not good:
                failed.append(f"{spec['label']}: {info}")
            elif port:
                done += 1
                self._mark_mitigated(target, spec["how"])
            else:
                done += 1
                self._mark_finding(target, spec["how"])
        if len(targets) == 1:
            text = targets[0][1]["how"].capitalize() + "." if done else failed[0]
        else:
            text = f"{done} de {len(targets)} riesgos mitigados." + (f" Fallos: {failed[0]}" if failed else "")
        Toast.notify(self.app, "*" if not failed else "!" if done else "x", "Mitigación", text, "fa5s.magic")
        self._rescore()
        self._update_counters()
        self._apply_filter()
        self._show_port_detail()
        self._show_detail()

    def _mark_finding(self, finding, how: str) -> None:
        """Fila del diagnóstico en verde ✔ MITIGADO."""
        self._fixed[id(finding)] = how
        r = next(i for i, x in enumerate(self.findings) if x is finding)
        item = self.table.item(r, 0)
        item.setText("✔ MITIGADO")
        item.setForeground(QColor(COLORS["ok"]))

    def _rescore(self) -> None:
        """Puntuación con la fórmula de Report.score(): cada riesgo mitigado cuenta como superado."""
        if self.last_result is None:
            return
        live = [f for f in self.findings if id(f) not in self._fixed]
        passed = sum(1 for f in self.findings if f.severity is PASS) + len(self._fixed)
        crit = sum(1 for f in live if f.severity is CRITICAL)
        warn = sum(1 for f in live if f.severity is WARNING)
        total = passed + warn + 3 * crit
        score = round(100 * passed / total) if total else 100
        self.last_result = (score, crit, warn)
        self.score.setText(f"{score}/100")
        self.counts[CRITICAL].setText(str(crit))
        self.counts[WARNING].setText(str(warn))
        self._refresh_metrics()

    def _kill_owner(self) -> None:
        """Finaliza el proceso dueño del puerto con la lógica (y la confirmación) del Monitor en Vivo."""
        row = self._selected_port()
        if row is None or row["pid"] is None or self._protected(row):
            return
        name = None if row["process"] in ("?", "—") else row["process"]
        try:
            proc = psutil.Process(row["pid"])
            same = _same_process(proc, name, None)
        except psutil.Error:
            same = False
        if not same:
            Toast.notify(self.app, "x", "Proceso no encontrado",
                         f"PID {row['pid']} ya no es «{row['process']}». Repite la auditoría.", "fa5s.times-circle")
            return
        if _control_process(self.app, proc, "terminate", name):  # ConfirmDialog + Caja Negra + Toast
            self._mark_mitigated(row, f"proceso «{row['process']}» (PID {row['pid']}) finalizado")

    def _mark_mitigated(self, row: dict, how: str) -> None:
        """Marca la fila como MITIGADO en verde y lo deja en la Caja Negra."""
        row["mitigated"] = how
        r = next(i for i, x in enumerate(self._port_rows) if x is row)
        green = QColor(COLORS["ok"])
        for col, text in ((0, "✔"), (1, "MITIGADO")):
            item = self.port_table.item(r, col)
            item.setText(text)
            item.setForeground(green)
        _emit_event(self.app, source="vectores:puertos", event_type="port.mitigated",
                    payload={"port": row["port"], "proto": row["proto"], "pid": row["pid"], "how": how})
        self.app.log_tactical(f"Puerto {row['proto']} {row['port']} MITIGADO: {how}")
        self._refresh_metrics()
        self._update_counters()
        if row is self._selected_port():
            self._show_port_detail()

    # --- Diagnóstico completo (todos los plugins) -----------------------------------------------
    def start(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        if not self.app.modules:
            self.status.setText("No hay ningún plugin válido en modulos/")
            return
        self.findings = []
        self._fixed = {}
        self.finding_inspector.setVisible(False)
        self.table.setRowCount(0)
        self._update_counters()
        for val in self.counts.values():
            val.setText("0")
        self.score.setText("—")
        self.progress.setValue(0)
        self.tabs.setCurrentIndex(1)
        set_busy(self.run_btn, True, "Analizando…")
        self.status.setText("Analizando…")
        self.status.setObjectName("StatusMuted")
        repolish(self.status)
        self.app.log_tactical(f"Diagnóstico iniciado · {len(self.app.modules)} módulos (solo lectura)")
        self.worker = AuditWorker(self.app.modules, self.app.admin)
        self.worker.progress.connect(self._progress)
        self.worker.found.connect(self._finding)
        self.worker.report_ready.connect(self._finished)
        self.worker.failed.connect(self._failed)
        self.worker.start()

    def _progress(self, index: int, total: int, title: str) -> None:
        self.progress.setValue(int((index - 1) / total * 100))
        self.status.setText(f"Analizando: {title}  ({index}/{total})")
        self.app.console.log("~", f"Módulo {index}/{total}: {title}")

    def _finding(self, finding) -> None:
        self.findings.append(finding)
        self.counts[finding.severity].setText(str(int(self.counts[finding.severity].text()) + 1))
        r = self.table.rowCount()
        self.table.insertRow(r)
        cells = [finding.severity.value, self.app.module_titles.get(finding.module, finding.module), finding.title]
        for col, v in enumerate(cells):
            item = QTableWidgetItem(v)
            if col == 0:
                item.setForeground(QColor(SEVERITY_COLORS[finding.severity]))
            self.table.setItem(r, col, item)
        self.table.setRowHidden(r, not self._finding_visible(finding))
        self._update_counters()  # contador en vivo mientras llegan los hallazgos
        if finding.severity in (CRITICAL, WARNING):
            self.app.console.log("!", f"{finding.severity.value} · {finding.title}")

    def _finished(self, report) -> None:
        self.progress.setValue(100)
        set_busy(self.run_btn, False)
        score, c, w = report.score(), report.count(CRITICAL), report.count(WARNING)
        self.last_result = (score, c, w)  # lo lee el panel de salud del Centro de Comando
        self.score.setText(f"{score}/100")
        self._refresh_metrics()
        self._update_counters()
        self.status.setText(f"Completado: {c} CRITICAL · {w} WARNING")
        self.status.setObjectName("StatusOk")
        repolish(self.status)
        self.app.log_tactical(f"Diagnóstico completado · {c} CRITICAL · {w} WARNING · {score}/100")

    def _failed(self, msg: str) -> None:
        set_busy(self.run_btn, False)
        self.status.setText(f"Error: {msg}")
        self.app.console.log("x", f"Diagnóstico: {msg}")

    def _selected_finding(self):
        r = self.table.currentRow()
        return self.findings[r] if 0 <= r < len(self.findings) else None

    def _show_detail(self) -> None:
        f = self._selected_finding()
        self.finding_inspector.setVisible(f is not None)
        if f is None:
            return
        spec = finding_fix(f)
        fixed = self._fixed.get(id(f))
        state = "✔ MITIGADO" if fixed else f.severity.value
        parts = [f"{state}  ·  {self.app.module_titles.get(f.module, f.module)}", f.title]
        if f.detail:
            parts += ["", "Detalle técnico:", f.detail]
        if spec:
            parts += ["", "Qué protege:", DEFENSE[spec["kind"]]]
        if f.recommendation and f.severity in (WARNING, CRITICAL):
            parts += ["", "Qué hacer:", f"➜ {f.recommendation}"]
        if fixed:
            parts += ["", f"✔ Mitigado: {fixed}."]
        self.detail.setPlainText("\n".join(parts))
        admin_ok = spec is not None and spec["kind"] == "admin" and getattr(self.app, "admin", False)
        self.harden_btn.setVisible(spec is not None and not admin_ok)
        if spec is not None:
            self.harden_btn.setText(spec["label"])
            with_icon(self.harden_btn, spec["icon"], COLORS["danger"])
            self.harden_btn.setEnabled(not fixed and not self._fixing)
        self.harden_note.setText("Ya se ejecuta como Administrador: repite el diagnóstico." if admin_ok else
                                 f"Se aplicará: {spec['what']}" if spec and "what" in spec else
                                 "" if spec else "Sin remediación automática: sigue la recomendación.")

    def _harden_selected(self) -> None:
        f = self._selected_finding()
        spec = finding_fix(f) if f is not None and id(f) not in self._fixed else None
        if spec is None:
            return
        if spec["kind"] == "admin":
            self.app.relaunch_as_admin()
        else:
            self._run_fixes([(f, spec)])

    # --- Utilidades rápidas --------------------------------------------------------------------
    def install_dependencies(self) -> None:
        if not ConfirmDialog.ask(self.app, "Verificar / Instalar Dependencias",
                                 f"Se ejecutará con este Python:\n\n{os.path.basename(sys.executable)} -m pip install "
                                 f"-r requirements.txt\n\nDescarga de internet los paquetes que falten "
                                 "(PySide6, qtawesome, psutil, plyer…). ¿Continuar?",
                                 confirm_text="Instalar"):
            return
        set_busy(self.deps_btn, True, "Instalando…")
        self.app.log_tactical("Verificando dependencias (pip install -r requirements.txt)")

        def done(ok, res):
            set_busy(self.deps_btn, False)
            if not ok or not isinstance(res, dict):
                res = {"ok": False, "summary": str(res)}
            kind = "*" if res["ok"] else "x"
            self.app.console.log(kind, f"Dependencias: {res['summary']}")
            _emit_event(self.app, source="vectores:utilidades", event_type="tools.dependencies",
                        payload={"ok": res["ok"], "summary": res["summary"]})
            Toast.notify(self.app, kind, "Dependencias", res["summary"], "fa5s.box-open")

        self.app.run_task(lambda emit: install_requirements(), done)

    def rescue_network(self) -> None:
        if not getattr(self.app, "admin", False):
            Toast.notify(self.app, "x", "Se requiere elevación",
                         "El rescate de red (ARP y Winsock) necesita Administrador. Relanza Lozarus como "
                         f"{ADMIN_NAME} y vuelve a intentarlo.", "fa5s.user-shield")
            return
        pasos = "\n".join(f"  · {' '.join(cmd)}" for _label, cmd in NETWORK_RESCUE_STEPS)
        if not ConfirmDialog.ask(self.app, "Rescate de Red",
                                 f"Se ejecutarán en este equipo:\n\n{pasos}\n\nLa conexión puede cortarse unos "
                                 "segundos y el restablecimiento de Winsock se completa al reiniciar. ¿Continuar?",
                                 confirm_text="Reparar red", danger=True):
            return
        set_busy(self.netfix_btn, True, "Reparando…")
        self.app.log_tactical("Rescate de red: flush DNS · ARP · Winsock")

        def done(ok, res):
            set_busy(self.netfix_btn, False)
            steps = res if ok and isinstance(res, list) else [("Rescate de red", False, str(res))]
            good = [label for label, success, _msg in steps if success]
            bad = [f"{label}: {msg or 'falló'}" for label, success, msg in steps if not success]
            kind = "*" if not bad else "!" if good else "x"
            text = (" · ".join(good) or "Ningún paso se completó.") + (f"\nSin aplicar: {' · '.join(bad)}" if bad else "")
            self.app.console.log(kind, f"Rescate de red: {text}")
            _emit_event(self.app, source="vectores:utilidades", event_type="tools.network_rescue",
                        payload={"done": good, "failed": bad})
            Toast.notify(self.app, kind, "Rescate de Red", text, "fa5s.first-aid")

        self.app.run_task(lambda emit: network_rescue(), done)
