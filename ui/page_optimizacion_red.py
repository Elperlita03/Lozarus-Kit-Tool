"""
ui/page_optimizacion_red.py · LOZARUS KIT TOOL

Página OPTIMIZACIÓN DE RED Y PROCESOS (motor: modulos/_optimizacion_red.py):
  · Gestión de conectividad: auditoría de adaptadores (enlace, velocidad, MTU, direcciones y tasa de
    errores) y mantenimiento preventivo de la pila de red (Winsock, TCP/IP, DHCP, DNS) con netsh /
    ipconfig. Requiere Administrador y confirmación explícita.
  · Administración de procesos seguros: escaneo con PID, nombre, ruta, CPU/RAM, estado y firma
    Authenticode; finaliza procesos bloqueados o con consumo anómalo (nunca los críticos).

Todo corre en segundo plano (app.run_task + spinner en el botón), queda en la Caja Negra
(_emit_event) y avisa con Toast.notify.
"""

from __future__ import annotations

import getpass
import sys
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy,
                               QTableWidgetItem, QVBoxLayout)

from modulos._optimizacion_red import (CPU_ANOMALY_PCT, IS_WINDOWS, MAINTENANCE_OPS, adapters_overview,
                                       run_maintenance, scan_processes, terminate_process)

from ui.theme import COLORS, badge_qss
from ui.widgets import (Page, _emit_event, flash_aura, format_bytes, frozen, make_card, make_table, set_busy,
                        stat_chip, tech_tip, with_icon)
from ui.dialogs import ConfirmDialog
from ui.chrome import Toast

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

PAGE_KEY = "optimizacion"
PAGE_ICON = "fa5s.tools"
SOURCE = "optimizacion:red-procesos"

# Botón de mantenimiento: clave -> (icono, texto, explicación para la confirmación)
OPS_UI = {
    "winsock": ("fa5s.plug", "Restablecer Winsock",
                "Devuelve el catálogo de sockets a su estado de fábrica y elimina proveedores LSP "
                "corruptos. Algunas VPN o antivirus deberán reinstalar su componente de red. "
                "Requiere REINICIAR el equipo."),
    "tcpip": ("fa5s.layer-group", "Restablecer pila TCP/IP",
              "Reescribe la configuración IPv4/IPv6 del registro a sus valores por defecto. Se pierden "
              "las IP estáticas configuradas a mano. Requiere REINICIAR el equipo."),
    "dhcp": ("fa5s.sync-alt", "Renovar concesión DHCP",
             "Libera y vuelve a pedir la dirección IP de cada adaptador. La conexión se CORTA unos "
             "segundos."),
    "dns": ("fa5s.broom", "Purgar y re-registrar DNS",
            "Vacía la caché del solucionador DNS y vuelve a registrar el nombre del equipo. No corta "
            "la conexión."),
}
HEALTH_STYLE = {"ok": (COLORS["ok"], "● Activo"), "degradado": (COLORS["warn"], "● Degradado"),
                "inactivo": (COLORS["muted"], "○ Inactivo")}
SIG_COLOR = {"valid": COLORS["ok"], "invalid": COLORS["warn"], "unknown": COLORS["muted"]}


def _item(text: str, color: Optional[str] = None, tip: str = "", data: Any = None) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    if color:
        it.setForeground(QColor(color))
    if tip:
        it.setToolTip(tip)
    if data is not None:
        it.setData(Qt.ItemDataRole.UserRole, data)
    return it


class OptimizacionRedPage(Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Optimización de Red y Procesos",
                         "Audita los adaptadores, aplica mantenimiento preventivo a la pila de red y localiza "
                         "procesos bloqueados, sin firma o con consumo anómalo. Cada cambio pide confirmación "
                         "y queda en la Caja Negra.", PAGE_ICON)
        self.app = app
        self._running = 0
        self._adapters: List[Dict[str, Any]] = []
        self._procs: List[Dict[str, Any]] = []
        self._op_buttons: Dict[str, QPushButton] = {}
        self._build_status_header()
        self.root.addLayout(self._build_stats())
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.addWidget(self._build_adapters_card(), 0, 0)
        grid.addWidget(self._build_maintenance_card(), 0, 1)
        grid.setColumnStretch(0, 3)
        grid.setColumnStretch(1, 2)
        self.root.addLayout(grid)
        self.root.addWidget(self._build_processes_card())
        self.root.addStretch(1)
        self._update_status()

    # =============================================================================================
    # Utilidades
    # =============================================================================================
    @staticmethod
    def _btn(text: str, icon_name: str, kind: str, slot: Optional[Callable] = None) -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName(kind)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        color = {"Danger": COLORS["danger"], "Warn": COLORS["danger"], "Ghost": COLORS["muted"],
                 "Toggle": COLORS["muted"]}.get(kind)
        with_icon(btn, icon_name, color, 14)
        if slot is not None:
            btn.clicked.connect(slot)
        return btn

    def _task(self, button: QPushButton, busy_text: str, fn: Callable[[Callable], Any],
              on_done: Callable[[bool, Any], None]) -> None:
        """app.run_task con spinner en el botón y el indicador de estado de la cabecera al día."""
        set_busy(button, True, busy_text)
        self._running += 1
        self._update_status()

        def done(ok: bool, payload: Any) -> None:
            self._running = max(0, self._running - 1)
            set_busy(button, False)
            self._update_status()
            on_done(ok, payload)

        self.app.run_task(fn, done)

    def _result(self, button: QPushButton, ok: bool, title: str, text: str, icon_name: str) -> None:
        """Consola + micro-interacción del botón + aviso flotante."""
        self.app.console.log("*" if ok else "x", text if text.startswith(title) else f"{title}: {text}")
        flash_aura(button, COLORS["ok"] if ok else COLORS["danger"])
        Toast.notify(self.app, "*" if ok else "x", title, text, icon_name)

    def _ensure_admin(self, action: str) -> bool:
        """True si hay privilegios; si no, ofrece relanzar Lozarus elevado (UAC) y devuelve False."""
        if getattr(self.app, "admin", False):
            return True
        self.app.console.log("!", f"{action}: requiere Administrador")
        if ConfirmDialog.ask(self.app, "Se requiere Administrador",
                             f"«{action}» modifica el sistema y exige privilegios de Administrador.\n\n"
                             "¿Relanzar Lozarus elevado (UAC)? Esta ventana se cerrará si la elevación tiene éxito.",
                             confirm_text="Relanzar como Administrador"):
            self.app.relaunch_as_admin()
        return False

    # =============================================================================================
    # Cabecera: indicador de estado + privilegios
    # =============================================================================================
    def _build_status_header(self) -> None:
        header = self.layout().itemAt(0).layout()  # cabecera fija de Page (icono + título)
        pills = QVBoxLayout()
        pills.setSpacing(6)
        self.status_pill = QLabel()
        self.priv_pill = QLabel()
        for pill in (self.status_pill, self.priv_pill):
            pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
            pills.addWidget(pill, 0, Qt.AlignmentFlag.AlignRight)
        pills.addStretch(1)
        header.addLayout(pills)

    def _update_status(self) -> None:
        if self._running:
            text, color = f"●  EN CURSO · {self._running}", COLORS["accent"]
        else:
            pending = (sum(1 for p in self._procs if p["anomalies"] or p["sig_state"] == "invalid")
                       + sum(1 for a in self._adapters if a["health"] == "degradado"))
            text, color = (f"●  REVISAR · {pending}", COLORS["warn"]) if pending else ("●  LISTO", COLORS["ok"])
        self.status_pill.setText(text)
        self.status_pill.setStyleSheet(badge_qss(color, 10))
        admin = bool(getattr(self.app, "admin", False))
        self.priv_pill.setText("ADMINISTRADOR" if admin else "USUARIO ESTÁNDAR")
        self.priv_pill.setStyleSheet(badge_qss(COLORS["ok"] if admin else COLORS["muted"], 10))

    # =============================================================================================
    # Fila Bento de métricas
    # =============================================================================================
    def _build_stats(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        self._stats = {}
        for key, caption in (("adapters", "ADAPTADORES ACTIVOS"), ("traffic", "TRÁFICO DE LA SESIÓN"),
                             ("procs", "PROCESOS ANALIZADOS"), ("alerts", "ANÓMALOS / FIRMA NO VÁLIDA")):
            chip, val = stat_chip(caption)
            note = QLabel("sin datos")
            note.setObjectName("Tiny")
            chip.layout().addWidget(note)
            self._stats[key] = (val, note)
            row.addWidget(chip, 1)
        return row

    def _set_stat(self, key: str, value: str, note: str, color: Optional[str] = None) -> None:
        val, lbl = self._stats[key]
        val.setText(value)
        val.setStyleSheet(f"color:{color};" if color else "")
        lbl.setText(note)

    # =============================================================================================
    # Gestión de conectividad: adaptadores
    # =============================================================================================
    def _build_adapters_card(self):
        box, lay = make_card("Gestión de conectividad",
                             "Estado de cada adaptador: enlace, velocidad, MTU, direcciones y tasa de paquetes "
                             "con error o descartados (más de un 1 % = degradado). Solo lectura.")
        row = QHBoxLayout()
        self.audit_btn = self._btn("Auditar adaptadores", "fa5s.search", "Primary", self._audit_adapters)
        row.addWidget(self.audit_btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.adapters_table = make_table(
            ["Adaptador", "Estado", "Velocidad", "IPv4", "MTU", "Errores"],
            widths=[150, 104, 92, 130, 64],
            empty="Pulsa «Auditar adaptadores» para leer el estado de las interfaces de red.",
            empty_icon="fa5s.ethernet")
        self.adapters_table.setMinimumHeight(250)
        lay.addWidget(self.adapters_table, 1)
        return box

    def _audit_adapters(self) -> None:
        self.app.log_tactical("Auditando adaptadores de red")

        def done(ok: bool, rows) -> None:
            if not ok or not isinstance(rows, list):
                self._result(self.audit_btn, False, "Auditoría de red", f"No se pudo completar: {rows}",
                             "fa5s.ethernet")
                return
            self._adapters = rows
            self._render_adapters()
            up = sum(1 for a in rows if a["up"])
            degraded = [a["name"] for a in rows if a["health"] == "degradado"]
            _emit_event(self.app, source=SOURCE, event_type="network.adapters_audited",
                        payload={"total": len(rows), "up": up, "degraded": degraded})
            text = f"{up} activos de {len(rows)}" + (f" · degradados: {', '.join(degraded)}" if degraded
                                                     else " · sin errores relevantes")
            self._result(self.audit_btn, not degraded, "Auditoría de red", text, "fa5s.ethernet")
            self._update_status()

        self._task(self.audit_btn, "Auditando…", lambda emit: adapters_overview(), done)

    def _render_adapters(self) -> None:
        rows = self._adapters
        with frozen(self.adapters_table):
            self.adapters_table.setRowCount(len(rows))
            for r, a in enumerate(rows):
                color, label = HEALTH_STYLE[a["health"]]
                vals = [
                    _item(a["name"], COLORS["text"], f"MAC: {a['mac']} · IPv6: {a['ipv6']} dirección(es) · "
                                                     f"↑ {format_bytes(a['sent'])} · ↓ {format_bytes(a['recv'])}"),
                    _item(label, color),
                    _item(f"{a['speed']} Mb/s" if a["speed"] else "—"),
                    _item(a["ipv4"]), _item(str(a["mtu"] or "—")),
                    _item(f"{a['error_ratio'] * 100:.2f} %",
                          COLORS["warn"] if a["health"] == "degradado" else COLORS["text2"]),
                ]
                for c, it in enumerate(vals):
                    self.adapters_table.setItem(r, c, it)
        up = sum(1 for a in rows if a["up"])
        self._set_stat("adapters", str(up), f"de {len(rows)} interfaces", None if up else COLORS["warn"])
        self._set_stat("traffic", format_bytes(sum(a["sent"] + a["recv"] for a in rows)),
                       "enviado + recibido desde el arranque")

    # =============================================================================================
    # Gestión de conectividad: mantenimiento de la pila
    # =============================================================================================
    def _build_maintenance_card(self):
        box, lay = make_card("Mantenimiento de la pila de red",
                             "Operaciones preventivas con comandos del sistema. Requieren Administrador y "
                             "confirmación; las marcadas en rojo se aplican al reiniciar el equipo.")
        grid = QGridLayout()
        grid.setSpacing(10)
        for i, (key, (desc, commands, reboot)) in enumerate(MAINTENANCE_OPS.items()):
            icon_name, text, detail = OPS_UI[key]
            btn = self._btn(text, icon_name, "Danger" if reboot else "Ghost",
                            lambda _=False, k=key: self._maintenance(k))
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.setToolTip(tech_tip(desc, [" ".join(c) for c in commands], detail))
            if not IS_WINDOWS:
                btn.setEnabled(False)
            self._op_buttons[key] = btn
            grid.addWidget(btn, i // 2, i % 2)
        lay.addLayout(grid)
        self.maint_status = QLabel("Sin operaciones en esta sesión.")
        self.maint_status.setObjectName("Tiny")
        self.maint_status.setWordWrap(True)
        lay.addWidget(self.maint_status)
        if not IS_WINDOWS:
            self.maint_status.setText(f"Sistema detectado: {sys.platform}. El mantenimiento de pila usa "
                                      "netsh / ipconfig y solo existe en Windows; la auditoría y los "
                                      "procesos funcionan igual.")
        elif not getattr(self.app, "admin", False):
            lay.addWidget(self._btn("Relanzar como Administrador (UAC)", "fa5s.user-shield", "Warn",
                                    self.app.relaunch_as_admin))
        lay.addStretch(1)
        return box

    def _maintenance(self, key: str) -> None:
        desc, commands, reboot = MAINTENANCE_OPS[key]
        _icon_name, text, detail = OPS_UI[key]
        if not IS_WINDOWS:
            Toast.notify(self.app, "!", text, "Disponible solo en Windows.", "fa5s.wrench")
            return
        if not self._ensure_admin(text):
            return
        cmds = "\n".join(f"   {' '.join(c)}" for c in commands)
        if not ConfirmDialog.ask(self.app, text, f"{detail}\n\nSe ejecutará:\n{cmds}\n\n¿Aplicar ahora en ESTE equipo?",
                                 confirm_text="Aplicar", danger=True):
            self.app.console.log("~", f"{text}: cancelado")
            return
        self.app.log_tactical(f"Mantenimiento de red: {text}")
        btn = self._op_buttons[key]

        def done(ok: bool, res) -> None:
            if not ok or not isinstance(res, dict):
                self._result(btn, False, text, f"No se pudo completar: {res}", "fa5s.wrench")
                return
            for step in res["steps"]:
                self.app.console.log("~", f"$ {step['cmd']} → código {step['rc']}")
            _emit_event(self.app, source=SOURCE, event_type="network.stack_maintenance",
                        payload={"op": key, "ok": res["ok"], "reboot": res["reboot"],
                                 "steps": [{"cmd": s["cmd"], "rc": s["rc"]} for s in res["steps"]]})
            self.maint_status.setText(res["message"])
            self.maint_status.setStyleSheet(f"color:{COLORS['ok'] if res['ok'] else COLORS['danger']};")
            self._result(btn, res["ok"], text, res["message"], "fa5s.wrench")

        self._task(btn, "Aplicando…", lambda emit: run_maintenance(key, admin=True), done)

    # =============================================================================================
    # Administración de procesos seguros
    # =============================================================================================
    def _build_processes_card(self):
        box, lay = make_card("Administración de procesos seguros",
                             f"Procesos en ejecución con su ruta y firma digital (Authenticode, solo Windows). "
                             f"CPU ≥ {CPU_ANOMALY_PCT:.0f} %, RAM ≥ 1,5 GB, detenidos o zombi se marcan como "
                             "anómalos. Los procesos críticos del sistema no se pueden finalizar.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.scan_btn = self._btn("Escanear procesos", "fa5s.search", "Primary", self._scan_processes)
        self.sig_toggle = self._btn("Verificar firmas", "fa5s.certificate", "Toggle")
        self.sig_toggle.setCheckable(True)
        self.sig_toggle.setChecked(IS_WINDOWS)
        self.sig_toggle.setEnabled(IS_WINDOWS)
        self.sig_toggle.setToolTip(tech_tip("Firma Authenticode", ["Get-AuthenticodeSignature -LiteralPath <ruta>"],
                                            "Más lento: verifica cada ejecutable en bloque."
                                            if IS_WINDOWS else "Solo disponible en Windows."))
        self.only_flagged = self._btn("Solo anómalos / sin firma", "fa5s.filter", "Toggle")
        self.only_flagged.setCheckable(True)
        self.only_flagged.toggled.connect(lambda _on: self._render_processes())
        self.kill_btn = self._btn("Finalizar proceso", "fa5s.stop-circle", "Danger", self._terminate_selected)
        self.kill_btn.setEnabled(False)
        for w in (self.scan_btn, self.sig_toggle, self.only_flagged):
            row.addWidget(w)
        row.addStretch(1)
        row.addWidget(self.kill_btn)
        lay.addLayout(row)
        self.proc_filter = QLineEdit()
        self.proc_filter.setPlaceholderText("Filtrar por PID, nombre, ruta, usuario o firma…")
        self.proc_filter.setClearButtonEnabled(True)
        self.proc_filter.textChanged.connect(lambda _t: self._render_processes())
        lay.addWidget(self.proc_filter)
        self.proc_table = make_table(["PID", "Nombre", "Ruta", "CPU", "RAM", "Estado", "Firma digital"],
                                     widths=[70, 180, 330, 70, 86, 96],
                                     empty="Pulsa «Escanear procesos» para listar los procesos en ejecución.",
                                     empty_icon="fa5s.microchip")
        self.proc_table.setMinimumHeight(340)
        self.proc_table.itemSelectionChanged.connect(self._on_proc_select)
        lay.addWidget(self.proc_table)
        return box

    def _scan_processes(self) -> None:
        verify = IS_WINDOWS and self.sig_toggle.isChecked()
        self.app.log_tactical("Escaneando procesos" + (" y verificando firmas" if verify else ""))

        def done(ok: bool, rows) -> None:
            if not ok or not isinstance(rows, list):
                self._result(self.scan_btn, False, "Escaneo de procesos", f"No se pudo completar: {rows}",
                             "fa5s.microchip")
                return
            self._procs = rows
            self._render_processes()
            anomal = [r for r in rows if r["anomalies"]]
            unsigned = [r for r in rows if r["sig_state"] == "invalid"]
            flagged = len({r["pid"] for r in anomal + unsigned})
            self._set_stat("procs", str(len(rows)), "firmas verificadas" if verify else "sin verificar firmas")
            self._set_stat("alerts", str(flagged), f"{len(anomal)} anómalos · {len(unsigned)} firma no válida",
                           COLORS["warn"] if flagged else None)
            _emit_event(self.app, source=SOURCE, event_type="process.scan_completed",
                        payload={"total": len(rows), "signatures_verified": verify,
                                 "invalid_signatures": len(unsigned),
                                 "anomalous": [{"pid": r["pid"], "name": r["name"], "reasons": r["anomalies"]}
                                               for r in anomal[:25]]})
            self._result(self.scan_btn, True, "Escaneo de procesos",
                         f"{len(rows)} analizados · {len(anomal)} anómalos · {len(unsigned)} con firma no válida",
                         "fa5s.microchip")
            self._update_status()

        self._task(self.scan_btn, "Verificando firmas…" if verify else "Escaneando…",
                   lambda emit: scan_processes(verify_signatures=verify), done)

    def _render_processes(self) -> None:
        needle = self.proc_filter.text().strip().lower()
        only = self.only_flagged.isChecked()
        rows = [p for p in self._procs
                if (not only or p["anomalies"] or p["sig_state"] == "invalid")
                and (not needle or needle in f"{p['pid']} {p['name']} {p['exe']} {p['user']} {p['sig_label']}".lower())]
        if self._procs and not rows:
            self.proc_table.set_empty_text("Ningún proceso coincide con el filtro.", "fa5s.search")
        with frozen(self.proc_table):
            self.proc_table.setRowCount(len(rows))
            for r, p in enumerate(rows):
                name_color = COLORS["warn"] if p["anomalies"] else COLORS["muted"] if p["protected"] else COLORS["text"]
                tip = " · ".join(p["anomalies"]) or ("Proceso crítico del sistema: protegido" if p["protected"] else "")
                vals = [
                    _item(str(p["pid"]), COLORS["text2"], data=p["pid"]),
                    _item(p["name"], name_color, tip),
                    _item(p["exe"] or "—", COLORS["text2"], p["exe"]),
                    _item(f"{p['cpu']:.1f} %", COLORS["warn"] if p["cpu"] >= CPU_ANOMALY_PCT else COLORS["text2"]),
                    _item(format_bytes(p["rss"]), COLORS["text2"]),
                    _item(p["status"] or "—",
                          COLORS["danger"] if p["status"] in ("zombie", "stopped") else COLORS["text2"]),
                    _item(p["sig_label"], SIG_COLOR[p["sig_state"]], p["sig_signer"]),
                ]
                for c, it in enumerate(vals):
                    self.proc_table.setItem(r, c, it)
        self._on_proc_select()

    def _selected_proc(self) -> Optional[Dict[str, Any]]:
        if not self.proc_table.selectedItems():
            return None
        item = self.proc_table.item(self.proc_table.currentRow(), 0)
        pid = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return next((p for p in self._procs if p["pid"] == pid), None)

    def _on_proc_select(self) -> None:
        p = self._selected_proc()
        self.kill_btn.setEnabled(p is not None and not p["protected"])
        self.kill_btn.setToolTip("Proceso crítico del sistema: protegido." if p and p["protected"] else "")

    def _terminate_selected(self) -> None:
        p = self._selected_proc()
        if p is None:
            return
        if p["protected"]:
            Toast.notify(self.app, "!", "Procesos", f"«{p['name']}» es un proceso crítico del sistema: "
                                                    "no se finaliza.", "fa5s.shield-alt")
            return
        me = (getpass.getuser() or "").lower()
        owner = (p["user"] or "").lower()
        own = bool(owner) and (owner == me or owner.endswith("\\" + me))
        if not own and not self._ensure_admin(f"Finalizar {p['name']}"):
            return
        motivo = ("\nMotivo: " + ", ".join(p["anomalies"])) if p["anomalies"] else ""
        if not ConfirmDialog.ask(self.app, "Finalizar proceso",
                                 f"Vas a finalizar:\n\n{p['name']}  (PID {p['pid']})\n"
                                 f"{p['exe'] or 'ruta no disponible'}\nFirma: {p['sig_label']}{motivo}\n\n"
                                 "Se perderán los datos sin guardar de ese programa. ¿Continuar?",
                                 confirm_text="Finalizar", danger=True):
            self.app.console.log("~", f"Finalizar {p['name']}: cancelado")
            return
        self.app.log_tactical(f"Finalizando proceso {p['name']} (PID {p['pid']})")
        pid, name = p["pid"], p["name"]

        def done(ok: bool, res) -> None:
            good, msg = res if ok and isinstance(res, tuple) else (False, str(res))
            _emit_event(self.app, source=SOURCE, event_type="process.terminate_requested", process_id=pid,
                        payload={"pid": pid, "name": name, "exe": p["exe"], "ok": good, "message": msg,
                                 "anomalies": p["anomalies"], "signature": p["sig_status"]})
            if good:
                self._procs = [x for x in self._procs if x["pid"] != pid]
                self._render_processes()
            self._result(self.kill_btn, good, "Procesos", msg, "fa5s.stop-circle")
            self._update_status()

        self._task(self.kill_btn, "Finalizando…", lambda emit: terminate_process(pid, name), done)
