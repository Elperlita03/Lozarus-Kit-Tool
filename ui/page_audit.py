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

import psutil
from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QButtonGroup, QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QProgressBar, QPushButton,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from modulos._base import CRITICAL, INFO, IS_WINDOWS, PASS, WARNING, AuditContext, Report
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
        self.fix_btn.setToolTip("Las acciones de mitigación se activan en el siguiente paso del rediseño.")
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
        crit = sum(1 for r in ports if r["severity"] is CRITICAL) + sum(1 for f in self.findings if f.severity is CRITICAL)
        warn = sum(1 for r in ports if r["severity"] is WARNING) + sum(1 for f in self.findings if f.severity is WARNING)
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

    def _build_port_inspector(self) -> QFrame:
        """Inspector del puerto seleccionado: explicación defensiva (izq.) y acciones reales (der.)."""
        self.inspector = QFrame()
        self.inspector.setObjectName("Card")
        row = QHBoxLayout(self.inspector)
        row.setContentsMargins(16, 12, 16, 12)
        row.setSpacing(18)
        cols = []
        for caption in ("POR QUÉ ES UN VECTOR DE RIESGO", "ACCIONES"):
            col = QVBoxLayout()
            col.setSpacing(8)
            cap = QLabel(caption)
            cap.setObjectName("ChipCap")
            col.addWidget(cap)
            cols.append(col)
        cols[0].addWidget(self.port_detail, 1)
        self.block_btn = QPushButton("Bloquear Puerto en Firewall")
        self.kill_btn = QPushButton("Finalizar Proceso Propietario")
        for button, icon_name, slot in ((self.block_btn, "fa5s.ban", self._block_port),
                                        (self.kill_btn, "fa5s.times-circle", self._kill_owner)):
            button.setObjectName("Danger")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            with_icon(button, icon_name, COLORS["danger"])
            button.clicked.connect(slot)
            cols[1].addWidget(button)
        cols[1].addStretch(1)
        row.addLayout(cols[0], 3)
        row.addLayout(cols[1], 2)
        self.inspector.setVisible(False)  # solo aparece al seleccionar un puerto en escucha
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
        self.detail.setFixedHeight(118)
        self.detail.setPlainText("Selecciona un hallazgo de la tabla para ver su detalle y la recomendación.")
        lay.addWidget(self.detail, 1)
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
        self.block_btn.setEnabled(not done)
        killable = row["pid"] is not None and not self._protected(row)
        self.kill_btn.setEnabled(killable and not done)
        self.kill_btn.setToolTip("" if killable else "Proceso protegido del sistema o PID desconocido.")

    def _block_port(self) -> None:
        """Regla de entrada REAL en el Firewall de Windows (netsh advfirewall); exige Administrador."""
        row = self._selected_port()
        if row is None:
            return
        label = f"{row['proto']} {row['port']} ({row['service']})"
        if not IS_WINDOWS:
            Toast.notify(self.app, "!", "Firewall", "netsh advfirewall solo existe en Windows.", "fa5s.ban")
            return
        if not self.app.admin:
            if ConfirmDialog.ask(self.app, "Se requiere Administrador",
                                 "Crear reglas en el Firewall de Windows exige privilegios de Administrador. "
                                 "¿Relanzar Lozarus elevado (UAC)?", confirm_text="Relanzar como Administrador"):
                self.app.relaunch_as_admin()
            return
        if not ConfirmDialog.ask(self.app, "Bloquear puerto", f"Se creará una regla de entrada que bloquea {label}: "
                                 "dejará de ser accesible desde otros equipos. ¿Continuar?",
                                 confirm_text="Bloquear puerto", danger=True):
            return
        rule = f"Lozarus - Bloqueo {row['proto']} {row['port']}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule}", "dir=in", "action=block",
               f"protocol={row['proto']}", f"localport={row['port']}"]
        self.app.log_tactical(f"Firewall: bloqueando {label}")
        self.block_btn.setEnabled(False)
        self.app.run_task(lambda emit: run_cmd(cmd), lambda ok, res: self._block_done(row, rule, ok, res))

    def _block_done(self, row: dict, rule: str, ok: bool, res) -> None:
        applied = ok and isinstance(res, tuple) and res[0] == 0
        detail = (res[1] or res[2]).strip() if ok and isinstance(res, tuple) else str(res)
        text = (f"Regla «{rule}» creada." if applied
                else f"No se pudo bloquear {row['proto']} {row['port']}: {detail}")
        self.app.console.log("*" if applied else "x", f"Firewall: {text}")
        _emit_event(self.app, source="vectores:puertos", event_type="firewall.block",
                    payload={"port": row["port"], "proto": row["proto"], "rule": rule, "ok": applied,
                             "detail": detail})
        Toast.notify(self.app, "*" if applied else "x", "Puerto bloqueado" if applied else "Firewall", text,
                     "fa5s.ban")
        if applied:
            self._mark_mitigated(row, f"bloqueado en el firewall (regla «{rule}»)")
        elif row is self._selected_port():
            self._show_port_detail()  # reactiva los botones

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

    def _show_detail(self) -> None:
        r = self.table.currentRow()
        if r < 0 or r >= len(self.findings):
            return
        f = self.findings[r]
        parts = [f"{f.severity.value}  ·  {self.app.module_titles.get(f.module, f.module)}", f.title]
        if f.detail:
            parts += ["", "Detalle:", f.detail]
        if f.recommendation and f.severity in (WARNING, CRITICAL):
            parts += ["", "Qué hacer:", f"➜ {f.recommendation}"]
        self.detail.setPlainText("\n".join(parts))
