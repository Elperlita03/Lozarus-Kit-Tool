"""
ui/page_audit.py · LOZARUS KIT TOOL

Página ESCANEO DE VECTORES (Sistema y Perímetro):
  · Métricas Bento: Puntuación Global de Seguridad en vivo, riesgos pendientes, puertos expuestos y
    vectores mitigados en la sesión.
  · Operaciones: diagnóstico completo (todos los plugins de modulos/, solo lectura), auditoría de puertos
    (motor real del plugin 04_puertos) y mitigación en lote.
  · Telemetría filtrable (diagnóstico y puertos), cada una con su inspector de doble columna:
    inteligencia defensiva | acción directa (winreg, netsh, directivas de seguridad).
Las remediaciones viven en modulos/_mitigacion.py: transaccionales, verificadas, con antes/después en la
Caja Negra y deshacer quirúrgico.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import os
import sys
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import psutil
from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QButtonGroup, QHBoxLayout, QHeaderView, QLabel, QProgressBar, QPushButton,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from modulos import _mitigacion as mit
from modulos._base import CRITICAL, INFO, IS_WINDOWS, PASS, WARNING, AuditContext, Report

from ui.theme import COLORS, SEVERITY_COLORS
from ui.widgets import BentoCard, Page, ScoreRing, _emit_event, frozen, icon, make_table, set_busy, tech_tip
from ui.chrome import Toast
from ui.informe import REPORTS_DIR, compute_security, export_report
from ui.kit import HeaderStatus, Inspector, SafeActions, Tile, action_button
from ui.page_monitor import PROTECTED_PROCS, _control_process, _same_process

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

# Orden de la telemetría de puertos: lo peligroso arriba, lo solo-local al final.
PORT_RISK_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2, PASS: 3}
FILTERS = (("all", "TODOS"), ("critical", "CRITICAL"), ("warning", "WARNING"), ("exposed", "EXPUESTOS"),
           ("mitigated", "MITIGADOS"))
RISK_EXPOSED = ("Cualquier equipo de la red (o de Internet, si el router lo reenvía) puede conectarse, probar "
                "contraseñas por fuerza bruta o explotar una vulnerabilidad del proceso para ejecutar código con "
                "sus privilegios.")
RISK_LOCAL = ("Solo escucha en loopback: otros equipos no lo alcanzan, pero un programa malicioso que ya corra en "
              "este equipo sí puede usarlo para escalar privilegios.")
MITIGATED = "✔ MITIGADO"
SOURCE = "vectores:mitigacion"
Target = object  # Finding o fila de puerto (dict)


def _n(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


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
    Inventario de puertos en escucha clasificado con la tabla RISKY_PORTS del plugin: expuesto + servicio
    de riesgo → su severidad; expuesto sin riesgo conocido → INFO; solo loopback → PASS. Solo lectura.
    """
    rows = []
    for sock in backend.get_listening_sockets():
        rule = backend.RISKY_PORTS.get(sock.port)
        risky = rule is not None and sock.proto in rule.protos
        service = rule.service if rule else backend.COMMON_SERVICES.get(sock.port, "—")
        if not sock.exposed:
            severity, why = PASS, "Solo accesible desde este equipo (loopback)."
        elif risky:
            severity, why = rule.severity, f"{rule.reason} ➜ {rule.advice}"
        else:
            severity, why = INFO, "Escucha en la red. Si no reconoces el proceso, revisa si lo necesitas."
        rows.append({"severity": severity, "proto": sock.proto, "ip": sock.ip, "port": sock.port,
                     "service": service, "process": sock.process, "pid": sock.pid,
                     "exposed": sock.exposed, "why": why})
    rows.sort(key=lambda r: (PORT_RISK_ORDER.get(r["severity"], 9), r["port"], r["proto"]))
    return rows


class AuditWorker(QThread):
    """
    Ejecuta los plugins de auditoría (solo lectura) en segundo plano y publica el progreso y cada hallazgo
    por señales, que Qt entrega al hilo de la interfaz de forma segura. Mismo motor que auditor.py.
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
            ctx = AuditContext(args=argparse.Namespace(escanear=None, timeout=0.5), report=report, is_admin=self.admin)
            for index, module_cls in enumerate(self.modules, 1):
                self.progress.emit(index, len(self.modules), module_cls.title)
                module_cls(ctx).run()  # AuditModule.run convierte los errores en [SKIP]
            self.report_ready.emit(report)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class AuditPage(SafeActions, Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Escaneo de Vectores",
                         f"Audita los vectores de ataque del equipo (puertos en escucha y {len(app.modules)} plugins "
                         "de diagnóstico) y los corrige con remediaciones reales: registro, firewall y directivas de "
                         "seguridad. Cada cambio se confirma, se verifica, queda en la Caja Negra y se puede deshacer.",
                         "fa5s.shield-alt")
        self.app = app
        self.findings: list = []
        self.worker: Optional[AuditWorker] = None
        self.last_result: Optional[Tuple[int, int, int]] = None  # (puntuación, CRITICAL, WARNING)
        self._ports_backend = ports_backend(app.modules)
        self._port_rows: Optional[list] = None
        self._fixed: Dict[int, str] = {}                              # id(Finding) -> cómo se mitigó
        self._journal: Dict[int, Tuple[mit.Remedy, list]] = {}        # id(Finding) -> (remedio, registros)
        self._remedies: Dict[int, Optional[mit.Remedy]] = {}          # caché: remedy_for sondea el registro
        self._mitigating = False
        self._diag_note = "Sin ejecutar en esta sesión."
        self._ports_note = "Sin auditar en esta sesión."

        self.header_status = HeaderStatus()
        self.add_header_widget(self.header_status)
        self.root.addLayout(self._build_metrics())
        self.root.addLayout(self._build_operations())
        self.root.addLayout(self._build_toolbar())
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_diag_tab(), icon("fa5s.shield-alt"), "Diagnóstico completo")
        self.tabs.addTab(self._build_ports_tab(), icon("fa5s.satellite-dish"), "Telemetría de puertos")
        self.root.addWidget(self.tabs, 1)
        self._update_counters()

    # =============================================================================================
    # Construcción
    # =============================================================================================
    def _build_metrics(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        self._metric_cards = [
            BentoCard("fa5s.tachometer-alt", "Puntuación global", "Diagnóstico, puertos y Arsenal ponderados en vivo.",
                      self._status_score, lambda: self.app._select("comando")),
            BentoCard("fa5s.exclamation-triangle", "Riesgos pendientes", "CRITICAL y WARNING sin mitigar.",
                      self._status_risks, lambda: self._set_filter("critical")),
            BentoCard("fa5s.globe", "Puertos expuestos", "Escuchan fuera de 127.0.0.1 / ::1.",
                      self._status_exposed, lambda: self._set_filter("exposed")),
            BentoCard("fa5s.check-double", "Vectores mitigados", "Correcciones aplicadas en esta sesión.",
                      self._status_mitigated, lambda: self._set_filter("mitigated")),
        ]
        for card in self._metric_cards:
            row.addWidget(card, 1)
        return row

    def _build_operations(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        n = len(self.app.modules)
        self.diag_tile = Tile("fa5s.shield-alt", "Diagnóstico completo",
                              f"{n} plugins en solo lectura: hardening, cuentas, firewall, persistencia, telemetría "
                              "e inyecciones.", level="card")
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.diag_tile.body.addWidget(self.progress)
        self.run_btn = self.diag_tile.add_action(action_button("Iniciar diagnóstico", "fa5s.play", "Primary",
                                                                self.start))
        self.ports_tile = Tile("fa5s.satellite-dish", "Auditoría de puertos",
                               "Inventario de sockets en escucha cruzado con la tabla de servicios de riesgo del "
                               "plugin de puertos.", level="card")
        self.ports_btn = self.ports_tile.add_action(action_button("Auditar puertos", "fa5s.search", "Primary",
                                                                  self.audit_ports))
        if self._ports_backend is None:
            self.ports_btn.setEnabled(False)
            self.ports_btn.setToolTip("El plugin de puertos (modulos/04_puertos.py) no está disponible.")
        self.fix_tile = Tile("fa5s.magic", "Mitigación en lote",
                             "Corrige en un paso los vectores CRITICAL y WARNING con remediación automática. "
                             "Transaccional: si un paso falla, se deshacen los anteriores.", level="card")
        self.fix_btn = self.fix_tile.add_action(action_button("Mitigar riesgos detectados", "fa5s.magic", "Danger",
                                                              self.mitigate_all))
        for tile in (self.diag_tile, self.ports_tile, self.fix_tile):
            row.addWidget(tile, 1)
        return row

    def _build_toolbar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)
        cap = QLabel("FILTRAR")
        cap.setObjectName("ChipCap")
        bar.addWidget(cap)
        self._filter = "all"
        self._filter_group = QButtonGroup(self)
        self._filter_group.setExclusive(True)
        self._filter_btns: Dict[str, QPushButton] = {}
        for key, text in FILTERS:
            chip = QPushButton(text)
            chip.setObjectName("Chiplet")
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.clicked.connect(lambda _=False, k=key: self._set_filter(k))
            self._filter_group.addButton(chip)
            self._filter_btns[key] = chip
            bar.addWidget(chip)
        self._filter_btns["all"].setChecked(True)
        bar.addStretch(1)
        self.report_btn = action_button("Exportar informe", "fa5s.file-export", "Ghost",
                                        lambda: export_report(self.app))
        self.report_btn.setToolTip(tech_tip("Informe de auditoría técnica (HTML)", [REPORTS_DIR],
                                            "Puntuación, vectores mitigados, riesgos pendientes, Arsenal y puertos."))
        bar.addWidget(self.report_btn)
        return bar

    def _build_diag_tab(self) -> QWidget:
        host = QWidget()
        host.setObjectName("Content")
        lay = QVBoxLayout(host)
        lay.setContentsMargins(0, 10, 0, 0)
        lay.setSpacing(12)
        self.table = make_table(["Nivel", "Módulo", "Hallazgo", "Acción directa"], widths=[118, 190, 420, 150],
                                empty="Pulsa «Iniciar diagnóstico» para auditar los vectores de este equipo "
                                      "(solo lectura).", empty_icon="fa5s.shield-alt")
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setMinimumHeight(260)
        self.table.itemSelectionChanged.connect(self._show_finding)
        self.finding_inspector = Inspector("INTELIGENCIA DEFENSIVA", "ACCIÓN DIRECTA")
        self.harden_btn = action_button("Aplicar", "fa5s.magic", "Danger", self._harden_selected)
        self.undo_btn = action_button("Deshacer mitigación", "fa5s.undo", "Ghost", self._undo_selected)
        self.copy_btn = action_button("Copiar comandos", "fa5s.copy", "Mini", self._copy_targets)
        for btn in (self.harden_btn, self.undo_btn, self.copy_btn):
            self.finding_inspector.actions.addWidget(btn)
        lay.addWidget(self.table, 1)
        lay.addWidget(self.finding_inspector)
        return host

    def _build_ports_tab(self) -> QWidget:
        host = QWidget()
        host.setObjectName("Content")
        lay = QVBoxLayout(host)
        lay.setContentsMargins(0, 10, 0, 0)
        lay.setSpacing(12)
        self.port_table = make_table(["", "Riesgo", "Proto", "Dirección local", "Puerto", "Servicio", "Proceso", "PID"],
                                     widths=[34, 110, 64, 170, 74, 150, 190],
                                     empty="Pulsa «Auditar puertos» para inventariar los puertos en escucha de este "
                                           "equipo.", empty_icon="fa5s.satellite-dish")
        self.port_table.setMinimumHeight(260)
        self.port_table.itemSelectionChanged.connect(self._show_port)
        self.port_inspector = Inspector("POR QUÉ ES UN VECTOR DE RIESGO", "ACCIÓN DIRECTA")
        self.block_btn = action_button("Bloquear en el firewall", "fa5s.ban", "Danger", self._block_port)
        self.kill_btn = action_button("Finalizar proceso propietario", "fa5s.times-circle", "Danger", self._kill_owner)
        self.port_undo_btn = action_button("Eliminar regla de bloqueo", "fa5s.undo", "Ghost", self._undo_port)
        self.port_copy_btn = action_button("Copiar comando", "fa5s.copy", "Mini", self._copy_port)
        for btn in (self.block_btn, self.kill_btn, self.port_undo_btn, self.port_copy_btn):
            self.port_inspector.actions.addWidget(btn)
        lay.addWidget(self.port_table, 1)
        lay.addWidget(self.port_inspector)
        return host

    # =============================================================================================
    # Estado global, métricas y contadores
    # =============================================================================================
    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._update_counters()  # la nota depende también del Arsenal: se relee al volver

    def _busy_changed(self) -> None:
        self._refresh_status()

    def _refresh_status(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.header_status.set_state(f"ANALIZANDO · {self.progress.value()} %", COLORS["accent"])
        elif self._mitigating:
            self.header_status.set_state("MITIGANDO", COLORS["accent"])
        elif self.running:
            self.header_status.set_state(f"EN CURSO · {self.running}", COLORS["accent"])
        else:
            result, step, _inputs = compute_security(self.app)
            if result is None:
                self.header_status.set_state("SIN MEDIR", COLORS["faint"], f"➜ {step}")
            else:
                self.header_status.set_state(f"{result['score']}/100 · {result['letter']} {result['label']}",
                                             ScoreRing.color_for(result["score"]), f"➜ {step}")
        self.header_status.set_admin(bool(getattr(self.app, "admin", False)))

    def _remedy(self, finding) -> Optional[mit.Remedy]:
        key = id(finding)
        if key not in self._remedies:
            try:
                self._remedies[key] = mit.remedy_for(finding)
            except Exception:  # noqa: BLE001  (un sondeo del registro fallido no rompe la tabla)
                self._remedies[key] = None
        return self._remedies[key]

    @staticmethod
    def _port_remedy(row: dict) -> mit.Remedy:
        return mit.port_block_remedy(row["proto"], row["port"])

    def _counts(self) -> dict:
        """Lo lee también ui/informe.py (riesgos pendientes de la Puntuación de Seguridad)."""
        ports = self._port_rows or []
        live_ports = [r for r in ports if not r.get("mitigated")]
        live = [f for f in self.findings if id(f) not in self._fixed]
        return {"all": len(ports) + len(self.findings),
                "critical": sum(1 for r in live_ports if r["severity"] is CRITICAL)
                + sum(1 for f in live if f.severity is CRITICAL),
                "warning": sum(1 for r in live_ports if r["severity"] is WARNING)
                + sum(1 for f in live if f.severity is WARNING),
                "exposed": sum(1 for r in live_ports if r["exposed"]),
                "mitigated": len(self._fixed) + sum(1 for r in ports if r.get("mitigated"))}

    def _pending(self) -> List[Tuple[Target, mit.Remedy]]:
        """(objetivo, remedio) pendientes: puertos de riesgo expuestos y hallazgos con remediación."""
        out: List[Tuple[Target, mit.Remedy]] = [
            (r, self._port_remedy(r)) for r in self._port_rows or []
            if r["exposed"] and r["severity"] in (CRITICAL, WARNING) and not r.get("mitigated")]
        for f in self.findings:
            remedy = None if id(f) in self._fixed else self._remedy(f)
            if remedy is not None:
                out.append((f, remedy))
        return out

    def _update_counters(self) -> None:
        counts = self._counts()
        for key, text in FILTERS:
            label = f"{text} · {counts[key]}"
            if self._filter_btns[key].text() != label:
                self._filter_btns[key].setText(label)
        pending = self._pending()
        batch = [(t, r) for t, r in pending if r.batch]
        manual = [r for _t, r in pending if not r.batch]
        known = self._port_rows is not None or self.findings or self.last_result is not None
        risks = counts["critical"] + counts["warning"]
        self.diag_tile.set_pill(_n(len(self.findings), "HALLAZGO", "HALLAZGOS") if self.findings else "",
                                COLORS["danger"] if any(f.severity is CRITICAL for f in self.findings) else COLORS["text2"])
        self.diag_tile.set_note(self._diag_note)
        exposed = counts["exposed"]
        self.ports_tile.set_pill("" if self._port_rows is None else _n(exposed, "EXPUESTO", "EXPUESTOS"),
                                 COLORS["warn"] if exposed else COLORS["ok"])
        self.ports_tile.set_note(self._ports_note)
        self.fix_tile.set_pill(_n(len(batch), "LISTA", "LISTAS") if known else "",
                               COLORS["danger"] if counts["critical"] else COLORS["warn"] if batch else COLORS["ok"])
        if not known:
            note = "Lanza el diagnóstico o la auditoría de puertos para detectar riesgos."
        elif not pending:
            note = "Nada que mitigar automáticamente." if not risks else f"{risks} riesgo(s) sin remediación automática: sigue la recomendación."
        else:
            note = f"{len(batch)} remediación(es) en lote" + (f" · {len(manual)} solo individual" if manual else "")
        self.fix_tile.set_note(note)
        self.fix_btn.setEnabled(bool(batch) and not self._mitigating and not self.fix_btn.property("busy"))
        jobs = {r.key: r for _t, r in batch}
        self.fix_btn.setToolTip(tech_tip(f"Mitigar {len(batch)} riesgo(s) · {len(jobs)} remediación(es)",
                                         [f"{r.label}: {t}" for r in list(jobs.values())[:6] for t in r.targets()[:2]],
                                         "Una sola confirmación con lo exacto; cada paso se verifica.")
                                if batch else "No hay riesgos con remediación automática en lote.")
        for card in self._metric_cards:
            card.refresh()
        self._refresh_status()

    def _status_score(self):
        result, step, _inputs = compute_security(self.app)
        if result is None:
            return (False, "Lanza el diagnóstico para medir el equipo", "—")
        return (ScoreRing.color_for(result["score"]), f"{result['letter']} · {result['label']}", f"{result['score']}/100")

    def _status_risks(self):
        if self._port_rows is None and not self.findings:
            return (False, "Sin analizar todavía", "—")
        counts = self._counts()
        crit, warn = counts["critical"], counts["warning"]
        color = COLORS["danger"] if crit else COLORS["warn"] if warn else COLORS["ok"]
        return (color, f"{crit} CRITICAL · {warn} WARNING" if crit + warn else "Ningún riesgo pendiente", str(crit + warn))

    def _status_exposed(self):
        rows = self._port_rows
        if rows is None:
            return (False, "Sin auditar todavía", "—")
        exposed = self._counts()["exposed"]
        risky = sum(1 for r in rows if r["exposed"] and r["severity"] in (CRITICAL, WARNING) and not r.get("mitigated"))
        return (COLORS["warn"] if exposed else COLORS["ok"], f"de {len(rows)} en escucha · {risky} de riesgo", str(exposed))

    def _status_mitigated(self):
        count = self._counts()["mitigated"]
        undoable = sum(1 for remedy, _r in self._journal.values() if remedy.undoable) + sum(
            1 for r in self._port_rows or [] if r.get("_undo"))
        return (COLORS["ok"] if count else False, f"{undoable} con «Deshacer» disponible" if count else "Ninguno todavía",
                str(count))

    # =============================================================================================
    # Filtros
    # =============================================================================================
    def _set_filter(self, key: str) -> None:
        self._filter = key
        self._filter_btns[key].setChecked(True)
        if key == "exposed":
            self.tabs.setCurrentIndex(1)  # los puertos expuestos viven en la telemetría de puertos
        self._apply_filter()

    def _port_visible(self, row: dict) -> bool:
        f, done = self._filter, bool(row.get("mitigated"))
        return (f == "all" or (f == "critical" and row["severity"] is CRITICAL and not done)
                or (f == "warning" and row["severity"] is WARNING and not done)
                or (f == "exposed" and row["exposed"] and not done) or (f == "mitigated" and done))

    def _finding_visible(self, finding) -> bool:
        f, done = self._filter, id(finding) in self._fixed
        return (f == "all" or (f == "critical" and finding.severity is CRITICAL and not done)
                or (f == "warning" and finding.severity is WARNING and not done)
                or (f == "exposed" and finding.module == "puertos") or (f == "mitigated" and done))

    def _apply_filter(self) -> None:
        """Oculta/muestra filas sin rehacer las tablas (setRowHidden: sin re-render completo)."""
        for r, row in enumerate(self._port_rows or []):
            self.port_table.setRowHidden(r, not self._port_visible(row))
        for r, finding in enumerate(self.findings):
            self.table.setRowHidden(r, not self._finding_visible(finding))

    # =============================================================================================
    # Diagnóstico completo (todos los plugins)
    # =============================================================================================
    def start(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        if not self.app.modules:
            Toast.notify(self.app, "x", "Diagnóstico", "No hay ningún plugin válido en modulos/.", "fa5s.shield-alt")
            return
        self.findings, self._fixed, self._journal, self._remedies = [], {}, {}, {}
        self.finding_inspector.setVisible(False)
        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.tabs.setCurrentIndex(0)
        set_busy(self.run_btn, True, "Analizando…")  # el diagnóstico usa su propio QThread (progreso en streaming)
        self._diag_note = "Analizando…"
        self.app.log_tactical(f"Diagnóstico iniciado · {len(self.app.modules)} módulos (solo lectura)")
        self.worker = AuditWorker(self.app.modules, self.app.admin)
        self.worker.progress.connect(self._progress)
        self.worker.found.connect(self._finding)
        self.worker.report_ready.connect(self._finished)
        self.worker.failed.connect(self._failed)
        self.worker.start()
        self._update_counters()

    def _progress(self, index: int, total: int, title: str) -> None:
        self.progress.setValue(int((index - 1) / total * 100))
        self.diag_tile.set_note(f"Analizando: {title} ({index}/{total})")
        self.app.console.log("~", f"Módulo {index}/{total}: {title}")
        self._refresh_status()

    def _finding(self, finding) -> None:
        self.findings.append(finding)
        r = self.table.rowCount()
        self.table.insertRow(r)
        remedy = self._remedy(finding)
        action = ("UAC" if mit.needs_elevation(finding) else " · ".join(remedy.mechanisms) if remedy else "—")
        cells = [finding.severity.value, self.app.module_titles.get(finding.module, finding.module), finding.title, action]
        for col, text in enumerate(cells):
            item = QTableWidgetItem(text)
            if col == 0:
                item.setForeground(QColor(SEVERITY_COLORS[finding.severity]))
            elif col == 3:
                item.setForeground(QColor(COLORS["text"] if action != "—" else COLORS["faint"]))
                if remedy is not None:
                    item.setToolTip(tech_tip(remedy.label, remedy.targets()))
            self.table.setItem(r, col, item)
        self.table.setRowHidden(r, not self._finding_visible(finding))
        if finding.severity in (CRITICAL, WARNING):
            self.app.console.log("!", f"{finding.severity.value} · {finding.title}")
            self._update_counters()  # contador en vivo mientras llegan los riesgos

    def _finished(self, report) -> None:
        self.progress.setValue(100)
        set_busy(self.run_btn, False)
        score, c, w = report.score(), report.count(CRITICAL), report.count(WARNING)
        self.last_result = (score, c, w)  # lo lee el panel de salud del Centro de Comando
        self._diag_note = f"Último: {dt.datetime.now():%H:%M} · {c} CRITICAL · {w} WARNING · {score}/100"
        self.app.log_tactical(f"Diagnóstico completado · {c} CRITICAL · {w} WARNING · {score}/100")
        _emit_event(self.app, source="vectores:diagnostico", event_type="audit.completed",
                    payload={"score": score, "critical": c, "warning": w, "findings": len(self.findings),
                             "auto_fixable": len(self._pending())})
        self._update_counters()
        Toast.notify(self.app, "x" if c else "!" if w else "*", "Diagnóstico completo",
                     f"{c} CRITICAL · {w} WARNING · {score}/100", "fa5s.shield-alt")

    def _failed(self, msg: str) -> None:
        set_busy(self.run_btn, False)
        self._diag_note = f"Error: {msg}"
        self.app.console.log("x", f"Diagnóstico: {msg}")
        self._update_counters()

    # =============================================================================================
    # Auditoría de puertos
    # =============================================================================================
    def audit_ports(self) -> None:
        if self._ports_backend is None or self.ports_btn.property("busy"):
            return
        self.tabs.setCurrentIndex(1)
        self._ports_note = "Inventariando puertos en escucha…"
        self.app.log_tactical("Auditoría de puertos iniciada (solo lectura)")
        backend = self._ports_backend
        self.run_action(self.ports_btn, "Auditando…", lambda emit: audit_ports(backend), self._ports_done)
        self._update_counters()

    def _ports_done(self, ok: bool, rows) -> None:
        if not ok or not isinstance(rows, list):
            self._ports_note = f"Error: {rows}"
            self.finish(self.ports_btn, "x", "Auditoría de puertos", f"No se pudo completar: {rows}",
                        "fa5s.satellite-dish", source="vectores:puertos", event_type="audit.ports_failed",
                        payload={"error": str(rows)})
            self._update_counters()
            return
        self._port_rows = rows
        self.port_inspector.setVisible(False)
        table = self.port_table
        if not rows:
            table.set_empty_text("No hay ningún puerto en escucha en este equipo.", "fa5s.check-circle")
        with frozen(table):
            table.setRowCount(len(rows))
            for r, row in enumerate(rows):
                self._paint_port_row(r, row)
        crit = sum(1 for r in rows if r["severity"] is CRITICAL)
        warn = sum(1 for r in rows if r["severity"] is WARNING)
        exposed = sum(1 for r in rows if r["exposed"])
        text = f"{len(rows)} en escucha · {exposed} expuestos · {crit} críticos · {warn} avisos"
        self._ports_note = f"Último: {dt.datetime.now():%H:%M} · {text}"
        self._apply_filter()
        self._update_counters()
        self.finish(self.ports_btn, "x" if crit else "!" if warn else "*", "Auditoría de puertos", text,
                    "fa5s.satellite-dish", source="vectores:puertos", event_type="audit.ports",
                    payload={"listening": len(rows), "exposed": exposed, "critical": crit, "warning": warn})

    def _paint_port_row(self, r: int, row: dict) -> None:
        done = bool(row.get("mitigated"))
        color = QColor(COLORS["ok"] if done else SEVERITY_COLORS[row["severity"]])
        dot = QTableWidgetItem("✔" if done else "●")
        dot.setForeground(color)
        dot.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        risk = QTableWidgetItem("MITIGADO" if done else row["severity"].value)
        risk.setForeground(color)
        cells = [dot, risk] + [QTableWidgetItem(v) for v in (
            row["proto"], row["ip"], str(row["port"]), row["service"], row["process"],
            str(row["pid"]) if row["pid"] is not None else "—")]
        for c, item in enumerate(cells):
            self.port_table.setItem(r, c, item)

    def _selected_port(self) -> Optional[dict]:
        r = self.port_table.currentRow()
        return self._port_rows[r] if self._port_rows and 0 <= r < len(self._port_rows) else None

    @staticmethod
    def _protected(row: dict) -> bool:
        """Misma regla que el Monitor en Vivo: nunca finalizar procesos críticos de Windows ni Lozarus."""
        return row["pid"] in (0, 4, os.getpid()) or (row["process"] or "").lower() in PROTECTED_PROCS

    def _show_port(self) -> None:
        row = self._selected_port()
        if row is None:
            self.port_inspector.setVisible(False)
            return
        remedy, done = self._port_remedy(row), row.get("mitigated")
        state = MITIGATED if done else row["severity"].value
        color = COLORS["ok"] if done else SEVERITY_COLORS[row["severity"]]
        where = "expuesto en la red" if row["exposed"] else "solo local"
        risk = f"{row['why']}\n{RISK_EXPOSED if row['exposed'] else RISK_LOCAL}"
        fields = [("Riesgo", risk, False), ("Regla propuesta", remedy.targets()[0], True),
                  ("Impacto de la corrección", remedy.impact, False)]
        if done:
            fields.insert(0, ("Estado", f"Mitigado: {done}.", False))
        self.port_inspector.show_item(state, color, f"{row['proto']} {row['ip']}:{row['port']} · {row['service']} · "
                                                    f"{row['process']} · {where}",
                                      f"Puerto {row['port']}/{row['proto']} en escucha", fields,
                                      mit.MECHANISMS["NETSH"], "Requiere Administrador · se registra en la Caja Negra.")
        killable = row["pid"] is not None and not self._protected(row)
        self.block_btn.setVisible(not done)
        self.block_btn.setEnabled(not self._mitigating)
        self.kill_btn.setVisible(not done)
        self.kill_btn.setEnabled(killable)
        self.kill_btn.setToolTip(tech_tip("Finalizar proceso propietario",
                                          [f"psutil.Process({row['pid']}).terminate()  # {row['process']}"],
                                          "Pide confirmación; no se puede deshacer.") if killable
                                 else "Proceso protegido del sistema o PID desconocido.")
        self.port_undo_btn.setVisible(bool(row.get("_undo")))

    def _block_port(self) -> None:
        row = self._selected_port()
        if row is not None and not row.get("mitigated"):
            self._run_remedies([(row, self._port_remedy(row))], self.block_btn, "Bloquear puerto en el firewall")

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
            self._mark(row, None, [], f"proceso «{row['process']}» (PID {row['pid']}) finalizado")

    def _copy_port(self) -> None:
        row = self._selected_port()
        if row is not None:
            QGuiApplication.clipboard().setText(self._port_remedy(row).targets()[0])
            self.app.console.log("~", "Comando copiado al portapapeles")

    # =============================================================================================
    # Inspector de hallazgos
    # =============================================================================================
    def _selected_finding(self):
        r = self.table.currentRow()
        return self.findings[r] if 0 <= r < len(self.findings) and self.table.selectedItems() else None

    def _show_finding(self) -> None:
        f = self._selected_finding()
        if f is None:
            self.finding_inspector.setVisible(False)
            return
        module = self.app.module_titles.get(f.module, f.module)
        done = self._fixed.get(id(f))
        state = MITIGATED if done else f.severity.value
        color = COLORS["ok"] if done else SEVERITY_COLORS[f.severity]
        if mit.needs_elevation(f):
            admin = getattr(self.app, "admin", False)
            self.finding_inspector.show_item(state, color, module, f.title, [
                ("Detalle técnico", f.detail, False),
                ("Impacto", "Una comprobación omitida es un punto ciego: con privilegios se audita completa.", False)],
                "UAC · ShellExecute runas",
                "Ya se ejecuta como Administrador: repite el diagnóstico." if admin else
                "Relanza Lozarus elevado y repite el diagnóstico.")
            self._set_inspector_actions(harden=None if admin else "Relanzar como Administrador",
                                        harden_icon="fa5s.user-shield")
            return
        remedy = self._remedy(f)
        if remedy is None:
            self.finding_inspector.show_item(state, color, module, f.title, [
                ("Detalle técnico", f.detail, False), ("Recomendación", f.recommendation, False)], "",
                "Sin remediación automática segura: sigue la recomendación." if f.severity in (CRITICAL, WARNING)
                else "Hallazgo informativo: no requiere acción.")
            self._set_inspector_actions()
            return
        flags = ["requiere reiniciar"] * remedy.reboot + ["no admite deshacer"] * (not remedy.undoable) + \
            ["solo individual"] * (not remedy.batch)
        impact = remedy.impact + (f" ({' · '.join(flags)})" if flags else "")
        risk = remedy.protects + (f"\n\nDetectado: {f.detail}" if f.detail else "")
        fields = [("Riesgo", risk, False), ("Clave afectada", "\n".join(remedy.targets()), True),
                  ("Impacto de la corrección", impact, False), ("Recomendación", f.recommendation, False)]
        if done:
            fields[3] = ("Estado", f"Mitigado: {done}.", False)
        note = ("Requiere Administrador · " if remedy.admin else "") + "verificación tras escribir · antes/después en la Caja Negra"
        self.finding_inspector.show_item(state, color, module, f.title, fields,
                                         " · ".join(mit.MECHANISMS[m] for m in remedy.mechanisms), note)
        self._set_inspector_actions(harden=None if done else remedy.label, harden_icon=remedy.icon,
                                    undo=bool(done) and id(f) in self._journal and remedy.undoable)

    def _set_inspector_actions(self, harden: Optional[str] = None, harden_icon: str = "fa5s.magic",
                               undo: bool = False) -> None:
        self.harden_btn.setVisible(harden is not None)
        if harden is not None and not self.harden_btn.property("busy"):
            self.harden_btn.setText(harden)
            self.harden_btn.setIcon(icon(harden_icon, COLORS["danger"]))
            self.harden_btn.setEnabled(not self._mitigating)
        self.undo_btn.setVisible(undo)
        self.copy_btn.setVisible(harden is not None and harden != "Relanzar como Administrador" or undo)

    def _harden_selected(self) -> None:
        f = self._selected_finding()
        if f is None or id(f) in self._fixed:
            return
        if mit.needs_elevation(f):
            self.app.relaunch_as_admin()
            return
        remedy = self._remedy(f)
        if remedy is not None:
            self._run_remedies([(f, remedy)], self.harden_btn, remedy.label)

    def _copy_targets(self) -> None:
        f = self._selected_finding()
        remedy = self._remedy(f) if f is not None else None
        if remedy is not None:
            QGuiApplication.clipboard().setText("\n".join(remedy.targets()))
            self.app.console.log("~", f"{remedy.label}: comandos copiados al portapapeles")

    # =============================================================================================
    # Mitigación (individual y en lote) y deshacer
    # =============================================================================================
    def mitigate_all(self) -> None:
        pending = self._pending()
        batch = [(t, r) for t, r in pending if r.batch]
        manual = [r for _t, r in pending if not r.batch]
        self._run_remedies(batch, self.fix_btn, "Mitigar riesgos detectados", manual)

    def _run_remedies(self, targets: List[Tuple[Target, mit.Remedy]], button: QPushButton, title: str,
                      manual: Optional[List[mit.Remedy]] = None) -> None:
        """Privilegios → una confirmación con lo exacto → aplicación transaccional en segundo plano."""
        if not targets or self._mitigating:
            return
        if not IS_WINDOWS:
            Toast.notify(self.app, "!", title, "Las remediaciones solo existen en Windows.", "fa5s.magic")
            return
        jobs: Dict[str, mit.Remedy] = {}
        for _target, remedy in targets:
            jobs.setdefault(remedy.key, remedy)
        if any(r.admin for r in jobs.values()) and not self.admin_ok(
                title, "Las correcciones escriben en HKLM, en el firewall o en las directivas de seguridad."):
            return
        lines = []
        for remedy in jobs.values():
            lines.append(f"• {remedy.label}" + ("  (requiere reiniciar)" if remedy.reboot else ""))
            lines.extend(f"    {t}" for t in remedy.targets())
        footer = "Cada paso se verifica tras escribirse; si uno falla, se deshacen los anteriores. El antes y el " \
                 "después quedan en la Caja Negra."
        if manual:
            footer += f"\nQuedan fuera {len(manual)} corrección(es) de revisión individual: " + \
                      ", ".join(dict.fromkeys(r.label for r in manual)) + "."
        if len(targets) == 1:
            intro = f"{targets[0][1].protects}"
        else:
            intro = f"Se aplicarán {len(jobs)} remediaciones sobre {len(targets)} riesgos."
        if not self.confirm_exact(title, intro, lines, footer=footer, limit=16):
            return
        self._mitigating = True
        work = list(jobs.items())
        self.app.log_tactical(f"Mitigación: {len(work)} remediación(es) · {len(targets)} riesgo(s)")

        def run(emit):
            results = {}
            for key, remedy in work:
                emit("~", f"Mitigación · {remedy.label}…")
                results[key] = mit.apply_remedy(remedy)
            return results

        self.run_action(button, "Mitigando…", run,
                        lambda ok, res: self._remedies_done(targets, jobs, button, title, ok, res))
        self._update_counters()

    def _remedies_done(self, targets, jobs: Dict[str, mit.Remedy], button, title: str, ok: bool, res) -> None:
        self._mitigating = False
        results = res if ok and isinstance(res, dict) else {}
        failed: List[str] = []
        arsenal_touched = False
        for key, remedy in jobs.items():
            result = results.get(key) or {"ok": False, "error": str(res)}
            payload = mit.event_payload(remedy, result)
            payload["objetivos"] = [self._describe_target(t) for t, r in targets if r.key == key]
            _emit_event(self.app, source=SOURCE, event_type="finding.mitigated" if result["ok"]
                        else "finding.mitigation_failed", payload=payload)
            if result["ok"]:
                arsenal_touched |= any(isinstance(s, mit.ArsenalTweak) for s in remedy.steps)
                self.app.console.log("*", f"{remedy.label}: aplicado y verificado ({remedy.mechanism})")
            else:
                note = " · cambios previos revertidos" if result.get("rolled_back") else ""
                failed.append(f"{remedy.label}: {result.get('error')}")
                self.app.console.log("x", f"{remedy.label}: {result.get('error')}{note}")
        done = 0
        for target, remedy in targets:
            result = results.get(remedy.key)
            if result and result["ok"]:
                done += 1
                self._mark(target, remedy, result["records"], f"{remedy.label} ({remedy.mechanism})")
        if len(targets) == 1:
            text = f"{jobs[targets[0][1].key].label}: aplicado y verificado." if done else failed[0]
        else:
            text = f"{done} de {len(targets)} riesgos mitigados." + (f" Fallo: {failed[0]}" if failed else "")
        reboot = [r.label for k, r in jobs.items() if r.reboot and (results.get(k) or {}).get("ok")]
        if reboot:
            text += " Reinicia el equipo para completar: " + ", ".join(reboot) + "."
        kind = "*" if not failed else "!" if done else "x"
        self._rescore()
        self.finish(button, kind, title, text, "fa5s.magic", source=SOURCE, event_type="audit.mitigation_batch",
                    payload={"targets": len(targets), "remedies": len(jobs), "mitigated": done, "failed": failed,
                             "reboot": reboot, "score": self.last_result[0] if self.last_result else None})
        if arsenal_touched:
            arsenal = getattr(self.app, "pages", {}).get("arsenal")
            if arsenal is not None and hasattr(arsenal, "refresh"):
                arsenal.refresh()  # sus badges pasan a ✔ APLICADO (y la puntuación del Arsenal sube)
        self._after_change()

    @staticmethod
    def _describe_target(target) -> str:
        if isinstance(target, dict):
            return f"puerto {target['proto']} {target['port']} ({target['process']})"
        return f"{target.severity.value} · {target.title}"

    def _mark(self, target, remedy: Optional[mit.Remedy], records: list, how: str) -> None:
        """Fila en verde ✔ MITIGADO; guarda el remedio y sus registros para «Deshacer»."""
        if isinstance(target, dict):
            target["mitigated"] = how
            if remedy is not None and remedy.undoable:
                target["_undo"] = (remedy, records)
            r = next(i for i, x in enumerate(self._port_rows) if x is target)
            self._paint_port_row(r, target)
            self.app.log_tactical(f"Puerto {target['proto']} {target['port']} MITIGADO: {how}")
            if remedy is None:
                self._after_change()
            return
        self._fixed[id(target)] = how
        if remedy is not None:
            self._journal[id(target)] = (remedy, records)
        r = next(i for i, x in enumerate(self.findings) if x is target)
        item = self.table.item(r, 0)
        item.setText(MITIGATED)
        item.setForeground(QColor(COLORS["ok"]))

    def _unmark(self, target) -> None:
        if isinstance(target, dict):
            target.pop("mitigated", None)
            target.pop("_undo", None)
            r = next(i for i, x in enumerate(self._port_rows) if x is target)
            self._paint_port_row(r, target)
            return
        self._fixed.pop(id(target), None)
        self._journal.pop(id(target), None)
        r = next(i for i, x in enumerate(self.findings) if x is target)
        item = self.table.item(r, 0)
        item.setText(target.severity.value)
        item.setForeground(QColor(SEVERITY_COLORS[target.severity]))

    def _undo_selected(self) -> None:
        f = self._selected_finding()
        entry = self._journal.get(id(f)) if f is not None else None
        if entry is not None:
            self._undo(f, entry[0], entry[1], self.undo_btn)

    def _undo_port(self) -> None:
        row = self._selected_port()
        if row is not None and row.get("_undo"):
            remedy, records = row["_undo"]
            self._undo(row, remedy, records, self.port_undo_btn)

    def _undo(self, target, remedy: mit.Remedy, records: list, button: QPushButton) -> None:
        if not remedy.undoable or self._mitigating:
            return
        if remedy.admin and not self.admin_ok(f"Deshacer · {remedy.label}"):
            return
        lines = mit.undo_preview(remedy, records) if records else []
        if not self.confirm_exact("Deshacer mitigación", f"Se restaurará el estado previo a «{remedy.label}».",
                                  lines, confirm_text="Deshacer", danger=True):
            return
        self.app.log_tactical(f"Deshaciendo mitigación: {remedy.label}")

        def done(ok: bool, res) -> None:
            good = ok and isinstance(res, dict) and res.get("ok")
            errors = res.get("errors") if isinstance(res, dict) else [str(res)]
            if good:
                self._unmark(target)
                self._rescore()
            self.finish(button, "*" if good else "x", "Deshacer mitigación",
                        f"{remedy.label}: estado previo restaurado." if good else f"{remedy.label}: {errors[0]}",
                        "fa5s.undo", source=SOURCE, event_type="finding.mitigation_undone",
                        payload={"remedy": remedy.key, "action": remedy.label, "ok": bool(good), "errors": errors,
                                 "objetivo": self._describe_target(target)})
            self._after_change()

        self.run_action(button, "Deshaciendo…", lambda emit: mit.undo_remedy(remedy, records), done)

    def on_firewall_rule_removed(self, rule_name: str) -> None:
        """La página de Red retiró una regla: si era un bloqueo de esta sesión, el puerto vuelve a pendiente."""
        changed = False
        for row in self._port_rows or []:
            undo = row.get("_undo")
            if undo and any(f"name={rule_name}" in t for t in undo[0].targets()):
                self._unmark(row)
                changed = True
        if changed:
            self._after_change()

    def _rescore(self) -> None:
        """Puntuación con la fórmula de Report.score(): cada riesgo mitigado cuenta como superado."""
        if self.last_result is None:
            return
        live = [f for f in self.findings if id(f) not in self._fixed]
        passed = sum(1 for f in self.findings if f.severity is PASS) + len(self._fixed)
        crit = sum(1 for f in live if f.severity is CRITICAL)
        warn = sum(1 for f in live if f.severity is WARNING)
        total = passed + warn + 3 * crit
        self.last_result = (round(100 * passed / total) if total else 100, crit, warn)

    def _after_change(self) -> None:
        self._update_counters()
        self._apply_filter()
        self._show_port()
        self._show_finding()
