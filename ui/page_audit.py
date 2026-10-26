"""
ui/page_audit.py · LOZARUS KIT TOOL

Página ESCANEO DE VECTORES: auditoría estática con los plugins de modulos/ en segundo plano.
"""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Optional, Tuple

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QPlainTextEdit, QProgressBar, QPushButton,
                               QTableWidgetItem)

from modulos._base import CRITICAL, WARNING, AuditContext, Report

from ui.theme import SEVERITY_COLORS, SEVERITY_ORDER
from ui.widgets import Page, make_table, repolish, set_busy, stat_chip, with_icon

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow


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
    """Ejecuta los plugins de modulos/ (solo lectura) y muestra los hallazgos en vivo."""

    def __init__(self, app: "MainWindow"):
        super().__init__("Escaneo de Vectores (Estático)",
                         f"Ejecuta los {len(app.modules)} plugins de modulos/ en modo solo lectura y revisa cada hallazgo.",
                         "fa5s.shield-alt")
        self.app = app
        self.findings = []
        self.worker = None
        self.last_result: Optional[Tuple[int, int, int]] = None  # (puntuación, CRITICAL, WARNING)

        top = QHBoxLayout()
        top.setSpacing(10)
        self.run_btn = QPushButton("Ejecutar diagnóstico")
        self.run_btn.setObjectName("Primary")
        with_icon(self.run_btn, "fa5s.play")
        self.run_btn.clicked.connect(self.start)
        self.status = QLabel("Listo para analizar")
        self.status.setObjectName("StatusMuted")
        top.addWidget(self.run_btn)
        top.addWidget(self.status)
        top.addStretch(1)
        self.root.addLayout(top)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.root.addWidget(self.progress)

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
        self.root.addLayout(chips)

        self.table = make_table(["Nivel", "Módulo", "Hallazgo"], widths=[100, 220],
                                empty="Pulsa «Ejecutar diagnóstico» para auditar los vectores de "
                                      "este equipo (solo lectura).", empty_icon="fa5s.shield-alt")
        self.table.itemSelectionChanged.connect(self._show_detail)
        self.root.addWidget(self.table, 2)
        self.detail = QPlainTextEdit()
        self.detail.setObjectName("Detail")
        self.detail.setReadOnly(True)
        self.detail.setFixedHeight(118)
        self.detail.setPlainText("Selecciona un hallazgo de la tabla para ver su detalle y la recomendación.")
        self.root.addWidget(self.detail, 1)

    def start(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        if not self.app.modules:
            self.status.setText("No hay ningún plugin válido en modulos/")
            return
        self.findings = []
        self.table.setRowCount(0)
        for val in self.counts.values():
            val.setText("0")
        self.score.setText("—")
        self.progress.setValue(0)
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
        if finding.severity in (CRITICAL, WARNING):
            self.app.console.log("!", f"{finding.severity.value} · {finding.title}")

    def _finished(self, report) -> None:
        self.progress.setValue(100)
        set_busy(self.run_btn, False)
        score, c, w = report.score(), report.count(CRITICAL), report.count(WARNING)
        self.last_result = (score, c, w)  # lo lee el panel de salud del Centro de Comando
        self.score.setText(f"{score}/100")
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
