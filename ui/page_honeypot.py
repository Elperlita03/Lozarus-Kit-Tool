"""
ui/page_honeypot.py · LOZARUS KIT TOOL

Página HONEYPOT: archivos trampa vigilados por el motor de engaño (solo detecta y avisa).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QSplitter,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from ui.theme import COLORS
from ui.widgets import Page, frozen, make_table, stat_chip, with_icon

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow


class HoneypotPage(Page):
    """
    Campo de señuelos (Honeypot): despliega trampas, vigila su integridad EN VIVO, registra cada
    ataque en la Caja Negra y (opcional) reconstruye los cebos. Solo observa y registra.
    """

    def __init__(self, app: "MainWindow"):
        super().__init__("Campo de Señuelos (Honeypot)",
                         "Despliega trampas señuelo y vigila su integridad en tiempo real. Detecta "
                         "modificación y borrado, lo graba en la Caja Negra y puede reconstruir los "
                         "cebos. Solo observa: no actúa contra ningún proceso.", "fa5s.eye")
        self.app = app
        self.engine = getattr(app, "honeypot", None)
        self._seen = 0  # incidentes ya volcados a la consola de alertas
        self._last_sig = None  # última firma pintada (para repintar solo si algo cambió)

        if self.engine is None:
            box = QFrame()
            box.setObjectName("Card")
            bl = QVBoxLayout(box)
            bl.setContentsMargins(18, 16, 18, 16)
            msg = QLabel("El motor de Honeypot no está disponible en esta sesión.")
            msg.setObjectName("CardText")
            bl.addWidget(msg)
            self.root.addWidget(box)
            self.root.addStretch(1)
            return

        self._build_controls()
        self._build_cards()
        # Tabla de cebos (arriba) y consola de alertas (abajo) en un QSplitter arrastrable, para que
        # ninguna de las dos quede aplastada al redimensionar.
        split = QSplitter(Qt.Orientation.Vertical)
        split.setObjectName("VSplit")
        split.setHandleWidth(6)
        split.addWidget(self._build_table())
        split.addWidget(self._build_alert_console())
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setCollapsible(0, False)
        self.root.addWidget(split, 1)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)   # refresco en vivo cada segundo
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    # --- cabecera de control --------------------------------------------------------------
    def _build_controls(self) -> None:
        box = QFrame()
        box.setObjectName("Card")
        lay = QHBoxLayout(box)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(10)
        self.master_btn = QPushButton("Desplegar red de trampas")
        self.master_btn.setObjectName("Primary")
        with_icon(self.master_btn, "fa5s.network-wired")
        self.master_btn.clicked.connect(self._toggle_master)
        lay.addWidget(self.master_btn)
        self.rebuild_btn = QPushButton("Auto-Reconstrucción: OFF")
        self.rebuild_btn.setObjectName("Toggle")
        self.rebuild_btn.setCheckable(True)
        self.rebuild_btn.setChecked(bool(self.engine.auto_rebuild))
        with_icon(self.rebuild_btn, "fa5s.sync-alt", COLORS["muted"])
        self.rebuild_btn.clicked.connect(self._toggle_rebuild)
        lay.addWidget(self.rebuild_btn)
        self.open_btn = QPushButton("Abrir carpeta")
        self.open_btn.setToolTip(f"Abre en el Explorador la carpeta de cebos: {self.engine.decoy_dir}")
        self.open_btn.setObjectName("Ghost")
        with_icon(self.open_btn, "fa5s.folder-open", COLORS["muted"])
        self.open_btn.clicked.connect(self._open_folder)
        lay.addWidget(self.open_btn)
        self.custom_trap_btn = QPushButton("+ Trampa personalizada")
        self.custom_trap_btn.setObjectName("Mini")
        with_icon(self.custom_trap_btn, "fa5s.plus", COLORS["muted"])
        self.custom_trap_btn.setToolTip("Crea una trampa señuelo con el nombre que elijas.")
        self.custom_trap_btn.clicked.connect(self._create_custom_trap)
        lay.addWidget(self.custom_trap_btn)
        lay.addStretch(1)
        self.root.addWidget(box)

    # --- tarjetas de estado ---------------------------------------------------------------
    def _build_cards(self) -> None:
        row = QHBoxLayout()
        row.setSpacing(10)
        self.card_count, self._v_count = stat_chip("TRAMPAS ACTIVAS")
        self.card_integ, self._v_integ = stat_chip("INTEGRIDAD")
        self.card_inc, self._v_inc = stat_chip("INCIDENTES CAZADOS")
        for c in (self.card_count, self.card_integ, self.card_inc):
            row.addWidget(c)
        self.root.addLayout(row)

    # --- tabla de cebos -------------------------------------------------------------------
    def _build_table(self) -> QWidget:
        self.table = make_table(["Archivo trampa", "Tipo", "Ruta", "SHA-256", "Estado"],
                                widths=[190, 100, 300, 130],
                                empty="Red de trampas retirada. Pulsa «Desplegar red de trampas» para "
                                      "crear los cebos y vigilarlos en vivo.", empty_icon="fa5s.eye")
        self.table.setMinimumHeight(240)
        return self.table

    # --- consola de alertas de engaño -----------------------------------------------------
    def _build_alert_console(self) -> QWidget:
        host = QWidget()
        host.setObjectName("Content")
        lay = QVBoxLayout(host)
        lay.setContentsMargins(0, 2, 0, 0)
        lay.setSpacing(4)
        cap = QLabel("CONSOLA DE ALERTAS DE ENGAÑO")
        cap.setObjectName("ConsoleTitle")
        lay.addWidget(cap)
        self.alerts = QPlainTextEdit()
        self.alerts.setObjectName("Console")
        self.alerts.setReadOnly(True)
        self.alerts.setFont(QFont("Consolas", 10))
        self.alerts.setMinimumHeight(90)
        lay.addWidget(self.alerts, 1)
        return host

    # --- acciones -------------------------------------------------------------------------
    def _toggle_master(self) -> None:
        if self.engine.active:
            self.engine.stop()
            self.engine.retract()
            if self.app.tactical_config:
                self.app.tactical_config.set("hp_active", False)
            self.app.log_tactical("Honeypot: red de trampas RETIRADA")
        else:
            self.engine.deploy()
            self.engine.start()
            if self.app.tactical_config:
                self.app.tactical_config.set("hp_active", True)
            self.app.log_tactical(f"Honeypot: red de trampas DESPLEGADA en {self.engine.decoy_dir}")
        self.refresh()

    def _toggle_rebuild(self) -> None:
        on = self.rebuild_btn.isChecked()
        self.engine.auto_rebuild = on
        if self.app.tactical_config:
            self.app.tactical_config.set("hp_auto_rebuild", on)
        self.app.log_tactical(f"Honeypot: Auto-Reconstrucción {'ACTIVADA' if on else 'desactivada'}")
        self.refresh()

    def _open_folder(self) -> None:
        path = self.engine.decoy_dir
        try:
            os.makedirs(path, exist_ok=True)
            os.startfile(path)  # noqa: S606  (abrir el Explorador en la carpeta de cebos propia)
        except Exception as exc:  # noqa: BLE001
            self.app.console.log("x", f"No se pudo abrir la carpeta de cebos: {exc}")

    # --- refresco en vivo -----------------------------------------------------------------
    def refresh(self) -> None:
        # Los incidentes se vuelcan SIEMPRE (también con la pestaña oculta): son alertas de seguridad.
        self._drain_incidents()
        if not self.isVisible():
            return  # oculta: no repintar; al volver se pinta con el estado actual (firma distinta)
        st = self.engine.status()
        traps = self.engine.trap_list()
        firma = (st["active"], st["total"], st["integridad"], st["incidentes"], self.engine.auto_rebuild,
                 tuple((t["name"], t["state"], t["hash"]) for t in traps))
        if firma == self._last_sig:
            return  # nada cambió: no recrear 30 celdas ni re-aplicar estilos cada segundo
        self._last_sig = firma

        active = st["active"]
        self.master_btn.setText("Retirar red de trampas" if active else "Desplegar red de trampas")
        self.rebuild_btn.setText(f"Auto-Reconstrucción: {'ON' if self.engine.auto_rebuild else 'OFF'}")

        self._v_count.setText(str(st["total"]))
        if not active:
            self._v_integ.setText("—")
            self._v_integ.setStyleSheet("")
        elif st["integridad"]:
            self._v_integ.setText("100% Íntegro")
            self._v_integ.setStyleSheet("color:#22C55E; font-size:20px; font-weight:bold;")
        else:
            self._v_integ.setText("¡COMPROMETIDO!")
            self._v_integ.setStyleSheet("color:#EF4444; font-size:20px; font-weight:bold;")
        self._v_inc.setText(str(st["incidentes"]))

        with frozen(self.table):
            self.table.setRowCount(len(traps))
            for r, t in enumerate(traps):
                color = "#22C55E" if t["state"] == "Intacto" else "#EF4444"
                for c, v in enumerate([t["name"], t["tipo"], t["path"],
                                       t["hash"] + "…" if t["hash"] else "—", t["state"]]):
                    item = QTableWidgetItem(v)
                    if c == 4:
                        item.setForeground(QColor(color))
                    self.table.setItem(r, c, item)

    def _create_custom_trap(self) -> None:
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self.app, "Nueva trampa personalizada",
                                        "Nombre del archivo señuelo (con extensión, p.ej. informe_2026.pdf):")
        if not ok or not name.strip():
            return
        try:
            path = self.engine.add_custom_trap(name.strip())
            self.app.console.log("+", f"Trampa creada: {path}")
            self.app.log_tactical(f"Honeypot: trampa personalizada añadida «{name.strip()}»")
            self.refresh()
        except Exception as exc:  # noqa: BLE001
            self.app.console.log("x", f"No se pudo crear la trampa: {exc}")

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self.engine is not None:
            self.refresh()

    def _drain_incidents(self) -> None:
        for inc in self.engine.new_incidents(self._seen):
            marca = "grabado en Caja Negra" if inc["recorded"] else "sin bus"
            self.alerts.appendPlainText(
                f"[{inc['ts']}] ⚠ {inc['change'].upper()}: {inc['trap']} ({inc['tipo']}) · "
                f"sospechoso: {inc['suspect']} · {marca}")
            self.app.console.log("!", f"HONEYPOT: {inc['change']} de «{inc['trap']}» ({marca})")
            self.app.record_alert("x", f"Trampa {inc['change']}: «{inc['trap']}» ({inc['tipo']})",
                                  module="honeypot")
            self._seen += 1
