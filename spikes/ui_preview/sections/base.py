# -*- coding: utf-8 -*-
"""Clase base de todas las secciones: cabecera, botón de vuelta al Cuartel general y área con scroll."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QSizePolicy, QVBoxLayout, QWidget

from runtime import BetaContext
from widgets import action_button, hline, label, scroll_area


class Section(QWidget):
    KEY: str = ""
    TITLE: str = "Sección"
    NAV_LABEL: str = ""          # nombre corto para la barra lateral (por defecto, TITLE)
    KICKER: str = ""
    SUBTITLE: str = ""
    ICON: str = ""
    SHOW_BACK: bool = True

    def __init__(self, ctx: BetaContext, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.ctx = ctx

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        head = QWidget()
        hl = QVBoxLayout(head)
        hl.setContentsMargins(30, 20, 30, 13)
        hl.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(12)
        tcol = QVBoxLayout()
        tcol.setSpacing(2)
        if self.KICKER:
            tcol.addWidget(label(self.KICKER, "PageKicker", wrap=False))
        tcol.addWidget(label(self.TITLE, "PageTitle", wrap=False))
        top.addLayout(tcol)
        top.addStretch(1)
        if self.SHOW_BACK:
            back = action_button("Cuartel general", "fa5s.arrow-left", "Mini")
            back.setToolTip("Volver a la pantalla principal")
            back.clicked.connect(lambda: self.ctx.navigate.emit("hq"))
            top.addWidget(back, 0, Qt.AlignmentFlag.AlignTop)
        hl.addLayout(top)
        if self.SUBTITLE:
            hl.addWidget(label(self.SUBTITLE, "PageSub"))

        outer.addWidget(head)
        outer.addWidget(hline())

        inner = QWidget()
        self.col = QVBoxLayout(inner)
        self.col.setContentsMargins(30, 18, 30, 28)
        self.col.setSpacing(15)
        outer.addWidget(scroll_area(inner), 1)

        self.build()
        self.col.addStretch(1)

    # --- API para las subclases -----------------------------------------------------------
    def build(self) -> None:
        """Las subclases construyen aquí su contenido con self.add(...) y self.group(...)."""

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.col.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        self.col.addLayout(layout)

    def group(self, title: str, hint: str = "") -> QWidget:
        box = QWidget()
        # Alto fijo y suficiente: con fuentes de sustitución el texto se recortaba por arriba.
        box.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        lay = QVBoxLayout(box)
        lay.setContentsMargins(0, 10, 0, 2)
        lay.setSpacing(3)
        heading = label(title, "GroupTitle", wrap=False)
        heading.setMinimumHeight(26)
        lay.addWidget(heading)
        if hint:
            hint_label = label(hint, "GroupHint")
            hint_label.setMinimumHeight(16)
            lay.addWidget(hint_label)
        box.setMinimumHeight(64 if hint else 40)
        self.col.addWidget(box)
        return box

    # --- ganchos del ciclo de vida --------------------------------------------------------
    def on_show(self) -> None:
        """Se llama cada vez que la sección pasa a estar visible."""

    def on_demo_changed(self, enabled: bool) -> None:
        """Se llama al activar/desactivar el modo demostración."""
