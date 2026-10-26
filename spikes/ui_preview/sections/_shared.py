# -*- coding: utf-8 -*-
"""Ayudas compartidas por las secciones: tablas, cabeceras de demostración y avisos."""

from __future__ import annotations

from typing import Callable, Optional, Sequence

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QTableWidget,
                               QTableWidgetItem, QWidget)

from theme import C, icon
from widgets import DemoBadge, label, vbox


def data_table(headers: Sequence[str], rows: Sequence[Sequence[str]],
               color_column: Optional[int] = None,
               colorizer: Optional[Callable[[Sequence[str]], Optional[str]]] = None,
               height: int = 210) -> QTableWidget:
    """Tabla de solo lectura. `colorizer` devuelve un color para la fila (o None)."""
    table = QTableWidget(len(rows), len(headers))
    table.setHorizontalHeaderLabels(list(headers))
    table.verticalHeader().setVisible(False)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setShowGrid(False)
    table.setMinimumHeight(height)
    for r, row in enumerate(rows):
        color = colorizer(row) if colorizer else None
        for c, value in enumerate(row):
            item = QTableWidgetItem(str(value))
            if color and (color_column is None or c == color_column):
                item.setForeground(Qt.GlobalColor.white if color is None else _qcolor(color))
            table.setItem(r, c, item)
    head = table.horizontalHeader()
    head.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    if headers:
        head.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    return table


def _qcolor(value: str):
    from PySide6.QtGui import QColor
    return QColor(value)


def demo_row(text: str = "DATOS DE DEMOSTRACIÓN") -> QHBoxLayout:
    row = QHBoxLayout()
    row.addWidget(DemoBadge(text))
    row.addStretch(1)
    return row


def notice(text: str, color: Optional[str] = None, icon_name: str = "fa5s.info-circle") -> QFrame:
    """Aviso destacado (por ejemplo: «esto no se ejecuta de verdad»)."""
    col = color or C["cyan"]
    box = QFrame()
    box.setStyleSheet(f"QFrame {{ background-color:{C['surface2']}; border:1px solid {col};"
                      f" border-radius:10px; }}")
    lay = QHBoxLayout(box)
    lay.setContentsMargins(13, 11, 13, 11)
    lay.setSpacing(10)
    ico = QWidget()
    il = vbox(ico, 0, 0)
    from PySide6.QtWidgets import QLabel
    pix = QLabel()
    pix.setPixmap(icon(icon_name, col).pixmap(15, 15))
    pix.setAlignment(Qt.AlignmentFlag.AlignTop)
    il.addWidget(pix)
    il.addStretch(1)
    ico.setFixedWidth(18)
    lay.addWidget(ico)
    text_label = label(text, "CardText")
    text_label.setStyleSheet(f"color:{C['text2']}; font-size:12px;")
    lay.addWidget(text_label, 1)
    return box
