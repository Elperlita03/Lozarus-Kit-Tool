"""
ui/dialogs.py · LOZARUS KIT TOOL

Diálogos modales: doble validación («CONFIRMAR»), protocolo de reset y terminal en vivo.
"""

from __future__ import annotations

import datetime as dt
import html

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
                               QVBoxLayout)


class ResetConfirmDialog(QDialog):
    """Doble validación para acciones extremas: exige teclear la palabra exacta para habilitar OK."""

    def __init__(self, parent, title: str, message: str, keyword: str = "CONFIRMAR",
                 confirm_text: str = "EJECUTAR"):
        super().__init__(parent)
        self.keyword = keyword
        self.setObjectName("Dialog")
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 20)
        lay.setSpacing(12)
        head = QLabel(title)
        head.setObjectName("DialogTitle")
        body = QLabel(message)
        body.setObjectName("DialogBody")
        body.setWordWrap(True)
        hint = QLabel(f"Escribe  {keyword}  para desbloquear:")
        hint.setObjectName("DialogHint")
        self.entry = QLineEdit()
        self.entry.setPlaceholderText(keyword)
        self.entry.textChanged.connect(self._check)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton("Cancelar")
        cancel.setObjectName("Ghost")
        cancel.clicked.connect(self.reject)
        self.ok = QPushButton(confirm_text)
        self.ok.setObjectName("Danger")
        self.ok.setEnabled(False)
        self.ok.clicked.connect(self.accept)
        row.addWidget(cancel)
        row.addWidget(self.ok)
        for w in (head, body, hint, self.entry):
            lay.addWidget(w)
        lay.addLayout(row)

    def _check(self, text: str) -> None:
        self.ok.setEnabled(text.strip() == self.keyword)


class ConfirmDialog(QDialog):
    """Confirmación simple (Confirmar / Cancelar). danger=True para acciones destructivas."""

    def __init__(self, parent, title: str, message: str, confirm_text: str = "Confirmar", danger: bool = False):
        super().__init__(parent)
        self.setObjectName("Dialog")
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(470)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 20)
        lay.setSpacing(12)
        head = QLabel(title)
        head.setObjectName("DialogTitle")
        body = QLabel(message)
        body.setObjectName("DialogBody")
        body.setWordWrap(True)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton("Cancelar")
        cancel.setObjectName("Ghost")
        cancel.clicked.connect(self.reject)
        ok = QPushButton(confirm_text)
        ok.setObjectName("Danger" if danger else "Primary")
        ok.clicked.connect(self.accept)
        row.addWidget(cancel)
        row.addWidget(ok)
        for w in (head, body):
            lay.addWidget(w)
        lay.addLayout(row)

    @staticmethod
    def ask(parent, title: str, message: str, confirm_text: str = "Confirmar", danger: bool = False) -> bool:
        return ConfirmDialog(parent, title, message, confirm_text, danger).exec() == QDialog.DialogCode.Accepted


class TerminalDialog(QDialog):
    """Terminal en vivo estilo «matrix»: fondo negro, texto verde/azul, auto-scroll. Se alimenta por
    append() según llegan las líneas y, al terminar, habilita el botón de cerrar."""
    KIND = {"+": "#56B6FF", "~": "#22C55E", "*": "#56FF9E", "!": "#FFB300", "x": "#FF5252",
            "TACTICAL": "#56B6FF"}

    def __init__(self, parent, title: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(False)
        self.resize(720, 420)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)
        self.heading = QLabel(f"●  {title}")
        self.heading.setStyleSheet("color:#22C55E; font-family:'Consolas'; font-weight:bold; font-size:12px;")
        self.box = QPlainTextEdit()
        self.box.setReadOnly(True)
        self.box.setMaximumBlockCount(1000)
        self.box.setFont(QFont("Consolas", 10))
        self.box.setStyleSheet("QPlainTextEdit { background:#000000; color:#22C55E; "
                               "border:1px solid #1A1A1A; border-radius:8px; }")
        self.close_btn = QPushButton("Cerrar")
        self.close_btn.setObjectName("Ghost")
        self.close_btn.setEnabled(False)
        self.close_btn.clicked.connect(self.accept)
        lay.addWidget(self.heading)
        lay.addWidget(self.box, 1)
        lay.addWidget(self.close_btn, 0, Qt.AlignmentFlag.AlignRight)
        self.setStyleSheet("QDialog { background:#000000; }")

    def append(self, kind: str, text: str) -> None:
        color = self.KIND.get(kind, "#22C55E")
        when = dt.datetime.now().strftime("%H:%M:%S")
        safe = html.escape(text.rstrip())
        self.box.appendHtml(f'<span style="color:#2E7D46">[{when}]</span> '
                            f'<span style="color:{color}">{safe}</span>')
        self.box.verticalScrollBar().setValue(self.box.verticalScrollBar().maximum())

    def finish(self) -> None:
        self.heading.setText(self.heading.text().replace("●", "✔"))
        self.heading.setStyleSheet("color:#56FF9E; font-family:'Consolas'; font-weight:bold; font-size:12px;")
        self.close_btn.setEnabled(True)
