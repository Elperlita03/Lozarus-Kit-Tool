# -*- coding: utf-8 -*-
"""
LOZARUS · BETA VISUAL — punto de entrada.

Ejecutar:   python spikes/ui_preview/app.py

Qué es: un prototipo de interfaz NAVEGABLE para evaluar el diseño del producto. Aislado en
`spikes/`, no toca el backend ni sustituye a `gui_qt.py`.

Qué NO hace, por diseño:
  · No abre sesiones ETW ni ejecuta nada privilegiado.
  · No termina procesos, no borra archivos, no toca el Registro ni el cortafuegos.
  · No guarda configuración en disco.
Lo único real que lee son CPU, RAM y número de procesos de este equipo (psutil).
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:                       # permite ejecutarlo como script desde cualquier sitio
    sys.path.insert(0, _HERE)

from PySide6.QtCore import Qt                                                     # noqa: E402
from PySide6.QtGui import QFont, QKeySequence, QShortcut                          # noqa: E402
from PySide6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel,         # noqa: E402
                               QMainWindow, QPlainTextEdit, QPushButton, QSizeGrip,
                               QStackedWidget, QVBoxLayout, QWidget)

from runtime import BetaContext                                                    # noqa: E402
from theme import C, QSS, icon, with_icon                                          # noqa: E402
from widgets import hline, label                                                   # noqa: E402

from sections.analyze import AnalyzeSection                                        # noqa: E402
from sections.catalog_view import CatalogSection                                   # noqa: E402
from sections.decoys import DecoysSection                                          # noqa: E402
from sections.defense import DefenseSection                                        # noqa: E402
from sections.forensics import ForensicsSection                                    # noqa: E402
from sections.hq import HQSection                                                  # noqa: E402
from sections.memory import MemorySection                                          # noqa: E402
from sections.perimeter import PerimeterSection                                    # noqa: E402
from sections.rescue import RescueSection                                          # noqa: E402
from sections.sentinel import SentinelSection                                      # noqa: E402
from sections.settings import SettingsSection                                      # noqa: E402

APP_NAME = "LOZARUS"
APP_TAG = "BETA VISUAL"

# Las diez áreas del producto, en el orden acordado.
MAIN_SECTIONS = [
    (HQSection, "fa5s.tachometer-alt"),
    (SentinelSection, "fa5s.wave-square"),
    (AnalyzeSection, "fa5s.search"),
    (DefenseSection, "fa5s.hand-paper"),
    (DecoysSection, "fa5s.eye"),
    (MemorySection, "fa5s.microchip"),
    (PerimeterSection, "fa5s.network-wired"),
    (ForensicsSection, "fa5s.fingerprint"),
    (RescueSection, "fa5s.life-ring"),
    (SettingsSection, "fa5s.sliders-h"),
]
# Añadido a la navegación propuesta: el catálogo necesita sitio propio (ver README).
EXTRA_SECTIONS = [
    (CatalogSection, "fa5s.th-list"),
]


class TitleBar(QFrame):
    """Barra de título propia (la ventana es sin marco)."""

    def __init__(self, window: QMainWindow):
        super().__init__()
        self.setObjectName("TitleBar")
        self.setFixedHeight(46)
        self._win = window
        lay = QHBoxLayout(self)
        lay.setContentsMargins(18, 0, 10, 0)
        lay.setSpacing(10)

        mark = QLabel()
        mark.setPixmap(icon("fa5s.shield-alt", C["cyan"]).pixmap(19, 19))
        lay.addWidget(mark)
        lay.addWidget(label(APP_NAME, "Brand", wrap=False))
        tag = QLabel(APP_TAG)
        tag.setObjectName("BrandTag")
        tag.setStyleSheet(f"color:{C['cyan']}; font-size:9px; font-weight:700; letter-spacing:2px;"
                          f" border:1px solid {C['cyan']}; border-radius:8px; padding:2px 7px;")
        lay.addWidget(tag)
        lay.addStretch(1)

        self.demo_flag = QLabel("")
        self.demo_flag.setStyleSheet(f"color:{C['demo']}; font-size:10px; font-weight:700;"
                                     " letter-spacing:1px;")
        lay.addWidget(self.demo_flag)
        lay.addSpacing(8)

        for text, obj, slot in (("—", "WinBtn", window.showMinimized),
                                ("□", "WinBtn", self._toggle_max),
                                ("✕", "WinClose", window.close)):
            btn = QPushButton(text)
            btn.setObjectName(obj)
            btn.setFixedSize(30, 26)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(slot)
            lay.addWidget(btn)

    def _toggle_max(self) -> None:
        if self._win.isMaximized():
            self._win.showNormal()
        else:
            self._win.showMaximized()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            handle = self._win.windowHandle()
            if handle is not None:
                handle.startSystemMove()
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        self._toggle_max()
        super().mouseDoubleClickEvent(event)


class NavButton(QPushButton):
    def __init__(self, text: str, icon_name: str):
        super().__init__(text)
        self.setObjectName("NavBtn")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(38)
        with_icon(self, icon_name, C["text2"], 15)


class DemoConsole(QPlainTextEdit):
    """Registro visual de las interacciones de demostración."""

    def __init__(self):
        super().__init__()
        self.setObjectName("Console")
        self.setReadOnly(True)
        self.setFixedHeight(104)
        self.setFrameShape(QFrame.Shape.NoFrame)

    def write(self, stamp: str, kind: str, message: str) -> None:
        color = {"nav": C["text2"], "demo": C["demo"], "info": C["cyan"],
                 "block": C["warn"], "ok": C["ok"]}.get(kind, C["text2"])
        glyph = BetaContext.KINDS.get(kind, "·")
        self.appendHtml(
            f'<span style="color:{C["faint"]}">{stamp}</span> '
            f'<span style="color:{color}; font-weight:bold">{glyph}</span> '
            f'<span style="color:{C["text2"]}">{message}</span>')
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())


class LozarusBeta(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ctx = BetaContext()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setWindowTitle(f"{APP_NAME} · {APP_TAG}")
        self.setWindowIcon(icon("fa5s.shield-alt", C["cyan"]))
        self.resize(1320, 860)
        self.setMinimumSize(1060, 680)

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)

        self.titlebar = TitleBar(self)
        outer.addWidget(self.titlebar)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.stack.setObjectName("Content")
        self.pages = {}
        for cls, _ in MAIN_SECTIONS + EXTRA_SECTIONS:
            page = cls(self.ctx)
            self.pages[cls.KEY] = page
            self.stack.addWidget(page)
        body.addWidget(self.stack, 1)
        outer.addLayout(body, 1)

        console_wrap = QVBoxLayout()
        console_wrap.setContentsMargins(22, 8, 22, 10)
        console_wrap.setSpacing(4)
        head = QHBoxLayout()
        head.addWidget(label("CONSOLA DE DEMOSTRACIÓN", "ConsoleTitle", wrap=False))
        head.addStretch(1)
        grip = QSizeGrip(self)
        grip.setFixedSize(14, 14)
        head.addWidget(grip, 0, Qt.AlignmentFlag.AlignBottom)
        console_wrap.addLayout(head)
        self.console = DemoConsole()
        console_wrap.addWidget(self.console)
        outer.addLayout(console_wrap)

        self.ctx.logged.connect(self.console.write)
        self.ctx.navigate.connect(self.select)
        self.ctx.demo_changed.connect(self._on_demo)

        self._shortcuts()
        self.select("hq")
        self.ctx.log("ok", f"{APP_NAME} {APP_TAG} iniciada · prototipo aislado en spikes/ui_preview")
        self.ctx.log("info", "Esta beta no ejecuta operaciones privilegiadas ni toca el sistema. "
                             "CPU y RAM son reales; el resto va marcado como demostración.")

    # ---------------------------------------------------------------- barra lateral
    def _build_sidebar(self) -> QWidget:
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(274)
        lay = QVBoxLayout(side)
        lay.setContentsMargins(12, 16, 12, 14)
        lay.setSpacing(3)

        lay.addWidget(label("ÁREAS", "NavTitle", wrap=False))
        self.nav_buttons = {}
        for cls, icon_name in MAIN_SECTIONS:
            btn = NavButton(cls.NAV_LABEL or cls.TITLE, icon_name)
            btn.clicked.connect(lambda _=False, k=cls.KEY: self.select(k))
            self.nav_buttons[cls.KEY] = btn
            lay.addWidget(btn)

        lay.addSpacing(10)
        lay.addWidget(label("EXPLORAR", "NavTitle", wrap=False))
        for cls, icon_name in EXTRA_SECTIONS:
            btn = NavButton(cls.NAV_LABEL or cls.TITLE, icon_name)
            btn.clicked.connect(lambda _=False, k=cls.KEY: self.select(k))
            self.nav_buttons[cls.KEY] = btn
            lay.addWidget(btn)

        lay.addStretch(1)
        lay.addWidget(hline())
        lay.addSpacing(8)
        foot = label("Prototipo visual · no es producción.\nNo ejecuta acciones privilegiadas.",
                     "Tiny")
        lay.addWidget(foot)
        return side

    def _shortcuts(self) -> None:
        keys = [cls.KEY for cls, _ in MAIN_SECTIONS]
        for i, key in enumerate(keys[:9], start=1):
            QShortcut(QKeySequence(f"Ctrl+{i}"), self, lambda k=key: self.select(k))
        if len(keys) >= 10:
            QShortcut(QKeySequence("Ctrl+0"), self, lambda: self.select(keys[9]))
        QShortcut(QKeySequence("Ctrl+L"), self, lambda: self.select("catalog"))
        QShortcut(QKeySequence("Ctrl+D"), self, lambda: self.ctx.set_demo(not self.ctx.demo))
        QShortcut(QKeySequence("Escape"), self, lambda: self.select("hq"))

    # ---------------------------------------------------------------- navegación
    def select(self, key: str) -> None:
        page = self.pages.get(key)
        if page is None:
            self.ctx.log("block", f"La sección «{key}» no existe en esta beta")
            return
        for k, btn in self.nav_buttons.items():
            btn.setChecked(k == key)
        self.stack.setCurrentWidget(page)
        page.on_show()
        self.ctx.log("nav", f"Sección: {page.TITLE}")

    def _on_demo(self, enabled: bool) -> None:
        self.titlebar.demo_flag.setText("● MODO DEMOSTRACIÓN" if enabled else "")
        for page in self.pages.values():
            page.on_demo_changed(enabled)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(f"{APP_NAME} {APP_TAG}")
    app.setStyleSheet(QSS)
    app.setFont(QFont("Segoe UI", 9))
    window = LozarusBeta()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
