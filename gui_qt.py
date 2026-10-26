#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gui_qt.py · LOZARUS KIT TOOL — interfaz PRINCIPAL (PySide6)
==========================================================

Interfaz PRINCIPAL de Lozarus: panel de endurecimiento y defensa LOCAL del equipo, en PySide6
(aceleración por hardware y aspecto nativo). Es la única interfaz gráfica: la versión anterior en
CustomTkinter (gui.py) se retiró el 2026-10-21. El motor (modulos/) es el mismo que usa el CLI
auditor.py.

Uso:  python gui_qt.py        (como Administrador para la auditoría completa y las acciones
                               que modifican el sistema)

Incluye:
  · Ventana sin marco (FramelessWindowHint) con barra de título propia y arrastrable.
  · Tema oscuro en QSS (negro profundo, azul Lozarus #0078D7).
  · Hover suave del menú lateral con QPropertyAnimation.
  · Worker(QThread): clase base para correr diagnósticos / PowerShell en segundo plano sin
    congelar la interfaz (comunica por señales, que Qt entrega al hilo de la UI de forma segura).
  · Módulos defensivos LOCALES: Endurecimiento de Red (ocultar ante ping / ICMP) y Honeypot de
    detección (archivos señuelo que solo se vigilan y avisan; no actúan contra nadie).
  · Consola de Telemetría (QPlainTextEdit monoespaciado) y diálogo de doble validación «CONFIRMAR».

Todo es defensivo, local y reversible. Requisito:  pip install PySide6
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import html
import importlib
import importlib.util
import json
import os
import socket
import sys
import tempfile
import time
import traceback
from collections import deque
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional, Sequence, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import psutil  # noqa: E402
from PySide6.QtCore import (Property, QEasingCurve, QEvent, QObject, QPointF, QPropertyAnimation,  # noqa: E402
                            QRect, QRectF, Qt, QSize, QThread, QTimer, Signal)
from PySide6.QtGui import (QBrush, QColor, QFont, QIcon, QPainter, QPainterPath, QPen,  # noqa: E402
                           QPolygonF)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QDialog, QFileDialog,  # noqa: E402
                               QFrame, QGraphicsOpacityEffect, QGridLayout, QHBoxLayout, QLabel,
                               QLineEdit, QMainWindow, QPlainTextEdit, QProgressBar, QPushButton,
                               QScrollArea, QSizeGrip, QSplitter, QStackedWidget,
                               QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

try:
    import qtawesome as qta  # iconos vectoriales (Font Awesome); opcional
    HAS_QTA = True
except ImportError:
    qta, HAS_QTA = None, False

from modulos._alertas import HAS_PLYER, Sentinel, describe_threats, notify  # noqa: E402
from modulos._base import CRITICAL, INFO, PASS, SKIP, WARNING, AuditContext, Report  # noqa: E402
from modulos._cargador import discover_modules  # noqa: E402
from modulos._contencion import apply_quarantine, lift_quarantine, quarantine_active  # noqa: E402
from modulos._defensa_local import icmp_block_active, set_icmp_block  # noqa: E402
from modulos._endurecimiento_red import (SERVICIOS_SENSIBLES, disable_service, firewall_status,  # noqa: E402
                                         flush_dns, listening_keys, restore_service, scan_connections,
                                         services_overview, split_connections)
from modulos._privacidad import (clean_temp, clear_clipboard, empty_working_sets, is_hijack_swap,  # noqa: E402
                                 looks_sensitive, read_clipboard_text, shred_file, temp_dir)
from modulos._forense import FORENSICS_DIR, forensic_report, list_snapshots, system_snapshot  # noqa: E402
from modulos._listablanca import CONFIG_KEY as TRUST_KEY  # noqa: E402
from modulos._listablanca import add_trusted, is_trusted  # noqa: E402
from modulos._obsidian import (events_per_minute, health_score, jsonl_size_kb,  # noqa: E402
                               process_vitals)
from modulos._forense_autopsia import (analyze_file, classify_entropy, event_row, export_report,  # noqa: E402
                                       read_events)
from modulos import _procmon  # noqa: E402  (muestreo de procesos para el Monitor en Vivo)
from modulos._monitor import LiveMonitor  # noqa: E402
from modulos._tacticas import (GHOST_STEPS, factory_reset, ghost_mode, ghost_preview,  # noqa: E402
                               launch_in_sandbox, sandbox_available)
from modulos._utilidades import HAS_PSUTIL, _powershell_exe, is_admin, request_admin_relaunch  # noqa: E402
from modulos._inicio import startup_entries  # noqa: E402

try:  # Núcleo de eventos + Caja Negra (opcionales: si faltan, la GUI sigue sin ellos)
    from core.bus import EventBus  # noqa: E402
    from core.events import Event, ObservationQuality  # noqa: E402
    from forensics.blackbox import CajaNegra  # noqa: E402
    HAS_BLACKBOX = True
except Exception:  # noqa: BLE001
    EventBus = Event = ObservationQuality = CajaNegra = None
    HAS_BLACKBOX = False

try:  # Persistencia táctica + motor de Honeypot autónomo (opcionales)
    from storage.persistence import TacticalConfig  # noqa: E402
    from deception.honeypot_engine import HoneypotEngine  # noqa: E402
    HAS_HONEYPOT = True
except Exception:  # noqa: BLE001
    TacticalConfig = HoneypotEngine = None
    HAS_HONEYPOT = False

APP_NAME = "LOZARUS KIT TOOL"

SEVERITY_COLORS = {CRITICAL: "#FF5252", WARNING: "#FFB300", PASS: "#22C55E", INFO: "#4FC3F7", SKIP: "#8A8A8A"}
SEVERITY_ORDER = (CRITICAL, WARNING, PASS, INFO, SKIP)

COLORS = {
    "bg": "#09090B", "sidebar": "#121217", "panel": "#121217", "panel_alt": "#27272A",
    "border": "#272730", "text": "#FAFAFA", "text2": "#A1A1AA", "muted": "#71717A", "faint": "#52525B",
    "accent": "#60A5FA", "accent_hover": "#93C5FD", "accent_soft": "#1E2633", "beacon": "#EF4444",
    "terminal": "#22C55E", "disabled": "#3F3F4E", "card": "#18181F", "panel2": "#121217",
}

# Hoja de estilo (QSS): tema oscuro corporativo (grises neutros + acento azul)
QSS = """
* { font-family: 'Segoe UI', 'Inter', 'Helvetica', sans-serif; }
#Root { background-color: #09090B; border: 1px solid #272730; }
#TitleBar { background-color: #121217; border-bottom: 1px solid #272730; }
#Logo { color: #60A5FA; font-size: 20px; font-weight: bold; }
#Brand { color: #FAFAFA; font-size: 19px; font-weight: bold; letter-spacing: 3px; }
#BrandSub { color: #60A5FA; font-size: 11px; font-weight: bold; letter-spacing: 1px; }
#WinBtn { background: transparent; color: #A1A1AA; border: none; padding: 0; font-size: 14px; border-radius: 6px; }
#WinBtn:hover { background-color: #272730; color: #FAFAFA; }
#WinClose { background: transparent; color: #A1A1AA; border: none; padding: 0; font-size: 14px; border-radius: 6px; }
#WinClose:hover { background-color: #EF4444; color: #09090B; }
#Sidebar { background-color: #121217; border-right: 1px solid #272730; }
#NavTitle { color: #52525B; font-size: 11px; font-weight: bold; }
#Content { background-color: #09090B; }
#PageTitle { color: #FAFAFA; font-size: 23px; font-weight: bold; letter-spacing: 0.3px; }
#PageSub { color: #A1A1AA; font-size: 13px; }
#Card { background-color: #18181F; border: 1px solid #272730; border-radius: 11px; }
#CardTitle { color: #FAFAFA; font-size: 14px; font-weight: bold; letter-spacing: 0.2px; }
#CardText { color: #A1A1AA; font-size: 12px; }
#Value { color: #FAFAFA; font-size: 15px; font-weight: bold; }

/* Botones (outlined): acento azul por defecto, relleno al pasar el ratón */
QPushButton { background: transparent; color: #60A5FA; border: 1px solid #60A5FA; border-radius: 8px;
    padding: 9px 16px; font-weight: 600; font-size: 13px; }
QPushButton:hover { background-color: #60A5FA; color: #09090B; }
QPushButton:disabled { color: #3F3F4E; border-color: #272730; background: transparent; }
QPushButton#Primary { color: #60A5FA; border-color: #60A5FA; }
QPushButton#Primary:hover { background-color: #60A5FA; color: #09090B; }
QPushButton#Primary:disabled { color: #3F3F4E; border-color: #272730; }
QPushButton#Ghost { color: #A1A1AA; border-color: #272730; }
QPushButton#Ghost:hover { background-color: #272730; color: #FAFAFA; border-color: #3F3F4E; }
QPushButton#Danger { color: #EF4444; border-color: #EF4444; }
QPushButton#Danger:hover { background-color: #EF4444; color: #09090B; }
QPushButton#Danger:disabled { color: #7F1D1D; border-color: #3F1414; }
/* Botones de advertencia del menú: borde rojo sobre panel (hold-to-execute) */
QPushButton#Warn { background-color: #18181F; color: #EF4444; border: 1px solid #EF4444; border-radius: 8px;
    padding: 10px 14px; font-weight: bold; font-size: 13px; }
QPushButton#Warn:hover { background-color: #EF4444; color: #09090B; }
QPushButton#Warn:disabled { color: #7F1D1D; border-color: #3F1414; }
QPushButton#Mini { color: #A1A1AA; border-color: #272730; padding: 8px 10px; font-size: 11px; }
QPushButton#Mini:hover { background-color: #272730; color: #FAFAFA; border-color: #3F3F4E; }
QPushButton#Toggle { background: #18181F; color: #A1A1AA; border: 1px solid #272730; border-radius: 8px;
    padding: 8px; font-size: 12px; font-weight: bold; text-align: left; }
QPushButton#Toggle:hover { border-color: #60A5FA; color: #FAFAFA; }
QPushButton#Toggle:checked { background: #1E2633; color: #FAFAFA; border-color: #60A5FA; }
/* Pulsado: respuesta táctil inmediata. Va DESPUÉS de los :hover (misma especificidad → gana). */
QPushButton:pressed, QPushButton#Primary:pressed { background-color: #3B82F6; border-color: #3B82F6; color: #09090B; }
QPushButton#Ghost:pressed, QPushButton#Mini:pressed { background-color: #3F3F4E; border-color: #52525B; color: #FAFAFA; }
QPushButton#Danger:pressed { background-color: #DC2626; border-color: #DC2626; color: #09090B; }
QPushButton#Toggle:pressed { background: #272730; }
/* Deshabilitado: un selector con ID (#Ghost…) pesa más que QPushButton:disabled, así que cada
   variante necesita su propia regla o el botón PARECERÍA activo estando deshabilitado. */
QPushButton#Ghost:disabled, QPushButton#Mini:disabled { color: #3F3F4E; border-color: #272730; background: transparent; }
QPushButton#Toggle:disabled { color: #3F3F4E; border-color: #272730; background: #141418; }
QPushButton:focus { outline: none; }
/* Ocupado (set_busy): deshabilitado pero con texto en acento = «trabajando», no «no disponible».
   Una regla por variante: el ID de cada tipo pesa más que la propiedad sola. */
QPushButton[busy="true"]:disabled, QPushButton#Primary[busy="true"]:disabled,
QPushButton#Ghost[busy="true"]:disabled, QPushButton#Mini[busy="true"]:disabled,
QPushButton#Danger[busy="true"]:disabled, QPushButton#Toggle[busy="true"]:disabled {
    color: #93C5FD; border-color: #1E3A5F; background: #141A24; }
/* Indicador global de actividad (junto a la consola): no es clicable ni cambia al pasar el ratón. */
QPushButton#Activity, QPushButton#Activity:hover, QPushButton#Activity:pressed { background: transparent;
    border: none; color: #60A5FA; padding: 0 2px; font-size: 11px; font-weight: 600; text-align: right; }

#Dialog { background-color: #18181F; }
#DialogTitle { color: #FAFAFA; font-size: 18px; font-weight: bold; }
#DialogBody { color: #A1A1AA; font-size: 13px; }
#DialogHint { color: #EF4444; font-size: 12px; font-weight: bold; }
QLineEdit { background-color: #09090B; border: 1px solid #272730; border-radius: 8px;
    padding: 8px; color: #FAFAFA; font-family: 'Consolas'; font-size: 13px;
    selection-background-color: #1E3A5F; }
QLineEdit:hover { border-color: #3F3F4E; }
QLineEdit:focus { border-color: #60A5FA; }
QLineEdit:disabled { color: #3F3F4E; }
/* Desplegables con el mismo lenguaje que los campos de texto (antes salían en blanco nativo). */
QComboBox { background-color: #09090B; border: 1px solid #272730; border-radius: 8px;
    padding: 7px 28px 7px 10px; color: #FAFAFA; font-size: 12px; min-width: 70px; }
QComboBox:hover { border-color: #3F3F4E; }
QComboBox:focus, QComboBox:on { border-color: #60A5FA; }
QComboBox:disabled { color: #3F3F4E; border-color: #272730; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: center right; width: 24px;
    border: none; }
QComboBox::down-arrow { image: url("__ARROW_DOWN__"); width: 10px; height: 10px; }
QComboBox QAbstractItemView { background-color: #18181F; border: 1px solid #3F3F4E; color: #FAFAFA;
    selection-background-color: #1E2633; selection-color: #FAFAFA; outline: 0; padding: 4px; }
QToolTip { background-color: #18181F; color: #FAFAFA; border: 1px solid #3F3F4E; padding: 6px 8px;
    border-radius: 6px; font-size: 12px; }
#Console { background-color: #09090B; border: 1px solid #272730; border-radius: 8px; color: #FAFAFA;
    padding: 4px; selection-background-color: #1E3A5F; selection-color: #FAFAFA; }
#ConsoleTitle { color: #A1A1AA; font-size: 11px; font-weight: bold; letter-spacing: 0.5px; }
#StatusOk { color: #22C55E; font-weight: bold; }
#StatusWarn { color: #F59E0B; font-weight: bold; }
#StatusMuted { color: #A1A1AA; }
QScrollArea#Content { background: transparent; border: none; }
QScrollBar:vertical { background: #09090B; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #272730; border-radius: 5px; min-height: 24px; }
QScrollBar:horizontal { background: #09090B; height: 10px; margin: 0; }
QScrollBar::handle:horizontal { background: #272730; border-radius: 5px; min-width: 24px; }
QScrollBar::handle:hover { background: #3F3F4E; }
QScrollBar::handle:pressed { background: #52525B; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
/* Tablas: filas de alto fijo (make_table), sin rejilla ni rectángulo de foco, selección en acento. */
QTableWidget { background-color: #18181F; alternate-background-color: #1C1C24; border: none;
    gridline-color: transparent; color: #A1A1AA; font-size: 12px; outline: 0;
    selection-background-color: #1E2633; }
QTableWidget::item { padding: 0 8px; color: #FAFAFA; border: none; }
QTableWidget::item:selected { background-color: #1E2633; color: #FAFAFA; }
QHeaderView { background-color: #18181F; border: none; }
QHeaderView::section { background-color: #18181F; color: #71717A; border: none;
    border-bottom: 1px solid #272730; padding: 7px 8px; font-size: 10px; font-weight: bold; letter-spacing: 0.8px; }
QHeaderView::section:hover { color: #A1A1AA; }
QTableCornerButton::section { background-color: #18181F; border: none; }
QTabWidget::pane { border: 1px solid #272730; border-radius: 8px; top: -1px; background: #09090B; }
QTabBar::tab { background: #18181F; color: #A1A1AA; padding: 8px 18px; border: 1px solid #272730;
    border-bottom: none; border-top-left-radius: 8px; border-top-right-radius: 8px; font-size: 12px;
    margin-right: 4px; }
QTabBar::tab:hover:!selected { color: #FAFAFA; border-color: #3F3F4E; }
QTabBar::tab:selected { background: #1E2633; color: #FAFAFA; border-color: #3F3F4E; }
QProgressBar { background-color: #272730; border: none; border-radius: 3px; max-height: 6px;
    text-align: center; color: transparent; }
QProgressBar::chunk { background-color: #60A5FA; border-radius: 3px; }
#Chip { background-color: #18181F; border: 1px solid #272730; border-radius: 8px; }
#ChipCap { color: #A1A1AA; font-size: 11px; font-weight: bold; }
#ChipVal { color: #FAFAFA; font-size: 20px; font-weight: bold; }
#Detail { background-color: #141418; border: 1px solid #272730; border-radius: 8px; color: #A1A1AA;
    font-size: 13px; padding: 6px; }
QLabel#Tiny { color: #A1A1AA; font-size: 11px; }
/* Campana de alertas de la cabecera */
#AlertBell { background: transparent; border: none; color: #71717A; font-size: 12px; font-weight: bold;
    padding: 0 8px; border-radius: 6px; }
#AlertBell:hover { color: #FAFAFA; background: #272730; }
/* Chips de filtro de la consola */
QPushButton#Chiplet { background: #121217; color: #71717A; border: 1px solid #272730; border-radius: 10px;
    padding: 3px 11px; font-size: 10px; font-weight: bold; letter-spacing: 0.5px; }
QPushButton#Chiplet:hover { color: #FAFAFA; border-color: #3F3F4E; }
QPushButton#Chiplet:checked { background: #1E2633; color: #FAFAFA; border-color: #60A5FA; }
QPushButton#ToastClose { background: transparent; border: none; color: #71717A; font-size: 13px; }
QPushButton#ToastClose:hover { color: #FAFAFA; }
#ConsoleWrap { background: transparent; }
QSplitter#VSplit::handle:vertical { background: transparent; }
QSplitter#VSplit::handle:vertical:hover { background: #272730; }
QSizeGrip { background: transparent; }
/* Mini-botón de acceso «→» en cada tarjeta del panel de salud */
QPushButton#CompGo { background: transparent; border: 1px solid #272730; border-radius: 11px;
    color: #71717A; font-size: 13px; font-weight: bold; padding: 0; }
QPushButton#CompGo:hover { border-color: #60A5FA; color: #60A5FA; background: #141A24; }
"""


def _ui_asset(name: str, svg: str) -> str:
    """
    Escribe UNA vez un pequeño SVG de interfaz en la carpeta temporal y devuelve su ruta con «/»
    (formato de url() en QSS). El QSS no admite dibujar un chevron con bordes de forma fiable. Si no
    se puede escribir, devuelve "" y el combo simplemente se queda sin flecha (no rompe nada).
    """
    folder = os.path.join(tempfile.gettempdir(), "lozarus_ui")
    path = os.path.join(folder, name)
    try:
        if not os.path.isfile(path):
            os.makedirs(folder, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(svg)
    except OSError:
        return ""
    return path.replace("\\", "/")


QSS = QSS.replace("__ARROW_DOWN__", _ui_asset(
    "chevron-down.svg",
    '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 10 10">'
    '<path d="M1.5 3.5 L5 7 L8.5 3.5" fill="none" stroke="#A1A1AA" stroke-width="1.6" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'))


# Iconos vectoriales (qtawesome). Si no está instalado, se devuelven iconos vacíos y la app sigue.
NAV_ICONS = {
    "comando": "fa5s.tachometer-alt", "monitor": "fa5s.wave-square", "auditoria": "fa5s.shield-alt",
    "historial": "fa5s.history", "red": "fa5s.network-wired", "honeypot": "fa5s.eye",
    "fantasma": "fa5s.ghost",
}


def icon(name: str, color: Optional[str] = None, disabled_color: Optional[str] = None,
         animation: Any = None) -> QIcon:
    """
    Icono vectorial qtawesome. En estado deshabilitado se pinta con el mismo gris que el texto
    deshabilitado (antes qtawesome usaba un gris claro y el icono «brillaba» en botones inactivos).
    """
    if not HAS_QTA or not name:
        return QIcon()
    opts = {"color": color or COLORS["accent"], "color_disabled": disabled_color or COLORS["disabled"]}
    if animation is not None:
        opts["animation"] = animation
    try:
        return qta.icon(name, **opts)
    except Exception:  # noqa: BLE001  (icono inexistente en esta versión de qtawesome)
        return QIcon()


def with_icon(button, name: str, color: Optional[str] = None, size: int = 16):
    """Pone un icono vectorial a un botón (y devuelve el botón, para encadenar)."""
    button.setIcon(icon(name, color))
    button.setIconSize(QSize(size, size))
    return button


def set_busy(button: QPushButton, busy: bool, text: Optional[str] = None) -> None:
    """
    Estado «ocupado» de un botón mientras su tarea corre en segundo plano: lo deshabilita (evita el
    doble clic), muestra un texto de progreso y un spinner animado en color de acento. Al terminar
    restaura su texto e icono originales. Un único `Spin` por botón, reutilizado: qtawesome crea un
    QTimer hijo por animación, así que crear uno nuevo en cada clic acumularía temporizadores.
    """
    button.setProperty("busy", busy)  # estilo propio en el QSS (texto en acento mientras trabaja)
    button.style().unpolish(button)
    button.style().polish(button)
    if busy:
        if getattr(button, "_lz_idle", None) is None:   # guarda el estado de reposo una sola vez
            button._lz_idle = (button.text(), button.icon())
        button.setEnabled(False)
        if text:
            button.setText(text)
        if HAS_QTA:
            spin = getattr(button, "_lz_spin", None)
            if spin is None:
                spin = qta.Spin(button, interval=30, step=10)
                button._lz_spin = spin
            else:
                spin.start()
            button.setIcon(icon("fa5s.circle-notch", COLORS["accent"], COLORS["accent"], spin))
        return
    spin = getattr(button, "_lz_spin", None)
    if spin is not None:
        spin.stop()
    idle = getattr(button, "_lz_idle", None)
    if idle is not None:
        button.setText(idle[0])
        button.setIcon(idle[1])
        button._lz_idle = None
    button.setEnabled(True)


@contextmanager
def frozen(widget: QWidget) -> Iterator[None]:
    """Suspende el repintado durante un relleno masivo (p. ej. cientos de celdas) y repinta UNA vez."""
    widget.setUpdatesEnabled(False)
    try:
        yield
    finally:
        widget.setUpdatesEnabled(True)


class LzTable(QTableWidget):
    """
    QTableWidget con ESTADO VACÍO: sin filas, pinta un icono y un mensaje centrados en lugar de un
    recuadro negro vacío, para que se entienda qué mostrará la tabla y cómo llenarla.
    """

    def __init__(self, rows: int, cols: int):
        super().__init__(rows, cols)
        self._empty_text = ""
        self._empty_icon = "fa5s.inbox"

    def set_empty_text(self, text: str, icon_name: str = "fa5s.inbox") -> None:
        self._empty_text, self._empty_icon = text, icon_name
        self.viewport().update()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self.rowCount() or not self._empty_text:
            return
        p = QPainter(self.viewport())
        try:
            area = self.viewport().rect().adjusted(32, 0, -32, 0)
            if HAS_QTA:
                pix = icon(self._empty_icon, "#3F3F46").pixmap(30, 30)
                p.drawPixmap(area.center().x() - 15, area.center().y() - 40, pix)
            p.setPen(QColor("#71717A"))
            font = p.font()
            font.setPointSize(10)
            p.setFont(font)
            p.drawText(area.adjusted(0, 4, 0, 40), int(Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap),
                       self._empty_text)
        finally:
            p.end()


def make_table(headers: Sequence[str], widths: Optional[Sequence[int]] = None,
               empty: str = "", empty_icon: str = "fa5s.inbox") -> QTableWidget:
    """
    Tabla de solo lectura con el aspecto común de Lozarus: filas de alto fijo, cabecera alineada a
    la izquierda, sin rejilla, selección de fila única y texto recortado con «…» en vez de saltos.
    `empty`: mensaje que se muestra centrado mientras la tabla no tiene filas.
    """
    t = LzTable(0, len(headers))
    if empty:
        t.set_empty_text(empty, empty_icon)
    t.setHorizontalHeaderLabels(list(headers))
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(30)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.setWordWrap(False)
    t.setTextElideMode(Qt.TextElideMode.ElideRight)
    hh = t.horizontalHeader()
    hh.setStretchLastSection(True)
    hh.setHighlightSections(False)
    hh.setMinimumSectionSize(48)
    hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    for i, w in enumerate(widths or ()):
        t.setColumnWidth(i, w)
    return t


def make_card(title: str, desc: str = "") -> Tuple[QFrame, QVBoxLayout]:
    """Tarjeta estándar (márgenes y espaciado únicos) con título y descripción opcional."""
    box = QFrame()
    box.setObjectName("Card")
    lay = QVBoxLayout(box)
    lay.setContentsMargins(18, 16, 18, 16)
    lay.setSpacing(10)
    head = QLabel(title)
    head.setObjectName("CardTitle")
    lay.addWidget(head)
    if desc:
        sub = QLabel(desc)
        sub.setObjectName("CardText")
        sub.setWordWrap(True)
        lay.addWidget(sub)
    return box, lay


# ===========================================================================
# HILO DE TRABAJO (clase base)
# ===========================================================================
# Hilos que seguían vivos al cerrar la ventana (ver MainWindow._wait_workers y main()).
_ORPHAN_WORKERS: list = []


class Worker(QThread):
    """
    Clase base para ejecutar trabajo en segundo plano (diagnósticos, scripts de PowerShell) sin
    congelar la interfaz. Recibe una función `fn(emit)` donde `emit(kind, text)` publica líneas en
    la consola. Las señales de Qt se entregan al hilo de la UI de forma segura (conexión en cola),
    así que nunca se tocan widgets desde aquí.
    """
    log = Signal(str, str)       # (kind, text) -> consola de telemetría
    done = Signal(bool, object)  # (ok, resultado-o-mensaje-de-error)

    def __init__(self, fn: Callable[[Callable[[str, str], None]], Any]):
        super().__init__()
        self._fn = fn

    def run(self) -> None:
        try:
            result = self._fn(self.log.emit)
            self.done.emit(True, result)
        except Exception as exc:
            self.done.emit(False, f"{type(exc).__name__}: {exc}")


# ===========================================================================
# PIEZAS DE INTERFAZ
# ===========================================================================
class TitleBar(QFrame):
    """Barra de título propia (la ventana es sin marco): logo, nombre y botones minimizar/cerrar."""

    def __init__(self, window: QMainWindow):
        super().__init__()
        self.setObjectName("TitleBar")
        self.setFixedHeight(54)
        self.win = window
        self._drag = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(20, 0, 10, 0)
        lay.setSpacing(12)
        logo = QLabel()
        logo.setPixmap(icon("fa5s.shield-alt", COLORS["accent"]).pixmap(26, 26))
        brand = QLabel("LOZARUS")
        brand.setObjectName("Brand")
        sub = QLabel("KIT TOOL")
        sub.setObjectName("BrandSub")
        for w in (logo, brand, sub):
            lay.addWidget(w)
        lay.addStretch(1)
        # Campana de alertas (el panel y el contador se cablean en MainWindow).
        self.alert_btn = QPushButton("")
        self.alert_btn.setObjectName("AlertBell")
        self.alert_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.alert_btn.setFixedHeight(30)
        with_icon(self.alert_btn, "fa5s.bell", COLORS["muted"], 15)
        self.alert_btn.clicked.connect(window.toggle_alert_center)
        lay.addWidget(self.alert_btn)
        self.min_btn = self._win_button("—", window.showMinimized, "WinBtn")
        self.max_btn = self._win_button("□", window.toggle_max_restore, "WinBtn")
        self.close_btn = self._win_button("✕", window.close, "WinClose")
        for b in (self.min_btn, self.max_btn, self.close_btn):
            lay.addWidget(b)

    def set_alert_count(self, n: int) -> None:
        """Pinta el contador de alertas recientes (vacío si 0) y resalta la campana si hay alguna."""
        self.alert_btn.setText(f"  {n}" if n else "")
        color = COLORS["beacon"] if n else COLORS["muted"]
        with_icon(self.alert_btn, "fa5s.bell" if n else "fa5s.bell", color, 15)
        self.alert_btn.setStyleSheet(f"#AlertBell {{ color:{color}; }}")

    def _win_button(self, text: str, slot, name: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName(name if name == "WinClose" else "WinBtn")
        if name == "WinClose":
            btn.setProperty("objectName", "WinClose")
        btn.setFixedSize(34, 30)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(slot)
        return btn

    # Arrastre de la ventana sin marco (no al estar maximizada)
    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton and not self.win.isMaximized():
            self._drag = event.globalPosition().toPoint() - self.win.frameGeometry().topLeft()

    def mouseMoveEvent(self, event) -> None:
        if self._drag is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.win.move(event.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, event) -> None:
        self._drag = None

    def mouseDoubleClickEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.win.toggle_max_restore()


class NavButton(QPushButton):
    """Botón del menú lateral con hover/activo suave mediante QPropertyAnimation (color de fondo)."""

    def __init__(self, text: str, icon_name: str = None):
        super().__init__(text)
        self.setObjectName("NavButton")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(44)
        self._active = False
        self._icon_name = icon_name
        self._bg = QColor(0, 0, 0, 0)
        self._anim = QPropertyAnimation(self, b"bg", self)
        self._anim.setDuration(170)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        if icon_name:
            self.setIconSize(QSize(17, 17))
        self._apply()
        self._refresh_icon()

    def _refresh_icon(self) -> None:
        if self._icon_name:
            self.setIcon(icon(self._icon_name, COLORS["accent"] if self._active else COLORS["muted"]))

    def _get_bg(self) -> QColor:
        return self._bg

    def _set_bg(self, color: QColor) -> None:
        self._bg = color
        self._apply()

    bg = Property(QColor, _get_bg, _set_bg)

    def _apply(self) -> None:
        c = self._bg
        self.setStyleSheet(
            f"QPushButton#NavButton {{ background-color: rgba({c.red()},{c.green()},{c.blue()},{c.alpha()});"
            f" text-align: left; padding-left: 14px; border: none; border-radius: 8px;"
            f" color: {'#FAFAFA' if self._active else '#A1A1AA'}; font-size: 13px; }}")

    def _to(self, color: QColor) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._bg)
        self._anim.setEndValue(color)
        self._anim.start()

    def set_active(self, on: bool) -> None:
        self._active = on
        self._apply()
        self._refresh_icon()
        self._to(QColor(30, 38, 51, 255) if on else QColor(0, 0, 0, 0))  # accent_soft #1E2633

    def enterEvent(self, event) -> None:
        if not self._active:
            self._to(QColor(39, 39, 42, 255))  # panel_alt #27272A
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        if not self._active:
            self._to(QColor(0, 0, 0, 0))
        super().leaveEvent(event)

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self._active:  # barra de acento vertical a la izquierda del botón seleccionado
            p = QPainter(self)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(COLORS["accent"]))
            p.drawRoundedRect(QRectF(0, 9, 3, self.height() - 18), 1.5, 1.5)
            p.end()


class HoldButton(QPushButton):
    """
    Botón de «mantener pulsado para ejecutar»: para acciones peligrosas, emite `held` solo si se
    mantiene pulsado HOLD_MS (1,5 s); si se suelta antes, se cancela. Mientras se mantiene, muestra
    «MANTÉN PULSADO…» y una barra de progreso azul que se llena. Evita disparos por un clic accidental.
    """
    held = Signal()
    HOLD_MS = 1500

    def __init__(self, text: str):
        super().__init__(text)
        self.setObjectName("Warn")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._base = text
        self._fill = 0.0
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._fire)
        self._anim = QPropertyAnimation(self, b"fill", self)
        self._anim.setDuration(self.HOLD_MS)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)

    def setText(self, text: str) -> None:  # mantiene sincronizado el texto base al cambiarlo la app
        self._base = text
        super().setText(text)

    def _get_fill(self):
        return self._fill

    def _set_fill(self, value):
        self._fill = value
        self.update()

    fill = Property(float, _get_fill, _set_fill)

    def _begin_hold(self) -> None:
        if not self.isEnabled():
            return
        super().setText("◼  MANTÉN PULSADO…")
        self._timer.start(self.HOLD_MS)
        self._anim.stop()
        self._anim.start()

    def _end_hold(self) -> None:
        if self._timer.isActive():  # se soltó antes de tiempo: cancelar
            self._timer.stop()
            self._anim.stop()
            self._set_fill(0.0)
            super().setText(self._base)

    def _fire(self) -> None:
        self._anim.stop()
        self._set_fill(0.0)
        super().setText(self._base)
        self.held.emit()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._begin_hold()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        self._end_hold()
        super().mouseReleaseEvent(event)

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self._fill > 0:  # barra de progreso del «hold» en el borde inferior
            p = QPainter(self)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor("#60A5FA"))
            p.drawRect(0, self.height() - 3, int(self.width() * self._fill), 3)


class TelemetryConsole(QPlainTextEdit):
    """
    Consola de telemetría corporativa (SOC): solo lectura, monoespaciada, con marca de tiempo tenue,
    etiqueta de sistema coloreada por tipo (azul hielo para [+]/[TACTICAL]) y mensaje en blanco hueso;
    el rojo se reserva para errores/alertas críticas. Auto-scroll al final.
    """
    KIND = {"+": "#60A5FA", "~": "#A1A1AA", "*": "#22C55E", "!": "#F59E0B", "x": "#EF4444",
            "TACTICAL": "#60A5FA"}

    def __init__(self):
        super().__init__()
        self.setObjectName("Console")
        self.setReadOnly(True)
        self.setMaximumBlockCount(600)
        self.setFont(QFont("Consolas", 10))

    def log(self, kind: str, text: str) -> None:
        tag = self.KIND.get(kind, "#A1A1AA")
        msg = "#EF4444" if kind == "x" else "#FAFAFA"  # rojo solo para errores/alertas críticas
        when = dt.datetime.now().strftime("%H:%M:%S")
        safe = html.escape(text.rstrip())
        self.appendHtml(f'<span style="color:#71717A">[{when}]</span> '
                        f'<span style="color:{tag}">[{kind}]</span> '
                        f'<span style="color:{msg}">{safe}</span>')
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())  # auto-scroll al final


class ConsolePanel(QFrame):
    """
    Consola de telemetría plegable con cabecera: título, indicador de actividad, filtros rápidos por
    tipo de mensaje (TODOS/TACTICAL/WARNING/CRITICAL), contador de eventos y botones Limpiar y
    Plegar/Desplegar. Expone `log(kind, text)`, así que `app.console` la sustituye sin más cambios.
    """
    # etiqueta -> conjunto de `kind` que deja pasar (None = todos)
    FILTERS = [("TODOS", None), ("TACTICAL", {"TACTICAL"}), ("WARNING", {"!"}), ("CRITICAL", {"x"})]
    MAX_KEEP = 600

    def __init__(self):
        super().__init__()
        self.setObjectName("ConsoleWrap")
        self._count = 0
        self._filter = None
        self._entries = deque(maxlen=self.MAX_KEEP)   # (kind, text) para re-render al filtrar
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        head.setSpacing(8)
        title = QLabel("CONSOLA DE TELEMETRÍA")
        title.setObjectName("ConsoleTitle")
        head.addWidget(title)
        self._filter_btns = {}
        for label, kinds in self.FILTERS:
            b = QPushButton(label)
            b.setObjectName("Chiplet")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=kinds, lb=label: self._set_filter(k, lb))
            head.addWidget(b)
            self._filter_btns[label] = b
        self._filter_btns["TODOS"].setChecked(True)
        head.addStretch(1)
        # Indicador global de actividad (lo gestiona MainWindow a través de .activity).
        self.activity = QPushButton("")
        self.activity.setObjectName("Activity")
        self.activity.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.activity.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.activity.setIconSize(QSize(13, 13))
        self.activity_spin = qta.Spin(self.activity, interval=30, step=10) if HAS_QTA else None
        self.activity.setIcon(icon("fa5s.circle-notch", COLORS["accent"], animation=self.activity_spin))
        self.activity.hide()
        head.addWidget(self.activity)
        self.counter = QLabel("0 eventos")
        self.counter.setObjectName("Tiny")
        head.addWidget(self.counter)
        self.clear_btn = QPushButton("Limpiar")
        self.clear_btn.setObjectName("Mini")
        with_icon(self.clear_btn, "fa5s.trash-alt", COLORS["muted"], 12)
        self.clear_btn.clicked.connect(self.clear)
        head.addWidget(self.clear_btn)
        self.collapse_btn = QPushButton("▼")
        self.collapse_btn.setObjectName("Mini")
        self.collapse_btn.setFixedWidth(34)
        self.collapse_btn.setToolTip("Plegar la consola")
        self.collapse_btn.clicked.connect(self.toggle_collapsed)
        head.addWidget(self.collapse_btn)
        lay.addLayout(head)

        self.console = TelemetryConsole()
        self.console.setMinimumHeight(110)
        lay.addWidget(self.console, 1)

    def log(self, kind: str, text: str) -> None:
        self._entries.append((kind, text))
        self._count += 1
        self.counter.setText(f"{self._count} evento{'s' if self._count != 1 else ''}")
        if self._filter is None or kind in self._filter:
            self.console.log(kind, text)

    def _set_filter(self, kinds, label) -> None:
        for lb, b in self._filter_btns.items():
            b.setChecked(lb == label)
        self._filter = kinds
        self.console.clear()
        for kind, text in self._entries:   # re-pinta solo lo que pasa el filtro
            if kinds is None or kind in kinds:
                self.console.log(kind, text)

    def clear(self) -> None:
        self._entries.clear()
        self.console.clear()
        self._count = 0
        self.counter.setText("0 eventos")

    def toggle_collapsed(self) -> None:
        collapsed = self.console.isVisible()
        self.console.setVisible(not collapsed)
        self.collapse_btn.setText("▲" if collapsed else "▼")
        self.collapse_btn.setToolTip("Desplegar la consola" if collapsed else "Plegar la consola")


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


class Page(QWidget):
    """
    Sección con cabecera FIJA (título + subtítulo) y un cuerpo con scroll vertical. `self.root` es el
    layout de ese cuerpo: las páginas añaden ahí sus tarjetas sin ocuparse del scroll. Sin él, el
    QStackedWidget heredaba el mínimo de la página más alta (≈1430×1630 px) e ignoraba el tamaño de
    la ventana, que se salía de una pantalla 1080p.
    """

    def __init__(self, title: str, subtitle: str, icon_name: Optional[str] = None):
        super().__init__()
        self.setObjectName("Content")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(30, 26, 30, 16)
        outer.setSpacing(16)
        header = QHBoxLayout()
        header.setSpacing(14)
        if icon_name:
            ic = QLabel()
            ic.setPixmap(icon(icon_name, COLORS["accent"]).pixmap(30, 30))
            ic.setAlignment(Qt.AlignmentFlag.AlignTop)
            header.addWidget(ic)
        titlecol = QVBoxLayout()
        titlecol.setSpacing(2)
        head = QLabel(title)
        head.setObjectName("PageTitle")
        sub = QLabel(subtitle)
        sub.setObjectName("PageSub")
        sub.setWordWrap(True)
        titlecol.addWidget(head)
        titlecol.addWidget(sub)
        header.addLayout(titlecol, 1)
        outer.addLayout(header)

        scroll = QScrollArea()
        scroll.setObjectName("Content")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        body.setObjectName("Content")
        self.root = QVBoxLayout(body)
        self.root.setContentsMargins(0, 0, 4, 0)
        self.root.setSpacing(16)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)


class Gauge(QWidget):
    """Medidor circular dibujado con QPainter: pista gris, arco de color y porcentaje en el centro."""

    def __init__(self, color="#60A5FA", size=132, thickness=11):
        super().__init__()
        self.setFixedSize(size, size)
        self._value = 0.0
        self._color = color
        self._thickness = thickness

    def set_value(self, value) -> None:
        self._value = max(0.0, min(100.0, float(value)))
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        m = self._thickness / 2 + 4
        rect = QRectF(m, m, self.width() - 2 * m, self.height() - 2 * m)
        track = QPen(QColor("#27272A"))
        track.setWidthF(self._thickness)
        track.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(track)
        p.drawArc(rect, 0, 360 * 16)
        if self._value > 0:
            arc = QPen(QColor(self._color))
            arc.setWidthF(self._thickness)
            arc.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(arc)
            p.drawArc(rect, 90 * 16, -int(360 * 16 * self._value / 100))
        p.setPen(QColor("#FAFAFA"))
        p.setFont(QFont("Segoe UI", 21, QFont.Weight.Bold))
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{self._value:.0f}%")


class BentoCard(QFrame):
    """Tarjeta grande clicable (bento) con icono, título, descripción y estado; borde animado al hover."""

    def __init__(self, icon_name, title, desc, status_fn, on_click):
        super().__init__()
        self.setObjectName("Bento")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(154)
        self._on_click = on_click
        self._status_fn = status_fn
        self._border = QColor(COLORS["border"])
        self._anim = QPropertyAnimation(self, b"border", self)
        self._anim.setDuration(170)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(8)
        top = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon(icon_name, COLORS["accent"]).pixmap(26, 26))
        top.addWidget(ic)
        top.addStretch(1)
        self.dot = QLabel("●")
        self.dot.setStyleSheet("color:#52525B; font-size:11px;")
        top.addWidget(self.dot)
        lay.addLayout(top)
        t = QLabel(title)
        t.setObjectName("CardTitle")
        t.setWordWrap(True)  # sin esto, 4 títulos largos por fila forzaban scroll horizontal
        d = QLabel(desc)
        d.setObjectName("CardText")
        d.setWordWrap(True)
        lay.addWidget(t)
        lay.addWidget(d)
        lay.addStretch(1)
        self.status = QLabel("")
        self.status.setObjectName("Tiny")
        lay.addWidget(self.status)
        self._last: Optional[Tuple[bool, str]] = None
        self._apply()
        self.refresh()

    def refresh(self) -> None:
        state = self._status_fn()
        if state == self._last:
            return  # sin cambios: no re-aplicar estilos (cada setStyleSheet fuerza un re-polish)
        self._last = state
        active, text = state
        self.dot.setStyleSheet(f"color:{'#22C55E' if active else '#52525B'}; font-size:11px;")
        self.status.setText(text)

    def _get_border(self):
        return self._border

    def _set_border(self, color):
        self._border = color
        self._apply()

    border = Property(QColor, _get_border, _set_border)

    def _apply(self):
        c = self._border
        self.setStyleSheet(f"#Bento {{ background:#18181C; border:1px solid "
                           f"rgb({c.red()},{c.green()},{c.blue()}); border-radius:10px; }}")

    def _to(self, color):
        self._anim.stop()
        self._anim.setStartValue(self._border)
        self._anim.setEndValue(QColor(color))
        self._anim.start()

    def enterEvent(self, event):
        self._to(QColor(COLORS["accent"]))
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._to(QColor(COLORS["border"]))
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._on_click()
        super().mousePressEvent(event)


# ===========================================================================
# ESTADO DE COMPONENTES (comprobaciones REALES, sin datos ficticios)
# ===========================================================================
# Cuatro estados, cada uno con color + TEXTO (nunca solo color).
ST_OK, ST_DEGRADED, ST_STOPPED, ST_NOIMPL = "operativo", "degradado", "detenido", "no_implementado"
ST_ALERT = "alerta"  # incidente activo (p. ej. una trampa del honeypot comprometida)
STATE_STYLE = {
    ST_OK:       ("#10B981", "OPERATIVO"),
    ST_DEGRADED: ("#F59E0B", "DEGRADADO"),
    ST_ALERT:    ("#EF4444", "ALERTA"),
    ST_STOPPED:  ("#71717A", "DETENIDO"),
    ST_NOIMPL:   ("#52525B", "NO IMPLEMENTADO"),
}


def badge_qss(color: str, size: int = 10) -> str:
    """Estilo de «píldora» semántica: texto del color del estado sobre un tinte suave del mismo."""
    r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
    return (f"color:{color}; background: rgba({r},{g},{b},0.13); border: 1px solid rgba({r},{g},{b},0.40);"
            f" border-radius: 9px; padding: 2px 9px; font-size:{size}px; font-weight:bold;"
            f" letter-spacing:0.5px;")

class PulseGraph(QWidget):
    """
    Pulso en vivo (QPainter): curvas de los últimos 60 s de CPU %, Memoria % y tráfico de red. CPU y
    RAM van en escala fija 0-100; la red se autoescala a su máximo reciente (se muestra su KB/s). Es
    ligero: guarda tres deques de 60 puntos y repinta en cada tic de 1 s.
    """
    SERIES = [("CPU", "#60A5FA"), ("RAM", "#A78BFA"), ("RED", "#34D399")]

    def __init__(self):
        super().__init__()
        self.setMinimumSize(210, 96)
        self._cpu = deque(maxlen=60)
        self._ram = deque(maxlen=60)
        self._net = deque(maxlen=60)
        self._net_kbs = 0.0

    def push(self, cpu: float, ram: float, net_kbs: float) -> None:
        self._cpu.append(max(0.0, min(100.0, cpu)))
        self._ram.append(max(0.0, min(100.0, ram)))
        self._net.append(max(0.0, net_kbs))
        self._net_kbs = net_kbs
        self.update()

    def _poly(self, data, w, h, pad, vmax):
        n = len(data)
        if n < 2:
            return None
        step = (w - 2 * pad) / (self._cpu.maxlen - 1)
        x0 = w - pad - (n - 1) * step
        pts = []
        for i, v in enumerate(data):
            y = h - pad - (v / vmax if vmax else 0) * (h - 2 * pad)
            pts.append(QPointF(x0 + i * step, y))
        return QPolygonF(pts)

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h, pad = self.width(), self.height(), 8
        p.setPen(QPen(QColor("#1F1F27"), 1))
        for frac in (0.0, 0.5, 1.0):   # rejilla horizontal tenue
            y = pad + frac * (h - 2 * pad)
            p.drawLine(int(pad), int(y), int(w - pad), int(y))
        net_max = max(list(self._net) or [1.0]) or 1.0
        for data, (_lbl, color), vmax in ((self._cpu, self.SERIES[0], 100.0),
                                          (self._ram, self.SERIES[1], 100.0),
                                          (self._net, self.SERIES[2], net_max)):
            poly = self._poly(data, w, h, pad, vmax)
            if poly is None:
                continue
            pen = QPen(QColor(color))
            pen.setWidthF(1.6)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPolyline(poly)
        p.end()

    def net_label(self) -> str:
        v = self._net_kbs
        return f"{v/1024:.1f} MB/s" if v >= 1024 else f"{v:.0f} KB/s"


class HealthBadge(QFrame):
    """Puntuación de salud global del sistema (0-100): número grande + etiqueta, con color semántico."""

    def __init__(self):
        super().__init__()
        self.setObjectName("Card")
        self.setFixedWidth(118)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(13, 10, 13, 10)
        lay.setSpacing(2)
        cap = QLabel("SALUD")
        cap.setObjectName("ChipCap")
        self.value = QLabel("—")
        self.value.setStyleSheet("color:#FAFAFA; font-size:28px; font-weight:bold;")
        self.label = QLabel("")
        self.label.setObjectName("Tiny")
        lay.addWidget(cap)
        lay.addWidget(self.value)
        lay.addWidget(self.label)

    def set_score(self, score: Optional[int], etiqueta: str) -> None:
        if score is None:
            self.value.setText("—")
            self.label.setText("calculando…")
            return
        color = "#10B981" if score >= 85 else "#F59E0B" if score >= 60 else "#EF4444"
        self.value.setText(str(score))
        self.value.setStyleSheet(f"color:{color}; font-size:30px; font-weight:bold;")
        self.label.setText(etiqueta)


# Componente del panel de salud -> página a la que lleva su mini-botón de acceso (o None).
COMPONENT_PAGE = {
    "Motor de auditoría": "auditoria", "Telemetría de procesos": "monitor", "Honeypot": "honeypot",
    "Persistencia Táctica": "honeypot", "Caja Negra": "historial", "Endurecimiento de Red": "red",
    "Modo Fantasma (herramientas)": "fantasma", "Laboratorio Forense": "historial",
    "Núcleo de eventos (bus)": "historial", "OBSIDIAN (salud de telemetría)": "comando",
}


class ComponentCard(QFrame):
    """Tarjeta compacta de un componente para la rejilla Bento de 2 columnas (sustituye a la fila)."""

    def __init__(self, name: str, state: str, detail: str, on_open):
        super().__init__()
        self.setObjectName("CompCard")
        self.name = name
        self._state = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(3)
        top = QHBoxLayout()
        top.setSpacing(8)
        self.dot = QLabel("●")
        nm = QLabel(name)
        nm.setStyleSheet("color:#FAFAFA; font-size:12px; font-weight:600;")
        self.badge = QLabel()
        top.addWidget(self.dot)
        top.addWidget(nm)
        top.addStretch(1)
        top.addWidget(self.badge)
        key = COMPONENT_PAGE.get(name)
        if key and on_open is not None:
            go = QPushButton("→")
            go.setObjectName("CompGo")
            go.setFixedSize(22, 22)
            go.setCursor(Qt.CursorShape.PointingHandCursor)
            go.setToolTip(f"Ir a {name}")
            go.clicked.connect(lambda _=False, k=key: on_open(k))
            top.addWidget(go)
        lay.addLayout(top)
        self.detail = QLabel(detail)
        self.detail.setStyleSheet("color:#A1A1AA; font-size:11px;")
        self.detail.setWordWrap(True)
        lay.addWidget(self.detail)
        self.setStyleSheet("#CompCard { background:#141418; border:1px solid #272730; border-radius:9px; }")
        self.set_state(state, detail)

    def set_state(self, state: str, detail: str) -> None:
        if detail != self.detail.text():
            self.detail.setText(detail)
        if state == self._state:
            return
        self._state = state
        color, label = STATE_STYLE.get(state, ("#71717A", "—"))
        self.dot.setStyleSheet(f"color:{color}; font-size:10px;")
        self.badge.setText(label)
        self.badge.setStyleSheet(badge_qss(color, 9))


# Las 8 áreas previstas del producto. `key` = página existente a la que navega, o None si es el
# propio Cuartel General o un área aún no implementada (se marca «Pendiente», sin fingir que va).
AREAS = [
    ("fa5s.tachometer-alt", "Cuartel General", "Resumen de estado y telemetría del equipo.", None),
    ("fa5s.wave-square", "Centinela", "Monitor en vivo de red y procesos.", "monitor"),
    ("fa5s.shield-alt", "Taller Windows", "Auditoría y endurecimiento del sistema.", "auditoria"),
    ("fa5s.eye", "Defensa y engaño", "Honeypot y señuelos defensivos.", "honeypot"),
    ("fa5s.network-wired", "Perímetro y dispositivos", "Red (ICMP) y control de USB.", "red"),
    ("fa5s.fingerprint", "Laboratorio forense", "Snapshots e historial del sistema.", "historial"),
    ("fa5s.ghost", "Modo Fantasma", "Privacidad, anti-clipper y limpieza.", "fantasma"),
    ("fa5s.vial", "Mesa de Autopsias", "Análisis estático de archivos sospechosos.", "historial"),
]


def collect_component_status(modules, plugin_errors, bus=None, blackbox=None,
                             honeypot=None, tactical_config=None, live=None):
    """
    Comprueba el estado REAL de los componentes de Lozarus en este equipo. Función pensada para
    ejecutarse en un hilo de fondo (hace algún os.stat); no toca la interfaz ni modifica nada.
    `live` es una instantánea barata tomada en el hilo de la UI (vigilancias activas, Vanguardia,
    último diagnóstico) para que esas filas muestren el estado VIVO; si falta una clave, la fila no
    la menciona (nunca se muestra un valor por defecto como si fuera real).
    Devuelve [(nombre, estado, detalle)]. Nunca inventa datos: lo que no existe se marca como tal.
    """
    live = live or {}
    rows = []

    # Privilegios
    if is_admin():
        rows.append(("Privilegios", ST_OK, "Administrador: auditoría y acciones completas"))
    else:
        rows.append(("Privilegios", ST_DEGRADED, "Usuario estándar: auditoría parcial · eleva con UAC"))

    # Motor de auditoría (plugins cargados + último diagnóstico de la sesión)
    n = len(modules)
    audit = live.get("last_audit")
    ultimo = (f" · último diagnóstico {audit[0]}/100 ({audit[1]} CRITICAL, {audit[2]} WARNING)"
              if audit else " · sin diagnóstico en esta sesión")
    if n == 0:
        rows.append(("Motor de auditoría", ST_STOPPED, "ningún plugin cargado"))
    elif plugin_errors:
        rows.append(("Motor de auditoría", ST_DEGRADED,
                     f"{n} plugins · {len(plugin_errors)} con error" + ultimo))
    else:
        rows.append(("Motor de auditoría", ST_OK, f"{n} plugins cargados" + ultimo))

    # Telemetría de procesos (psutil): recuento real de procesos ahora mismo
    if HAS_PSUTIL:
        try:
            rows.append(("Telemetría de procesos", ST_OK,
                         f"psutil · {len(psutil.pids())} procesos en el equipo ahora"))
        except Exception as exc:  # noqa: BLE001
            rows.append(("Telemetría de procesos", ST_DEGRADED, f"psutil con error: {exc}"))
    else:
        rows.append(("Telemetría de procesos", ST_STOPPED, "psutil no disponible"))

    # PowerShell (muchas comprobaciones dependen de él)
    ps = _powershell_exe()
    rows.append(("PowerShell", ST_OK if ps else ST_STOPPED,
                 f"disponible · {ps}" if ps else "no encontrado"))

    # Notificaciones de escritorio (Vanguardia)
    sentinel_on = bool(live.get("sentinel_on"))
    rows.append(("Notificaciones (Vanguardia)", ST_OK if HAS_PLYER else ST_DEGRADED,
                 ("plyer disponible · Vanguardia " + ("ACTIVA" if sentinel_on else "desactivada"))
                 if HAS_PLYER else "sin plyer: avisos nativos desactivados"))

    # Windows Sandbox (detonación aislada)
    ok_sb, _info = sandbox_available()
    rows.append(("Windows Sandbox", ST_OK if ok_sb else ST_STOPPED,
                 "disponible" if ok_sb else "no activado en este Windows"))

    # Cuarentena (estado actual real): activa = el equipo está aislado → ALERTA visible
    q_on = quarantine_active()
    rows.append(("Cuarentena", ST_ALERT if q_on else ST_OK,
                 "ACTIVA ahora: equipo aislado" if q_on else "en reposo (lista)"))

    # Honeypot: estado en vivo del motor de engaño (comprometido = ALERTA en rojo).
    if honeypot is not None:
        st = honeypot.status()
        if not st["active"]:
            rows.append(("Honeypot", ST_STOPPED, "red de trampas retirada (lista para desplegar)"))
        elif not st["integridad"]:
            rows.append(("Honeypot", ST_ALERT,
                         f"{st['comprometidos']} trampa(s) comprometida(s) · "
                         f"{st['incidentes']} incidente(s)"))
        else:
            rows.append(("Honeypot", ST_OK,
                         f"{st['total']} cebos activos · {st['incidentes']} incidente(s) · "
                         f"auto-reconstrucción {'ON' if st.get('auto_rebuild') else 'OFF'}"))
    else:
        rows.append(("Honeypot", ST_NOIMPL, "motor de engaño no disponible"))

    # Persistencia Táctica: configuración que sobrevive al reinicio.
    if tactical_config is not None:
        rows.append(("Persistencia Táctica", ST_OK,
                     f"{len(tactical_config.as_dict())} ajuste(s) guardado(s) · "
                     f"{os.path.basename(tactical_config.path)}"))
    else:
        rows.append(("Persistencia Táctica", ST_STOPPED, "no disponible"))

    # Colector ETW: el código existe y está probado, pero la GUI aún no abre ninguna sesión.
    has_etw = importlib.util.find_spec("etw") is not None
    rows.append(("Colector ETW", ST_STOPPED,
                 "código probado; la GUI no abre sesión"
                 + ("" if has_etw else " · pywintrace no instalado aquí")))

    # Núcleo de eventos (bus): operativo si la GUI lo ha arrancado; si no, solo probado.
    if bus is not None:
        try:
            m = bus.metrics()
            rows.append(("Núcleo de eventos (bus)", ST_OK,
                         f"en ejecución · {m.published} publicados, {m.delivered} entregados, "
                         f"{m.dropped} descartados"))
        except Exception:  # noqa: BLE001
            rows.append(("Núcleo de eventos (bus)", ST_STOPPED, "cargado, sin métricas disponibles"))
    else:
        try:
            importlib.import_module("core.bus")
            rows.append(("Núcleo de eventos (bus)", ST_STOPPED, "implementado y probado; integración pendiente"))
        except Exception:  # noqa: BLE001
            rows.append(("Núcleo de eventos (bus)", ST_STOPPED, "no cargado"))

    # Caja Negra: operativa si está persistiendo eventos; si no, no disponible en esta sesión.
    if blackbox is not None:
        mb = blackbox.metrics()
        detalle = f"{mb['written']} eventos persistidos en esta sesión (JSONL append-only)"
        if mb["dropped"] or mb["write_errors"]:
            detalle += f" · {mb['dropped']} descartados, {mb['write_errors']} errores de escritura"
        rows.append(("Caja Negra", ST_DEGRADED if mb["write_errors"] else ST_OK, detalle))
    else:
        rows.append(("Caja Negra", ST_NOIMPL, "persistencia de eventos no disponible en esta sesión"))

    # Endurecimiento de Red: herramientas + estado real de la vigilancia de puertos (si se conoce).
    detalle_red = "escáner de puertos, flushdns y lectura de Firewall/servicios"
    if "net_watch" in live:
        detalle_red += (f" · vigilancia de puertos ON ({live.get('net_watch_ports', 0)} en escucha "
                        "de referencia)" if live["net_watch"] else " · vigilancia de puertos OFF")
    if not HAS_PSUTIL:
        detalle_red += " · sin psutil: escáner limitado"
    if not is_admin():
        detalle_red += " · servicios/ICMP requieren Admin"
    rows.append(("Endurecimiento de Red", ST_OK if HAS_PSUTIL else ST_DEGRADED, detalle_red))

    # Modo Fantasma: herramientas + estado real de la vigilancia del portapapeles (si se conoce).
    detalle_fantasma = "trituradora, anti-clipper, optimizar RAM y limpieza de temporales"
    if "clip_watch" in live:
        detalle_fantasma += (" · portapapeles vigilado" if live["clip_watch"]
                             else " · portapapeles sin vigilar")
        if live.get("autopurge"):
            detalle_fantasma += " · auto-purga ON"
    rows.append(("Modo Fantasma (herramientas)", ST_OK, detalle_fantasma))

    # Laboratorio Forense: expedientes guardados en disco (dato real) + herramientas.
    try:
        snaps = len(list_snapshots())
    except Exception:  # noqa: BLE001
        snaps = 0
    rows.append(("Laboratorio Forense", ST_OK,
                 f"{snaps} snapshot(s) en disco · visor de la Caja Negra y mesa de autopsias"))

    # OBSIDIAN: salud de la PROPIA telemetría (ritmo del bus, tamaño del JSONL, CPU/RAM/hilos de Lozarus).
    obs = live.get("obsidian")
    if obs is not None:
        v = obs.get("vitals") or {}
        partes = []
        if obs.get("epm") is not None:
            partes.append(f"{obs['epm']:.0f} ev/min")
        if obs.get("jsonl_kb") is not None:
            partes.append(f"eventos.jsonl {obs['jsonl_kb']} KB")
        if v.get("rss_mb") is not None:
            partes.append(f"Lozarus {v['rss_mb']} MB")
        if v.get("cpu") is not None:
            partes.append(f"{v['cpu']}% CPU")
        if v.get("threads") is not None:
            partes.append(f"{v['threads']} hilos")
        rows.append(("OBSIDIAN (salud de telemetría)", ST_OK, " · ".join(partes) or "midiendo…"))
    else:
        rows.append(("OBSIDIAN (salud de telemetría)", ST_STOPPED, "sin datos de telemetría en esta sesión"))

    return rows


class ComponentRow(QFrame):
    """Fila de estado de un componente: punto de color + nombre + detalle + etiqueta de estado."""

    def __init__(self, name: str, state: str, detail: str):
        super().__init__()
        self.setObjectName("CompRow")
        self.name = name
        self._state: Optional[str] = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 7, 12, 7)
        lay.setSpacing(10)
        self.dot = QLabel("●")
        lay.addWidget(self.dot)
        nm = QLabel(name)
        nm.setStyleSheet("color:#FAFAFA; font-size:13px; font-weight:600;")
        nm.setMinimumWidth(190)
        lay.addWidget(nm)
        self.detail = QLabel(detail)
        self.detail.setStyleSheet("color:#A1A1AA; font-size:11px;")
        self.detail.setWordWrap(True)
        lay.addWidget(self.detail, 1)
        self.badge = QLabel()
        lay.addWidget(self.badge)
        self.setStyleSheet("#CompRow { background:#141418; border:1px solid #27272A; border-radius:8px; }")
        self.set_state(state, detail)

    def set_state(self, state: str, detail: str) -> None:
        """Actualiza la fila EN SU SITIO; solo re-aplica estilos si cambió el estado (no el detalle)."""
        if detail != self.detail.text():
            self.detail.setText(detail)
        if state == self._state:
            return
        self._state = state
        color, label = STATE_STYLE.get(state, ("#71717A", "—"))
        self.dot.setStyleSheet(f"color:{color}; font-size:11px;")
        self.badge.setText(label)
        self.badge.setStyleSheet(badge_qss(color))


# ===========================================================================
# PÁGINAS
# ===========================================================================
class CommandPage(Page):
    """Cuartel General: telemetría real (CPU/RAM), estado de componentes y accesos a las 8 áreas."""

    def __init__(self, app: "MainWindow"):
        super().__init__("Centro de Comando",
                         "Telemetría del sistema y acceso rápido a la defensa local.", "fa5s.tachometer-alt")
        self.app = app

        # --- Cabecera de telemetría en vivo ---
        tele = QFrame()
        tele.setObjectName("Card")
        tlay = QHBoxLayout(tele)
        tlay.setContentsMargins(24, 20, 24, 20)
        tlay.setSpacing(20)
        self.cpu_gauge = Gauge("#60A5FA", size=116)
        self.ram_gauge = Gauge("#A78BFA", size=116)
        for gauge, caption in ((self.cpu_gauge, "CPU"), (self.ram_gauge, "MEMORIA")):
            col = QVBoxLayout()
            col.setSpacing(8)
            col.addWidget(gauge, 0, Qt.AlignmentFlag.AlignHCenter)
            lbl = QLabel(caption)
            lbl.setObjectName("ChipCap")
            lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            col.addWidget(lbl)
            tlay.addLayout(col)
        # Pulso en vivo (CPU/RAM/Red, últimos 60 s) + puntuación de salud del sistema
        pulsecol = QVBoxLayout()
        pulsecol.setSpacing(4)
        pcap = QLabel("PULSO · 60 s")
        pcap.setObjectName("ChipCap")
        self.pulse = PulseGraph()
        self.pulse_legend = QLabel("CPU — · RAM — · RED —")
        self.pulse_legend.setObjectName("Tiny")
        pulsecol.addWidget(pcap)
        pulsecol.addWidget(self.pulse, 1)
        pulsecol.addWidget(self.pulse_legend)
        tlay.addLayout(pulsecol, 1)
        self.health = HealthBadge()
        tlay.addWidget(self.health)
        # Escudo global
        shield = QVBoxLayout()
        shield.setSpacing(8)
        self.shield_icon = QLabel()
        self.shield_icon.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.shield_icon.setFixedHeight(76)
        self.shield_state = QLabel("")
        self.shield_state.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        lbl = QLabel("ESCUDO")
        lbl.setObjectName("ChipCap")
        lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        shield.addWidget(self.shield_icon)
        shield.addWidget(self.shield_state)
        shield.addWidget(lbl)
        tlay.addLayout(shield)
        # Info del equipo
        info = QVBoxLayout()
        info.setSpacing(6)
        info.addStretch(1)
        for label, value in self._system_rows():
            row = QHBoxLayout()
            k = QLabel(label)
            k.setObjectName("CardText")
            k.setFixedWidth(88)
            v = QLabel(value)
            v.setStyleSheet("color:#FAFAFA; font-family:'Consolas'; font-size:12px;")
            row.addWidget(k)
            row.addWidget(v, 1)
            info.addLayout(row)
        info.addStretch(1)
        tlay.addLayout(info, 1)
        self.root.addWidget(tele)

        # --- Perfiles rápidos de operación (1 clic) ---
        prof_row = QHBoxLayout()
        prof_row.setSpacing(10)
        plabel = QLabel("PERFIL:")
        plabel.setObjectName("ChipCap")
        prof_row.addWidget(plabel)
        self.profile_btns = {}
        for key, text, tip in (
                ("equilibrado", "Equilibrado", "Sondeos a ritmo normal; sin tocar el equipo."),
                ("rendimiento", "Rendimiento / Baja latencia",
                 "Reduce la frecuencia de los sondeos y libera working sets de RAM una vez."),
                ("supervision", "Supervisión total",
                 "Activa todos los monitores disponibles: red, portapapeles y procesos.")):
            b = QPushButton(text)
            b.setObjectName("Toggle")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setToolTip(tip)
            b.clicked.connect(lambda _=False, k=key: self.app.apply_profile(k))
            self.profile_btns[key] = b
            prof_row.addWidget(b)
        self.profile_btns["equilibrado"].setChecked(True)
        prof_row.addStretch(1)
        self.root.addLayout(prof_row)

        # --- Piloto Automático ---
        self.root.addWidget(self._build_autopilot_card())

        # --- Aviso + relanzamiento con UAC (solo si NO somos Administrador) ---
        if not app.admin:
            uac_row = QHBoxLayout()
            uac_row.setSpacing(10)
            self.uac_btn = QPushButton("Relanzar como Administrador (UAC)")
            self.uac_btn.setObjectName("Warn")
            with_icon(self.uac_btn, "fa5s.user-shield", COLORS["beacon"])
            self.uac_btn.clicked.connect(self.app.relaunch_as_admin)
            aviso = QLabel("Sin privilegios: desactivar servicios y el ocultamiento ICMP requieren "
                           "elevación.")
            aviso.setObjectName("Tiny")
            aviso.setWordWrap(True)
            uac_row.addWidget(self.uac_btn)
            uac_row.addWidget(aviso, 1)
            self.root.addLayout(uac_row)

        # --- Panel de estado de componentes (comprobaciones reales, en segundo plano) ---
        comp_card = QFrame()
        comp_card.setObjectName("Card")
        cl = QVBoxLayout(comp_card)
        cl.setContentsMargins(18, 16, 18, 16)
        cl.setSpacing(8)
        ctitle = QLabel("Estado de los componentes de Lozarus")
        ctitle.setObjectName("CardTitle")
        csub = QLabel("Comprobaciones reales de este equipo. Lo que aún no tiene backend se marca como "
                      "detenido o no implementado, sin fingir que funciona.")
        csub.setObjectName("CardText")
        csub.setWordWrap(True)
        cl.addWidget(ctitle)
        cl.addWidget(csub)
        self.comp_grid = QGridLayout()
        self.comp_grid.setSpacing(8)
        self.comp_grid.setColumnStretch(0, 1)
        self.comp_grid.setColumnStretch(1, 1)
        cl.addLayout(self.comp_grid)
        self.comp_loading = QLabel("Comprobando componentes…")
        self.comp_loading.setObjectName("Tiny")
        cl.addWidget(self.comp_loading)
        self.root.addWidget(comp_card)
        self._comp_worker = None

        # --- Rejilla de accesos a las 8 áreas del producto ---
        areas_title = QLabel("Áreas de Lozarus")
        areas_title.setObjectName("CardTitle")
        areas_title.setStyleSheet("margin-top:4px;")
        self.root.addWidget(areas_title)
        grid = QGridLayout()
        grid.setSpacing(14)
        self.cards = []
        for index, (icon_name, title, desc, key) in enumerate(AREAS):
            card = BentoCard(icon_name, title, desc, self._area_status_fn(key, title),
                             (lambda k=key, t=title: self._open_area(k, t)))
            self.cards.append(card)
            grid.addWidget(card, index // 4, index % 4)
        self.root.addLayout(grid)
        self.root.addStretch(1)

        psutil.cpu_percent(interval=None)  # primer muestreo (devuelve 0; los siguientes miden el delta)
        try:
            self._net_io = psutil.net_io_counters()
        except Exception:  # noqa: BLE001
            self._net_io = None
        self._net_t = time.monotonic()
        self._shield_on: Optional[bool] = None   # último estado pintado del escudo
        self._obs_prev = None                     # muestra previa del contador del bus (OBSIDIAN)
        self._obs_prev_t = None
        self._ap_ram_last = 0.0                   # último momento en que se liberó RAM automáticamente
        self._comp_rows: list = []               # filas de componentes vivas (se actualizan en su sitio)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        # Los componentes cambian despacio: se recomprueban cada 8 s, en un hilo aparte.
        self._comp_timer = QTimer(self)
        self._comp_timer.setInterval(8000)
        self._comp_timer.timeout.connect(self._load_components)
        self._comp_timer.start()
        # Primer tic y primera carga de componentes diferidos a cuando arranca el bucle de eventos:
        # no bloquean la construcción (así el arranque se mantiene por debajo de 300 ms) y, para
        # entonces, self.app.pages ya existe y las tarjetas de área muestran su estado real.
        QTimer.singleShot(0, self._tick)
        QTimer.singleShot(0, self._load_components)

    # --- Áreas (navegación honesta: disponible vs. pendiente) ---------------------------------
    def _area_status_fn(self, key, title):
        # El estado se evalúa EN CADA LLAMADA (no al construir): self.app.pages todavía no existe
        # mientras se crea esta página, así que no se puede capturar aquí.
        def status():
            pages = getattr(self.app, "pages", {})
            if key is None and title == "Cuartel General":
                return (True, "Área actual")
            if key and key in pages:
                if key == "monitor":
                    running = bool(getattr(pages.get("monitor"), "running", False))
                    return (running, "En directo" if running else "Disponible")
                if key == "honeypot":
                    hp = getattr(self.app, "honeypot", None)
                    if hp is None or not hp.active:
                        return (False, "Disponible")
                    integ = hp.status()["integridad"]
                    return (integ, "Desplegado" if integ else "¡COMPROMETIDO!")
                if key == "historial":
                    return (False, f"{len(list_snapshots())} snapshots")
                if key == "red":
                    return (False, "Reversible · requiere admin")
                return (False, "Disponible")
            return (False, "Pendiente")  # área sin implementar todavía
        return status

    def _open_area(self, key, title):
        pages = getattr(self.app, "pages", {})
        if key and key in pages:
            self.app._select(key)
        elif key is None and title == "Cuartel General":
            return  # ya estás aquí
        else:
            self.app.console.log("!", f"Área «{title}»: aún no implementada en esta versión "
                                      "(prevista en el diseño del producto).")

    # --- Estado de componentes (hilo de fondo) ------------------------------------------------
    def showEvent(self, event) -> None:
        """Al volver a la página se refresca al instante (mientras está oculta no se repinta)."""
        super().showEvent(event)
        self._tick()
        self._load_components()

    def _load_components(self) -> None:
        if not self.isVisible() or getattr(self.app, "_closing", False):
            return  # página oculta o ventana cerrándose: no lanzar comprobaciones
        if self._comp_worker is not None and self._comp_worker.isRunning():
            return  # ya hay una comprobación en curso
        modules, errors = self.app.modules, self.app.plugin_errors
        bus, blackbox = getattr(self.app, "bus", None), getattr(self.app, "blackbox", None)
        hp, cfg = getattr(self.app, "honeypot", None), getattr(self.app, "tactical_config", None)
        live = self._live_snapshot()  # en el hilo de la UI: solo lee el estado de los widgets
        worker = Worker(lambda emit: collect_component_status(modules, errors, bus, blackbox, hp, cfg,
                                                              live=live))
        worker.done.connect(self._components_ready)
        self._comp_worker = worker
        worker.start()

    def _live_snapshot(self) -> dict:
        """
        Estado VIVO que el panel de salud no puede leer desde el hilo de fondo: vigilancias activas
        de las páginas, Vanguardia y el último diagnóstico. Lectura barata de widgets (hilo de la UI).
        Cada clave solo se incluye si su fuente existe; si no, la fila no la menciona.
        """
        pages = getattr(self.app, "pages", {})
        live: dict = {"sentinel_on": bool(getattr(self.app, "sentinel_on", False))}
        net = pages.get("red")
        if net is not None and hasattr(net, "_watch_timer"):
            live["net_watch"] = net._watch_timer.isActive()
            live["net_watch_ports"] = len(net._baseline or ())
        ghost = pages.get("fantasma")
        if ghost is not None and hasattr(ghost, "_clip_timer"):
            live["clip_watch"] = ghost._clip_timer.isActive()
            live["autopurge"] = ghost.autopurge_btn.isChecked()
        audit = pages.get("auditoria")
        if audit is not None and getattr(audit, "last_result", None) is not None:
            live["last_audit"] = audit.last_result
        # OBSIDIAN: salud de la propia telemetría (CPU/RAM/hilos del proceso, ritmo del bus, tamaño JSONL)
        obs = {"vitals": process_vitals()}
        bb = getattr(self.app, "blackbox", None)
        if bb is not None and getattr(bb, "path", None):
            obs["jsonl_kb"] = jsonl_size_kb(bb.path)
        bus = getattr(self.app, "bus", None)
        if bus is not None:
            try:
                cur = bus.metrics().published
            except Exception:  # noqa: BLE001
                cur = None
            if cur is not None:
                now = time.monotonic()
                obs["epm"] = events_per_minute(self._obs_prev, self._obs_prev_t, cur, now)
                self._obs_prev, self._obs_prev_t = cur, now
        live["obsidian"] = obs
        return live

    def _components_ready(self, ok: bool, rows) -> None:
        if not ok or not isinstance(rows, list):
            self.comp_loading.setText("No se pudo comprobar el estado de los componentes.")
            self.comp_loading.show()
            return
        self.comp_loading.hide()
        if [r.name for r in self._comp_rows] == [name for name, _s, _d in rows]:
            # Misma lista de componentes: actualizar en su sitio (sin destruir/recrear las tarjetas
            # cada 8 s, que provocaba un parpadeo del panel).
            for card, (_name, state, detail) in zip(self._comp_rows, rows):
                card.set_state(state, detail)
            return
        with frozen(self):
            while self.comp_grid.count():
                item = self.comp_grid.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            self._comp_rows = [ComponentCard(name, state, detail, self.app._select)
                               for name, state, detail in rows]
            for i, card in enumerate(self._comp_rows):   # rejilla de 2 columnas (sin scroll interno)
                self.comp_grid.addWidget(card, i // 2, i % 2)

    def _system_rows(self):
        try:
            user = getpass.getuser()
        except Exception:
            user = "?"
        return [("Equipo", socket.gethostname()), ("Usuario", user),
                ("Privilegios", "Administrador" if self.app.admin else "Estándar (parcial)"),
                ("Módulos", f"{len(self.app.modules)} plugins")]

    def _tick(self) -> None:
        if not self.isVisible():
            return  # oculta tras otra pestaña: nada que pintar (se refresca en showEvent)
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        self.cpu_gauge.set_value(cpu)
        self.ram_gauge.set_value(ram)
        # Tráfico de red (KB/s) a partir del delta de contadores desde el tic anterior.
        now = time.monotonic()
        net_kbs = 0.0
        try:
            io = psutil.net_io_counters()
            delta_t = now - self._net_t
            if delta_t > 0 and self._net_io is not None:
                total = (io.bytes_sent + io.bytes_recv) - (self._net_io.bytes_sent + self._net_io.bytes_recv)
                net_kbs = max(0.0, total / 1024 / delta_t)
            self._net_io, self._net_t = io, now
        except Exception:  # noqa: BLE001
            pass
        self.pulse.push(cpu, ram, net_kbs)
        self.pulse_legend.setText(f"CPU {cpu:.0f}%  ·  RAM {ram:.0f}%  ·  RED {self.pulse.net_label()}")
        # Puntuación de salud global del sistema.
        audit = getattr(self.app.pages.get("auditoria"), "last_result", None)
        crit, warn = (audit[1], audit[2]) if audit else (0, 0)
        hp = getattr(self.app, "honeypot", None)
        hp_alert = bool(hp is not None and hp.active and not hp.status()["integridad"])
        write_errors = 0
        if self.app.blackbox is not None:
            try:
                write_errors = self.app.blackbox.metrics()["write_errors"]
            except Exception:  # noqa: BLE001
                write_errors = 0
        score, etiqueta = health_score(cpu, ram, critical=crit, warning=warn, honeypot_alert=hp_alert,
                                       bus_ok=self.app.bus is not None, write_errors=write_errors)
        self.health.set_score(score, etiqueta)
        # Escudo global: verde si hay alguna defensa activa (operaciones de lectura rápida, sin PowerShell)
        hp_on = bool(hp is not None and hp.active)
        protected = bool(quarantine_active() or hp_on or self.app.sentinel_on)
        if protected != self._shield_on:  # regenerar icono y estilo SOLO al cambiar de estado
            self._shield_on = protected
            color = "#22C55E" if protected else "#71717A"
            self.shield_icon.setPixmap(icon("fa5s.shield-alt", color).pixmap(48, 48))
            self.shield_state.setText("ACTIVO" if protected else "EN REPOSO")
            self.shield_state.setStyleSheet(f"color:{color}; font-size:11px; font-weight:bold;")
        for bcard in self.cards:
            bcard.refresh()
        # Piloto Automático: Auto-Optimizar RAM (comprueba en cada tic del cmd, visible)
        tc = self.app.tactical_config
        if tc and tc.get("ap_autoram", False):
            if ram > 80 and (now - self._ap_ram_last) > 300:  # cooldown 5 min
                self._ap_ram_last = now
                self.app.console.log("~", f"Piloto: RAM {ram:.0f}% > 80% → liberando working sets…")
                self.app.run_task(lambda emit: empty_working_sets(), self._ap_ram_done, track=False)

    def _ap_ram_done(self, ok: bool, res) -> None:
        if ok and isinstance(res, dict) and res.get("ok"):
            self.app.console.log("*", f"Piloto Auto-RAM: {res['liberado_mb']} MB liberados ({res['procesos']} proc)")
        else:
            self.app.console.log("x", f"Piloto Auto-RAM: {res.get('error') if isinstance(res, dict) else res}")

    def _build_autopilot_card(self) -> QFrame:
        box, lay = make_card("Piloto Automático",
                             "Automatizaciones persistentes que actúan en segundo plano sin clics manuales.")
        tc = self.app.tactical_config
        row1 = QHBoxLayout()
        row1.setSpacing(10)
        self._ap_ram_btn = QPushButton("Auto-Optimizar RAM (>80%)")
        self._ap_ram_btn.setObjectName("Toggle")
        self._ap_ram_btn.setCheckable(True)
        self._ap_ram_btn.setChecked(bool(tc and tc.get("ap_autoram", False)))
        with_icon(self._ap_ram_btn, "fa5s.memory", COLORS["muted"])
        self._ap_ram_btn.setToolTip("Si la RAM supera el 80%, libera working sets en segundo plano (cooldown 5 min).")
        self._ap_ram_btn.clicked.connect(self._toggle_ap_ram)
        self._ap_defense_btn = QPushButton("Auto-Defensa al Iniciar")
        self._ap_defense_btn.setObjectName("Toggle")
        self._ap_defense_btn.setCheckable(True)
        self._ap_defense_btn.setChecked(bool(tc and tc.get("ap_autodefense", False)))
        with_icon(self._ap_defense_btn, "fa5s.shield-alt", COLORS["muted"])
        self._ap_defense_btn.setToolTip("Al abrir Lozarus despliega el Honeypot y activa la vigilancia de puertos.")
        self._ap_defense_btn.clicked.connect(self._toggle_ap_defense)
        row1.addWidget(self._ap_ram_btn)
        row1.addWidget(self._ap_defense_btn)
        row1.addStretch(1)
        lay.addLayout(row1)
        row2 = QHBoxLayout()
        row2.setSpacing(10)
        self._maintenance_btn = QPushButton("⚡ Puesta a Punto Rápida")
        self._maintenance_btn.setObjectName("Ghost")
        with_icon(self._maintenance_btn, "fa5s.bolt", COLORS["muted"])
        self._maintenance_btn.setToolTip("DNS flush + limpiar %TEMP% + liberar RAM en un clic.")
        self._maintenance_btn.clicked.connect(self._quick_maintenance)
        row2.addWidget(self._maintenance_btn)
        row2.addStretch(1)
        lay.addLayout(row2)
        return box

    def _toggle_ap_ram(self) -> None:
        on = self._ap_ram_btn.isChecked()
        if self.app.tactical_config:
            self.app.tactical_config.set("ap_autoram", on)
        self.app.console.log("~", f"Piloto Auto-RAM {'ACTIVADO' if on else 'desactivado'}")

    def _toggle_ap_defense(self) -> None:
        on = self._ap_defense_btn.isChecked()
        if self.app.tactical_config:
            self.app.tactical_config.set("ap_autodefense", on)
        self.app.console.log("~", f"Piloto Auto-Defensa al Iniciar {'ACTIVADO' if on else 'desactivado'}")

    def _quick_maintenance(self) -> None:
        set_busy(self._maintenance_btn, True, "Ejecutando…")

        def task(emit):
            results = {}
            try:
                res = flush_dns()
                results["dns"] = res.get("ok", False)
            except Exception:  # noqa: BLE001
                results["dns"] = False
            try:
                res = clean_temp()
                results["temp_mb"] = res.get("freed_mb", 0)
            except Exception:  # noqa: BLE001
                results["temp_mb"] = 0
            try:
                res = empty_working_sets()
                results["ram_mb"] = res.get("liberado_mb", 0) if res.get("ok") else 0
            except Exception:  # noqa: BLE001
                results["ram_mb"] = 0
            return results

        def done(ok, res):
            set_busy(self._maintenance_btn, False)
            if not ok:
                self.app.console.log("x", f"Puesta a Punto: {res}")
                return
            dns_ok = "✓" if res.get("dns") else "✗"
            self.app.console.log("*",
                f"Puesta a Punto: DNS {dns_ok} · TEMP {res.get('temp_mb', 0):.1f} MB liberados "
                f"· RAM {res.get('ram_mb', 0):.0f} MB liberados")

        self.app.run_task(task, done)


class NetworkPage(Page):
    """
    Endurecimiento de red (herramientas base): enumerar puertos/conexiones, purgar la caché DNS,
    vigilar la apertura de puertos LISTEN nuevos (→ Caja Negra), leer el estado del Firewall y de
    servicios sensibles con opción de desactivarlos/restaurarlos (requiere Administrador). Mantiene
    el ocultamiento ICMP. Solo observa y, a petición de la persona, cambia la configuración local.
    """

    def __init__(self, app: "MainWindow"):
        super().__init__("Endurecimiento de Red",
                         "Herramientas base para reducir la exposición del equipo en la red. Lo que "
                         "requiere Administrador se indica; la vigilancia de puertos queda registrada "
                         "en la Caja Negra.", "fa5s.network-wired")
        self.app = app
        self._scan_busy = False
        self._baseline = None          # puertos LISTEN de referencia para la vigilancia
        self._svc_labels = {}
        self._svc_buttons = {}
        self._blocked = False          # estado ICMP; se lee en segundo plano (PowerShell, ~1 s)

        body = self.root
        body.addWidget(self._build_ports_card())
        body.addWidget(self._build_tools_card())
        body.addWidget(self._build_services_card())
        body.addStretch(1)

        self._watch_timer = QTimer(self)
        self._watch_timer.setInterval(3000)
        self._watch_timer.timeout.connect(self._watch_tick)

        self._show_icmp_state(None)  # «comprobando…» hasta que llegue la lectura en segundo plano
        # ICMP (PowerShell, ~1 s), Firewall y servicios se leen en segundo plano. Se aplaza hasta que
        # el bucle de eventos arranca: la consola de telemetría aún no existe al construir las
        # páginas, y así la ventana aparece al instante (antes el ICMP la bloqueaba ~1 s al abrir).
        QTimer.singleShot(0, self._initial_refresh)

    def _initial_refresh(self) -> None:
        if getattr(self.app, "console", None) is None:
            return
        self._refresh_icmp()
        self.refresh_firewall()
        self.refresh_services()

    # --- Puertos y conexiones -------------------------------------------------------------
    def _build_ports_card(self) -> QFrame:
        box, lay = make_card("Puertos y conexiones",
                             "Enumera los puertos en escucha (LISTEN) y las conexiones activas "
                             "(ESTABLISHED) de este equipo. Solo lectura; sin privilegios algún proceso "
                             "ajeno puede aparecer como «—».")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.scan_btn = QPushButton("Escanear puertos y conexiones")
        self.scan_btn.setObjectName("Primary")
        with_icon(self.scan_btn, "fa5s.search")
        self.scan_btn.clicked.connect(self._scan)
        self.watch_btn = QPushButton("Vigilar nuevos puertos: OFF")
        self.watch_btn.setObjectName("Toggle")
        self.watch_btn.setCheckable(True)
        with_icon(self.watch_btn, "fa5s.binoculars", COLORS["muted"])
        self.watch_btn.clicked.connect(self._toggle_watch)
        self.ports_export_btn = QPushButton("Exportar mapa")
        self.ports_export_btn.setObjectName("Ghost")
        with_icon(self.ports_export_btn, "fa5s.file-export", COLORS["muted"])
        self.ports_export_btn.setEnabled(False)
        self.ports_export_btn.setToolTip("Exporta las conexiones activas a JSON o CSV")
        self.ports_export_btn.clicked.connect(self._export_connections)
        row.addWidget(self.scan_btn)
        row.addWidget(self.watch_btn)
        row.addStretch(1)
        row.addWidget(self.ports_export_btn)
        self._last_conns = []
        self.ports_filter = QLineEdit()
        self.ports_filter.setPlaceholderText("Filtrar por proto, IP, puerto, estado, PID o proceso…")
        self.ports_filter.setClearButtonEnabled(True)
        self.ports_filter.textChanged.connect(lambda: self._render_ports())
        chips = QHBoxLayout()
        chips.setSpacing(10)
        self.card_listen, self._v_listen = stat_chip("EN ESCUCHA (LISTEN)")
        self.card_estab, self._v_estab = stat_chip("ACTIVAS (ESTABLISHED)")
        chips.addWidget(self.card_listen)
        chips.addWidget(self.card_estab)
        chips.addStretch(1)
        self.ports_table = make_table(
            ["Proto", "IP local", "Puerto", "IP remota", "Puerto", "Estado", "PID", "Proceso"],
            widths=[64, 140, 70, 140, 70, 110, 70],
            empty="Pulsa «Escanear puertos y conexiones» para ver los puertos en escucha y las "
                  "conexiones activas de este equipo.", empty_icon="fa5s.network-wired")
        self.ports_table.setMinimumHeight(240)
        lay.addLayout(row)
        lay.addLayout(chips)
        lay.addWidget(self.ports_filter)
        lay.addWidget(self.ports_table)
        return box

    def _scan(self) -> None:
        set_busy(self.scan_btn, True, "Escaneando…")
        self.app.log_tactical("Escaneando puertos y conexiones del equipo")
        self.app.run_task(lambda emit: scan_connections(), self._scanned)

    def _scanned(self, ok: bool, conns) -> None:
        set_busy(self.scan_btn, False)
        if not ok or not isinstance(conns, list):
            self.app.console.log("x", f"Escáner de puertos: {conns}")
            return
        escucha, activas = split_connections(conns)
        self._v_listen.setText(str(len(escucha)))
        self._v_estab.setText(str(len(activas)))
        resto = [c for c in conns if c.status not in ("LISTEN", "ESTABLISHED")]
        self._last_conns = escucha + activas + resto
        self.ports_export_btn.setEnabled(bool(self._last_conns))
        self._render_ports()
        self.app.console.log("*", f"Escáner de puertos: {len(escucha)} en escucha, "
                                  f"{len(activas)} activas ({len(conns)} conexiones en total)")

    def _render_ports(self) -> None:
        needle = self.ports_filter.text().strip().lower()
        rows = [c for c in self._last_conns
                if not needle or needle in " ".join(str(x) for x in c).lower()]
        if self._last_conns and not rows:
            self.ports_table.set_empty_text(f"Ninguna conexión coincide con «{needle}».", "fa5s.search")
        with frozen(self.ports_table):
            self.ports_table.setRowCount(len(rows))
            for r, c in enumerate(rows):
                vals = [c.proto, c.local_ip, str(c.local_port or "—"), c.remote_ip,
                        str(c.remote_port or "—"), c.status, str(c.pid or "—"), c.proceso]
                for col, v in enumerate(vals):
                    self.ports_table.setItem(r, col, QTableWidgetItem(v))

    def _export_connections(self) -> None:
        if not self._last_conns:
            return
        destino, _ = QFileDialog.getSaveFileName(
            self.app, "Exportar mapa de conexiones",
            os.path.join(os.path.expanduser("~"), "lozarus_conexiones.json"),
            "JSON (*.json);;CSV (*.csv)")
        if not destino:
            return
        conns = list(self._last_conns)

        def work(emit):
            filas = [{"proto": c.proto, "ip_local": c.local_ip, "puerto_local": c.local_port,
                      "ip_remota": c.remote_ip, "puerto_remoto": c.remote_port, "estado": c.status,
                      "pid": c.pid, "proceso": c.proceso} for c in conns]
            if destino.lower().endswith(".csv"):
                import csv
                with open(destino, "w", encoding="utf-8-sig", newline="") as fh:
                    writer = csv.DictWriter(fh, fieldnames=list(filas[0]))
                    writer.writeheader()
                    writer.writerows(filas)
            else:
                with open(destino, "w", encoding="utf-8") as fh:
                    json.dump({"capturado": dt.datetime.now().isoformat(timespec="seconds"),
                               "equipo": socket.gethostname(), "conexiones": filas}, fh,
                              ensure_ascii=False, indent=2)
            return len(filas)

        self.app.run_task(work, lambda ok, n: self.app.console.log(
            "*" if ok else "x", f"Mapa de conexiones: {n} filas exportadas a {destino}" if ok
            else f"Exportar: {n}"))

    def _toggle_watch(self) -> None:
        on = self.watch_btn.isChecked()
        self.watch_btn.setText("Vigilar nuevos puertos: " + ("ON" if on else "OFF"))
        if on:
            self._baseline = None  # la referencia se fija en el primer escaneo del vigilante
            self._watch_timer.start()
            self.app.log_tactical("Vigilancia de puertos LISTEN activada (cada 3 s)")
        else:
            self._watch_timer.stop()
            self.app.console.log("~", "Vigilancia de puertos detenida")

    def _watch_tick(self) -> None:
        if self._scan_busy:
            return
        self._scan_busy = True

        def done(ok, keys):
            self._scan_busy = False
            if not ok or not isinstance(keys, (set, frozenset)):
                return
            if self._baseline is None:
                self._baseline = set(keys)  # primera foto: solo referencia, sin avisar
                return
            nuevos = keys - self._baseline
            if nuevos:
                self._baseline |= nuevos
                for k in sorted(nuevos):
                    self.app.console.log("!", f"Puerto nuevo en escucha: {k}")
                    self.app.record_alert("!", f"Puerto nuevo en escucha: {k}", module="red")
                    _emit_event(self.app, source="red:puertos",
                                event_type="network.new_listen_port", payload={"port_key": k})

        # Sondeo periódico: no cuenta como «tarea en curso» (el indicador parpadearía cada 3 s).
        self.app.run_task(lambda emit: listening_keys(scan_connections()), done, track=False)

    # --- Caché DNS + ocultamiento ICMP ----------------------------------------------------
    def _build_tools_card(self) -> QFrame:
        box, lay = make_card("Caché DNS y ocultamiento",
                             "Purga la caché del solucionador DNS (sin privilegios) y oculta el equipo "
                             "frente a los ping entrantes con una regla de Firewall reversible "
                             "(requiere Administrador).")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.dns_btn = QPushButton("Purgar caché DNS (flushdns)")
        self.dns_btn.setObjectName("Ghost")
        with_icon(self.dns_btn, "fa5s.broom", COLORS["muted"])
        self.dns_btn.clicked.connect(self._flush_dns)
        self.toggle_btn = QPushButton("Activar ocultamiento")
        self.toggle_btn.setObjectName("Primary")
        with_icon(self.toggle_btn, "fa5s.eye-slash")
        self.toggle_btn.clicked.connect(self._toggle)
        self.toggle_btn.setEnabled(False)  # se habilita cuando se conoce el estado real (y si hay admin)
        row.addWidget(self.dns_btn)
        row.addWidget(self.toggle_btn)
        row.addStretch(1)
        self.status = QLabel("—")
        self.status.setObjectName("StatusMuted")
        lay.addLayout(row)
        lay.addWidget(self.status)
        return box

    def _flush_dns(self) -> None:
        set_busy(self.dns_btn, True, "Purgando…")
        self.app.log_tactical("Purgando la caché del solucionador DNS")

        def done(ok, payload):
            set_busy(self.dns_btn, False)
            if ok and isinstance(payload, tuple):
                good, msg = payload
                self.app.console.log("*" if good else "x", f"DNS: {msg}")
            else:
                self.app.console.log("x", f"DNS: {payload}")

        self.app.run_task(lambda emit: flush_dns(), done)

    def _refresh_icmp(self) -> None:
        """Lee en SEGUNDO PLANO si la regla ICMP está puesta (PowerShell, ~1 s; antes congelaba la UI)."""
        self._show_icmp_state(None)

        def done(ok: bool, blocked) -> None:
            self._show_icmp_state(bool(blocked) if ok else None, failed=not ok)

        self.app.run_task(lambda emit: icmp_block_active(), done, track=False)

    def _show_icmp_state(self, blocked: Optional[bool], failed: bool = False) -> None:
        """Pinta el estado ICMP. `blocked=None` = aún desconocido (comprobando o error de lectura)."""
        if blocked is None:
            self.status.setText("No se pudo leer el estado del ocultamiento." if failed
                                else "Comprobando el estado del ocultamiento…")
            self.status.setObjectName("StatusMuted")
            self.toggle_btn.setEnabled(False)
        else:
            self._blocked = blocked
            if blocked:
                self.status.setText("● Oculto: el equipo NO responde a ping entrante")
                self.status.setObjectName("StatusWarn")
                self.toggle_btn.setText("Desactivar ocultamiento")
            else:
                self.status.setText("○ Visible: el equipo responde a ping"
                                    + ("" if self.app.admin else "  ·  requiere Administrador"))
                self.status.setObjectName("StatusMuted")
                self.toggle_btn.setText("Activar ocultamiento")
            self.toggle_btn.setEnabled(self.app.admin)
        repolish(self.status)

    def _toggle(self) -> None:
        target = not self._blocked
        self.app.log_tactical(f"{'Activando' if target else 'Desactivando'} ocultamiento de red (ICMP)")
        set_busy(self.toggle_btn, True, "Aplicando…")

        def done(ok: bool, payload) -> None:
            set_busy(self.toggle_btn, False)
            if not ok:
                self.app.console.log("x", f"Endurecimiento de red: {payload}")
            self._refresh_icmp()  # relee el estado real (también deja el botón según privilegios)

        self.app.run_task(lambda emit: set_icmp_block(target), done)

    # --- Firewall y servicios -------------------------------------------------------------
    def _build_services_card(self) -> QFrame:
        box, lay = make_card("Firewall y servicios críticos",
                             "Estado del Firewall de Windows por perfil y de servicios sensibles "
                             "(telemetría y superficie de ataque). Desactivarlos es endurecimiento, no "
                             "quitar una protección; es reversible y requiere Administrador.")
        top = QHBoxLayout()
        top.setSpacing(10)
        self.fw_label = QLabel("Firewall: comprobando…")
        self.fw_label.setObjectName("Tiny")
        self.fw_label.setWordWrap(True)
        self.fw_btn = QPushButton("Actualizar estado")
        self.fw_btn.setObjectName("Mini")
        with_icon(self.fw_btn, "fa5s.sync-alt", COLORS["muted"], 13)
        self.fw_btn.clicked.connect(lambda: (self.refresh_firewall(), self.refresh_services()))
        top.addWidget(self.fw_label, 1)
        top.addWidget(self.fw_btn)
        lay.addLayout(top)
        for name, motivo in SERVICIOS_SENSIBLES:
            lay.addLayout(self._build_service_row(name, motivo))
        if not self.app.admin:
            uac_row = QHBoxLayout()
            uac_row.setSpacing(10)
            self.uac_btn = QPushButton("Relanzar como Administrador (UAC)")
            self.uac_btn.setObjectName("Warn")
            with_icon(self.uac_btn, "fa5s.user-shield", COLORS["beacon"])
            self.uac_btn.clicked.connect(self.app.relaunch_as_admin)
            hint = QLabel("Desactivar/restaurar servicios y el ocultamiento ICMP requieren "
                          "Administrador: eleva y los botones se activarán.")
            hint.setObjectName("Tiny")
            hint.setWordWrap(True)
            uac_row.addWidget(self.uac_btn)
            uac_row.addWidget(hint, 1)
            lay.addLayout(uac_row)
        return box

    def _build_service_row(self, name: str, motivo: str) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        lbl = QLabel(name)
        lbl.setStyleSheet("color:#FAFAFA; font-size:12px; font-weight:600;")
        lbl.setMinimumWidth(128)
        lbl.setToolTip(motivo)
        st = QLabel("comprobando…")
        st.setObjectName("Tiny")
        dis = QPushButton("Desactivar")
        dis.setObjectName("Mini")
        dis.clicked.connect(lambda _=False, n=name: self._change_service(n, "disable"))
        res = QPushButton("Restaurar")
        res.setObjectName("Mini")
        res.clicked.connect(lambda _=False, n=name: self._change_service(n, "restore"))
        if not self.app.admin:
            dis.setEnabled(False)
            res.setEnabled(False)
        row.addWidget(lbl)
        row.addWidget(st, 1)
        row.addWidget(dis)
        row.addWidget(res)
        self._svc_labels[name] = st
        self._svc_buttons[name] = {"disable": dis, "restore": res}
        return row

    def refresh_firewall(self) -> None:
        set_busy(self.fw_btn, True, "Leyendo…")

        def done(ok, payload):
            set_busy(self.fw_btn, False)
            if not ok or not isinstance(payload, tuple):
                self.fw_label.setText("Firewall: no se pudo leer")
                return
            good, estado, msg = payload
            if good and estado:
                partes = " · ".join(f"{k}: {'ON' if v else 'OFF'}" for k, v in estado.items())
                self.fw_label.setText("Firewall → " + partes)
            else:
                self.fw_label.setText(f"Firewall: {msg or 'sin datos'}")

        self.app.run_task(lambda emit: firewall_status(), done)

    def refresh_services(self) -> None:
        def done(ok, data):
            if not ok or not isinstance(data, list):
                return
            for info in data:
                lbl = self._svc_labels.get(info["name"])
                if lbl is None:
                    continue
                if not info.get("exists"):
                    lbl.setText("no instalado")
                else:
                    lbl.setText(f"{info['status']} · arranque {info['start_type']}")

        self.app.run_task(lambda emit: services_overview(), done)

    def _change_service(self, name: str, action: str) -> None:
        verbo = "desactivar" if action == "disable" else "restaurar"
        detalle = ("Se detendrá y quedará con el arranque deshabilitado."
                   if action == "disable" else "Se restaurará su arranque por defecto.")
        if not ConfirmDialog.ask(self.app, f"{verbo.capitalize()} servicio",
                                 f"Vas a {verbo} el servicio «{name}» de ESTE equipo.\n\n{detalle}\n"
                                 "Requiere Administrador. ¿Continuar?",
                                 confirm_text=verbo.capitalize(), danger=(action == "disable")):
            return
        self.app.log_tactical(f"Servicio {name}: {verbo}")
        fn = disable_service if action == "disable" else restore_service
        btn = self._svc_buttons.get(name, {}).get(action)
        if btn is not None:
            set_busy(btn, True, "…")

        def done(ok, payload):
            if btn is not None:
                set_busy(btn, False)
            if ok and isinstance(payload, tuple):
                good, needs_admin, msg = payload
                if good:
                    self.app.console.log("*", f"Servicio {name}: {msg}")
                    _emit_event(self.app, source="red:servicios",
                                event_type="service.config_changed",
                                payload={"service": name, "action": action})
                else:
                    self.app.console.log("!" if needs_admin else "x", f"Servicio {name}: {msg}")
            else:
                self.app.console.log("x", f"Servicio {name}: {payload}")
            self.refresh_services()

        self.app.run_task(lambda emit: fn(name), done)


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


def format_bytes(value: int) -> str:
    return f"{value / 1024 ** 3:.1f} GB" if value >= 1024 ** 3 else f"{value / 1024 ** 2:.0f} MB"


def repolish(widget) -> None:
    """Reaplica el QSS tras cambiar el objectName de un widget en caliente."""
    widget.setStyleSheet("")
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def stat_chip(caption: str):
    """Tarjeta compacta: rótulo arriba y valor grande debajo. Devuelve (tarjeta, label-del-valor)."""
    chip = QFrame()
    chip.setObjectName("Chip")
    chip.setMinimumHeight(66)   # evita que el rótulo superior quede recortado por arriba
    lay = QVBoxLayout(chip)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(3)
    cap = QLabel(caption)
    cap.setObjectName("ChipCap")
    val = QLabel("—")
    val.setObjectName("ChipVal")
    lay.addWidget(cap)
    lay.addWidget(val)
    return chip, val


def _emit_event(app, *, source, event_type, payload, observation=None, **extra):
    """
    Publica un Event en el bus de la GUI (que la Caja Negra persiste en eventos.jsonl). No bloquea y
    NUNCA lanza: si el bus/núcleo no está disponible devuelve False sin romper la función que llama.
    """
    bus = getattr(app, "bus", None)
    if bus is None or Event is None:
        return False
    try:
        obs = observation or (ObservationQuality.PARTIAL if ObservationQuality else None)
        bus.publish(Event.create(source=source, host=socket.gethostname(), observation=obs,
                                 event_type=event_type, payload=payload, **extra))
        return True
    except Exception as exc:  # noqa: BLE001
        try:
            app.console.log("x", f"Caja Negra: no se registró el evento: {exc}")
        except Exception:  # noqa: BLE001
            pass
        return False


def proc_key(alert) -> str:
    """Identidad estable de un proceso marcado (PID + instante de creación)."""
    return f"{alert.pid}:{int(getattr(alert, 'created', 0) * 1000)}"


class Sparkline(QWidget):
    """Mini gráfico de línea (~20 valores): línea azul con relleno tenue y punto final luminoso."""

    def __init__(self, zero_based: bool = True, floor: float = 1.0, width: int = 104, height: int = 28):
        super().__init__()
        self.setFixedSize(width, height)
        self.zero_based = zero_based
        self.floor = floor
        self._values = []

    def set_values(self, values) -> None:
        self._values = list(values)[-20:]
        self.update()

    def paintEvent(self, event) -> None:
        vals = self._values
        w, h, pad = self.width(), self.height(), 3
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(QPen(QColor(COLORS["border"]), 1))
        p.drawLine(pad, h - pad, w - pad, h - pad)
        if len(vals) < 2:
            if vals:
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor("#DBEAFE"))
                p.drawEllipse(QPointF(w - pad, h - pad), 2.0, 2.0)
            return
        lo = 0.0 if self.zero_based else min(vals)
        hi = max(vals)
        hi = max(hi * 1.15, self.floor) if self.zero_based else max(hi, lo + self.floor)
        span = (hi - lo) or 1.0
        n = len(vals)
        pts = [QPointF(pad + (w - 2 * pad) * i / (n - 1),
                       (h - pad) - (h - 2 * pad) * ((v - lo) / span)) for i, v in enumerate(vals)]
        path = QPainterPath()
        path.moveTo(pts[0].x(), h - pad)
        for pt in pts:
            path.lineTo(pt)
        path.lineTo(pts[-1].x(), h - pad)
        path.closeSubpath()
        p.fillPath(path, QColor(96, 165, 250, 46))  # acento #60A5FA translúcido
        pen = QPen(QColor(COLORS["accent_hover"]))
        pen.setWidthF(1.6)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(QBrush(Qt.BrushStyle.NoBrush))
        p.drawPolyline(QPolygonF(pts))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#DBEAFE"))
        p.drawEllipse(pts[-1], 2.2, 2.2)


class ProcCard(QFrame):
    """Tarjeta de un proceso sospechoso con sparklines de CPU y RAM y hover/selección animados (Aura)."""

    def __init__(self, on_select):
        super().__init__()
        self.setObjectName("ProcCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._on_select = on_select
        self.alert = None
        self._selected = False
        self._border = QColor(COLORS["border"])
        self._anim = QPropertyAnimation(self, b"border", self)
        self._anim.setDuration(170)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 8, 12, 8)
        lay.setSpacing(12)
        self.stripe = QFrame()
        self.stripe.setFixedWidth(3)
        self.stripe.setStyleSheet("background:#5E5E5E; border-radius:2px;")
        lay.addWidget(self.stripe)

        info = QVBoxLayout()
        info.setSpacing(1)
        self.name = QLabel("—")
        self.name.setStyleSheet("color:#FAFAFA; font-weight:bold; font-size:12px;")
        self.meta = QLabel("")
        self.meta.setStyleSheet("color:#9A9A9A; font-family:'Consolas'; font-size:11px;")
        info.addWidget(self.name)
        info.addWidget(self.meta)
        namebox = QWidget()
        namebox.setLayout(info)
        namebox.setFixedWidth(180)
        lay.addWidget(namebox)

        self.reasons = QLabel("")
        self.reasons.setStyleSheet("color:#E0E0E0; font-size:11px;")
        self.reasons.setWordWrap(True)
        lay.addWidget(self.reasons, 1)

        self.cpu_val, self.cpu_spark = self._spark_block(lay, "CPU", zero_based=True, floor=5.0)
        self.ram_val, self.ram_spark = self._spark_block(lay, "RAM", zero_based=False, floor=8 * 1024 ** 2)
        self._apply()

    def _spark_block(self, parent_layout, caption, zero_based, floor):
        block = QVBoxLayout()
        block.setSpacing(1)
        head = QHBoxLayout()
        cap = QLabel(caption)
        cap.setStyleSheet("color:#5E5E5E; font-size:9px; font-weight:bold;")
        val = QLabel("—")
        val.setStyleSheet("color:#E0E0E0; font-family:'Consolas'; font-size:10px;")
        head.addWidget(cap)
        head.addStretch(1)
        head.addWidget(val)
        spark = Sparkline(zero_based=zero_based, floor=floor)
        block.addLayout(head)
        block.addWidget(spark)
        parent_layout.addLayout(block)
        return val, spark

    def _get_border(self):
        return self._border

    def _set_border(self, color):
        self._border = color
        self._apply()

    border = Property(QColor, _get_border, _set_border)

    def _apply(self):
        c = self._border
        bg = "#1E2633" if self._selected else "#18181C"
        self.setStyleSheet(f"#ProcCard {{ background:{bg}; border:1px solid "
                           f"rgb({c.red()},{c.green()},{c.blue()}); border-radius:8px; }}")

    def _to(self, color):
        self._anim.stop()
        self._anim.setStartValue(self._border)
        self._anim.setEndValue(QColor(color))
        self._anim.start()

    def set_selected(self, on):
        self._selected = on
        self._apply()
        self._to(QColor(COLORS["accent"]) if on else QColor(COLORS["border"]))

    def enterEvent(self, event):
        if not self._selected:
            self._to(QColor(COLORS["accent"]))
        super().enterEvent(event)

    def leaveEvent(self, event):
        if not self._selected:
            self._to(QColor(COLORS["border"]))
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if self.alert is not None:
            self._on_select(self.alert)
        super().mousePressEvent(event)

    def update_data(self, alert, cpu_hist, ram_hist):
        self.alert = alert
        color = SEVERITY_COLORS[alert.severity]
        self.name.setText(alert.name)
        self.meta.setText(f"PID {alert.pid} · {alert.severity.value}")
        self.meta.setStyleSheet(f"color:{color}; font-family:'Consolas'; font-size:11px;")
        self.stripe.setStyleSheet(f"background:{color}; border-radius:2px;")
        self.reasons.setText("; ".join(alert.reasons))
        self.cpu_val.setText(f"{alert.cpu:.1f} %" if alert.cpu < 10 else f"{alert.cpu:.0f} %")
        self.ram_val.setText(format_bytes(alert.rss))
        self.cpu_spark.set_values(cpu_hist)
        self.ram_spark.set_values(ram_hist)


class ProcBoard(QScrollArea):
    """Lista de tarjetas de procesos sospechosos, actualizadas por diferencias (crea/actualiza/borra)."""

    def __init__(self, on_select):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet("background: transparent;")
        self.on_select = on_select
        self.cards = {}
        self.order = []
        self.selected_key = None
        self._host = QWidget()
        self._lay = QVBoxLayout(self._host)
        self._lay.setContentsMargins(4, 4, 4, 4)
        self._lay.setSpacing(6)
        self.empty = QLabel("Sin procesos sospechosos en la última muestra.")
        self.empty.setObjectName("CardText")
        self._lay.addWidget(self.empty)
        self._lay.addStretch(1)
        self.setWidget(self._host)

    def update_cards(self, alerts, history):
        keys = [proc_key(a) for a in alerts]
        for key in list(self.cards):
            if key not in keys:
                w = self.cards.pop(key)
                w.setParent(None)
                w.deleteLater()
        for a, key in zip(alerts, keys):
            card = self.cards.get(key)
            if card is None:
                card = ProcCard(self._select_from_card)
                self.cards[key] = card
            hist = history.get(key, {})
            card.update_data(a, list(hist.get("cpu", [])), list(hist.get("rss", [])))
            card.set_selected(key == self.selected_key)
        if keys != self.order:  # recoloca solo si cambió el conjunto o el orden
            for card in self.cards.values():
                self._lay.removeWidget(card)
            for key in keys:
                self._lay.insertWidget(self._lay.count() - 1, self.cards[key])
            self.order = keys
        self.empty.setVisible(not alerts)

    def _select_from_card(self, alert):
        self.selected_key = proc_key(alert)
        for key, card in self.cards.items():
            card.set_selected(key == self.selected_key)
        self.on_select(alert)


# ===========================================================================
# ESCANEO EN SEGUNDO PLANO (QThread)
# ===========================================================================
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


# ===========================================================================
# PÁGINA: MONITOR EN VIVO
# ===========================================================================
class ProcessMonitor(QWidget):
    """
    Tabla de procesos EN VIVO (solo observación): PID, nombre, usuario, CPU %, memoria y estado.
    Muestreo en segundo plano (self.app.run_task) con intervalo configurable; búsqueda por nombre o
    PID, ordenación por columnas y panel de detalle del proceso seleccionado. No termina procesos ni
    cambia prioridades: solo observa. Los valores no accesibles se muestran «—», nunca como 0.
    """

    COLS = [("pid", "PID", 72), ("name", "Nombre", 230), ("user", "Usuario", 150),
            ("cpu", "CPU", 80), ("rss", "Memoria", 100), ("status", "Estado", 90)]

    def __init__(self, app: "MainWindow"):
        super().__init__()
        self.app = app
        self._rows = []              # última muestra (lista de _procmon.ProcRow)
        self._sort_key = "cpu"
        self._sort_desc = True
        self._query = ""
        self._detail_pid = None       # proceso cuyo detalle se muestra (se refresca en vivo)
        self._detail_extra = None     # metadatos ya cargados (exe, comando, creación…)
        self._sampling = False
        self._running = False
        self._available = _procmon.HAS_PSUTIL

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 10, 0, 0)
        lay.setSpacing(10)

        ctl = QHBoxLayout()
        ctl.setSpacing(10)
        self.toggle_btn = QPushButton("Iniciar")
        self.toggle_btn.setObjectName("Primary")
        with_icon(self.toggle_btn, "fa5s.play")
        self.toggle_btn.clicked.connect(self._toggle)
        ctl.addWidget(self.toggle_btn)
        cap = QLabel("Intervalo:")
        cap.setObjectName("CardText")
        ctl.addWidget(cap)
        self.interval = QComboBox()
        for label, ms in (("1 s", 1000), ("2 s", 2000), ("3 s", 3000), ("5 s", 5000)):
            self.interval.addItem(label, ms)
        self.interval.setCurrentIndex(1)  # 2 s por defecto
        self.interval.currentIndexChanged.connect(self._interval_changed)
        ctl.addWidget(self.interval)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar por nombre o PID…")
        self.search.textChanged.connect(self._search_changed)
        ctl.addWidget(self.search, 1)
        self.count = QLabel("")
        self.count.setObjectName("CardText")
        ctl.addWidget(self.count)
        lay.addLayout(ctl)

        self.notice = QLabel("")
        self.notice.setObjectName("Tiny")
        self.notice.setWordWrap(True)
        lay.addWidget(self.notice)

        body = QHBoxLayout()
        body.setSpacing(12)
        self.table = make_table([c[1] for c in self.COLS], widths=[c[2] for c in self.COLS],
                                empty="Pulsa «Iniciar» para muestrear los procesos del equipo.",
                                empty_icon="fa5s.microchip")
        hh = self.table.horizontalHeader()
        hh.setCursor(Qt.CursorShape.PointingHandCursor)   # la cabecera ordena: que se note
        hh.setSortIndicatorShown(True)                      # flecha en la columna de orden actual
        self._update_sort_indicator()
        hh.sectionClicked.connect(self._header_clicked)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        body.addWidget(self.table, 3)

        detail_box = QFrame()
        detail_box.setObjectName("Card")
        dl = QVBoxLayout(detail_box)
        dl.setContentsMargins(14, 12, 14, 12)
        dl.setSpacing(6)
        dt_title = QLabel("Detalle del proceso")
        dt_title.setObjectName("CardTitle")
        self.detail = QLabel("Selecciona un proceso para ver sus metadatos.")
        self.detail.setObjectName("CardText")
        self.detail.setWordWrap(True)
        self.detail.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        dl.addWidget(dt_title)
        dl.addWidget(self.detail, 1)
        detail_box.setMinimumWidth(280)
        body.addWidget(detail_box, 2)
        lay.addLayout(body, 1)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        if not self._available:
            self.toggle_btn.setEnabled(False)
            self.interval.setEnabled(False)
            self.search.setEnabled(False)
            self.notice.setText("psutil no está disponible: la tabla de procesos no puede funcionar.")
        else:
            self.notice.setText("Pulsa «Iniciar» para muestrear los procesos del equipo.")

    # --- control de arranque / parada ---------------------------------------------------------
    def _toggle(self) -> None:
        self.stop() if self._running else self.start()

    def start(self) -> None:
        if self._running or not self._available:
            return
        self._running = True
        self.toggle_btn.setText("Detener")
        self.toggle_btn.setObjectName("Ghost")
        with_icon(self.toggle_btn, "fa5s.stop", COLORS["muted"])
        repolish(self.toggle_btn)
        if not self._rows:
            self.notice.setText("Muestreando procesos…")
        self.timer.start(self._effective_interval())
        self._tick()

    def stop(self) -> None:
        self._running = False
        self.timer.stop()
        self.toggle_btn.setText("Iniciar")
        self.toggle_btn.setObjectName("Primary")
        with_icon(self.toggle_btn, "fa5s.play")
        repolish(self.toggle_btn)

    def _effective_interval(self) -> int:
        """Intervalo de muestreo, nunca por debajo del suelo que fija el perfil de operación."""
        return max(self.interval.currentData(), getattr(self, "_sampling_floor", 0))

    def set_sampling_floor(self, ms: int) -> None:
        self._sampling_floor = ms
        if self._running:
            self.timer.start(self._effective_interval())

    def _interval_changed(self) -> None:
        if self._running:
            self.timer.start(self._effective_interval())

    def _search_changed(self, text: str) -> None:
        self._query = text
        self._render()  # filtra sobre la última muestra, sin volver a consultar el sistema

    # --- muestreo en segundo plano ------------------------------------------------------------
    def _tick(self) -> None:
        if not self.isVisible():
            return  # pestaña oculta: no lanzar sondeo hasta que el usuario la vea
        if self._sampling or not self._available:
            return
        self._sampling = True
        # Sondeo periódico: no cuenta como «tarea en curso» en el indicador global.
        self.app.run_task(lambda emit: _procmon.sample_processes(), self._sampled, track=False)

    def _sampled(self, ok: bool, result) -> None:
        self._sampling = False
        if not ok:
            self.notice.setText(f"No se pudieron muestrear los procesos: {result}")
            return
        self._rows = result
        self._render()

    # --- render (hilo principal, rápido: filtra/ordena sobre la muestra ya obtenida) ----------
    def _render(self) -> None:
        rows = _procmon.sort_rows(_procmon.filter_rows(self._rows, self._query),
                                  self._sort_key, self._sort_desc)
        if not self._rows:
            self.table.set_empty_text("Muestreando procesos…" if self._running else
                                      "Pulsa «Iniciar» para muestrear los procesos del equipo.",
                                      "fa5s.microchip")
        elif not rows:
            self.table.set_empty_text(f"Ningún proceso coincide con «{self._query}».", "fa5s.search")
        sel_pid = self._selected_pid()
        with frozen(self.table):  # ~300 filas × 6 celdas: un solo repintado al final
            self.table.setRowCount(len(rows))
            for r, pr in enumerate(rows):
                vals = [str(pr.pid) if pr.pid is not None else "—",
                        _procmon.fmt_text(pr.name), _procmon.fmt_text(pr.user),
                        _procmon.fmt_cpu(pr.cpu), _procmon.fmt_mem(pr.rss), _procmon.fmt_text(pr.status)]
                for c, v in enumerate(vals):
                    item = QTableWidgetItem(v)
                    if c == 0:
                        item.setData(Qt.ItemDataRole.UserRole, pr.pid)
                    self.table.setItem(r, c, item)

        summ = _procmon.access_summary(self._rows)
        self.count.setText(f"{summ['total']} procesos" if self._rows else "")
        if not self._rows:
            self.notice.setText("Muestreando procesos…" if self._running
                                else "Pulsa «Iniciar» para muestrear los procesos del equipo.")
        elif not rows:
            self.notice.setText(f"Sin resultados para «{self._query}».")
        else:
            incompletos = max(summ["sin_usuario"], summ["sin_cpu"])
            extra = (f"  ·  {incompletos} sin datos completos (muchos procesos del sistema requieren "
                     "Administrador)") if incompletos else ""
            self.notice.setText(f"Mostrando {len(rows)} de {summ['total']} procesos{extra}.")
        if sel_pid is not None:
            self._select_pid(sel_pid)
        if self._detail_pid is not None:  # mantener el detalle en vivo (CPU/memoria al día)
            self.detail.setText(self._compose_detail(self._detail_pid))

    # --- selección y orden --------------------------------------------------------------------
    def _selected_pid(self):
        items = self.table.selectedItems()
        if not items:
            return None
        it = self.table.item(items[0].row(), 0)
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def _select_pid(self, pid) -> None:
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 0)
            if it and it.data(Qt.ItemDataRole.UserRole) == pid:
                self.table.blockSignals(True)
                self.table.selectRow(r)
                self.table.blockSignals(False)
                return

    def _header_clicked(self, index: int) -> None:
        key = self.COLS[index][0]
        if key == self._sort_key:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_key = key
            self._sort_desc = key in ("cpu", "rss")  # columnas numéricas: de mayor a menor primero
        self._update_sort_indicator()
        self._render()

    def _update_sort_indicator(self) -> None:
        """Refleja en la cabecera la columna y el sentido del orden (solo visual: ordena _procmon)."""
        index = next((i for i, c in enumerate(self.COLS) if c[0] == self._sort_key), -1)
        order = Qt.SortOrder.DescendingOrder if self._sort_desc else Qt.SortOrder.AscendingOrder
        self.table.horizontalHeader().setSortIndicator(index, order)

    def _compose_detail(self, pid) -> str:
        """Texto del panel de detalle: cabecera EN VIVO (de la última muestra) + metadatos ya
        cargados. Si el proceso ya no está en la muestra, lo indica en vez de mostrar datos viejos."""
        row = next((r for r in self._rows if r.pid == pid), None)
        if row is None:
            return f"PID {pid}: el proceso ya no está en la última muestra."
        base = (f"PID {row.pid} · {_procmon.fmt_text(row.name)}\n"
                f"Usuario: {_procmon.fmt_text(row.user)}\n"
                f"CPU: {_procmon.fmt_cpu(row.cpu)}    Memoria: {_procmon.fmt_mem(row.rss)}\n"
                f"Estado: {_procmon.fmt_text(row.status)}\n\n")
        return base + (self._detail_extra if self._detail_extra is not None
                       else "Cargando metadatos adicionales…")

    def _selection_changed(self) -> None:
        pid = self._selected_pid()
        if pid is None:
            self._detail_pid = None
            self._detail_extra = None
            self.detail.setText("Selecciona un proceso para ver sus metadatos.")
            return
        self._detail_pid = pid
        self._detail_extra = None  # metadatos del proceso anterior ya no valen
        self.detail.setText(self._compose_detail(pid))
        self.app.run_task(lambda emit, p=pid: _procmon.process_detail(p),
                          lambda ok, d, p=pid: self._detail_ready(ok, d, p), track=False)

    def _detail_ready(self, ok: bool, detail, pid) -> None:
        if self._detail_pid != pid:
            return  # el usuario ya cambió de selección mientras se cargaban los metadatos
        if not ok or not isinstance(detail, dict):
            self._detail_extra = "No se pudieron leer metadatos adicionales."
        elif detail.get("error"):
            self._detail_extra = f"Metadatos no disponibles: {detail['error']}"
        else:
            cmd = detail.get("cmdline")
            cmd = " ".join(cmd) if isinstance(cmd, list) and cmd else None
            ct = detail.get("create_time")
            ct_s = (dt.datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
                    if isinstance(ct, (int, float)) else None)

            def line(label, value):
                return f"{label}: {value}" if value not in (None, "", []) else f"{label}: —"

            self._detail_extra = "\n".join([line("Ejecutable", detail.get("exe")),
                                            line("Comando", cmd), line("Creado", ct_s),
                                            line("Hilos", detail.get("num_threads")),
                                            line("PID padre", detail.get("ppid"))])
        self.detail.setText(self._compose_detail(pid))


# ===========================================================================
class MonitorPage(Page):
    """Radar en tiempo real (solo lectura): conexiones de red y procesos sospechosos. Muestra en
    un hilo cada 3 s (LiveMonitor.sample) para no congelar la interfaz."""

    def __init__(self, app: "MainWindow"):
        super().__init__("Monitor en Vivo",
                         "Radar en tiempo real de las conexiones de red y de los procesos con comportamiento anómalo.",
                         "fa5s.wave-square")
        self.app = app
        try:
            self.monitor = LiveMonitor()
            self.unavailable = ""
        except Exception as exc:
            self.monitor, self.unavailable = None, str(exc)
        self.running = False
        self.sampling = False
        self.timer = QTimer(self)
        self.timer.setInterval(3000)
        self.timer.timeout.connect(self._tick)

        ctl = QHBoxLayout()
        ctl.setSpacing(10)
        self.start_btn = QPushButton("Iniciar monitor")
        self.start_btn.setObjectName("Primary")
        with_icon(self.start_btn, "fa5s.play")
        self.start_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("Detener")
        self.stop_btn.setObjectName("Ghost")
        with_icon(self.stop_btn, "fa5s.stop", COLORS["muted"])
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop)
        self.status = QLabel("○  Monitor detenido")
        self.status.setObjectName("StatusMuted")
        ctl.addWidget(self.start_btn)
        ctl.addWidget(self.stop_btn)
        ctl.addWidget(self.status)
        ctl.addStretch(1)
        self.root.addLayout(ctl)

        stats = QHBoxLayout()
        stats.setSpacing(10)
        self.stats = {}
        for key, cap in (("conns", "CONEXIONES"), ("internet", "DESTINOS INTERNET"),
                         ("procs", "PROCESOS CON RED"), ("alerts", "SOSPECHOSOS")):
            chip, val = stat_chip(cap)
            self.stats[key] = val
            stats.addWidget(chip)
        self.root.addLayout(stats)

        self.tabs = QTabWidget()
        self.conn_table = self._table(["Proceso", "PID", "IP local", "Puerto", "IP remota", "Puerto",
                                       "Estado", "Destino"], widths=[170, 70, 130, 70, 130, 70, 110],
                                      empty="Inicia el monitor para ver las conexiones de red en tiempo "
                                            "real.", empty_icon="fa5s.wave-square")
        self.board = ProcBoard(self._on_proc_select)
        self.history = {}  # proceso -> {cpu: deque, rss: deque} de los últimos ~20 s (sparklines)
        self.proc_monitor = ProcessMonitor(app)  # tabla general de procesos (observación)
        self.tabs.addTab(self.proc_monitor, icon("fa5s.microchip"), "Procesos del sistema")
        self.tabs.addTab(self.conn_table, icon("fa5s.network-wired"), "Conexiones de red")
        self.tabs.addTab(self.board, icon("fa5s.bug"), "Procesos sospechosos")
        self.root.addWidget(self.tabs, 1)

        # Acciones sobre el proceso sospechoso seleccionado: Sandbox / Reporte Forense
        self.snapshot = None
        self.alerts = []
        self.selected = None
        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.proc_detail = QLabel("Selecciona un proceso en «Procesos sospechosos» para analizarlo.")
        self.proc_detail.setObjectName("CardText")
        self.proc_detail.setWordWrap(True)
        self.sandbox_btn = QPushButton("Lanzar en Sandbox")
        self.sandbox_btn.setObjectName("Ghost")
        with_icon(self.sandbox_btn, "fa5s.vial", COLORS["muted"])
        self.sandbox_btn.setEnabled(False)
        self.sandbox_btn.clicked.connect(self._launch_sandbox)
        self.forensic_btn = QPushButton("Reporte Forense")
        self.forensic_btn.setObjectName("Ghost")
        with_icon(self.forensic_btn, "fa5s.file-download", COLORS["muted"])
        self.forensic_btn.setEnabled(False)
        self.forensic_btn.clicked.connect(self._forensic)
        self.autopsy_btn = QPushButton("Enviar a Autopsias")
        self.autopsy_btn.setObjectName("Ghost")
        with_icon(self.autopsy_btn, "fa5s.vials", COLORS["muted"])
        self.autopsy_btn.setEnabled(False)
        self.autopsy_btn.setToolTip("Analiza el ejecutable (sin ejecutarlo) en la Mesa de Autopsias")
        self.autopsy_btn.clicked.connect(self._send_to_autopsy)
        self.trust_btn = QPushButton("Confiar")
        self.trust_btn.setObjectName("Ghost")
        with_icon(self.trust_btn, "fa5s.user-check", COLORS["muted"])
        self.trust_btn.setEnabled(False)
        self.trust_btn.setToolTip("Marca el proceso como de confianza: dejará de generar alertas")
        self.trust_btn.clicked.connect(self._trust_selected)
        actions.addWidget(self.proc_detail, 1)
        for b in (self.trust_btn, self.autopsy_btn, self.sandbox_btn, self.forensic_btn):
            actions.addWidget(b)
        self.root.addLayout(actions)

        if self.monitor is None:
            self.start_btn.setEnabled(False)
            self.status.setText(self.unavailable or "Monitor no disponible")

    @staticmethod
    def _table(headers, widths=None, empty="", empty_icon="fa5s.inbox"):
        return make_table(headers, widths, empty, empty_icon)  # alias: todas comparten fábrica

    def start(self) -> None:
        if self.running or self.monitor is None:
            return
        self.running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status.setText("●  EN DIRECTO")
        self.status.setObjectName("StatusOk")
        repolish(self.status)
        self.app.log_tactical("Monitor en vivo iniciado")
        self._tick()
        self.timer.start()
        self.app.refresh_sentinel_status()

    def stop(self) -> None:
        self.running = False
        self.timer.stop()
        self.proc_monitor.stop()  # detiene también el muestreo de procesos (cierre limpio)
        self.start_btn.setEnabled(self.monitor is not None)
        self.stop_btn.setEnabled(False)
        self.status.setText("○  Monitor detenido")
        self.status.setObjectName("StatusMuted")
        repolish(self.status)
        self.app.refresh_sentinel_status()

    def _tick(self) -> None:
        if not self.running or self.sampling:
            return
        self.sampling = True
        self.app.run_task(lambda emit: self.monitor.sample(), self._received, track=False)  # sondeo

    def _received(self, ok: bool, snap) -> None:
        self.sampling = False
        if not ok:
            self.app.console.log("x", f"Monitor: {snap}")
            return
        self._render(snap)
        self.app.sentinel_check(snap)  # Modo Centinela: avisa de amenazas nuevas (sin bloquear)
        self._publish_to_bus(snap)     # persiste la telemetría real en la Caja Negra (vía bus)

    def _publish_to_bus(self, snap) -> None:
        """
        Convierte cada instantánea del monitor en eventos del núcleo y los publica en el bus (que la
        Caja Negra persiste). Datos REALES del equipo; sin privilegios. publish() es no bloqueante.
        """
        bus = getattr(self.app, "bus", None)
        if bus is None or Event is None:
            return
        host = socket.gethostname()
        internet = {c.remote_ip for c in snap.connections if c.scope == "Internet"}
        crit = sum(1 for a in snap.alerts if a.severity is CRITICAL)
        try:
            bus.publish(Event.create(
                source="monitor:snapshot", host=host, observation=ObservationQuality.COMPLETE,
                event_type="monitor.snapshot",
                payload={"total_processes": snap.total_processes,
                         "connections": len(snap.connections),
                         "internet_destinations": len(internet),
                         "alerts": len(snap.alerts), "critical": crit,
                         "hidden_paths": snap.hidden_paths}))
            for a in snap.alerts:  # una entrada por proceso sospechoso (si los hay)
                bus.publish(Event.create(
                    source="monitor:alert", host=host, observation=ObservationQuality.PARTIAL,
                    event_type="process.alert", process_id=a.pid, provider_name=a.name,
                    payload={"name": a.name, "pid": a.pid, "severity": a.severity.value,
                             "reasons": list(a.reasons), "cpu": a.cpu, "rss": a.rss,
                             "path": a.path, "signature": a.signature}))
        except Exception as exc:  # noqa: BLE001  (nunca romper el monitor por un fallo del bus)
            self.app.console.log("x", f"Caja Negra: no se pudo publicar la telemetría: {exc}")

    def _render(self, snap) -> None:
        self.snapshot = snap
        self.alerts = list(snap.alerts)
        internet = [c for c in snap.connections if c.scope == "Internet"]
        self.stats["conns"].setText(str(len(snap.connections)))
        self.stats["internet"].setText(str(len({c.remote_ip for c in internet})))
        self.stats["procs"].setText(str(len({c.pid for c in snap.connections})))
        crit = sum(1 for a in snap.alerts if a.severity is CRITICAL)
        self.stats["alerts"].setText(f"{len(snap.alerts)}" + (f"  ({crit} crít.)" if crit else ""))
        with frozen(self.conn_table):
            self.conn_table.setRowCount(len(snap.connections))
            for r, c in enumerate(snap.connections):
                for col, v in enumerate([c.name, str(c.pid or "—"), c.local_ip, str(c.local_port),
                                         c.remote_ip, str(c.remote_port), c.status, c.scope]):
                    self.conn_table.setItem(r, col, QTableWidgetItem(v))
        now_keys = {proc_key(a): a for a in snap.alerts}
        for key, a in now_keys.items():  # historia de CPU/RAM para las sparklines
            hist = self.history.setdefault(key, {"cpu": deque(maxlen=20), "rss": deque(maxlen=20)})
            hist["cpu"].append(a.cpu)
            hist["rss"].append(a.rss)
        for key in list(self.history):
            if key not in now_keys:
                self.history.pop(key, None)
        self.board.update_cards(snap.alerts, self.history)
        self.status.setText(f"●  EN DIRECTO · {snap.taken:%H:%M:%S} · {snap.total_processes} procesos")

    def _on_proc_select(self, alert) -> None:
        self.selected = alert
        trusted = " · DE CONFIANZA" if self.app.is_process_trusted(alert.name) else ""
        self.proc_detail.setText(f"{alert.severity.value} · {alert.name} (PID {alert.pid}){trusted} · "
                                 f"Firma: {alert.signature}\n{alert.path or 'ruta no accesible'}")
        has_file = bool(alert.path and os.path.isfile(alert.path))
        self.sandbox_btn.setEnabled(has_file)
        self.autopsy_btn.setEnabled(has_file)
        self.forensic_btn.setEnabled(True)
        self.trust_btn.setEnabled(True)

    def _send_to_autopsy(self) -> None:
        a = self.selected
        if a is None or not (a.path and os.path.isfile(a.path)):
            return
        self.app.log_tactical(f"Enviando a la Mesa de Autopsias: {a.name}")
        self.app._select("historial")
        self.app.pages["historial"].analyze_path(a.path)

    def _trust_selected(self) -> None:
        a = self.selected
        if a is None:
            return
        self.app.trust_process(a.name)
        self._on_proc_select(a)  # refresca la etiqueta «DE CONFIANZA» del detalle

    def _launch_sandbox(self) -> None:
        a = self.selected
        if a is None:
            return
        available, info = sandbox_available()
        if not available:
            self.proc_detail.setText(info)
            self.app.console.log("x", "Windows Sandbox no disponible")
            return
        if not ConfirmDialog.ask(self.app, "Lanzar en Windows Sandbox",
                                 f"Se analizará «{a.name}» (PID {a.pid}) en una VM DESECHABLE y aislada: se "
                                 "congela el proceso, la carpeta del ejecutable se mapea en SOLO LECTURA y la "
                                 "muestra se deja PREPARADA (no se ejecuta sola). Al cerrar el Sandbox todo se "
                                 "destruye. ¿Continuar?", confirm_text="Lanzar Sandbox"):
            return
        self.app.log_tactical(f"Lanzando análisis aislado (Sandbox) sobre PID {a.pid} ({a.name})")
        tgt = a
        self.app.run_task(lambda emit: launch_in_sandbox(tgt.pid, tgt.name, tgt.path, emit=emit),
                          lambda ok, p: self.app.console.log("*" if ok else "x",
                                                             f"Sandbox: {'VM lanzada' if ok else p}"))

    def _forensic(self) -> None:
        a = self.selected
        if a is None:
            return
        self.app.log_tactical(f"Generando reporte forense de PID {a.pid} ({a.name})")
        tgt = a
        set_busy(self.forensic_btn, True, "Generando…")

        def done(ok, payload):
            set_busy(self.forensic_btn, False)
            if ok:
                self.app.console.log("*", f"Reporte forense: {os.path.basename(str(payload))}")
            else:
                self.app.console.log("x", f"Reporte forense: {payload}")

        self.app.run_task(lambda emit: forensic_report(tgt.pid, name=tgt.name, path=tgt.path,
                                                       signature=tgt.signature, reasons=list(tgt.reasons))[0], done)


# ===========================================================================
# PÁGINA: ESCANEO DE VECTORES (auditoría estática)
# ===========================================================================
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

        self.table = MonitorPage._table(["Nivel", "Módulo", "Hallazgo"], widths=[100, 220],
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


# ===========================================================================
# PÁGINA: MODO FANTASMA (limpieza de privacidad, con terminal en vivo)
# ===========================================================================
class GhostPage(Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Modo Fantasma",
                         "Herramientas de privacidad y limpieza de ESTE equipo. Las acciones "
                         "destructivas piden confirmación. La vigilancia del portapapeles avisa y, si "
                         "detecta el cambio de dirección típico de un clipper, vacía el portapapeles; "
                         "no elimina el malware.",
                         "fa5s.ghost")
        self.app = app
        self._clip_last = None
        self._clip_last_time = None

        body = self.root
        body.addWidget(self._build_shredder_card())
        body.addWidget(self._build_clipboard_card())
        body.addWidget(self._build_ram_card())
        body.addWidget(self._build_temp_card())
        body.addWidget(self._build_purge_card())
        body.addWidget(self._build_health_card())
        body.addWidget(self._build_autoruns_card())
        body.addStretch(1)

        # 600 ms: suficiente para cazar un intercambio de dirección cripto en < 1,5 s y vaciar en el acto.
        self._clip_timer = QTimer(self)
        self._clip_timer.setInterval(600)
        self._clip_timer.timeout.connect(self._clip_tick)

    # --- Trituradora de archivos ----------------------------------------------------------
    def _build_shredder_card(self) -> QFrame:
        box, lay = make_card("Trituradora de archivos",
                             "Elige un archivo: se sobrescribe con bytes aleatorios y se elimina. "
                             "Irreversible. En discos SSD la sobrescritura no garantiza el borrado "
                             "físico (wear-leveling); para eso haría falta cifrado de disco.")
        row = QHBoxLayout()
        self.shred_btn = QPushButton("Elegir archivo y triturar")
        self.shred_btn.setObjectName("Danger")
        with_icon(self.shred_btn, "fa5s.eraser", COLORS["beacon"])
        self.shred_btn.clicked.connect(self._shred)
        row.addWidget(self.shred_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return box

    def _shred(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self.app, "Selecciona el archivo a triturar",
                                              os.path.expanduser("~"))
        if not path:
            return
        if not ConfirmDialog.ask(self.app, "Triturar archivo",
                                 f"Se sobrescribirá y borrará DEFINITIVAMENTE:\n\n{path}\n\n"
                                 "Esta acción no se puede deshacer. ¿Continuar?",
                                 confirm_text="Triturar", danger=True):
            return
        set_busy(self.shred_btn, True, "Triturando…")
        self.app.log_tactical(f"Triturando archivo: {os.path.basename(path)}")

        def done(ok, res):
            set_busy(self.shred_btn, False)
            if ok and isinstance(res, dict) and res.get("ok"):
                self.app.console.log("*", f"Triturado: {os.path.basename(path)} "
                                          f"({res['bytes']} bytes · {res['passes']} pasada/s)")
                _emit_event(self.app, source="fantasma:trituradora",
                            event_type="privacy.file_shredded",
                            payload={"name": os.path.basename(path), "bytes": res["bytes"]})
            else:
                err = res.get("error") if isinstance(res, dict) else res
                self.app.console.log("x", f"Trituradora: {err}")

        self.app.run_task(lambda emit: shred_file(path), done)

    # --- Portapapeles (anti-clipper) ------------------------------------------------------
    def _build_clipboard_card(self) -> QFrame:
        box, lay = make_card("Portapapeles (anti-clipper)",
                             "Vacía el portapapeles al instante y, opcionalmente, vigila si copias datos "
                             "que PARECEN sensibles (frase semilla, dirección cripto, clave, tarjeta). La "
                             "vigilancia avisa y lo registra en la Caja Negra; no guarda el contenido "
                             "copiado.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.clip_clear_btn = QPushButton("Vaciar portapapeles ahora")
        self.clip_clear_btn.setObjectName("Ghost")
        with_icon(self.clip_clear_btn, "fa5s.clipboard", COLORS["muted"])
        self.clip_clear_btn.clicked.connect(self._clear_clipboard)
        self.clip_watch_btn = QPushButton("Vigilar portapapeles: OFF")
        self.clip_watch_btn.setObjectName("Toggle")
        self.clip_watch_btn.setCheckable(True)
        with_icon(self.clip_watch_btn, "fa5s.binoculars", COLORS["muted"])
        self.clip_watch_btn.clicked.connect(self._toggle_clip_watch)
        self.autopurge_btn = QPushButton("Auto-purgar en 15 s: OFF")
        self.autopurge_btn.setObjectName("Toggle")
        self.autopurge_btn.setCheckable(True)
        with_icon(self.autopurge_btn, "fa5s.hourglass-half", COLORS["muted"])
        self.autopurge_btn.clicked.connect(
            lambda: self.autopurge_btn.setText(
                "Auto-purgar en 15 s: " + ("ON" if self.autopurge_btn.isChecked() else "OFF")))
        # Acción inmediata en una fila y los dos interruptores en otra: en una sola fila los tres
        # botones no cabían en la ventana por defecto y aparecía scroll horizontal.
        row.addWidget(self.clip_clear_btn)
        row.addStretch(1)
        toggles = QHBoxLayout()
        toggles.setSpacing(10)
        toggles.addWidget(self.clip_watch_btn)
        toggles.addWidget(self.autopurge_btn)
        toggles.addStretch(1)
        defensa = QLabel("Defensa anti-swap activa mientras vigilas: si el portapapeles pasa de una "
                         "dirección cripto a otra distinta en <1,5 s, se vacía al instante y se graba "
                         "un evento crítico en la Caja Negra.")
        defensa.setObjectName("Tiny")
        defensa.setWordWrap(True)
        lay.addLayout(row)
        lay.addLayout(toggles)
        lay.addWidget(defensa)
        return box

    def _clear_clipboard(self) -> None:
        ok, msg = clear_clipboard()
        self.app.console.log("*" if ok else "x", f"Portapapeles: {msg}")
        self._clip_last = None

    def _toggle_clip_watch(self) -> None:
        on = self.clip_watch_btn.isChecked()
        self.clip_watch_btn.setText("Vigilar portapapeles: " + ("ON" if on else "OFF"))
        if on:
            self._clip_last = read_clipboard_text()  # referencia inicial: no avisa de lo ya copiado
            self._clip_last_time = time.monotonic()
            self._clip_timer.start()
            self.app.log_tactical("Vigilancia del portapapeles activada (anti-clipper)")
        else:
            self._clip_timer.stop()
            self.app.console.log("~", "Vigilancia del portapapeles detenida")

    def _clip_tick(self) -> None:
        text = read_clipboard_text()
        if text is None or text == self._clip_last:
            return
        ahora = time.monotonic()
        prev, prev_t = self._clip_last, self._clip_last_time
        self._clip_last, self._clip_last_time = text, ahora

        # 1) Defensa anti-swap: ¿una dirección cripto cambió por otra en < 1,5 s? → vaciar YA.
        delta = (ahora - prev_t) if prev_t is not None else None
        if is_hijack_swap(prev, text, delta):
            clear_clipboard()
            self._clip_last = None
            self.app.console.log("x", "¡Clipper bloqueado! El portapapeles cambió de dirección cripto; "
                                      "se vació para que no pegaras la del atacante.")
            self.app.record_alert("x", "Clipper bloqueado: el portapapeles cambió de dirección cripto "
                                       "y se vació en el acto.", module="fantasma")
            _emit_event(self.app, source="fantasma:portapapeles",
                        event_type="clipboard.hijack_blocked",
                        observation=(ObservationQuality.COMPLETE if ObservationQuality else None),
                        payload={"motivo": "intercambio de dirección cripto en <1,5 s",
                                 "delta_s": round(delta, 2) if delta is not None else None})
            return

        # 2) Clasificación/aviso y, si procede, auto-purga a los 15 s.
        sensible, etiqueta = looks_sensitive(text)
        if sensible:
            self.app.console.log("!", f"Portapapeles: contenido sensible detectado — {etiqueta}")
            self.app.record_alert("!", f"Portapapeles: contenido sensible — {etiqueta}", module="fantasma")
            _emit_event(self.app, source="fantasma:portapapeles", event_type="clipboard.sensitive",
                        payload={"clasificacion": etiqueta, "longitud": len(text)})
            if self.autopurge_btn.isChecked():
                self.app.console.log("~", "Auto-purga programada: el portapapeles se vaciará en 15 s "
                                          "si sigue igual.")
                QTimer.singleShot(15000, lambda s=text: self._autopurge(s))

    def _autopurge(self, snapshot) -> None:
        if read_clipboard_text() != snapshot:
            return  # el contenido ya cambió: no tocamos lo que la persona copió después
        ok, _msg = clear_clipboard()
        if ok:
            self._clip_last = None
            self.app.console.log("*", "Auto-purga: portapapeles vaciado (dato sensible, 15 s).")
            _emit_event(self.app, source="fantasma:portapapeles",
                        event_type="clipboard.auto_purged", payload={"tras_segundos": 15})

    # --- Optimizar RAM (working sets) -----------------------------------------------------
    def _build_ram_card(self) -> QFrame:
        box, lay = make_card("Optimizar RAM (vaciar working sets)",
                             "Pide a Windows que recorte el working set de los procesos accesibles del "
                             "usuario y muestra los MB realmente liberados. Sin privilegios (los procesos "
                             "del sistema se omiten). Es temporal: la RAM vuelve a crecer según haga falta.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.ram_btn = QPushButton("Optimizar RAM ahora")
        self.ram_btn.setObjectName("Ghost")
        with_icon(self.ram_btn, "fa5s.memory", COLORS["muted"])
        self.ram_btn.clicked.connect(self._optimize_ram)
        self.ram_status = QLabel("—")
        self.ram_status.setObjectName("Tiny")
        row.addWidget(self.ram_btn)
        row.addWidget(self.ram_status, 1)
        lay.addLayout(row)
        return box

    def _optimize_ram(self) -> None:
        set_busy(self.ram_btn, True, "Optimizando…")
        self.ram_status.setText("Recortando working sets…")
        self.app.log_tactical("Optimizando RAM: vaciando working sets de los procesos del usuario")

        def done(ok, res):
            set_busy(self.ram_btn, False)
            if ok and isinstance(res, dict) and res.get("ok"):
                self.ram_status.setText(f"{res['liberado_mb']} MB liberados · {res['procesos']} "
                                        f"procesos · {res['omitidos']} omitidos")
                self.app.console.log("*", f"RAM: {res['liberado_mb']} MB liberados en "
                                          f"{res['procesos']} procesos ({res['omitidos']} omitidos)")
                _emit_event(self.app, source="fantasma:ram", event_type="privacy.ram_optimized",
                            payload={"liberado_mb": res["liberado_mb"], "procesos": res["procesos"],
                                     "omitidos": res["omitidos"]})
            else:
                err = res.get("error") if isinstance(res, dict) else res
                self.ram_status.setText("no disponible")
                self.app.console.log("x", f"RAM: {err}")

        self.app.run_task(lambda emit: empty_working_sets(), done)

    # --- Limpiar temporales ---------------------------------------------------------------
    def _build_temp_card(self) -> QFrame:
        box, lay = make_card("Limpiar temporales (%TEMP%)",
                             "Borra los archivos de la carpeta de temporales del usuario que no estén en "
                             f"uso y dice cuántos. Los bloqueados se omiten.\nCarpeta: {temp_dir()}")
        row = QHBoxLayout()
        self.temp_btn = QPushButton("Limpiar temporales")
        self.temp_btn.setObjectName("Ghost")
        with_icon(self.temp_btn, "fa5s.broom", COLORS["muted"])
        self.temp_btn.clicked.connect(self._clean_temp)
        row.addWidget(self.temp_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return box

    def _clean_temp(self) -> None:
        if not ConfirmDialog.ask(self.app, "Limpiar temporales",
                                 f"Se borrarán los archivos NO bloqueados de:\n\n{temp_dir()}\n\n"
                                 "Los archivos en uso se omiten automáticamente. ¿Continuar?",
                                 confirm_text="Limpiar", danger=True):
            return
        set_busy(self.temp_btn, True, "Limpiando…")
        self.app.log_tactical("Limpiando la carpeta de temporales del usuario")

        def done(ok, res):
            set_busy(self.temp_btn, False)
            if ok and isinstance(res, dict) and res.get("ok"):
                mb = res["bytes"] / (1024 * 1024)
                self.app.console.log("*", f"Temporales: {res['eliminados']} archivos borrados "
                                          f"({mb:.1f} MB) · {res['omitidos']} omitidos (en uso)")
                _emit_event(self.app, source="fantasma:temporales",
                            event_type="privacy.temp_cleaned",
                            payload={"eliminados": res["eliminados"], "omitidos": res["omitidos"],
                                     "bytes": res["bytes"]})
            else:
                err = res.get("error") if isinstance(res, dict) else res
                self.app.console.log("x", f"Temporales: {err}")

        self.app.run_task(lambda emit: clean_temp(), done)

    # --- Purga completa (comportamiento previo) -------------------------------------------
    def _build_purge_card(self) -> QFrame:
        steps = " · ".join(label for _k, label, *_ in GHOST_STEPS)
        box, lay = make_card("Purga de privacidad completa",
                             "Ejecuta de una vez todos los pasos de limpieza (con recuento previo y "
                             "confirmación): " + steps + ".")
        row = QHBoxLayout()
        self.run_btn = QPushButton("Ejecutar Modo Fantasma")
        self.run_btn.setObjectName("Danger")
        with_icon(self.run_btn, "fa5s.ghost", COLORS["beacon"])
        self.run_btn.clicked.connect(self._run)
        row.addWidget(self.run_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return box

    def _run(self) -> None:
        set_busy(self.run_btn, True, "Calculando…")
        self.app.console.log("~", "Modo Fantasma: calculando lo que se va a limpiar…")
        self.app.run_task(lambda emit: ghost_preview(), self._previewed)

    def _previewed(self, ok: bool, counts) -> None:
        set_busy(self.run_btn, False)
        counts = counts if ok and isinstance(counts, dict) else {}
        contado = bool(counts.get("ok"))  # True solo si el recuento se calculó de verdad

        def _n(key):  # muestra «?» cuando el recuento no se pudo obtener (desconocido, no 0)
            return counts.get(key, 0) if contado else "?"

        aviso = "" if contado else ("• No se pudo calcular el recuento: se limpiará lo que haya "
                                    "(el recuento de arriba es solo informativo)\n")
        logs = ("• Registros de eventos (Application, System, Security) — IRREVERSIBLE\n" if self.app.admin
                else "• Registros de eventos: se omitirán (requieren Administrador)\n")
        msg = ("Borra de ESTE equipo, sin posibilidad de deshacer:\n\n"
               "• Caché DNS y ARP, portapapeles e historial de PowerShell\n"
               f"• {_n('recientes')} archivo(s) reciente(s) y Jump Lists\n"
               f"• Papelera ({_n('papelera')}) y temporales ({_n('temporales')})\n"
               "• Carpeta Prefetch\n" + logs + aviso +
               "\nEs limpieza de privacidad: no toca tus documentos. ¿Continuar?")
        if not ConfirmDialog.ask(self.app, "Activar Modo Fantasma", msg, confirm_text="Limpiar ahora", danger=True):
            self.app.console.log("~", "Modo Fantasma cancelado")
            return
        options = {k: True for k, _l, needs_admin, _d, _r in GHOST_STEPS if not needs_admin or self.app.admin}
        self.app.log_tactical("Modo Fantasma: iniciando purga de privacidad del equipo")
        set_busy(self.run_btn, True, "Purgando…")
        term = TerminalDialog(self.app, "MODO FANTASMA · purga en curso")
        term.show()
        self.app.run_ghost(options, term, lambda: set_busy(self.run_btn, False))

    # --- Salud del portátil (batería, disco, top procesos) ----------------------------------------
    def _build_health_card(self) -> QFrame:
        box, lay = make_card("Salud del portátil",
                             "Batería, espacio en C: y los 5 procesos que más RAM/CPU consumen ahora.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self._health_lbl = QLabel("Pulsa Actualizar para leer.")
        self._health_lbl.setObjectName("CardText")
        self._health_lbl.setWordWrap(True)
        refresh_btn = QPushButton("Actualizar")
        refresh_btn.setObjectName("Ghost")
        with_icon(refresh_btn, "fa5s.sync-alt", COLORS["muted"])
        refresh_btn.clicked.connect(self._refresh_health)
        row.addWidget(self._health_lbl, 1)
        row.addWidget(refresh_btn)
        lay.addLayout(row)
        self._top_table = make_table(["Proceso", "PID", "CPU %", "RAM MB", "Usuario"],
                                     widths=[200, 70, 70, 80])
        self._top_table.setMaximumHeight(180)
        lay.addWidget(self._top_table)
        self._health_terminate_btn = QPushButton("Finalizar proceso seleccionado (usuario)")
        self._health_terminate_btn.setObjectName("Danger")
        with_icon(self._health_terminate_btn, "fa5s.times-circle", COLORS["beacon"])
        self._health_terminate_btn.setEnabled(False)
        self._health_terminate_btn.clicked.connect(self._terminate_selected_proc)
        self._top_table.itemSelectionChanged.connect(self._on_top_select)
        row2 = QHBoxLayout()
        row2.addWidget(self._health_terminate_btn)
        row2.addStretch(1)
        lay.addLayout(row2)
        return box

    def _refresh_health(self) -> None:
        def task(emit):
            out = {}
            try:
                batt = psutil.sensors_battery()
                if batt:
                    out["batt"] = f"{batt.percent:.0f}%  {'enchufado' if batt.power_plugged else 'batería'}"
                else:
                    out["batt"] = "PC de escritorio (sin batería)"
            except Exception:  # noqa: BLE001
                out["batt"] = "N/A"
            try:
                du = psutil.disk_usage("C:\\")
                out["disk_free"] = f"{du.free / 1024**3:.1f} GB libres de {du.total / 1024**3:.1f} GB"
            except Exception:  # noqa: BLE001
                out["disk_free"] = "N/A"
            try:
                procs = []
                for p in psutil.process_iter(["pid", "name", "username", "memory_info", "cpu_percent"]):
                    try:
                        procs.append({"pid": p.info["pid"], "name": p.info["name"] or "",
                                      "user": p.info["username"] or "", "cpu": p.info["cpu_percent"] or 0,
                                      "ram": (p.info["memory_info"].rss / 1024**2) if p.info["memory_info"] else 0})
                    except Exception:  # noqa: BLE001
                        continue
                top5 = sorted(procs, key=lambda x: x["ram"], reverse=True)[:5]
                out["top5"] = top5
            except Exception:  # noqa: BLE001
                out["top5"] = []
            return out

        def done(ok, res):
            if not ok:
                self._health_lbl.setText(f"Error: {res}")
                return
            self._health_lbl.setText(f"Batería: {res.get('batt', 'N/A')}  ·  Disco C: {res.get('disk_free', 'N/A')}")
            top5 = res.get("top5", [])
            self._top_table.setProperty("_health_rows", top5)
            with frozen(self._top_table):
                self._top_table.setRowCount(len(top5))
                for r, p in enumerate(top5):
                    for c, v in enumerate([p["name"], str(p["pid"]), f"{p['cpu']:.1f}", f"{p['ram']:.0f}", p["user"]]):
                        self._top_table.setItem(r, c, QTableWidgetItem(v))

        self.app.run_task(task, done, track=False)

    def _on_top_select(self) -> None:
        self._health_terminate_btn.setEnabled(len(self._top_table.selectedItems()) > 0)

    def _terminate_selected_proc(self) -> None:
        rows = self._top_table.selectedItems()
        if not rows:
            return
        row = self._top_table.currentRow()
        name_item = self._top_table.item(row, 0)
        pid_item = self._top_table.item(row, 1)
        user_item = self._top_table.item(row, 4)
        if not pid_item:
            return
        pid = int(pid_item.text()) if pid_item.text().isdigit() else -1
        name = name_item.text() if name_item else "?"
        user = user_item.text() if user_item else ""
        me = getpass.getuser()
        if user and me and user.lower() != me.lower() and me.lower() not in user.lower():
            self.app.console.log("!", f"Proceso {name} (PID {pid}) pertenece a otro usuario ({user}): no se puede finalizar.")
            return
        if not ConfirmDialog.ask(self.app, "Finalizar proceso",
                                 f"Finalizar el proceso del USUARIO:\n\n{name}  (PID {pid})\n\n"
                                 "No finalices procesos del sistema. ¿Continuar?",
                                 confirm_text="Finalizar", danger=True):
            return
        try:
            psutil.Process(pid).terminate()
            self.app.console.log("*", f"Proceso finalizado: {name} (PID {pid})")
        except Exception as exc:  # noqa: BLE001
            self.app.console.log("x", f"No se pudo finalizar {name}: {exc}")

    # --- Inspector de Inicio de Windows (Autoruns) ------------------------------------------------
    def _build_autoruns_card(self) -> QFrame:
        box, lay = make_card("Inspector de Inicio de Windows (Autoruns)",
                             "Entradas que arrancan automáticamente con el equipo (HKCU Run + carpetas Inicio). "
                             "Solo lectura; ayuda a detectar programas que ralentizan el arranque.")
        row = QHBoxLayout()
        row.setSpacing(10)
        scan_btn = QPushButton("Escanear entradas de inicio")
        scan_btn.setObjectName("Ghost")
        with_icon(scan_btn, "fa5s.search", COLORS["muted"])
        self._autoruns_table = make_table(["Nombre", "Origen", "Ruta del ejecutable", "Existe"],
                                          widths=[180, 200, 300],
                                          empty="Pulsa «Escanear» para listar las entradas de inicio.")
        self._autoruns_table.setMaximumHeight(200)
        scan_btn.clicked.connect(self._scan_autoruns)
        row.addWidget(scan_btn)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addWidget(self._autoruns_table)
        return box

    def _scan_autoruns(self) -> None:
        def done(ok, entries):
            if not ok:
                self.app.console.log("x", f"Autoruns: {entries}")
                return
            with frozen(self._autoruns_table):
                self._autoruns_table.setRowCount(len(entries))
                for r, e in enumerate(entries):
                    existe = "Sí" if e.get("existe") else "No"
                    color = "#22C55E" if e.get("existe") else "#F59E0B"
                    for c, v in enumerate([e.get("nombre", ""), e.get("origen", ""), e.get("ruta", ""), existe]):
                        item = QTableWidgetItem(v)
                        if c == 3:
                            item.setForeground(QColor(color))
                        self._autoruns_table.setItem(r, c, item)
            self.app.console.log("~", f"Autoruns: {len(entries)} entradas de inicio encontradas")
        self.app.run_task(lambda emit: startup_entries(), done, track=False)


# ===========================================================================
# PÁGINA: HISTORIAL (snapshots de caja negra)
# ===========================================================================
class HistorialPage(Page):
    """
    Panel forense: visor/rebobinado de la Caja Negra (eventos.jsonl real), mesa de autopsias ESTÁTICA
    de archivos (hashes, entropía, cabeceras PE, indicadores) y snapshots del estado volátil. Todo
    local y de solo lectura: no ejecuta nada ni modifica los archivos analizados.
    """

    SOURCES = [("todas", "Todas las fuentes"), ("honeypot", "Honeypot"), ("privacy", "Privacidad"),
               ("network", "Red"), ("monitor", "Monitor"), ("forensics", "Forense"), ("otros", "Otros")]

    def __init__(self, app: "MainWindow"):
        super().__init__("Historial y Laboratorio Forense",
                         "Visor de la Caja Negra, mesa de autopsias de archivos y snapshots del "
                         "sistema. Todo local y de solo lectura.", "fa5s.history")
        self.app = app
        self.snaps = []
        self._events = []
        self._filtered = []
        # Debounce del buscador: filtrar hasta 5000 eventos en CADA pulsación hacía que escribir
        # fuese a saltos; se filtra 200 ms después de la última tecla.
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(200)
        self._search_timer.timeout.connect(self._apply_filter)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_blackbox_tab(), "Visor de Caja Negra")
        self.tabs.addTab(self._build_autopsy_tab(), "Mesa de Autopsias")
        self.tabs.addTab(self._build_snapshots_tab(), "Snapshots del sistema")
        self.root.addWidget(self.tabs, 1)
        self.refresh()        # lista de snapshots (síncrono)
        # La carga de la Caja Negra usa run_task (consola): se aplaza hasta que el bucle de eventos
        # arranca, porque la consola de telemetría aún no existe al construir las páginas.
        QTimer.singleShot(0, self._initial_load)

    def _initial_load(self) -> None:
        if getattr(self.app, "console", None) is not None:
            self.reload_events()

    # --- Visor de la Caja Negra -----------------------------------------------------------
    def _blackbox_file(self) -> str:
        bb = getattr(self.app, "blackbox", None)
        if bb is not None and getattr(bb, "path", None):
            return bb.path
        return os.path.join(FORENSICS_DIR, "CajaNegra", "eventos.jsonl")

    def _build_blackbox_tab(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Content")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)  # aire dentro del marco de la pestaña
        lay.setSpacing(10)
        ctl = QHBoxLayout()
        ctl.setSpacing(10)
        self.reload_btn = QPushButton("Recargar / Rebobinar")
        self.reload_btn.setObjectName("Primary")
        with_icon(self.reload_btn, "fa5s.redo")
        self.reload_btn.clicked.connect(self.reload_events)
        self.source_combo = QComboBox()
        for key, label in self.SOURCES:
            self.source_combo.addItem(label, key)
        self.source_combo.currentIndexChanged.connect(self._apply_filter)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Buscar texto en los eventos…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._search_timer.start)  # reinicia el debounce
        self.export_btn = QPushButton("Exportar informe")
        self.export_btn.setObjectName("Ghost")
        with_icon(self.export_btn, "fa5s.file-export", COLORS["muted"])
        self.export_btn.clicked.connect(self._export_events)
        ctl.addWidget(self.reload_btn)
        ctl.addWidget(self.source_combo)
        ctl.addStretch(1)
        ctl.addWidget(self.export_btn)
        lay.addLayout(ctl)
        lay.addWidget(self.search_edit)  # fila propia y a todo lo ancho: antes quedaba aplastado
        self.bb_count = QLabel("—")
        self.bb_count.setObjectName("Tiny")
        lay.addWidget(self.bb_count)
        self.events_table = MonitorPage._table(["Hora (UTC)", "Categoría", "Fuente", "Tipo", "Resumen"],
                                               widths=[150, 105, 170, 210])
        self.events_table.setMinimumHeight(240)
        self.events_table.itemSelectionChanged.connect(self._show_event_json)
        # Tabla (arriba) y JSON del evento (abajo) en un QSplitter: ninguno queda aplastado.
        json_host = QWidget()
        json_host.setObjectName("Content")
        jl = QVBoxLayout(json_host)
        jl.setContentsMargins(0, 2, 0, 0)
        jl.setSpacing(4)
        cap = QLabel("JSON DEL EVENTO SELECCIONADO")
        cap.setObjectName("ConsoleTitle")
        jl.addWidget(cap)
        self.event_json = QPlainTextEdit()
        self.event_json.setObjectName("Console")
        self.event_json.setReadOnly(True)
        self.event_json.setFont(QFont("Consolas", 10))
        self.event_json.setMinimumHeight(110)
        jl.addWidget(self.event_json, 1)
        split = QSplitter(Qt.Orientation.Vertical)
        split.setObjectName("VSplit")
        split.setHandleWidth(6)
        split.addWidget(self.events_table)
        split.addWidget(json_host)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setCollapsible(0, False)
        lay.addWidget(split, 1)
        return w

    def reload_events(self) -> None:
        path = self._blackbox_file()
        set_busy(self.reload_btn, True, "Leyendo…")

        def done(ok, data):
            set_busy(self.reload_btn, False)
            self._events = data if ok and isinstance(data, list) else []
            if not ok:
                self.app.console.log("x", f"Caja Negra: {data}")
            self._apply_filter()

        self.app.run_task(lambda emit: read_events(path, limit=5000), done)

    def _apply_filter(self) -> None:
        key = self.source_combo.currentData()
        needle = self.search_edit.text().strip().lower()
        self._filtered = []
        rows = []
        for ev in self._events:
            r = event_row(ev)
            if key and key != "todas" and r[1] != key:
                continue
            if needle and needle not in " ".join(str(x) for x in r).lower():
                continue
            self._filtered.append(ev)
            rows.append(r)
        if not self._events:
            self.events_table.set_empty_text("La Caja Negra está vacía: los eventos de seguridad "
                                             "aparecerán aquí según ocurran.", "fa5s.box-open")
        elif not rows:
            self.events_table.set_empty_text("Ningún evento coincide con el filtro actual.", "fa5s.search")
        with frozen(self.events_table):
            self.events_table.setRowCount(len(rows))
            for i, r in enumerate(rows):
                for col, v in enumerate(r):
                    self.events_table.setItem(i, col, QTableWidgetItem(str(v)))
        total = len(self._events)
        filtro = f" de {total}" if len(rows) != total else ""
        # Solo el nombre del fichero: la ruta completa (sin espacios, no se puede partir) forzaba
        # scroll horizontal. La ruta entera queda en el tooltip.
        self.bb_count.setText(f"{len(rows)}{filtro} evento(s) · {os.path.basename(self._blackbox_file())}")
        self.bb_count.setToolTip(self._blackbox_file())
        self.event_json.setPlainText("")

    def _show_event_json(self) -> None:
        r = self.events_table.currentRow()
        if 0 <= r < len(self._filtered):
            self.event_json.setPlainText(json.dumps(self._filtered[r], ensure_ascii=False, indent=2))

    def _export_events(self) -> None:
        if not self._filtered:
            self.app.console.log("~", "No hay eventos que exportar con el filtro actual.")
            return
        destino, _ = QFileDialog.getSaveFileName(
            self.app, "Exportar evidencias",
            os.path.join(os.path.expanduser("~"), "lozarus_evidencias.json"),
            "JSON (*.json);;Texto JSONL (*.txt)")
        if not destino:
            return

        set_busy(self.export_btn, True, "Exportando…")

        def done(ok, n):
            set_busy(self.export_btn, False)
            if ok:
                self.app.console.log("*", f"Exportados {n} evento(s) a {destino}")
            else:
                self.app.console.log("x", f"Exportar: {n}")

        eventos = list(self._filtered)
        self.app.run_task(lambda emit: export_report(eventos, destino), done)

    # --- Mesa de autopsias estática -------------------------------------------------------
    def _build_autopsy_tab(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Content")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)  # aire dentro del marco de la pestaña
        lay.setSpacing(10)
        desc = QLabel("Analiza un archivo SIN ejecutarlo: hashes (MD5/SHA-256), tamaño, entropía de "
                      "Shannon (aviso si supera 7,2), cabeceras PE e indicadores (IPs, URLs, registro, "
                      "APIs sospechosas).")
        desc.setObjectName("CardText")
        desc.setWordWrap(True)
        row = QHBoxLayout()
        self.analyze_btn = QPushButton("Analizar archivo (.exe / .dll / script)")
        self.analyze_btn.setObjectName("Primary")
        with_icon(self.analyze_btn, "fa5s.vial")
        self.analyze_btn.clicked.connect(self._analyze)
        row.addWidget(self.analyze_btn)
        row.addStretch(1)
        lay.addWidget(desc)
        lay.addLayout(row)
        self.autopsy_head = QLabel("—")
        self.autopsy_head.setObjectName("Tiny")
        self.autopsy_head.setWordWrap(True)
        lay.addWidget(self.autopsy_head)
        self.autopsy_out = QPlainTextEdit()
        self.autopsy_out.setObjectName("Console")
        self.autopsy_out.setReadOnly(True)
        self.autopsy_out.setFont(QFont("Consolas", 10))
        lay.addWidget(self.autopsy_out, 1)
        return w

    def _analyze(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self.app, "Selecciona el archivo a analizar",
                                              os.path.expanduser("~"))
        if path:
            self.analyze_path(path)

    def analyze_path(self, path: str) -> None:
        """Analiza `path` en la Mesa de Autopsias (usado también desde el Monitor en Vivo)."""
        if not path:
            return
        self.tabs.setCurrentIndex(1)   # pestaña «Mesa de Autopsias»
        set_busy(self.analyze_btn, True, "Analizando…")
        self.autopsy_head.setText(f"Analizando {os.path.basename(path)}…")
        self.autopsy_out.setPlainText("")
        self.app.log_tactical(f"Autopsia estática: {os.path.basename(path)}")

        def done(ok, res):
            set_busy(self.analyze_btn, False)
            if ok and isinstance(res, dict) and res.get("ok"):
                self._render_autopsy(res)
                _emit_event(self.app, source="forensics:autopsia",
                            event_type="forensics.file_analyzed",
                            payload={"name": res["name"], "sha256": res["sha256"],
                                     "size": res["size"], "entropy": res["entropy"],
                                     "is_pe": res["is_pe"]})
            else:
                err = res.get("error") if isinstance(res, dict) else res
                self.autopsy_head.setText("Error en el análisis")
                self.autopsy_out.setPlainText(str(err))

        self.app.run_task(lambda emit: analyze_file(path), done)

    def _render_autopsy(self, res) -> None:
        etiqueta, warn = classify_entropy(res["entropy"])
        cabecera = f"{res['name']}  ·  {res['size']} bytes  ·  entropía {res['entropy']}/8 ({etiqueta})"
        self.autopsy_head.setText(("⚠ " if warn else "") + cabecera)
        self.autopsy_head.setStyleSheet("color:%s; font-size:12px; font-weight:600;" %
                                        ("#EF4444" if warn else "#A1A1AA"))
        lines = [f"MD5     : {res['md5']}",
                 f"SHA-256 : {res['sha256']}",
                 f"Tamaño  : {res['size']} bytes",
                 f"Entropía: {res['entropy']} / 8  → {etiqueta}"
                 + ("   ⚠ POSIBLE PACKER/CIFRADO" if warn else "")]
        if res["is_pe"] and res["pe"]:
            pe = res["pe"]
            tipo = "DLL" if pe["is_dll"] else ("EXE" if pe["is_exe"] else "PE")
            lines += ["",
                      f"PE      : {pe['magic_name']} · {tipo} · {pe['machine_name']}",
                      f"          secciones={pe['sections']} · subsistema={pe['subsystem_name']}",
                      f"          compilado={pe['timestamp_utc'] or pe['timestamp']}"]
        elif res["is_pe"]:
            lines += ["", "PE      : cabecera MZ presente, pero no se pudo parsear la cabecera PE."]
        else:
            lines += ["", "PE      : no es un ejecutable PE (sin cabecera MZ)."]
        ind = res.get("indicators") or {}
        for titulo, clave in (("IPs", "ips"), ("URLs", "urls"),
                              ("Rutas de registro", "registry"), ("APIs sospechosas", "apis")):
            vals = ind.get(clave) or []
            lines += ["", f"{titulo} ({len(vals)}):"]
            lines += [f"  · {v}" for v in vals] if vals else ["  (ninguno)"]
        self.autopsy_out.setPlainText("\n".join(lines))

    # --- Snapshots del estado volátil (comportamiento previo) -----------------------------
    def _build_snapshots_tab(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Content")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)  # aire dentro del marco de la pestaña
        lay.setSpacing(10)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.snap_btn = QPushButton("Tomar Snapshot del Sistema")
        self.snap_btn.setObjectName("Primary")
        with_icon(self.snap_btn, "fa5s.camera")
        self.snap_btn.clicked.connect(self._take)
        open_btn = QPushButton("Abrir carpeta forense")
        open_btn.setObjectName("Ghost")
        with_icon(open_btn, "fa5s.folder-open", COLORS["muted"])
        open_btn.clicked.connect(lambda: self._open(FORENSICS_DIR))
        row.addWidget(self.snap_btn)
        row.addWidget(open_btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.table = MonitorPage._table(["Snapshot", "Fecha", "Tamaño"], widths=[320, 170],
                                        empty="Aún no hay snapshots. Pulsa «Tomar Snapshot del Sistema» o usa "
                                              "la Captura Instantánea del Centro de Comando.",
                                        empty_icon="fa5s.camera")
        self.table.setToolTip("Doble clic para abrir la carpeta del snapshot")
        self.table.doubleClicked.connect(self._open_selected)
        lay.addWidget(self.table, 1)
        return w

    def refresh(self) -> None:
        self.snaps = list_snapshots()
        with frozen(self.table):
            self.table.setRowCount(len(self.snaps))
            for r, (path, name, when) in enumerate(self.snaps):
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                for col, v in enumerate([name, f"{when:%d/%m/%Y %H:%M:%S}", f"{size / 1024:.0f} KB"]):
                    self.table.setItem(r, col, QTableWidgetItem(v))

    def _take(self) -> None:
        set_busy(self.snap_btn, True, "Capturando…")
        self.app.log_tactical("Capturando snapshot de caja negra del sistema")

        def done(ok, payload):
            set_busy(self.snap_btn, False)
            if ok:
                path, summary = payload
                self.app.console.log("*", f"Snapshot guardado: {os.path.basename(path)} "
                                          f"({summary['procesos']} procesos · {summary['conexiones']} conexiones)")
                self.refresh()
            else:
                self.app.console.log("x", f"Snapshot: {payload}")

        self.app.run_task(lambda emit: system_snapshot(), done)

    def _open_selected(self) -> None:
        r = self.table.currentRow()
        if 0 <= r < len(self.snaps):
            self._open(self.snaps[r][0])

    def _open(self, path: str) -> None:
        try:
            os.startfile(os.path.dirname(path) if os.path.isfile(path) else path)  # noqa: S606
        except Exception as exc:  # noqa: BLE001  (antes se silenciaba: el clic no hacía nada)
            self.app.console.log("x", f"No se pudo abrir «{path}»: {exc}")


# ===========================================================================
# VENTANA PRINCIPAL
# ===========================================================================
class Toast(QFrame):
    """
    Aviso in-app no intrusivo: una tarjeta que aparece abajo a la derecha, se apila con las demás,
    se auto-descarta a los ~7 s y ofrece acciones rápidas (Ir al módulo / Confiar / Descartar). No
    bloquea nada: el evento ya está en la consola y en la Caja Negra; esto es solo un recordatorio.
    """
    KIND_COLOR = {"!": "#F59E0B", "x": "#EF4444", "*": "#22C55E", "~": "#60A5FA", "+": "#60A5FA"}
    _active: list = []
    LIFE_MS = 7000

    def __init__(self, win, entry: dict):
        super().__init__(win)
        self.win = win
        self.entry = entry
        self.setObjectName("Toast")
        color = self.KIND_COLOR.get(entry.get("kind"), "#60A5FA")
        self.setStyleSheet("#Toast { background:#18181F; border:1px solid #2E2E38; border-left:3px solid "
                           + color + "; border-radius:10px; }")
        self.setFixedWidth(348)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 12, 12)
        lay.setSpacing(8)
        top = QHBoxLayout()
        top.setSpacing(8)
        ic = QLabel()
        ic.setPixmap(icon("fa5s.exclamation-circle", color).pixmap(16, 16))
        head = QLabel("Alerta de seguridad")
        head.setStyleSheet(f"color:{color}; font-weight:bold; font-size:12px;")
        close = QPushButton("✕")
        close.setObjectName("ToastClose")
        close.setFixedSize(20, 20)
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.clicked.connect(self.dismiss)
        top.addWidget(ic)
        top.addWidget(head)
        top.addStretch(1)
        top.addWidget(close)
        lay.addLayout(top)
        body = QLabel(entry.get("text", ""))
        body.setStyleSheet("color:#D4D4D8; font-size:12px;")
        body.setWordWrap(True)
        lay.addWidget(body)
        actions = QHBoxLayout()
        actions.setSpacing(8)
        if entry.get("module") and entry["module"] in getattr(win, "pages", {}):
            go = QPushButton("Ir al módulo")
            go.setObjectName("Mini")
            go.clicked.connect(lambda: (win._select(entry["module"]), self.dismiss()))
            actions.addWidget(go)
        if entry.get("process") and hasattr(win, "trust_process"):
            trust = QPushButton("Confiar")
            trust.setObjectName("Mini")
            trust.clicked.connect(lambda: (win.trust_process(entry["process"]), self.dismiss()))
            actions.addWidget(trust)
        actions.addStretch(1)
        dismiss = QPushButton("Descartar")
        dismiss.setObjectName("Mini")
        dismiss.clicked.connect(self.dismiss)
        actions.addWidget(dismiss)
        lay.addLayout(actions)
        self._life = QTimer(self)
        self._life.setSingleShot(True)
        self._life.timeout.connect(self.dismiss)

    def slide_in(self) -> None:
        self.adjustSize()
        Toast._active.append(self)
        self._reflow()
        self.show()
        self.raise_()
        self._life.start(self.LIFE_MS)

    def dismiss(self) -> None:
        if self in Toast._active:
            Toast._active.remove(self)
        self._life.stop()
        self.hide()
        self.deleteLater()
        Toast._reflow_all()

    @classmethod
    def _reflow_all(cls) -> None:
        for t in list(cls._active):
            t._reflow()

    def _reflow(self) -> None:
        """Apila los toasts activos desde la esquina inferior derecha hacia arriba."""
        try:
            idx = Toast._active.index(self)
        except ValueError:
            return
        self.adjustSize()
        margin, gap, y = 18, 10, 0
        for t in Toast._active[Toast._active.index(self) + 1:]:
            y += t.height() + gap
        x = self.win.width() - self.width() - margin
        bottom = self.win.height() - margin - (self._grip_clearance())
        self.move(x, bottom - self.height() - y)
        _ = idx

    def _grip_clearance(self) -> int:
        return 20  # deja hueco al QSizeGrip de la esquina


class AlertCenter(QFrame):
    """Panel desplegable (anclado bajo la campana) con el historial de alertas de la sesión."""

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setObjectName("AlertCenter")
        self.setStyleSheet("#AlertCenter { background:#121217; border:1px solid #2E2E38; border-radius:12px; }")
        self.setFixedWidth(410)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)
        head = QHBoxLayout()
        title = QLabel("Alertas de la sesión")
        title.setObjectName("CardTitle")
        self.clear_btn = QPushButton("Limpiar")
        self.clear_btn.setObjectName("Mini")
        self.clear_btn.clicked.connect(self._clear)
        close = QPushButton("✕")
        close.setObjectName("ToastClose")
        close.setFixedSize(22, 22)
        close.clicked.connect(self.hide)
        head.addWidget(title)
        head.addStretch(1)
        head.addWidget(self.clear_btn)
        head.addWidget(close)
        lay.addLayout(head)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setObjectName("Content")
        self.scroll.setFixedHeight(360)
        self._body = QWidget()
        self._body.setObjectName("Content")
        self._list = QVBoxLayout(self._body)
        self._list.setContentsMargins(0, 0, 6, 0)
        self._list.setSpacing(6)
        self._list.addStretch(1)
        self.scroll.setWidget(self._body)
        lay.addWidget(self.scroll)

    def _clear(self) -> None:
        self.win.alerts_log.clear()
        self.win.titlebar.set_alert_count(0)
        self.refresh()

    def refresh(self) -> None:
        while self._list.count() > 1:   # deja el stretch final
            item = self._list.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        alerts = list(reversed(self.win.alerts_log))
        if not alerts:
            empty = QLabel("Sin alertas en esta sesión. Aquí aparecerán los procesos sin firma, los "
                           "cambios en archivos vigilados, los puertos nuevos y las alertas del "
                           "portapapeles.")
            empty.setObjectName("Tiny")
            empty.setWordWrap(True)
            self._list.insertWidget(0, empty)
            return
        for entry in alerts[:200]:
            self._list.insertWidget(self._list.count() - 1, self._row(entry))

    def _row(self, entry: dict) -> QFrame:
        color = Toast.KIND_COLOR.get(entry.get("kind"), "#60A5FA")
        row = QFrame()
        row.setStyleSheet("background:#18181F; border:1px solid #272730; border-radius:8px;")
        rl = QVBoxLayout(row)
        rl.setContentsMargins(10, 8, 10, 8)
        rl.setSpacing(3)
        top = QHBoxLayout()
        dot = QLabel("●")
        dot.setStyleSheet(f"color:{color}; font-size:10px;")
        when = QLabel(entry["when"].strftime("%H:%M:%S"))
        when.setObjectName("Tiny")
        top.addWidget(dot)
        top.addWidget(when)
        top.addStretch(1)
        if entry.get("module") and entry["module"] in getattr(self.win, "pages", {}):
            go = QPushButton("Ir")
            go.setObjectName("Mini")
            go.setFixedHeight(22)
            go.clicked.connect(lambda _=False, k=entry["module"]: (self.win._select(k), self.hide()))
            top.addWidget(go)
        rl.addLayout(top)
        text = QLabel(entry.get("text", ""))
        text.setStyleSheet("color:#D4D4D8; font-size:12px;")
        text.setWordWrap(True)
        rl.addWidget(text)
        return row

    def reposition(self) -> None:
        self.adjustSize()
        x = max(10, self.win.width() - self.width() - 14)
        self.move(x, 50)
        self.raise_()


class EdgeResizer(QObject):
    """
    Redimensionado por los bordes de una ventana SIN marco. Filtra los eventos de ratón a nivel de
    aplicación (así llegan aunque el cursor esté sobre un widget hijo) y solo actúa en una franja de
    MARGIN px pegada al borde de la ventana: fuera de esa franja no interfiere con ningún clic.
    """
    MARGIN = 6

    def __init__(self, win: QMainWindow):
        super().__init__(win)
        self.win = win
        self._edges = ""
        self._active = False
        self._geo0: Optional[QRect] = None
        self._pos0 = None

    def _hit(self, gpos) -> str:
        if self.win.isMaximized() or self.win.isFullScreen():
            return ""
        g = self.win.frameGeometry()
        m = self.MARGIN
        if not g.adjusted(-m, -m, m, m).contains(gpos):
            return ""
        edges = ""
        if abs(gpos.x() - g.left()) <= m:
            edges += "l"
        elif abs(gpos.x() - g.right()) <= m:
            edges += "r"
        if abs(gpos.y() - g.top()) <= m:
            edges += "t"
        elif abs(gpos.y() - g.bottom()) <= m:
            edges += "b"
        return edges

    @staticmethod
    def _cursor_for(edges: str):
        s = set(edges)
        if s in ({"l", "t"}, {"r", "b"}):
            return Qt.CursorShape.SizeFDiagCursor
        if s in ({"r", "t"}, {"l", "b"}):
            return Qt.CursorShape.SizeBDiagCursor
        if s & {"l", "r"}:
            return Qt.CursorShape.SizeHorCursor
        if s & {"t", "b"}:
            return Qt.CursorShape.SizeVerCursor
        return Qt.CursorShape.ArrowCursor

    def eventFilter(self, obj, event) -> bool:
        et = event.type()
        if et == QEvent.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
            edges = self._hit(event.globalPosition().toPoint())
            if edges:
                self._active, self._edges = True, edges
                self._geo0 = QRect(self.win.geometry())
                self._pos0 = event.globalPosition().toPoint()
                return True
        elif et == QEvent.Type.MouseMove:
            if self._active:
                self._do_resize(event.globalPosition().toPoint())
                return True
            edges = self._hit(event.globalPosition().toPoint())
            if edges:
                self.win.setCursor(self._cursor_for(edges))
            elif self.win.cursor().shape() != Qt.CursorShape.ArrowCursor:
                self.win.unsetCursor()
        elif et == QEvent.Type.MouseButtonRelease and self._active:
            self._active, self._edges = False, ""
            self.win.unsetCursor()
            return True
        return False

    def _do_resize(self, gpos) -> None:
        d = gpos - self._pos0
        g = QRect(self._geo0)
        mn = self.win.minimumSize()
        if "l" in self._edges:
            g.setLeft(min(g.left() + d.x(), g.right() - mn.width()))
        if "r" in self._edges:
            g.setRight(max(g.right() + d.x(), g.left() + mn.width()))
        if "t" in self._edges:
            g.setTop(min(g.top() + d.y(), g.bottom() - mn.height()))
        if "b" in self._edges:
            g.setBottom(max(g.bottom() + d.y(), g.top() + mn.height()))
        self.win.setGeometry(g)


class MainWindow(QMainWindow):
    NAV = [("comando", "Centro de Comando"), ("monitor", "Monitor en Vivo"),
           ("auditoria", "Escaneo de Vectores"), ("historial", "Historial"),
           ("red", "Endurecimiento de Red"), ("honeypot", "Honeypot"),
           ("fantasma", "Modo Fantasma")]

    NAV_SECTORS = [
        ("CENTRO DE CONTROL", ["comando", "monitor"]),
        ("SISTEMA Y PERÍMETRO", ["auditoria", "red", "fantasma"]),
        ("LABORATORIO Y REGISTRO", ["honeypot", "historial"]),
    ]

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1280, 800)
        # Arranque amplio pero contenido dentro de la pantalla disponible (90%, tope 1600×1000).
        screen = QApplication.primaryScreen()
        avail = screen.availableGeometry() if screen else None
        if avail is not None:
            w0 = max(1280, min(1600, int(avail.width() * 0.9)))
            h0 = max(800, min(1000, int(avail.height() * 0.9)))
            self.resize(w0, h0)
            self.move(avail.center().x() - w0 // 2, avail.center().y() - h0 // 2)
        else:
            self.resize(1440, 900)
        self.admin = is_admin()
        self._workers = []  # mantiene vivos los QThread en curso (se liberan en su señal finished)
        self._closing = False   # True desde closeEvent: ya no se lanzan tareas ni se tocan widgets
        self._active_tasks = 0  # tareas visibles para el usuario en curso (indicador de actividad)
        self.alerts_log = []    # historial de alertas de la sesión (campana de la cabecera)
        self.alert_center = None  # panel desplegable de alertas (perezoso)
        self.modules, self.plugin_errors = discover_modules()  # mismos plugins que auditor.py
        self.module_titles = {m.key: m.title for m in self.modules}
        self.sentinel = Sentinel()      # anti-spam del Modo Centinela (Vanguardia)
        self.sentinel_on = False
        self.last_notice = None

        # Bus de eventos + Caja Negra (persistencia JSONL). Se crean ANTES que las páginas porque
        # el Cuartel General lee self.blackbox al construirse. Si algo falla, la GUI sigue sin ellos.
        self.bus = None
        self.blackbox = None
        self._blackbox_error = ""
        if HAS_BLACKBOX:
            try:
                self.bus = EventBus(name="lozarus-gui")
                self.blackbox = CajaNegra(os.path.join(FORENSICS_DIR, "CajaNegra"))
                self.blackbox.attach(self.bus)
                self.bus.start()
                self.blackbox.start()
            except Exception as exc:  # noqa: BLE001
                self.bus = self.blackbox = None
                self._blackbox_error = f"{type(exc).__name__}: {exc}"

        # Persistencia táctica + motor de Honeypot autónomo (sin admin). Se crean ANTES que las
        # páginas porque la pestaña Honeypot y el Cuartel General leen self.honeypot al construirse.
        self.tactical_config = None
        self.honeypot = None
        if HAS_HONEYPOT:
            try:
                self.tactical_config = TacticalConfig(os.path.join(FORENSICS_DIR, "tactical_config.json"))
                decoy_dir = os.path.join(os.path.expanduser("~"), "Documents", "Lozarus_Vault_Decoy")
                self.honeypot = HoneypotEngine(
                    decoy_dir, bus=self.bus,
                    auto_rebuild=bool(self.tactical_config.get("hp_auto_rebuild", False)))
            except Exception as exc:  # noqa: BLE001
                self.tactical_config = self.honeypot = None
                self._blackbox_error = (self._blackbox_error + " · " if self._blackbox_error else "") \
                    + f"Honeypot: {type(exc).__name__}: {exc}"

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)
        self.titlebar = TitleBar(self)
        outer.addWidget(self.titlebar)

        # Cuerpo (barra lateral + páginas) y consola, dentro de un QSplitter vertical arrastrable.
        body_wrap = QWidget()
        body = QHBoxLayout(body_wrap)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())
        self.stack = QStackedWidget()
        self.pages = {"comando": CommandPage(self), "monitor": MonitorPage(self),
                      "auditoria": AuditPage(self), "historial": HistorialPage(self),
                      "red": NetworkPage(self), "honeypot": HoneypotPage(self),
                      "fantasma": GhostPage(self)}
        for page in self.pages.values():
            self.stack.addWidget(page)
        body.addWidget(self.stack, 1)

        console_host = QWidget()
        cw = QVBoxLayout(console_host)
        cw.setContentsMargins(30, 6, 30, 16)
        cw.setSpacing(0)
        self.console = ConsolePanel()          # expone .log(kind, text) como la antigua consola
        self.activity = self.console.activity  # el indicador global de actividad vive en el panel
        self._activity_spin = self.console.activity_spin
        cw.addWidget(self.console)

        self.vsplit = QSplitter(Qt.Orientation.Vertical)
        self.vsplit.setObjectName("VSplit")
        self.vsplit.setHandleWidth(6)
        self.vsplit.addWidget(body_wrap)
        self.vsplit.addWidget(console_host)
        self.vsplit.setStretchFactor(0, 1)
        self.vsplit.setStretchFactor(1, 0)
        self.vsplit.setCollapsible(0, False)
        self.vsplit.setSizes([760, 170])
        outer.addWidget(self.vsplit, 1)

        # Agarre de redimensionado en la esquina inferior derecha + resize por los 4 bordes.
        grip = QSizeGrip(root)
        grip.setFixedSize(16, 16)
        self._grip = grip
        self._resizer = EdgeResizer(self)
        # El filtro de ratón se instala a nivel de aplicación: se aplaza hasta DESPUÉS de construir la
        # ventana para no pasar por él los miles de eventos del arranque (mantiene el arranque < 300 ms).
        QTimer.singleShot(0, lambda: QApplication.instance().installEventFilter(self._resizer))

        self._select("comando")
        self.console.log("+", f"Lozarus (PySide6) iniciado · {'Administrador' if self.admin else 'usuario estándar'}")
        if self.blackbox is not None:
            self.console.log("+", f"Caja Negra activa · {self.blackbox.path}")
        elif self._blackbox_error:
            self.console.log("x", f"Caja Negra no disponible: {self._blackbox_error}")
        # Restaura el Honeypot si quedó activo en la sesión anterior (persistencia táctica).
        if self.honeypot is not None and self.tactical_config.get("hp_active", False):
            try:
                self.honeypot.deploy()
                self.honeypot.start()
                self.console.log("+", f"Honeypot restaurado (activo) · {self.honeypot.decoy_dir}")
            except Exception as exc:  # noqa: BLE001
                self.console.log("x", f"Honeypot no se pudo restaurar: {exc}")
        self.refresh_sentinel_status()
        self._update_quarantine_ui()
        # Piloto: Auto-Defensa al Iniciar (despliega honeypot + activa vigilancia de puertos).
        if self.tactical_config and self.tactical_config.get("ap_autodefense", False):
            QTimer.singleShot(500, self._autopilot_autodefense)

    def _autopilot_autodefense(self) -> None:
        try:
            hp = getattr(self, "honeypot", None)
            if hp is not None and not hp.active:
                hp.deploy()
                hp.start()
                self.tactical_config.set("hp_active", True)
                self.console.log("+", "Piloto Auto-Defensa: Honeypot desplegado automáticamente")
            net = self.pages.get("red")
            if net and hasattr(net, "watch_btn") and not net.watch_btn.isChecked():
                net.watch_btn.setChecked(True)
                net._toggle_watch()
                self.console.log("+", "Piloto Auto-Defensa: vigilancia de puertos activada")
        except Exception as exc:  # noqa: BLE001
            self.console.log("x", f"Piloto Auto-Defensa: {exc}")

    def _build_sidebar(self) -> QWidget:
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(272)   # holgado: «Endurecimiento de Red» no se recorta en ninguna fuente
        lay = QVBoxLayout(side)
        lay.setContentsMargins(14, 16, 14, 16)
        lay.setSpacing(3)
        self.nav_buttons = {}
        labels = dict(self.NAV)
        for si, (sector, keys) in enumerate(self.NAV_SECTORS):
            cap = QLabel(sector)
            cap.setObjectName("NavTitle")
            if si:
                cap.setStyleSheet("margin-top:12px;")
            lay.addWidget(cap)
            for key in keys:
                btn = NavButton(labels[key], NAV_ICONS.get(key))
                btn.clicked.connect(lambda _=False, k=key: self._select(k))
                self.nav_buttons[key] = btn
                lay.addWidget(btn)
        lay.addStretch(1)
        prot = QLabel("ACCIONES CRÍTICAS")
        prot.setObjectName("NavTitle")
        lay.addWidget(prot)

        # Vanguardia (Modo Centinela): avisos nativos de amenazas nuevas del monitor
        sent_row = QHBoxLayout()
        sent_row.setSpacing(6)
        self.sentinel_btn = QPushButton("Vanguardia")
        self.sentinel_btn.setObjectName("Toggle")
        with_icon(self.sentinel_btn, "fa5s.satellite-dish", COLORS["muted"])
        self.sentinel_btn.setCheckable(True)
        self.sentinel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.sentinel_btn.clicked.connect(self._toggle_sentinel)
        self.sentinel_test = QPushButton("Probar")
        self.sentinel_test.setObjectName("Mini")
        with_icon(self.sentinel_test, "fa5s.bell", COLORS["muted"], 13)
        self.sentinel_test.clicked.connect(self.test_notification)
        sent_row.addWidget(self.sentinel_btn, 1)
        sent_row.addWidget(self.sentinel_test)
        lay.addLayout(sent_row)
        self.sentinel_status = QLabel("")
        self.sentinel_status.setObjectName("Tiny")
        self.sentinel_status.setWordWrap(True)
        lay.addWidget(self.sentinel_status)
        if not HAS_PLYER:
            self.sentinel_btn.setEnabled(False)
            self.sentinel_test.setEnabled(False)

        # Cuarentena Absoluta: aislamiento reversible (firewall + procesos + USB), en QThread
        self.quarantine_btn = HoldButton("CUARENTENA ABSOLUTA")  # mantener pulsado 1,5 s
        with_icon(self.quarantine_btn, "fa5s.shield-virus", COLORS["beacon"])
        self.quarantine_btn.held.connect(self._toggle_quarantine)
        lay.addWidget(self.quarantine_btn)
        self.quarantine_status = QLabel("")
        self.quarantine_status.setObjectName("Tiny")
        self.quarantine_status.setWordWrap(True)
        lay.addWidget(self.quarantine_status)

        self.reset_btn = HoldButton("PROTOCOLO RESET OS")  # mantener pulsado 1,5 s
        with_icon(self.reset_btn, "fa5s.skull-crossbones", COLORS["beacon"])
        self.reset_btn.held.connect(self._reset)
        lay.addWidget(self.reset_btn)
        return side

    def toggle_max_restore(self) -> None:
        if self.isMaximized():
            self.showNormal()
            self.titlebar.max_btn.setText("□")
        else:
            self.showMaximized()
            self.titlebar.max_btn.setText("❐")

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if getattr(self, "_grip", None) is not None:   # grip pegado a la esquina inferior derecha
            self._grip.move(self.width() - self._grip.width() - 3,
                            self.height() - self._grip.height() - 3)
            self._grip.raise_()
        panel = getattr(self, "alert_center", None)
        if panel is not None and panel.isVisible():
            panel.reposition()

    def _select(self, key: str) -> None:
        for name, btn in self.nav_buttons.items():
            btn.set_active(name == key)
        order = [k for k, _ in self.NAV]
        self.stack.setCurrentIndex(order.index(key))
        self._fade_in(self.stack.currentWidget())

    def _fade_in(self, widget) -> None:
        """Transición suave al cambiar de sección: la página nueva aparece con un fundido breve."""
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", widget)
        anim.setDuration(160)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.finished.connect(lambda: widget.setGraphicsEffect(None))  # quita el efecto al acabar
        self._fade_anim = anim  # mantener viva la animación
        anim.start()

    # --- Telemetría y trabajo en segundo plano ---------------------------------------------
    def log_tactical(self, text: str) -> None:
        self.console.log("TACTICAL", text)

    def relaunch_as_admin(self) -> None:
        """Relanza Lozarus con elevación UAC y cierra esta instancia si la elevación arranca."""
        if self.admin:
            self.console.log("~", "Ya se está ejecutando como Administrador.")
            return
        self.log_tactical("Solicitando elevación UAC para relanzar Lozarus")
        ok, msg = request_admin_relaunch()
        if ok:
            self.console.log("+", f"UAC: {msg}")
            self.close()  # cierre limpio (closeEvent detiene bus/caja negra/honeypot)
        else:
            self.console.log("!", f"UAC: {msg}")

    def run_task(self, fn: Callable[[Callable[[str, str], None]], Any],
                 on_done: Callable[[bool, Any], None], track: bool = True) -> None:
        """
        Lanza fn(emit) en un Worker; conecta su log a la consola y entrega el resultado a on_done
        en el hilo de la interfaz. `track=False` para sondeos periódicos (no encienden el indicador
        de actividad). Tras cerrar la ventana no se lanza nada ni se ejecuta ningún callback.
        """
        if self._closing:
            return
        worker = Worker(fn)
        worker.log.connect(self.console.log)

        def finish(ok: bool, payload: Any) -> None:
            if self._closing:
                return  # la ventana se está cerrando: sus widgets pueden no existir ya
            try:
                on_done(ok, payload)
            except Exception as exc:  # noqa: BLE001  (un fallo de la UI no debe perderse en stderr)
                traceback.print_exc()
                self.console.log("x", f"Error interno de la interfaz: {type(exc).__name__}: {exc}")

        worker.done.connect(finish)
        self._launch(worker, track)

    def run_ghost(self, options, term, on_finish: Callable[[], None]) -> None:
        """Ejecuta ghost_mode en segundo plano volcando cada línea a la consola Y a la terminal en vivo."""
        if self._closing:
            return
        worker = Worker(lambda emit: ghost_mode(options, is_admin=self.admin, emit=emit))

        def on_log(kind: str, text: str) -> None:
            self.console.log(kind, text)
            if term is not None:
                term.append(kind, text)

        worker.log.connect(on_log)

        def finish(ok: bool, payload: Any) -> None:
            if self._closing:
                return
            if term is not None:
                term.finish()
            if not ok:
                self.console.log("x", f"Modo Fantasma: {payload}")
            on_finish()

        worker.done.connect(finish)
        self._launch(worker, track=True)

    def _launch(self, worker: QThread, track: bool) -> None:
        """
        Arranca un hilo y lo mantiene referenciado hasta su señal `finished` (el hilo YA ha terminado).
        Liberarlo en `done` —como antes— podía destruir un QThread que aún estaba saliendo de run()
        («QThread: Destroyed while thread is still running»).
        """
        self._workers.append(worker)
        if track:
            self._set_activity(+1)

        def release() -> None:
            if worker in self._workers:
                self._workers.remove(worker)
            if track and not self._closing:
                self._set_activity(-1)

        worker.finished.connect(release)
        worker.start()

    def _set_activity(self, delta: int) -> None:
        self._active_tasks = max(0, self._active_tasks + delta)
        n = self._active_tasks
        if n:
            self.activity.setText(f"{n} tarea{'s' if n != 1 else ''} en segundo plano")
            if self._activity_spin is not None:
                self._activity_spin.start()
            self.activity.show()
        else:
            if self._activity_spin is not None:
                self._activity_spin.stop()
            self.activity.hide()

    # --- Modo Centinela (Vanguardia): avisos nativos de amenazas nuevas --------------------
    def sentinel_check(self, snapshot) -> None:
        """Con cada muestra del monitor: registra las amenazas nuevas (siempre, para que al activar
        el modo no salte lo que ya estaba) y, si está activo, avisa a Windows. notify() ya es
        asíncrono (hilo propio), así que esto no bloquea la interfaz."""
        fresh = self.sentinel.new_threats(snapshot.alerts, set(snapshot.paths))
        # Lista blanca: los procesos marcados de confianza no generan alerta ni aviso.
        fresh = [a for a in fresh if not self.is_process_trusted(a.name)]
        for a in fresh:
            motivo = ", ".join(a.reasons) if getattr(a, "reasons", None) else a.signature
            self.record_alert("!", f"Proceso sospechoso: {a.name} (PID {a.pid}) — {motivo}",
                              module="monitor", process=a.name)
        if fresh and self.sentinel_on and HAS_PLYER:
            severity, message = describe_threats(fresh)
            if notify(severity, message):
                names = ", ".join(a.name for a in fresh[:2]) + (f" y {len(fresh) - 2} más" if len(fresh) > 2 else "")
                self.last_notice = (snapshot.taken, names)
                self.log_tactical(f"Vanguardia: aviso nativo enviado a Windows ({names})")
                self.refresh_sentinel_status()

    def _toggle_sentinel(self) -> None:
        self.sentinel_on = self.sentinel_btn.isChecked()
        monitor = self.pages.get("monitor")
        if self.sentinel_on and monitor is not None and not monitor.running:
            monitor.start()  # sin monitor no hay nada que vigilar
        self.log_tactical(f"Vanguardia (Centinela) {'activada' if self.sentinel_on else 'desactivada'}")
        self.refresh_sentinel_status()

    def test_notification(self) -> None:
        if notify(CRITICAL, "Proceso sospechoso detectado: prueba.exe (PID: 4012)\n"
                            "Motivo: aviso de prueba de Lozarus Kit Tool (simulado)"):
            self.sentinel_status.setText("Aviso de prueba enviado a Windows")
            self.log_tactical("Vanguardia: aviso de prueba enviado a Windows")

    def refresh_sentinel_status(self) -> None:
        monitor = self.pages.get("monitor") if hasattr(self, "pages") else None
        if not HAS_PLYER:
            text = "Instala plyer para activarlo: pip install plyer"
        elif not self.sentinel_on:
            text = "Desactivada: el monitor trabaja en silencio"
        elif monitor is None or not monitor.running:
            text = "Activa, pero el monitor está detenido"
        elif self.last_notice:
            when, names = self.last_notice
            text = f"Último aviso {when:%H:%M:%S}: {names}"
        else:
            text = "Vigilando: avisará de amenazas nuevas"
        self.sentinel_status.setText(text)

    # --- Cuarentena Absoluta (aislamiento reversible, en QThread) --------------------------
    def _toggle_quarantine(self) -> None:
        if not self.admin:
            self.console.log("x", "Cuarentena Absoluta denegada: requiere Administrador")
            self.quarantine_status.setText("Requiere Administrador")
            return
        if quarantine_active():
            self._lift_quarantine()
        else:
            self._apply_quarantine()

    def _apply_quarantine(self) -> None:
        monitor = self.pages.get("monitor")
        flagged = list(monitor.snapshot.alerts) if (monitor and monitor.snapshot) else []
        detail = (f"{len(flagged)} proceso(s) marcado(s) por el monitor" if flagged
                  else "el monitor no ha marcado procesos (se aislará la red y el USB igualmente)")
        if not ConfirmDialog.ask(self, "Activar Cuarentena Absoluta",
                                 "Esto AÍSLA el equipo de inmediato (reversible):\n\n"
                                 "1. Red: bloquea todo el tráfico de salida salvo la LAN.\n"
                                 f"2. Software: congela {detail}.\n"
                                 "3. Hardware: activa el bloqueo de puertos USB.\n\n"
                                 "Podrás revertirlo con «Levantar cuarentena». ¿Continuar?",
                                 confirm_text="Activar cuarentena", danger=True):
            return
        self.quarantine_btn.setEnabled(False)
        self.log_tactical(f"Activando Cuarentena Absoluta · {len(flagged)} proceso(s) marcado(s)")
        self.run_task(lambda emit: apply_quarantine(flagged),
                      lambda ok, p: self._quarantine_done(ok, p, "Cuarentena activada"))

    def _lift_quarantine(self) -> None:
        if not ConfirmDialog.ask(self, "Levantar la cuarentena",
                                 "Se restaurará todo a la normalidad: reanuda los procesos congelados, "
                                 "restaura el Firewall y devuelve el USB a su estado anterior. ¿Continuar?",
                                 confirm_text="Levantar cuarentena"):
            return
        self.quarantine_btn.setEnabled(False)
        self.log_tactical("Levantando la cuarentena y restaurando el equipo")
        self.run_task(lambda emit: lift_quarantine(),
                      lambda ok, p: self._quarantine_done(ok, p, "Cuarentena levantada"))

    def _quarantine_done(self, ok, payload, title) -> None:
        self.quarantine_btn.setEnabled(True)
        self._update_quarantine_ui()
        if ok:
            for step in payload["steps"]:
                self.console.log("*" if step["ok"] else "x", f"{title}: {step['accion']}")
        else:
            self.console.log("x", f"Cuarentena: {payload}")

    def _update_quarantine_ui(self) -> None:
        if quarantine_active():
            self.quarantine_btn.setText("LEVANTAR CUARENTENA")
            with_icon(self.quarantine_btn, "fa5s.unlock", COLORS["accent"])
            self.quarantine_btn.setStyleSheet(
                "QPushButton{background:#1E2633;color:#FAFAFA;border:1px solid #60A5FA;border-radius:8px;"
                "padding:10px 14px;font-weight:bold;font-size:13px;} QPushButton:hover{background:#60A5FA;color:#0B0B0E;}")
            self.quarantine_status.setText("● CUARENTENA ACTIVA")
        else:
            self.quarantine_btn.setText("CUARENTENA ABSOLUTA")
            with_icon(self.quarantine_btn, "fa5s.shield-virus", COLORS["beacon"])
            self.quarantine_btn.setStyleSheet("")  # vuelve al estilo #Warn del QSS
            self.quarantine_status.setText("Aísla el equipo al instante" if self.admin else "Requiere Administrador")

    # --- Protocolo de restablecimiento (herramienta nativa de Windows) ---------------------
    def _reset(self) -> None:
        if not self.admin:
            self.console.log("x", "Protocolo de Restablecimiento: requiere Administrador")
            return
        dlg = ResetConfirmDialog(self, "⚠  Protocolo de Restablecimiento",
                                 "Esto abrirá el asistente NATIVO de restablecimiento de Windows "
                                 "(«Restablecer este PC»). Windows volverá a pedir confirmación y te dejará "
                                 "elegir si conservas o eliminas tus archivos.",
                                 keyword="CONFIRMAR", confirm_text="EJECUTAR")
        if dlg.exec() != QDialog.DialogCode.Accepted:
            self.console.log("~", "Protocolo de Restablecimiento cancelado")
            return
        self.log_tactical("Protocolo de Restablecimiento: abriendo el asistente de Windows")
        self.run_task(lambda emit: factory_reset(emit=emit),
                      lambda ok, p: self.console.log("*" if ok else "x",
                                                     f"Restablecimiento: {'asistente abierto' if ok else p}"))

    # --- Perfiles de operación + lista blanca de procesos ---------------------------------
    def apply_profile(self, mode: str) -> None:
        """Aplica un perfil de operación de 1 clic ajustando ritmos de sondeo y monitores."""
        cmd, mon, net, gh = (self.pages["comando"], self.pages["monitor"],
                             self.pages["red"], self.pages["fantasma"])
        for k, b in cmd.profile_btns.items():
            b.setChecked(k == mode)
        if mode == "rendimiento":
            cmd._timer.setInterval(2000)
            cmd._comp_timer.setInterval(16000)
            if hasattr(mon, "proc_monitor"):
                mon.proc_monitor.set_sampling_floor(5000)   # procesos cada 5 s como mínimo
            self.log_tactical("Perfil Rendimiento: sondeos más lentos y liberación de RAM")
            self.run_task(lambda emit: empty_working_sets(), self._profile_ram_done)
        elif mode == "supervision":
            cmd._timer.setInterval(1000)
            cmd._comp_timer.setInterval(8000)
            if hasattr(mon, "proc_monitor"):
                mon.proc_monitor.set_sampling_floor(0)
            if not net.watch_btn.isChecked():
                net.watch_btn.setChecked(True)
                net._toggle_watch()
            if not gh.clip_watch_btn.isChecked():
                gh.clip_watch_btn.setChecked(True)
                gh._toggle_clip_watch()
            if not mon.running:
                mon.start()
            self.log_tactical("Perfil Supervisión total: vigilancia de red, portapapeles y procesos activada")
        else:  # equilibrado
            cmd._timer.setInterval(1000)
            cmd._comp_timer.setInterval(8000)
            if hasattr(mon, "proc_monitor"):
                mon.proc_monitor.set_sampling_floor(0)
            self.log_tactical("Perfil Equilibrado: sondeos a ritmo normal")

    def _profile_ram_done(self, ok, res) -> None:
        if ok and isinstance(res, dict) and res.get("ok"):
            self.console.log("*", f"RAM: {res['liberado_mb']} MB liberados en {res['procesos']} procesos")
        else:
            self.console.log("x", f"RAM: {res.get('error') if isinstance(res, dict) else res}")

    def trusted_processes(self) -> list:
        if self.tactical_config is None:
            return []
        return self.tactical_config.get(TRUST_KEY, []) or []

    def is_process_trusted(self, name: str) -> bool:
        return is_trusted(name, self.trusted_processes())

    def trust_process(self, name: str) -> None:
        """Añade un proceso a la lista blanca (persistida) para que deje de generar alertas."""
        if self.tactical_config is None:
            self.console.log("!", "Sin persistencia táctica: no se puede guardar la lista blanca.")
            return
        nueva, cambio = add_trusted(name, self.trusted_processes())
        base = os.path.basename(str(name))
        if cambio:
            self.tactical_config.set(TRUST_KEY, nueva)
            self.console.log("*", f"«{base}» añadido a la lista blanca: no volverá a generar alertas.")
        else:
            self.console.log("~", f"«{base}» ya estaba en la lista blanca.")

    # --- Centro de alertas y avisos in-app (se completan en el bloque de alertas) ----------
    def record_alert(self, kind: str, text: str, module: Optional[str] = None,
                     process: Optional[str] = None) -> None:
        """Registra una alerta de la sesión, actualiza el contador de la campana y lanza un toast."""
        entry = {"when": dt.datetime.now(), "kind": kind, "text": text,
                 "module": module, "process": process}
        self.alerts_log.append(entry)
        if getattr(self, "titlebar", None) is not None:
            self.titlebar.set_alert_count(len(self.alerts_log))
        if getattr(self, "alert_center", None) is not None and self.alert_center.isVisible():
            self.alert_center.refresh()
        self._show_toast(entry)

    def toggle_alert_center(self) -> None:
        if self.alert_center is None:
            self.alert_center = AlertCenter(self)
        if self.alert_center.isVisible():
            self.alert_center.hide()
        else:
            self.alert_center.refresh()
            self.alert_center.reposition()
            self.alert_center.show()
            self.alert_center.raise_()

    def _show_toast(self, entry: dict) -> None:
        Toast(self, entry).slide_in()

    WORKER_WAIT_MS = 3000  # tope TOTAL de espera a los hilos en curso al cerrar

    def closeEvent(self, event) -> None:
        """
        Cierre ordenado en pasos AISLADOS (un fallo en uno no impide los siguientes):
          1. marca el cierre: ya no se lanzan tareas ni se ejecutan callbacks sobre widgets;
          2. detiene TODOS los temporizadores de la ventana (antes solo se paraban tres);
          3. para los monitores;
          4. espera, con tope, a los hilos en curso — ANTES de cerrar el bus y la Caja Negra,
             porque esos hilos aún pueden publicar eventos;
          5. honeypot → configuración táctica → Caja Negra (vacía y cierra el JSONL) → bus.
        """
        if self._closing:  # segundo close() (p. ej. tras relanzar con UAC): ya se hizo todo
            super().closeEvent(event)
            return
        self._closing = True
        steps = [
            ("temporizadores", self._stop_all_timers),
            ("monitor", lambda: self.pages["monitor"].stop() if "monitor" in self.pages else None),
            ("hilos en curso", self._wait_workers),
            ("honeypot", lambda: self.honeypot.stop() if self.honeypot is not None else None),
            ("configuración táctica",
             lambda: self.tactical_config.save() if self.tactical_config is not None else None),
            ("Caja Negra", lambda: self.blackbox.stop() if self.blackbox is not None else None),
            ("bus de eventos", lambda: self.bus.stop() if self.bus is not None else None),
        ]
        for name, step in steps:
            try:
                step()
            except Exception:  # noqa: BLE001
                print(f"[cierre] fallo al detener: {name}", file=sys.stderr)
                traceback.print_exc()
        super().closeEvent(event)

    def _stop_all_timers(self) -> None:
        for timer in self.findChildren(QTimer):  # recursivo: páginas, tarjetas, spinners…
            timer.stop()

    def _wait_workers(self) -> None:
        """Espera (con tope total) a los hilos vivos: los de run_task y los propios de las páginas."""
        pending = list(self._workers)
        for page_worker in (getattr(self.pages.get("comando"), "_comp_worker", None),
                            getattr(self.pages.get("auditoria"), "worker", None)):
            if page_worker is not None and page_worker not in pending:
                pending.append(page_worker)
        deadline = time.monotonic() + self.WORKER_WAIT_MS / 1000
        for worker in pending:
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                break
            if worker.isRunning():
                worker.wait(remaining)
        alive = [w for w in pending if w.isRunning()]
        if alive:
            # Se mantienen referenciados: destruir un QThread vivo aborta el proceso (ver main()).
            _ORPHAN_WORKERS.extend(alive)
            print(f"[cierre] {len(alive)} hilo(s) siguen en curso tras {self.WORKER_WAIT_MS} ms",
                  file=sys.stderr)


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    win = MainWindow()
    win.show()
    code = app.exec()
    if any(w.isRunning() for w in _ORPHAN_WORKERS):
        # Algún hilo no terminó a tiempo (p. ej. una auditoría larga). Finalizar el intérprete
        # destruiría un QThread vivo y Qt abortaría el proceso; se sale sin esa finalización. La
        # Caja Negra, el bus y la configuración ya quedaron cerrados en closeEvent.
        os._exit(code)
    sys.exit(code)


if __name__ == "__main__":
    main()
