# -*- coding: utf-8 -*-
"""
Identidad visual de la BETA VISUAL de Lozarus.

Dirección inicial (NO definitiva, pensada para iterar): fondo carbón, superficies diferenciadas,
azul eléctrico + cian como acentos. Todo el color vive aquí; ninguna sección define colores propios.

Regla de accesibilidad del proyecto: **el estado nunca se comunica solo por color**. Cada estado
tiene color + icono + código de texto distintos (ver `STATUS`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from PySide6.QtCore import QSize
from PySide6.QtGui import QIcon

try:
    import qtawesome as qta
    HAS_QTA = True
except Exception:                                  # la beta funciona igual sin iconos vectoriales
    qta = None
    HAS_QTA = False


# ---------------------------------------------------------------------------------------------
# Paleta
# ---------------------------------------------------------------------------------------------
C: Dict[str, str] = {
    # Fondos y superficies (carbón → superficies cada vez más claras)
    "bg": "#070A0F",
    "surface": "#0E131B",
    "surface2": "#141A24",
    "surface3": "#1B2330",
    "border": "#202A38",
    "border_hi": "#2E3B4E",
    # Texto
    "text": "#EEF4FC",
    "text2": "#9DABBE",
    "muted": "#6C7B90",
    "faint": "#4A5768",
    # Acentos: azul eléctrico + cian
    "blue": "#2F80FF",
    "blue_hi": "#5B9DFF",
    "cyan": "#1FD9E8",
    "cyan_hi": "#63E9F4",
    "glow": "#10243F",
    # Semánticos
    "ok": "#2FD27A",
    "warn": "#FFB020",
    "crit": "#FF4D5E",
    "info": "#1FD9E8",
    "demo": "#A96CFF",          # violeta: SIEMPRE significa «dato de demostración»
    "redesign": "#FF7A45",
}


# ---------------------------------------------------------------------------------------------
# Estados de implementación (los 7 estados inequívocos del proyecto)
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Status:
    key: str
    label: str          # texto completo
    code: str           # código corto para etiquetas compactas (no depende del color)
    color: str
    icon: str
    blurb: str          # qué significa exactamente, en una frase


STATUS: Dict[str, Status] = {
    "impl_tested": Status(
        "impl_tested", "Implementado y probado", "PROBADO", C["ok"], "fa5s.check-double",
        "El código existe y tiene pruebas automáticas que pasan."),
    "impl_partial": Status(
        "impl_partial", "Implementado parcialmente", "PARCIAL", C["blue"], "fa5s.adjust",
        "Hay código real funcionando, pero con alcance incompleto y sin pruebas automáticas."),
    "proto_tested": Status(
        "proto_tested", "Prototipo probado", "PROTOTIPO", C["cyan"], "fa5s.flask",
        "Validado en un spike aislado con pruebas; no es código de producción."),
    "designed": Status(
        "designed", "Diseñado, pendiente de implementación", "DISEÑADO", C["muted"],
        "fa5s.drafting-compass",
        "Existe diseño y contrato documentado, pero todavía no hay código."),
    "needs_valid": Status(
        "needs_valid", "Pendiente de validación técnica", "VALIDAR", C["warn"],
        "fa5s.question-circle",
        "No se sabe aún si es viable con los medios previstos; requiere un prototipo que lo decida."),
    "demo_only": Status(
        "demo_only", "Demostración visual", "DEMO", C["demo"], "fa5s.desktop",
        "En esta beta solo existe como maqueta navegable, sin backend detrás."),
    "redesign": Status(
        "redesign", "Rediseño pendiente", "REDISEÑO", C["redesign"], "fa5s.redo-alt",
        "La idea original se descartó o se acotó; necesita rediseñarse antes de implementarse."),
}

STATUS_ORDER = ("impl_tested", "impl_partial", "proto_tested", "designed",
                "needs_valid", "demo_only", "redesign")


# ---------------------------------------------------------------------------------------------
# Iconos
# ---------------------------------------------------------------------------------------------
def icon(name: Optional[str], color: Optional[str] = None) -> QIcon:
    """Icono vectorial. Si qtawesome no está, devuelve un icono vacío y la beta sigue funcionando."""
    if not HAS_QTA or not name:
        return QIcon()
    try:
        return qta.icon(name, color=color or C["blue"])
    except Exception:
        return QIcon()


def with_icon(widget, name: Optional[str], color: Optional[str] = None, size: int = 16):
    """Pone un icono a un botón/acción y devuelve el widget (para encadenar)."""
    widget.setIcon(icon(name, color))
    widget.setIconSize(QSize(size, size))
    return widget


# ---------------------------------------------------------------------------------------------
# Hoja de estilo
# ---------------------------------------------------------------------------------------------
QSS = f"""
* {{ font-family: 'Segoe UI', 'Inter', 'Noto Sans', sans-serif; }}

#Root {{ background-color: {C['bg']}; border: 1px solid {C['border']}; }}
#Content {{ background-color: {C['bg']}; }}

/* ---------- Barra de título ---------- */
#TitleBar {{ background-color: {C['surface']}; border-bottom: 1px solid {C['border']}; }}
#Brand {{ color: {C['text']}; font-size: 18px; font-weight: 700; letter-spacing: 5px; }}
#BrandTag {{ color: {C['cyan']}; font-size: 10px; font-weight: 700; letter-spacing: 2px; }}
#WinBtn {{ background: transparent; color: {C['text2']}; border: none; border-radius: 6px; font-size: 13px; }}
#WinBtn:hover {{ background-color: {C['surface3']}; color: {C['text']}; }}
#WinClose {{ background: transparent; color: {C['text2']}; border: none; border-radius: 6px; font-size: 13px; }}
#WinClose:hover {{ background-color: {C['crit']}; color: {C['bg']}; }}

/* ---------- Barra lateral ---------- */
#Sidebar {{ background-color: {C['surface']}; border-right: 1px solid {C['border']}; }}
#NavTitle {{ color: {C['faint']}; font-size: 10px; font-weight: 700; letter-spacing: 1.5px; }}
#NavBtn {{ background: transparent; color: {C['text2']}; border: none; border-left: 2px solid transparent;
    border-radius: 7px; padding: 9px 12px; text-align: left; font-size: 13px; font-weight: 600; }}
#NavBtn:hover {{ background-color: {C['surface2']}; color: {C['text']}; }}
#NavBtn:checked {{ background-color: {C['glow']}; color: {C['text']}; border-left: 2px solid {C['cyan']}; }}

/* ---------- Cabeceras de sección ---------- */
#PageTitle {{ color: {C['text']}; font-size: 25px; font-weight: 700; }}
#PageSub {{ color: {C['text2']}; font-size: 13px; }}
#PageKicker {{ color: {C['cyan']}; font-size: 10px; font-weight: 700; letter-spacing: 2px; }}
#GroupTitle {{ color: {C['text']}; font-size: 15px; font-weight: 700; }}
#GroupHint {{ color: {C['muted']}; font-size: 11px; }}

/* ---------- Tarjetas ---------- */
#Card {{ background-color: {C['surface']}; border: 1px solid {C['border']}; border-radius: 12px; }}
#Card:hover {{ border: 1px solid {C['border_hi']}; }}
#CardAccent {{ background-color: {C['surface']}; border: 1px solid {C['border_hi']}; border-radius: 12px; }}
#CardTitle {{ color: {C['text']}; font-size: 14px; font-weight: 700; }}
#CardText {{ color: {C['text2']}; font-size: 12px; }}
#CardMeta {{ color: {C['muted']}; font-size: 11px; }}
#Metric {{ color: {C['text']}; font-size: 28px; font-weight: 700; }}
#MetricUnit {{ color: {C['muted']}; font-size: 12px; font-weight: 600; }}
#MetricCap {{ color: {C['text2']}; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}

/* ---------- Botones ---------- */
QPushButton {{ background: transparent; color: {C['blue_hi']}; border: 1px solid {C['border_hi']};
    border-radius: 9px; padding: 9px 16px; font-weight: 600; font-size: 13px; }}
QPushButton:hover {{ background-color: {C['glow']}; border-color: {C['blue']}; color: {C['text']}; }}
QPushButton:disabled {{ color: {C['faint']}; border-color: {C['border']}; }}
QPushButton#Primary {{ background-color: {C['blue']}; color: #FFFFFF; border: 1px solid {C['blue']}; }}
QPushButton#Primary:hover {{ background-color: {C['blue_hi']}; border-color: {C['blue_hi']}; }}
QPushButton#Primary:disabled {{ background-color: {C['surface3']}; color: {C['faint']}; border-color: {C['border']}; }}
QPushButton#Cyan {{ background-color: {C['cyan']}; color: #04222A; border: 1px solid {C['cyan']}; }}
QPushButton#Cyan:hover {{ background-color: {C['cyan_hi']}; border-color: {C['cyan_hi']}; }}
QPushButton#Ghost {{ color: {C['text2']}; border-color: {C['border']}; }}
QPushButton#Ghost:hover {{ background-color: {C['surface2']}; color: {C['text']}; }}
QPushButton#Mini {{ color: {C['text2']}; border-color: {C['border']}; padding: 6px 11px; font-size: 11px; }}
QPushButton#Mini:hover {{ background-color: {C['surface3']}; color: {C['text']}; }}
QPushButton#Filter {{ color: {C['text2']}; border-color: {C['border']}; padding: 6px 12px; font-size: 11px;
    font-weight: 600; border-radius: 13px; }}
QPushButton#Filter:hover {{ background-color: {C['surface3']}; color: {C['text']}; }}
QPushButton#Filter:checked {{ background-color: {C['glow']}; color: {C['text']}; border-color: {C['cyan']}; }}
QPushButton#Link {{ border: none; color: {C['cyan']}; padding: 2px 0; text-align: left; font-size: 12px; }}
QPushButton#Link:hover {{ color: {C['cyan_hi']}; }}

/* ---------- Entradas ---------- */
QLineEdit {{ background-color: {C['bg']}; border: 1px solid {C['border']}; border-radius: 9px;
    padding: 8px 11px; color: {C['text']}; font-size: 13px; }}
QLineEdit:focus {{ border-color: {C['cyan']}; }}
QComboBox {{ background-color: {C['bg']}; border: 1px solid {C['border']}; border-radius: 9px;
    padding: 7px 11px; color: {C['text']}; font-size: 12px; }}
QComboBox:hover {{ border-color: {C['border_hi']}; }}
QComboBox QAbstractItemView {{ background-color: {C['surface2']}; color: {C['text']};
    selection-background-color: {C['glow']}; border: 1px solid {C['border_hi']}; outline: none; }}

/* ---------- Tablas y listas ---------- */
QTableWidget {{ background-color: {C['surface']}; alternate-background-color: {C['surface2']};
    border: none; gridline-color: transparent; color: {C['text2']}; font-size: 12px; }}
QTableWidget::item {{ padding: 7px; color: {C['text']}; }}
QTableWidget::item:selected {{ background-color: {C['glow']}; color: {C['text']}; }}
QHeaderView::section {{ background-color: {C['surface']}; color: {C['muted']}; border: none;
    border-bottom: 1px solid {C['border']}; padding: 8px; font-size: 10px; font-weight: 700;
    letter-spacing: 1px; }}
QTreeWidget {{ background-color: {C['surface']}; border: none; color: {C['text2']}; font-size: 12px;
    outline: none; }}
QTreeWidget::item {{ padding: 5px; color: {C['text']}; }}
QTreeWidget::item:selected {{ background-color: {C['glow']}; color: {C['text']}; }}

/* ---------- Pestañas ---------- */
QTabWidget::pane {{ border: 1px solid {C['border']}; border-radius: 11px; top: -1px; }}
QTabBar::tab {{ background: {C['surface']}; color: {C['text2']}; padding: 8px 18px;
    border: 1px solid {C['border']}; border-bottom: none; border-top-left-radius: 10px;
    border-top-right-radius: 10px; font-size: 12px; font-weight: 600; }}
QTabBar::tab:selected {{ background: {C['glow']}; color: {C['text']}; }}

/* ---------- Progreso y barras ---------- */
QProgressBar {{ background-color: {C['surface3']}; border: none; border-radius: 4px; max-height: 7px;
    text-align: center; color: transparent; }}
QProgressBar::chunk {{ background-color: {C['blue']}; border-radius: 4px; }}

/* ---------- Consola de demostración ---------- */
#Console {{ background-color: {C['bg']}; border: 1px solid {C['border']}; border-radius: 10px;
    color: {C['text2']}; font-family: 'Cascadia Mono', 'Consolas', monospace; font-size: 11px; }}
#ConsoleTitle {{ color: {C['muted']}; font-size: 10px; font-weight: 700; letter-spacing: 1.5px; }}

/* ---------- Diálogos ---------- */
#Dialog {{ background-color: {C['surface']}; border: 1px solid {C['border_hi']}; border-radius: 14px; }}
#DialogTitle {{ color: {C['text']}; font-size: 17px; font-weight: 700; }}
#DialogBody {{ color: {C['text2']}; font-size: 13px; }}

/* ---------- Varios ---------- */
#Sep {{ background-color: {C['border']}; }}
#Tiny {{ color: {C['muted']}; font-size: 10px; }}
#Mono {{ color: {C['text2']}; font-family: 'Cascadia Mono', 'Consolas', monospace; font-size: 11px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {C['border_hi']}; border-radius: 5px; min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: {C['muted']}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {C['border_hi']}; border-radius: 5px; min-width: 28px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollArea {{ border: none; background: transparent; }}
QToolTip {{ background-color: {C['surface3']}; color: {C['text']}; border: 1px solid {C['border_hi']};
    padding: 6px; border-radius: 6px; font-size: 12px; }}
"""
