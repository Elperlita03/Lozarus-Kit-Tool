"""
ui/theme.py · LOZARUS KIT TOOL

Identidad visual de Lozarus: paleta, hoja de estilo QSS, iconos del menú y estilos de estado.
"""

from __future__ import annotations

import os
import tempfile

from modulos._base import CRITICAL, INFO, PASS, SKIP, WARNING


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
