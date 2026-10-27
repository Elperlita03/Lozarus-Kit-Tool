"""
ui/theme.py · LOZARUS KIT TOOL

Identidad visual de Lozarus: paleta, hoja de estilo QSS, iconos del menú y estilos de estado.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from string import Template

from PySide6.QtGui import QFont

from modulos._base import CRITICAL, INFO, PASS, SKIP, WARNING


APP_NAME = "LOZARUS KIT TOOL"

SEVERITY_COLORS = {CRITICAL: "#F87171", WARNING: "#F5B544", PASS: "#4ADE80", INFO: "#E5E5E5", SKIP: "#8A8A8A"}

SEVERITY_ORDER = (CRITICAL, WARNING, PASS, INFO, SKIP)

# Paleta «Black & White Aura»: negro absoluto / gris vacío de fondo, blanco puro en texto y acentos.
# Sin azules ni violetas; rojo, ámbar y verde quedan SOLO para estados de seguridad (con texto).
# Solo HEX: el código los usa con QColor (border/border_hi = blanco al 20 % / 36 % sobre negro).
COLORS = {
    "bg": "#000000", "bg_glow": "#050505", "sidebar": "#000000", "panel": "#050505", "panel2": "#050505",
    "panel_alt": "#141414", "card": "#0A0A0A", "border": "#333333", "border_hi": "#5C5C5C",
    "text": "#FFFFFF", "text2": "#BDBDBD", "muted": "#8A8A8A", "faint": "#555555", "disabled": "#3A3A3A",
    "accent": "#FFFFFF", "accent_hover": "#D4D4D4", "accent_2": "#A3A3A3", "accent_soft": "#1A1A1A",
    "beacon": "#F87171", "terminal": "#4ADE80",
    "ok": "#4ADE80", "warn": "#F5B544", "danger": "#F87171", "info": "#E5E5E5",
}

# Tipografía corporativa: pila sans-serif del sistema (Windows → Linux/Android → macOS) a 10 pt y
# monoespaciada para consola, terminal y campos técnicos. La base se fija con base_font() en la
# QApplication (así los setFont() de cada widget siguen valiendo); el QSS solo ajusta jerarquías.
FONT_FAMILIES = ["Segoe UI Variable Text", "Segoe UI", "Roboto", "SF Pro Text", ".AppleSystemUIFont",
                 "Helvetica Neue", "Inter", "Arial"]
MONO_FAMILIES = ["Cascadia Mono", "Consolas", "JetBrains Mono", "SF Mono", "Menlo", "DejaVu Sans Mono"]
BASE_PT = 10


def base_font() -> QFont:
    """Fuente base de la aplicación (QApplication.setFont)."""
    font = QFont()
    font.setFamilies(FONT_FAMILIES)
    font.setPointSize(BASE_PT)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    return font


def _css_families(families) -> str:
    return ", ".join(f"'{f}'" for f in families)


MONO_CSS = _css_families(MONO_FAMILIES) + ", monospace"  # para font-family en estilos en línea

# Superficies de «cristal» (rgba, para QSS y estilos en línea; no valen para QColor).
GLASS = {
    "card": "rgba(255, 255, 255, 0.03)",        # tarjetas: un velo blanco casi invisible sobre negro
    "card_hi": "rgba(255, 255, 255, 0.06)",
    "inset": "rgba(0, 0, 0, 0.6)",              # baldosas hundidas dentro de una tarjeta
    "selected": "rgba(255, 255, 255, 0.10)",    # elemento seleccionado
    "border": "rgba(255, 255, 255, 0.2)",       # borde fino sobre el que destaca el aura
    "border_hi": "rgba(255, 255, 255, 0.36)",
}

# Tokens SOLO para el QSS (admiten rgba() y degradados). Todo el «cristal» es QSS estático:
# QLinearGradient + transparencias, sin temporizadores ni animaciones (coste de CPU nulo en reposo).
_QSS_TOKENS = {
    **COLORS,
    "border": GLASS["border"],                  # en el QSS, bordes blancos translúcidos de verdad
    "border_hi": GLASS["border_hi"],
    "line": "rgba(255, 255, 255, 0.45)",        # contorno de los botones
    "glass": GLASS["card"],
    "glass_hi": GLASS["card_hi"],
    "inset": GLASS["inset"],
    "field": "rgba(255, 255, 255, 0.02)",       # campos de texto y consola
    "tint": "rgba(255, 255, 255, 0.08)",        # hover
    "tint_hi": "rgba(255, 255, 255, 0.14)",     # selección / pulsado
    "select": "rgba(255, 255, 255, 0.85)",      # selección de texto (con texto negro encima)
    "grad_root": "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #000000, stop:1 #050505)",
    "grad_head": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #050505, stop:0.5 #000000, stop:1 #050505)",
    "grad_side": "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #050505, stop:1 #000000)",
    "grad_dialog": "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0A0A0A, stop:1 #000000)",
    "grad_accent": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FFFFFF, stop:1 #A3A3A3)",
    "grad_primary": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255, 255, 255, 0.12), "
                    "stop:1 rgba(255, 255, 255, 0.05))",
    "grad_primary_hi": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255, 255, 255, 0.22), "
                       "stop:1 rgba(255, 255, 255, 0.10))",
    "mono": MONO_CSS,
}

# Hoja de estilo (QSS) «Black & White Aura». Plantilla con ${token} (string.Template): los valores
# salen de COLORS / _QSS_TOKENS, así que cambiar el tema es cambiar la paleta, no 150 líneas.
QSS = Template("""
#Root { background: ${grad_root}; border: 1px solid ${border}; }
#TitleBar { background: ${grad_head}; border-bottom: 1px solid ${border}; }
#Brand { color: ${text}; font-size: 13pt; font-weight: 800; letter-spacing: 5px; }
#BrandSub { color: ${accent_2}; font-size: 8pt; font-weight: 700; letter-spacing: 3px; }
#BrandDivider { background: ${border_hi}; }
#WinBtn { background: transparent; color: ${text2}; border: none; padding: 0; font-size: 14px; border-radius: 6px; }
#WinBtn:hover { background-color: ${glass_hi}; color: ${text}; }
#WinClose { background: transparent; color: ${text2}; border: none; padding: 0; font-size: 14px; border-radius: 6px; }
#WinClose:hover { background-color: ${danger}; color: ${bg}; }
#Sidebar { background: ${grad_side}; border-right: 1px solid ${border}; }
#NavTitle { color: ${faint}; font-size: 8pt; font-weight: 700; letter-spacing: 1.5px; }
#Content { background: transparent; }
#PageTitle { color: ${text}; font-size: 17pt; font-weight: 700; letter-spacing: 0.4px; }
#PageSub { color: ${text2}; font-size: 10pt; }
#Card { background-color: ${glass}; border: 1px solid ${border}; border-radius: 14px; }
#Card:hover { border-color: ${border_hi}; }
#CardTitle { color: ${text}; font-size: 11pt; font-weight: 700; letter-spacing: 0.5px; }
#CardText { color: ${text2}; font-size: 10pt; }
/* Baldosas hundidas dentro de una tarjeta (componentes, paneles del Piloto Automático) */
#Inset, #CompCard, #CompRow { background-color: ${inset}; border: 1px solid ${border}; border-radius: 10px; }
#Inset:hover, #CompCard:hover, #CompRow:hover { border-color: ${border_hi}; }
/* Interruptor (QCheckBox#Switch): pista y mando son SVG estáticos, sin animación ni repintado extra */
QCheckBox#Switch { color: ${text}; font-size: 10pt; font-weight: 600; spacing: 10px; }
QCheckBox#Switch:disabled { color: ${disabled}; }
QCheckBox#Switch::indicator { width: 36px; height: 20px; image: url("__SWITCH_OFF__"); }
QCheckBox#Switch::indicator:hover { image: url("__SWITCH_OFF_HOVER__"); }
QCheckBox#Switch::indicator:checked, QCheckBox#Switch::indicator:checked:hover { image: url("__SWITCH_ON__"); }
QCheckBox#Switch::indicator:disabled { image: url("__SWITCH_DISABLED__"); }
#Value { color: ${text}; font-size: 12pt; font-weight: 700; }

/* Botones: contorno + tinte translúcido. Hover y pulsado suben el tinte un escalón (sin destellos). */
QPushButton { background: transparent; color: ${accent}; border: 1px solid ${line};
    border-radius: 9px; padding: 9px 16px; font-weight: 600; font-size: 10pt; }
QPushButton:hover { background: ${tint}; border-color: ${accent}; color: ${accent_hover}; }
QPushButton:disabled { color: ${disabled}; border-color: ${border}; background: transparent; }
QPushButton#Primary { background: ${grad_primary}; color: #FFFFFF; border: 1px solid rgba(255, 255, 255, 0.7); }
QPushButton#Primary:hover { background: ${grad_primary_hi}; border-color: #FFFFFF; color: #FFFFFF; }
QPushButton#Primary:disabled { background: transparent; color: ${disabled}; border-color: ${border}; }
QPushButton#Ghost { color: ${text2}; border-color: ${border}; }
QPushButton#Ghost:hover { background: rgba(255, 255, 255, 0.04); color: ${text}; border-color: ${border_hi}; }
QPushButton#Danger { color: ${danger}; border-color: rgba(248, 113, 113, 0.45); }
QPushButton#Danger:hover { background: rgba(248, 113, 113, 0.12); border-color: ${danger}; color: #FCA5A5; }
QPushButton#Danger:disabled { color: #5A2A2A; border-color: #2E1A1A; background: transparent; }
/* Botones de advertencia del menú: rojo suave sobre cristal (hold-to-execute) */
QPushButton#Warn { background-color: rgba(248, 113, 113, 0.06); color: ${danger};
    border: 1px solid rgba(248, 113, 113, 0.45); border-radius: 9px; padding: 10px 14px; font-weight: 700;
    font-size: 10pt; letter-spacing: 0.5px; }
QPushButton#Warn:hover { background-color: rgba(248, 113, 113, 0.14); border-color: ${danger}; color: #FCA5A5; }
QPushButton#Warn:disabled { color: #5A2A2A; border-color: #2E1A1A; }
QPushButton#Mini { color: ${text2}; border-color: ${border}; padding: 8px 10px; font-size: 9pt; }
QPushButton#Mini:hover { background: rgba(255, 255, 255, 0.04); color: ${text}; border-color: ${border_hi}; }
QPushButton#Toggle { background: ${glass}; color: ${text2}; border: 1px solid ${border}; border-radius: 9px;
    padding: 8px; font-size: 10pt; font-weight: 600; text-align: left; }
QPushButton#Toggle:hover { border-color: ${border_hi}; color: ${text}; }
QPushButton#Toggle:checked { background: ${grad_primary}; color: ${text}; border-color: rgba(255, 255, 255, 0.7); }
/* Pulsado: respuesta táctil inmediata. Va DESPUÉS de los :hover (misma especificidad → gana). */
QPushButton:pressed, QPushButton#Primary:pressed { background: ${tint_hi}; border-color: ${accent}; color: #FFFFFF; }
QPushButton#Ghost:pressed, QPushButton#Mini:pressed { background: rgba(255, 255, 255, 0.08);
    border-color: ${faint}; color: ${text}; }
QPushButton#Danger:pressed { background: rgba(248, 113, 113, 0.22); border-color: ${danger}; color: #FFFFFF; }
QPushButton#Toggle:pressed { background: ${glass_hi}; }
/* Deshabilitado: un selector con ID (#Ghost…) pesa más que QPushButton:disabled, así que cada
   variante necesita su propia regla o el botón PARECERÍA activo estando deshabilitado. */
QPushButton#Ghost:disabled, QPushButton#Mini:disabled { color: ${disabled}; border-color: ${border}; background: transparent; }
QPushButton#Toggle:disabled { color: ${disabled}; border-color: ${border}; background: ${field}; }
QPushButton:focus { outline: none; }
/* Ocupado (set_busy): deshabilitado pero con texto en acento = «trabajando», no «no disponible».
   Una regla por variante: el ID de cada tipo pesa más que la propiedad sola. */
QPushButton[busy="true"]:disabled, QPushButton#Primary[busy="true"]:disabled,
QPushButton#Ghost[busy="true"]:disabled, QPushButton#Mini[busy="true"]:disabled,
QPushButton#Danger[busy="true"]:disabled, QPushButton#Toggle[busy="true"]:disabled {
    color: ${accent_hover}; border-color: ${border_hi}; background: ${tint}; }
/* Indicador global de actividad (junto a la consola): no es clicable ni cambia al pasar el ratón. */
QPushButton#Activity, QPushButton#Activity:hover, QPushButton#Activity:pressed { background: transparent;
    border: none; color: ${accent}; padding: 0 2px; font-size: 9pt; font-weight: 600; text-align: right; }

#Dialog { background: ${grad_dialog}; }
#DialogTitle { color: ${text}; font-size: 14pt; font-weight: 700; letter-spacing: 0.3px; }
#DialogBody { color: ${text2}; font-size: 10pt; }
#DialogHint { color: ${danger}; font-size: 9pt; font-weight: 700; }
QLineEdit { background-color: ${field}; border: 1px solid ${border}; border-radius: 9px;
    padding: 8px 10px; color: ${text}; font-family: ${mono}; font-size: 10pt;
    selection-background-color: ${select}; selection-color: #000000; }
QLineEdit:hover { border-color: ${border_hi}; }
QLineEdit:focus { border-color: ${accent}; }
QLineEdit:disabled { color: ${disabled}; }
/* Desplegables con el mismo lenguaje que los campos de texto (antes salían en blanco nativo). */
QComboBox { background-color: ${field}; border: 1px solid ${border}; border-radius: 9px;
    padding: 7px 28px 7px 10px; color: ${text}; font-size: 10pt; min-width: 70px; }
QComboBox:hover { border-color: ${border_hi}; }
QComboBox:focus, QComboBox:on { border-color: ${accent}; }
QComboBox:disabled { color: ${disabled}; border-color: ${border}; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: center right; width: 24px;
    border: none; }
QComboBox::down-arrow { image: url("__ARROW_DOWN__"); width: 10px; height: 10px; }
QComboBox QAbstractItemView { background-color: ${card}; border: 1px solid ${border_hi}; color: ${text};
    selection-background-color: ${tint_hi}; selection-color: #FFFFFF; outline: 0; padding: 4px; }
/* Ventanas emergentes (tooltip, menús): son ventanas propias, así que van opacas. */
QToolTip { background-color: ${card}; color: ${text}; border: 1px solid ${border_hi}; padding: 6px 8px;
    border-radius: 6px; font-size: 9pt; }
QMenu { background-color: ${card}; border: 1px solid ${border_hi}; padding: 6px; color: ${text}; }
QMenu::item { padding: 6px 18px 6px 10px; border-radius: 6px; }
QMenu::item:selected { background: ${tint_hi}; }
QMenu::item:disabled { color: ${faint}; }
QMenu::separator { height: 1px; background: ${border}; margin: 4px 6px; }
QPlainTextEdit { font-family: ${mono}; }
#Console { background-color: ${field}; border: 1px solid ${border}; border-radius: 10px; color: ${text};
    padding: 4px; selection-background-color: ${select}; selection-color: #000000; }
#ConsoleTitle { color: ${text2}; font-size: 8pt; font-weight: 700; letter-spacing: 1.2px; }
#StatusOk { color: ${ok}; font-weight: 700; }
#StatusWarn { color: ${warn}; font-weight: 700; }
#StatusMuted { color: ${text2}; }
QScrollArea#Content { background: transparent; border: none; }
QScrollBar:vertical { background: transparent; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: ${border}; border-radius: 4px; min-height: 24px; }
QScrollBar:horizontal { background: transparent; height: 8px; margin: 0; }
QScrollBar::handle:horizontal { background: ${border}; border-radius: 4px; min-width: 24px; }
QScrollBar::handle:hover { background: ${border_hi}; }
QScrollBar::handle:pressed { background: ${faint}; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
/* Tablas: transparentes sobre el cristal, filas de alto fijo (make_table), sin rejilla ni foco. */
QTableWidget { background-color: transparent; alternate-background-color: rgba(255, 255, 255, 0.022);
    border: none; gridline-color: transparent; color: ${text2}; font-size: 10pt; outline: 0;
    selection-background-color: ${tint_hi}; }
QTableWidget::item { padding: 0 8px; color: ${text}; border: none; }
QTableWidget::item:selected { background-color: ${tint_hi}; color: #FFFFFF; }
QHeaderView { background-color: transparent; border: none; }
QHeaderView::section { background-color: rgba(255, 255, 255, 0.04); color: ${text2}; border: none;
    border-bottom: 1px solid ${border}; padding: 8px 8px; font-size: 9pt; font-weight: 700; letter-spacing: 0.8px;
    font-variant: small-caps; }
QHeaderView::section:hover { color: ${text}; }
QTableCornerButton::section { background-color: transparent; border: none; }
QTabWidget::pane { border: 1px solid ${border}; border-radius: 12px; top: -1px; background: ${glass}; }
QTabBar::tab { background: transparent; color: ${text2}; padding: 9px 18px; border: 1px solid transparent;
    border-bottom: 2px solid transparent; border-top-left-radius: 9px; border-top-right-radius: 9px;
    font-size: 10pt; font-weight: 600; margin-right: 4px; }
QTabBar::tab:hover:!selected { color: ${text}; background: rgba(255, 255, 255, 0.03); }
QTabBar::tab:selected { background: ${glass_hi}; color: #FFFFFF; border-color: ${border};
    border-bottom: 2px solid ${accent}; }
QProgressBar { background-color: ${border}; border: none; border-radius: 3px; max-height: 6px;
    text-align: center; color: transparent; }
QProgressBar::chunk { background: ${grad_accent}; border-radius: 3px; }
#Chip { background-color: ${glass}; border: 1px solid ${border}; border-radius: 12px; }
#Chip:hover { border-color: ${border_hi}; }
#ChipCap { color: ${text2}; font-size: 8pt; font-weight: 700; letter-spacing: 1px; }
#ChipVal { color: ${text}; font-size: 15pt; font-weight: 700; }
#Detail { background-color: ${field}; border: 1px solid ${border}; border-radius: 10px; color: ${text2};
    font-size: 10pt; padding: 6px; }
QLabel#Tiny { color: ${text2}; font-size: 9pt; }
/* Campana de alertas de la cabecera */
#AlertBell { background: transparent; border: none; color: ${muted}; font-size: 9pt; font-weight: 700;
    padding: 0 8px; border-radius: 6px; }
#AlertBell:hover { color: ${text}; background: ${glass_hi}; }
/* Chips de filtro de la consola */
QPushButton#Chiplet { background: transparent; color: ${muted}; border: 1px solid ${border}; border-radius: 10px;
    padding: 3px 11px; font-size: 8pt; font-weight: 700; letter-spacing: 0.6px; }
QPushButton#Chiplet:hover { color: ${text}; border-color: ${border_hi}; }
QPushButton#Chiplet:checked { background: ${tint_hi}; color: #FFFFFF; border-color: rgba(255, 255, 255, 0.7); }
QPushButton#ToastClose { background: transparent; border: none; color: ${muted}; font-size: 13px; }
QPushButton#ToastClose:hover { color: ${text}; }
#ConsoleWrap { background: transparent; }
QSplitter#VSplit::handle:vertical { background: transparent; }
QSplitter#VSplit::handle:vertical:hover { background: ${border}; }
QSizeGrip { background: transparent; }
/* Mini-botón de acceso «→» en cada tarjeta del panel de salud */
QPushButton#CompGo { background: transparent; border: 1px solid ${border}; border-radius: 11px;
    color: ${muted}; font-size: 13px; font-weight: bold; padding: 0; }
QPushButton#CompGo:hover { border-color: ${accent}; color: ${accent}; background: ${tint}; }
""").substitute(_QSS_TOKENS)


def _ui_asset(name: str, svg: str) -> str:
    """
    Escribe UNA vez un pequeño SVG de interfaz en la carpeta temporal y devuelve su ruta con «/»
    (formato de url() en QSS). El QSS no admite dibujar un chevron con bordes de forma fiable. Si no
    se puede escribir, devuelve "" y el widget simplemente se queda sin imagen (no rompe nada). El
    nombre lleva un hash del contenido: si cambia el tema, no se reutiliza un SVG antiguo en caché.
    """
    folder = os.path.join(tempfile.gettempdir(), "lozarus_ui")
    stem, ext = os.path.splitext(name)
    path = os.path.join(folder, f"{stem}-{hashlib.sha1(svg.encode('utf-8')).hexdigest()[:8]}{ext}")
    try:
        if not os.path.isfile(path):
            os.makedirs(folder, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(svg)
    except OSError:
        return ""
    return path.replace("\\", "/")


def _switch_svg(on: bool, track: str, stroke: str, knob: str) -> str:
    """Interruptor 36×20: pista redondeada (degradado del acento si está activo) y mando circular."""
    fill = "url(#g)" if on else track
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="36" height="20" viewBox="0 0 36 20">'
            '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="0">'
            f'<stop offset="0" stop-color="{COLORS["accent"]}"/><stop offset="1" stop-color="{COLORS["accent_2"]}"/>'
            '</linearGradient></defs>'
            f'<rect x="0.5" y="0.5" width="35" height="19" rx="9.5" fill="{fill}" stroke="{stroke}"/>'
            f'<circle cx="{26 if on else 10}" cy="10" r="6.5" fill="{knob}"/></svg>')


for _token, _name, _svg in (
        ("__ARROW_DOWN__", "chevron-down.svg",
         '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 10 10">'
         f'<path d="M1.5 3.5 L5 7 L8.5 3.5" fill="none" stroke="{COLORS["text2"]}" stroke-width="1.6" '
         'stroke-linecap="round" stroke-linejoin="round"/></svg>'),
        ("__SWITCH_OFF__", "switch-off.svg", _switch_svg(False, COLORS["card"], COLORS["border_hi"], COLORS["muted"])),
        ("__SWITCH_OFF_HOVER__", "switch-off-hover.svg",
         _switch_svg(False, COLORS["card"], COLORS["accent"], COLORS["text2"])),
        ("__SWITCH_ON__", "switch-on.svg", _switch_svg(True, "", COLORS["accent"], COLORS["bg"])),
        ("__SWITCH_DISABLED__", "switch-disabled.svg",
         _switch_svg(False, COLORS["panel"], COLORS["border"], COLORS["disabled"]))):
    QSS = QSS.replace(_token, _ui_asset(_name, _svg))

# Logo opcional de la barra de título (si no existe, chrome.TitleBar usa un icono de qtawesome).
LOGO_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "logo.png")


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
    ST_OK:       (COLORS["ok"], "OPERATIVO"),
    ST_DEGRADED: (COLORS["warn"], "DEGRADADO"),
    ST_ALERT:    (COLORS["danger"], "ALERTA"),
    ST_STOPPED:  (COLORS["muted"], "DETENIDO"),
    ST_NOIMPL:   (COLORS["faint"], "NO IMPLEMENTADO"),
}


def badge_qss(color: str, size: int = 10) -> str:
    """Estilo de «píldora» semántica: texto del color del estado sobre un tinte suave del mismo."""
    r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
    return (f"color:{color}; background: rgba({r},{g},{b},0.11); border: 1px solid rgba({r},{g},{b},0.32);"
            f" border-radius: 9px; padding: 2px 9px; font-size:{size}px; font-weight:bold;"
            f" letter-spacing:0.8px;")
