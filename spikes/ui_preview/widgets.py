# -*- coding: utf-8 -*-
"""
Componentes visuales reutilizables de la beta. Ninguno toca el sistema: solo pintan.

Convención importante: `StatusTag` y `DemoBadge` llevan SIEMPRE icono + texto además del color, para
que el estado se entienda sin depender de distinguir colores.
"""

from __future__ import annotations

from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QDialog, QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel,
                               QPushButton, QScrollArea, QSizePolicy, QVBoxLayout, QWidget)

from theme import C, STATUS, icon, with_icon


# =============================================================================================
# Básicos
# =============================================================================================
def hline(parent: Optional[QWidget] = None) -> QFrame:
    line = QFrame(parent)
    line.setObjectName("Sep")
    line.setFixedHeight(1)
    return line


def label(text: str, obj: str = "CardText", wrap: bool = True) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName(obj)
    lab.setWordWrap(wrap)
    return lab


def vbox(widget: QWidget, margin: int = 16, spacing: int = 10) -> QVBoxLayout:
    lay = QVBoxLayout(widget)
    lay.setContentsMargins(margin, margin, margin, margin)
    lay.setSpacing(spacing)
    return lay


class Card(QFrame):
    """Tarjeta base (Bento). `title` e `icon_name` son opcionales."""

    def __init__(self, title: str = "", icon_name: str = "", accent: bool = False,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("CardAccent" if accent else "Card")
        self.body = vbox(self)
        if title:
            head = QHBoxLayout()
            head.setSpacing(8)
            if icon_name:
                ico = QLabel()
                ico.setPixmap(icon(icon_name, C["cyan"]).pixmap(16, 16))
                head.addWidget(ico)
            head.addWidget(label(title, "CardTitle", wrap=False))
            head.addStretch(1)
            self.head = head
            self.body.addLayout(head)
        else:
            self.head = None

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        self.body.addLayout(layout)

    def add_text(self, text: str, obj: str = "CardText") -> QLabel:
        return self.add(label(text, obj))


class StatusTag(QFrame):
    """Etiqueta de estado: color + icono + CÓDIGO DE TEXTO (nunca solo color)."""

    def __init__(self, status_key: str, compact: bool = False, parent: Optional[QWidget] = None):
        super().__init__(parent)
        st = STATUS[status_key]
        self.setToolTip(f"{st.label} — {st.blurb}")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 3, 9, 3)
        lay.setSpacing(6)
        ico = QLabel()
        ico.setPixmap(icon(st.icon, st.color).pixmap(12, 12))
        lay.addWidget(ico)
        text = st.code if compact else st.label
        lab = QLabel(text)
        lab.setStyleSheet(f"color:{st.color}; font-size:10px; font-weight:700; letter-spacing:0.5px;")
        lay.addWidget(lab)
        self.setStyleSheet(
            f"StatusTag {{ background-color: {C['surface2']}; border:1px solid {st.color};"
            f" border-radius: 10px; }}")
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)


class DemoBadge(QFrame):
    """Marca inequívoca de dato simulado. Violeta + icono + palabra «DEMO»."""

    def __init__(self, text: str = "DATO DE DEMOSTRACIÓN", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setToolTip("Dato simulado para esta beta. No procede de ninguna observación real.")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 3, 9, 3)
        lay.setSpacing(6)
        ico = QLabel()
        ico.setPixmap(icon("fa5s.desktop", C["demo"]).pixmap(11, 11))
        lay.addWidget(ico)
        lab = QLabel(text)
        lab.setStyleSheet(f"color:{C['demo']}; font-size:10px; font-weight:700; letter-spacing:1px;")
        lay.addWidget(lab)
        self.setStyleSheet(f"DemoBadge {{ background-color: #1A1226; border:1px solid {C['demo']};"
                           f" border-radius: 10px; }}")
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)


class Chip(QFrame):
    """Etiqueta neutra para metadatos (dependencias, áreas, privilegios)."""

    def __init__(self, text: str, color: Optional[str] = None, icon_name: str = "",
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        col = color or C["text2"]
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 3, 9, 3)
        lay.setSpacing(5)
        if icon_name:
            ico = QLabel()
            ico.setPixmap(icon(icon_name, col).pixmap(11, 11))
            lay.addWidget(ico)
        lab = QLabel(text)
        lab.setStyleSheet(f"color:{col}; font-size:10px; font-weight:600;")
        lay.addWidget(lab)
        self.setStyleSheet(f"Chip {{ background-color:{C['surface2']}; border:1px solid {C['border']};"
                           f" border-radius: 9px; }}")
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)


def chip_row(items: Sequence[Tuple[str, Optional[str], str]], spacing: int = 6) -> QHBoxLayout:
    """Fila de chips: cada item es (texto, color|None, icono|'')."""
    row = QHBoxLayout()
    row.setSpacing(spacing)
    for text, color, ico in items:
        row.addWidget(Chip(text, color, ico))
    row.addStretch(1)
    return row


# =============================================================================================
# Indicadores
# =============================================================================================
class Gauge(QWidget):
    """Indicador circular. `value=None` significa DESCONOCIDO y se dibuja como «—», nunca como 0."""

    def __init__(self, caption: str = "", color: Optional[str] = None, size: int = 104,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._value: Optional[float] = None
        self._caption = caption
        self._color = QColor(color or C["blue"])
        self.setFixedSize(size, size)

    def set_value(self, value: Optional[float]) -> None:
        self._value = value
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height())
        pad = 9.0
        rect = QRectF(pad, pad, side - 2 * pad, side - 2 * pad)

        p.setPen(QPen(QColor(C["surface3"]), 8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(rect, 225 * 16, -270 * 16)

        if self._value is not None:
            frac = max(0.0, min(1.0, self._value / 100.0))
            p.setPen(QPen(self._color, 8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawArc(rect, 225 * 16, int(-270 * 16 * frac))

        p.setPen(QColor(C["text"] if self._value is not None else C["muted"]))
        f = QFont()
        f.setPointSize(15)
        f.setBold(True)
        p.setFont(f)
        text = "—" if self._value is None else f"{self._value:.0f}%"
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)

        if self._caption:
            p.setPen(QColor(C["muted"]))
            f2 = QFont()
            f2.setPointSize(7)
            f2.setBold(True)
            p.setFont(f2)
            p.drawText(QRectF(0, side - 15, side, 13), Qt.AlignmentFlag.AlignCenter, self._caption)
        p.end()


class Sparkline(QWidget):
    """Mini gráfico de línea. Sin datos → línea base y aviso «sin datos»."""

    def __init__(self, color: Optional[str] = None, height: int = 44, capacity: int = 60,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._points: List[float] = []
        self._color = QColor(color or C["cyan"])
        self._capacity = capacity
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def push(self, value: Optional[float]) -> None:
        if value is None:
            return
        self._points.append(float(value))
        if len(self._points) > self._capacity:
            self._points.pop(0)
        self.update()

    def set_points(self, points: Iterable[float]) -> None:
        self._points = list(points)[-self._capacity:]
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        if len(self._points) < 2:
            p.setPen(QColor(C["faint"]))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "sin datos suficientes")
            p.end()
            return
        lo, hi = min(self._points), max(self._points)
        span = (hi - lo) or 1.0
        step = w / (len(self._points) - 1)
        path = QPainterPath()
        pts = []
        for i, val in enumerate(self._points):
            x = i * step
            y = h - 4 - ((val - lo) / span) * (h - 10)
            pts.append(QPointF(x, y))
        path.moveTo(pts[0])
        for pt in pts[1:]:
            path.lineTo(pt)
        p.setPen(QPen(self._color, 1.8))
        p.drawPath(path)
        fill = QPainterPath(path)
        fill.lineTo(QPointF(w, h))
        fill.lineTo(QPointF(0, h))
        fill.closeSubpath()
        col = QColor(self._color)
        col.setAlpha(34)
        p.fillPath(fill, col)
        p.end()


class MetricCard(Card):
    """Tarjeta de métrica grande: valor + unidad + pie. Soporta valor desconocido («—»)."""

    def __init__(self, caption: str, unit: str = "", icon_name: str = "",
                 color: Optional[str] = None, parent: Optional[QWidget] = None):
        super().__init__(parent=parent)
        self.body.setSpacing(4)
        top = QHBoxLayout()
        top.setSpacing(7)
        if icon_name:
            ico = QLabel()
            ico.setPixmap(icon(icon_name, color or C["cyan"]).pixmap(13, 13))
            top.addWidget(ico)
        top.addWidget(label(caption.upper(), "MetricCap", wrap=False))
        top.addStretch(1)
        self.body.addLayout(top)

        row = QHBoxLayout()
        row.setSpacing(4)
        self.value = label("—", "Metric", wrap=False)
        if color:
            self.value.setStyleSheet(f"color:{color}; font-size:28px; font-weight:700;")
        row.addWidget(self.value)
        if unit:
            u = label(unit, "MetricUnit", wrap=False)
            u.setAlignment(Qt.AlignmentFlag.AlignBottom)
            row.addWidget(u)
        row.addStretch(1)
        self.body.addLayout(row)
        self.foot = label("", "CardMeta")
        self.body.addWidget(self.foot)

    def set_value(self, value: Optional[object], foot: str = "") -> None:
        self.value.setText("—" if value is None else str(value))
        if foot:
            self.foot.setText(foot)


class BarRow(QWidget):
    """Fila «etiqueta — barra — valor», para repartos (estados, categorías)."""

    def __init__(self, text: str, value: int, total: int, color: str,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._frac = (value / total) if total else 0.0
        self._color = QColor(color)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 3, 0, 3)
        lay.setSpacing(10)
        name = label(text, "CardText")           # con ajuste de línea: las etiquetas largas no se cortan
        name.setMinimumWidth(150)
        lay.addWidget(name, 1)
        self.bar = _Bar(self._frac, self._color)
        self.bar.setMinimumWidth(56)
        lay.addWidget(self.bar)
        val = label(str(value), "CardTitle", wrap=False)
        val.setFixedWidth(26)
        val.setAlignment(Qt.AlignmentFlag.AlignRight)
        lay.addWidget(val)


class _Bar(QWidget):
    def __init__(self, frac: float, color: QColor, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._frac = frac
        self._color = color
        self.setFixedHeight(8)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(C["surface3"]))
        p.drawRoundedRect(QRectF(0, 0, self.width(), 8), 4, 4)
        if self._frac > 0:
            p.setBrush(self._color)
            p.drawRoundedRect(QRectF(0, 0, max(8.0, self.width() * self._frac), 8), 4, 4)
        p.end()


# =============================================================================================
# Diagrama de flujo (arquitectura)
# =============================================================================================
class FlowDiagram(QWidget):
    """
    Cadena horizontal de bloques conectados por flechas: sirve para enseñar la arquitectura
    (sensor → bus → detección → interfaz) con el color del ESTADO de cada pieza.
    """

    def __init__(self, nodes: Sequence[Tuple[str, str, str]], parent: Optional[QWidget] = None):
        # nodes: (título, subtítulo, clave de estado)
        super().__init__(parent)
        self._nodes = list(nodes)
        self.setMinimumHeight(104)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setToolTip("El color del borde indica el estado de implementación de cada pieza.")

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        n = len(self._nodes)
        if not n:
            p.end()
            return
        gap = 26.0
        total_gap = gap * (n - 1)
        bw = max(96.0, (self.width() - total_gap - 8) / n)
        bh = 66.0
        y = (self.height() - bh) / 2

        for i, (title, sub, status_key) in enumerate(self._nodes):
            x = 4 + i * (bw + gap)
            col = QColor(STATUS[status_key].color)
            rect = QRectF(x, y, bw, bh)
            p.setPen(QPen(col, 1.4))
            p.setBrush(QColor(C["surface2"]))
            p.drawRoundedRect(rect, 10, 10)

            p.setPen(QColor(C["text"]))
            f = QFont()
            f.setPointSize(8)
            f.setBold(True)
            p.setFont(f)
            p.drawText(QRectF(x + 6, y + 9, bw - 12, 16),
                       Qt.AlignmentFlag.AlignCenter, title)

            p.setPen(QColor(C["muted"]))
            f2 = QFont()
            f2.setPointSize(7)
            p.setFont(f2)
            p.drawText(QRectF(x + 6, y + 26, bw - 12, 26),
                       Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap,
                       sub)

            p.setPen(QColor(col))
            f3 = QFont()
            f3.setPointSize(6)
            f3.setBold(True)
            p.setFont(f3)
            p.drawText(QRectF(x + 6, y + bh - 17, bw - 12, 12),
                       Qt.AlignmentFlag.AlignCenter, STATUS[status_key].code)

            if i < n - 1:
                ax0 = x + bw + 5
                ax1 = x + bw + gap - 5
                ay = y + bh / 2
                p.setPen(QPen(QColor(C["border_hi"]), 1.4))
                p.drawLine(QPointF(ax0, ay), QPointF(ax1, ay))
                head = QPainterPath()
                head.moveTo(QPointF(ax1, ay))
                head.lineTo(QPointF(ax1 - 5, ay - 3.5))
                head.lineTo(QPointF(ax1 - 5, ay + 3.5))
                head.closeSubpath()
                p.setBrush(QColor(C["border_hi"]))
                p.setPen(Qt.PenStyle.NoPen)
                p.drawPath(head)
        p.end()


# =============================================================================================
# Listas, cronologías y filas
# =============================================================================================
def bullet_list(items: Sequence[str], icon_name: str = "fa5s.circle",
                color: Optional[str] = None) -> QWidget:
    box = QWidget()
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(7)
    for text in items:
        row = QHBoxLayout()
        row.setSpacing(9)
        ico = QLabel()
        ico.setPixmap(icon(icon_name, color or C["cyan"]).pixmap(10, 10))
        ico.setAlignment(Qt.AlignmentFlag.AlignTop)
        ico.setFixedWidth(13)
        row.addWidget(ico)
        row.addWidget(label(text, "CardText"), 1)
        lay.addLayout(row)
    return box


class KeyValue(QWidget):
    """Fila clave → valor, con la clave atenuada."""

    def __init__(self, key: str, value: str, value_color: Optional[str] = None,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 2, 0, 2)
        lay.setSpacing(12)
        k = label(key, "CardMeta", wrap=False)
        k.setMinimumWidth(128)
        k.setAlignment(Qt.AlignmentFlag.AlignTop)
        lay.addWidget(k)
        v = label(value, "CardText")
        if value_color:
            v.setStyleSheet(f"color:{value_color}; font-size:12px;")
        lay.addWidget(v, 1)


class TimelineView(QWidget):
    """Cronología vertical con marcador de hora, severidad y texto."""

    def __init__(self, entries: Sequence[Tuple[str, str, str, str]],
                 parent: Optional[QWidget] = None):
        # entries: (hora, título, detalle, color)
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        for i, (when, title, detail, color) in enumerate(entries):
            lay.addWidget(_TimelineRow(when, title, detail, color, last=(i == len(entries) - 1)))


class _TimelineRow(QWidget):
    def __init__(self, when: str, title: str, detail: str, color: str, last: bool,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._color = QColor(color)
        self._last = last
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        stamp = label(when, "Mono", wrap=False)
        stamp.setFixedWidth(62)
        stamp.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        stamp.setContentsMargins(0, 10, 0, 0)
        lay.addWidget(stamp)
        lay.addSpacing(18)                      # carril del marcador, pintado en paintEvent
        text = QWidget()
        tl = QVBoxLayout(text)
        tl.setContentsMargins(0, 7, 0, 13)
        tl.setSpacing(2)
        head = label(title, "CardTitle")
        head.setStyleSheet(f"color:{color}; font-size:13px; font-weight:700;")
        tl.addWidget(head)
        tl.addWidget(label(detail, "CardText"))
        lay.addWidget(text, 1)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        x = 62 + 9
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(self._color)
        p.drawEllipse(QPointF(x, 14), 4.0, 4.0)
        if not self._last:
            p.setPen(QPen(QColor(C["border"]), 1.2))
            p.drawLine(QPointF(x, 20), QPointF(x, self.height()))
        p.end()


# =============================================================================================
# Diálogo e interacciones
# =============================================================================================
class InfoDialog(QDialog):
    """Diálogo explicativo. Solo informa; nunca ejecuta nada."""

    def __init__(self, title: str, body: str, bullets: Sequence[str] = (),
                 note: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setObjectName("Dialog")
        self.setMinimumWidth(520)
        lay = vbox(self, 22, 13)
        lay.addWidget(label(title, "DialogTitle"))
        lay.addWidget(label(body, "DialogBody"))
        if bullets:
            lay.addWidget(bullet_list(list(bullets), "fa5s.angle-right"))
        if note:
            box = QFrame()
            box.setStyleSheet(f"QFrame {{ background-color:{C['surface2']};"
                              f" border:1px solid {C['border_hi']}; border-radius:9px; }}")
            bl = vbox(box, 12, 5)
            bl.addWidget(label(note, "CardMeta"))
            lay.addWidget(box)
        row = QHBoxLayout()
        row.addStretch(1)
        close = QPushButton("Entendido")
        close.setObjectName("Primary")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        lay.addLayout(row)


class ClickableCard(Card):
    """Tarjeta que reacciona al clic (con realce suave al pasar el ratón)."""

    clicked = Signal()

    def __init__(self, title: str = "", icon_name: str = "", parent: Optional[QWidget] = None):
        super().__init__(title, icon_name, parent=parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._fx = QGraphicsOpacityEffect(self)
        self._fx.setOpacity(1.0)
        self.setGraphicsEffect(self._fx)

    def enterEvent(self, event) -> None:
        self._fx.setOpacity(0.86)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._fx.setOpacity(1.0)
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


def scroll_area(inner: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setWidget(inner)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    return area


def action_button(text: str, icon_name: str = "", obj: str = "", color: Optional[str] = None,
                  on_click: Optional[Callable[[], None]] = None) -> QPushButton:
    btn = QPushButton(text)
    if obj:
        btn.setObjectName(obj)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    if icon_name:
        with_icon(btn, icon_name, color or C["cyan"], 14)
    if on_click:
        btn.clicked.connect(on_click)
    return btn


def clear_layout(layout) -> None:
    """
    Vacía un layout de verdad.

    Ojo: `deleteLater()` por sí solo NO basta — la destrucción es diferida y el widget sigue
    pintándose encima del contenido nuevo hasta que el bucle de eventos la procesa. Hay que
    desvincularlo del padre en el momento (`setParent(None)`).
    """
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
        elif item.layout() is not None:
            clear_layout(item.layout())
            item.layout().deleteLater()


def grid(columns: int = 3, spacing: int = 14):
    """Devuelve (widget, añadir) para colocar tarjetas en rejilla simple por filas."""
    from PySide6.QtWidgets import QGridLayout
    host = QWidget()
    lay = QGridLayout(host)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    state = {"i": 0}

    def add(widget: QWidget, span: int = 1) -> QWidget:
        row, col = divmod(state["i"], columns)
        lay.addWidget(widget, row, col, 1, span)
        state["i"] += span
        return widget

    return host, add


__all__ = ["Card", "StatusTag", "DemoBadge", "Chip", "chip_row", "Gauge", "Sparkline", "MetricCard",
           "BarRow", "FlowDiagram", "bullet_list", "KeyValue", "TimelineView", "InfoDialog",
           "ClickableCard", "scroll_area", "action_button", "grid", "hline", "label", "vbox",
           "clear_layout"]
