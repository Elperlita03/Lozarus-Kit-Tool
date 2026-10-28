"""
ui/chrome.py · LOZARUS KIT TOOL

Marco de la ventana principal: barra de título, consola de telemetría, avisos (Toast),
centro de alertas y redimensionado de los bordes de la ventana sin marco.
"""

from __future__ import annotations

import datetime as dt
import html
import os
from collections import deque
from typing import Optional

from PySide6.QtCore import QEvent, QObject, QPointF, QRect, QRectF, QSize, QTimer, Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QIcon, QLinearGradient, QPainter, QPixmap
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QMainWindow, QPlainTextEdit,
                               QPushButton, QScrollArea, QVBoxLayout, QWidget)

from ui._compat import HAS_QTA, qta
from ui.theme import COLORS, GLASS, ICON_PATH, LOGO_PATH
from ui.widgets import apply_aura, icon, with_icon


def _logo_pixmap(height: int) -> Optional[QPixmap]:
    """assets/logo.png escalado (nítido en pantallas HiDPI) a la altura dada; None si no hay logo."""
    if not os.path.isfile(LOGO_PATH):
        return None
    pix = QPixmap(LOGO_PATH)
    if pix.isNull():
        return None
    dpr = QGuiApplication.instance().devicePixelRatio() if QGuiApplication.instance() else 1.0
    pix = pix.scaledToHeight(round(height * dpr), Qt.TransformationMode.SmoothTransformation)
    pix.setDevicePixelRatio(dpr)
    return pix


def _cosmic_icon(name: str, size: int) -> Optional[QPixmap]:
    """
    Icono de qtawesome teñido con el degradado azul eléctrico → violeta del tema. Se pinta UNA sola
    vez al crear la barra (QPainter en modo SourceIn): ningún coste por fotograma.
    """
    base = icon(name, "#FFFFFF").pixmap(size, size)
    if base.isNull():
        return None
    out = QPixmap(base.size())
    out.setDevicePixelRatio(base.devicePixelRatio())
    out.fill(Qt.GlobalColor.transparent)
    area = QRectF(QPointF(0, 0), base.deviceIndependentSize())
    grad = QLinearGradient(area.topLeft(), area.bottomRight())
    grad.setColorAt(0.0, QColor(COLORS["accent"]))
    grad.setColorAt(1.0, QColor(COLORS["accent_2"]))
    p = QPainter(out)
    p.drawPixmap(0, 0, base)
    p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    p.fillRect(area, grad)
    p.end()
    return out


def app_icon() -> QIcon:
    """
    Icono de la ventana y de la barra de tareas: assets/logo.png si existe; si no, el .ico de la
    marca; y si tampoco, el meteorito de la cabecera en varios tamaños (16-256 px).
    """
    for path in (LOGO_PATH, ICON_PATH):
        if os.path.isfile(path):
            candidate = QIcon(path)
            if not candidate.isNull():
                return candidate
    fallback = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pix = _cosmic_icon("fa5s.meteor", size)
        if pix is not None:
            fallback.addPixmap(pix)
    return fallback


class TitleBar(QFrame):
    """
    Barra de título propia (la ventana es sin marco): marca, campana de alertas y botones de
    ventana. La marca usa assets/logo.png si existe; si es un logotipo apaisado (ya trae el nombre)
    va solo, y si es un símbolo va seguido del nombre. Sin logo: meteorito de qtawesome con el
    degradado del tema + «LOZARUS | KIT TOOL».
    """

    def __init__(self, window: QMainWindow):
        super().__init__()
        self.setObjectName("TitleBar")
        self.setFixedHeight(54)
        self.win = window
        self._drag = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(20, 0, 10, 0)
        lay.setSpacing(12)
        logo = _logo_pixmap(30)
        mark = QLabel()
        mark.setObjectName("BrandMark")
        mark.setPixmap(logo if logo is not None else (_cosmic_icon("fa5s.meteor", 24) or QPixmap()))
        mark.setVisible(not mark.pixmap().isNull())
        lay.addWidget(mark)
        if logo is None or logo.width() < logo.height() * 1.6:  # sin logotipo con nombre: wordmark
            brand = QLabel("LOZARUS")
            brand.setObjectName("Brand")
            divider = QFrame()
            divider.setObjectName("BrandDivider")
            divider.setFixedSize(1, 16)
            sub = QLabel("KIT TOOL")
            sub.setObjectName("BrandSub")
            for w in (brand, divider, sub):
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


class TelemetryConsole(QPlainTextEdit):
    """
    Consola de telemetría corporativa (SOC): solo lectura, monoespaciada, con marca de tiempo tenue,
    etiqueta de sistema coloreada por tipo (azul hielo para [+]/[TACTICAL]) y mensaje en blanco hueso;
    el rojo se reserva para errores/alertas críticas. Auto-scroll al final.
    """
    KIND = {"+": COLORS["accent"], "~": COLORS["text2"], "*": COLORS["ok"], "!": COLORS["warn"],
            "x": COLORS["danger"], "TACTICAL": COLORS["accent"]}

    def __init__(self):
        super().__init__()
        self.setObjectName("Console")
        self.setReadOnly(True)
        self.setMaximumBlockCount(600)
        self.setFont(QFont("Consolas", 10))

    def log(self, kind: str, text: str) -> None:
        tag = self.KIND.get(kind, COLORS["text2"])
        msg = COLORS["danger"] if kind == "x" else COLORS["text"]  # rojo solo para errores/alertas críticas
        when = dt.datetime.now().strftime("%H:%M:%S")
        safe = html.escape(text.rstrip())
        self.appendHtml(f'<span style="color:{COLORS["muted"]}">[{when}]</span> '
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


class Toast(QFrame):
    """
    Aviso in-app no intrusivo: una tarjeta que aparece abajo a la derecha, se apila con las demás,
    se auto-descarta a los ~7 s y ofrece acciones rápidas (Ir al módulo / Confiar / Descartar). No
    bloquea nada: el evento ya está en la consola y en la Caja Negra; esto es solo un recordatorio.
    `entry` admite `title` e `icon` opcionales (por defecto, «Alerta de seguridad»).
    """
    KIND_COLOR = {"!": COLORS["warn"], "x": COLORS["danger"], "*": COLORS["ok"], "~": COLORS["accent"],
                  "+": COLORS["accent"]}
    _active: list = []
    LIFE_MS = 7000

    def __init__(self, win, entry: dict):
        super().__init__(win)
        self.win = win
        self.entry = entry
        self.setObjectName("Toast")
        color = self.KIND_COLOR.get(entry.get("kind"), COLORS["accent"])
        self.setStyleSheet(f"#Toast {{ background: rgba(5, 5, 5, 0.96); border:1px solid {GLASS['border']};"
                           f" border-left:3px solid {color}; border-radius:12px; }}")
        apply_aura(self)  # flota sobre el contenido: el resplandor la separa del fondo negro
        self.setFixedWidth(348)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 12, 12)
        lay.setSpacing(8)
        top = QHBoxLayout()
        top.setSpacing(8)
        ic = QLabel()
        ic.setPixmap(icon(entry.get("icon") or "fa5s.exclamation-circle", color).pixmap(16, 16))
        head = QLabel(entry.get("title") or "Alerta de seguridad")
        head.setStyleSheet(f"color:{color}; font-weight:700; font-size:10pt; letter-spacing:0.3px;")
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
        body.setStyleSheet(f"color:{COLORS['text']}; font-size:10pt;")
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

    @classmethod
    def notify(cls, win, kind: str, title: str, text: str, icon_name: Optional[str] = None) -> "Toast":
        """Aviso del resultado de una acción (no entra en el Centro de Alertas: no es un incidente)."""
        toast = cls(win, {"when": dt.datetime.now(), "kind": kind, "title": title, "text": text,
                          "icon": icon_name})
        toast.slide_in()
        return toast

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
        self.setStyleSheet(f"#AlertCenter {{ background: rgba(5, 5, 5, 0.97); border:1px solid {GLASS['border']};"
                           " border-radius:14px; }")
        apply_aura(self)  # panel flotante bajo demanda: solo se repinta al abrirlo o desplazarlo
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
        color = Toast.KIND_COLOR.get(entry.get("kind"), COLORS["accent"])
        row = QFrame()
        row.setObjectName("AlertRow")  # con selector: el estilo no se hereda a las etiquetas internas
        row.setStyleSheet(f"#AlertRow {{ background: {COLORS['card']}; border:1px solid {GLASS['border']};"
                          " border-radius:9px; }")
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
        text.setStyleSheet(f"color:{COLORS['text']}; font-size:10pt;")
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
