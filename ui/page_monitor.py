"""
ui/page_monitor.py · LOZARUS KIT TOOL

Página MONITOR EN VIVO: conexiones de red y tablero de procesos sospechosos en tiempo real, con
controles directos sobre los procesos (menú contextual «Navaja Suiza»: finalizar, suspender,
reanudar y confiar).
"""

from __future__ import annotations

import datetime as dt
import os
import socket
from collections import deque
from typing import TYPE_CHECKING

import psutil
from PySide6.QtCore import Property, QEasingCurve, QPointF, QPropertyAnimation, QTimer, Qt
from PySide6.QtGui import QBrush, QColor, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton,
                               QScrollArea, QTabWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from modulos._base import CRITICAL
from modulos._forense import forensic_report
from modulos import _procmon  # muestreo de procesos para el Monitor en Vivo
from modulos._monitor import LiveMonitor
from modulos._tacticas import launch_in_sandbox, sandbox_available

from ui._compat import Event, ObservationQuality
from ui.theme import COLORS, SEVERITY_COLORS
from ui.widgets import (Page, _emit_event, format_bytes, frozen, icon, make_table, repolish, set_busy,
                        stat_chip, with_icon)
from ui.dialogs import ConfirmDialog
from ui.chrome import Toast

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow


def proc_key(alert) -> str:
    """Identidad estable de un proceso marcado (PID + instante de creación)."""
    return f"{alert.pid}:{int(getattr(alert, 'created', 0) * 1000)}"


# ===========================================================================
# NAVAJA SUIZA: controles REALES (psutil) sobre un proceso, desde el menú contextual
# ===========================================================================
# Procesos cuyo cierre o congelación tumba Windows (pantallazo azul) o deja el escritorio sin
# pintar: el menú no los ofrece aunque Lozarus corra como Administrador. Se comparan por nombre.
PROTECTED_PROCS = frozenset({"system", "secure system", "registry", "memory compression", "smss.exe",
                             "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
                             "dwm.exe"})
# acción -> (texto del menú, icono, color, infinitivo y participio para los mensajes)
PROC_ACTIONS = {
    "terminate": ("Finalizar tarea", "fa5s.times-circle", "#EF4444", "finalizar", "finalizado"),
    "suspend": ("Suspender", "fa5s.pause-circle", "#F59E0B", "suspender", "suspendido"),
    "resume": ("Reanudar", "fa5s.play-circle", "#22C55E", "reanudar", "reanudado"),
    "trust": ("Confiar (lista blanca)", "fa5s.user-check", "#60A5FA", "confiar en", "de confianza"),
}
# En Windows cada suspensión se acumula (hay que reanudar tantas veces como se suspendió): se
# recuerda qué procesos suspendió Lozarus para no ofrecer «Suspender» dos veces seguidas.
_SUSPENDED: set = set()  # (pid, create_time)
MENU_QSS = (f"QMenu {{ background:{COLORS['card']}; border:1px solid {COLORS['border']}; border-radius:8px;"
            f" padding:6px; color:{COLORS['text']}; }}"
            "QMenu::item { padding:6px 18px 6px 8px; border-radius:6px; }"
            f"QMenu::item:selected {{ background:{COLORS['accent_soft']}; }}"
            f"QMenu::item:disabled {{ color:{COLORS['faint']}; }}"
            f"QMenu::separator {{ height:1px; background:{COLORS['border']}; margin:4px 6px; }}")


def _toast(app, kind: str, title: str, text: str, icon_name: str) -> None:
    """Aviso in-app del resultado (no entra en el Centro de Alertas: lo ha pedido el usuario)."""
    Toast(app, {"when": dt.datetime.now(), "kind": kind, "title": title, "text": text,
                "icon": icon_name}).slide_in()


def _identity(proc) -> tuple:
    try:
        return proc.pid, proc.create_time()
    except psutil.Error:
        return proc.pid, None


def _same_process(proc, name, created) -> bool:
    """Evita actuar sobre un PID reutilizado: compara nombre e instante de creación con la muestra."""
    try:
        if created and abs(proc.create_time() - created) > 1.0:
            return False
        return not name or proc.name().lower() == name.lower()
    except psutil.AccessDenied:
        return True  # sin permiso para leerlo; psutil vuelve a validar la identidad al actuar


def _report(app, action: str, pid: int, name, ok: bool, title: str, text: str, icon_name: str) -> bool:
    """Deja el resultado en la consola, en la Caja Negra (vía bus) y en un Toast. Devuelve ok."""
    app.console.log("*" if ok else "x", f"{PROC_ACTIONS[action][0]}: {text}")
    _emit_event(app, source="monitor:control", event_type=f"process.{action}",
                payload={"pid": pid, "name": name, "ok": ok, "detail": text}, process_id=pid)
    _toast(app, "*" if ok else "x", title, text, icon_name)
    return ok


def _control_process(app, proc, action: str, name) -> bool:
    """Finaliza, suspende o reanuda el proceso con psutil. Devuelve True si se aplicó."""
    text, _icon, _color, infinitive, participle = PROC_ACTIONS[action]
    label = f"«{name or '?'}» (PID {proc.pid})"
    if action == "terminate" and not ConfirmDialog.ask(
            app, "Finalizar tarea", f"Se cerrará {label} de inmediato: perderá el trabajo que no haya "
            "guardado y no se puede deshacer. ¿Continuar?", confirm_text="Finalizar tarea", danger=True):
        return False
    key = _identity(proc)
    app.log_tactical(f"{text}: {label}")
    try:
        {"terminate": proc.terminate, "suspend": proc.suspend, "resume": proc.resume}[action]()
    except psutil.AccessDenied:
        if getattr(app, "admin", False):
            title, hint = "Acceso denegado", "Windows protege este proceso incluso frente a un Administrador."
        else:
            title, hint = "Se requiere elevación", "Ejecuta Lozarus como Administrador y vuelve a intentarlo."
        return _report(app, action, proc.pid, name, False, title,
                       f"Acceso denegado al {infinitive} {label}. {hint}", "fa5s.user-shield")
    except psutil.NoSuchProcess:  # incluye ZombieProcess y el PID reutilizado (psutil lo detecta)
        _SUSPENDED.discard(key)
        return _report(app, action, proc.pid, name, False, "Proceso no encontrado",
                       f"{label} ya no existe.", "fa5s.exclamation-triangle")
    except (psutil.Error, OSError) as exc:
        return _report(app, action, proc.pid, name, False, "Acción no aplicada",
                       f"No se pudo {infinitive} {label}: {exc}", "fa5s.exclamation-triangle")
    if action == "suspend":
        _SUSPENDED.add(key)
    else:
        _SUSPENDED.discard(key)
    return _report(app, action, proc.pid, name, True, text, f"{label} {participle}.", "fa5s.check-circle")


def _trust_process(app, pid: int, name: str) -> bool:
    """Lista blanca por NOMBRE de ejecutable: MainWindow.trust_process aplica add_trusted
    (modulos._listablanca) y la persiste; el monitor y el Centinela dejan de alertar por él."""
    app.trust_process(name)
    if not app.is_process_trusted(name):
        return _report(app, "trust", pid, name, False, "Lista blanca no disponible",
                       f"Sin persistencia táctica: no se pudo guardar «{name}».", "fa5s.database")
    return _report(app, "trust", pid, name, True, "Añadido a la lista blanca",
                   f"«{name}» no volverá a generar alertas del monitor.", "fa5s.user-check")


def process_menu(app, parent, global_pos, pid, name=None, *, status=None, created=None,
                 on_done=None) -> None:
    """
    Menú contextual «Navaja Suiza» sobre un proceso: Finalizar tarea (con confirmación),
    Suspender, Reanudar y Confiar. Acciones REALES con psutil; el resultado o el motivo del fallo
    (p. ej. falta de elevación) se avisa con un Toast. Lozarus y los procesos críticos de Windows
    no se pueden finalizar ni suspender. `on_done` se llama tras una acción aplicada.
    """
    if pid is None:
        return
    try:
        proc = psutil.Process(pid)
        same = _same_process(proc, name, created)
    except psutil.NoSuchProcess:
        _toast(app, "x", "Proceso no encontrado", f"«{name or '?'}» (PID {pid}) ya no existe.",
               "fa5s.exclamation-triangle")
        return
    except (psutil.Error, OSError) as exc:
        _toast(app, "x", "Control de procesos", f"No se pudo abrir el PID {pid}: {exc}",
               "fa5s.exclamation-triangle")
        return
    if not same:
        _toast(app, "!", "Control de procesos", f"El PID {pid} ya pertenece a otro proceso; espera a la "
               "siguiente muestra.", "fa5s.exclamation-triangle")
        return

    own = pid == os.getpid()
    protected = own or pid in (0, 4) or (name or "").lower() in PROTECTED_PROCS
    menu = QMenu(parent)
    menu.setStyleSheet(MENU_QSS)
    menu.setToolTipsVisible(True)
    head = menu.addAction(f"{name or 'Proceso'}  ·  PID {pid}")
    head.setEnabled(False)
    menu.addSeparator()
    acts = {}
    for key, (text, icon_name, color, _inf, _part) in PROC_ACTIONS.items():
        if key == "trust":
            menu.addSeparator()
        acts[key] = menu.addAction(icon(icon_name, color, COLORS["faint"]), text)

    def block(key, why):
        acts[key].setEnabled(False)
        acts[key].setToolTip(why)

    if protected:
        why = ("Es el propio Lozarus." if own else
               "Proceso crítico de Windows: cerrarlo o congelarlo tumba el sistema.")
        for key in ("terminate", "suspend", "resume") if own else ("terminate", "suspend"):
            block(key, why)
    elif status == psutil.STATUS_STOPPED or _identity(proc) in _SUSPENDED:
        block("suspend", "Ya está suspendido: usa «Reanudar».")
    if not name:
        block("trust", "Nombre de ejecutable no accesible.")
    elif app.is_process_trusted(name):
        block("trust", "Ya está en la lista blanca.")

    chosen = menu.exec(global_pos)
    key = next((k for k, a in acts.items() if a is chosen), None)
    if key is None:
        return
    done = _trust_process(app, pid, name) if key == "trust" else _control_process(app, proc, key, name)
    if done and on_done is not None:
        on_done()


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

    def __init__(self, on_select, on_menu=None):
        super().__init__()
        self.setObjectName("ProcCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._on_select = on_select
        self._on_menu = on_menu  # clic derecho: menú «Navaja Suiza» sobre el proceso
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

    def contextMenuEvent(self, event):
        if self.alert is not None and self._on_menu is not None:
            self._on_menu(self.alert, event.globalPos())

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

    def __init__(self, on_select, on_menu=None):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet("background: transparent;")
        self.on_select = on_select
        self.on_menu = on_menu
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
                card = ProcCard(self._select_from_card, self._menu_from_card)
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

    def _menu_from_card(self, alert, global_pos):
        self._select_from_card(alert)  # también con la tecla de menú, que no pasa por el clic
        if self.on_menu is not None:
            self.on_menu(alert, global_pos)


class ProcessMonitor(QWidget):
    """
    Tabla de procesos EN VIVO: PID, nombre, usuario, CPU %, memoria y estado. Muestreo en segundo
    plano (self.app.run_task) con intervalo configurable; búsqueda por nombre o PID, ordenación por
    columnas y panel de detalle del proceso seleccionado. Clic derecho sobre una fila: menú «Navaja
    Suiza» (process_menu) para finalizar, suspender, reanudar o confiar en el proceso. Los valores
    no accesibles se muestran «—», nunca como 0.
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
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
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

    def _context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is None:
            return
        self.table.selectRow(item.row())
        pid_item = self.table.item(item.row(), 0)
        pid = pid_item.data(Qt.ItemDataRole.UserRole) if pid_item else None
        row = next((r for r in self._rows if r.pid == pid), None)
        process_menu(self.app, self, self.table.viewport().mapToGlobal(pos), pid,
                     row.name if row else None, status=row.status if row else None, on_done=self._tick)

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


class MonitorPage(Page):
    """Radar en tiempo real: conexiones de red y procesos sospechosos. Muestra en un hilo cada 3 s
    (LiveMonitor.sample) para no congelar la interfaz. Las pestañas de procesos ofrecen el menú
    contextual «Navaja Suiza» (finalizar, suspender, reanudar, confiar)."""

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
        self.conn_table = make_table(["Proceso", "PID", "IP local", "Puerto", "IP remota", "Puerto",
                                      "Estado", "Destino"], widths=[170, 70, 130, 70, 130, 70, 110],
                                     empty="Inicia el monitor para ver las conexiones de red en tiempo "
                                           "real.", empty_icon="fa5s.wave-square")
        self.board = ProcBoard(self._on_proc_select, self._proc_menu)
        self.history = {}  # proceso -> {cpu: deque, rss: deque} de los últimos ~20 s (sparklines)
        self.proc_monitor = ProcessMonitor(app)  # tabla general de procesos (con menú contextual)
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

    def _proc_menu(self, alert, global_pos) -> None:
        process_menu(self.app, self, global_pos, alert.pid, alert.name,
                     created=getattr(alert, "created", None) or None,
                     on_done=lambda: self._after_control(alert))

    def _after_control(self, alert) -> None:
        if self.selected is alert:
            self._on_proc_select(alert)  # refresca la etiqueta «DE CONFIANZA» del detalle
        self._tick()  # nueva muestra: el proceso finalizado desaparece del tablero

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
