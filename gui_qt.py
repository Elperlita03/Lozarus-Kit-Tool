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
  · Tema «Dark Cosmos Glass» en QSS (degradados estáticos y tarjetas translúcidas, sin animar).
  · Hover suave del menú lateral con QPropertyAnimation.
  · Worker(QThread): clase base para correr diagnósticos / PowerShell en segundo plano sin
    congelar la interfaz (comunica por señales, que Qt entrega al hilo de la UI de forma segura).
  · Módulos defensivos LOCALES: Endurecimiento de Red (ocultar ante ping / ICMP) y Honeypot de
    detección (archivos señuelo que solo se vigilan y avisan; no actúan contra nadie).
  · Consola de Telemetría (QPlainTextEdit monoespaciado) y diálogo de doble validación «CONFIRMAR».

Estructura: este archivo monta la ventana (MainWindow) y el menú lateral; las páginas y piezas
visuales viven en el paquete ui/ (ver ui/__init__.py).

Todo es defensivo, local y reversible. Requisito:  pip install PySide6
"""

from __future__ import annotations

import datetime as dt
import os
import sys
import time
import traceback
from typing import Any, Callable, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from PySide6.QtCore import (Property, QEasingCurve, QPropertyAnimation, QRectF, QSize, QThread,  # noqa: E402
                            QTimer, Qt, Signal)
from PySide6.QtGui import QColor, QPainter  # noqa: E402
from PySide6.QtWidgets import (QApplication, QDialog, QFrame, QGraphicsOpacityEffect, QHBoxLayout,  # noqa: E402
                               QLabel, QMainWindow, QPushButton, QSizeGrip, QSplitter,
                               QStackedWidget, QVBoxLayout, QWidget)

from modulos._alertas import HAS_PLYER, Sentinel, describe_threats, notify  # noqa: E402
from modulos._base import CRITICAL  # noqa: E402
from modulos._cargador import discover_modules  # noqa: E402
from modulos._contencion import apply_quarantine, lift_quarantine, quarantine_active  # noqa: E402
from modulos._privacidad import empty_working_sets  # noqa: E402
from modulos._forense import FORENSICS_DIR  # noqa: E402
from modulos._listablanca import CONFIG_KEY as TRUST_KEY  # noqa: E402
from modulos._listablanca import add_trusted, is_trusted  # noqa: E402
from modulos._tacticas import factory_reset, ghost_mode  # noqa: E402
from modulos._utilidades import is_admin, request_admin_relaunch  # noqa: E402

from ui._compat import (HAS_BLACKBOX, HAS_HONEYPOT, CajaNegra, EventBus, HoneypotEngine,  # noqa: E402
                        TacticalConfig)
from ui.theme import APP_NAME, COLORS, NAV_ICONS, QSS, base_font  # noqa: E402
from ui.widgets import _ORPHAN_WORKERS, Worker, icon, with_icon  # noqa: E402
from ui.dialogs import ConfirmDialog, ResetConfirmDialog  # noqa: E402
from ui.chrome import AlertCenter, ConsolePanel, EdgeResizer, TitleBar, Toast  # noqa: E402
from ui.page_command import CommandPage  # noqa: E402
from ui.page_monitor import MonitorPage, ProcessMonitor  # noqa: E402
from ui.page_audit import AuditPage  # noqa: E402
from ui.page_network import NetworkPage  # noqa: E402
from ui.page_honeypot import HoneypotPage  # noqa: E402
from ui.page_ghost import GhostPage  # noqa: E402
from ui.page_history import HistorialPage  # noqa: E402

__all__ = ["MainWindow", "NavButton", "HoldButton", "ProcessMonitor", "main"]  # ProcessMonitor: pruebas


# ===========================================================================
# MENÚ LATERAL
# ===========================================================================
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


# ===========================================================================
# VENTANA PRINCIPAL
# ===========================================================================
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
    app.setFont(base_font())  # tipografía corporativa (el QSS solo ajusta jerarquías)
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
