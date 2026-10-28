"""
ui/page_salud.py · LOZARUS KIT TOOL

Página SALUD DEL SISTEMA (motor: modulos/_salud_sistema.py):
  · Indicador de estado global (SALUDABLE / ATENCIÓN / CRÍTICO / SIN VERIFICAR) con sus motivos, a partir
    del historial de integridad y de las señales de estabilidad del equipo.
  · Integridad con las herramientas estándar de Windows: sfc /verifyonly, DISM /CheckHealth y
    /ScanHealth (solo lectura) y la reparación oficial DISM /RestoreHealth + sfc /scannow. Progreso
    real (el porcentaje que imprime cada herramienta) y cancelación.
  · Estabilidad: reinicio pendiente, tiempo encendido, apagados inesperados, pantallazos azules y salud
    de los discos físicos.
  · Registro de verificaciones (Lozarus_Forensics/salud_sistema.json) y exportación del informe ejecutivo.

Cada acción pide confirmación (ConfirmDialog.ask vía SafeActions), corre en segundo plano, queda en la
Caja Negra (_emit_event) y avisa con Toast.notify; una corrupción detectada entra además en el Centro de
Alertas. report_data() alimenta el informe ejecutivo y el panel de componentes del Centro de Comando.
"""

from __future__ import annotations

import datetime as dt
import html
import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QTableWidgetItem, QVBoxLayout

from modulos import _salud_sistema as health
from modulos._salud_sistema import format_duration

from ui.theme import COLORS
from ui.widgets import Page, fit_columns, frozen, icon, make_card, make_table, tech_tip
from ui.chrome import Toast
from ui.informe import export_report
from ui.kit import HeaderStatus, ProgressStrip, SafeActions, TaskProgress, Tile, action_button

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

PAGE_KEY = "salud"
PAGE_ICON = "fa5s.heartbeat"
SOURCE = "salud:integridad"
LEVEL_COLOR = {"ok": COLORS["ok"], "warn": COLORS["warn"], "critical": COLORS["danger"], "unknown": COLORS["faint"]}
LEVEL_ICON = {"ok": "fa5s.heartbeat", "warn": "fa5s.exclamation-triangle", "critical": "fa5s.times-circle",
              "unknown": "fa5s.question-circle"}
LEVEL_KIND = {"ok": "*", "warn": "!", "critical": "x", "unknown": "!"}
SIGNALS_TTL_S = 60          # al volver a la página, las señales se releen si tienen más de un minuto
# Tiempo orientativo de cada comprobación (texto de la confirmación)
DURATION_HINT = {"dism_check": "unos segundos", "dism_scan": "entre 5 y 20 minutos",
                 "sfc_verify": "entre 5 y 15 minutos"}


def _when_text(iso: Optional[str]) -> str:
    try:
        when = dt.datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return "—"
    days = (dt.date.today() - when.date()).days
    return (f"hoy {when:%H:%M}" if days == 0 else f"ayer {when:%H:%M}" if days == 1
            else f"{when:%d/%m/%Y %H:%M}")


class HealthPage(SafeActions, Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Salud del Sistema",
                         "Supervisa la integridad de los archivos protegidos de Windows con sus herramientas estándar "
                         "(SFC y DISM), la estabilidad del equipo y el estado de los discos. Cada verificación queda en "
                         "la Caja Negra y en el historial.", PAGE_ICON)
        self.app = app
        self._state: Dict[str, Any] = health.load_state()   # historial persistente (JSON pequeño)
        self._signals: Optional[Dict[str, Any]] = None
        self._signals_at: Optional[float] = None
        self._signals_busy = False
        self._verdict: Optional[Dict[str, Any]] = None
        self._last_level: Optional[str] = None
        self._op: Optional[str] = None                      # comprobación de integridad en curso
        self._buttons: Dict[str, QPushButton] = {}
        self.header_status = HeaderStatus()
        self.add_header_widget(self.header_status)
        self.root.addWidget(self._build_hero())
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(16)
        for i, tile in enumerate((self._build_files_tile(), self._build_store_tile(), self._build_repair_tile(),
                                  self._build_stability_tile())):
            grid.addWidget(tile, i // 2, i % 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        self.root.addLayout(grid)
        self.root.addWidget(self._build_history_card())
        self.root.addStretch(1)
        self._render()

    # =============================================================================================
    # Construcción
    # =============================================================================================
    def _build_hero(self) -> QFrame:
        box = QFrame()
        box.setObjectName("Card")
        lay = QHBoxLayout(box)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(24)
        state = QVBoxLayout()
        state.setSpacing(6)
        self.state_icon = QLabel()
        self.state_icon.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.state_icon.setFixedSize(132, 64)
        self.state_label = QLabel("SIN VERIFICAR")
        self.state_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        cap = QLabel("ESTADO DEL SISTEMA")
        cap.setObjectName("ChipCap")
        cap.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        state.addWidget(self.state_icon, 0, Qt.AlignmentFlag.AlignHCenter)
        state.addWidget(self.state_label)
        state.addWidget(cap)
        lay.addLayout(state)
        body = QVBoxLayout()
        body.setSpacing(8)
        head = QLabel("DIAGNÓSTICO")
        head.setObjectName("ChipCap")
        self.reasons = QLabel("")
        self.reasons.setObjectName("CardText")
        self.reasons.setWordWrap(True)
        self.reasons.setTextFormat(Qt.TextFormat.RichText)
        self.last_check = QLabel("")
        self.last_check.setObjectName("Tiny")
        self.last_check.setWordWrap(True)
        body.addWidget(head)
        body.addWidget(self.reasons, 1)
        body.addWidget(self.last_check)
        lay.addLayout(body, 1)
        actions = QVBoxLayout()
        actions.setSpacing(10)
        self.quick_btn = action_button("Comprobación rápida", "fa5s.stethoscope", "Primary", self._quick_check)
        self.quick_btn.setToolTip(tech_tip("Comprobación rápida",
                                           ["DISM /Online /Cleanup-Image /CheckHealth (Administrador)",
                                            "Registro System: Kernel-Power 41, EventLog 6008, BugCheck 1001",
                                            "Reinicio pendiente (CBS, Windows Update) · Get-PhysicalDisk"],
                                           "Solo lectura: no cambia nada del sistema."))
        self.report_btn = action_button("Exportar informe ejecutivo", "fa5s.file-export", "Ghost",
                                        lambda: export_report(self.app))
        self.report_btn.setToolTip(tech_tip("Informe ejecutivo (HTML)", ["Lozarus_Forensics/Informes"],
                                            "Cabecera corporativa lista para imprimir, rendimiento, salud del sistema "
                                            "y resumen visual de optimizaciones."))
        actions.addStretch(1)
        actions.addWidget(self.quick_btn)
        actions.addWidget(self.report_btn)
        if not getattr(self.app, "admin", False):
            actions.addWidget(action_button("Relanzar como Administrador", "fa5s.user-shield", "Warn",
                                            self.app.relaunch_as_admin))
        actions.addStretch(1)
        lay.addLayout(actions)
        return box

    def _check_button(self, tile: Tile, key: str, text: str, kind: str, icon_name: str) -> QPushButton:
        title, argv, _timeout, _tool = health.CHECKS[key]
        btn = tile.add_action(action_button(text, icon_name, kind, lambda: self._run_check(key)))
        btn.setToolTip(tech_tip(title, [" ".join(argv)], "Solo lectura · requiere Administrador · duración: "
                                                         f"{DURATION_HINT.get(key, 'variable')}."))
        self._buttons[key] = btn
        return btn

    def _build_files_tile(self) -> Tile:
        tile = Tile("fa5s.file-medical-alt", "Archivos protegidos (SFC)",
                    "Comprueba que los archivos protegidos de Windows coinciden con sus versiones originales. "
                    "Verificación de solo lectura: no repara nada.", level="card")
        self.files_strip = ProgressStrip()
        tile.body.addWidget(self.files_strip)
        self._check_button(tile, "sfc_verify", "Verificar archivos", "Primary", "fa5s.search")
        self.files_tile = tile
        return tile

    def _build_store_tile(self) -> Tile:
        tile = Tile("fa5s.layer-group", "Almacén de componentes (DISM)",
                    "El almacén de componentes es la copia de la que Windows repara sus archivos. CheckHealth lee "
                    "su marca de corrupción en segundos; ScanHealth lo examina a fondo.", level="card")
        self.store_strip = ProgressStrip()
        tile.body.addWidget(self.store_strip)
        self._check_button(tile, "dism_check", "Comprobación rápida", "Ghost", "fa5s.bolt")
        self._check_button(tile, "dism_scan", "Examen profundo", "Ghost", "fa5s.search-plus")
        self.store_tile = tile
        return tile

    def _build_repair_tile(self) -> Tile:
        tile = Tile("fa5s.first-aid", "Reparación del sistema",
                    "Reparación oficial de Microsoft: DISM /RestoreHealth repara el almacén (puede descargar de "
                    "Windows Update) y sfc /scannow repara los archivos desde él. 15-45 min; reinicia al terminar.",
                    level="card")
        self.repair_strip = ProgressStrip()
        tile.body.addWidget(self.repair_strip)
        btn = tile.add_action(action_button("Reparar sistema", "fa5s.first-aid", "Danger", self._repair))
        btn.setToolTip(tech_tip("Reparación del sistema", [" ".join(health.CHECKS[k][1]) for k in health.REPAIR_STEPS],
                                "Modifica archivos del sistema con las herramientas oficiales · requiere Administrador."))
        self._buttons["repair"] = btn
        self.repair_tile = tile
        return tile

    def _build_stability_tile(self) -> Tile:
        tile = Tile("fa5s.power-off", "Estabilidad y discos",
                    f"Reinicio pendiente, tiempo encendido, apagados inesperados y pantallazos azules de los últimos "
                    f"{health.EVENT_WINDOW_DAYS} días, y la salud que informa cada disco físico.", level="card")
        self.stability = QLabel("Leyendo señales del equipo…")
        self.stability.setObjectName("CardText")
        self.stability.setWordWrap(True)
        self.stability.setTextFormat(Qt.TextFormat.RichText)
        tile.body.addWidget(self.stability)
        self.signals_btn = tile.add_action(action_button("Actualizar señales", "fa5s.sync-alt", "Ghost",
                                                         lambda: self._refresh_signals(user=True)))
        self.stability_tile = tile
        return tile

    def _build_history_card(self) -> QFrame:
        box, lay = make_card("Registro de verificaciones",
                             f"Últimas verificaciones de integridad de este equipo ({health.STATE_FILE}). También "
                             "quedan en la Caja Negra.")
        self.history_table = make_table(["Fecha", "Comprobación", "Resultado", "Duración", "Detalle"],
                                        widths=[128, 250, 130, 90],
                                        empty="Aún no hay verificaciones. Empieza con «Comprobación rápida».",
                                        empty_icon="fa5s.clipboard-list")
        fit_columns(self.history_table, 4)
        self.history_table.setMinimumHeight(220)
        lay.addWidget(self.history_table)
        return box

    # =============================================================================================
    # Estado en vivo
    # =============================================================================================
    def showEvent(self, event) -> None:
        """Al abrir la página se releen las señales si no las hay o tienen más de un minuto (en segundo plano)."""
        super().showEvent(event)
        if self._signals_at is None or time.monotonic() - self._signals_at > SIGNALS_TTL_S:
            self._refresh_signals()

    def _refresh_signals(self, user: bool = False) -> None:
        if self._signals_busy:
            return
        self._signals_busy = True
        self._signals_at = time.monotonic()
        if user:
            self.app.log_tactical("Salud del sistema: leyendo señales de estabilidad y discos")
        self.signals_btn.setEnabled(False)

        def done(ok: bool, res) -> None:
            self._signals_busy = False
            self.signals_btn.setEnabled(True)
            if ok and isinstance(res, dict):
                self._signals = res
            elif user:
                Toast.notify(self.app, "x", "Salud del sistema", f"No se pudieron leer las señales: {res}", PAGE_ICON)
            self._render(log_change=True)
            if user and ok and self._verdict is not None:
                v = self._verdict
                self.finish(None, LEVEL_KIND[v["level"]], "Salud del sistema", self._verdict_text(v), PAGE_ICON,
                            source=SOURCE, event_type="health.status", payload=self._status_payload())

        self.app.run_task(lambda emit: health.collect_signals(), done, track=user)

    def _busy_changed(self) -> None:
        self._refresh_status()

    def _compute(self) -> Dict[str, Any]:
        self._verdict = health.health_verdict(self._signals, health.integrity_status(self._state))
        return self._verdict

    @staticmethod
    def _verdict_text(v: Dict[str, Any]) -> str:
        worst = [t for lvl, t in v["reasons"] if lvl in ("warn", "critical")]
        return f"{v['label']}: " + ("; ".join(worst[:2]) if worst else
                                    "sin incidencias" if v["level"] == "ok" else "falta verificar la integridad")

    def _status_payload(self) -> dict:
        v, s = self._verdict or {}, self._signals or {}
        return {"level": v.get("level"), "label": v.get("label"), "reasons": [t for _l, t in v.get("reasons", [])],
                "pending_reboot": s.get("pending_reboot"), "unexpected_shutdowns": s.get("unexpected_shutdowns"),
                "bugchecks": s.get("bugchecks"), "uptime_s": s.get("uptime_s"),
                "disks": [{"model": d["model"], "health": d["health"]} for d in s.get("disks") or []]}

    def _refresh_status(self) -> None:
        v = self._verdict or self._compute()
        if self._op is not None:
            title = health.CHECKS[self._op][0] if self._op in health.CHECKS else "Reparación del sistema"
            self.header_status.set_state(f"EN CURSO · {title.split(' · ')[0].upper()}", COLORS["accent"])
        elif self.running:
            self.header_status.set_state(f"EN CURSO · {self.running}", COLORS["accent"])
        else:
            self.header_status.set_state(v["label"], LEVEL_COLOR[v["level"]], self._verdict_text(v))
        self.header_status.set_admin(bool(getattr(self.app, "admin", False)))

    # =============================================================================================
    # Render
    # =============================================================================================
    def _render(self, log_change: bool = False) -> None:
        v = self._compute()
        color = LEVEL_COLOR[v["level"]]
        self.state_icon.setPixmap(icon(LEVEL_ICON[v["level"]], color).pixmap(56, 56))
        self.state_label.setText(v["label"])
        self.state_label.setStyleSheet(f"color:{color}; font-size:17pt; font-weight:800; letter-spacing:1px;")
        bullets = [f"<span style='color:{LEVEL_COLOR[lvl]}'>●</span>&nbsp; {html.escape(text)}"
                   for lvl, text in v["reasons"][:6]]
        if not bullets:
            bullets = [f"<span style='color:{COLORS['ok']}'>●</span>&nbsp; Sin incidencias en las señales leídas."]
        if self._signals is None:
            bullets.append(f"<span style='color:{COLORS['faint']}'>●</span>&nbsp; Leyendo las señales de estabilidad…")
        self.reasons.setText("<br>".join(bullets))
        integ = health.integrity_status(self._state)
        self.last_check.setText(f"Última verificación de integridad: {_when_text(integ['last_when'])}."
                                if integ["last_when"] else "Ninguna verificación de integridad registrada en este equipo.")
        self._render_tiles(integ)
        self._render_stability()
        self._render_history()
        busy = self._op is not None
        for key, btn in self._buttons.items():
            if not btn.property("busy"):
                btn.setEnabled(health.IS_WINDOWS and not busy)
        if not self.quick_btn.property("busy"):
            self.quick_btn.setEnabled(not busy and not self._signals_busy)
        if log_change and self._last_level is not None and v["level"] != self._last_level:
            _old = self._last_level
            self.app.console.log(LEVEL_KIND[v["level"]], f"Salud del sistema: {_old.upper()} → {v['label']}")
        self._last_level = v["level"]
        self._refresh_status()

    def _render_tiles(self, integ: Dict[str, Any]) -> None:
        for tile, result, empty in ((self.files_tile, integ["files"], "SIN VERIFICAR"),
                                    (self.store_tile, integ["store"], "SIN VERIFICAR")):
            if not health.IS_WINDOWS:
                tile.set_pill("SOLO WINDOWS", COLORS["faint"])
                tile.set_note("SFC y DISM solo existen en Windows.")
            elif result:
                tile.set_pill(result["label"], LEVEL_COLOR.get(result["level"], COLORS["faint"]))
                tile.set_note(f"{_when_text(result['when'])} · {format_duration(result.get('seconds'))} · "
                              f"{result.get('message', '')}", tip=" · ".join(result.get("lines") or []))
            else:
                tile.set_pill(empty, COLORS["faint"])
                tile.set_note("Sin resultados en este equipo." if getattr(self.app, "admin", False) else
                              "Sin resultados · requiere Administrador.")
        last_repair = next((h for h in self._state.get("history", []) if h.get("key") in health.REPAIR_STEPS), None)
        if not health.IS_WINDOWS:
            self.repair_tile.set_pill("SOLO WINDOWS", COLORS["faint"])
        elif last_repair:
            self.repair_tile.set_pill(last_repair["label"], LEVEL_COLOR.get(last_repair["level"], COLORS["faint"]))
            self.repair_tile.set_note(f"Última: {_when_text(last_repair['when'])} · {last_repair.get('message', '')}")
        else:
            self.repair_tile.set_pill("", COLORS["faint"])
            self.repair_tile.set_note("Úsala si la verificación encuentra infracciones o el almacén es reparable.")

    def _render_stability(self) -> None:
        s = self._signals
        if s is None:
            self.stability_tile.set_pill("LEYENDO…", COLORS["faint"])
            return
        lines, worst = [], "ok"

        def add(level: str, text: str) -> None:
            nonlocal worst
            lines.append(f"<span style='color:{LEVEL_COLOR[level]}'>●</span>&nbsp; {html.escape(text)}")
            if health.LEVEL_RANK[level] > health.LEVEL_RANK[worst]:
                worst = level

        pending = s.get("pending_reboot")
        if pending is None:
            add("unknown", "Reinicio pendiente: no se puede leer en este sistema")
        else:
            add("warn" if pending else "ok", ("Reinicio pendiente: " + ", ".join(pending)) if pending
                else "Sin reinicios pendientes")
        uptime = s.get("uptime_s")
        if uptime is not None:
            long_on = uptime > health.UPTIME_WARN_DAYS * 86400
            add("warn" if long_on else "ok", f"Encendido desde hace {format_duration(uptime)}")
        days = s.get("window_days", health.EVENT_WINDOW_DAYS)
        for value, label, crit in ((s.get("unexpected_shutdowns"), "apagado(s) inesperado(s)", 3),
                                   (s.get("bugchecks"), "pantallazo(s) azul(es)", 2)):
            if value is None:
                add("unknown", f"{label.capitalize()} ({days} días): no disponible")
            else:
                add("critical" if value >= crit else "warn" if value else "ok", f"{value} {label} en {days} días")
        disks = s.get("disks")
        if disks:
            for d in disks:
                add(d["level"] if d["level"] != "unknown" else "unknown",
                    f"{d['model']} · {d['media']} · {d['label'].lower()}")
        elif disks is not None:
            add("unknown", "Discos físicos: Windows no los informó")
        self.stability.setText("<br>".join(lines))
        label = {"ok": "ESTABLE", "warn": "ATENCIÓN", "critical": "INESTABLE", "unknown": "PARCIAL"}[worst]
        self.stability_tile.set_pill(label, LEVEL_COLOR[worst])
        when = dt.datetime.fromtimestamp(time.time() - (time.monotonic() - (self._signals_at or time.monotonic())))
        self.stability_tile.set_note(f"Leído a las {when:%H:%M}")

    def _render_history(self) -> None:
        rows = [h for h in self._state.get("history", []) if isinstance(h, dict)]
        with frozen(self.history_table):
            self.history_table.setRowCount(len(rows))
            for r, h in enumerate(rows):
                color = LEVEL_COLOR.get(h.get("level"), COLORS["text2"])
                cells = [QTableWidgetItem(_when_text(h.get("when"))), QTableWidgetItem(h.get("title") or h.get("key", "")),
                         QTableWidgetItem(h.get("label") or "—"), QTableWidgetItem(format_duration(h.get("seconds"))),
                         QTableWidgetItem(h.get("message") or "")]
                cells[1].setToolTip(h.get("command") or "")
                cells[2].setForeground(QColor(color))
                cells[4].setToolTip("\n".join(h.get("lines") or []))
                for c, it in enumerate(cells):
                    self.history_table.setItem(r, c, it)

    # =============================================================================================
    # Comprobaciones de integridad
    # =============================================================================================
    def _strip_for(self, key: str) -> ProgressStrip:
        return self.files_strip if key.startswith("sfc") else self.store_strip

    def _quick_check(self) -> None:
        """Señales de estabilidad siempre; con Administrador, además DISM /CheckHealth (segundos, solo lectura)."""
        self._refresh_signals(user=True)
        if health.IS_WINDOWS and getattr(self.app, "admin", False) and self._op is None:
            self._run_check("dism_check", confirm=False)
        elif health.IS_WINDOWS and not getattr(self.app, "admin", False):
            self.app.console.log("!", "Salud del sistema: la comprobación de integridad (DISM) requiere Administrador")

    def _run_check(self, key: str, confirm: bool = True) -> None:
        if self._op is not None:
            return
        title, argv, _timeout, _tool = health.CHECKS[key]
        if not health.IS_WINDOWS:
            Toast.notify(self.app, "!", title, "SFC y DISM solo existen en Windows.", PAGE_ICON)
            return
        if not self.admin_ok(title, "SFC y DISM solo funcionan con privilegios de Administrador."):
            return
        if confirm and not self.confirm_exact(
                title, f"Verificación de SOLO LECTURA de este equipo; tarda {DURATION_HINT.get(key, 'un rato')}.",
                [" ".join(argv)], footer="Puedes seguir usando Lozarus y cancelarla en cualquier momento.",
                confirm_text="Iniciar verificación", danger=False):
            return
        task = TaskProgress()
        self._op = key
        strip = self._strip_for(key)
        strip.start(task, argv[0].upper() + (" " + argv[-1] if argv[0] == "dism" else " /verifyonly"))
        self._render()
        self.app.log_tactical(f"Salud del sistema: {title} ({' '.join(argv)})")
        self.run_action(self._buttons[key], "Verificando…",
                        lambda emit: health.run_check(key, admin=True, cancel=task.cancel, on_progress=task.set,
                                                      emit=emit),
                        lambda ok, res: self._check_done(key, strip, ok, res))

    def _check_done(self, key: str, strip: ProgressStrip, ok: bool, res) -> None:
        strip.stop()
        self._op = None
        title = health.CHECKS[key][0]
        if not ok or not isinstance(res, dict):
            self.finish(self._buttons[key], "x", title, f"No se pudo completar: {res}", PAGE_ICON, source=SOURCE,
                        event_type="health.integrity_check", payload={"key": key, "ok": False, "error": str(res)})
            self._render()
            return
        self._state = health.load_state()   # run_check ya guardó el resultado
        kind = "~" if res["verdict"] == "cancelled" else LEVEL_KIND[res["level"]]
        self.finish(self._buttons[key], kind, title, res["message"], PAGE_ICON, source=SOURCE,
                    event_type="health.integrity_check",
                    payload={k: res.get(k) for k in ("key", "command", "verdict", "level", "rc", "seconds", "lines")})
        if res["level"] == "critical":
            self.app.record_alert("x", f"Integridad del sistema: {res['message']}", module=PAGE_KEY)
        self._render(log_change=True)

    def _repair(self) -> None:
        if self._op is not None:
            return
        if not health.IS_WINDOWS:
            Toast.notify(self.app, "!", "Reparación del sistema", "Disponible solo en Windows.", PAGE_ICON)
            return
        if not self.admin_ok("Reparar el sistema", "DISM y SFC solo reparan con privilegios de Administrador."):
            return
        commands = [" ".join(health.CHECKS[k][1]) for k in health.REPAIR_STEPS]
        if not self.confirm_exact("Reparar el sistema",
                                  "Reparación OFICIAL de Microsoft sobre este equipo: sustituye los archivos del sistema "
                                  "dañados por sus versiones originales. Tarda entre 15 y 45 minutos y puede descargar "
                                  "componentes de Windows Update.", commands,
                                  footer="No toca tus documentos ni tus programas. Al terminar, reinicia el equipo.",
                                  confirm_text="Reparar sistema", danger=True):
            return
        task = TaskProgress()
        self._op = "repair"
        self.repair_strip.start(task, "DISM + SFC")
        self._render()
        self.app.log_tactical("Salud del sistema: reparación (DISM /RestoreHealth + sfc /scannow)")
        self.run_action(self._buttons["repair"], "Reparando…",
                        lambda emit: health.repair_system(admin=True, cancel=task.cancel, on_progress=task.set,
                                                          emit=emit),
                        self._repair_done)

    def _repair_done(self, ok: bool, res) -> None:
        self.repair_strip.stop()
        self._op = None
        btn = self._buttons["repair"]
        if not ok or not isinstance(res, dict):
            self.finish(btn, "x", "Reparación del sistema", f"No se pudo completar: {res}", PAGE_ICON, source=SOURCE,
                        event_type="health.repair", payload={"ok": False, "error": str(res)})
            self._render()
            return
        self._state = health.load_state()
        kind = "~" if res["verdict"] == "cancelled" else LEVEL_KIND[res["level"]]
        self.finish(btn, kind, "Reparación del sistema", res["message"], "fa5s.first-aid", source=SOURCE,
                    event_type="health.repair",
                    payload={"verdict": res["verdict"], "level": res["level"], "seconds": res["seconds"],
                             "steps": [{k: s.get(k) for k in ("key", "command", "verdict", "rc", "seconds")}
                                       for s in res["steps"]]})
        if res["level"] == "critical":
            self.app.record_alert("x", f"Reparación del sistema: {res['message']}", module=PAGE_KEY)
        self._render(log_change=True)

    def cancel_tasks(self) -> None:
        """Cierre de la ventana: detiene SFC/DISM si siguen en marcha (MainWindow.closeEvent)."""
        for strip in (self.files_strip, self.store_strip, self.repair_strip):
            strip.cancel()

    # =============================================================================================
    # Datos para el informe ejecutivo y el Centro de Comando
    # =============================================================================================
    def report_data(self) -> Dict[str, Any]:
        v = self._verdict or self._compute()
        integ = health.integrity_status(self._state)
        return {"verdict": {"level": v["level"], "label": v["label"], "reasons": list(v["reasons"])},
                "integrity": {"files": integ["files"], "store": integ["store"], "verified": integ["verified"],
                              "last_when": integ["last_when"]},
                "signals": self._signals, "history": [h for h in self._state.get("history", [])][:8]}

    def verdict(self) -> Dict[str, Any]:
        """Veredicto actual (lectura barata para el panel de componentes)."""
        return self._verdict or self._compute()
