"""
ui/page_guard.py · LOZARUS KIT TOOL

Página GUARDIA & ROLLBACK:
  · Guardia en Vivo: vigila en segundo plano la persistencia de arranque (Run/RunOnce, carpetas
    Inicio) y los puertos en escucha contra una referencia guardada; cada elemento nuevo lanza una
    alerta roja con «Bloquear» y «Caja Negra» (motor: modulos/_guardia.py).
  · Gestor de Rollback: lee rollback_state.json del Arsenal, compara cada valor original con el
    actual de Windows y restaura valores sueltos de forma quirúrgica (modulos/_arsenal.py).
"""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING, List, Optional

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHBoxLayout, QLabel, QPushButton, QTableWidgetItem

from modulos import _arsenal as arsenal
from modulos import _guardia as guardia
from modulos._inicio import startup_entries

from ui.theme import COLORS
from ui.widgets import Page, _emit_event, flash_aura, frozen, make_card, make_table, set_busy, tech_tip, with_icon
from ui.dialogs import ConfirmDialog
from ui.chrome import Toast

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

GUARD_INTERVAL_MS = 5000
STATE_COLOR = {"PENDIENTE": COLORS["danger"], "BLOQUEADO": COLORS["ok"], "APROBADO": COLORS["muted"],
               "EN CAJA NEGRA": COLORS["warn"]}


def _fmt(exists: bool, data, kind: Optional[int]) -> str:
    if not exists:
        return "(no existe)"
    tipo = {1: "SZ", 2: "EXPAND_SZ", 4: "DWORD"}.get(kind, str(kind))
    return f"{data!r} ({tipo})"


class GuardPage(Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Guardia & Rollback",
                         "Vigilancia activa de la persistencia de arranque y de los puertos en escucha, y "
                         "restauración quirúrgica de los cambios del Arsenal.", "fa5s.user-shield")
        self.app = app
        self._baseline = None            # claves de la referencia (None hasta la primera pasada)
        self._seen: set = set()          # avisadas en esta sesión (no se repiten)
        self._detections: List[dict] = []
        self._guard_busy = False
        self._acting = False
        self._rb_rows: List[dict] = []
        self._autoruns_busy = False
        self._autoruns_done = False
        self.root.addWidget(self._build_guard_card())
        self.root.addWidget(self._build_rollback_card())
        self.root.addWidget(self._build_autoruns_card())
        self.root.addStretch(1)
        self._timer = QTimer(self)
        self._timer.setInterval(GUARD_INTERVAL_MS)
        self._timer.timeout.connect(self._guard_tick)
        QTimer.singleShot(0, lambda: self.guard_btn.setChecked(True))  # la Guardia arranca activa

    @staticmethod
    def _btn(text: str, icon_name: str, kind: str, slot) -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName(kind)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        with_icon(btn, icon_name, COLORS["danger"] if kind == "Danger" else COLORS["muted"] if kind == "Ghost" else None)
        btn.clicked.connect(slot)
        return btn

    # =============================================================================================
    # Guardia en Vivo
    # =============================================================================================
    def _build_guard_card(self):
        box, lay = make_card("Guardia en Vivo",
                             "Cada 5 s compara las claves Run/RunOnce, las carpetas Inicio y los puertos TCP en "
                             "escucha con la referencia guardada. Lo nuevo dispara una alerta roja inmediata.")
        top = QHBoxLayout()
        top.setSpacing(10)
        self.guard_btn = self._btn("Guardia en Vivo: OFF", "fa5s.user-shield", "Primary", lambda: None)
        self.guard_btn.setCheckable(True)
        self.guard_btn.toggled.connect(self._toggle_guard)
        self.guard_btn.setToolTip(tech_tip("Guardia en Vivo", ["HKLM/HKCU\\...\\CurrentVersion\\Run, RunOnce (+ WOW6432Node)",
                                                               "Carpetas Inicio (usuario y todos)",
                                                               "psutil.net_connections(kind='tcp') · LISTEN"],
                                           f"Referencia: {guardia.BASELINE_FILE}"))
        rebase = self._btn("Restablecer referencia", "fa5s.sync-alt", "Ghost", self._rebaseline)
        rebase.setToolTip(tech_tip("Restablecer referencia", [guardia.BASELINE_FILE],
                                   "Lo que hay ahora pasa a considerarse conocido."))
        self.guard_status = QLabel("Guardia detenida.")
        self.guard_status.setObjectName("CardText")
        top.addWidget(self.guard_btn)
        top.addWidget(rebase)
        top.addWidget(self.guard_status, 1)
        lay.addLayout(top)
        self.det_table = make_table(["Hora", "Tipo", "Elemento", "Detalle", "Estado"], widths=[70, 150, 230, 330],
                                    empty="Sin detecciones: nada nuevo desde la referencia.",
                                    empty_icon="fa5s.user-shield")
        self.det_table.setMinimumHeight(190)
        self.det_table.itemSelectionChanged.connect(self._det_buttons)
        lay.addWidget(self.det_table)
        acts = QHBoxLayout()
        acts.setSpacing(10)
        self.block_btn = self._btn("Bloquear", "fa5s.ban", "Danger", lambda: self._block(self._selected_det()))
        self.evidence_btn = self._btn("Enviar a la Caja Negra", "fa5s.box", "Ghost",
                                      lambda: self._evidence(self._selected_det()))
        self.approve_btn = self._btn("Aprobar (es legítimo)", "fa5s.check", "Ghost",
                                     lambda: self._approve(self._selected_det()))
        for b in (self.block_btn, self.evidence_btn, self.approve_btn):
            acts.addWidget(b)
        acts.addStretch(1)
        lay.addLayout(acts)
        self._det_buttons()
        return box

    def _toggle_guard(self, on: bool) -> None:
        self.guard_btn.setText(f"Guardia en Vivo: {'ON' if on else 'OFF'}")
        if on:
            self._timer.start()
            self._guard_tick()
            self.app.log_tactical("Guardia en Vivo activada (persistencia + puertos, cada 5 s)")
        else:
            self._timer.stop()
            self.guard_status.setText("Guardia detenida.")
            self.app.console.log("~", "Guardia en Vivo detenida")

    def _guard_tick(self) -> None:
        if self._guard_busy:
            return
        self._guard_busy = True
        self.app.run_task(lambda emit: (guardia.load_baseline() if self._baseline is None else None,
                                        guardia.snapshot()), self._guard_done, track=False)

    def _guard_done(self, ok: bool, res) -> None:
        self._guard_busy = False
        if not ok or not isinstance(res, tuple):
            self.guard_status.setText(f"Error en la pasada: {res}")
            return
        stored, current = res
        if self._baseline is None:
            if stored is None:  # primera vez en este equipo: lo actual es la referencia, sin avisar
                self._baseline = set(current)
                self._save_baseline()
                self.app.console.log("*", f"Guardia: referencia creada con {len(current)} elementos")
            else:
                self._baseline = stored
        runs = sum(1 for v in current.values() if v["kind"] != "port")
        self.guard_status.setText(f"Vigilando {runs} entradas de arranque y {len(current) - runs} puertos · "
                                  f"última pasada {dt.datetime.now():%H:%M:%S}")
        for key in guardia.new_items(self._baseline, current, self._seen):
            self._seen.add(key)
            self._alert({"key": key, "item": current[key], "when": dt.datetime.now(), "state": "PENDIENTE"})

    def _alert(self, det: dict) -> None:
        item = det["item"]
        self._detections.append(det)
        self._render_detections()
        port = item["kind"] == "port"
        text = (f"Nuevo puerto en escucha: TCP {item['port']} · {item['name']} ({item['command']})" if port else
                f"Nueva entrada de arranque «{item['name']}» en {item['label']}: {item['command']}")
        self.app.console.log("x", f"Guardia: {text}")
        _emit_event(self.app, source="guardia", event_type="guard.new_listen_port" if port else "guard.new_persistence",
                    payload={"key": det["key"], **item})
        self.app.record_alert("x", text, module="guardia", title="Posible vector de entrada", icon="fa5s.user-shield",
                              life_ms=20000, actions=[("Bloquear", lambda: self._block(det)),
                                                      ("Caja Negra", lambda: self._evidence(det))])

    def _render_detections(self) -> None:
        t = self.det_table
        with frozen(t):
            t.setRowCount(len(self._detections))
            for r, det in enumerate(reversed(self._detections)):  # lo más reciente arriba
                item = det["item"]
                where = f"{item['location']}" if item["kind"] != "port" else f"{item['location']} · {item['name']}"
                cells = [det["when"].strftime("%H:%M:%S"), guardia.KIND_LABEL[item["kind"]], item["name"],
                         f"{item['command']}  ·  {where}", det["state"]]
                for c, v in enumerate(cells):
                    cell = QTableWidgetItem(str(v))
                    if c == 4:
                        cell.setForeground(QColor(STATE_COLOR.get(det["state"], COLORS["text"])))
                    t.setItem(r, c, cell)
        self._det_buttons()

    def _selected_det(self) -> Optional[dict]:
        r = self.det_table.currentRow()
        return self._detections[len(self._detections) - 1 - r] if 0 <= r < len(self._detections) else None

    def _det_buttons(self) -> None:
        det = self._selected_det()
        open_ = det is not None and det["state"] in ("PENDIENTE", "EN CAJA NEGRA") and not self._acting
        self.block_btn.setEnabled(open_)
        self.evidence_btn.setEnabled(det is not None and not self._acting)
        self.approve_btn.setEnabled(open_)
        if det is not None:
            self.block_btn.setToolTip(tech_tip("Bloquear", [guardia.describe_block(det["item"])],
                                               "Requiere Administrador." if guardia.needs_admin(det["item"]) else ""))

    def _save_baseline(self) -> None:
        try:
            guardia.save_baseline(self._baseline)
        except OSError as exc:
            self.app.console.log("x", f"Guardia: no se pudo guardar la referencia: {exc}")

    def _rebaseline(self) -> None:
        if not ConfirmDialog.ask(self.app, "Restablecer referencia",
                                 "Todo lo que hay ahora en el arranque y en escucha pasará a considerarse "
                                 "conocido y dejará de avisar. ¿Continuar?", confirm_text="Restablecer"):
            return
        self._baseline = None
        self._seen.clear()
        try:
            guardia.save_baseline([])  # se rehace en la próxima pasada
        except OSError:
            pass
        self.app.run_task(lambda emit: guardia.snapshot(), self._rebase_done, track=False)

    def _rebase_done(self, ok: bool, current) -> None:
        if ok and isinstance(current, dict):
            self._baseline = set(current)
            self._save_baseline()
            _emit_event(self.app, source="guardia", event_type="guard.rebaseline", payload={"items": len(current)})
            Toast.notify(self.app, "*", "Guardia", f"Referencia restablecida: {len(current)} elementos.",
                         "fa5s.user-shield")

    # --- Acciones sobre una detección -----------------------------------------------------------
    def _set_state(self, det: dict, state: str) -> None:
        det["state"] = state
        self._render_detections()

    def _approve(self, det: Optional[dict]) -> None:
        if det is None:
            return
        self._baseline.add(det["key"])
        self._save_baseline()
        _emit_event(self.app, source="guardia", event_type="guard.approved", payload={"key": det["key"], **det["item"]})
        self._set_state(det, "APROBADO")
        Toast.notify(self.app, "*", "Guardia", f"«{det['item']['name']}» aprobado: no volverá a avisar.",
                     "fa5s.check")

    def _evidence(self, det: Optional[dict]) -> None:
        if det is None or self._acting:
            return
        self._acting = True
        self._det_buttons()
        self.app.run_task(lambda emit: guardia.evidence(det["item"]), lambda ok, res: self._evidence_done(det, ok, res))

    def _evidence_done(self, det: dict, ok: bool, res) -> None:
        self._acting = False
        good = ok and isinstance(res, dict)
        _emit_event(self.app, source="guardia", event_type="guard.evidence",
                    payload={"key": det["key"], "ok": good, **(res if good else {"error": str(res)})})
        if good and det["state"] == "PENDIENTE":
            self._set_state(det, "EN CAJA NEGRA")
        self._det_buttons()
        Toast.notify(self.app, "*" if good else "x", "Caja Negra",
                     (f"Evidencia de «{det['item']['name']}» registrada" + (f" · SHA-256 {res['sha256'][:16]}…"
                                                                           if good and res.get("sha256") else "."))
                     if good else f"No se pudo registrar: {res}", "fa5s.box")

    def _block(self, det: Optional[dict]) -> None:
        if det is None or self._acting or det["state"] in ("BLOQUEADO", "APROBADO"):
            return
        item = det["item"]
        if guardia.needs_admin(item) and not getattr(self.app, "admin", False):
            if ConfirmDialog.ask(self.app, "Se requiere Administrador",
                                 "Bloquear este elemento exige privilegios de Administrador. ¿Relanzar Lozarus "
                                 "elevado (UAC)?", confirm_text="Relanzar como Administrador"):
                self.app.relaunch_as_admin()
            return
        if not ConfirmDialog.ask(self.app, "Bloquear vector de entrada",
                                 f"Se aplicará exactamente:\n• {guardia.describe_block(item)}\n\n¿Continuar?",
                                 confirm_text="Bloquear", danger=True):
            return
        self._acting = True
        set_busy(self.block_btn, True, "Bloqueando…")
        self.app.log_tactical(f"Guardia: bloqueando {item['name']}")
        self.app.run_task(lambda emit: guardia.block(item), lambda ok, res: self._block_done(det, ok, res))

    def _block_done(self, det: dict, ok: bool, res) -> None:
        self._acting = False
        set_busy(self.block_btn, False)
        good = ok and isinstance(res, dict)
        _emit_event(self.app, source="guardia", event_type="guard.blocked",
                    payload={"key": det["key"], "item": det["item"], "ok": good,
                             **(res if good else {"error": str(res)})})
        if good:
            if det["item"]["kind"] == "port":  # sigue escuchando tras el firewall: ya está gestionado
                self._baseline.add(det["key"])
                self._save_baseline()
            self._set_state(det, "BLOQUEADO")
        flash_aura(self.block_btn, COLORS["ok"] if good else COLORS["danger"])
        self._det_buttons()
        Toast.notify(self.app, "*" if good else "x", "Guardia",
                     f"«{det['item']['name']}» bloqueado." if good else f"No se pudo bloquear: {res}", "fa5s.ban")

    # =============================================================================================
    # Gestor de Rollback
    # =============================================================================================
    def _build_rollback_card(self):
        box, lay = make_card("Gestor de Rollback",
                             f"Cada valor que el Arsenal modificó, con su original guardado en "
                             f"{arsenal.STATE_FILE} y el valor actual de Windows. Selecciona filas (Ctrl/Mayús) "
                             "y restáuralas una a una.")
        self.rb_table = make_table(["Ajuste", "Clave de registro", "Valor", "Original (respaldo)",
                                    "Actual en Windows", "Estado"], widths=[190, 330, 150, 140, 140],
                                   empty="Sin respaldos: el Arsenal no ha modificado nada (o ya se revirtió).",
                                   empty_icon="fa5s.undo")
        self.rb_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.rb_table.setMinimumHeight(220)
        self.rb_table.itemSelectionChanged.connect(self._rb_buttons)
        lay.addWidget(self.rb_table)
        acts = QHBoxLayout()
        acts.setSpacing(10)
        self.rb_refresh_btn = self._btn("Actualizar", "fa5s.sync-alt", "Ghost", self.refresh_rollback)
        self.restore_btn = self._btn("Restaurar Seleccionado", "fa5s.undo", "Danger", self._restore_selected)
        self.rb_status = QLabel("")
        self.rb_status.setObjectName("CardText")
        acts.addWidget(self.rb_refresh_btn)
        acts.addWidget(self.restore_btn)
        acts.addWidget(self.rb_status, 1)
        lay.addLayout(acts)
        self._rb_buttons()
        return box

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh_rollback()
        if not self._autoruns_done:
            self._scan_autoruns()

    # =============================================================================================
    # Inventario de inicio (Autoruns): lo que arranca solo con Windows, en solo lectura
    # =============================================================================================
    def _build_autoruns_card(self):
        box, lay = make_card("Inventario de inicio (Autoruns)",
                             "Programas que arrancan solos con Windows: claves Run/RunOnce (HKCU y HKLM, incluida la "
                             "vista de 32 bits) y carpetas Inicio. Solo lectura. ● verde: el ejecutable existe en disco · "
                             "● ámbar: ruta rota o ejecutable fantasma.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self._autoruns_btn = self._btn("Volver a escanear", "fa5s.search", "Ghost", self._scan_autoruns)
        self._autoruns_summary = QLabel("Se escanea al entrar en la página.")
        self._autoruns_summary.setObjectName("Tiny")
        row.addWidget(self._autoruns_btn)
        row.addWidget(self._autoruns_summary, 1)
        self._autoruns_table = make_table(["", "Nombre", "Origen", "Ruta del ejecutable", "Estado"],
                                          widths=[34, 180, 170, 330],
                                          empty="Escaneando las entradas de inicio…", empty_icon="fa5s.rocket")
        self._autoruns_table.setMinimumHeight(200)
        lay.addLayout(row)
        lay.addWidget(self._autoruns_table)
        return box

    def _scan_autoruns(self) -> None:
        if self._autoruns_busy:
            return
        self._autoruns_busy = True
        set_busy(self._autoruns_btn, True, "Escaneando…")

        def done(ok, entries):
            self._autoruns_busy = False
            self._autoruns_done = True
            set_busy(self._autoruns_btn, False)
            if not ok or not isinstance(entries, list):
                self._autoruns_summary.setText(f"No se pudo leer el inicio: {entries}")
                self.app.console.log("x", f"Autoruns: {entries}")
                return
            # Primero lo sospechoso (ruta rota / fantasma), luego por nombre.
            entries = sorted(entries, key=lambda e: (bool(e.get("existe")), str(e.get("nombre", "")).lower()))
            broken = sum(1 for e in entries if not e.get("existe"))
            table = self._autoruns_table
            if not entries:
                table.set_empty_text("No hay programas que arranquen solos con el equipo.", "fa5s.check-circle")
            with frozen(table):
                table.setRowCount(len(entries))
                for r, e in enumerate(entries):
                    exists = bool(e.get("existe"))
                    ruta = str(e.get("ruta") or "")
                    estado = "En disco" if exists else ("Ruta rota" if ruta else "Ruta no determinable")
                    tip = f"{e.get('comando', '')}\n{e.get('ubicacion', '')}"
                    dot = QTableWidgetItem("●")
                    dot.setForeground(QColor(COLORS["ok"] if exists else COLORS["warn"]))
                    dot.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    cells = [dot] + [QTableWidgetItem(v) for v in (str(e.get("nombre", "")), str(e.get("origen", "")),
                                                                    ruta or "—", estado)]
                    if not exists:
                        cells[-1].setForeground(QColor(COLORS["warn"]))
                    for c, item in enumerate(cells):
                        item.setToolTip(tip)
                        table.setItem(r, c, item)
            summary = f"{len(entries)} entradas" + (f" · {broken} con ruta rota o fantasma" if broken else
                                                    " · todas apuntan a archivos existentes")
            self._autoruns_summary.setText(summary)
            self.app.console.log("!" if broken else "~", f"Autoruns: {summary}")

        self.app.run_task(lambda emit: startup_entries(), done, track=False)

    def refresh_rollback(self) -> None:
        if not arsenal.IS_WINDOWS:
            self.rb_table.set_empty_text("El registro de Windows no está disponible en este sistema.", "fa5s.undo")
            return
        self.app.run_task(lambda emit: arsenal.rollback_entries(), self._rb_loaded, track=False)

    def _rb_loaded(self, ok: bool, rows) -> None:
        if not ok or not isinstance(rows, list):
            self.rb_status.setText(f"No se pudo leer el respaldo: {rows}")
            return
        self._rb_rows = rows
        t = self.rb_table
        with frozen(t):
            t.setRowCount(len(rows))
            for r, row in enumerate(rows):
                state = "COINCIDE" if row["matches"] else "MODIFICADO"
                cells = [row["title"], f"{row['hive']}\\{row['subkey']}", row["name"] or "(predeterminado)",
                         _fmt(row["orig_exists"], row["orig_data"], row["orig_type"]),
                         _fmt(row["cur_exists"], row["cur_data"], row["cur_type"]), state]
                for c, v in enumerate(cells):
                    cell = QTableWidgetItem(str(v))
                    if c == 5:
                        cell.setForeground(QColor(COLORS["muted"] if row["matches"] else COLORS["warn"]))
                    t.setItem(r, c, cell)
        modified = sum(1 for r in rows if not r["matches"])
        self.rb_status.setText(f"{len(rows)} valores respaldados · {modified} distintos del original")
        self._rb_buttons()

    def _rb_selected(self) -> List[dict]:
        rows = sorted({i.row() for i in self.rb_table.selectedIndexes()})
        return [self._rb_rows[r] for r in rows if r < len(self._rb_rows)]

    def _rb_buttons(self) -> None:
        sel = self._rb_selected()
        self.restore_btn.setEnabled(bool(sel) and not self._acting)
        self.restore_btn.setToolTip(tech_tip(f"Restaurar {len(sel)} valor(es)", [self._restore_line(r) for r in sel[:8]],
                                             "Se aplica el original con winreg y se quita del respaldo.")
                                    if sel else "Selecciona una o varias filas.")

    @staticmethod
    def _restore_line(row: dict) -> str:
        target = f"{row['hive']}\\{row['subkey']}\\{row['name'] or '(predeterminado)'}"
        return (f"{target} ← {row['orig_data']!r}" if row["orig_exists"] else f"Eliminar {target} (no existía)")

    def _restore_selected(self) -> None:
        sel = self._rb_selected()
        if not sel or self._acting:
            return
        if any(r["admin"] for r in sel) and not getattr(self.app, "admin", False):
            if ConfirmDialog.ask(self.app, "Se requiere Administrador",
                                 "Algunos valores están en HKLM y exigen privilegios de Administrador. ¿Relanzar "
                                 "Lozarus elevado (UAC)? Si cancelas se restaurarán solo los de HKCU.",
                                 confirm_text="Relanzar como Administrador"):
                self.app.relaunch_as_admin()
                return
            sel = [r for r in sel if not r["admin"]]
            if not sel:
                return
        if not ConfirmDialog.ask(self.app, "Restaurar Seleccionado", "Se aplicará exactamente:\n"
                                 + "\n".join(f"• {self._restore_line(r)}" for r in sel) + "\n\n¿Continuar?",
                                 confirm_text="Restaurar", danger=True):
            return
        self._acting = True
        set_busy(self.restore_btn, True, "Restaurando…")
        targets = [(r["tweak"], r["hive"], r["subkey"], r["name"]) for r in sel]

        def work(emit):
            out = []
            for target in targets:
                try:
                    out.append((True, arsenal.restore_value(*target)))
                except Exception as exc:  # noqa: BLE001  (cada fallo se informa por separado)
                    out.append((False, f"{type(exc).__name__}: {exc}"))
            return out

        self.app.run_task(work, lambda ok, res: self._restore_done(sel, ok, res))

    def _restore_done(self, sel: List[dict], ok: bool, res) -> None:
        self._acting = False
        set_busy(self.restore_btn, False)
        results = res if ok and isinstance(res, list) else [(False, str(res))] * len(sel)
        good = 0
        for row, (done, info) in zip(sel, results):
            _emit_event(self.app, source="arsenal", event_type="arsenal.rollback",
                        payload={"op": "restore_value", "tweak": row["tweak"], "ok": done,
                                 "registry": f"{row['hive']}\\{row['subkey']}", "value": row["name"],
                                 "detail": info})
            self.app.console.log("*" if done else "x", f"Rollback: {self._restore_line(row)} → "
                                                       f"{'OK' if done else info}")
            good += done
        flash_aura(self.restore_btn, COLORS["ok"] if good == len(sel) else COLORS["warn"] if good else COLORS["danger"])
        Toast.notify(self.app, "*" if good == len(sel) else "!" if good else "x", "Rollback",
                     f"{good} de {len(sel)} valor(es) restaurados.", "fa5s.undo")
        self.refresh_rollback()
        ars = self.app.pages.get("arsenal")
        if ars is not None:
            ars.refresh()  # badges y Puntuación de Seguridad al día
