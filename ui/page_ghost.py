"""
ui/page_ghost.py · LOZARUS KIT TOOL

Herramientas del MODO FANTASMA, como mixin de ArsenalPage (page_arsenal.py): trituradora de archivos,
portapapeles anti-clipper (vigilancia, defensa anti-swap y auto-purga), optimización de RAM y purga de
privacidad completa con terminal en vivo. La página que lo usa es también SafeActions: cada acción
confirma lo exacto, corre en segundo plano con spinner, queda en la Caja Negra y avisa con un Toast.

Atributos públicos que leen otras partes: clip_watch_btn / _toggle_clip_watch (perfiles de operación de
gui_qt), _clip_timer y autopurge_btn (panel de salud del Centro de Comando).
"""

from __future__ import annotations

import os
import time
from typing import List

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QFileDialog, QHBoxLayout

from modulos._privacidad import (clear_clipboard, empty_working_sets, is_hijack_swap, looks_sensitive,
                                 read_clipboard_text, shred_file)
from modulos._tacticas import GHOST_STEPS, ghost_preview

from ui._compat import ObservationQuality
from ui.widgets import _emit_event, set_busy
from ui.dialogs import TerminalDialog
from ui.kit import Tile, action_button

CLIP_POLL_MS = 600       # caza un intercambio de dirección cripto en < 1,5 s y vacía en el acto
AUTOPURGE_MS = 15000     # dato sensible: el portapapeles se vacía a los 15 s si sigue igual


class GhostTools:
    """Mixin: requiere self.app y los métodos de ui.kit.SafeActions."""

    def _init_ghost_tools(self) -> None:
        self._clip_last = None
        self._clip_last_time = None
        self._clip_timer = QTimer(self)
        self._clip_timer.setInterval(CLIP_POLL_MS)
        self._clip_timer.timeout.connect(self._clip_tick)

    def _build_ghost_tiles(self) -> List[Tile]:
        shred = Tile("fa5s.eraser", "Trituradora de archivos",
                     "Sobrescribe el archivo con bytes aleatorios y lo elimina tras confirmar la ruta exacta. "
                     "Irreversible; en discos SSD la sobrescritura no garantiza el borrado físico.")
        self.shred_btn = shred.add_action(action_button("Elegir y triturar", "fa5s.eraser", "Danger", self._shred))

        clip = Tile("fa5s.clipboard", "Portapapeles anti-clipper",
                    "Avisa si copias algo que parece sensible y, si una dirección cripto se sustituye por otra en "
                    "menos de 1,5 s, vacía el portapapeles y lo registra como crítico.")
        toggles = QHBoxLayout()
        toggles.setSpacing(8)
        self.clip_watch_btn = action_button("Vigilar: OFF", "fa5s.binoculars", "Toggle")
        self.clip_watch_btn.setCheckable(True)
        self.clip_watch_btn.clicked.connect(self._toggle_clip_watch)
        self.autopurge_btn = action_button("Auto-purgar 15 s: OFF", "fa5s.hourglass-half", "Toggle")
        self.autopurge_btn.setCheckable(True)
        self.autopurge_btn.clicked.connect(self._toggle_autopurge)
        toggles.addWidget(self.clip_watch_btn)
        toggles.addWidget(self.autopurge_btn)
        toggles.addStretch(1)
        clip.body.addLayout(toggles)
        self.clip_clear_btn = clip.add_action(action_button("Vaciar ahora", "fa5s.clipboard", "Ghost",
                                                            self._clear_clipboard))

        purge = Tile("fa5s.ghost", "Purga de privacidad completa",
                     " · ".join(label for _k, label, *_ in GHOST_STEPS) + ". Con recuento previo y terminal en vivo.")
        self.ghost_btn = purge.add_action(action_button("Ejecutar Modo Fantasma", "fa5s.ghost", "Danger", self._run))
        return [shred, clip, purge]

    # --- Trituradora ------------------------------------------------------------------------------
    def _shred(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self.app, "Selecciona el archivo a triturar", os.path.expanduser("~"))
        if not path or not self.confirm_exact("Triturar archivo", "Se sobrescribirá con bytes aleatorios y se borrará "
                                              "DEFINITIVAMENTE este archivo:", [path],
                                              footer="Esta acción no se puede deshacer.", confirm_text="Triturar"):
            return
        name = os.path.basename(path)
        self.app.log_tactical(f"Triturando archivo: {name}")

        def done(ok, res):
            good = ok and isinstance(res, dict) and res.get("ok")
            err = res.get("error") if isinstance(res, dict) else res
            self.finish(self.shred_btn, "*" if good else "x", "Trituradora",
                        f"{name} triturado ({res['bytes']} bytes · {res['passes']} pasada/s)." if good else f"{name}: {err}",
                        "fa5s.eraser", source="fantasma:trituradora", event_type="privacy.file_shredded",
                        payload={"name": name, "ok": bool(good), "bytes": res.get("bytes") if good else 0,
                                 "error": "" if good else str(err)})

        self.run_action(self.shred_btn, "Triturando…", lambda emit: shred_file(path), done)

    # --- Portapapeles (anti-clipper) --------------------------------------------------------------
    def _clear_clipboard(self) -> None:
        ok, msg = clear_clipboard()
        self._clip_last = None
        self.finish(self.clip_clear_btn, "*" if ok else "x", "Portapapeles", msg, "fa5s.clipboard",
                    source="fantasma:portapapeles", event_type="clipboard.cleared", payload={"ok": ok, "detail": msg})

    def _toggle_clip_watch(self) -> None:
        on = self.clip_watch_btn.isChecked()
        self.clip_watch_btn.setText("Vigilar: " + ("ON" if on else "OFF"))
        if on:
            self._clip_last = read_clipboard_text()  # referencia inicial: no avisa de lo ya copiado
            self._clip_last_time = time.monotonic()
            self._clip_timer.start()
            self.app.log_tactical("Vigilancia del portapapeles activada (anti-clipper)")
        else:
            self._clip_timer.stop()
            self.app.console.log("~", "Vigilancia del portapapeles detenida")
        _emit_event(self.app, source="fantasma:portapapeles", event_type="clipboard.watch_toggled",
                    payload={"active": on, "autopurge": self.autopurge_btn.isChecked()})

    def _toggle_autopurge(self) -> None:
        self.autopurge_btn.setText("Auto-purgar 15 s: " + ("ON" if self.autopurge_btn.isChecked() else "OFF"))

    def _clip_tick(self) -> None:
        text = read_clipboard_text()
        if text is None or text == self._clip_last:
            return
        now = time.monotonic()
        prev, prev_t = self._clip_last, self._clip_last_time
        self._clip_last, self._clip_last_time = text, now
        delta = (now - prev_t) if prev_t is not None else None
        if is_hijack_swap(prev, text, delta):  # 1) defensa anti-swap: vaciar YA
            clear_clipboard()
            self._clip_last = None
            self.app.console.log("x", "¡Clipper bloqueado! El portapapeles cambió de dirección cripto; se vació para "
                                      "que no pegaras la del atacante.")
            self.app.record_alert("x", "Clipper bloqueado: el portapapeles cambió de dirección cripto y se vació en "
                                       "el acto.", module="arsenal")
            _emit_event(self.app, source="fantasma:portapapeles", event_type="clipboard.hijack_blocked",
                        observation=(ObservationQuality.COMPLETE if ObservationQuality else None),
                        payload={"motivo": "intercambio de dirección cripto en <1,5 s",
                                 "delta_s": round(delta, 2) if delta is not None else None})
            return
        sensitive, label = looks_sensitive(text)  # 2) clasificación, aviso y auto-purga opcional
        if sensitive:
            self.app.console.log("!", f"Portapapeles: contenido sensible detectado — {label}")
            self.app.record_alert("!", f"Portapapeles: contenido sensible — {label}", module="arsenal")
            _emit_event(self.app, source="fantasma:portapapeles", event_type="clipboard.sensitive",
                        payload={"clasificacion": label, "longitud": len(text)})
            if self.autopurge_btn.isChecked():
                self.app.console.log("~", "Auto-purga programada: el portapapeles se vaciará en 15 s si sigue igual.")
                QTimer.singleShot(AUTOPURGE_MS, lambda s=text: self._autopurge(s))

    def _autopurge(self, snapshot) -> None:
        if read_clipboard_text() != snapshot:
            return  # el contenido ya cambió: no se toca lo que la persona copió después
        ok, _msg = clear_clipboard()
        if ok:
            self._clip_last = None
            self.app.console.log("*", "Auto-purga: portapapeles vaciado (dato sensible, 15 s).")
            _emit_event(self.app, source="fantasma:portapapeles", event_type="clipboard.auto_purged",
                        payload={"tras_segundos": AUTOPURGE_MS // 1000})

    # --- RAM (working sets) -----------------------------------------------------------------------
    def _optimize_ram(self, button) -> None:
        self.app.log_tactical("Optimizando RAM: vaciando working sets de los procesos del usuario")

        def done(ok, res):
            good = ok and isinstance(res, dict) and res.get("ok")
            text = (f"{res['liberado_mb']} MB liberados en {res['procesos']} procesos ({res['omitidos']} omitidos)."
                    if good else f"No disponible: {res.get('error') if isinstance(res, dict) else res}")
            self.finish(button, "*" if good else "x", "Optimizar RAM", text, "fa5s.memory", source="fantasma:ram",
                        event_type="privacy.ram_optimized",
                        payload={k: res.get(k) for k in ("liberado_mb", "procesos", "omitidos")} if good
                        else {"error": text})
            if good:
                self._set_action_result("ram", f"{res['liberado_mb']} MB")

        self.run_action(button, "Optimizando…", lambda emit: empty_working_sets(), done)

    def _set_action_result(self, key: str, text: str) -> None:
        """Gancho: la página muestra el último resultado en la baldosa de la acción."""

    # --- Purga de privacidad completa -------------------------------------------------------------
    def _run(self) -> None:
        self.run_action(self.ghost_btn, "Calculando…", lambda emit: ghost_preview(), self._previewed)

    def _previewed(self, ok: bool, counts) -> None:
        counts = counts if ok and isinstance(counts, dict) else {}
        counted = bool(counts.get("ok"))  # True solo si el recuento se calculó de verdad

        def n(key):  # «?» cuando el recuento no se pudo obtener (desconocido, no 0)
            return counts.get(key, 0) if counted else "?"

        admin = bool(getattr(self.app, "admin", False))
        steps = [label + (" (requiere Administrador: se omitirá)" if needs_admin and not admin else "")
                 for _k, label, needs_admin, _d, _r in GHOST_STEPS]
        intro = (f"Borra de ESTE equipo, sin posibilidad de deshacer: {n('recientes')} archivo(s) reciente(s), "
                 f"papelera ({n('papelera')}) y temporales ({n('temporales')}), además de:")
        footer = ("Es limpieza de privacidad: no toca tus documentos." if counted else
                  "No se pudo calcular el recuento: se limpiará lo que haya.")
        if not self.confirm_exact("Activar Modo Fantasma", intro, steps, footer=footer, confirm_text="Limpiar ahora"):
            self.app.console.log("~", "Modo Fantasma cancelado")
            return
        options = {k: True for k, _l, needs_admin, _d, _r in GHOST_STEPS if not needs_admin or admin}
        self.app.log_tactical("Modo Fantasma: iniciando purga de privacidad del equipo")
        set_busy(self.ghost_btn, True, "Purgando…")
        term = TerminalDialog(self.app, "MODO FANTASMA · purga en curso")
        term.show()
        self.app.run_ghost(options, term, self._ghost_done)

    def _ghost_done(self, ok: bool, res) -> None:
        set_busy(self.ghost_btn, False)
        steps = res.get("steps", []) if ok and isinstance(res, dict) else []
        good = sum(1 for s in steps if s.get("ok"))
        kind = "*" if ok and good == len(steps) else "!" if good else "x"
        text = f"{good} de {len(steps)} pasos completados." if ok else f"No se pudo completar: {res}"
        self.finish(self.ghost_btn, kind, "Modo Fantasma", text, "fa5s.ghost", source="fantasma:purga",
                    event_type="privacy.ghost_purge", payload={"ok": ok, "steps": steps})
