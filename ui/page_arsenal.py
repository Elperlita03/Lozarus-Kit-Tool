"""
ui/page_arsenal.py · LOZARUS KIT TOOL

Página ARSENAL & MODO FANTASMA: 12 controles en vivo (privacidad, red/USB, UX y limpieza) con perfiles
en 1 clic y rollback, seguidos de las herramientas del Modo Fantasma (hereda de GhostPage). El motor
(registro + rollback_state.json) vive en modulos/_arsenal.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from modulos import _arsenal as arsenal

from ui.theme import COLORS, badge_qss
from ui.widgets import _emit_event, make_card, set_busy, with_icon
from ui.page_ghost import GhostPage
from ui.dialogs import ConfirmDialog
from ui.chrome import Toast

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

Op = Tuple[str, Optional[str]]  # (apply | revert | purge | debloat | finish_rollback, clave del ajuste)

CARDS = (("privacy", "Privacidad y anti-telemetría", "Modo Fantasma: menos datos tuyos saliendo del equipo."),
         ("network", "Blindaje de red y protección USB", "Modo Búnker: cierra vectores clásicos de la red local "
                                                         "y de los USB."),
         ("ux", "Kit técnico, UX y limpieza rápida", "Explorador sin trampas, menú clásico y limpieza."))
# Perfiles en 1 clic: (clave, texto, icono, tarjeta cuyos ajustes aplica)
PROFILES = (("ghost", "Modo Fantasma (Privacidad)", "fa5s.ghost", "privacy"),
            ("bunker", "Blindaje Búnker (Red y USB)", "fa5s.shield-alt", "network"),
            ("tech", "Kit Técnico (UX y Limpieza)", "fa5s.tools", "ux"),
            ("rollback", "Revertir Todo (Rollback)", "fa5s.undo", ""))
ACTIONS = (("purge", "Purgar Temporales y Caché", "Borra los ficheros no bloqueados de %TEMP% y C:\\Windows\\Temp.",
            "Purgar ahora", "fa5s.broom"),
           ("debloat", "Debloater Rápido", "Quita BingNews, GetHelp, Getstarted, Feedback Hub y Solitaire "
                                           "(Remove-AppxPackage).", "Quitar bloatware", "fa5s.trash-alt"))


class ArsenalPage(GhostPage):
    """
    Matriz de ajustes con badge en vivo, Aplicar/Revertir individual y perfiles en lote; debajo, las
    herramientas del Modo Fantasma (la limpieza de %TEMP% la cubre la purga del Arsenal).
    """
    TOOL_CARDS = tuple(c for c in GhostPage.TOOL_CARDS if c != "_build_temp_card")

    def __init__(self, app: "MainWindow"):
        super().__init__(app, "Arsenal & Modo Fantasma",
                         "12 controles en vivo: privacidad, red/USB, UX y limpieza, más las herramientas del "
                         "Modo Fantasma. Cada ajuste guarda antes el valor original en rollback_state.json "
                         "para poder revertirlo.", "fa5s.user-secret")
        self._snap: Optional[dict] = None
        self._busy = False
        self._rows: Dict[str, dict] = {}       # clave -> {badge, apply, revert} / {badge, run}
        self._profile_badges: Dict[str, QLabel] = {}
        self._profile_btns: Dict[str, QPushButton] = {}

        # --- Perfiles en 1 clic -----------------------------------------------------------------
        bar = QHBoxLayout()
        bar.setSpacing(12)
        for key, text, icon_name, _card in PROFILES:
            btn = QPushButton(text)
            btn.setObjectName("Danger" if key == "rollback" else "Primary")
            btn.setMinimumHeight(52)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            with_icon(btn, icon_name, COLORS["danger"] if key == "rollback" else None, 18)
            btn.clicked.connect(lambda _=False, k=key: self.run_profile(k))
            badge = QLabel("—")
            badge.setStyleSheet(badge_qss(COLORS["faint"], 11))
            bar.addWidget(btn, 1)
            bar.addWidget(badge)
            self._profile_btns[key], self._profile_badges[key] = btn, badge
        self.root.insertLayout(0, bar)  # encima de las herramientas del Modo Fantasma

        # --- Matriz de 12 controles en 3 tarjetas -----------------------------------------------
        for index, (card_key, title, desc) in enumerate(CARDS, 1):
            box, lay = make_card(title, desc)
            grid = QGridLayout()
            grid.setHorizontalSpacing(10)
            grid.setVerticalSpacing(10)
            grid.setColumnStretch(0, 1)
            items = [t for t in arsenal.TWEAKS if t.card == card_key]
            for r, tweak in enumerate(items):
                self._add_tweak_row(grid, r, tweak)
            if card_key == "ux":
                for r, action in enumerate(ACTIONS, len(items)):
                    self._add_action_row(grid, r, *action)
            lay.addLayout(grid)
            self.root.insertWidget(index, box)
        tools = QLabel("Herramientas del Modo Fantasma")
        tools.setObjectName("CardTitle")
        tools.setStyleSheet("margin-top:6px;")
        self.root.insertWidget(len(CARDS) + 1, tools)
        self._render()

    # --- Construcción ---------------------------------------------------------------------------
    @staticmethod
    def _text(title: str, desc: str) -> QVBoxLayout:
        col = QVBoxLayout()
        col.setSpacing(2)
        head = QLabel(title)
        head.setStyleSheet("font-weight:600;")
        sub = QLabel(desc)
        sub.setObjectName("CardText")
        sub.setWordWrap(True)
        col.addWidget(head)
        col.addWidget(sub)
        return col

    @staticmethod
    def _button(text: str, icon_name: str, slot) -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName("Mini")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        with_icon(btn, icon_name, None, 13)
        btn.clicked.connect(slot)
        return btn

    def _add_tweak_row(self, grid: QGridLayout, r: int, tweak) -> None:
        grid.addLayout(self._text(tweak.title + ("  · HKLM" if tweak.admin else ""), tweak.desc), r, 0)
        badge = QLabel()
        apply_btn = self._button("Aplicar", "fa5s.check", lambda: self._execute([("apply", tweak.key)]))
        revert_btn = self._button("Revertir", "fa5s.undo", lambda: self._execute([("revert", tweak.key)]))
        apply_btn.setToolTip("\n".join(arsenal.describe(v) for v in tweak.values))
        for c, w in enumerate((badge, apply_btn, revert_btn), 1):
            grid.addWidget(w, r, c)
        self._rows[tweak.key] = {"badge": badge, "apply": apply_btn, "revert": revert_btn}

    def _add_action_row(self, grid: QGridLayout, r: int, key, title, desc, button, icon_name) -> None:
        grid.addLayout(self._text(title, desc), r, 0)
        badge = QLabel()
        run_btn = self._button(button, icon_name, lambda: self._execute([(key, None)]))
        grid.addWidget(badge, r, 1)
        grid.addWidget(run_btn, r, 2, 1, 2)
        self._rows[key] = {"badge": badge, "run": run_btn, "last": None}

    # --- Estado en vivo -------------------------------------------------------------------------
    def showEvent(self, event) -> None:
        """Al abrir la pestaña relee el estado real del registro (en segundo plano)."""
        super().showEvent(event)
        self.refresh()

    def refresh(self) -> None:
        if self._busy or not arsenal.IS_WINDOWS:
            return
        self.app.run_task(lambda emit: arsenal.snapshot(), self._snapshot_done, track=False)

    def _snapshot_done(self, ok: bool, snap) -> None:
        if ok and isinstance(snap, dict):
            self._snap = snap
        self._render()

    @staticmethod
    def _badge(label: QLabel, text: str, color: str) -> None:
        if label.text() != text:
            label.setText(text)
            label.setStyleSheet(badge_qss(color, 10))

    def _applied(self, key: str) -> bool:
        return bool(self._snap and self._snap["applied"].get(key))

    def _backed_up(self) -> List[str]:
        return list(self._snap["backed_up"]) if self._snap else []

    def _render(self) -> None:
        live = self._snap is not None
        for tweak in arsenal.TWEAKS:
            row, on = self._rows[tweak.key], self._applied(tweak.key)
            if not arsenal.IS_WINDOWS:
                self._badge(row["badge"], "SOLO WINDOWS", COLORS["faint"])
            elif not live:
                self._badge(row["badge"], "LEYENDO…", COLORS["faint"])
            else:
                self._badge(row["badge"], "✔ APLICADO" if on else "POR DEFECTO", COLORS["ok"] if on else COLORS["faint"])
            row["apply"].setEnabled(live and not on and not self._busy)
            row["revert"].setEnabled(live and (on or tweak.key in self._backed_up()) and not self._busy)
        for key, *_rest in ACTIONS:
            row = self._rows[key]
            self._badge(row["badge"], row["last"] or ("LISTO" if arsenal.IS_WINDOWS else "SOLO WINDOWS"),
                        COLORS["ok"] if row["last"] else COLORS["faint"])
            row["run"].setEnabled(arsenal.IS_WINDOWS and not self._busy)
        for key, _text, _icon, card in PROFILES:
            if key == "rollback":
                count, total = len(self._backed_up()), None
            else:
                tweaks = [t for t in arsenal.TWEAKS if t.card == card]
                count, total = sum(self._applied(t.key) for t in tweaks), len(tweaks)
            text = "—" if not live else str(count) if total is None else f"{count}/{total}"
            done = total is not None and count == total
            self._badge(self._profile_badges[key], text, COLORS["ok"] if live and done else
                        COLORS["warn"] if live and count else COLORS["faint"])
            self._profile_btns[key].setEnabled(live and not self._busy)

    # --- Perfiles y ejecución -------------------------------------------------------------------
    def run_profile(self, key: str) -> None:
        if self._snap is None:
            return
        if key == "rollback":
            ops: List[Op] = [("revert", k) for k in self._backed_up() if k in arsenal.BY_KEY]
            if self._backed_up():
                ops.append(("finish_rollback", None))  # limpia rollback_state.json al terminar
        else:
            card = next(c for k, _t, _i, c in PROFILES if k == key)
            ops = [("apply", t.key) for t in arsenal.TWEAKS if t.card == card and not self._applied(t.key)]
            if key == "tech":
                ops.append(("purge", None))
        if not ops:
            Toast.notify(self.app, "*", "Arsenal", "Nada que hacer: el perfil ya está en ese estado.", "fa5s.ghost")
            return
        self._execute(ops, profile=next(t for k, t, _i, _c in PROFILES if k == key))

    @staticmethod
    def _needs_admin(op: Op) -> bool:
        return op[0] in ("apply", "revert") and arsenal.BY_KEY[op[1]].admin

    def _describe(self, op: Op) -> str:
        kind, key = op
        if kind == "purge":
            return "• Purgar los ficheros no bloqueados de %TEMP% y C:\\Windows\\Temp"
        if kind == "debloat":
            return "• Remove-AppxPackage: " + ", ".join(arsenal.BLOATWARE)
        if kind == "finish_rollback":
            return "• Limpiar rollback_state.json (se borra si no queda nada pendiente)"
        tweak = arsenal.BY_KEY[key]
        if kind == "apply":
            return f"• {tweak.title}: " + "; ".join(arsenal.describe(v) for v in tweak.values)
        how = "valor original del respaldo" if key in self._backed_up() else "borrar el valor (por defecto de Windows)"
        return f"• Revertir {tweak.title}: {how}"

    def _execute(self, ops: List[Op], profile: Optional[str] = None) -> None:
        """Elevación (HKLM), una confirmación con lo exacto que se aplicará y ejecución en segundo plano."""
        if self._busy or not ops:
            return
        if not arsenal.IS_WINDOWS:
            Toast.notify(self.app, "!", "Arsenal", "Estos ajustes solo existen en Windows.", "fa5s.ghost")
            return
        admin_ops = [op for op in ops if self._needs_admin(op)]
        if admin_ops and not getattr(self.app, "admin", False):
            rest = len(ops) - len(admin_ops)
            if ConfirmDialog.ask(self.app, "Se requiere Administrador",
                                 f"{len(admin_ops)} cambio(s) modifican HKLM y exigen privilegios de Administrador. "
                                 "¿Relanzar Lozarus elevado (UAC)?"
                                 + (f"\n\nSi cancelas se aplicarán solo los {rest} cambios restantes." if rest else ""),
                                 confirm_text="Relanzar como Administrador"):
                self.app.relaunch_as_admin()
                return
            ops = [op for op in ops if not self._needs_admin(op)]
            if not ops:
                return
        title = profile or {"purge": "Purgar temporales", "debloat": "Debloater rápido"}.get(
            ops[0][0], arsenal.BY_KEY[ops[0][1]].title if ops[0][1] else "Arsenal")
        rollback = all(kind in ("revert", "finish_rollback") for kind, _ in ops)
        if not ConfirmDialog.ask(self.app, title, "Se aplicará exactamente:\n" + "\n".join(map(self._describe, ops))
                                 + "\n\nLos valores originales del registro se guardan antes en rollback_state.json."
                                 "\n¿Continuar?", confirm_text="Revertir" if rollback else "Aplicar",
                                 danger=rollback or any(kind == "debloat" for kind, _ in ops)):
            return
        self._busy = True
        busy_btn = self._profile_btns.get(next((k for k, t, *_ in PROFILES if t == profile), ""))
        if busy_btn is not None:
            set_busy(busy_btn, True, "Aplicando…")
        self._render()
        self.app.log_tactical(f"Arsenal: {title} · {len(ops)} operación(es)")
        funcs = {"apply": lambda k: arsenal.apply(arsenal.BY_KEY[k]),
                 "revert": lambda k: arsenal.revert(arsenal.BY_KEY[k]),
                 "purge": lambda _k: arsenal.purge_temp(), "debloat": lambda _k: arsenal.debloat(),
                 "finish_rollback": lambda _k: arsenal.finish_rollback()}

        def work(emit):
            results = []
            for kind, key in ops:
                try:
                    results.append((True, funcs[kind](key)))
                except Exception as exc:  # noqa: BLE001  (cada fallo se informa por separado)
                    results.append((False, f"{type(exc).__name__}: {exc}"))
            return results, arsenal.snapshot()

        self.app.run_task(work, lambda ok, res: self._done(ops, title, busy_btn, ok, res))

    def _done(self, ops: List[Op], title: str, busy_btn, ok: bool, res) -> None:
        self._busy = False
        if busy_btn is not None:
            set_busy(busy_btn, False)
        if not ok or not isinstance(res, tuple):
            Toast.notify(self.app, "x", title, f"No se pudo completar: {res}", "fa5s.ghost")
            self._render()
            return
        results, self._snap = res
        good, notes, explorer = 0, [], []
        pairs = list(zip(ops, results))
        for (kind, key), (done, info) in pairs:
            if kind == "finish_rollback":
                self._rollback_event(pairs, done, info)
                continue
            _emit_event(self.app, source="arsenal", event_type="arsenal.rollback" if kind == "revert"
                        else "arsenal.toggle", payload={"op": kind, "tweak": key, "ok": done, "detail": info})
            name = arsenal.BY_KEY[key].title if key else title
            self.app.console.log("*" if done else "x", f"Arsenal · {kind} · {name}: {'OK' if done else info}")
            if not done:
                notes.append(f"{name}: {info}")
                continue
            good += 1
            if kind in ("apply", "revert") and arsenal.BY_KEY[key].explorer:
                explorer.append(arsenal.BY_KEY[key].title)
            if kind == "purge":
                mb = info["bytes"] / 1048576
                self._rows["purge"]["last"] = f"{mb:.1f} MB"
                notes.append(f"{info['eliminados']} archivos · {mb:.1f} MB liberados "
                             f"({info['omitidos']} en uso omitidos)")
            elif kind == "debloat":
                self._rows["debloat"]["last"] = f"{len(info['removed'])} QUITADOS"
                notes.append(f"{len(info['removed'])} paquete(s) eliminados" if info["removed"]
                             else "Ningún paquete de la lista estaba instalado")
        changes = sum(1 for kind, _ in ops if kind != "finish_rollback")
        failed = changes - good
        verb = "revertidos" if all(kind in ("revert", "finish_rollback") for kind, _ in ops) else "aplicados"
        head = f"{good} de {changes} cambios {verb}." if changes > 1 else ("Hecho." if good else "Falló.")
        if changes:
            Toast.notify(self.app, "x" if not good else "!" if failed else "*", title,
                         " ".join([head] + notes[:2]), "fa5s.ghost")
        self._render()
        if explorer:  # tras pintar el resultado: el diálogo no bloquea el repintado
            QTimer.singleShot(0, lambda: self._offer_explorer_restart(explorer))

    def _rollback_event(self, pairs: list, done: bool, info) -> None:
        """Resumen de «Revertir Todo» en la Caja Negra: qué se revirtió, qué falló y si el JSON se limpió."""
        reverted = [key for (kind, key), (ok, _i) in pairs if kind == "revert" and ok]
        failed = [key for (kind, key), (ok, _i) in pairs if kind == "revert" and not ok]
        payload = {"op": "rollback_all", "ok": done and not failed, "reverted": reverted, "failed": failed}
        payload.update(info if done else {"error": info})
        _emit_event(self.app, source="arsenal", event_type="arsenal.rollback", payload=payload)
        cleaned = done and info.get("state_file_removed")
        self.app.console.log("*" if cleaned else "!", "Arsenal · Revertir Todo: " + (
            "rollback_state.json limpiado" if cleaned else
            f"quedan respaldos pendientes: {', '.join(info['remaining'])}" if done else f"error al limpiar: {info}"))
        if not reverted and not failed:  # solo había respaldos huérfanos: el Toast general no sale
            Toast.notify(self.app, "*" if cleaned else "x", "Revertir Todo",
                         "Respaldo limpiado." if cleaned else "No se pudo limpiar el respaldo.", "fa5s.undo")

    # --- Reinicio del Explorador ------------------------------------------------------------------
    def _offer_explorer_restart(self, titles: List[str]) -> None:
        if not ConfirmDialog.ask(self.app, "Reiniciar el Explorador",
                                 f"{', '.join(titles)}: el cambio se ve al reiniciar explorer.exe.\n\n"
                                 "La barra de tareas y las ventanas de carpetas desaparecerán unos segundos; "
                                 "tus programas y documentos siguen abiertos. ¿Reiniciar el Explorador ahora?",
                                 confirm_text="Reiniciar Explorador"):
            Toast.notify(self.app, "*", "Explorador", "El cambio se verá al reiniciar el Explorador o la sesión.",
                         "fa5s.sync-alt")
            return
        self.app.log_tactical("Arsenal: reiniciando explorer.exe")
        self.app.run_task(lambda emit: arsenal.restart_explorer(), self._explorer_done)

    def _explorer_done(self, ok: bool, res) -> None:
        good = ok and isinstance(res, dict)
        _emit_event(self.app, source="arsenal", event_type="arsenal.toggle",
                    payload={"op": "restart_explorer", "tweak": None, "ok": good, "detail": res})
        Toast.notify(self.app, "*" if good else "x", "Explorador",
                     f"explorer.exe reiniciado ({res['how']})." if good else f"No se pudo reiniciar: {res}",
                     "fa5s.sync-alt")
