"""
ui/page_arsenal.py · LOZARUS KIT TOOL

Página ARSENAL & MODO FANTASMA (endurecimiento reversible):
  · Perfiles en 1 clic (Modo Fantasma, Blindaje Búnker, Kit Técnico y Revertir todo) con su progreso.
  · Tres tarjetas: Privacidad y Telemetría, Blindaje de Red / USB y Kit Técnico de Optimización UX. Cada
    ajuste lee el estado REAL de Windows al mostrar la página (✔ APLICADO / POR DEFECTO) y se aplica o
    revierte de forma individual: antes de escribir, el valor original se guarda en rollback_state.json.
  · Herramientas del Modo Fantasma (trituradora, portapapeles anti-clipper, purga completa: ui/page_ghost.py).
Motor: modulos/_arsenal.py (registro + rollback). Todo cambio exige confirmación con lo exacto, corre en
segundo plano y queda en la Caja Negra con aviso flotante.
"""

from __future__ import annotations

import os
import sys
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import psutil
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton

from modulos import _arsenal as arsenal

from ui.theme import COLORS
from ui.widgets import Page, _emit_event, flash_aura, make_card, tech_tip
from ui.chrome import Toast
from ui.dialogs import ConfirmDialog
from ui.kit import HeaderStatus, SafeActions, Tile, action_button
from ui.page_ghost import GhostTools

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

Op = Tuple[str, Optional[str]]  # (apply | revert | purge | debloat | finish_rollback, clave del ajuste)

CARDS = (("privacy", "Privacidad y Telemetría",
          "Menos datos tuyos saliendo del equipo: telemetría, búsqueda web, identificador publicitario e historial."),
         ("network", "Blindaje de Red / USB",
          "Cierra vectores clásicos de la red local (envenenamiento de nombres, proxy falso, SMBv1) y de los USB."),
         ("ux", "Kit Técnico de Optimización UX",
          "Explorador sin trampas, menú clásico, limpieza y utilidades para el técnico."))
# Perfiles en 1 clic: (clave, título, icono, tarjeta cuyos ajustes aplica, descripción)
PROFILES = (("ghost", "Modo Fantasma", "fa5s.ghost", "privacy", "Aplica los ajustes de privacidad y telemetría."),
            ("bunker", "Blindaje Búnker", "fa5s.shield-alt", "network", "Cierra LLMNR, AutoRun, SMBv1 y WPAD."),
            ("tech", "Kit Técnico", "fa5s.tools", "ux", "UX del Explorador y purga de temporales."),
            ("rollback", "Revertir todo", "fa5s.undo", "", "Restaura cada valor original desde rollback_state.json."))
TWEAK_ICONS = {"telemetry": "fa5s.satellite", "bing": "fa5s.search", "adid": "fa5s.ad", "activity": "fa5s.history",
               "llmnr": "fa5s.broadcast-tower", "autorun": "fa5s.compact-disc", "smb1": "fa5s.server",
               "wpad": "fa5s.route", "extensions": "fa5s.file-code", "classic_menu": "fa5s.mouse-pointer"}
# Acciones sin estado del Kit Técnico: (clave, título, descripción, botón, icono)
ACTIONS = (("purge", "Purgar temporales y caché", "Borra los ficheros no bloqueados de %TEMP% y C:\\Windows\\Temp.",
            "Purgar ahora", "fa5s.broom"),
           ("debloat", "Debloater rápido", "Quita BingNews, GetHelp, Getstarted, Feedback Hub y Solitaire "
                                           "(Remove-AppxPackage, solo usuario actual).", "Quitar bloatware",
            "fa5s.trash-alt"),
           ("ram", "Optimizar RAM", "Recorta el working set de los procesos del usuario y mide los MB liberados. "
                                    "Temporal y sin privilegios.", "Optimizar", "fa5s.memory"),
           ("deps", "Dependencias de Lozarus", "Verifica e instala lo que falte de requirements.txt con este mismo "
                                               "Python (necesita internet).", "Verificar", "fa5s.box-open"))
SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:") + "\\"
HEALTH_REFRESH_S = 15


class ArsenalPage(SafeActions, GhostTools, Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Arsenal & Modo Fantasma",
                         "Endurecimiento reversible: privacidad y telemetría, blindaje de red/USB y kit técnico. Cada "
                         "ajuste lee el estado real de Windows, guarda el valor original en rollback_state.json y se "
                         "aplica o revierte de forma individual.", "fa5s.user-secret")
        self.app = app
        self._snap: Optional[dict] = None       # lo leen la Puntuación de Seguridad y el informe
        self._busy = False
        self._rows: Dict[str, dict] = {}        # clave -> {tile, apply, revert} / {tile, run, last}
        self._profile_tiles: Dict[str, Tile] = {}
        self._profile_btns: Dict[str, QPushButton] = {}
        self._health_at: Optional[float] = None
        self._init_ghost_tools()

        self.header_status = HeaderStatus()
        self.add_header_widget(self.header_status)
        self.root.addLayout(self._build_profiles())
        for card_key, title, desc in CARDS:
            self.root.addWidget(self._build_category(card_key, title, desc))
        box, lay = make_card("Herramientas del Modo Fantasma",
                             "Privacidad inmediata sobre ESTE equipo. Las acciones destructivas piden confirmación con "
                             "la ruta o los pasos exactos.")
        tools = QHBoxLayout()
        tools.setSpacing(12)
        for tile in self._build_ghost_tiles():
            tools.addWidget(tile, 1)
        lay.addLayout(tools)
        self.root.addWidget(box)
        self.root.addStretch(1)
        self._render()
        QTimer.singleShot(0, self.refresh)  # la Puntuación de Seguridad lo necesita sin abrir la pestaña

    # =============================================================================================
    # Construcción
    # =============================================================================================
    def _build_profiles(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        for key, title, icon_name, _card, desc in PROFILES:
            tile = Tile(icon_name, title, desc, level="card")
            rollback = key == "rollback"
            btn = tile.add_action(action_button("Revertir todo" if rollback else "Aplicar perfil",
                                                "fa5s.undo" if rollback else "fa5s.bolt",
                                                "Danger" if rollback else "Primary",
                                                lambda _=False, k=key: self.run_profile(k)))
            self._profile_tiles[key], self._profile_btns[key] = tile, btn
            row.addWidget(tile, 1)
        return row

    def _build_category(self, card_key: str, title: str, desc: str):
        box, lay = make_card(title, desc)
        if card_key == "ux":
            self.health_label = QLabel("Equipo: leyendo disco y batería…")
            self.health_label.setObjectName("Tiny")
            lay.addWidget(self.health_label)
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        tiles = [self._tweak_tile(t) for t in arsenal.TWEAKS if t.card == card_key]
        if card_key == "ux":
            tiles += [self._action_tile(*action) for action in ACTIONS]
        for i, tile in enumerate(tiles):
            grid.addWidget(tile, i // 2, i % 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        lay.addLayout(grid)
        return box

    def _tweak_tile(self, tweak) -> Tile:
        tile = Tile(TWEAK_ICONS.get(tweak.key, "fa5s.cog"), tweak.title, tweak.desc)
        apply_btn = tile.add_action(action_button("Aplicar", "fa5s.check", "Mini",
                                                  lambda: self._execute([("apply", tweak.key)], button=apply_btn), 12))
        revert_btn = tile.add_action(action_button("Revertir", "fa5s.undo", "Mini",
                                                   lambda: self._execute([("revert", tweak.key)], button=revert_btn), 12))
        notes = ["el valor actual se guarda antes en rollback_state.json"]
        notes += ["requiere Administrador"] * tweak.admin + ["se ve tras reiniciar el Explorador"] * tweak.explorer
        apply_btn.setToolTip(tech_tip(f"Aplicar · {tweak.title}", [arsenal.describe(v) for v in tweak.values],
                                      "; ".join(notes)[:1].upper() + "; ".join(notes)[1:] + "."))
        self._rows[tweak.key] = {"tile": tile, "apply": apply_btn, "revert": revert_btn}
        return tile

    def _action_tile(self, key: str, title: str, desc: str, button: str, icon_name: str) -> Tile:
        tile = Tile(icon_name, title, desc)
        run_btn = tile.add_action(action_button(button, icon_name, "Mini", lambda: self._run_action_tile(key, run_btn), 12))
        tips = {"purge": tech_tip("Purgar temporales", [arsenal.temp_dir(), r"%SystemRoot%\Temp"],
                                  "Solo ficheros no bloqueados; los que estén en uso se omiten."),
                "debloat": tech_tip("Debloater (PowerShell)", [f"Get-AppxPackage -Name {n} | Remove-AppxPackage"
                                                               for n in arsenal.BLOATWARE],
                                    "Solo para el usuario actual. Se reinstalan desde Microsoft Store."),
                "ram": tech_tip("Optimizar RAM", ["EmptyWorkingSet(proceso) · procesos del usuario"],
                                "Sin privilegios: los procesos del sistema se omiten."),
                "deps": tech_tip("Dependencias", [f"{os.path.basename(sys.executable)} -m pip install -r "
                                                  "requirements.txt"], arsenal.REQUIREMENTS_PATH)}
        run_btn.setToolTip(tips[key])
        self._rows[key] = {"tile": tile, "run": run_btn, "last": None}
        return tile

    def _run_action_tile(self, key: str, button: QPushButton) -> None:
        if key in ("purge", "debloat"):
            self._execute([(key, None)], button=button)
        elif key == "ram":
            self._optimize_ram(button)
        else:
            self._install_dependencies(button)

    # =============================================================================================
    # Estado en vivo
    # =============================================================================================
    def showEvent(self, event) -> None:
        """Al abrir la pestaña relee el estado real del registro y la salud del equipo (en segundo plano)."""
        super().showEvent(event)
        self.refresh()
        if self._health_at is None or time.monotonic() - self._health_at > HEALTH_REFRESH_S:
            self._refresh_health()

    def refresh(self) -> None:
        if self._busy or not arsenal.IS_WINDOWS:
            self._render()
            return
        self.app.run_task(lambda emit: arsenal.snapshot(), self._snapshot_done, track=False)

    def _snapshot_done(self, ok: bool, snap) -> None:
        if ok and isinstance(snap, dict):
            self._snap = snap
        self._render()

    def _refresh_health(self) -> None:
        self._health_at = time.monotonic()

        def read(emit):
            parts = []
            try:
                du = psutil.disk_usage(SYSTEM_DRIVE)
                parts.append(f"Disco {SYSTEM_DRIVE[:2]} {du.free / 1024 ** 3:.1f} GB libres de "
                             f"{du.total / 1024 ** 3:.1f} GB ({du.free / du.total * 100:.0f} %)")
            except Exception:  # noqa: BLE001
                parts.append(f"Disco {SYSTEM_DRIVE[:2]} no disponible")
            try:
                batt = psutil.sensors_battery()
                parts.append("Sin batería (equipo de sobremesa)" if batt is None else
                             f"Batería: {batt.percent:.0f} %" + (" · cargando" if batt.power_plugged else ""))
            except Exception:  # noqa: BLE001
                parts.append("Batería: no disponible")
            return "Equipo · " + " · ".join(parts)

        self.app.run_task(read, lambda ok, text: self.health_label.setText(text if ok else f"Equipo: {text}"),
                          track=False)

    def _busy_changed(self) -> None:
        self._refresh_status()

    def _applied(self, key: str) -> bool:
        return bool(self._snap and self._snap["applied"].get(key))

    def _backed_up(self) -> List[str]:
        return list(self._snap["backed_up"]) if self._snap else []

    def _refresh_status(self) -> None:
        total = len(arsenal.TWEAKS)
        if self.running:
            self.header_status.set_state(f"APLICANDO · {self.running}", COLORS["accent"])
        elif not arsenal.IS_WINDOWS:
            self.header_status.set_state("SOLO WINDOWS", COLORS["faint"], "El Arsenal ajusta el registro de Windows.")
        elif self._snap is None:
            self.header_status.set_state("LEYENDO REGISTRO", COLORS["faint"])
        else:
            applied = sum(self._snap["applied"].values())
            tip = f"{len(self._backed_up())} respaldo(s) en {arsenal.STATE_FILE}"
            if applied == total:
                self.header_status.set_state(f"BLINDADO · {applied}/{total}", COLORS["ok"], tip)
            else:
                self.header_status.set_state(f"{applied}/{total} APLICADOS", COLORS["warn"] if applied else COLORS["faint"],
                                             tip)
        self.header_status.set_admin(bool(getattr(self.app, "admin", False)))

    def _render(self) -> None:
        live = self._snap is not None
        backed = self._backed_up()
        for tweak in arsenal.TWEAKS:
            row, on = self._rows[tweak.key], self._applied(tweak.key)
            tile = row["tile"]
            if not arsenal.IS_WINDOWS:
                tile.set_pill("SOLO WINDOWS", COLORS["faint"])
            elif not live:
                tile.set_pill("LEYENDO…", COLORS["faint"])
            else:
                tile.set_pill("✔ APLICADO" if on else "POR DEFECTO", COLORS["ok"] if on else COLORS["faint"])
            note = ["HKLM · Administrador" if tweak.admin else "HKCU"]
            if tweak.key in backed:
                note.append("↺ respaldo guardado")
            if tweak.explorer:
                note.append("Explorador")
            tile.set_note(" · ".join(note))
            for btn, enabled in ((row["apply"], live and not on), (row["revert"], live and (on or tweak.key in backed))):
                if not btn.property("busy"):
                    btn.setEnabled(enabled and not self._busy)
            row["revert"].setToolTip(self._revert_tip(tweak))
        for key, *_rest in ACTIONS:
            row = self._rows[key]
            windows_only = key in ("purge", "debloat")
            ready = not windows_only or arsenal.IS_WINDOWS
            row["tile"].set_pill(row["last"] or ("" if ready else "SOLO WINDOWS"),
                                 COLORS["ok"] if row["last"] else COLORS["faint"])
            if not row["run"].property("busy"):
                row["run"].setEnabled(ready and not self._busy)
        for key, _title, _icon, card, _desc in PROFILES:
            tile, btn = self._profile_tiles[key], self._profile_btns[key]
            if key == "rollback":
                count = len(backed)
                tile.set_pill(("SIN RESPALDOS" if not count else "1 RESPALDO" if count == 1 else f"{count} RESPALDOS")
                              if live else "", COLORS["warn"] if count else COLORS["faint"])
                tile.set_note("Nada que revertir." if live and not count else
                              f"{count} ajuste(s) con su valor original guardado." if live else "")
            else:
                tweaks = [t for t in arsenal.TWEAKS if t.card == card]
                count = sum(self._applied(t.key) for t in tweaks)
                done = count == len(tweaks)
                tile.set_pill(f"{count}/{len(tweaks)}" if live else "",
                              COLORS["ok"] if done else COLORS["warn"] if count else COLORS["faint"])
                tile.set_note(("Perfil completo." if done else f"Faltan {len(tweaks) - count} ajuste(s).") if live else
                              ("Solo Windows." if not arsenal.IS_WINDOWS else "Leyendo el registro…"))
            if not btn.property("busy"):
                btn.setEnabled(live and not self._busy)
            btn.setToolTip(self._profile_tip(key, card))
        self._refresh_status()

    def _set_action_result(self, key: str, text: str) -> None:
        self._rows[key]["last"] = text
        self._render()

    def _revert_tip(self, tweak) -> str:
        if tweak.key in self._backed_up():
            return tech_tip(f"Revertir · {tweak.title}", [f"{h}\\{s}\\{n or '(predeterminado)'} ← valor original"
                                                         for h, s, n, _d in tweak.values],
                            f"Desde el respaldo: {arsenal.STATE_FILE}")
        lines = [f"Eliminar {h}\\{s}\\{n or '(predeterminado)'}" for h, s, n, _d in tweak.values]
        lines += [f"Eliminar clave {h}\\{s}" for h, s in tweak.own_keys]
        return tech_tip(f"Revertir · {tweak.title}", lines, "Sin respaldo de Lozarus: vuelve al comportamiento "
                                                             "por defecto de Windows.")

    def _profile_tip(self, key: str, card: str) -> str:
        if key == "rollback":
            return tech_tip("Revertir todo (rollback)", [arsenal.STATE_FILE],
                            f"Restaura {len(self._backed_up())} respaldo(s) y borra el fichero al terminar.")
        lines = [arsenal.describe(v) for t in arsenal.TWEAKS if t.card == card for v in t.values]
        if key == "tech":
            lines.append("Purgar %TEMP% y %SystemRoot%\\Temp")
        return tech_tip(next(t for k, t, *_ in PROFILES if k == key), lines,
                        "Solo se aplica lo que falta; los originales se guardan en rollback_state.json.")

    # =============================================================================================
    # Perfiles y ejecución
    # =============================================================================================
    def run_profile(self, key: str) -> None:
        if self._snap is None:
            return
        if key == "rollback":
            ops: List[Op] = [("revert", k) for k in self._backed_up() if k in arsenal.BY_KEY]
            if self._backed_up():
                ops.append(("finish_rollback", None))  # limpia rollback_state.json al terminar
        else:
            card = next(c for k, _t, _i, c, _d in PROFILES if k == key)
            ops = [("apply", t.key) for t in arsenal.TWEAKS if t.card == card and not self._applied(t.key)]
            if key == "tech":
                ops.append(("purge", None))
        if not ops:
            Toast.notify(self.app, "*", "Arsenal", "Nada que hacer: el perfil ya está en ese estado.", "fa5s.ghost")
            return
        self._execute(ops, profile=next(t for k, t, *_ in PROFILES if k == key), button=self._profile_btns[key])

    @staticmethod
    def _needs_admin(op: Op) -> bool:
        return op[0] in ("apply", "revert") and arsenal.BY_KEY[op[1]].admin

    def _describe(self, op: Op) -> List[str]:
        """Líneas EXACTAS de la confirmación para una operación."""
        kind, key = op
        if kind == "purge":
            return [f"Purgar los ficheros no bloqueados de {arsenal.temp_dir()} y %SystemRoot%\\Temp"]
        if kind == "debloat":
            return [f"Get-AppxPackage -Name {n} | Remove-AppxPackage" for n in arsenal.BLOATWARE]
        if kind == "finish_rollback":
            return [f"Limpiar {arsenal.STATE_FILE} (se borra si no queda nada pendiente)"]
        tweak = arsenal.BY_KEY[key]
        if kind == "apply":
            return [f"{tweak.title}: {arsenal.describe(v)}" for v in tweak.values]
        if key in self._backed_up():
            return [f"Revertir {tweak.title}: {h}\\{s}\\{n or '(predeterminado)'} ← valor original del respaldo"
                    for h, s, n, _d in tweak.values]
        return [f"Revertir {tweak.title}: eliminar {h}\\{s}\\{n or '(predeterminado)'} (por defecto de Windows)"
                for h, s, n, _d in tweak.values]

    def _execute(self, ops: List[Op], profile: Optional[str] = None, button: Optional[QPushButton] = None) -> None:
        """Elevación (HKLM) → una confirmación con lo exacto → ejecución en segundo plano con spinner."""
        if self._busy or not ops:
            return
        if not arsenal.IS_WINDOWS:
            Toast.notify(self.app, "!", "Arsenal", "Estos ajustes solo existen en Windows.", "fa5s.ghost")
            return
        title = profile or {"purge": "Purgar temporales", "debloat": "Debloater rápido"}.get(
            ops[0][0], arsenal.BY_KEY[ops[0][1]].title if ops[0][1] else "Arsenal")
        admin_ops = [op for op in ops if self._needs_admin(op)]
        if admin_ops and not getattr(self.app, "admin", False):
            rest = [op for op in ops if not self._needs_admin(op)]
            self.app.console.log("!", f"{title}: {len(admin_ops)} cambio(s) en HKLM requieren Administrador")
            if ConfirmDialog.ask(self.app, "Se requiere Administrador",
                                 f"{len(admin_ops)} cambio(s) escriben en HKLM y exigen privilegios de Administrador. "
                                 "¿Relanzar Lozarus elevado (UAC)?" +
                                 (f"\n\nSi cancelas se aplicarán solo los {len(rest)} cambio(s) de HKCU." if rest else ""),
                                 confirm_text="Relanzar como Administrador"):
                self.app.relaunch_as_admin()
                return
            if not rest:
                return
            ops = rest
        rollback = all(kind in ("revert", "finish_rollback") for kind, _ in ops)
        lines = [line for op in ops for line in self._describe(op)]
        footer = ("Los valores originales del registro se guardan antes en rollback_state.json."
                  if not rollback else "Se restauran los valores originales guardados por Lozarus.")
        if not self.confirm_exact(title, "Operaciones del Arsenal sobre este equipo:", lines, footer=footer,
                                  confirm_text="Revertir" if rollback else "Aplicar",
                                  danger=rollback or any(kind == "debloat" for kind, _ in ops)):
            return
        self._busy = True
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

        self.run_action(button, "Revirtiendo…" if rollback else "Aplicando…", work,
                        lambda ok, res: self._done(ops, title, button, ok, res))

    def _done(self, ops: List[Op], title: str, button, ok: bool, res) -> None:
        self._busy = False
        if not ok or not isinstance(res, tuple):
            if button is not None:
                flash_aura(button, COLORS["danger"])
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
                notes.append(f"{info['eliminados']} archivos · {mb:.1f} MB liberados ({info['omitidos']} en uso omitidos)")
            elif kind == "debloat":
                self._rows["debloat"]["last"] = f"{len(info['removed'])} QUITADOS"
                notes.append(f"{len(info['removed'])} paquete(s) eliminados" if info["removed"]
                             else "Ningún paquete de la lista estaba instalado")
        changes = sum(1 for kind, _ in ops if kind != "finish_rollback")
        failed = changes - good
        verb = "revertidos" if all(kind in ("revert", "finish_rollback") for kind, _ in ops) else "aplicados"
        head = f"{good} de {changes} cambios {verb}." if changes > 1 else ("Hecho." if good else "Falló.")
        if button is not None:
            flash_aura(button, COLORS["danger"] if not good else COLORS["warn"] if failed else COLORS["ok"])
        if changes:
            Toast.notify(self.app, "x" if not good else "!" if failed else "*", title, " ".join([head] + notes[:2]),
                         "fa5s.ghost")
        self._render()
        audit = getattr(self.app, "pages", {}).get("auditoria")
        if audit is not None and hasattr(audit, "_update_counters"):
            audit._update_counters()  # la Puntuación Global incluye el Arsenal
        if explorer:  # tras pintar el resultado: el diálogo no bloquea el repintado
            QTimer.singleShot(0, lambda: self._offer_explorer_restart(explorer))

    def _rollback_event(self, pairs: list, done: bool, info) -> None:
        """Resumen de «Revertir todo» en la Caja Negra: qué se revirtió, qué falló y si el JSON se limpió."""
        reverted = [key for (kind, key), (ok, _i) in pairs if kind == "revert" and ok]
        failed = [key for (kind, key), (ok, _i) in pairs if kind == "revert" and not ok]
        payload = {"op": "rollback_all", "ok": done and not failed, "reverted": reverted, "failed": failed}
        payload.update(info if done else {"error": info})
        _emit_event(self.app, source="arsenal", event_type="arsenal.rollback", payload=payload)
        cleaned = done and info.get("state_file_removed")
        self.app.console.log("*" if cleaned else "!", "Arsenal · Revertir todo: " + (
            "rollback_state.json limpiado" if cleaned else
            f"quedan respaldos pendientes: {', '.join(info['remaining'])}" if done else f"error al limpiar: {info}"))
        if not reverted and not failed:  # solo había respaldos huérfanos: el Toast general no sale
            Toast.notify(self.app, "*" if cleaned else "x", "Revertir todo",
                         "Respaldo limpiado." if cleaned else "No se pudo limpiar el respaldo.", "fa5s.undo")

    # =============================================================================================
    # Kit Técnico: dependencias y reinicio del Explorador
    # =============================================================================================
    def _install_dependencies(self, button: QPushButton) -> None:
        command = f"{os.path.basename(sys.executable)} -m pip install -r requirements.txt"
        if not self.confirm_exact("Verificar / instalar dependencias", "Descarga de internet los paquetes que falten "
                                  "(PySide6, qtawesome, psutil, plyer…) con este mismo Python.", [command],
                                  confirm_text="Instalar", danger=False):
            return
        self.app.log_tactical("Verificando dependencias (pip install -r requirements.txt)")

        def done(ok, res):
            res = res if ok and isinstance(res, dict) else {"ok": False, "summary": str(res)}
            self.finish(button, "*" if res["ok"] else "x", "Dependencias", res["summary"], "fa5s.box-open",
                        source="arsenal:kit", event_type="tools.dependencies",
                        payload={"ok": res["ok"], "summary": res["summary"]})
            if res["ok"]:
                self._set_action_result("deps", "AL DÍA")

        self.run_action(button, "Instalando…", lambda emit: arsenal.install_requirements(), done)

    def _offer_explorer_restart(self, titles: List[str]) -> None:
        if not self.confirm_exact("Reiniciar el Explorador", f"{', '.join(titles)}: el cambio se ve al reiniciar el "
                                  "shell. La barra de tareas y las carpetas desaparecerán unos segundos; tus programas "
                                  "y documentos siguen abiertos.", ["taskkill /f /im explorer.exe",
                                                                   "explorer.exe (relanzado sin privilegios)"],
                                  confirm_text="Reiniciar Explorador", danger=False):
            Toast.notify(self.app, "*", "Explorador", "El cambio se verá al reiniciar el Explorador o la sesión.",
                         "fa5s.sync-alt")
            return
        self.app.log_tactical("Arsenal: reiniciando explorer.exe")

        def done(ok, res):
            good = ok and isinstance(res, dict)
            self.finish(None, "*" if good else "x", "Explorador",
                        f"explorer.exe reiniciado ({res['how']})." if good else f"No se pudo reiniciar: {res}",
                        "fa5s.sync-alt", source="arsenal", event_type="arsenal.toggle",
                        payload={"op": "restart_explorer", "tweak": None, "ok": good, "detail": res})

        self.run_action(None, "", lambda emit: arsenal.restart_explorer(), done)
