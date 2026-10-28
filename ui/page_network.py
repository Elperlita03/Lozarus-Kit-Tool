"""
ui/page_network.py · LOZARUS KIT TOOL

Página ENDURECIMIENTO DE RED Y PERÍMETRO:
  · Métricas Bento: firewall por perfil, puertos en escucha, conexiones activas y reglas de contención.
  · Firewall y contención: estado REAL de cada perfil (con corrección netsh), ocultamiento ante ping y las
    reglas que creó Lozarus (bloqueos de puerto, Guardia…), retirables de una en una.
  · Rescate de red: purga de la caché DNS y de la tabla ARP y restablecimiento de Winsock.
  · Puertos y conexiones (exposición y vigilancia de puertos nuevos) y servicios sensibles.
Toda acción que modifica Windows exige Administrador, se confirma con el comando exacto, corre en segundo
plano y queda en la Caja Negra con aviso flotante (modulos/_perimetro.py y modulos/_optimizacion_red.py).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
import subprocess
from typing import TYPE_CHECKING, Dict, Optional

from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFileDialog, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QTableWidgetItem

from modulos import _optimizacion_red as opt
from modulos import _perimetro as per
from modulos._base import IS_WINDOWS
from modulos._defensa_local import ICMP_GROUP, ICMP_RULE, set_icmp_block
from modulos._endurecimiento_red import (SERVICIOS_SENSIBLES, disable_service, listening_keys, restore_service,
                                         scan_connections, service_commands, services_overview, split_connections)

from ui.theme import COLORS
from ui.widgets import BentoCard, Page, _emit_event, fit_columns, frozen, make_card, make_table, tech_tip
from ui.chrome import Toast
from ui.kit import HeaderStatus, SafeActions, Tile, action_button, set_pill

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

SOURCE = "red:perimetro"
ICMP_ON = (f"New-NetFirewallRule -DisplayName '{ICMP_RULE}' -Group '{ICMP_GROUP}' -Direction Inbound "
           "-Protocol ICMPv4 -IcmpType 8 -Action Block -Profile Any")
ICMP_OFF = f"Remove-NetFirewallRule -Group '{ICMP_GROUP}'"
# Rescate: operación -> (icono, texto del botón)
RESCUE_UI = {"flushdns": ("fa5s.broom", "Purgar caché DNS"), "arp": ("fa5s.sitemap", "Purgar tabla ARP"),
             "winsock": ("fa5s.plug", "Restablecer Winsock")}
RESCUE_DESC = {"flushdns": "Vacía las resoluciones guardadas: corrige nombres que apuntan a una IP antigua o "
                           "envenenada.",
               "arp": "Olvida las asociaciones IP ↔ MAC de la red local: descarta entradas falsas de un ARP "
                      "spoofing.",
               "winsock": "Devuelve el catálogo de sockets a fábrica y elimina proveedores LSP corruptos o "
                          "maliciosos."}
SERVICE_STATE = {"running": ("EN EJECUCIÓN", COLORS["warn"]), "stopped": ("DETENIDO", COLORS["ok"])}
START_TYPE = {"automatic": "automático", "manual": "manual", "disabled": "deshabilitado"}


def _cmd(argv) -> str:
    return subprocess.list2cmdline(argv)


class NetworkPage(SafeActions, Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Endurecimiento de Red y Perímetro",
                         "Estado del perímetro del equipo: firewall por perfil, reglas de contención de Lozarus, "
                         "puertos en escucha y servicios expuestos, con utilidades de rescate de red. Todo cambio exige "
                         "Administrador, se confirma con el comando exacto y queda en la Caja Negra.",
                         "fa5s.network-wired")
        self.app = app
        self._profiles: Optional[list] = None
        self._profiles_error = ""
        self._rules: Optional[list] = None
        self._blocked: Optional[bool] = None     # ocultamiento ICMP (None = desconocido)
        self._last_conns: list = []
        self._scanned = False
        self._scan_busy = False                  # sondeo de la vigilancia en curso
        self._baseline = None                    # puertos LISTEN de referencia para la vigilancia
        self._svc_tiles: Dict[str, Tile] = {}
        self._svc_buttons: Dict[str, dict] = {}

        self.header_status = HeaderStatus()
        self.add_header_widget(self.header_status)
        self.root.addLayout(self._build_metrics())
        row = QHBoxLayout()
        row.setSpacing(16)
        row.addWidget(self._build_firewall_card(), 3)
        row.addWidget(self._build_rescue_card(), 2)
        self.root.addLayout(row)
        self.root.addWidget(self._build_ports_card())
        self.root.addWidget(self._build_services_card())
        self.root.addStretch(1)

        self._watch_timer = QTimer(self)
        self._watch_timer.setInterval(3000)
        self._watch_timer.timeout.connect(self._watch_tick)
        self._render_perimeter()
        # La lectura del perímetro (PowerShell, ~1-2 s) se aplaza al bucle de eventos: la consola aún no
        # existe al construir las páginas y así la ventana aparece al instante.
        QTimer.singleShot(0, self._initial_refresh)

    def _initial_refresh(self) -> None:
        if getattr(self.app, "console", None) is None:
            return
        self.refresh_perimeter()
        self.refresh_services()

    # =============================================================================================
    # Construcción
    # =============================================================================================
    def _build_metrics(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(16)
        self._metric_cards = [
            BentoCard("fa5s.shield-alt", "Firewall de Windows", "Perfiles Dominio, Privado y Público.",
                      self._status_firewall, self.refresh_perimeter),
            BentoCard("fa5s.plug", "Puertos en escucha", "Sockets LISTEN del último escaneo.",
                      self._status_listening, self._scan),
            BentoCard("fa5s.exchange-alt", "Conexiones activas", "Sesiones ESTABLISHED con otros equipos.",
                      self._status_established, self._scan),
            BentoCard("fa5s.ban", "Reglas de contención", "Reglas del firewall creadas por Lozarus.",
                      self._status_rules, self.refresh_perimeter),
        ]
        for card in self._metric_cards:
            row.addWidget(card, 1)
        return row

    def _build_firewall_card(self):
        box, lay = make_card("Firewall y contención",
                             "Estado real de cada perfil (almacén activo, incluida la GPO), ocultamiento ante ping y "
                             "las reglas que creó Lozarus. Corregir y retirar exigen Administrador.")
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)
        self._profile_rows: Dict[str, tuple] = {}
        for r, (name, label, _netsh) in enumerate(per.PROFILES):
            title = QLabel(f"Perfil {label}")
            title.setObjectName("TileTitle")
            state, inbound = QLabel(), QLabel()
            grid.addWidget(title, r, 0)
            grid.addWidget(state, r, 1)
            grid.addWidget(inbound, r, 2)
            self._profile_rows[name] = (state, inbound)
        grid.setColumnStretch(3, 1)
        lay.addLayout(grid)
        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.fix_fw_btn = action_button("Corregir perfiles", "fa5s.shield-alt", "Danger", self.fix_profiles)
        self.icmp_btn = action_button("Ocultar ante ping", "fa5s.eye-slash", "Primary", self._toggle_icmp)
        self.refresh_fw_btn = action_button("Actualizar", "fa5s.sync-alt", "Mini",
                                            lambda: self.refresh_perimeter(self.refresh_fw_btn), 13)
        self.icmp_pill = QLabel()
        for w in (self.fix_fw_btn, self.icmp_btn, self.icmp_pill):
            actions.addWidget(w)
        actions.addStretch(1)
        actions.addWidget(self.refresh_fw_btn)
        lay.addLayout(actions)
        cap = QLabel("REGLAS DE CONTENCIÓN DE LOZARUS")
        cap.setObjectName("FieldCap")
        lay.addWidget(cap)
        self.rules_table = make_table(["Regla", "Tipo", "Dirección", "Acción", "Protocolo / puerto"],
                                      widths=[205, 125, 78, 78],
                                      empty="Sin reglas de Lozarus: aún no se ha bloqueado ni ocultado nada.",
                                      empty_icon="fa5s.ban")
        fit_columns(self.rules_table, 0, (1, 2, 3, 4))
        self.rules_table.setMinimumHeight(150)
        self.rules_table.itemSelectionChanged.connect(self._rule_selected)
        lay.addWidget(self.rules_table, 1)  # absorbe la altura sobrante de la fila (sin huecos en la tarjeta)
        rule_row = QHBoxLayout()
        self.remove_rule_btn = action_button("Retirar regla seleccionada", "fa5s.trash-alt", "Danger", self.remove_rule)
        self.remove_rule_btn.setEnabled(False)
        self.rules_note = QLabel("")
        self.rules_note.setObjectName("Tiny")
        rule_row.addWidget(self.remove_rule_btn)
        rule_row.addWidget(self.rules_note, 1)
        lay.addLayout(rule_row)
        if not IS_WINDOWS:
            for btn in (self.fix_fw_btn, self.icmp_btn):
                btn.setEnabled(False)
                btn.setToolTip("Solo disponible en Windows.")
        return box

    def _build_rescue_card(self):
        box, lay = make_card("Rescate de red",
                             "Utilidades para recuperar la conectividad o limpiar rastros de un envenenamiento de la "
                             "red. Exigen Administrador y piden confirmación con el comando exacto.")
        self._rescue_buttons: Dict[str, object] = {}
        for op in opt.RESCUE_OPS:
            title, commands, reboot = opt.MAINTENANCE_OPS[op]
            icon_name, text = RESCUE_UI[op]
            tile = Tile(icon_name, title, RESCUE_DESC[op])
            tile.set_note(" · ".join(_cmd(c) for c in commands))
            if reboot:
                tile.set_pill("REINICIO", COLORS["warn"])
            btn = tile.add_action(action_button("Ejecutar", "fa5s.play", "Mini",
                                                lambda _=False, o=op: self._rescue((o,), self._rescue_buttons[o]), 12))
            btn.setToolTip(tech_tip(text, [_cmd(c) for c in commands], "Requiere Administrador."))
            self._rescue_buttons[op] = btn
            lay.addWidget(tile)
        self.rescue_all_btn = action_button("Rescate completo (DNS + ARP + Winsock)", "fa5s.first-aid", "Danger",
                                            lambda: self._rescue(opt.RESCUE_OPS, self.rescue_all_btn))
        lay.addWidget(self.rescue_all_btn)
        self.rescue_note = QLabel("Sin ejecutar en esta sesión.")
        self.rescue_note.setObjectName("Tiny")
        self.rescue_note.setWordWrap(True)
        lay.addWidget(self.rescue_note)
        lay.addStretch(1)
        if not IS_WINDOWS:
            for btn in list(self._rescue_buttons.values()) + [self.rescue_all_btn]:
                btn.setEnabled(False)
                btn.setToolTip("Solo disponible en Windows.")
        return box

    def _build_ports_card(self):
        box, lay = make_card("Puertos y conexiones",
                             "Puertos en escucha (LISTEN) y conexiones activas (ESTABLISHED) de este equipo. Solo "
                             "lectura; «EXPUESTO» = accesible desde otros equipos. Para bloquear un puerto de riesgo "
                             "usa la Auditoría de Puertos de Escaneo de Vectores.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.scan_btn = action_button("Escanear puertos y conexiones", "fa5s.search", "Primary", self._scan)
        self.watch_btn = action_button("Vigilar nuevos puertos: OFF", "fa5s.binoculars", "Toggle")
        self.watch_btn.setCheckable(True)
        self.watch_btn.clicked.connect(self._toggle_watch)
        self.ports_filter = QLineEdit()
        self.ports_filter.setPlaceholderText("Filtrar por proto, IP, puerto, estado, PID o proceso…")
        self.ports_filter.setClearButtonEnabled(True)
        self.ports_filter.textChanged.connect(lambda _t: self._render_ports())
        self.ports_export_btn = action_button("Exportar mapa", "fa5s.file-export", "Ghost", self._export_connections)
        self.ports_export_btn.setEnabled(False)
        self.ports_export_btn.setToolTip("Exporta las conexiones a JSON o CSV")
        row.addWidget(self.scan_btn)
        row.addWidget(self.watch_btn)
        row.addWidget(self.ports_filter, 1)
        row.addWidget(self.ports_export_btn)
        lay.addLayout(row)
        self.ports_table = make_table(
            ["Proto", "IP local", "Puerto", "IP remota", "Puerto", "Estado", "Exposición", "PID", "Proceso"],
            widths=[64, 140, 70, 140, 70, 110, 100, 70],
            empty="Pulsa «Escanear puertos y conexiones» para ver los puertos en escucha y las conexiones activas "
                  "de este equipo.", empty_icon="fa5s.network-wired")
        self.ports_table.setMinimumHeight(260)
        lay.addWidget(self.ports_table)
        return box

    def _build_services_card(self):
        box, lay = make_card("Servicios sensibles",
                             "Telemetría y superficie de ataque. Desactivarlos es endurecimiento, no quitar una "
                             "protección; es reversible con «Restaurar» y exige Administrador.")
        row = QHBoxLayout()
        row.setSpacing(12)
        for name, motivo in SERVICIOS_SENSIBLES:
            tile = Tile("fa5s.cogs", name, motivo)
            tile.set_pill("LEYENDO…", COLORS["faint"])
            dis = tile.add_action(action_button("Desactivar", "fa5s.power-off", "Mini",
                                                lambda _=False, n=name: self._change_service(n, "disable"), 12))
            res = tile.add_action(action_button("Restaurar", "fa5s.undo", "Mini",
                                                lambda _=False, n=name: self._change_service(n, "restore"), 12))
            for btn, action in ((dis, "disable"), (res, "restore")):
                btn.setToolTip(tech_tip(f"{btn.text()} {name}", [_cmd(c) for c in service_commands(name, action)],
                                        "Requiere Administrador."))
                btn.setEnabled(IS_WINDOWS)
            self._svc_tiles[name] = tile
            self._svc_buttons[name] = {"disable": dis, "restore": res}
            row.addWidget(tile, 1)
        lay.addLayout(row)
        return box

    # =============================================================================================
    # Estado global y métricas
    # =============================================================================================
    def _busy_changed(self) -> None:
        self._refresh_status()

    def _refresh_status(self) -> None:
        if self.running:
            self.header_status.set_state(f"EN CURSO · {self.running}", COLORS["accent"])
        elif self._profiles is None:
            if self._profiles_error:
                self.header_status.set_state("FIREWALL NO DISPONIBLE", COLORS["faint"], self._profiles_error)
            else:
                self.header_status.set_state("LEYENDO PERÍMETRO", COLORS["faint"])
        else:
            verdict = per.perimeter_verdict(self._profiles)
            rules = len(self._rules or [])
            tip = f"{verdict['active']}/{verdict['total']} perfiles activos · {rules} regla(s) de contención"
            if verdict["off"]:
                self.header_status.set_state(f"FIREWALL APAGADO · {', '.join(verdict['off'])}", COLORS["danger"], tip)
            elif verdict["open_inbound"]:
                self.header_status.set_state(f"ENTRADA ABIERTA · {', '.join(verdict['open_inbound'])}",
                                             COLORS["warn"], tip)
            else:
                self.header_status.set_state("PERÍMETRO PROTEGIDO", COLORS["ok"], tip)
        self.header_status.set_admin(bool(getattr(self.app, "admin", False)))

    def _refresh_metrics(self) -> None:
        for card in self._metric_cards:
            card.refresh()
        self._refresh_status()

    def _status_firewall(self):
        if self._profiles is None:
            return (COLORS["warn"] if self._profiles_error else False,
                    self._profiles_error or "Leyendo el estado…", "—")
        verdict = per.perimeter_verdict(self._profiles)
        if verdict["off"]:
            return (COLORS["danger"], "Apagado: " + ", ".join(verdict["off"]), f"{verdict['active']}/{verdict['total']}")
        if verdict["open_inbound"]:
            return (COLORS["warn"], "Entrada abierta: " + ", ".join(verdict["open_inbound"]),
                    f"{verdict['active']}/{verdict['total']}")
        return (COLORS["ok"], "Todos los perfiles bloquean la entrada", f"{verdict['active']}/{verdict['total']}")

    def _status_listening(self):
        if not self._scanned:
            return (False, "Sin escanear todavía", "—")
        listen = [c for c in self._last_conns if c.status == "LISTEN"]
        exposed = sum(1 for c in listen if per.exposed(c.local_ip))
        return (COLORS["warn"] if exposed else COLORS["ok"], f"{exposed} expuestos a la red", str(len(listen)))

    def _status_established(self):
        if not self._scanned:
            return (False, "Sin escanear todavía", "—")
        active = [c for c in self._last_conns if c.status == "ESTABLISHED"]
        procs = len({c.proceso for c in active})
        return (True if active else False, f"{procs} proceso(s) con conexión", str(len(active)))

    def _status_rules(self):
        if self._rules is None:
            return (False, "Leyendo…" if IS_WINDOWS else "Solo Windows", "—")
        kinds: Dict[str, int] = {}
        for rule in self._rules:
            kinds[rule["kind"]] = kinds.get(rule["kind"], 0) + 1
        text = " · ".join(f"{k}: {n}" for k, n in kinds.items()) or "Ninguna activa"
        return (COLORS["ok"] if self._rules else False, text, str(len(self._rules)))

    # =============================================================================================
    # Perímetro: perfiles, ICMP y reglas
    # =============================================================================================
    def refresh_perimeter(self, button=None) -> None:
        """Lee perfiles y reglas en SEGUNDO PLANO (PowerShell). Con botón, muestra su spinner."""
        def work(emit):
            out = {}
            try:
                out["profiles"] = per.firewall_profiles()
            except Exception as exc:  # noqa: BLE001  (fuera de Windows o sin PowerShell)
                out["profiles_error"] = str(exc)
            try:
                out["rules"] = per.containment_rules()
            except Exception as exc:  # noqa: BLE001
                out["rules_error"] = str(exc)
            return out

        if button is not None:
            self.run_action(button, "Leyendo…", work, self._perimeter_done)
        else:
            self.app.run_task(work, self._perimeter_done, track=False)

    def _perimeter_done(self, ok: bool, res) -> None:
        res = res if ok and isinstance(res, dict) else {"profiles_error": str(res)}
        self._profiles = res.get("profiles")
        self._profiles_error = res.get("profiles_error", "")
        self._rules = res.get("rules")
        if self._rules is not None:
            self._blocked = any(r["group"] == ICMP_GROUP for r in self._rules)
        self._render_perimeter()

    def _render_perimeter(self) -> None:
        profiles = {p["name"]: p for p in self._profiles or []}
        for name, (state, inbound) in self._profile_rows.items():
            p = profiles.get(name)
            if p is None:
                set_pill(state, "NO DISPONIBLE" if self._profiles_error else "LEYENDO…", COLORS["faint"])
                set_pill(inbound, "", COLORS["faint"])
                continue
            set_pill(state, "ACTIVO" if p["enabled"] else "APAGADO", COLORS["ok"] if p["enabled"] else COLORS["danger"])
            set_pill(inbound, "ENTRADA BLOQUEADA" if p["inbound_block"] else "ENTRADA ABIERTA",
                     COLORS["ok"] if p["inbound_block"] else COLORS["warn"])
        fixes = per.profile_fix_commands(self._profiles or [])
        self.fix_fw_btn.setVisible(bool(fixes))
        self.fix_fw_btn.setToolTip(tech_tip("Corregir perfiles", [_cmd(c) for c in fixes], "Requiere Administrador."))
        if self._blocked is None:
            set_pill(self.icmp_pill, "ICMP: LEYENDO…" if IS_WINDOWS else "", COLORS["faint"])
        else:
            set_pill(self.icmp_pill, "OCULTO ANTE PING" if self._blocked else "RESPONDE A PING",
                     COLORS["ok"] if self._blocked else COLORS["faint"])
            if not self.icmp_btn.property("busy"):
                self.icmp_btn.setText("Dejar de ocultar" if self._blocked else "Ocultar ante ping")
        self.icmp_btn.setToolTip(tech_tip("Ocultamiento ante ping (ICMP eco)", [ICMP_OFF if self._blocked else ICMP_ON],
                                          "Regla reversible; requiere Administrador."))
        if not self.icmp_btn.property("busy"):
            self.icmp_btn.setEnabled(IS_WINDOWS and self._blocked is not None)
        rules = self._rules or []
        if self._rules is None:
            self.rules_table.set_empty_text("Las reglas del firewall solo existen en Windows." if not IS_WINDOWS else
                                            "Leyendo las reglas del firewall…", "fa5s.ban")
        else:
            self.rules_table.set_empty_text("Sin reglas de Lozarus: aún no se ha bloqueado ni ocultado nada.",
                                            "fa5s.ban")
        with frozen(self.rules_table):
            self.rules_table.setRowCount(len(rules))
            for r, rule in enumerate(rules):
                where = f"{rule['proto']} {rule['port']}".strip() if rule["port"] not in ("", "Any") else rule["proto"]
                action = QTableWidgetItem("Bloquear" if rule["action"] == "Block" else "Permitir")
                action.setForeground(QColor(COLORS["warn"] if rule["action"] == "Block" else COLORS["ok"]))
                cells = [QTableWidgetItem(rule["name"]), QTableWidgetItem(rule["kind"]),
                         QTableWidgetItem("Entrada" if rule["dir"] == "Inbound" else "Salida"), action,
                         QTableWidgetItem(where or "—")]
                for c, item in enumerate(cells):
                    self.rules_table.setItem(r, c, item)
        self._rule_selected()
        self._refresh_metrics()

    def _selected_rule(self) -> Optional[dict]:
        r = self.rules_table.currentRow()
        rules = self._rules or []
        return rules[r] if 0 <= r < len(rules) and self.rules_table.selectedItems() else None

    def _rule_selected(self) -> None:
        rule = self._selected_rule()
        removable = rule is not None and per.removable(rule)
        if not self.remove_rule_btn.property("busy"):
            self.remove_rule_btn.setEnabled(removable and IS_WINDOWS)
        self.rules_note.setText("" if rule is None else "La cuarentena se levanta desde «Cuarentena Absoluta»."
                                if not removable else f"Se retirará «{rule['name']}».")

    def fix_profiles(self) -> None:
        cmds = per.profile_fix_commands(self._profiles or [])
        if not cmds:
            Toast.notify(self.app, "*", "Firewall", "Todos los perfiles ya bloquean la entrada.", "fa5s.shield-alt")
            return
        title = "Corregir perfiles del firewall"
        if not self.admin_ok(title) or not self.confirm_exact(
                title, "Se encenderán los perfiles apagados y se bloqueará la entrada no solicitada; la política "
                       "de salida y las reglas de permitir existentes se conservan.", [_cmd(c) for c in cmds]):
            return
        self.app.log_tactical(f"Firewall: corrigiendo {len(cmds)} ajuste(s) de perfil")

        def done(ok: bool, res) -> None:
            steps = res if ok and isinstance(res, list) else [("netsh", False, str(res))]
            bad = [f"{line}: {msg or 'falló'}" for line, good, msg in steps if not good]
            kind = "*" if not bad else "!" if len(bad) < len(steps) else "x"
            text = f"{len(steps) - len(bad)} de {len(steps)} ajustes aplicados." + (f" Fallo: {bad[0]}" if bad else "")
            self.finish(self.fix_fw_btn, kind, title, text, "fa5s.shield-alt", source=SOURCE,
                        event_type="firewall.profiles_fixed",
                        payload={"commands": [line for line, _g, _m in steps], "failed": bad})
            self.refresh_perimeter()

        self.run_action(self.fix_fw_btn, "Aplicando…", lambda emit: per.run_commands(cmds), done)

    def _toggle_icmp(self) -> None:
        if self._blocked is None:
            return
        target = not self._blocked
        title = "Ocultar el equipo ante ping" if target else "Dejar de ocultar ante ping"
        intro = ("Se añadirá una regla de firewall que descarta el eco ICMP entrante: el equipo no responderá a ping "
                 "en ninguna red. Reversible." if target else "Se eliminará la regla de ocultamiento: el equipo "
                                                              "volverá a responder a ping.")
        if not self.admin_ok(title) or not self.confirm_exact(title, intro, [ICMP_ON if target else ICMP_OFF],
                                                              danger=False):
            return
        self.app.log_tactical(f"{'Activando' if target else 'Retirando'} el ocultamiento ICMP")

        def done(ok: bool, res) -> None:
            text = ("Equipo oculto ante ping." if target else "El equipo vuelve a responder a ping.") if ok else str(res)
            self.finish(self.icmp_btn, "*" if ok else "x", title, text, "fa5s.eye-slash", source=SOURCE,
                        event_type="network.icmp_stealth", payload={"blocked": target, "ok": ok,
                                                                    "detail": res if ok else str(res)})
            self.refresh_perimeter()

        self.run_action(self.icmp_btn, "Aplicando…", lambda emit: set_icmp_block(target), done)

    def remove_rule(self) -> None:
        rule = self._selected_rule()
        if rule is None or not per.removable(rule):
            return
        title = "Retirar regla de contención"
        command = f"Remove-NetFirewallRule -DisplayName '{rule['name']}'"
        if not self.admin_ok(title) or not self.confirm_exact(
                title, f"«{rule['name']}» ({rule['kind'].lower()}) dejará de aplicarse.", [command]):
            return
        name = rule["name"]

        def done(ok: bool, res) -> None:
            self.finish(self.remove_rule_btn, "*" if ok else "x", title,
                        f"Regla «{name}» retirada." if ok else str(res), "fa5s.trash-alt", source=SOURCE,
                        event_type="firewall.rule_removed", payload={"rule": name, "kind": rule["kind"], "ok": ok,
                                                                     "error": "" if ok else str(res)})
            if ok:
                audit = getattr(self.app, "pages", {}).get("auditoria")
                if audit is not None and hasattr(audit, "on_firewall_rule_removed"):
                    audit.on_firewall_rule_removed(name)  # el puerto vuelve a figurar como pendiente
            self.refresh_perimeter()

        self.run_action(self.remove_rule_btn, "Retirando…", lambda emit: per.remove_rule(name), done)

    # =============================================================================================
    # Rescate de red
    # =============================================================================================
    def _rescue(self, ops, button) -> None:
        names = [opt.MAINTENANCE_OPS[o][0] for o in ops]
        title = names[0] if len(ops) == 1 else "Rescate de red completo"
        if not self.admin_ok(title, "El rescate de red reconfigura la pila de red del sistema."):
            return
        lines = [_cmd(c) for o in ops for c in opt.MAINTENANCE_OPS[o][1]]
        footer = ("Winsock se completa al reiniciar el equipo; algunas VPN o antivirus tendrán que reinstalar su "
                  "componente de red." if "winsock" in ops else "La conexión no se corta.")
        if not self.confirm_exact(title, f"Operaciones sobre este equipo: {' · '.join(names)}.", lines,
                                  footer=footer, confirm_text="Ejecutar"):
            return
        self.app.log_tactical(f"Rescate de red: {', '.join(names)}")

        def done(ok: bool, res) -> None:
            results = res if ok and isinstance(res, list) else [{"ok": False, "title": title, "message": str(res),
                                                                 "steps": []}]
            good = [r["title"] for r in results if r["ok"]]
            bad = [r["message"] for r in results if not r["ok"]]
            kind = "*" if not bad else "!" if good else "x"
            text = (" · ".join(good) + " completado." if good else "Ningún paso se completó.") + \
                (f" Sin aplicar: {bad[0]}" if bad else "")
            if any(r["ok"] and r.get("reboot") for r in results):
                text += " Reinicia el equipo para completar Winsock."
            self.rescue_note.setText(f"Último: {dt.datetime.now():%H:%M} · {text}")
            self.finish(button, kind, title, text, "fa5s.first-aid", source=SOURCE, event_type="network.rescue",
                        payload={"ops": list(ops), "results": [{k: r.get(k) for k in ("op", "ok", "message", "steps")}
                                                               for r in results]})

        self.run_action(button, "Ejecutando…", lambda emit: [opt.run_maintenance(o, admin=True) for o in ops], done)

    # =============================================================================================
    # Puertos y conexiones
    # =============================================================================================
    def _scan(self) -> None:
        if self.scan_btn.property("busy"):
            return
        self.app.log_tactical("Escaneando puertos y conexiones del equipo")
        self.run_action(self.scan_btn, "Escaneando…", lambda emit: scan_connections(), self._scanned_done)

    def _scanned_done(self, ok: bool, conns) -> None:
        if not ok or not isinstance(conns, list):
            self.finish(self.scan_btn, "x", "Puertos y conexiones", f"No se pudo escanear: {conns}", "fa5s.search",
                        source=SOURCE, event_type="network.scan_failed", payload={"error": str(conns)})
            return
        listen, active = split_connections(conns)
        rest = [c for c in conns if c.status not in ("LISTEN", "ESTABLISHED")]
        self._last_conns = listen + active + rest
        self._scanned = True
        self.ports_export_btn.setEnabled(bool(self._last_conns))
        self._render_ports()
        self._refresh_metrics()
        exposed = sum(1 for c in listen if per.exposed(c.local_ip))
        text = f"{len(listen)} en escucha ({exposed} expuestos) · {len(active)} conexiones activas"
        self.finish(self.scan_btn, "!" if exposed else "*", "Puertos y conexiones", text, "fa5s.search",
                    source=SOURCE, event_type="network.scan",
                    payload={"listening": len(listen), "exposed": exposed, "established": len(active),
                             "total": len(conns)})

    def _render_ports(self) -> None:
        needle = self.ports_filter.text().strip().lower()
        rows = [c for c in self._last_conns if not needle or needle in " ".join(str(x) for x in c).lower()]
        if self._last_conns and not rows:
            self.ports_table.set_empty_text(f"Ninguna conexión coincide con «{needle}».", "fa5s.search")
        with frozen(self.ports_table):
            self.ports_table.setRowCount(len(rows))
            for r, c in enumerate(rows):
                listening = c.status == "LISTEN"
                is_exposed = listening and per.exposed(c.local_ip)
                cells = [QTableWidgetItem(v) for v in (c.proto, c.local_ip, str(c.local_port or "—"), c.remote_ip,
                                                       str(c.remote_port or "—"), c.status)]
                cells[5].setForeground(QColor(COLORS["text"] if listening else COLORS["text2"]))
                exposure = QTableWidgetItem("EXPUESTO" if is_exposed else "LOCAL" if listening else "—")
                exposure.setForeground(QColor(COLORS["warn"] if is_exposed else COLORS["muted"]))
                cells += [exposure, QTableWidgetItem(str(c.pid or "—")), QTableWidgetItem(c.proceso)]
                for col, item in enumerate(cells):
                    self.ports_table.setItem(r, col, item)

    def _export_connections(self) -> None:
        if not self._last_conns:
            return
        destino, _ = QFileDialog.getSaveFileName(self.app, "Exportar mapa de conexiones",
                                                 os.path.join(os.path.expanduser("~"), "lozarus_conexiones.json"),
                                                 "JSON (*.json);;CSV (*.csv)")
        if not destino:
            return
        conns = list(self._last_conns)

        def work(emit):
            filas = [{"proto": c.proto, "ip_local": c.local_ip, "puerto_local": c.local_port, "ip_remota": c.remote_ip,
                      "puerto_remoto": c.remote_port, "estado": c.status, "pid": c.pid, "proceso": c.proceso,
                      "expuesto": c.status == "LISTEN" and per.exposed(c.local_ip)} for c in conns]
            if destino.lower().endswith(".csv"):
                import csv
                with open(destino, "w", encoding="utf-8-sig", newline="") as fh:
                    writer = csv.DictWriter(fh, fieldnames=list(filas[0]))
                    writer.writeheader()
                    writer.writerows(filas)
            else:
                with open(destino, "w", encoding="utf-8") as fh:
                    json.dump({"capturado": dt.datetime.now().isoformat(timespec="seconds"),
                               "equipo": socket.gethostname(), "conexiones": filas}, fh, ensure_ascii=False, indent=2)
            return len(filas)

        def done(ok: bool, n) -> None:
            self.finish(self.ports_export_btn, "*" if ok else "x", "Mapa de conexiones",
                        f"{n} filas exportadas a {os.path.basename(destino)}" if ok else f"No se pudo exportar: {n}",
                        "fa5s.file-export", source=SOURCE, event_type="network.map_exported",
                        payload={"path": destino, "rows": n if ok else 0, "ok": ok})

        self.run_action(self.ports_export_btn, "Exportando…", work, done)

    def _toggle_watch(self) -> None:
        on = self.watch_btn.isChecked()
        self.watch_btn.setText("Vigilar nuevos puertos: " + ("ON" if on else "OFF"))
        if on:
            self._baseline = None  # la referencia se fija en el primer sondeo
            self._watch_timer.start()
            self.app.log_tactical("Vigilancia de puertos LISTEN activada (cada 3 s)")
        else:
            self._watch_timer.stop()
            self.app.console.log("~", "Vigilancia de puertos detenida")
        _emit_event(self.app, source="red:puertos", event_type="network.watch_toggled", payload={"active": on})

    def _watch_tick(self) -> None:
        if self._scan_busy:
            return
        self._scan_busy = True

        def done(ok, keys):
            self._scan_busy = False
            if not ok or not isinstance(keys, (set, frozenset)):
                return
            if self._baseline is None:
                self._baseline = set(keys)  # primera foto: solo referencia, sin avisar
                return
            nuevos = keys - self._baseline
            if nuevos:
                self._baseline |= nuevos
                for k in sorted(nuevos):
                    self.app.console.log("!", f"Puerto nuevo en escucha: {k}")
                    self.app.record_alert("!", f"Puerto nuevo en escucha: {k}", module="red")
                    _emit_event(self.app, source="red:puertos", event_type="network.new_listen_port",
                                payload={"port_key": k})

        # Sondeo periódico: no cuenta como «tarea en curso» (el indicador parpadearía cada 3 s).
        self.app.run_task(lambda emit: listening_keys(scan_connections()), done, track=False)

    # =============================================================================================
    # Servicios sensibles
    # =============================================================================================
    def refresh_services(self) -> None:
        def done(ok, data):
            if not ok or not isinstance(data, list):
                return
            for info in data:
                tile = self._svc_tiles.get(info["name"])
                if tile is None:
                    continue
                if not info.get("exists"):
                    tile.set_pill("NO INSTALADO" if IS_WINDOWS else "SOLO WINDOWS", COLORS["faint"])
                    tile.set_note(info.get("error", "")[:80] if IS_WINDOWS else "")
                    for btn in self._svc_buttons[info["name"]].values():
                        btn.setEnabled(False)
                    continue
                text, color = SERVICE_STATE.get(info["status"], (str(info["status"]).upper(), COLORS["text2"]))
                tile.set_pill(text, color)
                tile.set_note(f"Arranque: {START_TYPE.get(info['start_type'], info['start_type'])}")
                for btn in self._svc_buttons[info["name"]].values():
                    if not btn.property("busy"):
                        btn.setEnabled(True)

        self.app.run_task(lambda emit: services_overview(), done, track=False)

    def _change_service(self, name: str, action: str) -> None:
        verb = "Desactivar" if action == "disable" else "Restaurar"
        title = f"{verb} servicio {name}"
        if not self.admin_ok(title):
            return
        detail = ("Se detendrá y quedará con el arranque deshabilitado." if action == "disable"
                  else "Se restaurará su arranque predeterminado.")
        if not self.confirm_exact(title, f"Servicio «{name}» de este equipo. {detail}",
                                  [_cmd(c) for c in service_commands(name, action)], confirm_text=verb,
                                  danger=action == "disable"):
            return
        fn = disable_service if action == "disable" else restore_service
        button = self._svc_buttons[name][action]

        def done(ok: bool, res) -> None:
            good, _needs_admin, msg = res if ok and isinstance(res, tuple) else (False, False, str(res))
            self.finish(button, "*" if good else "x", title, msg, "fa5s.cogs", source="red:servicios",
                        event_type="service.config_changed",
                        payload={"service": name, "action": action, "ok": good, "detail": msg})
            self.refresh_services()

        self.app.log_tactical(f"Servicio {name}: {verb.lower()}")
        self.run_action(button, "…", lambda emit: fn(name), done)
