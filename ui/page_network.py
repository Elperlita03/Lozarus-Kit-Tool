"""
ui/page_network.py · LOZARUS KIT TOOL

Página ENDURECIMIENTO DE RED: conexiones, puertos en escucha, servicios, firewall e ICMP.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
from typing import TYPE_CHECKING, Optional

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                               QTableWidgetItem)

from modulos._defensa_local import icmp_block_active, set_icmp_block
from modulos._endurecimiento_red import (SERVICIOS_SENSIBLES, disable_service, firewall_status,
                                         flush_dns, listening_keys, restore_service,
                                         scan_connections, services_overview, split_connections)

from ui.theme import COLORS
from ui.widgets import (Page, _emit_event, frozen, make_card, make_table, repolish, set_busy,
                        stat_chip, with_icon)
from ui.dialogs import ConfirmDialog

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow


class NetworkPage(Page):
    """
    Endurecimiento de red (herramientas base): enumerar puertos/conexiones, purgar la caché DNS,
    vigilar la apertura de puertos LISTEN nuevos (→ Caja Negra), leer el estado del Firewall y de
    servicios sensibles con opción de desactivarlos/restaurarlos (requiere Administrador). Mantiene
    el ocultamiento ICMP. Solo observa y, a petición de la persona, cambia la configuración local.
    """

    def __init__(self, app: "MainWindow"):
        super().__init__("Endurecimiento de Red",
                         "Herramientas base para reducir la exposición del equipo en la red. Lo que "
                         "requiere Administrador se indica; la vigilancia de puertos queda registrada "
                         "en la Caja Negra.", "fa5s.network-wired")
        self.app = app
        self._scan_busy = False
        self._baseline = None          # puertos LISTEN de referencia para la vigilancia
        self._svc_labels = {}
        self._svc_buttons = {}
        self._blocked = False          # estado ICMP; se lee en segundo plano (PowerShell, ~1 s)

        body = self.root
        body.addWidget(self._build_ports_card())
        body.addWidget(self._build_tools_card())
        body.addWidget(self._build_services_card())
        body.addStretch(1)

        self._watch_timer = QTimer(self)
        self._watch_timer.setInterval(3000)
        self._watch_timer.timeout.connect(self._watch_tick)

        self._show_icmp_state(None)  # «comprobando…» hasta que llegue la lectura en segundo plano
        # ICMP (PowerShell, ~1 s), Firewall y servicios se leen en segundo plano. Se aplaza hasta que
        # el bucle de eventos arranca: la consola de telemetría aún no existe al construir las
        # páginas, y así la ventana aparece al instante (antes el ICMP la bloqueaba ~1 s al abrir).
        QTimer.singleShot(0, self._initial_refresh)

    def _initial_refresh(self) -> None:
        if getattr(self.app, "console", None) is None:
            return
        self._refresh_icmp()
        self.refresh_firewall()
        self.refresh_services()

    # --- Puertos y conexiones -------------------------------------------------------------
    def _build_ports_card(self) -> QFrame:
        box, lay = make_card("Puertos y conexiones",
                             "Enumera los puertos en escucha (LISTEN) y las conexiones activas "
                             "(ESTABLISHED) de este equipo. Solo lectura; sin privilegios algún proceso "
                             "ajeno puede aparecer como «—».")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.scan_btn = QPushButton("Escanear puertos y conexiones")
        self.scan_btn.setObjectName("Primary")
        with_icon(self.scan_btn, "fa5s.search")
        self.scan_btn.clicked.connect(self._scan)
        self.watch_btn = QPushButton("Vigilar nuevos puertos: OFF")
        self.watch_btn.setObjectName("Toggle")
        self.watch_btn.setCheckable(True)
        with_icon(self.watch_btn, "fa5s.binoculars", COLORS["muted"])
        self.watch_btn.clicked.connect(self._toggle_watch)
        self.ports_export_btn = QPushButton("Exportar mapa")
        self.ports_export_btn.setObjectName("Ghost")
        with_icon(self.ports_export_btn, "fa5s.file-export", COLORS["muted"])
        self.ports_export_btn.setEnabled(False)
        self.ports_export_btn.setToolTip("Exporta las conexiones activas a JSON o CSV")
        self.ports_export_btn.clicked.connect(self._export_connections)
        row.addWidget(self.scan_btn)
        row.addWidget(self.watch_btn)
        row.addStretch(1)
        row.addWidget(self.ports_export_btn)
        self._last_conns = []
        self.ports_filter = QLineEdit()
        self.ports_filter.setPlaceholderText("Filtrar por proto, IP, puerto, estado, PID o proceso…")
        self.ports_filter.setClearButtonEnabled(True)
        self.ports_filter.textChanged.connect(lambda: self._render_ports())
        chips = QHBoxLayout()
        chips.setSpacing(10)
        self.card_listen, self._v_listen = stat_chip("EN ESCUCHA (LISTEN)")
        self.card_estab, self._v_estab = stat_chip("ACTIVAS (ESTABLISHED)")
        chips.addWidget(self.card_listen)
        chips.addWidget(self.card_estab)
        chips.addStretch(1)
        self.ports_table = make_table(
            ["Proto", "IP local", "Puerto", "IP remota", "Puerto", "Estado", "PID", "Proceso"],
            widths=[64, 140, 70, 140, 70, 110, 70],
            empty="Pulsa «Escanear puertos y conexiones» para ver los puertos en escucha y las "
                  "conexiones activas de este equipo.", empty_icon="fa5s.network-wired")
        self.ports_table.setMinimumHeight(240)
        lay.addLayout(row)
        lay.addLayout(chips)
        lay.addWidget(self.ports_filter)
        lay.addWidget(self.ports_table)
        return box

    def _scan(self) -> None:
        set_busy(self.scan_btn, True, "Escaneando…")
        self.app.log_tactical("Escaneando puertos y conexiones del equipo")
        self.app.run_task(lambda emit: scan_connections(), self._scanned)

    def _scanned(self, ok: bool, conns) -> None:
        set_busy(self.scan_btn, False)
        if not ok or not isinstance(conns, list):
            self.app.console.log("x", f"Escáner de puertos: {conns}")
            return
        escucha, activas = split_connections(conns)
        self._v_listen.setText(str(len(escucha)))
        self._v_estab.setText(str(len(activas)))
        resto = [c for c in conns if c.status not in ("LISTEN", "ESTABLISHED")]
        self._last_conns = escucha + activas + resto
        self.ports_export_btn.setEnabled(bool(self._last_conns))
        self._render_ports()
        self.app.console.log("*", f"Escáner de puertos: {len(escucha)} en escucha, "
                                  f"{len(activas)} activas ({len(conns)} conexiones en total)")

    def _render_ports(self) -> None:
        needle = self.ports_filter.text().strip().lower()
        rows = [c for c in self._last_conns
                if not needle or needle in " ".join(str(x) for x in c).lower()]
        if self._last_conns and not rows:
            self.ports_table.set_empty_text(f"Ninguna conexión coincide con «{needle}».", "fa5s.search")
        with frozen(self.ports_table):
            self.ports_table.setRowCount(len(rows))
            for r, c in enumerate(rows):
                vals = [c.proto, c.local_ip, str(c.local_port or "—"), c.remote_ip,
                        str(c.remote_port or "—"), c.status, str(c.pid or "—"), c.proceso]
                for col, v in enumerate(vals):
                    self.ports_table.setItem(r, col, QTableWidgetItem(v))

    def _export_connections(self) -> None:
        if not self._last_conns:
            return
        destino, _ = QFileDialog.getSaveFileName(
            self.app, "Exportar mapa de conexiones",
            os.path.join(os.path.expanduser("~"), "lozarus_conexiones.json"),
            "JSON (*.json);;CSV (*.csv)")
        if not destino:
            return
        conns = list(self._last_conns)

        def work(emit):
            filas = [{"proto": c.proto, "ip_local": c.local_ip, "puerto_local": c.local_port,
                      "ip_remota": c.remote_ip, "puerto_remoto": c.remote_port, "estado": c.status,
                      "pid": c.pid, "proceso": c.proceso} for c in conns]
            if destino.lower().endswith(".csv"):
                import csv
                with open(destino, "w", encoding="utf-8-sig", newline="") as fh:
                    writer = csv.DictWriter(fh, fieldnames=list(filas[0]))
                    writer.writeheader()
                    writer.writerows(filas)
            else:
                with open(destino, "w", encoding="utf-8") as fh:
                    json.dump({"capturado": dt.datetime.now().isoformat(timespec="seconds"),
                               "equipo": socket.gethostname(), "conexiones": filas}, fh,
                              ensure_ascii=False, indent=2)
            return len(filas)

        self.app.run_task(work, lambda ok, n: self.app.console.log(
            "*" if ok else "x", f"Mapa de conexiones: {n} filas exportadas a {destino}" if ok
            else f"Exportar: {n}"))

    def _toggle_watch(self) -> None:
        on = self.watch_btn.isChecked()
        self.watch_btn.setText("Vigilar nuevos puertos: " + ("ON" if on else "OFF"))
        if on:
            self._baseline = None  # la referencia se fija en el primer escaneo del vigilante
            self._watch_timer.start()
            self.app.log_tactical("Vigilancia de puertos LISTEN activada (cada 3 s)")
        else:
            self._watch_timer.stop()
            self.app.console.log("~", "Vigilancia de puertos detenida")

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
                    _emit_event(self.app, source="red:puertos",
                                event_type="network.new_listen_port", payload={"port_key": k})

        # Sondeo periódico: no cuenta como «tarea en curso» (el indicador parpadearía cada 3 s).
        self.app.run_task(lambda emit: listening_keys(scan_connections()), done, track=False)

    # --- Caché DNS + ocultamiento ICMP ----------------------------------------------------
    def _build_tools_card(self) -> QFrame:
        box, lay = make_card("Caché DNS y ocultamiento",
                             "Purga la caché del solucionador DNS (sin privilegios) y oculta el equipo "
                             "frente a los ping entrantes con una regla de Firewall reversible "
                             "(requiere Administrador).")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.dns_btn = QPushButton("Purgar caché DNS (flushdns)")
        self.dns_btn.setObjectName("Ghost")
        with_icon(self.dns_btn, "fa5s.broom", COLORS["muted"])
        self.dns_btn.clicked.connect(self._flush_dns)
        self.toggle_btn = QPushButton("Activar ocultamiento")
        self.toggle_btn.setObjectName("Primary")
        with_icon(self.toggle_btn, "fa5s.eye-slash")
        self.toggle_btn.clicked.connect(self._toggle)
        self.toggle_btn.setEnabled(False)  # se habilita cuando se conoce el estado real (y si hay admin)
        row.addWidget(self.dns_btn)
        row.addWidget(self.toggle_btn)
        row.addStretch(1)
        self.status = QLabel("—")
        self.status.setObjectName("StatusMuted")
        lay.addLayout(row)
        lay.addWidget(self.status)
        return box

    def _flush_dns(self) -> None:
        set_busy(self.dns_btn, True, "Purgando…")
        self.app.log_tactical("Purgando la caché del solucionador DNS")

        def done(ok, payload):
            set_busy(self.dns_btn, False)
            if ok and isinstance(payload, tuple):
                good, msg = payload
                self.app.console.log("*" if good else "x", f"DNS: {msg}")
            else:
                self.app.console.log("x", f"DNS: {payload}")

        self.app.run_task(lambda emit: flush_dns(), done)

    def _refresh_icmp(self) -> None:
        """Lee en SEGUNDO PLANO si la regla ICMP está puesta (PowerShell, ~1 s; antes congelaba la UI)."""
        self._show_icmp_state(None)

        def done(ok: bool, blocked) -> None:
            self._show_icmp_state(bool(blocked) if ok else None, failed=not ok)

        self.app.run_task(lambda emit: icmp_block_active(), done, track=False)

    def _show_icmp_state(self, blocked: Optional[bool], failed: bool = False) -> None:
        """Pinta el estado ICMP. `blocked=None` = aún desconocido (comprobando o error de lectura)."""
        if blocked is None:
            self.status.setText("No se pudo leer el estado del ocultamiento." if failed
                                else "Comprobando el estado del ocultamiento…")
            self.status.setObjectName("StatusMuted")
            self.toggle_btn.setEnabled(False)
        else:
            self._blocked = blocked
            if blocked:
                self.status.setText("● Oculto: el equipo NO responde a ping entrante")
                self.status.setObjectName("StatusWarn")
                self.toggle_btn.setText("Desactivar ocultamiento")
            else:
                self.status.setText("○ Visible: el equipo responde a ping"
                                    + ("" if self.app.admin else "  ·  requiere Administrador"))
                self.status.setObjectName("StatusMuted")
                self.toggle_btn.setText("Activar ocultamiento")
            self.toggle_btn.setEnabled(self.app.admin)
        repolish(self.status)

    def _toggle(self) -> None:
        target = not self._blocked
        self.app.log_tactical(f"{'Activando' if target else 'Desactivando'} ocultamiento de red (ICMP)")
        set_busy(self.toggle_btn, True, "Aplicando…")

        def done(ok: bool, payload) -> None:
            set_busy(self.toggle_btn, False)
            if not ok:
                self.app.console.log("x", f"Endurecimiento de red: {payload}")
            self._refresh_icmp()  # relee el estado real (también deja el botón según privilegios)

        self.app.run_task(lambda emit: set_icmp_block(target), done)

    # --- Firewall y servicios -------------------------------------------------------------
    def _build_services_card(self) -> QFrame:
        box, lay = make_card("Firewall y servicios críticos",
                             "Estado del Firewall de Windows por perfil y de servicios sensibles "
                             "(telemetría y superficie de ataque). Desactivarlos es endurecimiento, no "
                             "quitar una protección; es reversible y requiere Administrador.")
        top = QHBoxLayout()
        top.setSpacing(10)
        self.fw_label = QLabel("Firewall: comprobando…")
        self.fw_label.setObjectName("Tiny")
        self.fw_label.setWordWrap(True)
        self.fw_btn = QPushButton("Actualizar estado")
        self.fw_btn.setObjectName("Mini")
        with_icon(self.fw_btn, "fa5s.sync-alt", COLORS["muted"], 13)
        self.fw_btn.clicked.connect(lambda: (self.refresh_firewall(), self.refresh_services()))
        top.addWidget(self.fw_label, 1)
        top.addWidget(self.fw_btn)
        lay.addLayout(top)
        for name, motivo in SERVICIOS_SENSIBLES:
            lay.addLayout(self._build_service_row(name, motivo))
        if not self.app.admin:
            uac_row = QHBoxLayout()
            uac_row.setSpacing(10)
            self.uac_btn = QPushButton("Relanzar como Administrador (UAC)")
            self.uac_btn.setObjectName("Warn")
            with_icon(self.uac_btn, "fa5s.user-shield", COLORS["beacon"])
            self.uac_btn.clicked.connect(self.app.relaunch_as_admin)
            hint = QLabel("Desactivar/restaurar servicios y el ocultamiento ICMP requieren "
                          "Administrador: eleva y los botones se activarán.")
            hint.setObjectName("Tiny")
            hint.setWordWrap(True)
            uac_row.addWidget(self.uac_btn)
            uac_row.addWidget(hint, 1)
            lay.addLayout(uac_row)
        return box

    def _build_service_row(self, name: str, motivo: str) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        lbl = QLabel(name)
        lbl.setStyleSheet("color:#FAFAFA; font-size:12px; font-weight:600;")
        lbl.setMinimumWidth(128)
        lbl.setToolTip(motivo)
        st = QLabel("comprobando…")
        st.setObjectName("Tiny")
        dis = QPushButton("Desactivar")
        dis.setObjectName("Mini")
        dis.clicked.connect(lambda _=False, n=name: self._change_service(n, "disable"))
        res = QPushButton("Restaurar")
        res.setObjectName("Mini")
        res.clicked.connect(lambda _=False, n=name: self._change_service(n, "restore"))
        if not self.app.admin:
            dis.setEnabled(False)
            res.setEnabled(False)
        row.addWidget(lbl)
        row.addWidget(st, 1)
        row.addWidget(dis)
        row.addWidget(res)
        self._svc_labels[name] = st
        self._svc_buttons[name] = {"disable": dis, "restore": res}
        return row

    def refresh_firewall(self) -> None:
        set_busy(self.fw_btn, True, "Leyendo…")

        def done(ok, payload):
            set_busy(self.fw_btn, False)
            if not ok or not isinstance(payload, tuple):
                self.fw_label.setText("Firewall: no se pudo leer")
                return
            good, estado, msg = payload
            if good and estado:
                partes = " · ".join(f"{k}: {'ON' if v else 'OFF'}" for k, v in estado.items())
                self.fw_label.setText("Firewall → " + partes)
            else:
                self.fw_label.setText(f"Firewall: {msg or 'sin datos'}")

        self.app.run_task(lambda emit: firewall_status(), done)

    def refresh_services(self) -> None:
        def done(ok, data):
            if not ok or not isinstance(data, list):
                return
            for info in data:
                lbl = self._svc_labels.get(info["name"])
                if lbl is None:
                    continue
                if not info.get("exists"):
                    lbl.setText("no instalado")
                else:
                    lbl.setText(f"{info['status']} · arranque {info['start_type']}")

        self.app.run_task(lambda emit: services_overview(), done)

    def _change_service(self, name: str, action: str) -> None:
        verbo = "desactivar" if action == "disable" else "restaurar"
        detalle = ("Se detendrá y quedará con el arranque deshabilitado."
                   if action == "disable" else "Se restaurará su arranque por defecto.")
        if not ConfirmDialog.ask(self.app, f"{verbo.capitalize()} servicio",
                                 f"Vas a {verbo} el servicio «{name}» de ESTE equipo.\n\n{detalle}\n"
                                 "Requiere Administrador. ¿Continuar?",
                                 confirm_text=verbo.capitalize(), danger=(action == "disable")):
            return
        self.app.log_tactical(f"Servicio {name}: {verbo}")
        fn = disable_service if action == "disable" else restore_service
        btn = self._svc_buttons.get(name, {}).get(action)
        if btn is not None:
            set_busy(btn, True, "…")

        def done(ok, payload):
            if btn is not None:
                set_busy(btn, False)
            if ok and isinstance(payload, tuple):
                good, needs_admin, msg = payload
                if good:
                    self.app.console.log("*", f"Servicio {name}: {msg}")
                    _emit_event(self.app, source="red:servicios",
                                event_type="service.config_changed",
                                payload={"service": name, "action": action})
                else:
                    self.app.console.log("!" if needs_admin else "x", f"Servicio {name}: {msg}")
            else:
                self.app.console.log("x", f"Servicio {name}: {payload}")
            self.refresh_services()

        self.app.run_task(lambda emit: fn(name), done)
