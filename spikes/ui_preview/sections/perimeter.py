# -*- coding: utf-8 -*-
"""7 · PERÍMETRO Y HARDWARE — redes, dispositivos y controles de entrada/salida."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout

import demodata as D
from catalog import MODULES
from sections._shared import data_table, demo_row, notice
from sections.base import Section
from theme import C
from widgets import (Card, InfoDialog, MetricCard, StatusTag, action_button, bullet_list, grid,
                     label)

DEVICES = [
    ("Teclado USB", "HID", "VID_046D PID_C31C", "conectado", "normal"),
    ("Ratón USB", "HID", "VID_046D PID_C077", "conectado", "normal"),
    ("Memoria USB 32 GB", "Almacenamiento", "VID_0951 PID_1666", "conectado", "atencion"),
    ("Cámara integrada", "Imagen", "VID_04F2 PID_B6DD", "presente", "normal"),
    ("Adaptador Wi-Fi", "Red", "VID_8086 PID_2723", "activo", "normal"),
]


class PerimeterSection(Section):
    KEY = "perimeter"
    TITLE = "Perímetro y hardware"
    NAV_LABEL = "Perímetro"
    KICKER = "07 · ENTRADAS Y SALIDAS"
    SUBTITLE = "Red, dispositivos conectados y periféricos sensibles."
    ICON = "fa5s.network-wired"

    def build(self) -> None:
        self.add(notice(
            "Nada de esta sección modifica reglas de cortafuegos, políticas de dispositivos ni "
            "ajustes de privacidad. Los módulos reales de contención existen, pero se ejecutan desde "
            "la interfaz de producción, no desde esta beta.", C["warn"], "fa5s.hand-paper"))

        self._build_network()
        self._build_devices()
        self._build_privacy()
        self._build_capabilities()

    # ---------------------------------------------------------------- red
    def _build_network(self) -> None:
        self.group("Red")
        host, add = grid(4)
        for caption, unit, ico, color, value, foot in [
            ("Conexiones activas", "", "fa5s.exchange-alt", C["cyan"], len(D.CONNECTIONS),
             "Simulado para la demostración."),
            ("Puertos a la escucha", "", "fa5s.door-open", C["warn"], 7, "Simulado."),
            ("Destinos desconocidos", "", "fa5s.globe", C["crit"], 1, "Sin resolución DNS previa."),
            ("Perfil de red", "", "fa5s.wifi", C["ok"], "Privada", "Simulado."),
        ]:
            card = MetricCard(caption, unit, ico, color)
            card.set_value(value, foot)
            add(card)
        self.add(host)

        card = Card("Conexiones observadas", "fa5s.project-diagram")
        card.add_layout(demo_row())
        rows = [(c[0], c[1], c[2], c[3], c[4], D.VERDICT_LABELS[c[5]]) for c in D.CONNECTIONS]
        card.add(data_table(["Proceso", "Local", "Remoto", "Estado", "País", "Veredicto"], rows,
                            height=165))
        row = QHBoxLayout()
        row.setSpacing(9)
        row.addWidget(action_button("Aislar el equipo (demostración)", "fa5s.unlink", "Mini",
                                    C["crit"],
                                    on_click=lambda: self.ctx.act(
                                        "Aislar el equipo de la red",
                                        "reversible: se guarda el estado previo del cortafuegos")))
        row.addWidget(action_button("Exportar conexiones (demostración)", "fa5s.file-export", "Mini",
                                    on_click=lambda: self.ctx.act("Exportar conexiones")))
        row.addStretch(1)
        card.add_layout(row)
        self.add(card)

    # ---------------------------------------------------------------- dispositivos
    def _build_devices(self) -> None:
        self.group("Dispositivos conectados",
                   "El control de USB ya existe parcialmente en modulos/_contencion.py.")
        card = Card()
        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(StatusTag("impl_partial", compact=True))
        top.addWidget(label("Bloqueo de almacenamiento USB implementado; inventario histórico "
                            "pendiente", "CardMeta"))
        top.addStretch(1)
        card.add_layout(top)
        card.add_layout(demo_row("INVENTARIO SIMULADO"))
        rows = [(n, t, i, s, D.VERDICT_LABELS[v]) for n, t, i, s, v in DEVICES]
        card.add(data_table(["Dispositivo", "Tipo", "Identificador", "Estado", "Veredicto"], rows,
                            height=165))
        card.add(label(
            "Límite honesto: se puede bloquear el almacenamiento USB, pero no distinguir un teclado "
            "legítimo de uno malicioso que se hace pasar por teclado.", "CardMeta"))
        self.add(card)

    # ---------------------------------------------------------------- privacidad
    def _build_privacy(self) -> None:
        self.group("Periféricos sensibles")
        host, add = grid(2)

        cam = Card("Cámara y micrófono", "fa5s.video")
        tags = QHBoxLayout()
        tags.addWidget(StatusTag("designed", compact=True))
        tags.addStretch(1)
        cam.add_layout(tags)
        cam.add_text(
            "Windows registra qué aplicación ha usado cada periférico sensible y cuándo. Lozarus "
            "puede leer ese historial y llevarte al ajuste del sistema para cortar el acceso.")
        cam.add(bullet_list([
            "Leer el historial de uso: viable sin privilegios especiales.",
            "«Proteger» aquí significa conmutar los ajustes de privacidad del propio Windows.",
            "Lozarus NO intercepta el flujo de vídeo ni audio: eso sería invasivo y poco fiable.",
        ], "fa5s.angle-right", C["cyan"]))
        add(cam)

        wifi = Card("Radar Wi-Fi (Evil Twin)", "fa5s.broadcast-tower")
        tags2 = QHBoxLayout()
        tags2.addWidget(StatusTag("needs_valid", compact=True))
        tags2.addStretch(1)
        wifi.add_layout(tags2)
        wifi.add_text(
            "Detectar puntos de acceso que imitan tu red requiere poner el adaptador en modo "
            "monitor, algo poco habitual en Windows.")
        wifi.add(action_button("¿Por qué está sin validar?", "fa5s.question-circle", "Mini",
                               on_click=self._explain_wifi))
        add(wifi)
        self.add(host)

    def _explain_wifi(self) -> None:
        InfoDialog(
            "Radar Wi-Fi — pendiente de validación técnica",
            "Antes de implementar este módulo hay que comprobar algo que depende del hardware "
            "concreto de cada equipo.",
            ["El modo monitor permite capturar tráfico Wi-Fi que no va dirigido a tu equipo.",
             "En Windows, muy pocos adaptadores y controladores lo admiten.",
             "Requeriría además Npcap instalado y privilegios de Administrador.",
             "El primer paso sería una comprobación que diga si ESTE equipo puede hacerlo."],
            note="Por eso figura como «Pendiente de validación técnica» y no como «Diseñado».",
            parent=self).exec()
        self.ctx.log("info", "Consultado el estado del Radar Wi-Fi")

    # ---------------------------------------------------------------- capacidades
    def _build_capabilities(self) -> None:
        caps = [m for m in MODULES if m.area == "Perímetro y hardware"]
        self.group("Capacidades de esta área", f"{len(caps)} módulos de la arquitectura.")
        host, add = grid(3)
        for cap in caps:
            card = Card(cap.label, "fa5s.network-wired")
            tags = QHBoxLayout()
            tags.addWidget(StatusTag(cap.status, compact=True))
            tags.addStretch(1)
            card.add_layout(tags)
            card.add_text(cap.description)
            add(card)
        self.add(host)
