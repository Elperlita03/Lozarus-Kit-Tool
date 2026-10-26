# -*- coding: utf-8 -*-
"""
2 · CENTINELA — telemetría, vigilancia y salud de los sensores.

Representa la arquitectura REAL que ya existe (colector ETW → bus → consumidores) y la que falta
(Caja Negra, OBSIDIAN). Esta sección **no abre ninguna sesión ETW**: conectarse de verdad exigiría
Administrador y será siempre una acción explícita, separada del modo demostración.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout

import demodata as D
from catalog import CORE
from sections._shared import data_table, demo_row, notice
from sections.base import Section
from theme import C
from widgets import (Card, FlowDiagram, InfoDialog, KeyValue, Sparkline, StatusTag, action_button,
                     bullet_list, grid, label)

PIPELINE = [
    ("Colector ETW", "Recibe eventos de Windows y los normaliza", "impl_tested"),
    ("Modelo de evento", "Formato común lozarus.event.v1", "impl_tested"),
    ("Bus de eventos", "Cola acotada con descartes contados", "impl_tested"),
    ("Caja Negra", "Guarda la ventana reciente en disco", "designed"),
    ("OBSIDIAN", "Mide cobertura, huecos y pérdidas", "designed"),
    ("Interfaz", "Muestra sin mentir sobre lo no observado", "demo_only"),
]


class SentinelSection(Section):
    KEY = "sentinel"
    TITLE = "Centinela"
    KICKER = "02 · TELEMETRÍA Y VIGILANCIA"
    SUBTITLE = "Qué observa Lozarus, con qué fiabilidad y qué partes de la cadena ya existen."
    ICON = "fa5s.wave-square"

    def build(self) -> None:
        self.add(notice(
            "Esta beta NO abre sesiones ETW ni ejecuta nada privilegiado. El colector de producción "
            "existe y está probado, pero conectarlo requiere Administrador y será siempre una acción "
            "explícita, nunca algo que ocurra por abrir esta ventana.",
            C["warn"], "fa5s.shield-alt"))

        self.group("Cadena de telemetría", "El color del borde de cada bloque indica su estado real.")
        flow = Card()
        flow.add(FlowDiagram(PIPELINE))
        legend = QHBoxLayout()
        legend.setSpacing(9)
        for key in ("impl_tested", "designed", "demo_only"):
            legend.addWidget(StatusTag(key, compact=True))
        legend.addStretch(1)
        flow.add_layout(legend)
        self.add(flow)

        self._build_core()
        self._build_sensors()
        self._build_loss()

    # ---------------------------------------------------------------- piezas del núcleo
    def _build_core(self) -> None:
        self.group("Piezas implementadas", "Verificado contra el repositorio: estas sí tienen pruebas.")
        host, add = grid(3)
        for cap in CORE:
            if cap.area != "Núcleo y telemetría":
                continue
            card = Card(cap.name.split("—")[-1].strip() or cap.name, "fa5s.cube")
            top = QHBoxLayout()
            top.setSpacing(7)
            top.addWidget(StatusTag(cap.status, compact=True))
            top.addStretch(1)
            card.add_layout(top)
            card.add_text(cap.description)
            card.add(label(f"Pruebas: {cap.tests}", "CardMeta"))
            if cap.backing:
                card.add(label(cap.backing, "Mono"))
            add(card)
        self.add(host)

    # ---------------------------------------------------------------- sensores
    def _build_sensors(self) -> None:
        self.group("Estado de los sensores",
                   "«—» significa desconocido. Un sensor parado no produce ceros: no produce nada.")
        card = Card()
        card.add_layout(demo_row("ESTADO MOSTRATIVO — NINGÚN SENSOR ESTÁ CONECTADO"))
        rows = [(s[0], s[1], s[2], s[3], s[4]) for s in D.SENSORS]
        card.add(data_table(
            ["Sensor", "Estado", "Eventos", "Pérdida en origen", "Descartes del bus"], rows,
            height=190))
        card.add(label(
            "El colector ETW es el único con código de producción y pruebas. Los otros cinco están "
            "previstos en la arquitectura pero todavía no tienen implementación.", "CardMeta"))
        self.add(card)

    # ---------------------------------------------------------------- pérdidas
    def _build_loss(self) -> None:
        self.group("Cómo se cuentan las pérdidas",
                   "Es la regla que impide que el producto se mienta a sí mismo.")
        row = QHBoxLayout()
        row.setSpacing(14)

        states = Card("Tres estados, no dos", "fa5s.layer-group")
        states.add(bullet_list([
            "DESCONOCIDO («—»): no se ha podido medir. Nunca se convierte en 0.",
            "CERO CONFIRMADO (0): se midió y de verdad no se perdió nada.",
            "PÉRDIDA DETECTADA (>0): se midió y se perdieron eventos.",
        ], "fa5s.circle", C["cyan"]))
        states.add(label(
            "Esto ya está implementado y probado en core/contracts.py (LossState).", "CardMeta"))
        row.addWidget(states, 1)

        sep = Card("Dos pérdidas distintas, jamás sumadas", "fa5s.code-branch")
        sep.add(KeyValue("En el origen (ETW)",
                         "El propio Windows descartó eventos porque su búfer se llenó. Con pywintrace "
                         "solo se conoce al PARAR la sesión."))
        sep.add(KeyValue("En el bus interno",
                         "Nuestra cola estaba llena y descartó. Es culpa nuestra, no de Windows."))
        sep.add(label(
            "Sumarlas daría una cifra sin significado: tienen causas y remedios diferentes.",
            "CardMeta"))
        row.addWidget(sep, 1)
        self.add_layout(row)

        live = Card("Eventos observados", "fa5s.chart-line")
        live.add_layout(demo_row("SERIE SIMULADA"))
        self.spark = Sparkline(C["demo"], 78)
        live.add(self.spark)
        self.live_note = label("Activa el modo demostración para ver cómo se representaría el "
                               "caudal de eventos.", "CardMeta")
        live.add(self.live_note)
        btn = action_button("¿Qué haría falta para conectarlo de verdad?", "fa5s.question-circle",
                            "Mini", on_click=self._explain_real)
        live.add(btn)
        self.add(live)

    def _explain_real(self) -> None:
        InfoDialog(
            "Conectar la telemetría real",
            "El colector ETW de producción ya existe y pasa 13 pruebas automáticas. Para que "
            "publicara eventos reales en esta interfaz harían falta estos pasos, y todos deben ser "
            "explícitos:",
            ["Ejecutar Lozarus como Administrador (o pertenecer a «Performance Log Users»).",
             "Tener pywintrace instalado en el entorno de ejecución.",
             "Un modo de conexión real, separado y claramente distinto del modo demostración.",
             "Implementar la Caja Negra y OBSIDIAN para no mostrar datos sin declarar su cobertura.",
             "Un adaptador que lleve los eventos del bus al hilo de la interfaz sin bloquearla."],
            note="Mientras tanto, esta beta prefiere enseñar la arquitectura honestamente antes que "
                 "fingir una vigilancia que no está ocurriendo.",
            parent=self).exec()
        self.ctx.log("info", "Consultados los requisitos para conectar la telemetría real")

    def on_demo_changed(self, enabled: bool) -> None:
        if enabled:
            self.spark.set_points(D.EVENT_RATE_DEMO)
            self.live_note.setText("Serie SIMULADA. Ningún sensor real está publicando.")
        else:
            self.spark.set_points([])
            self.live_note.setText("Activa el modo demostración para ver cómo se representaría el "
                                   "caudal de eventos.")
