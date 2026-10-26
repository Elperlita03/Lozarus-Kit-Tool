# -*- coding: utf-8 -*-
"""
1 · CUARTEL GENERAL — pantalla principal.

Honestidad obligatoria: el estado general NUNCA dice «protegido». Con los sensores parados, el
estado es SIN VIGILANCIA, que es un estado de primera clase distinto de «todo correcto». CPU y RAM
son datos REALES del equipo (psutil); todo lo demás que se vea aquí va marcado como demostración.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QFrame, QHBoxLayout, QVBoxLayout

import demodata as D
from catalog import CORE, MODULES, counts_by_status
from runtime import host_label, read_metrics
from sections.base import Section
from theme import C, STATUS
from widgets import (Card, ClickableCard, DemoBadge, Gauge, InfoDialog, MetricCard, Sparkline,
                     StatusTag, TimelineView, action_button, clear_layout, grid, label, vbox)

QUICK_ACCESS = [
    ("sentinel", "Centinela", "fa5s.wave-square", "Telemetría, sensores y salud de la observación."),
    ("analyze", "Analizar equipo", "fa5s.search", "Procesos, conexiones, archivos y persistencia."),
    ("defense", "Defensa y contención", "fa5s.hand-paper", "Incidentes y respuestas reversibles."),
    ("forensics", "Laboratorio forense", "fa5s.fingerprint", "Cronologías, evidencia y análisis PE."),
    ("rescue", "Rescue USB", "fa5s.life-ring", "El entorno de recuperación arrancable."),
    ("catalog", "Catálogo", "fa5s.th-list", "Las 41 capacidades y su estado real."),
]


class HQSection(Section):
    KEY = "hq"
    TITLE = "Cuartel general"
    KICKER = "LOZARUS · BETA VISUAL"
    SUBTITLE = "Estado del equipo y acceso a todas las áreas del producto."
    ICON = "fa5s.tachometer-alt"
    SHOW_BACK = False

    def build(self) -> None:
        self._timer = QTimer(self)
        self._timer.setInterval(1500)
        self._timer.timeout.connect(self._refresh_metrics)

        self._build_banner()
        self._build_metrics()
        self._build_telemetry()
        self._build_incidents()
        self._build_quick_access()

    # ------------------------------------------------------------------ estado general
    def _build_banner(self) -> None:
        self.banner = Card(accent=True)
        self.banner.body.setContentsMargins(22, 20, 22, 20)
        row = QHBoxLayout()
        row.setSpacing(20)

        left = QVBoxLayout()
        left.setSpacing(5)
        self.state_label = label("SIN VIGILANCIA", "PageTitle", wrap=False)
        self.state_label.setStyleSheet(f"color:{C['warn']}; font-size:30px; font-weight:800;"
                                       " letter-spacing:1px;")
        left.addWidget(label("ESTADO GENERAL", "MetricCap", wrap=False))
        left.addWidget(self.state_label)
        self.state_detail = label("", "CardText")
        left.addWidget(self.state_detail)
        row.addLayout(left, 1)

        right = QVBoxLayout()
        right.setSpacing(8)
        right.addStretch(1)
        self.watch_btn = action_button("INICIAR VIGILANCIA DEMOSTRATIVA", "fa5s.play", "Primary",
                                       "#FFFFFF", self._toggle_watch)
        self.watch_btn.setMinimumHeight(42)
        self.watch_btn.setToolTip("Activa el modo demostración. No abre ninguna sesión ETW real "
                                  "ni toca el sistema.")
        right.addWidget(self.watch_btn)
        why = action_button("¿Por qué no dice «protegido»?", "", "Link", on_click=self._explain_state)
        right.addWidget(why, 0, Qt.AlignmentFlag.AlignRight)
        row.addLayout(right)

        self.banner.add_layout(row)
        self.add(self.banner)
        self._sync_state()

    def _explain_state(self) -> None:
        InfoDialog(
            "Por qué el estado no dice «protegido»",
            "Lozarus no afirma que un equipo está protegido si no está observándolo. Decirlo sin "
            "telemetría sería mentir, y es justo lo que el producto quiere evitar.",
            ["«Sin vigilancia» significa que ningún sensor está publicando eventos.",
             "«Sin datos» no es lo mismo que «todo correcto»: es la ausencia de información.",
             "Cuando OBSIDIAN esté implementado, además se mostrará qué ventanas de tiempo "
             "quedaron sin observar y cuántos eventos se perdieron.",
             "El colector ETW existe y está probado, pero esta beta NO lo conecta: hacerlo requiere "
             "Administrador y debe ser una acción explícita, nunca implícita por abrir una ventana."],
            note="Principio OBSIDIAN: el producto nunca declara «limpio» sobre lo que no pudo ver.",
            parent=self).exec()
        self.ctx.log("info", "Consultada la explicación del estado general")

    def _toggle_watch(self) -> None:
        self.ctx.set_demo(not self.ctx.demo)

    def _sync_state(self) -> None:
        if self.ctx.demo:
            self.state_label.setText("DEMOSTRACIÓN EN CURSO")
            self.state_label.setStyleSheet(f"color:{C['demo']}; font-size:30px; font-weight:800;"
                                           " letter-spacing:1px;")
            self.state_detail.setText(
                "Los eventos, incidentes y procesos que ves son SIMULADOS. Sirven para enseñar la "
                "interfaz, no describen nada que esté ocurriendo en este equipo.")
            self.watch_btn.setText("DETENER DEMOSTRACIÓN")
        else:
            self.state_label.setText("SIN VIGILANCIA")
            self.state_label.setStyleSheet(f"color:{C['warn']}; font-size:30px; font-weight:800;"
                                           " letter-spacing:1px;")
            self.state_detail.setText(
                "Ningún sensor está publicando eventos, así que no hay nada observado. Esto no "
                "significa que el equipo esté limpio: significa que no se está mirando.")
            self.watch_btn.setText("INICIAR VIGILANCIA DEMOSTRATIVA")

    # ------------------------------------------------------------------ métricas reales
    def _build_metrics(self) -> None:
        self.group("Equipo", f"Datos reales de este equipo · {host_label()}")
        host, add = grid(4)

        cpu_card = Card("Procesador", "fa5s.microchip")
        self.cpu_gauge = Gauge("CPU", C["blue"])
        wrap = QHBoxLayout()
        wrap.addStretch(1)
        wrap.addWidget(self.cpu_gauge)
        wrap.addStretch(1)
        cpu_card.add_layout(wrap)
        self.cpu_spark = Sparkline(C["blue"], 34)
        cpu_card.add(self.cpu_spark)
        add(cpu_card)

        ram_card = Card("Memoria", "fa5s.memory")
        self.ram_gauge = Gauge("RAM", C["cyan"])
        wrap2 = QHBoxLayout()
        wrap2.addStretch(1)
        wrap2.addWidget(self.ram_gauge)
        wrap2.addStretch(1)
        ram_card.add_layout(wrap2)
        self.ram_foot = label("—", "CardMeta")
        self.ram_foot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ram_card.add(self.ram_foot)
        add(ram_card)

        self.proc_card = MetricCard("Procesos en ejecución", "", "fa5s.list-ul", C["text"])
        add(self.proc_card)

        self.sensor_card = MetricCard("Sensores publicando", "de 6", "fa5s.satellite-dish", C["warn"])
        self.sensor_card.set_value(0, "Ninguno conectado: el colector ETW existe pero esta beta no "
                                      "lo arranca.")
        add(self.sensor_card)
        self.add(host)
        self._refresh_metrics()

    def _refresh_metrics(self) -> None:
        m = read_metrics()
        if not m.available:
            self.cpu_gauge.set_value(None)
            self.ram_gauge.set_value(None)
            self.proc_card.set_value(None, m.reason or "dato no disponible")
            self.ram_foot.setText(m.reason or "dato no disponible")
            return
        self.cpu_gauge.set_value(m.cpu_percent)
        self.cpu_spark.push(m.cpu_percent)
        self.ram_gauge.set_value(m.ram_percent)
        self.ram_foot.setText(f"{m.ram_used_gb:.1f} de {m.ram_total_gb:.1f} GB en uso")
        self.proc_card.set_value(m.processes, "Contados con psutil en este equipo.")

    # ------------------------------------------------------------------ telemetría
    def _build_telemetry(self) -> None:
        self.group("Telemetría", "Resumen de la observación. Un dato desconocido se muestra «—», "
                                 "nunca como cero.")
        row = QHBoxLayout()
        row.setSpacing(14)

        tele = Card("Eventos por segundo", "fa5s.chart-area")
        self.tele_badge_row = QHBoxLayout()
        self.tele_badge = DemoBadge("SERIE SIMULADA")
        self.tele_badge.setVisible(False)
        self.tele_badge_row.addWidget(self.tele_badge)
        self.tele_badge_row.addStretch(1)
        tele.add_layout(self.tele_badge_row)
        self.event_spark = Sparkline(C["demo"], 70)
        tele.add(self.event_spark)
        self.tele_note = label("Sin sensores conectados no hay eventos que contar.", "CardMeta")
        tele.add(self.tele_note)
        row.addWidget(tele, 2)

        loss = Card("Pérdidas", "fa5s.exclamation-triangle")
        loss.add_text("Lozarus cuenta por separado dos cosas que no son lo mismo:", "CardText")
        self.loss_src = label("Pérdida en el origen (ETW):  —  desconocida", "Mono")
        self.loss_bus = label("Descartes del bus interno:   —  desconocido", "Mono")
        loss.add(self.loss_src)
        loss.add(self.loss_bus)
        loss.add_text("Nunca se suman en una sola cifra, y un valor desconocido no se convierte en 0.",
                      "CardMeta")
        row.addWidget(loss, 1)
        self.add_layout(row)

    # ------------------------------------------------------------------ incidentes/actividad
    def _build_incidents(self) -> None:
        self.group("Incidentes y actividad")
        row = QHBoxLayout()
        row.setSpacing(14)

        self.inc_card = Card("Incidentes recientes", "fa5s.bell")
        self.inc_body = QVBoxLayout()
        self.inc_body.setSpacing(9)
        self.inc_card.add_layout(self.inc_body)
        row.addWidget(self.inc_card, 1)

        self.act_card = Card("Actividad reciente", "fa5s.stream")
        self.act_body = QVBoxLayout()
        self.act_body.setSpacing(0)
        self.act_card.add_layout(self.act_body)
        row.addWidget(self.act_card, 1)
        self.add_layout(row)
        self._fill_incidents()

    def _clear(self, layout) -> None:
        clear_layout(layout)

    def _fill_incidents(self) -> None:
        self._clear(self.inc_body)
        self._clear(self.act_body)
        if not self.ctx.demo:
            self.inc_body.addWidget(label(
                "No hay incidentes porque no hay observación. Inicia la vigilancia demostrativa "
                "para ver cómo se presentarían.", "CardText"))
            self.act_body.addWidget(label(
                "Sin actividad registrada. La cronología de ejemplo aparece en modo demostración.",
                "CardText"))
            return

        badge = QHBoxLayout()
        badge.addWidget(DemoBadge("INCIDENTES SIMULADOS"))
        badge.addStretch(1)
        self.inc_body.addLayout(badge)
        for ident, title, severity, state, summary in D.INCIDENTS:
            frame = QFrame()
            frame.setStyleSheet(f"QFrame {{ background-color:{C['surface2']};"
                                f" border-left:2px solid {D.SEVERITY_COLORS[severity]};"
                                f" border-radius:7px; }}")
            fl = vbox(frame, 11, 3)
            top = QHBoxLayout()
            top.setSpacing(8)
            tag = label(f"{ident} · {D.SEVERITY_LABELS[severity]}", "CardMeta", wrap=False)
            tag.setStyleSheet(f"color:{D.SEVERITY_COLORS[severity]}; font-size:10px; font-weight:700;")
            top.addWidget(tag)
            top.addStretch(1)
            top.addWidget(label(state, "CardMeta", wrap=False))
            fl.addLayout(top)
            fl.addWidget(label(title, "CardTitle"))
            fl.addWidget(label(summary, "CardText"))
            self.inc_body.addWidget(frame)

        badge2 = QHBoxLayout()
        badge2.addWidget(DemoBadge("CRONOLOGÍA SIMULADA"))
        badge2.addStretch(1)
        self.act_body.addLayout(badge2)
        self.act_body.addWidget(TimelineView(D.TIMELINE[:4]))

    # ------------------------------------------------------------------ accesos rápidos
    def _build_quick_access(self) -> None:
        self.group("Áreas del producto", "Todas las secciones son navegables.")
        host, add = grid(3)
        for key, title, ico, desc in QUICK_ACCESS:
            card = ClickableCard(title, ico)
            card.add_text(desc)
            card.clicked.connect(lambda k=key: self.ctx.navigate.emit(k))
            add(card)
        self.add(host)

        total = len(MODULES)
        counts = counts_by_status(MODULES)
        tested = sum(1 for c in CORE if c.status == "impl_tested")
        summary = Card("Dónde está el proyecto ahora mismo", "fa5s.info-circle")
        summary.add_text(
            f"De los {total} módulos de la arquitectura, <b>ninguno</b> tiene todavía pruebas "
            f"automáticas. Lo que sí está implementado y probado son {tested} piezas de "
            f"infraestructura: el modelo de eventos, los contratos, el bus y el colector ETW.")
        line = QHBoxLayout()
        line.setSpacing(7)
        for key in ("impl_partial", "designed", "needs_valid", "redesign"):
            if counts.get(key):
                tag = StatusTag(key, compact=True)
                tag.setToolTip(f"{counts[key]} módulos — {STATUS[key].label}")
                line.addWidget(tag)
                line.addWidget(label(f"{counts[key]}", "CardTitle", wrap=False))
                line.addSpacing(8)
        line.addStretch(1)
        summary.add_layout(line)
        go = action_button("Abrir el catálogo completo", "fa5s.th-list", "Mini",
                           on_click=lambda: self.ctx.navigate.emit("catalog"))
        summary.add(go)
        self.add(summary)

    # ------------------------------------------------------------------ ciclo de vida
    def showEvent(self, event) -> None:
        self._timer.start()
        super().showEvent(event)

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)

    def on_demo_changed(self, enabled: bool) -> None:
        self._sync_state()
        self._fill_incidents()
        self.tele_badge.setVisible(enabled)
        if enabled:
            self.event_spark.set_points(D.EVENT_RATE_DEMO)
            self.tele_note.setText("Serie simulada para ilustrar el gráfico. No hay sensores reales "
                                   "detrás de estos valores.")
            self.loss_src.setText("Pérdida en el origen (ETW):  —  desconocida (sesión no abierta)")
            self.loss_bus.setText("Descartes del bus interno:   0  (simulado)")
            self.sensor_card.set_value(1, "Sensor simulado. Ningún colector real está conectado.")
        else:
            self.event_spark.set_points([])
            self.tele_note.setText("Sin sensores conectados no hay eventos que contar.")
            self.loss_src.setText("Pérdida en el origen (ETW):  —  desconocida")
            self.loss_bus.setText("Descartes del bus interno:   —  desconocido")
            self.sensor_card.set_value(0, "Ninguno conectado: el colector ETW existe pero esta beta "
                                          "no lo arranca.")
