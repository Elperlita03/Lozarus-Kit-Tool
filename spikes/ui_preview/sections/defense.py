# -*- coding: utf-8 -*-
"""
4 · DEFENSA Y CONTENCIÓN — incidentes y respuestas.

Regla del producto que esta sección hace visible: **toda acción declara su impacto y si se puede
revertir, antes de ejecutarse.** En esta beta ninguna se ejecuta: no se cortan conexiones, no se
terminan procesos, no se tocan políticas de Windows.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout

import demodata as D
from sections._shared import data_table, demo_row, notice
from sections.base import Section
from theme import C
from widgets import Card, Chip, InfoDialog, TimelineView, action_button, grid, label, vbox


class DefenseSection(Section):
    KEY = "defense"
    TITLE = "Defensa y contención"
    KICKER = "04 · RESPUESTA"
    SUBTITLE = "Incidentes abiertos y qué se puede hacer, con el impacto siempre por delante."
    ICON = "fa5s.hand-paper"

    def build(self) -> None:
        self.add(notice(
            "Ningún botón de esta sección ejecuta una respuesta real. No se bloquean conexiones, no "
            "se terminan procesos, no se modifican el Registro ni las políticas de Windows. Cuando "
            "exista el servicio privilegiado, cada acción pasará por él con autorización por "
            "operación y quedará auditada.", C["crit"], "fa5s.exclamation-triangle"))

        self._build_incidents()
        self._build_containment()
        self._build_quarantine()
        self._build_policy()

    # ---------------------------------------------------------------- incidentes
    def _build_incidents(self) -> None:
        self.group("Incidentes", "Ejemplos para evaluar cómo se presenta un incidente.")
        row = QHBoxLayout()
        row.setSpacing(14)

        listing = Card("Abiertos y en revisión", "fa5s.folder-open")
        listing.add_layout(demo_row("INCIDENTES SIMULADOS"))
        for ident, title, severity, state, summary in D.INCIDENTS:
            frame = QFrame()
            frame.setStyleSheet(f"QFrame {{ background-color:{C['surface2']};"
                                f" border-left:3px solid {D.SEVERITY_COLORS[severity]};"
                                f" border-radius:8px; }}")
            fl = vbox(frame, 12, 4)
            head = QHBoxLayout()
            head.setSpacing(8)
            tag = label(f"{ident} · {D.SEVERITY_LABELS[severity]}", "CardMeta", wrap=False)
            tag.setStyleSheet(f"color:{D.SEVERITY_COLORS[severity]}; font-size:10px; font-weight:700;")
            head.addWidget(tag)
            head.addStretch(1)
            head.addWidget(Chip(state, C["text2"], "fa5s.circle"))
            fl.addLayout(head)
            fl.addWidget(label(title, "CardTitle"))
            fl.addWidget(label(summary, "CardText"))
            btn = action_button("Ver detalle", "fa5s.angle-right", "Link",
                               on_click=lambda i=ident, t=title, s=summary: self._incident(i, t, s))
            fl.addWidget(btn, 0, Qt.AlignmentFlag.AlignLeft)
            listing.add(frame)
        row.addWidget(listing, 1)

        chrono = Card("Cronología del incidente INC-0042", "fa5s.stream")
        chrono.add_layout(demo_row("CRONOLOGÍA SIMULADA"))
        chrono.add(TimelineView(D.TIMELINE))
        chrono.add(label(
            "Fíjate en la entrada atenuada: un hueco de observabilidad se muestra como lo que es. "
            "No se rellena con suposiciones ni se omite del relato.", "CardMeta"))
        row.addWidget(chrono, 1)
        self.add_layout(row)

    def _incident(self, ident: str, title: str, summary: str) -> None:
        InfoDialog(
            f"{ident} · {title}",
            summary,
            ["Observación: lo que el sensor vio directamente.",
             "Inferencia: lo que se deduce de varias observaciones.",
             "Conclusión: solo cuando la evidencia la sostiene.",
             "En la versión conectada, cada línea de la cronología enlazaría con el evento original "
             "y su procedencia."],
            note="Lozarus distingue siempre estos tres niveles para no presentar una sospecha como "
                 "un hecho probado.",
            parent=self).exec()
        self.ctx.log("info", f"Abierto el detalle del incidente {ident} (demostración)")

    # ---------------------------------------------------------------- contención
    def _build_containment(self) -> None:
        self.group("Respuestas disponibles",
                   "Ordenadas de menor a mayor impacto. Lo irreversible va siempre al final y "
                   "claramente marcado.")
        host, add = grid(2)
        for action, impact, reversible, explanation in D.CONTAINMENT:
            card = Card(action, "fa5s.shield-alt" if reversible else "fa5s.radiation")
            tags = QHBoxLayout()
            tags.setSpacing(7)
            impact_color = {"Bajo": C["ok"], "Medio": C["warn"], "Alto": C["redesign"],
                            "Muy alto": C["crit"]}.get(impact, C["text2"])
            tags.addWidget(Chip(f"Impacto: {impact}", impact_color, "fa5s.exclamation-circle"))
            if reversible:
                tags.addWidget(Chip("Reversible", C["ok"], "fa5s.undo"))
            else:
                tags.addWidget(Chip("IRREVERSIBLE", C["crit"], "fa5s.ban"))
            tags.addStretch(1)
            card.add_layout(tags)
            card.add_text(explanation)
            card.add(action_button(
                "Simular" if reversible else "Simular (requeriría confirmación reforzada)",
                "fa5s.play" if reversible else "fa5s.lock", "Mini",
                C["cyan"] if reversible else C["crit"],
                on_click=lambda a=action, r=reversible, e=explanation: self._simulate(a, r, e)))
            add(card)
        self.add(host)

    def _simulate(self, action: str, reversible: bool, explanation: str) -> None:
        self.ctx.act(action, "reversible" if reversible else "IRREVERSIBLE — exigiría doble confirmación")
        bullets = [explanation]
        if reversible:
            bullets.append("Se guardaría el estado previo para poder deshacerlo con un clic.")
        else:
            bullets.append("No hay vuelta atrás. En producción exigiría mantener pulsado el botón y "
                           "escribir una palabra clave, y solo después de preservar la evidencia.")
        bullets.append("La evidencia se preservaría y verificaría por hash ANTES de actuar.")
        InfoDialog(f"Simulación · {action}",
                   "Así se presentaría esta respuesta en la versión conectada. Aquí no se ejecuta nada.",
                   bullets,
                   note="Registrado en la consola de demostración, abajo.",
                   parent=self).exec()

    # ---------------------------------------------------------------- cuarentena
    def _build_quarantine(self) -> None:
        self.group("Cuarentena", "Aislar sin destruir: la evidencia se copia y se verifica antes.")
        card = Card()
        card.add_layout(demo_row("CUARENTENA SIMULADA"))
        card.add(data_table(["Archivo", "Origen", "Hash (SHA-256)", "Fecha", "Estado"],
                            D.QUARANTINE, height=120))
        card.add(label(
            "El orden importa: primero se copia el archivo y se comprueba que la copia tiene el "
            "mismo hash; solo entonces se mueve el original. Queda un manifiesto que permite "
            "restaurarlo.", "CardMeta"))
        row = QHBoxLayout()
        row.setSpacing(9)
        row.addWidget(action_button("Restaurar (demostración)", "fa5s.undo", "Mini",
                                    on_click=lambda: self.ctx.act("Restaurar de cuarentena")))
        row.addWidget(action_button("Exportar manifiesto (demostración)", "fa5s.file-export", "Mini",
                                    on_click=lambda: self.ctx.act("Exportar manifiesto")))
        row.addStretch(1)
        card.add_layout(row)
        self.add(card)

    # ---------------------------------------------------------------- política
    def _build_policy(self) -> None:
        self.group("Reglas que el producto se impone")
        card = Card("Observación y ejecución están separadas", "fa5s.balance-scale")
        from widgets import bullet_list
        card.add(bullet_list([
            "Los sensores solo observan: nunca ejecutan respuestas.",
            "Los motores de detección solo leen y puntúan: nunca actúan.",
            "Solo el motor de respuesta actúa, y lo privilegiado pasa por un servicio aparte.",
            "La interfaz nunca ejecuta operaciones privilegiadas directamente.",
            "Preservar evidencia va antes que limpiar o reparar, siempre que sea viable.",
            "Nada de contraataques, sabotaje remoto ni destrucción de datos de terceros.",
        ], "fa5s.check", C["ok"]))
        card.add(label(
            "Hoy la interfaz de producción todavía llama a PowerShell directamente: es deuda técnica "
            "reconocida y documentada, pendiente del servicio privilegiado.", "CardMeta"))
        self.add(card)
