# -*- coding: utf-8 -*-
"""
5 · CAMPO DE SEÑUELOS — inventario y activaciones de engaño defensivo.

Perímetro ético fijado en docs/00 §3.2: solo engaño **inocuo y pasivo** (archivos cebo que avisan).
El engaño activo (shell falso, tarpitting, redes de espejismo) está descartado fuera de un
laboratorio aislado y autorizado. Los señuelos NUNCA contienen credenciales reales.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout

import demodata as D
from sections._shared import data_table, demo_row, notice
from sections.base import Section
from theme import C
from widgets import Card, InfoDialog, StatusTag, action_button, bullet_list, grid, label

EXCLUDED = [
    ("17 · Shell señuelo", "Entretener a un intruso con una consola falsa.",
     "Añade superficie de ataque al equipo real y aporta poco valor defensivo."),
    ("18 · Tarpitting", "Ralentizar deliberadamente a un atacante.",
     "Puede atrapar tráfico legítimo. Solo admisible en entorno controlado."),
    ("19 · Red de Espejismos", "Simular una red entera falsa.",
     "Requiere virtualización; es claramente de laboratorio."),
]


class DecoysSection(Section):
    KEY = "decoys"
    TITLE = "Campo de señuelos"
    KICKER = "05 · ENGAÑO DEFENSIVO"
    SUBTITLE = "Cebos inocuos que avisan si alguien husmea. Nada de engaño activo."
    ICON = "fa5s.eye"

    def build(self) -> None:
        self.add(notice(
            "Los señuelos de Lozarus solo DETECTAN y AVISAN: no bloquean, no engañan activamente y "
            "no contienen credenciales reales. Un archivo cebo es un archivo sin valor cuyo único "
            "propósito es que nadie legítimo lo abra nunca.", C["cyan"], "fa5s.eye"))

        self._build_inventory()
        self._build_how()
        self._build_excluded()

    # ---------------------------------------------------------------- inventario
    def _build_inventory(self) -> None:
        self.group("Inventario de señuelos")
        card = Card()
        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(StatusTag("impl_partial", compact=True))
        top.addWidget(label("Los archivos señuelo ya existen en modulos/_defensa_local.py "
                            "(deploy_canaries, scan_canaries)", "CardMeta"))
        top.addStretch(1)
        card.add_layout(top)
        card.add_layout(demo_row("INVENTARIO SIMULADO"))
        rows = [(t, n, loc, st, str(act) if act else "ninguna")
                for t, n, loc, st, act in D.DECOYS]
        card.add(data_table(["Tipo", "Nombre", "Ubicación", "Estado", "Activaciones"], rows,
                            height=165))
        row = QHBoxLayout()
        row.setSpacing(9)
        row.addWidget(action_button("Desplegar señuelos (demostración)", "fa5s.plus", "Mini",
                                    on_click=lambda: self.ctx.act("Desplegar señuelos")))
        row.addWidget(action_button("Comprobar activaciones (demostración)", "fa5s.sync", "Mini",
                                    on_click=lambda: self.ctx.act("Comprobar activaciones")))
        row.addWidget(action_button("Retirar señuelos (demostración)", "fa5s.minus", "Mini",
                                    on_click=lambda: self.ctx.act("Retirar señuelos")))
        row.addStretch(1)
        card.add_layout(row)
        self.add(card)

    # ---------------------------------------------------------------- cómo funciona
    def _build_how(self) -> None:
        self.group("Cómo funciona", "Explicado para quien no es experto.")
        host, add = grid(3)

        what = Card("Qué es un archivo señuelo", "fa5s.file-alt")
        what.add_text(
            "Un archivo con un nombre apetecible («Contraseñas_backup.xlsx») que no contiene nada "
            "real. Nadie que use el equipo con normalidad tiene motivo para abrirlo. Si se abre, "
            "cifra o copia, algo anda mal.")
        add(what)

        why = Card("Por qué es fiable", "fa5s.thumbs-up")
        why.add(bullet_list([
            "Tasa de falsos positivos muy baja: no hay razón legítima para tocarlo.",
            "No modifica el sistema ni añade superficie de ataque.",
            "Detecta ransomware en una fase temprana: cifra todo lo que encuentra, incluido el cebo.",
            "Es reversible: retirar los señuelos no deja rastro.",
        ], "fa5s.check", C["ok"]))
        add(why)

        limits = Card("Sus límites", "fa5s.exclamation-circle")
        limits.add(bullet_list([
            "Solo avisa; no detiene nada por sí mismo.",
            "Para registrar QUIÉN abrió el archivo hace falta auditoría SACL, que requiere "
            "Administrador.",
            "Un atacante cuidadoso puede evitarlos si sospecha que existen.",
            "Las credenciales sintéticas son mucho menos útiles en un equipo suelto: detectar su "
            "USO requiere telemetría de dominio.",
        ], "fa5s.minus", C["warn"]))
        add(limits)
        self.add(host)

    # ---------------------------------------------------------------- excluidos
    def _build_excluded(self) -> None:
        self.group("Descartado del equipo real",
                   "Tres capacidades del diseño original que no entran en el producto base.")
        host, add = grid(3)
        for name, objective, reason in EXCLUDED:
            card = Card(name, "fa5s.ban")
            tags = QHBoxLayout()
            tags.addWidget(StatusTag("redesign", compact=True))
            tags.addStretch(1)
            card.add_layout(tags)
            card.add_text(objective)
            card.add(label(f"Por qué: {reason}", "CardMeta"))
            card.add(action_button("Ver la alternativa", "fa5s.lightbulb", "Link",
                                   on_click=lambda n=name, r=reason: self._alternative(n, r)))
            add(card)
        self.add(host)

    def _alternative(self, name: str, reason: str) -> None:
        InfoDialog(
            f"{name} — alternativa segura",
            f"Se descartó porque: {reason}",
            ["La detección inocua (archivos señuelo) cubre la mayor parte del valor sin el riesgo.",
             "Si algún día se quiere engaño activo, debe vivir dentro del Mirror Lab: una máquina "
             "desechable, aislada y etiquetada como entorno autorizado.",
             "Fuera de ese laboratorio, queda excluido del producto."],
            note="Decisión registrada en docs/00_AUDITORIA_ARQUITECTURA.md §3.2.",
            parent=self).exec()
        self.ctx.log("info", f"Consultada la alternativa para «{name}»")
