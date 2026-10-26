# -*- coding: utf-8 -*-
"""
8 · LABORATORIO FORENSE — cronologías, evidencia, análisis PE, CHRONOS, IRONCLAD y OBSIDIAN.

Todo lo forense arranca en SOLO LECTURA y con procedencia por dato: cada hallazgo dice de qué
artefacto sale y si es observación, inferencia o conclusión.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout

import demodata as D
from catalog import MODULES
from sections._shared import data_table, demo_row, notice
from sections.base import Section
from theme import C
from widgets import (BarRow, Card, Chip, InfoDialog, KeyValue, StatusTag, TimelineView,
                     action_button, bullet_list, grid, label)

PILLARS = [
    ("OBSIDIAN", "fa5s.eye", "designed",
     "Vigila que la vigilancia funcione: cobertura, huecos y pérdidas.",
     "Es el módulo que impide que el producto mienta. Prioridad máxima.",
     "Sus contratos (SensorHealth, LossState) ya están implementados y probados en core/."),
    ("CHRONOS", "fa5s.history", "designed",
     "Reconstruye qué pasó y en qué orden.",
     "Une diario de cambios NTFS, tabla maestra de archivos, Prefetch, Amcache y registros.",
     "Debe detectar lagunas y NO atribuir un cambio a un proceso solo por cercanía temporal."),
    ("IRONCLAD", "fa5s.lock", "designed",
     "Comprueba la cadena de confianza desde el encendido.",
     "Arranque seguro, virtualización de seguridad e inventario de controladores firmados.",
     "Desde modo usuario es observacional, no una verificación a prueba de manipulación."),
]


class ForensicsSection(Section):
    KEY = "forensics"
    TITLE = "Laboratorio forense"
    KICKER = "08 · EVIDENCIA Y CRONOLOGÍA"
    SUBTITLE = "Reconstruir lo ocurrido sin alterar lo que se investiga."
    ICON = "fa5s.fingerprint"

    def build(self) -> None:
        self.add(notice(
            "El trabajo forense de Lozarus es de SOLO LECTURA. La evidencia se copia y se verifica "
            "por hash antes de tocar nada, y nunca se escribe sobre el soporte investigado. Lo que "
            "ves aquí son ejemplos: la beta no analiza archivos reales.", C["cyan"], "fa5s.fingerprint"))

        self._build_pillars()
        self._build_blackbox()
        self._build_timeline()
        self._build_pe()
        self._build_evidence()

    # ---------------------------------------------------------------- pilares
    def _build_pillars(self) -> None:
        self.group("Los tres pilares forenses", "Diseñados en detalle, pendientes de implementación.")
        host, add = grid(3)
        for name, ico, status, objective, detail, note in PILLARS:
            card = Card(name, ico)
            tags = QHBoxLayout()
            tags.addWidget(StatusTag(status, compact=True))
            tags.addStretch(1)
            card.add_layout(tags)
            card.add_text(objective)
            card.add(label(detail, "CardText"))
            card.add(label(note, "CardMeta"))
            add(card)
        self.add(host)

    # ---------------------------------------------------------------- caja negra
    def _build_blackbox(self) -> None:
        self.group("Caja Negra", "La ventana reciente de todo lo observado, para poder mirar atrás.")
        row = QHBoxLayout()
        row.setSpacing(14)

        concept = Card("Cómo funciona el búfer circular", "fa5s.circle-notch")
        tags = QHBoxLayout()
        tags.addWidget(StatusTag("designed", compact=True))
        tags.addStretch(1)
        concept.add_layout(tags)
        concept.add_text(
            "Como la caja negra de un avión: guarda siempre los últimos N minutos. Cuando el búfer "
            "se llena, lo más antiguo se sobrescribe. Si salta una alerta, se puede reconstruir qué "
            "pasó justo antes.")
        concept.add(bullet_list([
            "Se suscribe al bus de eventos, que ya existe y está probado.",
            "Escribe en disco de forma append-only, sin bloquear al sensor.",
            "La ventana está limitada: lo que queda fuera se marca como hueco, no se oculta.",
            "Rescue podrá LEER una Caja Negra dejada por Sentinel, aunque el equipo ya no arranque.",
        ], "fa5s.angle-right", C["cyan"]))
        row.addWidget(concept, 1)

        state = Card("Estado del búfer", "fa5s.database")
        state.add_layout(demo_row("OCUPACIÓN SIMULADA"))
        state.add(BarRow("Eventos en memoria", 0, 10000, C["blue"]))
        state.add(BarRow("Escritos en disco", 0, 10000, C["cyan"]))
        state.add(BarRow("Huecos declarados", 0, 10, C["warn"]))
        state.add(label(
            "Todo a cero porque la Caja Negra todavía no existe: es la siguiente pieza a construir "
            "(Fase 3B), junto a OBSIDIAN.", "CardMeta"))
        state.add(action_button("¿Qué falta para tenerla?", "fa5s.question-circle", "Mini",
                                on_click=self._explain_blackbox))
        row.addWidget(state, 1)
        self.add_layout(row)

    def _explain_blackbox(self) -> None:
        InfoDialog(
            "Caja Negra — qué falta",
            "El transporte ya está resuelto: el bus de eventos existe, está probado y expone "
            "suscripción. Lo que falta es el consumidor que persiste.",
            ["Un consumidor que se suscriba al bus y escriba cada evento a un diario append-only.",
             "Rotación por tamaño o fecha, para que no crezca sin control.",
             "Escritura en un hilo propio: el bus no puede quedarse esperando al disco.",
             "Métricas propias: eventos escritos, fallos de escritura, rotaciones.",
             "Tolerancia a errores de disco sin tumbar al resto del sistema."],
            note="Es exactamente el alcance de la Fase 3B, junto con OBSIDIAN.",
            parent=self).exec()
        self.ctx.log("info", "Consultado el estado de la Caja Negra")

    # ---------------------------------------------------------------- cronología
    def _build_timeline(self) -> None:
        self.group("Cronología de incidente",
                   "Cada entrada debería enlazar con el artefacto del que sale.")
        card = Card()
        card.add_layout(demo_row("CRONOLOGÍA SIMULADA"))
        card.add(TimelineView(D.TIMELINE))
        card.add(label(
            "Regla de rigor: observación, inferencia y conclusión son tres cosas distintas. Que un "
            "archivo cambie justo después de que arranque un proceso NO demuestra que lo cambiara "
            "ese proceso.", "CardMeta"))
        self.add(card)

    # ---------------------------------------------------------------- análisis PE
    def _build_pe(self) -> None:
        self.group("Mesa de autopsias — análisis estático",
                   "Examinar un ejecutable sin llegar a ejecutarlo.")
        row = QHBoxLayout()
        row.setSpacing(14)

        detail = Card("Informe del archivo", "fa5s.file-code")
        tags = QHBoxLayout()
        tags.addWidget(StatusTag("designed", compact=True))
        tags.addWidget(Chip("pefile ya instalado", C["ok"], "fa5s.check"))
        tags.addStretch(1)
        detail.add_layout(tags)
        detail.add_layout(demo_row("INFORME SIMULADO"))
        for key, value in D.PE_SAMPLE.items():
            detail.add(KeyValue(key, value))
        detail.add(label(D.PE_NOTE, "CardMeta"))
        row.addWidget(detail, 2)

        why = Card("Por qué importa", "fa5s.lightbulb")
        why.add_text(
            "Es el mejor candidato del núcleo compartido: analizar un archivo funciona igual en un "
            "Windows en marcha que en un disco apagado examinado desde el USB de rescate.")
        why.add(bullet_list([
            "No requiere privilegios especiales.",
            "No ejecuta nada: es seguro por construcción.",
            "Mismo código en Sentinel y en Rescue.",
            "Solo depende de pefile y de la biblioteca estándar.",
        ], "fa5s.check", C["ok"]))
        row.addWidget(why, 1)
        self.add_layout(row)

    # ---------------------------------------------------------------- evidencia
    def _build_evidence(self) -> None:
        self.group("Evidencia e informes")
        row = QHBoxLayout()
        row.setSpacing(14)

        policy = Card("Política de evidencia", "fa5s.clipboard-list")
        policy.add(bullet_list([
            "Nunca se escribe en el soporte investigado: la evidencia va a un destino aparte.",
            "Hash SHA-256 antes y después de copiar. Si no coinciden, la copia se marca como "
            "NO verificada.",
            "Manifiesto append-only con una línea por artefacto y su procedencia.",
            "Marcas de tiempo honestas: hora original, tipo de reloj y UTC solo si es fiable.",
            "Nunca se borra nada antes de tener la evidencia copiada y verificada.",
            "Si un artefacto falta o es ilegible, se registra como laguna, no se omite.",
        ], "fa5s.shield-alt", C["ok"]))
        row.addWidget(policy, 1)

        files = Card("Lo que ya existe", "fa5s.folder")
        tags = QHBoxLayout()
        tags.addWidget(StatusTag("impl_partial", compact=True))
        tags.addStretch(1)
        files.add_layout(tags)
        files.add_text(
            "La carpeta Lozarus_Forensics/ ya recoge instantáneas, informes por proceso y los "
            "señuelos. El hashing SHA-256 también existe en modulos/_forense.py.")
        files.add(data_table(["Carpeta", "Contenido"], [
            ("Lozarus_Forensics/Snapshots", "Instantáneas del estado del sistema"),
            ("Lozarus_Forensics/Honeypot", "Archivos señuelo desplegados"),
            ("Lozarus_Forensics/Sandbox", "Material del laboratorio desechable"),
        ], height=110))
        files.add(label(
            "Falta formalizarlo en un paquete `evidence/` compartido, con manifiesto y cadena de "
            "custodia: hoy son informes de texto sueltos.", "CardMeta"))
        row.addWidget(files, 1)
        self.add_layout(row)

        caps = [m for m in MODULES if m.area == "Forense y evidencia"]
        self.group("Capacidades de esta área", f"{len(caps)} módulos de la arquitectura.")
        host, add = grid(3)
        for cap in caps:
            card = Card(cap.label, "fa5s.fingerprint")
            t = QHBoxLayout()
            t.addWidget(StatusTag(cap.status, compact=True))
            t.addStretch(1)
            card.add_layout(t)
            card.add_text(cap.description)
            add(card)
        self.add(host)
