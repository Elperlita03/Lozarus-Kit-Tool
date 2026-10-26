# -*- coding: utf-8 -*-
"""
6 · MEMORIA Y BAJO NIVEL — Phantom Map y análisis de procesos.

Esta sección existe sobre todo para enseñar un límite honesto: desde modo usuario, el análisis de
memoria produce INDICIOS, no pruebas, y hay procesos que simplemente no se pueden inspeccionar. El
producto está obligado a listar lo que NO pudo ver, en vez de darlo por limpio.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout

from catalog import MODULES
from sections._shared import data_table, demo_row, notice
from sections.base import Section
from theme import C
from widgets import Card, FlowDiagram, InfoDialog, StatusTag, action_button, grid, label

# Procesos no inspeccionables (simulado, pero los motivos son reales)
NOT_INSPECTABLE = [
    ("lsass.exe", 788, "Proceso protegido (PPL)", "RunAsPPL impide leer su memoria."),
    ("MsMpEng.exe", 3204, "Proceso protegido (antimalware)", "Defender corre como PPL."),
    ("csrss.exe", 644, "Integridad superior", "Requiere privilegios que la interfaz no tiene."),
    ("services.exe", 712, "Integridad superior", "Requiere Administrador."),
    ("smss.exe", 540, "Proceso del sistema", "No accesible desde modo usuario."),
]

PIPELINE = [
    ("Imagen en disco", "El archivo .exe tal como está guardado", "impl_partial"),
    ("Secciones en memoria", "Lo que de verdad se está ejecutando", "needs_valid"),
    ("Comparación", "Buscar diferencias entre ambos", "needs_valid"),
    ("Indicio", "Nunca una prueba: siempre con nivel de confianza", "designed"),
]


class MemorySection(Section):
    KEY = "memory"
    TITLE = "Memoria y bajo nivel"
    NAV_LABEL = "Memoria"
    KICKER = "06 · ANÁLISIS PROFUNDO"
    SUBTITLE = "Phantom Map, módulos inyectados y los límites reales de mirar la memoria."
    ICON = "fa5s.microchip"

    def build(self) -> None:
        self.add(notice(
            "Lo que se obtiene aquí son INDICIOS con nivel de confianza, nunca veredictos. Un EDR en "
            "modo usuario no puede probar una inyección: la telemetría a prueba de manipulación vive "
            "en un proveedor de Windows reservado a antivirus firmados por Microsoft. Es el límite "
            "más importante del proyecto.", C["warn"], "fa5s.balance-scale"))

        self._build_phantom()
        self._build_modules()
        self._build_blindspots()
        self._build_capabilities()

    # ---------------------------------------------------------------- phantom map
    def _build_phantom(self) -> None:
        self.group("Phantom Map — disco contra memoria",
                   "La idea: si algo se inyectó en un proceso, lo que corre en memoria deja de "
                   "parecerse al archivo original.")
        card = Card()
        card.add(FlowDiagram(PIPELINE))
        legend = QHBoxLayout()
        legend.setSpacing(9)
        for key in ("impl_partial", "needs_valid", "designed"):
            legend.addWidget(StatusTag(key, compact=True))
        legend.addStretch(1)
        card.add_layout(legend)
        card.add(label(
            "Estado real: el módulo 21 está PENDIENTE DE VALIDACIÓN TÉCNICA. Antes de implementarlo "
            "hace falta un prototipo que mida su cobertura real y su tasa de falsos positivos.",
            "CardMeta"))
        self.add(card)

    # ---------------------------------------------------------------- módulos cargados
    def _build_modules(self) -> None:
        self.group("Módulos cargados en procesos anfitriones",
                   "Esto sí existe hoy: modulos/13_inyecciones.py revisa procesos que suelen usarse "
                   "como anfitriones buscando bibliotecas que no deberían estar ahí.")
        card = Card()
        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(StatusTag("impl_partial", compact=True))
        top.addWidget(label("Código real, sin pruebas automáticas", "CardMeta", wrap=False))
        top.addStretch(1)
        card.add_layout(top)
        card.add_layout(demo_row("HALLAZGOS SIMULADOS"))
        rows = [
            ("explorer.exe", "4820", "upd_7742.dll", "%TEMP%", "sin firma", "Indicio alto"),
            ("svchost.exe", "1304", "—", "—", "—", "Sin anomalías"),
            ("chrome.exe", "9112", "—", "—", "—", "Sin anomalías"),
        ]
        card.add(data_table(
            ["Proceso anfitrión", "PID", "Módulo extraño", "Ruta", "Firma", "Valoración"],
            rows, height=120))
        card.add(label(
            "Los procesos del sistema (svchost, lsass…) solo son legibles como Administrador. Sin "
            "elevación se cuentan como inaccesibles y se recomienda repetir elevado, en lugar de "
            "informar de que están limpios.", "CardMeta"))
        self.add(card)

    # ---------------------------------------------------------------- puntos ciegos
    def _build_blindspots(self) -> None:
        self.group("Lo que NO se pudo inspeccionar",
                   "El principio OBSIDIAN aplicado aquí: declarar los puntos ciegos en vez de "
                   "silenciarlos.")
        card = Card("Procesos fuera de alcance", "fa5s.eye-slash")
        card.add_layout(demo_row("EJEMPLO ILUSTRATIVO — LOS MOTIVOS SON REALES"))
        card.add(data_table(["Proceso", "PID", "Motivo", "Explicación"],
                            [(n, str(p), m, e) for n, p, m, e in NOT_INSPECTABLE], height=165))
        card.add(label(
            "Un informe que omitiera esta tabla estaría afirmando implícitamente que esos procesos "
            "están limpios. No lo sabemos: no pudimos mirarlos.", "CardMeta"))
        card.add(action_button("¿Por qué no se pueden leer?", "fa5s.question-circle", "Mini",
                               on_click=self._explain))
        self.add(card)

    def _explain(self) -> None:
        InfoDialog(
            "Por qué algunos procesos no se pueden inspeccionar",
            "Windows protege deliberadamente ciertos procesos para que ni un administrador pueda "
            "leer su memoria con facilidad. Es una buena noticia para la seguridad del equipo y una "
            "limitación real para cualquier herramienta de análisis en modo usuario.",
            ["PPL (Protected Process Light): LSASS con RunAsPPL y los antivirus corren así. "
             "Leer su memoria exige ser, a su vez, un proceso protegido firmado por Microsoft.",
             "Credential Guard: aísla las credenciales en un entorno virtualizado aparte.",
             "Nivel de integridad: un proceso de integridad media no puede leer uno superior.",
             "Para superar esto haría falta un driver antimalware firmado (ELAM), que es un "
             "proyecto completamente distinto: firma, WHQL y mantenimiento de un driver."],
            note="Por eso Lozarus se posiciona como asistente de observabilidad y forense honesto, "
                 "no como un EDR que lo ve todo.",
            parent=self).exec()
        self.ctx.log("info", "Consultados los límites de inspección de memoria")

    # ---------------------------------------------------------------- capacidades
    def _build_capabilities(self) -> None:
        caps = [m for m in MODULES if m.area == "Memoria y bajo nivel"]
        self.group("Capacidades de esta área", f"{len(caps)} módulos de la arquitectura.")
        host, add = grid(3)
        for cap in caps:
            card = Card(cap.label, "fa5s.microchip")
            tags = QHBoxLayout()
            tags.addWidget(StatusTag(cap.status, compact=True))
            tags.addStretch(1)
            card.add_layout(tags)
            card.add_text(cap.description)
            if cap.limits:
                card.add(label(f"Límite: {cap.limits}", "CardMeta"))
            add(card)
        self.add(host)
