# -*- coding: utf-8 -*-
"""10 · AJUSTES Y AUDITORÍA — configuración, sensores, registro y estado de las funciones."""

from __future__ import annotations

import platform
import sys

from PySide6.QtWidgets import QHBoxLayout

from catalog import MODULES, counts_by_status
from runtime import HAS_PSUTIL, host_label
from sections._shared import data_table, notice
from sections.base import Section
from theme import C, HAS_QTA, STATUS, STATUS_ORDER
from widgets import BarRow, Card, InfoDialog, KeyValue, action_button, bullet_list, label


class SettingsSection(Section):
    KEY = "settings"
    TITLE = "Ajustes y auditoría"
    NAV_LABEL = "Ajustes"
    KICKER = "10 · CONFIGURACIÓN"
    SUBTITLE = "Entorno, dependencias, registro de la sesión y estado global del proyecto."
    ICON = "fa5s.sliders-h"

    def build(self) -> None:
        self.add(notice(
            "Esta beta no guarda configuración en disco, no escribe en el Registro de Windows y no "
            "modifica ningún ajuste del sistema. Los controles de abajo solo afectan a la propia "
            "ventana.", C["cyan"], "fa5s.info-circle"))

        self._build_environment()
        self._build_demo()
        self._build_project()
        self._build_log()

    # ---------------------------------------------------------------- entorno
    def _build_environment(self) -> None:
        self.group("Entorno de ejecución", "Comprobado al arrancar esta ventana.")
        row = QHBoxLayout()
        row.setSpacing(14)

        env = Card("Este equipo", "fa5s.desktop")
        env.add(KeyValue("Equipo", host_label()))
        env.add(KeyValue("Python", sys.version.split()[0]))
        env.add(KeyValue("Arquitectura", platform.machine()))
        row.addWidget(env, 1)

        deps = Card("Dependencias de la beta", "fa5s.cubes")
        try:
            import PySide6
            pyside = PySide6.__version__
        except Exception:
            pyside = "no disponible"
        deps.add(KeyValue("PySide6", pyside, C["ok"] if pyside != "no disponible" else C["crit"]))
        deps.add(KeyValue("qtawesome", "disponible" if HAS_QTA else "ausente (iconos desactivados)",
                          C["ok"] if HAS_QTA else C["warn"]))
        deps.add(KeyValue("psutil", "disponible" if HAS_PSUTIL else "ausente (CPU/RAM sin datos)",
                          C["ok"] if HAS_PSUTIL else C["warn"]))
        deps.add(label(
            "La beta degrada con elegancia: sin qtawesome pierde los iconos y sin psutil muestra "
            "«—» en las métricas, pero sigue siendo navegable.", "CardMeta"))
        row.addWidget(deps, 1)

        warn = Card("Deuda detectada en el proyecto", "fa5s.exclamation-triangle")
        warn.add(bullet_list([
            "No existe requirements.txt en la raíz: PySide6, psutil, qtawesome y plyer están sin "
            "declarar. Es necesario fijarlo antes de empaquetar nada.",
            "La interfaz de producción llama a PowerShell directamente, sin pasar por un servicio "
            "privilegiado. Es deuda reconocida y documentada.",
            "El colector ETW existe y está probado, pero ninguna interfaz lo consume todavía.",
        ], "fa5s.angle-right", C["warn"]))
        row.addWidget(warn, 1)
        self.add_layout(row)

    # ---------------------------------------------------------------- demostración
    def _build_demo(self) -> None:
        self.group("Modo demostración")
        card = Card("Qué cambia al activarlo", "fa5s.desktop")
        card.add(bullet_list([
            "Aparecen incidentes, procesos, conexiones y cronologías SIMULADOS.",
            "Cada bloque simulado lleva una etiqueta violeta «DATO DE DEMOSTRACIÓN».",
            "El estado general pasa a «DEMOSTRACIÓN EN CURSO», nunca a «protegido».",
            "No se abre ninguna sesión ETW, no se lee el Registro y no se tocan procesos.",
        ], "fa5s.angle-right", C["demo"]))
        row = QHBoxLayout()
        row.setSpacing(9)
        self.toggle = action_button("Activar modo demostración", "fa5s.play", "Primary", "#FFFFFF",
                                    lambda: self.ctx.set_demo(not self.ctx.demo))
        row.addWidget(self.toggle)
        row.addWidget(action_button("¿Por qué no hay datos reales?", "fa5s.question-circle", "Mini",
                                    on_click=self._explain))
        row.addStretch(1)
        card.add_layout(row)
        self.add(card)
        self._sync_toggle()

    def _explain(self) -> None:
        InfoDialog(
            "Por qué esta beta no muestra datos reales de seguridad",
            "Porque mostrarlos exigiría ejecutar operaciones privilegiadas, y eso no puede ocurrir "
            "por el simple hecho de abrir una ventana de pruebas.",
            ["Abrir una sesión ETW requiere Administrador y crea un recurso en el sistema.",
             "Ejecutar los módulos de auditoría lanza procesos de PowerShell.",
             "Leer memoria de otros procesos requiere permisos que un prototipo no debería pedir.",
             "Cuando conectemos el backend, será un modo explícito y separado, con su propio aviso.",
             "Lo único real que ves aquí son CPU, RAM y número de procesos de ESTE equipo."],
            note="Principio del proyecto: la observación y la ejecución están separadas, y nada "
                 "privilegiado ocurre de forma implícita.",
            parent=self).exec()
        self.ctx.log("info", "Consultado el porqué del modo demostración")

    def _sync_toggle(self) -> None:
        self.toggle.setText("Detener modo demostración" if self.ctx.demo
                            else "Activar modo demostración")

    def on_demo_changed(self, enabled: bool) -> None:
        self._sync_toggle()

    # ---------------------------------------------------------------- proyecto
    def _build_project(self) -> None:
        self.group("Estado global del proyecto",
                   "Lo mismo que muestra el catálogo, resumido.")
        row = QHBoxLayout()
        row.setSpacing(14)

        bars = Card("Los 41 módulos por estado", "fa5s.chart-bar")
        counts = counts_by_status(MODULES)
        for key in STATUS_ORDER:
            if counts.get(key):
                bars.add(BarRow(STATUS[key].label, counts[key], len(MODULES), STATUS[key].color))
        row.addWidget(bars, 1)

        tested = Card("Pruebas automáticas que existen hoy", "fa5s.vial")
        tested.add(data_table(["Componente", "Pruebas"], [
            ("core/events.py", "12"),
            ("core/contracts.py", "9 (4 pérdidas + 5 contrato)"),
            ("core/bus.py", "8"),
            ("collectors/etw_collector.py", "13 (sin Administrador)"),
            ("spikes/etw (prototipo)", "8 + integración"),
            ("TOTAL en producción", "42"),
        ], height=185))
        tested.add(label(
            "Las pruebas del colector ETW corren sin privilegios porque inyectan una sesión falsa. "
            "La captura real es una prueba de integración aparte, que se salta si no hay "
            "Administrador en vez de fingir que pasa.", "CardMeta"))
        row.addWidget(tested, 1)
        self.add_layout(row)

        docs = Card("Documentación del proyecto", "fa5s.book")
        docs.add(data_table(["Documento", "Contenido"], [
            ("docs/00_AUDITORIA_ARQUITECTURA.md", "Matriz de viabilidad de los 41 módulos"),
            ("docs/01_ARQUITECTURA_PROYECTO.md", "Árbol de paquetes y reglas de dependencia"),
            ("docs/02_CONTRATOS_EVENTOS.md", "Modelo de evento, bus y contratos"),
            ("docs/03_COLECTOR_ETW.md", "Colector ETW: diseño, tiempo, pérdidas y límites"),
            ("docs/05_PRODUCTO_SENTINEL_RESCUE.md", "Producto dual Sentinel + Rescue USB"),
        ], height=175))
        self.add(docs)

    # ---------------------------------------------------------------- registro
    def _build_log(self) -> None:
        self.group("Registro de la sesión",
                   "Todas las interacciones de demostración quedan anotadas abajo, en la consola.")
        card = Card("Auditoría de la propia herramienta", "fa5s.clipboard-list")
        card.add_text(
            "Lozarus registra lo que hace. En esta beta eso significa anotar cada navegación y cada "
            "acción demostrativa que se bloquea. En producción, el mismo principio cubre cada acción "
            "privilegiada: quién la pidió, con qué argumentos y qué resultado tuvo.")
        row = QHBoxLayout()
        row.setSpacing(9)
        row.addWidget(action_button("Vaciar la consola", "fa5s.eraser", "Mini",
                                    on_click=lambda: self.ctx.log("info", "Consola vaciada")))
        row.addWidget(action_button("Exportar registro (demostración)", "fa5s.file-export", "Mini",
                                    on_click=lambda: self.ctx.act("Exportar registro de sesión")))
        row.addStretch(1)
        card.add_layout(row)
        self.add(card)
