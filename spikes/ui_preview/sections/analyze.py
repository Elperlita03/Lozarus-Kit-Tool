# -*- coding: utf-8 -*-
"""
3 · ANALIZAR EQUIPO — análisis, procesos, archivos y conexiones.

Los 13 módulos de auditoría de `modulos/` SÍ existen y funcionan (los usa la GUI de producción y el
CLI). Esta beta los lista con sus comprobaciones reales, pero **no los ejecuta**: el objetivo es
evaluar el diseño visual, no lanzar auditorías desde un prototipo.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QTabWidget, QTreeWidget, QTreeWidgetItem, QWidget

import demodata as D
from sections._shared import data_table, demo_row, notice
from sections.base import Section
from theme import C, icon
from widgets import Card, InfoDialog, StatusTag, action_button, grid, label

# Módulos de auditoría REALES, con sus comprobaciones verificadas leyendo el código.
AUDIT_MODULES = [
    ("01 · Sistema", 4, "Sistema operativo, privilegios, tiempo encendido, reinicio pendiente."),
    ("02 · Red", 5, "Direccionamiento, DNS, perfil de red, Wi-Fi y tabla ARP."),
    ("03 · Cortafuegos", 2, "Estado del cortafuegos de Windows."),
    ("04 · Puertos", 2, "Puertos a la escucha y barrido local."),
    ("05 · Endurecimiento", 16, "UAC, Defender, actualizaciones, BitLocker, Arranque seguro, "
                                "SMBv1, firma SMB, RDP, LSASS (RunAsPPL) y más."),
    ("06 · Servicios", 3, "Servicios de Windows y rutas sin comillas."),
    ("07 · Cuentas", 7, "Política de contraseñas, cuentas locales, grupo de administradores."),
    ("08 · Registros", 3, "Eventos de Windows y registro de PowerShell."),
    ("09 · Intrusiones", 1, "Registro de seguridad."),
    ("10 · Software", 1, "Inventario de software instalado."),
    ("11 · Persistencia", 4, "Claves Run, Winlogon, tareas programadas y controladores."),
    ("12 · Telemetría", 3, "Servicios de telemetría, exclusiones e integridad de Defender."),
    ("13 · Inyecciones", 1, "Módulos cargados en procesos anfitriones habituales."),
]


class AnalyzeSection(Section):
    KEY = "analyze"
    TITLE = "Analizar equipo"
    KICKER = "03 · ANÁLISIS"
    SUBTITLE = "Procesos, conexiones, archivos y formas de arranque automático."
    ICON = "fa5s.search"

    def build(self) -> None:
        self.add(notice(
            "Los botones de análisis de esta sección son demostrativos: no ejecutan auditorías, no "
            "terminan procesos y no tocan el Registro. Los 13 módulos reales sí funcionan, pero se "
            "lanzan desde la interfaz de producción o desde el CLI.", C["warn"], "fa5s.hand-paper"))

        self._build_actions()
        self._build_results()
        self._build_modules()

    # ---------------------------------------------------------------- acciones
    def _build_actions(self) -> None:
        self.group("Lanzar un análisis")
        host, add = grid(3)

        quick = Card("Análisis rápido", "fa5s.bolt")
        quick.add_text("Revisa lo esencial en menos de un minuto: configuración de seguridad, "
                       "arranque automático y procesos llamativos.")
        quick.add(action_button("Ejecutar (demostración)", "fa5s.play", "Mini",
                                on_click=lambda: self._demo_action("Análisis rápido")))
        add(quick)

        full = Card("Análisis completo", "fa5s.clipboard-check")
        full.add_text("Pasa los 13 módulos de auditoría y produce un informe con severidades y "
                      "recomendaciones.")
        full.add(action_button("Ejecutar (demostración)", "fa5s.play", "Mini",
                               on_click=lambda: self._demo_action("Análisis completo")))
        add(full)

        targeted = Card("Análisis dirigido", "fa5s.crosshairs")
        targeted.add_text("Elegir un proceso o una carpeta concreta y examinar solo eso.")
        targeted.add(action_button("Elegir objetivo (demostración)", "fa5s.folder-open", "Mini",
                                   on_click=lambda: self._demo_action("Análisis dirigido")))
        add(targeted)
        self.add(host)

    def _demo_action(self, what: str) -> None:
        self.ctx.act(what, "en la versión conectada ejecutaría los módulos reales de modulos/")
        InfoDialog(
            f"{what} — demostración",
            "Esta beta no ejecuta análisis. Cuando conectemos el backend, esta acción lanzará los "
            "módulos de auditoría que ya existen y funcionan.",
            ["Los 13 módulos de `modulos/` son reales y los usa hoy la interfaz de producción.",
             "Algunas comprobaciones necesitan Administrador; sin él se marcan como omitidas, "
             "nunca como superadas.",
             "El resultado se mostrará con severidad, explicación y recomendación por hallazgo."],
            note="Se ha registrado la interacción en la consola de demostración, abajo.",
            parent=self).exec()

    # ---------------------------------------------------------------- resultados
    def _build_results(self) -> None:
        self.group("Resultados", "Ejemplos para evaluar la presentación de la información.")
        card = Card()
        card.add_layout(demo_row())
        tabs = QTabWidget()
        tabs.addTab(self._processes_tab(), icon("fa5s.sitemap", C["cyan"]), "Árbol de procesos")
        tabs.addTab(self._connections_tab(), icon("fa5s.exchange-alt", C["cyan"]), "Conexiones")
        tabs.addTab(self._files_tab(), icon("fa5s.file-code", C["cyan"]), "Archivos")
        tabs.addTab(self._persistence_tab(), icon("fa5s.redo", C["cyan"]), "Persistencia")
        tabs.currentChanged.connect(
            lambda i: self.ctx.log("nav", f"Analizar → pestaña «{tabs.tabText(i)}»"))
        card.add(tabs)
        self.add(card)

    def _processes_tab(self) -> QWidget:
        tree = QTreeWidget()
        tree.setHeaderLabels(["Proceso", "PID", "CPU", "Memoria", "Firma", "Veredicto"])
        tree.setColumnWidth(0, 230)
        nodes = {}
        # Primero los que tienen padre conocido dentro de la lista, luego el resto en la raíz.
        by_name = {p[0]: p for p in D.PROCESSES}
        for name, pid, parent, cpu, ram, sign, verdict in D.PROCESSES:
            item = QTreeWidgetItem([name, str(pid), f"{cpu:.1f} %", f"{ram} MB", sign,
                                    D.VERDICT_LABELS[verdict]])
            item.setIcon(0, icon(D.VERDICT_ICONS[verdict], D.VERDICT_COLORS[verdict]))
            item.setForeground(5, Qt.GlobalColor.white)
            from PySide6.QtGui import QColor
            item.setForeground(5, QColor(D.VERDICT_COLORS[verdict]))
            nodes[name] = item
        for name, pid, parent, *_ in D.PROCESSES:
            if parent in nodes and parent != name:
                nodes[parent].addChild(nodes[name])
            elif parent not in by_name:
                tree.addTopLevelItem(nodes[name])
        tree.expandAll()
        tree.setMinimumHeight(230)
        return tree

    def _connections_tab(self) -> QWidget:
        rows = [(c[0], c[1], c[2], c[3], c[4], D.VERDICT_LABELS[c[5]]) for c in D.CONNECTIONS]
        return data_table(["Proceso", "Local", "Remoto", "Estado", "País", "Veredicto"], rows,
                          color_column=5,
                          colorizer=lambda r: D.VERDICT_COLORS.get(
                              {v: k for k, v in D.VERDICT_LABELS.items()}.get(r[5], ""), None))

    def _files_tab(self) -> QWidget:
        rows = [(f[0], f[1], f[2], f[3], D.VERDICT_LABELS[f[4]]) for f in D.FILES]
        return data_table(["Archivo", "Tamaño", "Firma", "Entropía", "Veredicto"], rows,
                          color_column=4,
                          colorizer=lambda r: D.VERDICT_COLORS.get(
                              {v: k for k, v in D.VERDICT_LABELS.items()}.get(r[4], ""), None))

    def _persistence_tab(self) -> QWidget:
        rows = [(p[0], p[1], p[2], D.VERDICT_LABELS[p[3]]) for p in D.PERSISTENCE]
        return data_table(["Vía de arranque", "Nombre", "Qué ejecuta", "Veredicto"], rows,
                          color_column=3,
                          colorizer=lambda r: D.VERDICT_COLORS.get(
                              {v: k for k, v in D.VERDICT_LABELS.items()}.get(r[3], ""), None))

    # ---------------------------------------------------------------- módulos reales
    def _build_modules(self) -> None:
        total = sum(m[1] for m in AUDIT_MODULES)
        self.group("Módulos de auditoría reales",
                   f"{len(AUDIT_MODULES)} módulos con {total} comprobaciones, verificados leyendo "
                   f"el código. Existen y funcionan, pero no tienen pruebas automáticas.")
        card = Card()
        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(StatusTag("impl_partial", compact=True))
        top.addWidget(label("Código real sin pruebas automáticas", "CardMeta", wrap=False))
        top.addStretch(1)
        card.add_layout(top)
        rows = [(name, str(count), desc) for name, count, desc in AUDIT_MODULES]
        card.add(data_table(["Módulo", "Comprobaciones", "Qué revisa"], rows, height=330))
        self.add(card)
