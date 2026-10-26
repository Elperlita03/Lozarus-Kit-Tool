# -*- coding: utf-8 -*-
"""
9 · RESCUE USB — concepto del entorno de recuperación arrancable.

Esta sección es deliberadamente explícita sobre lo que NO existe: el USB no está construido, no se
ha reparado ningún Windows y la pieza técnica clave (¿funciona PySide6 dentro de WinPE?) sigue sin
verificar. Todo el contenido procede de docs/05_PRODUCTO_SENTINEL_RESCUE.md.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout

import demodata as D
from sections._shared import data_table, notice
from sections.base import Section
from theme import C
from widgets import (Card, Chip, InfoDialog, KeyValue, StatusTag, action_button, bullet_list, grid,
                     label)

WINPE_FACTS = [
    ("Base del medio", "WinPE, complemento del Windows ADK (descarga aparte)"),
    ("Arquitectura", "amd64 — WinPE no ejecuta aplicaciones de otra arquitectura"),
    ("Memoria mínima", "512 MB para la base; el arranque necesita memoria física contigua"),
    ("Espacio de trabajo", "512 MB como máximo, y vive en RAM"),
    ("Reinicio forzado", "WinPE se reinicia solo tras 240 h de uso continuo (no configurable)"),
    ("Persistencia", "Todos los cambios se pierden al reiniciar: es un disco en memoria"),
    ("Límite FAT32", "4 GB por archivo y 32 GB de volumen → hacen falta dos particiones"),
    ("Instaladores", "No admite archivos .MSI: las dependencias se copian, no se instalan"),
    ("BitLocker", "Requiere WinPE-SecureStartup, que a su vez depende de WinPE-WMI"),
]

SENTINEL_VS_RESCUE = [
    ("Vigilancia en tiempo real", "Sí", "No — no hay nada ejecutándose que observar"),
    ("Procesos y conexiones", "Sí", "No — el sistema investigado está apagado"),
    ("Análisis de persistencia", "Sí", "Sí, y además más fiable: el sistema no puede ocultarse"),
    ("Análisis estático de archivos", "Sí", "Sí — mismo código compartido"),
    ("Desbloqueo de BitLocker", "No", "Sí, con la clave legítima del usuario"),
    ("Recuperación de archivos", "No", "Sí — es la prioridad número uno del usuario real"),
    ("Reparación del arranque", "No", "Sí — sfc, DISM y BCD en modo offline"),
    ("Señuelos y contención", "Sí", "No aplica"),
]


class RescueSection(Section):
    KEY = "rescue"
    TITLE = "Rescue USB"
    KICKER = "09 · ENTORNO DE RECUPERACIÓN"
    SUBTITLE = "Un USB que arranca su propio sistema para examinar y reparar un Windows apagado."
    ICON = "fa5s.life-ring"

    def build(self) -> None:
        self._build_status()
        self._build_flow()
        self._build_limits()
        self._build_comparison()
        self._build_winpe()

    # ---------------------------------------------------------------- estado
    def _build_status(self) -> None:
        banner = Card(accent=True)
        banner.body.setContentsMargins(20, 18, 20, 18)
        row = QHBoxLayout()
        row.setSpacing(18)
        left = QVBoxLayout()
        left.setSpacing(5)
        left.addWidget(label("ESTADO DEL MEDIO", "MetricCap", wrap=False))
        title = label("NO CONSTRUIDO", "PageTitle", wrap=False)
        title.setStyleSheet(f"color:{C['warn']}; font-size:27px; font-weight:800; letter-spacing:1px;")
        left.addWidget(title)
        left.addWidget(label(
            "No existe ninguna imagen arrancable. Esta sección enseña el flujo previsto y los "
            "límites ya documentados, no un producto terminado.", "CardText"))
        tags = QHBoxLayout()
        tags.setSpacing(7)
        tags.addWidget(StatusTag("needs_valid", compact=True))
        tags.addWidget(Chip("Diseño completo en docs/05", C["cyan"], "fa5s.file-alt"))
        tags.addWidget(Chip("Decisión D1 sin resolver", C["warn"], "fa5s.question-circle"))
        tags.addStretch(1)
        left.addLayout(tags)
        row.addLayout(left, 1)

        right = QVBoxLayout()
        right.addStretch(1)
        right.addWidget(action_button("¿Qué bloquea su construcción?", "fa5s.exclamation-circle",
                                      "Primary", "#FFFFFF", self._explain_block))
        row.addLayout(right)
        banner.add_layout(row)
        self.add(banner)

        self.add(notice(
            "Esta beta NO crea imágenes arrancables, NO formatea unidades y NO repara ningún "
            "Windows. Los botones de esta sección solo explican el flujo previsto.",
            C["crit"], "fa5s.exclamation-triangle"))

    def _explain_block(self) -> None:
        InfoDialog(
            "Decisión D1 — ¿funciona PySide6 dentro de WinPE?",
            "Es el riesgo técnico principal del entorno de rescate, y está SIN VERIFICAR: no se "
            "encontró ninguna fuente, oficial ni comunitaria, que confirme Qt funcionando en WinPE.",
            ["WinPE no trae el runtime de Visual C++, y no se puede instalar con un .MSI porque "
             "WinPE no admite ese formato: hay que copiar las DLL junto a la aplicación.",
             "No hay aceleración gráfica: habría que forzar render por software y usar solo Qt "
             "Widgets, nunca QML.",
             "No hay shell de Windows, así que nada de bandeja del sistema ni diálogos del shell. "
             "La comprobación actual de BitLocker usa COM Shell.Application y NO sería portable.",
             "El plan previsto da 3 días de presupuesto a un prototipo mínimo: si una ventana Qt "
             "aparece en una máquina virtual, seguimos con Qt; si no, el rescate usa una interfaz "
             "de consola y el producto no se bloquea."],
            note="El núcleo compartido es idéntico en ambos caminos, así que esta decisión solo "
                 "afecta a la capa visual del rescate, nunca a la lógica.",
            parent=self).exec()
        self.ctx.log("info", "Consultada la decisión D1 (PySide6 en WinPE)")

    # ---------------------------------------------------------------- flujo
    def _build_flow(self) -> None:
        self.group("Flujo previsto", "Nueve pasos, del arranque al informe. Ninguno es ejecutable aquí.")
        host, add = grid(3)
        for step, title, desc in D.RESCUE_FLOW:
            card = Card(f"{step} · {title}", "fa5s.angle-double-right")
            card.add_text(desc)
            add(card)
        self.add(host)

        order = Card("El orden no es casual", "fa5s.sort-numeric-down")
        order.add(bullet_list([
            "Primero se RESCATAN LOS ARCHIVOS del usuario: es lo que de verdad le importa a quien "
            "ha perdido su equipo, y no tiene ningún riesgo.",
            "Después se repara el arranque, que es reversible si se guarda una copia del BCD.",
            "La reparación del sistema de archivos puede descartar datos corruptos: exige "
            "confirmación reforzada.",
            "La reinstalación o el formateo no se ofrecen como botón: se informa y se deriva.",
            "La evidencia se preserva ANTES de cualquier cuarentena o limpieza.",
        ], "fa5s.check", C["ok"]))
        self.add(order)

    # ---------------------------------------------------------------- límites
    def _build_limits(self) -> None:
        self.group("Lo que Rescue NO puede hacer",
                   "Honestidad obligatoria: son diferencias de naturaleza, no limitaciones mejorables.")
        card = Card("Límites reales", "fa5s.ban")
        card.add(bullet_list(list(D.RESCUE_LIMITS), "fa5s.times", C["crit"]))
        card.add(label(
            "Los restos de memoria que quedan en disco (hiberfil.sys, pagefile.sys, volcados de "
            "fallos) son artefactos históricos: pueden no existir, estar obsoletos o ser parciales. "
            "No son el estado del sistema en el momento del incidente.", "CardMeta"))
        self.add(card)

    # ---------------------------------------------------------------- comparación
    def _build_comparison(self) -> None:
        self.group("Sentinel y Rescue — cómo se relacionan",
                   "Un solo núcleo de modelos; dos capas de adquisición distintas.")
        card = Card()
        card.add(data_table(["Capacidad", "Sentinel (equipo encendido)", "Rescue (equipo apagado)"],
                            SENTINEL_VS_RESCUE, height=250))
        card.add(label(
            "Lo que se comparte es la verdad común: qué es un evento, una evidencia y un hallazgo. "
            "Lo que NO se comparte es todo lo que depende de APIs, hardware o privilegios distintos.",
            "CardMeta"))
        self.add(card)

    # ---------------------------------------------------------------- winpe
    def _build_winpe(self) -> None:
        self.group("Restricciones verificadas de WinPE",
                   "Datos tomados de la documentación oficial de Microsoft, no de suposiciones.")
        card = Card()
        for key, value in WINPE_FACTS:
            card.add(KeyValue(key, value))
        card.add(label(
            "Estas restricciones no son detalles: el límite de 4 GB de FAT32 es lo que obliga a que "
            "el USB tenga dos particiones, y el espacio de trabajo en RAM es lo que descarta "
            "empaquetar la aplicación en un único ejecutable autoextraíble.", "CardMeta"))
        self.add(card)
