# -*- coding: utf-8 -*-
"""
CATÁLOGO — las 41 capacidades de la arquitectura, filtrables, con ficha explicativa.

Los estados NO son estimaciones: salen de leer el repositorio (ver la cabecera de `catalog.py`).
Resultado honesto que esta vista hace evidente: ninguno de los 41 módulos tiene pruebas automáticas;
lo único probado es la infraestructura (`core/`, `collectors/`).
"""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLineEdit, QScrollArea, QVBoxLayout,
                               QWidget)

from catalog import AREA_ICONS, AREAS, CORE, MODULES, Capability, counts_by_status
from sections._shared import notice
from sections.base import Section
from theme import C, STATUS, STATUS_ORDER, icon
from widgets import (BarRow, Card, Chip, KeyValue, StatusTag, action_button, clear_layout, hline,
                     label)


class CatalogSection(Section):
    KEY = "catalog"
    TITLE = "Catálogo de capacidades"
    NAV_LABEL = "Catálogo"
    KICKER = "CATÁLOGO · 41 MÓDULOS + INFRAESTRUCTURA"
    SUBTITLE = "Qué está hecho, qué está a medias y qué sigue siendo solo un diseño."
    ICON = "fa5s.th-list"

    def build(self) -> None:
        self._status_filter: Optional[str] = None
        self._area_filter: str = "Todas las áreas"
        self._query: str = ""
        self._include_core = True
        self._selected: Optional[Capability] = None

        self.add(notice(
            "Los estados se han verificado leyendo el código, no estimado. Por eso ninguno de los 41 "
            "módulos aparece como «Implementado y probado»: lo único con pruebas automáticas es la "
            "infraestructura del núcleo y el colector ETW.", C["cyan"], "fa5s.clipboard-check"))

        self._build_summary()
        self._build_filters()
        self._build_body()
        self._refresh()

    # ---------------------------------------------------------------- resumen
    def _build_summary(self) -> None:
        self.group("Reparto por estado", f"{len(MODULES)} módulos de la arquitectura "
                                         f"+ {len(CORE)} piezas de infraestructura.")
        row = QHBoxLayout()
        row.setSpacing(14)

        mods = Card("Los 41 módulos", "fa5s.cubes")
        counts = counts_by_status(MODULES)
        for key in STATUS_ORDER:
            if counts.get(key):
                mods.add(BarRow(STATUS[key].label, counts[key], len(MODULES), STATUS[key].color))
        mods.add(label("Ninguno tiene pruebas automáticas todavía.", "CardMeta"))
        row.addWidget(mods, 1)

        core = Card("Infraestructura", "fa5s.server")
        ccounts = counts_by_status(CORE)
        for key in STATUS_ORDER:
            if ccounts.get(key):
                core.add(BarRow(STATUS[key].label, ccounts[key], len(CORE), STATUS[key].color))
        core.add(label("Aquí vive todo lo que sí está probado: 42 pruebas automáticas en total.",
                       "CardMeta"))
        row.addWidget(core, 1)

        meaning = Card("Qué significa cada estado", "fa5s.question-circle")
        for key in STATUS_ORDER:
            st = STATUS[key]
            line = QHBoxLayout()
            line.setSpacing(8)
            line.addWidget(StatusTag(key, compact=True))
            line.addWidget(label(st.blurb, "CardMeta"), 1)
            meaning.add_layout(line)
        row.addWidget(meaning, 1)
        self.add_layout(row)

    # ---------------------------------------------------------------- filtros
    def _build_filters(self) -> None:
        self.group("Filtrar")
        card = Card()

        chips = QHBoxLayout()
        chips.setSpacing(7)
        self._status_buttons = {}
        all_btn = action_button("Todos", "", "Filter")
        all_btn.setCheckable(True)
        all_btn.setChecked(True)
        all_btn.clicked.connect(lambda: self._set_status(None))
        self._status_buttons[None] = all_btn
        chips.addWidget(all_btn)
        for key in STATUS_ORDER:
            st = STATUS[key]
            btn = action_button(f"{st.code}", st.icon, "Filter", st.color)
            btn.setCheckable(True)
            btn.setToolTip(f"{st.label} — {st.blurb}")
            btn.clicked.connect(lambda _=False, k=key: self._set_status(k))
            self._status_buttons[key] = btn
            chips.addWidget(btn)
        chips.addStretch(1)
        card.add_layout(chips)

        tools = QHBoxLayout()
        tools.setSpacing(9)
        self.area_box = QComboBox()
        self.area_box.addItem("Todas las áreas")
        for area in AREAS:
            self.area_box.addItem(area)
        self.area_box.currentTextChanged.connect(self._set_area)
        self.area_box.setMinimumWidth(210)
        tools.addWidget(self.area_box)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar por nombre o descripción…")
        self.search.textChanged.connect(self._set_query)
        tools.addWidget(self.search, 1)

        self.core_btn = action_button("Incluir infraestructura", "fa5s.server", "Filter", C["ok"])
        self.core_btn.setCheckable(True)
        self.core_btn.setChecked(True)
        self.core_btn.clicked.connect(self._toggle_core)
        tools.addWidget(self.core_btn)
        card.add_layout(tools)

        self.count_label = label("", "CardMeta")
        card.add(self.count_label)
        self.add(card)

    def _set_status(self, key: Optional[str]) -> None:
        self._status_filter = key
        for k, btn in self._status_buttons.items():
            btn.setChecked(k == key)
        self._refresh()
        name = "todos los estados" if key is None else STATUS[key].label
        self.ctx.log("nav", f"Catálogo filtrado por {name}")

    def _set_area(self, area: str) -> None:
        self._area_filter = area
        self._refresh()

    def _set_query(self, text: str) -> None:
        self._query = text.strip().lower()
        self._refresh()

    def _toggle_core(self) -> None:
        self._include_core = self.core_btn.isChecked()
        self._refresh()

    # ---------------------------------------------------------------- cuerpo
    def _build_body(self) -> None:
        body = QHBoxLayout()
        body.setSpacing(14)

        list_host = QWidget()
        self.list_col = QVBoxLayout(list_host)
        self.list_col.setContentsMargins(0, 0, 4, 0)
        self.list_col.setSpacing(7)
        self.list_area = QScrollArea()
        self.list_area.setWidgetResizable(True)
        self.list_area.setWidget(list_host)
        self.list_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list_area.setMinimumHeight(560)
        body.addWidget(self.list_area, 3)

        self.detail = Card("Ficha", "fa5s.id-card")
        self.detail.setMinimumWidth(360)
        self.detail_col = QVBoxLayout()
        self.detail_col.setSpacing(7)
        self.detail.add_layout(self.detail_col)
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setWidget(self.detail)
        detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        detail_scroll.setMinimumHeight(560)
        body.addWidget(detail_scroll, 2)
        self.add_layout(body)
        self._show_detail(None)

    def _visible(self) -> List[Capability]:
        pool = (CORE + MODULES) if self._include_core else list(MODULES)
        out = []
        for cap in pool:
            if self._status_filter and cap.status != self._status_filter:
                continue
            if self._area_filter != "Todas las áreas" and cap.area != self._area_filter:
                continue
            if self._query and self._query not in (cap.name + " " + cap.description
                                                   + " " + cap.objective).lower():
                continue
            out.append(cap)
        return out

    def _refresh(self) -> None:
        clear_layout(self.list_col)
        caps = self._visible()
        self.count_label.setText(
            f"Mostrando {len(caps)} capacidades"
            + ("" if self._status_filter is None else f" con estado «{STATUS[self._status_filter].label}»")
            + ("" if self._area_filter == "Todas las áreas" else f" del área «{self._area_filter}»"))
        if not caps:
            self.list_col.addWidget(label(
                "Ninguna capacidad coincide con estos filtros. Prueba a quitar alguno.", "CardText"))
            self.list_col.addStretch(1)
            return
        for cap in caps:
            self.list_col.addWidget(_CapabilityRow(cap, self._show_detail))
        self.list_col.addStretch(1)

    # ---------------------------------------------------------------- ficha
    def _show_detail(self, cap: Optional[Capability]) -> None:
        clear_layout(self.detail_col)
        if cap is None:
            self.detail_col.addWidget(label(
                "Elige una capacidad de la lista para ver su ficha completa: objetivo, estado real, "
                "dependencias, si tiene pruebas, límites conocidos y siguiente paso previsto.",
                "CardText"))
            return

        self._selected = cap
        title = label(cap.label, "CardTitle")
        title.setStyleSheet("font-size:16px; font-weight:700;")
        self.detail_col.addWidget(title)

        tags = QHBoxLayout()
        tags.setSpacing(7)
        tags.addWidget(StatusTag(cap.status))
        tags.addStretch(1)
        self.detail_col.addLayout(tags)

        meta = QHBoxLayout()
        meta.setSpacing(6)
        meta.addWidget(Chip(cap.area, C["cyan"], AREA_ICONS.get(cap.area, "fa5s.cube")))
        meta.addWidget(Chip(f"Privilegios: {cap.privileges}", C["text2"], "fa5s.key"))
        if cap.num:
            meta.addWidget(Chip(f"Prioridad {cap.priority}", C["text2"], "fa5s.sort-amount-down"))
        meta.addStretch(1)
        self.detail_col.addLayout(meta)
        self.detail_col.addWidget(hline())

        self.detail_col.addWidget(KeyValue("Objetivo", cap.objective))
        self.detail_col.addWidget(KeyValue("Descripción", cap.description))
        self.detail_col.addWidget(KeyValue(
            "Estado", f"{STATUS[cap.status].label} — {STATUS[cap.status].blurb}",
            STATUS[cap.status].color))
        self.detail_col.addWidget(KeyValue(
            "Dependencias", ", ".join(cap.deps) if cap.deps else "Ninguna declarada"))
        self.detail_col.addWidget(KeyValue("Pruebas", cap.tests))
        if cap.backing:
            self.detail_col.addWidget(KeyValue("Código que lo respalda", cap.backing, C["ok"]))
        else:
            self.detail_col.addWidget(KeyValue("Código que lo respalda",
                                               "No hay código todavía", C["muted"]))
        if cap.limits:
            self.detail_col.addWidget(KeyValue("Limitaciones conocidas", cap.limits, C["warn"]))
        if cap.next_step:
            self.detail_col.addWidget(KeyValue("Siguiente paso", cap.next_step, C["cyan"]))
        self.ctx.log("nav", f"Ficha abierta: {cap.label}")


class _CapabilityRow(QFrame):
    """Fila compacta y pulsable de una capacidad."""

    def __init__(self, cap: Capability, on_click, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._cap = cap
        self._on_click = on_click
        st = STATUS[cap.status]
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(
            f"_CapabilityRow {{ background-color:{C['surface']}; border:1px solid {C['border']};"
            f" border-left:3px solid {st.color}; border-radius:9px; }}"
            f"_CapabilityRow:hover {{ background-color:{C['surface2']};"
            f" border-color:{C['border_hi']}; border-left:3px solid {st.color}; }}")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(13, 10, 13, 10)
        lay.setSpacing(11)

        from PySide6.QtWidgets import QLabel
        ico = QLabel()
        ico.setPixmap(icon(AREA_ICONS.get(cap.area, "fa5s.cube"), C["text2"]).pixmap(15, 15))
        ico.setAlignment(Qt.AlignmentFlag.AlignTop)
        ico.setToolTip(f"Área: {cap.area}")          # el área va en el icono y en la ficha
        lay.addWidget(ico)

        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(label(cap.label, "CardTitle"))
        col.addWidget(label(cap.objective, "CardMeta"))
        lay.addLayout(col, 1)

        tag = StatusTag(cap.status, compact=True)
        lay.addWidget(tag, 0, Qt.AlignmentFlag.AlignTop)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._on_click(self._cap)
        super().mouseReleaseEvent(event)
