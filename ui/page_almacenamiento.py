"""
ui/page_almacenamiento.py · LOZARUS KIT TOOL

Página ALMACENAMIENTO Y RENDIMIENTO (motor: modulos/_rendimiento_disco.py):
  · Tarjeta Bento principal: anillo de uso del disco del sistema, espacio libre, liberable ahora y
    recuperado en la sesión, con el botón asíncrono «Liberar espacio».
  · Saneamiento seguro: cada categoría del catálogo (temporales del sistema y cachés del usuario) con su
    tamaño liberable, su estado y una casilla; antigüedad mínima configurable.
  · Unidades: uso, libre, medio (SSD/HDD) y salud de cada volumen, y optimización nativa (defrag /O) con
    progreso y cancelación.
  · Consumidores de espacio: carpetas del usuario y archivos más grandes (solo lectura).

Todo corre en segundo plano (app.run_task con spinner), pide confirmación con las rutas o el comando
exactos, queda en la Caja Negra (_emit_event) y avisa con Toast.notify. report_data() alimenta el
informe ejecutivo y el panel de componentes del Centro de Comando.
"""

from __future__ import annotations

import datetime as dt
import os
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QTableWidgetItem, QVBoxLayout

from modulos import _rendimiento_disco as disk
from modulos._rendimiento_disco import human_bytes

from ui.theme import COLORS
from ui.widgets import Gauge, Page, fit_columns, frozen, make_card, make_table, tech_tip
from ui.chrome import Toast
from ui.kit import HeaderStatus, ProgressStrip, SafeActions, TaskProgress, action_button

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

PAGE_KEY = "almacenamiento"
PAGE_ICON = "fa5s.hdd"
SOURCE = "almacenamiento:saneamiento"
LEVEL_COLOR = {"ok": COLORS["ok"], "warn": COLORS["warn"], "critical": COLORS["danger"]}
AGE_LABELS = {24: "24 horas (recomendado)", 72: "3 días", 168: "7 días"}
STATUS_STYLE = {"admin": ("Requiere admin", COLORS["warn"]), "in_use": ("En uso", COLORS["warn"]),
                "absent": ("No existe", COLORS["faint"]), "unsafe": ("Rechazada", COLORS["danger"])}
RECLAIM_NOTICE = 1024 ** 3   # a partir de 1 GB liberable, la cabecera lo sugiere


def _item(text: str, color: Optional[str] = None, tip: str = "", data: Any = None) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    if color:
        it.setForeground(QColor(color))
    if tip:
        it.setToolTip(tip)
    if data is not None:
        it.setData(Qt.ItemDataRole.UserRole, data)
    return it


def _age_text(hours: float) -> str:
    if hours <= 0:
        return "cualquier antigüedad"
    return f"{hours / 24:.0f} días" if hours >= 48 else f"{hours:.0f} horas"


class StoragePage(SafeActions, Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Almacenamiento y Rendimiento",
                         "Analiza el espacio de cada unidad, libera temporales del sistema y cachés residuales del "
                         "usuario con reglas de seguridad (antigüedad mínima, sin seguir enlaces, navegadores "
                         "cerrados) y optimiza la unidad con la herramienta nativa de Windows.", PAGE_ICON)
        self.app = app
        self._volumes: List[Dict[str, Any]] = []
        self._disks: Optional[List[Dict[str, Any]]] = None
        self._scan: Optional[Dict[str, Any]] = None
        self._space: Optional[Dict[str, Any]] = None
        self._recovered = 0
        self._recovered_by: Dict[str, Dict[str, Any]] = {}   # clave -> {title, bytes, files}
        self._runs: List[Dict[str, Any]] = []                # limpiezas de la sesión (informe)
        self._optimized: Optional[Dict[str, Any]] = None
        self._checked = {t.key: t.default for t in disk.TARGETS}
        self._busy = False
        self._loaded = False
        self.header_status = HeaderStatus()
        self.add_header_widget(self.header_status)
        # Tarjetas a todo el ancho: a 1280×800 dos columnas dejaban las tablas sin sitio para las rutas.
        for card in (self._build_hero(), self._build_cleanup_card(), self._build_volumes_card(),
                     self._build_space_card()):
            self.root.addWidget(card)
        self.root.addStretch(1)
        self._render()

    # =============================================================================================
    # Construcción
    # =============================================================================================
    def _build_hero(self) -> QFrame:
        """Tarjeta Bento principal: métricas de almacenamiento y la acción asíncrona «Liberar espacio»."""
        box = QFrame()
        box.setObjectName("Card")
        lay = QHBoxLayout(box)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(24)
        ring = QVBoxLayout()
        ring.setSpacing(6)
        self.disk_gauge = Gauge(COLORS["accent"], size=124)
        cap = QLabel("DISCO DEL SISTEMA")
        cap.setObjectName("ChipCap")
        cap.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.disk_caption = QLabel("leyendo…")
        self.disk_caption.setObjectName("Tiny")
        self.disk_caption.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        ring.addWidget(self.disk_gauge, 0, Qt.AlignmentFlag.AlignHCenter)
        ring.addWidget(cap)
        ring.addWidget(self.disk_caption)
        lay.addLayout(ring)
        metrics = QGridLayout()
        metrics.setHorizontalSpacing(12)
        metrics.setVerticalSpacing(12)
        self._metrics: Dict[str, tuple] = {}
        for i, (key, caption) in enumerate((("free", "ESPACIO LIBRE"), ("reclaim", "LIBERABLE AHORA"),
                                            ("recovered", "RECUPERADO EN LA SESIÓN"),
                                            ("volumes", "UNIDADES"))):
            tile = QFrame()
            tile.setObjectName("Inset")
            tl = QVBoxLayout(tile)
            tl.setContentsMargins(14, 10, 14, 10)
            tl.setSpacing(2)
            c, v, n = QLabel(caption), QLabel("—"), QLabel("")
            c.setObjectName("ChipCap")
            v.setObjectName("ChipVal")
            n.setObjectName("Tiny")
            n.setWordWrap(True)
            for w in (c, v, n):
                tl.addWidget(w)
            self._metrics[key] = (v, n)
            metrics.addWidget(tile, i // 2, i % 2)
        lay.addLayout(metrics, 1)
        actions = QVBoxLayout()
        actions.setSpacing(10)
        self.clean_btn = action_button("Liberar espacio", "fa5s.broom", "Primary", self._clean)
        self.clean_btn.setToolTip(tech_tip("Liberar espacio", ["Categorías marcadas en «Saneamiento seguro»"],
                                           "Pide confirmación con las rutas exactas antes de borrar nada."))
        self.rescan_btn = action_button("Analizar de nuevo", "fa5s.sync-alt", "Ghost",
                                        lambda: self.refresh(user=True))
        self.hero_note = QLabel("Sin analizar todavía.")
        self.hero_note.setObjectName("Tiny")
        self.hero_note.setWordWrap(True)
        self.hero_note.setMaximumWidth(230)
        actions.addStretch(1)
        actions.addWidget(self.clean_btn)
        actions.addWidget(self.rescan_btn)
        actions.addWidget(self.hero_note)
        actions.addStretch(1)
        lay.addLayout(actions)
        return box

    def _build_cleanup_card(self) -> QFrame:
        box, lay = make_card("Saneamiento seguro",
                             "Temporales del sistema y cachés residuales del usuario. Solo se borra lo que supera la "
                             "antigüedad mínima, nunca a través de enlaces o uniones; lo que está en uso se omite y las "
                             "cachés de un navegador abierto no se tocan.")
        row = QHBoxLayout()
        row.setSpacing(10)
        cap = QLabel("Antigüedad mínima de los temporales:")
        cap.setObjectName("CardText")
        self.age_combo = QComboBox()
        self.age_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        for hours in disk.AGE_CHOICES:
            self.age_combo.addItem(AGE_LABELS.get(hours, f"{hours} h"), hours)
        self.age_combo.setToolTip("Los temporales más recientes pueden pertenecer a un instalador en marcha: se "
                                  "respetan. Las cachés regenerables (navegadores, miniaturas) no dependen de esto.")
        self.age_combo.currentIndexChanged.connect(lambda _i: self.refresh())
        self.defaults_btn = action_button("Marcar recomendadas", "fa5s.check-double", "Mini", self._reset_checks, 12)
        row.addWidget(cap)
        row.addWidget(self.age_combo)
        row.addStretch(1)
        row.addWidget(self.defaults_btn)
        lay.addLayout(row)
        self.targets_table = make_table(["", "Categoría", "Ámbito", "Archivos", "Liberable", "Estado"],
                                        widths=[34, 260, 84, 90, 100],
                                        empty="Analizando las categorías de limpieza…", empty_icon="fa5s.broom")
        fit_columns(self.targets_table, 1)
        self.targets_table.setColumnWidth(5, 170)
        self.targets_table.setMinimumHeight(30 * len(disk.TARGETS) + 46)  # todas las categorías sin scroll interno
        self.targets_table.itemChanged.connect(self._check_changed)
        lay.addWidget(self.targets_table, 1)
        self.cleanup_note = QLabel("")
        self.cleanup_note.setObjectName("Tiny")
        self.cleanup_note.setWordWrap(True)
        lay.addWidget(self.cleanup_note)
        return box

    def _build_volumes_card(self) -> QFrame:
        box, lay = make_card("Unidades y rendimiento",
                             "Uso de cada volumen y estado del disco físico que lo contiene. La optimización nativa "
                             "aplica TRIM en SSD o desfragmenta un HDD, según lo que detecte Windows.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.opt_btn = action_button("Optimizar unidad del sistema", "fa5s.tachometer-alt", "Ghost", self._optimize)
        self.opt_note = QLabel("")
        self.opt_note.setObjectName("Tiny")
        self.opt_note.setWordWrap(True)
        row.addWidget(self.opt_btn)
        row.addWidget(self.opt_note, 1)
        lay.addLayout(row)
        self.opt_strip = ProgressStrip()
        lay.addWidget(self.opt_strip)
        self.volumes_table = make_table(["Unidad", "Sistema de archivos", "Uso", "Libre", "Total", "Medio", "Salud",
                                         "Disco físico"], widths=[150, 128, 64, 100, 100, 64, 120],
                                        empty="Leyendo los volúmenes…", empty_icon="fa5s.hdd")
        fit_columns(self.volumes_table, 7)
        self.volumes_table.setMinimumHeight(160)
        lay.addWidget(self.volumes_table, 1)
        if not disk.IS_WINDOWS:
            self.opt_btn.setEnabled(False)
            self.opt_note.setText("La optimización nativa (defrag) solo existe en Windows; el análisis y el "
                                  "saneamiento funcionan igual.")
        elif not getattr(self.app, "admin", False):
            self.opt_note.setText("Requiere Administrador: al pulsar se ofrece relanzar Lozarus elevado (UAC).")
        return box

    def _build_space_card(self) -> QFrame:
        box, lay = make_card("Consumidores de espacio",
                             "Dónde se va el espacio de tu carpeta de usuario: tamaño de cada carpeta y los archivos "
                             "más grandes. Solo lectura: Lozarus nunca borra tus documentos. Doble clic para abrir la "
                             "ubicación.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.space_btn = action_button("Analizar carpetas del usuario", "fa5s.chart-pie", "Ghost", self._analyze_space)
        self.space_note = QLabel("")
        self.space_note.setObjectName("Tiny")
        self.space_note.setWordWrap(True)
        row.addWidget(self.space_btn)
        row.addWidget(self.space_note, 1)
        lay.addLayout(row)
        tables = QHBoxLayout()
        tables.setSpacing(14)
        self.folders_table = make_table(["Carpeta", "Tamaño", "Archivos"], widths=[180, 96],
                                        empty="Pulsa «Analizar carpetas del usuario».", empty_icon="fa5s.folder-open")
        fit_columns(self.folders_table, 0)
        self.folders_table.setColumnWidth(2, 84)
        self.files_table = make_table(["Archivo", "Tamaño", "Carpeta"], widths=[200, 90],
                                      empty="Aquí aparecerán los archivos más grandes.", empty_icon="fa5s.file")
        fit_columns(self.files_table, 2)
        for table in (self.folders_table, self.files_table):
            table.setMinimumHeight(250)
            table.doubleClicked.connect(lambda _idx, t=table: self._open_selected(t))
        tables.addWidget(self.folders_table, 2)
        tables.addWidget(self.files_table, 3)
        lay.addLayout(tables)
        return box

    # =============================================================================================
    # Estado en vivo
    # =============================================================================================
    def showEvent(self, event) -> None:
        """Primer acceso: analiza volúmenes y categorías en segundo plano (no en el arranque de la app)."""
        super().showEvent(event)
        if not self._loaded:
            self._loaded = True
            self.refresh()

    def _age(self) -> int:
        return int(self.age_combo.currentData() or disk.DEFAULT_AGE_H)

    def refresh(self, user: bool = False) -> None:
        """Volúmenes + discos físicos + análisis de las categorías (solo lectura)."""
        if self._busy:
            return
        self._busy = True
        self._render()
        age = self._age()
        if user:
            self.app.log_tactical("Almacenamiento: analizando volúmenes y categorías de limpieza")

        def work(emit):
            return {"volumes": disk.volumes_with_disks(), "scan": disk.scan_targets(age_h=age)}

        self.run_action(self.rescan_btn, "Analizando…", work, lambda ok, res: self._refreshed(ok, res, user))

    def _refreshed(self, ok: bool, res, user: bool) -> None:
        self._busy = False
        if not ok or not isinstance(res, dict):
            self.app.console.log("x", f"Almacenamiento: no se pudo analizar: {res}")
            if user:
                Toast.notify(self.app, "x", "Almacenamiento", f"No se pudo analizar: {res}", PAGE_ICON)
            self._render()
            return
        self._volumes, self._disks = res["volumes"]["volumes"], res["volumes"]["disks"]
        self._scan = res["scan"]
        self._render()
        scan, sysvol = self._scan, disk.system_volume(self._volumes)
        text = (f"{human_bytes(scan['eligible_bytes'])} liberables en {scan['eligible_files']} archivos"
                + (f" · disco del sistema al {sysvol['percent']:.0f} %" if sysvol else ""))
        self.app.console.log("~", f"Almacenamiento: {text}")
        if user:
            self.finish(self.rescan_btn, "*", "Análisis de almacenamiento", text, PAGE_ICON, source=SOURCE,
                        event_type="storage.scan_completed", payload=self._scan_payload())

    def _scan_payload(self) -> dict:
        scan, sysvol = self._scan or {}, disk.system_volume(self._volumes)
        return {"eligible_bytes": scan.get("eligible_bytes"), "eligible_files": scan.get("eligible_files"),
                "blocked_bytes": scan.get("blocked_bytes"), "age_h": scan.get("age_h"),
                "system_percent": sysvol["percent"] if sysvol else None,
                "system_free": sysvol["free"] if sysvol else None,
                "targets": [{"key": r["key"], "status": r["status"], "eligible_bytes": r["eligible_bytes"]}
                            for r in scan.get("targets", []) if r["status"] != "absent"]}

    def _busy_changed(self) -> None:
        self._refresh_status()

    def _refresh_status(self) -> None:
        sysvol = disk.system_volume(self._volumes) if self._volumes else None
        reclaim = (self._scan or {}).get("eligible_bytes") or 0
        if self.running:
            self.header_status.set_state(f"EN CURSO · {self.running}", COLORS["accent"])
        elif self._scan is None and not self._volumes:
            self.header_status.set_state("SIN ANALIZAR", COLORS["faint"])
        elif sysvol and sysvol["level"] == "critical":
            self.header_status.set_state(f"DISCO CRÍTICO · {sysvol['percent']:.0f} %", COLORS["danger"],
                                         f"{human_bytes(sysvol['free'])} libres en {sysvol['mount']}")
        elif sysvol and sysvol["level"] == "warn":
            self.header_status.set_state(f"ESPACIO BAJO · {sysvol['percent']:.0f} %", COLORS["warn"],
                                         f"{human_bytes(sysvol['free'])} libres en {sysvol['mount']}")
        elif reclaim >= RECLAIM_NOTICE:
            self.header_status.set_state(f"LIBERABLE · {human_bytes(reclaim)}", COLORS["warn"])
        else:
            self.header_status.set_state("ÓPTIMO", COLORS["ok"])
        self.header_status.set_admin(bool(getattr(self.app, "admin", False)))

    # =============================================================================================
    # Render
    # =============================================================================================
    def _render(self) -> None:
        self._render_hero()
        self._render_targets()
        self._render_volumes()
        for btn, enabled in ((self.clean_btn, not self._busy and self._scan is not None),
                             (self.rescan_btn, not self._busy),
                             (self.opt_btn, disk.IS_WINDOWS and not self.opt_strip.active)):
            if not btn.property("busy"):
                btn.setEnabled(enabled)
        self.age_combo.setEnabled(not self._busy)
        self._refresh_status()

    def _set_metric(self, key: str, value: str, note: str, color: Optional[str] = None) -> None:
        val, lbl = self._metrics[key]
        val.setText(value)
        val.setStyleSheet(f"color:{color};" if color else "")
        lbl.setText(note)

    def _render_hero(self) -> None:
        sysvol = disk.system_volume(self._volumes) if self._volumes else None
        if sysvol:
            color = LEVEL_COLOR[sysvol["level"]]
            self.disk_gauge.set_value(sysvol["percent"])
            self.disk_gauge.set_color(color)
            media = f" · {sysvol['media']}" if sysvol.get("media") not in (None, "—") else ""
            self.disk_caption.setText(f"{sysvol['mount']} · {sysvol['fstype']}{media}")
            self._set_metric("free", human_bytes(sysvol["free"]), f"de {human_bytes(sysvol['total'])} en {sysvol['mount']}",
                             None if sysvol["level"] == "ok" else color)
        else:
            self.disk_caption.setText("leyendo…" if self._busy or not self._loaded else "no disponible")
            self._set_metric("free", "—", "")
        scan = self._scan
        if scan is None:
            self._set_metric("reclaim", "—", "analizando…" if self._busy else "sin analizar")
        else:
            selected = self._selected_rows(ready_only=True)
            chosen = sum(r["eligible_bytes"] for r in selected)
            blocked = scan["blocked_bytes"]
            note = f"{len(selected)} categoría(s) marcadas y listas"
            if blocked:
                note += f" · {human_bytes(blocked)} más con admin o cerrando programas"
            self._set_metric("reclaim", human_bytes(chosen), note, COLORS["warn"] if chosen >= RECLAIM_NOTICE else None)
        self._set_metric("recovered", human_bytes(self._recovered),
                         f"{len(self._runs)} limpieza(s) en esta sesión" if self._runs else "ninguna limpieza todavía",
                         COLORS["ok"] if self._recovered else None)
        if self._volumes:
            worst = max(self._volumes, key=lambda v: ("ok", "warn", "critical").index(v["level"]))
            unhealthy = [v for v in self._volumes if v.get("health_level") in ("warn", "critical")]
            note = (f"disco {unhealthy[0]['health'].lower()}: {unhealthy[0].get('model', '')}" if unhealthy
                    else f"la más llena al {worst['percent']:.0f} %")
            self._set_metric("volumes", str(len(self._volumes)), note,
                             LEVEL_COLOR.get(unhealthy[0]["health_level"]) if unhealthy else None)
        else:
            self._set_metric("volumes", "—", "")
        if self._busy:
            self.hero_note.setText("Analizando…")
        elif scan is not None:
            when = dt.datetime.fromisoformat(scan["when"]).strftime("%H:%M")
            self.hero_note.setText(f"Último análisis {when} · antigüedad mínima {_age_text(scan['age_h'])}.")

    def _selected_rows(self, ready_only: bool = False) -> List[Dict[str, Any]]:
        rows = (self._scan or {}).get("targets", [])
        return [r for r in rows if self._checked.get(r["key"]) and (not ready_only or r["status"] == "ok")
                and r["status"] not in ("absent", "unsafe")]

    def _render_targets(self) -> None:
        rows = (self._scan or {}).get("targets", [])
        table = self.targets_table
        table.blockSignals(True)  # rellenar no debe disparar _check_changed
        with frozen(table):
            table.setRowCount(len(rows))
            for r, row in enumerate(rows):
                usable = row["status"] not in ("absent", "unsafe")
                check = _item("", data=row["key"])
                flags = Qt.ItemFlag.ItemIsUserCheckable | (Qt.ItemFlag.ItemIsEnabled if usable else Qt.ItemFlag.NoItemFlags)
                check.setFlags(flags)
                check.setCheckState(Qt.CheckState.Checked if self._checked.get(row["key"]) and usable
                                    else Qt.CheckState.Unchecked)
                roots = row["roots"] or [x["path"] for x in row.get("rejected", [])]
                rule = ("cualquier antigüedad (se regenera sola)" if row["age_h"] <= 0
                        else f"archivos con más de {_age_text(row['age_h'])}")
                title_tip = tech_tip(row["title"], roots or ["(no existe en este equipo)"],
                                     f"{row['desc']} Regla: {rule}." + (" Requiere Administrador." if row["admin"] else ""))
                text, color = self._status_text(row)
                files_tip = (f"{row['files']} archivos en total · {row['recent_files']} recientes (se respetan)"
                             + (" · análisis parcial por tiempo" if row["partial"] else ""))
                cells = [check,
                         _item(row["title"], COLORS["text"] if usable else COLORS["muted"], title_tip),
                         _item("Sistema" if row["scope"] == "system" else "Usuario", COLORS["text2"]),
                         _item(str(row["eligible_files"]) if usable else "—", COLORS["text2"], files_tip),
                         _item(human_bytes(row["eligible_bytes"]) if usable else "—",
                               COLORS["text"] if row["eligible_bytes"] else COLORS["muted"]),
                         _item(text, color, row["note"])]
                for c, it in enumerate(cells):
                    table.setItem(r, c, it)
        table.blockSignals(False)
        if self._scan is not None:
            table.set_empty_text("No hay categorías de limpieza en este sistema.", "fa5s.broom")
        self._render_cleanup_note()

    def _render_cleanup_note(self) -> None:
        if self._scan is None:
            self.cleanup_note.setText("")
            return
        ready = self._selected_rows(ready_only=True)
        pending = [r for r in self._selected_rows() if r["status"] != "ok"]
        note = (f"{len(ready)} categoría(s) marcadas listas para liberar "
                f"{human_bytes(sum(r['eligible_bytes'] for r in ready))}.")
        if pending:
            note += " Se omitirán: " + "; ".join(f"{r['title']} ({r['note'].rstrip('.')})" for r in pending) + "."
        self.cleanup_note.setText(note)

    @staticmethod
    def _status_text(row: Dict[str, Any]):
        if row["status"] in STATUS_STYLE:
            text, color = STATUS_STYLE[row["status"]]
        elif row["eligible_bytes"]:
            text, color = "● Lista", COLORS["ok"]
        else:
            text, color = "Nada que liberar", COLORS["muted"]
        return (text + " · parcial" if row["partial"] else text), color

    def _render_volumes(self) -> None:
        table = self.volumes_table
        with frozen(table):
            table.setRowCount(len(self._volumes))
            for r, v in enumerate(self._volumes):
                color = LEVEL_COLOR[v["level"]]
                name = v["mount"] + (" (sistema)" if v["system"] else "")
                tip = (f"{v['device']} · {human_bytes(v['used'])} usados de {human_bytes(v['total'])}"
                       + (" · extraíble" if v.get("removable") else ""))
                health = v.get("health")
                cells = [_item(name, COLORS["text"], tip),
                         _item(v["fstype"], COLORS["text2"]),
                         _item(f"{v['percent']:.0f} %", color),
                         _item(human_bytes(v["free"]), COLORS["text2"]),
                         _item(human_bytes(v["total"]), COLORS["text2"]),
                         _item(v.get("media") or "—", COLORS["text2"]),
                         _item(health or "—", LEVEL_COLOR.get(v.get("health_level"), COLORS["muted"]),
                               "Estado que informa Windows (Get-PhysicalDisk)" if health else
                               "Windows no informa la salud de este disco"),
                         _item(v.get("model") or "—", COLORS["text2"], v.get("model") or "")]
                for c, it in enumerate(cells):
                    table.setItem(r, c, it)
        if self._loaded and not self._busy and not self._volumes:
            table.set_empty_text("No se pudieron leer los volúmenes (¿psutil instalado?).", "fa5s.hdd")

    # =============================================================================================
    # Selección de categorías
    # =============================================================================================
    def _check_changed(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        key = item.data(Qt.ItemDataRole.UserRole)
        if key in self._checked:
            # Sin rehacer la tabla: este slot corre dentro de la señal del propio elemento.
            self._checked[key] = item.checkState() == Qt.CheckState.Checked
            self._render_hero()
            self._render_cleanup_note()

    def _reset_checks(self) -> None:
        self._checked = {t.key: t.default for t in disk.TARGETS}
        self._render()

    # =============================================================================================
    # Liberar espacio
    # =============================================================================================
    def _clean(self) -> None:
        if self._busy:
            return
        if self._scan is None:
            self.refresh(user=True)
            return
        chosen = self._selected_rows()   # marcadas y utilizables (existen y su ruta es segura)
        runnable = [r for r in chosen if r["status"] == "ok" and r["eligible_bytes"]]
        need_admin = [r for r in chosen if r["status"] == "admin"]
        skipped = [r for r in chosen if r["status"] == "in_use"]
        if need_admin and not getattr(self.app, "admin", False):
            # Sin elevación ni siquiera se puede medir lo que ocupan: se ofrece el UAC antes de nada.
            self.app.console.log("!", f"Liberar espacio: {len(need_admin)} categoría(s) del sistema requieren "
                                      "Administrador")
            if self.confirm_exact("Se requiere Administrador",
                                  f"{len(need_admin)} categoría(s) del sistema solo se pueden limpiar elevado: "
                                  + ", ".join(r["title"] for r in need_admin) + ".", [],
                                  footer=("¿Relanzar Lozarus como Administrador (UAC)? Si cancelas, se limpiarán solo "
                                          f"las otras {len(runnable)} categoría(s)." if runnable else
                                          "¿Relanzar Lozarus como Administrador (UAC)?"),
                                  confirm_text="Relanzar como Administrador", danger=False):
                self.app.relaunch_as_admin()
                return
        if not runnable:
            why = []
            if need_admin:
                why.append("las del sistema requieren Administrador")
            if skipped:
                why.append("hay programas abiertos: " + ", ".join(r["title"] for r in skipped))
            Toast.notify(self.app, "~", "Liberar espacio", "Las categorías marcadas no tienen nada que liberar ahora"
                         + (f" ({'; '.join(why)})." if why else "."), PAGE_ICON)
            return
        age = self._age()
        total = sum(r["eligible_bytes"] for r in runnable)
        lines = [f"{r['title']} · {human_bytes(r['eligible_bytes'])}: {root}" for r in runnable for root in r["roots"]]
        footer = (f"Solo archivos con más de {_age_text(age)} (las cachés regenerables, de cualquier antigüedad); "
                  "nunca a través de enlaces o uniones; lo que esté en uso se omite.")
        if skipped:
            footer += " Se omitirán: " + ", ".join(f"{r['title']} ({r['note'].rstrip('.')})" for r in skipped) + "."
        if not self.confirm_exact("Liberar espacio", f"Se liberarán hasta {human_bytes(total)} en {len(runnable)} "
                                  "categoría(s) de ESTE equipo:", lines, footer=footer,
                                  confirm_text="Liberar espacio", danger=True):
            self.app.console.log("~", "Liberar espacio: cancelado")
            return
        keys = [r["key"] for r in runnable]
        self._busy = True
        self._render()
        self.app.log_tactical(f"Almacenamiento: liberando espacio en {len(keys)} categoría(s) "
                              f"(antigüedad mínima {_age_text(age)})")
        self.run_action(self.clean_btn, "Liberando…", lambda emit: disk.clean_targets(keys, age_h=age, emit=emit),
                        self._cleaned)

    def _cleaned(self, ok: bool, res) -> None:
        self._busy = False
        if not ok or not isinstance(res, dict):
            self.finish(self.clean_btn, "x", "Liberar espacio", f"No se pudo completar: {res}", PAGE_ICON,
                        source=SOURCE, event_type="storage.cleanup_completed", payload={"ok": False, "error": str(res)})
            self.refresh()
            return
        self._recovered += res["freed"]
        for t in res["targets"]:
            if t["freed"] or t["deleted"]:
                acc = self._recovered_by.setdefault(t["key"], {"title": t["title"], "bytes": 0, "files": 0})
                acc["bytes"] += t["freed"]
                acc["files"] += t["deleted"]
        self._runs.append({"when": dt.datetime.now().isoformat(timespec="seconds"), "freed": res["freed"],
                           "deleted": res["deleted"], "age_h": res["age_h"]})
        gain = (res["free_after"] - res["free_before"]
                if res.get("free_after") is not None and res.get("free_before") is not None else None)
        text = f"{human_bytes(res['freed'])} liberados en {res['deleted']} archivos"
        if res["locked"]:
            text += f" · {res['locked']} en uso omitidos"
        if gain is not None and gain > 0:
            text += f" · espacio libre del sistema +{human_bytes(gain)}"
        kind = "*" if res["freed"] else "~"
        self.finish(self.clean_btn, kind, "Liberar espacio", text, PAGE_ICON, source=SOURCE,
                    event_type="storage.cleanup_completed",
                    payload={"ok": True, "freed": res["freed"], "deleted": res["deleted"], "locked": res["locked"],
                             "redirected": res["redirected"], "age_h": res["age_h"], "free_gain": gain,
                             "seconds": res["seconds"],
                             "targets": [{k: t[k] for k in ("key", "status", "deleted", "freed", "locked", "partial")}
                                         for t in res["targets"]]})
        if res["redirected"]:  # una unión intentó desviar el borrado: es un indicio que merece una alerta
            self.app.record_alert("x", f"Saneamiento: {res['redirected']} borrado(s) bloqueado(s) porque un enlace o "
                                       "una unión los desviaba fuera de su carpeta.", module=PAGE_KEY)
        self.refresh()

    # =============================================================================================
    # Optimización nativa de la unidad
    # =============================================================================================
    def _optimize(self) -> None:
        if self.opt_strip.active:
            return
        if not disk.IS_WINDOWS:
            Toast.notify(self.app, "!", "Optimizar unidad", "Disponible solo en Windows.", PAGE_ICON)
            return
        if not self.admin_ok("Optimizar la unidad", "defrag /O aplica TRIM en SSD o desfragmenta un HDD."):
            return
        sysvol = disk.system_volume(self._volumes) if self._volumes else None
        drive = disk.system_mount()[:2]
        media = (sysvol or {}).get("media", "—")
        detail = {"SSD": "Unidad SSD: Windows enviará TRIM (suele tardar segundos o pocos minutos).",
                  "HDD": "Disco duro (HDD): Windows lo desfragmentará; puede tardar bastante y puedes cancelarlo."}.get(
            media, "Windows elegirá TRIM o desfragmentación según el tipo de disco.")
        if not self.confirm_exact("Optimizar unidad del sistema", f"Optimización NATIVA de Windows sobre {drive}. {detail}",
                                  [f"defrag {drive} /O /U"],
                                  footer="Interrumpirla es seguro: la unidad queda consistente.",
                                  confirm_text="Optimizar", danger=False):
            return
        task = TaskProgress()
        self.opt_strip.start(task, f"defrag {drive}")
        self._render()
        self.app.log_tactical(f"Almacenamiento: optimizando la unidad {drive} (defrag /O)")
        self.run_action(self.opt_btn, "Optimizando…",
                        lambda emit: disk.optimize_volume(drive, admin=True, cancel=task.cancel,
                                                          on_progress=task.set, emit=emit),
                        self._optimized_done)

    def _optimized_done(self, ok: bool, res) -> None:
        self.opt_strip.stop()
        res = res if ok and isinstance(res, dict) else {"ok": False, "message": f"No se pudo completar: {res}",
                                                        "drive": "", "command": "", "rc": None, "seconds": 0.0,
                                                        "cancelled": False}
        self._optimized = {**res, "when": dt.datetime.now().isoformat(timespec="seconds")}
        self.opt_note.setText(res["message"])
        kind = "*" if res["ok"] else "~" if res.get("cancelled") else "x"
        self.finish(self.opt_btn, kind, "Optimizar unidad", res["message"], PAGE_ICON, source=SOURCE,
                    event_type="storage.volume_optimized",
                    payload={k: res.get(k) for k in ("drive", "command", "ok", "rc", "seconds", "cancelled", "lines")})
        self._render()

    def cancel_tasks(self) -> None:
        """Cierre de la ventana: detiene defrag si sigue en marcha (MainWindow.closeEvent)."""
        self.opt_strip.cancel()

    # =============================================================================================
    # Consumidores de espacio
    # =============================================================================================
    def _analyze_space(self) -> None:
        self.app.log_tactical("Almacenamiento: analizando las carpetas del usuario (solo lectura)")
        self.space_note.setText("Recorriendo las carpetas del usuario…")

        def done(ok: bool, res) -> None:
            if not ok or not isinstance(res, dict):
                self.space_note.setText(f"No se pudo analizar: {res}")
                Toast.notify(self.app, "x", "Consumidores de espacio", f"No se pudo analizar: {res}", "fa5s.chart-pie")
                return
            self._space = res
            self._render_space()
            top = res["folders"][0] if res["folders"] else None
            text = (f"{human_bytes(res['total'])} en {res['scanned']} archivos analizados"
                    + (f" · la mayor: {top['label']} ({human_bytes(top['bytes'])})" if top else ""))
            self.finish(self.space_btn, "*", "Consumidores de espacio", text, "fa5s.chart-pie", source=SOURCE,
                        event_type="storage.space_analyzed",
                        payload={"total": res["total"], "partial": res["partial"], "seconds": res["seconds"],
                                 "folders": [{"label": f["label"], "bytes": f["bytes"]} for f in res["folders"]],
                                 "largest": [{"name": f["name"], "bytes": f["bytes"]} for f in res["largest"][:5]]})

        self.run_action(self.space_btn, "Analizando…", lambda emit: disk.space_consumers(), done)

    def _render_space(self) -> None:
        res = self._space or {}
        folders, files = res.get("folders", []), res.get("largest", [])
        total = res.get("total") or 0
        with frozen(self.folders_table):
            self.folders_table.setRowCount(len(folders))
            for r, f in enumerate(folders):
                share = f" ({f['bytes'] / total * 100:.0f} %)" if total else ""
                cloud = f" · {f['cloud_files']} solo en la nube (no ocupan disco)" if f["cloud_files"] else ""
                for c, it in enumerate([_item(f["label"], COLORS["text"], f["path"] + cloud, data=f["path"]),
                                        _item(human_bytes(f["bytes"]) + share, COLORS["text2"]),
                                        _item(str(f["files"]), COLORS["text2"])]):
                    self.folders_table.setItem(r, c, it)
        with frozen(self.files_table):
            self.files_table.setRowCount(len(files))
            for r, f in enumerate(files):
                when = dt.datetime.fromisoformat(f["modified"]).strftime("%d/%m/%Y")
                for c, it in enumerate([_item(f["name"], COLORS["text"], f"{f['path']} · modificado {when}",
                                              data=f["folder"]),
                                        _item(human_bytes(f["bytes"]), COLORS["text2"]),
                                        _item(f["folder"], COLORS["muted"], f["folder"], data=f["folder"])]):
                    self.files_table.setItem(r, c, it)
        if res:
            self.folders_table.set_empty_text("No se encontraron las carpetas habituales del usuario.", "fa5s.folder-open")
            self.space_note.setText(f"{human_bytes(total)} analizados en {res['seconds']:.0f} s"
                                    + (" · PARCIAL: había demasiados archivos para el tiempo máximo" if res["partial"]
                                       else "") + ".")

    def _open_selected(self, table) -> None:
        row = table.currentRow()
        item = table.item(row, 0) if row >= 0 else None
        path = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if path and os.path.isdir(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    # =============================================================================================
    # Datos para el informe ejecutivo y el Centro de Comando
    # =============================================================================================
    def report_data(self) -> Dict[str, Any]:
        """Estado de la sesión para el informe. Sin análisis previo, lee los volúmenes al momento (psutil)."""
        volumes = self._volumes or disk.analyze_volumes()
        scan = self._scan
        return {
            "volumes": [{k: v.get(k) for k in ("mount", "fstype", "total", "used", "free", "percent", "level",
                                                "system", "media", "health", "health_level", "model")}
                        for v in volumes],
            "scan": None if scan is None else {
                "when": scan["when"], "age_h": scan["age_h"], "eligible_bytes": scan["eligible_bytes"],
                "eligible_files": scan["eligible_files"], "blocked_bytes": scan["blocked_bytes"],
                "targets": [{"title": r["title"], "scope": r["scope"], "status": r["status"],
                             "eligible_bytes": r["eligible_bytes"], "eligible_files": r["eligible_files"]}
                            for r in scan["targets"] if r["status"] != "absent"]},
            "recovered": self._recovered,
            "recovered_by": sorted(self._recovered_by.values(), key=lambda x: -x["bytes"]),
            "runs": len(self._runs),
            "optimized": None if self._optimized is None else
            {k: self._optimized.get(k) for k in ("drive", "ok", "message", "when", "seconds")},
            "space": None if self._space is None else {"total": self._space["total"],
                                                       "folders": self._space["folders"][:6],
                                                       "largest": self._space["largest"][:5]},
        }

    def reclaimable(self) -> Optional[int]:
        """Bytes liberables según el último análisis de la sesión (None si aún no se ha analizado)."""
        return None if self._scan is None else self._scan["eligible_bytes"]
