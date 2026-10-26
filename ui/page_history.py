"""
ui/page_history.py · LOZARUS KIT TOOL

Página HISTORIAL: snapshots de la caja negra, eventos y autopsia forense de archivos.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QPlainTextEdit, QPushButton, QSplitter, QTabWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from modulos._forense import FORENSICS_DIR, list_snapshots, system_snapshot
from modulos._forense_autopsia import (analyze_file, classify_entropy, event_row, export_report,
                                       read_events)

from ui.theme import COLORS
from ui.widgets import Page, _emit_event, frozen, make_table, set_busy, with_icon

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow


class HistorialPage(Page):
    """
    Panel forense: visor/rebobinado de la Caja Negra (eventos.jsonl real), mesa de autopsias ESTÁTICA
    de archivos (hashes, entropía, cabeceras PE, indicadores) y snapshots del estado volátil. Todo
    local y de solo lectura: no ejecuta nada ni modifica los archivos analizados.
    """

    SOURCES = [("todas", "Todas las fuentes"), ("honeypot", "Honeypot"), ("privacy", "Privacidad"),
               ("network", "Red"), ("monitor", "Monitor"), ("forensics", "Forense"), ("otros", "Otros")]

    def __init__(self, app: "MainWindow"):
        super().__init__("Historial y Laboratorio Forense",
                         "Visor de la Caja Negra, mesa de autopsias de archivos y snapshots del "
                         "sistema. Todo local y de solo lectura.", "fa5s.history")
        self.app = app
        self.snaps = []
        self._events = []
        self._filtered = []
        # Debounce del buscador: filtrar hasta 5000 eventos en CADA pulsación hacía que escribir
        # fuese a saltos; se filtra 200 ms después de la última tecla.
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(200)
        self._search_timer.timeout.connect(self._apply_filter)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_blackbox_tab(), "Visor de Caja Negra")
        self.tabs.addTab(self._build_autopsy_tab(), "Mesa de Autopsias")
        self.tabs.addTab(self._build_snapshots_tab(), "Snapshots del sistema")
        self.root.addWidget(self.tabs, 1)
        self.refresh()        # lista de snapshots (síncrono)
        # La carga de la Caja Negra usa run_task (consola): se aplaza hasta que el bucle de eventos
        # arranca, porque la consola de telemetría aún no existe al construir las páginas.
        QTimer.singleShot(0, self._initial_load)

    def _initial_load(self) -> None:
        if getattr(self.app, "console", None) is not None:
            self.reload_events()

    # --- Visor de la Caja Negra -----------------------------------------------------------
    def _blackbox_file(self) -> str:
        bb = getattr(self.app, "blackbox", None)
        if bb is not None and getattr(bb, "path", None):
            return bb.path
        return os.path.join(FORENSICS_DIR, "CajaNegra", "eventos.jsonl")

    def _build_blackbox_tab(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Content")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)  # aire dentro del marco de la pestaña
        lay.setSpacing(10)
        ctl = QHBoxLayout()
        ctl.setSpacing(10)
        self.reload_btn = QPushButton("Recargar / Rebobinar")
        self.reload_btn.setObjectName("Primary")
        with_icon(self.reload_btn, "fa5s.redo")
        self.reload_btn.clicked.connect(self.reload_events)
        self.source_combo = QComboBox()
        for key, label in self.SOURCES:
            self.source_combo.addItem(label, key)
        self.source_combo.currentIndexChanged.connect(self._apply_filter)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Buscar texto en los eventos…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._search_timer.start)  # reinicia el debounce
        self.export_btn = QPushButton("Exportar informe")
        self.export_btn.setObjectName("Ghost")
        with_icon(self.export_btn, "fa5s.file-export", COLORS["muted"])
        self.export_btn.clicked.connect(self._export_events)
        ctl.addWidget(self.reload_btn)
        ctl.addWidget(self.source_combo)
        ctl.addStretch(1)
        ctl.addWidget(self.export_btn)
        lay.addLayout(ctl)
        lay.addWidget(self.search_edit)  # fila propia y a todo lo ancho: antes quedaba aplastado
        self.bb_count = QLabel("—")
        self.bb_count.setObjectName("Tiny")
        lay.addWidget(self.bb_count)
        self.events_table = make_table(["Hora (UTC)", "Categoría", "Fuente", "Tipo", "Resumen"],
                                       widths=[150, 105, 170, 210])
        self.events_table.setMinimumHeight(240)
        self.events_table.itemSelectionChanged.connect(self._show_event_json)
        # Tabla (arriba) y JSON del evento (abajo) en un QSplitter: ninguno queda aplastado.
        json_host = QWidget()
        json_host.setObjectName("Content")
        jl = QVBoxLayout(json_host)
        jl.setContentsMargins(0, 2, 0, 0)
        jl.setSpacing(4)
        cap = QLabel("JSON DEL EVENTO SELECCIONADO")
        cap.setObjectName("ConsoleTitle")
        jl.addWidget(cap)
        self.event_json = QPlainTextEdit()
        self.event_json.setObjectName("Console")
        self.event_json.setReadOnly(True)
        self.event_json.setFont(QFont("Consolas", 10))
        self.event_json.setMinimumHeight(110)
        jl.addWidget(self.event_json, 1)
        split = QSplitter(Qt.Orientation.Vertical)
        split.setObjectName("VSplit")
        split.setHandleWidth(6)
        split.addWidget(self.events_table)
        split.addWidget(json_host)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setCollapsible(0, False)
        lay.addWidget(split, 1)
        return w

    def reload_events(self) -> None:
        path = self._blackbox_file()
        set_busy(self.reload_btn, True, "Leyendo…")

        def done(ok, data):
            set_busy(self.reload_btn, False)
            self._events = data if ok and isinstance(data, list) else []
            if not ok:
                self.app.console.log("x", f"Caja Negra: {data}")
            self._apply_filter()

        self.app.run_task(lambda emit: read_events(path, limit=5000), done)

    def _apply_filter(self) -> None:
        key = self.source_combo.currentData()
        needle = self.search_edit.text().strip().lower()
        self._filtered = []
        rows = []
        for ev in self._events:
            r = event_row(ev)
            if key and key != "todas" and r[1] != key:
                continue
            if needle and needle not in " ".join(str(x) for x in r).lower():
                continue
            self._filtered.append(ev)
            rows.append(r)
        if not self._events:
            self.events_table.set_empty_text("La Caja Negra está vacía: los eventos de seguridad "
                                             "aparecerán aquí según ocurran.", "fa5s.box-open")
        elif not rows:
            self.events_table.set_empty_text("Ningún evento coincide con el filtro actual.", "fa5s.search")
        with frozen(self.events_table):
            self.events_table.setRowCount(len(rows))
            for i, r in enumerate(rows):
                for col, v in enumerate(r):
                    self.events_table.setItem(i, col, QTableWidgetItem(str(v)))
        total = len(self._events)
        filtro = f" de {total}" if len(rows) != total else ""
        # Solo el nombre del fichero: la ruta completa (sin espacios, no se puede partir) forzaba
        # scroll horizontal. La ruta entera queda en el tooltip.
        self.bb_count.setText(f"{len(rows)}{filtro} evento(s) · {os.path.basename(self._blackbox_file())}")
        self.bb_count.setToolTip(self._blackbox_file())
        self.event_json.setPlainText("")

    def _show_event_json(self) -> None:
        r = self.events_table.currentRow()
        if 0 <= r < len(self._filtered):
            self.event_json.setPlainText(json.dumps(self._filtered[r], ensure_ascii=False, indent=2))

    def _export_events(self) -> None:
        if not self._filtered:
            self.app.console.log("~", "No hay eventos que exportar con el filtro actual.")
            return
        destino, _ = QFileDialog.getSaveFileName(
            self.app, "Exportar evidencias",
            os.path.join(os.path.expanduser("~"), "lozarus_evidencias.json"),
            "JSON (*.json);;Texto JSONL (*.txt)")
        if not destino:
            return

        set_busy(self.export_btn, True, "Exportando…")

        def done(ok, n):
            set_busy(self.export_btn, False)
            if ok:
                self.app.console.log("*", f"Exportados {n} evento(s) a {destino}")
            else:
                self.app.console.log("x", f"Exportar: {n}")

        eventos = list(self._filtered)
        self.app.run_task(lambda emit: export_report(eventos, destino), done)

    # --- Mesa de autopsias estática -------------------------------------------------------
    def _build_autopsy_tab(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Content")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)  # aire dentro del marco de la pestaña
        lay.setSpacing(10)
        desc = QLabel("Analiza un archivo SIN ejecutarlo: hashes (MD5/SHA-256), tamaño, entropía de "
                      "Shannon (aviso si supera 7,2), cabeceras PE e indicadores (IPs, URLs, registro, "
                      "APIs sospechosas).")
        desc.setObjectName("CardText")
        desc.setWordWrap(True)
        row = QHBoxLayout()
        self.analyze_btn = QPushButton("Analizar archivo (.exe / .dll / script)")
        self.analyze_btn.setObjectName("Primary")
        with_icon(self.analyze_btn, "fa5s.vial")
        self.analyze_btn.clicked.connect(self._analyze)
        row.addWidget(self.analyze_btn)
        row.addStretch(1)
        lay.addWidget(desc)
        lay.addLayout(row)
        self.autopsy_head = QLabel("—")
        self.autopsy_head.setObjectName("Tiny")
        self.autopsy_head.setWordWrap(True)
        lay.addWidget(self.autopsy_head)
        self.autopsy_out = QPlainTextEdit()
        self.autopsy_out.setObjectName("Console")
        self.autopsy_out.setReadOnly(True)
        self.autopsy_out.setFont(QFont("Consolas", 10))
        lay.addWidget(self.autopsy_out, 1)
        return w

    def _analyze(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self.app, "Selecciona el archivo a analizar",
                                              os.path.expanduser("~"))
        if path:
            self.analyze_path(path)

    def analyze_path(self, path: str) -> None:
        """Analiza `path` en la Mesa de Autopsias (usado también desde el Monitor en Vivo)."""
        if not path:
            return
        self.tabs.setCurrentIndex(1)   # pestaña «Mesa de Autopsias»
        set_busy(self.analyze_btn, True, "Analizando…")
        self.autopsy_head.setText(f"Analizando {os.path.basename(path)}…")
        self.autopsy_out.setPlainText("")
        self.app.log_tactical(f"Autopsia estática: {os.path.basename(path)}")

        def done(ok, res):
            set_busy(self.analyze_btn, False)
            if ok and isinstance(res, dict) and res.get("ok"):
                self._render_autopsy(res)
                _emit_event(self.app, source="forensics:autopsia",
                            event_type="forensics.file_analyzed",
                            payload={"name": res["name"], "sha256": res["sha256"],
                                     "size": res["size"], "entropy": res["entropy"],
                                     "is_pe": res["is_pe"]})
            else:
                err = res.get("error") if isinstance(res, dict) else res
                self.autopsy_head.setText("Error en el análisis")
                self.autopsy_out.setPlainText(str(err))

        self.app.run_task(lambda emit: analyze_file(path), done)

    def _render_autopsy(self, res) -> None:
        etiqueta, warn = classify_entropy(res["entropy"])
        cabecera = f"{res['name']}  ·  {res['size']} bytes  ·  entropía {res['entropy']}/8 ({etiqueta})"
        self.autopsy_head.setText(("⚠ " if warn else "") + cabecera)
        self.autopsy_head.setStyleSheet("color:%s; font-size:12px; font-weight:600;" %
                                        ("#EF4444" if warn else "#A1A1AA"))
        lines = [f"MD5     : {res['md5']}",
                 f"SHA-256 : {res['sha256']}",
                 f"Tamaño  : {res['size']} bytes",
                 f"Entropía: {res['entropy']} / 8  → {etiqueta}"
                 + ("   ⚠ POSIBLE PACKER/CIFRADO" if warn else "")]
        if res["is_pe"] and res["pe"]:
            pe = res["pe"]
            tipo = "DLL" if pe["is_dll"] else ("EXE" if pe["is_exe"] else "PE")
            lines += ["",
                      f"PE      : {pe['magic_name']} · {tipo} · {pe['machine_name']}",
                      f"          secciones={pe['sections']} · subsistema={pe['subsystem_name']}",
                      f"          compilado={pe['timestamp_utc'] or pe['timestamp']}"]
        elif res["is_pe"]:
            lines += ["", "PE      : cabecera MZ presente, pero no se pudo parsear la cabecera PE."]
        else:
            lines += ["", "PE      : no es un ejecutable PE (sin cabecera MZ)."]
        ind = res.get("indicators") or {}
        for titulo, clave in (("IPs", "ips"), ("URLs", "urls"),
                              ("Rutas de registro", "registry"), ("APIs sospechosas", "apis")):
            vals = ind.get(clave) or []
            lines += ["", f"{titulo} ({len(vals)}):"]
            lines += [f"  · {v}" for v in vals] if vals else ["  (ninguno)"]
        self.autopsy_out.setPlainText("\n".join(lines))

    # --- Snapshots del estado volátil (comportamiento previo) -----------------------------
    def _build_snapshots_tab(self) -> QWidget:
        w = QWidget()
        w.setObjectName("Content")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)  # aire dentro del marco de la pestaña
        lay.setSpacing(10)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.snap_btn = QPushButton("Tomar Snapshot del Sistema")
        self.snap_btn.setObjectName("Primary")
        with_icon(self.snap_btn, "fa5s.camera")
        self.snap_btn.clicked.connect(self._take)
        open_btn = QPushButton("Abrir carpeta forense")
        open_btn.setObjectName("Ghost")
        with_icon(open_btn, "fa5s.folder-open", COLORS["muted"])
        open_btn.clicked.connect(lambda: self._open(FORENSICS_DIR))
        row.addWidget(self.snap_btn)
        row.addWidget(open_btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.table = make_table(["Snapshot", "Fecha", "Tamaño"], widths=[320, 170],
                                empty="Aún no hay snapshots. Pulsa «Tomar Snapshot del Sistema» o usa "
                                      "la Captura Instantánea del Centro de Comando.",
                                empty_icon="fa5s.camera")
        self.table.setToolTip("Doble clic para abrir la carpeta del snapshot")
        self.table.doubleClicked.connect(self._open_selected)
        lay.addWidget(self.table, 1)
        return w

    def refresh(self) -> None:
        self.snaps = list_snapshots()
        with frozen(self.table):
            self.table.setRowCount(len(self.snaps))
            for r, (path, name, when) in enumerate(self.snaps):
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                for col, v in enumerate([name, f"{when:%d/%m/%Y %H:%M:%S}", f"{size / 1024:.0f} KB"]):
                    self.table.setItem(r, col, QTableWidgetItem(v))

    def _take(self) -> None:
        set_busy(self.snap_btn, True, "Capturando…")
        self.app.log_tactical("Capturando snapshot de caja negra del sistema")

        def done(ok, payload):
            set_busy(self.snap_btn, False)
            if ok:
                path, summary = payload
                self.app.console.log("*", f"Snapshot guardado: {os.path.basename(path)} "
                                          f"({summary['procesos']} procesos · {summary['conexiones']} conexiones)")
                self.refresh()
            else:
                self.app.console.log("x", f"Snapshot: {payload}")

        self.app.run_task(lambda emit: system_snapshot(), done)

    def _open_selected(self) -> None:
        r = self.table.currentRow()
        if 0 <= r < len(self.snaps):
            self._open(self.snaps[r][0])

    def _open(self, path: str) -> None:
        try:
            os.startfile(os.path.dirname(path) if os.path.isfile(path) else path)  # noqa: S606
        except Exception as exc:  # noqa: BLE001  (antes se silenciaba: el clic no hacía nada)
            self.app.console.log("x", f"No se pudo abrir «{path}»: {exc}")
