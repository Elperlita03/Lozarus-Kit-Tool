"""
ui/page_ghost.py · LOZARUS KIT TOOL

Página MODO FANTASMA: limpieza de privacidad con terminal en vivo.
"""

from __future__ import annotations

import getpass
import os
import time
from typing import TYPE_CHECKING

import psutil
from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QFileDialog, QFrame, QHBoxLayout, QLabel, QPushButton,
                               QTableWidgetItem)

from modulos._privacidad import (clean_temp, clear_clipboard, empty_working_sets, is_hijack_swap,
                                 looks_sensitive, read_clipboard_text, shred_file, temp_dir)
from modulos._tacticas import GHOST_STEPS, ghost_preview
from modulos._inicio import startup_entries

from ui._compat import ObservationQuality
from ui.theme import COLORS
from ui.widgets import Page, _emit_event, frozen, make_card, make_table, set_busy, with_icon
from ui.dialogs import ConfirmDialog, TerminalDialog

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow


class GhostPage(Page):
    def __init__(self, app: "MainWindow"):
        super().__init__("Modo Fantasma",
                         "Herramientas de privacidad y limpieza de ESTE equipo. Las acciones "
                         "destructivas piden confirmación. La vigilancia del portapapeles avisa y, si "
                         "detecta el cambio de dirección típico de un clipper, vacía el portapapeles; "
                         "no elimina el malware.",
                         "fa5s.ghost")
        self.app = app
        self._clip_last = None
        self._clip_last_time = None

        body = self.root
        body.addWidget(self._build_shredder_card())
        body.addWidget(self._build_clipboard_card())
        body.addWidget(self._build_ram_card())
        body.addWidget(self._build_temp_card())
        body.addWidget(self._build_purge_card())
        body.addWidget(self._build_health_card())
        body.addWidget(self._build_autoruns_card())
        body.addStretch(1)

        # 600 ms: suficiente para cazar un intercambio de dirección cripto en < 1,5 s y vaciar en el acto.
        self._clip_timer = QTimer(self)
        self._clip_timer.setInterval(600)
        self._clip_timer.timeout.connect(self._clip_tick)

    # --- Trituradora de archivos ----------------------------------------------------------
    def _build_shredder_card(self) -> QFrame:
        box, lay = make_card("Trituradora de archivos",
                             "Elige un archivo: se sobrescribe con bytes aleatorios y se elimina. "
                             "Irreversible. En discos SSD la sobrescritura no garantiza el borrado "
                             "físico (wear-leveling); para eso haría falta cifrado de disco.")
        row = QHBoxLayout()
        self.shred_btn = QPushButton("Elegir archivo y triturar")
        self.shred_btn.setObjectName("Danger")
        with_icon(self.shred_btn, "fa5s.eraser", COLORS["beacon"])
        self.shred_btn.clicked.connect(self._shred)
        row.addWidget(self.shred_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return box

    def _shred(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self.app, "Selecciona el archivo a triturar",
                                              os.path.expanduser("~"))
        if not path:
            return
        if not ConfirmDialog.ask(self.app, "Triturar archivo",
                                 f"Se sobrescribirá y borrará DEFINITIVAMENTE:\n\n{path}\n\n"
                                 "Esta acción no se puede deshacer. ¿Continuar?",
                                 confirm_text="Triturar", danger=True):
            return
        set_busy(self.shred_btn, True, "Triturando…")
        self.app.log_tactical(f"Triturando archivo: {os.path.basename(path)}")

        def done(ok, res):
            set_busy(self.shred_btn, False)
            if ok and isinstance(res, dict) and res.get("ok"):
                self.app.console.log("*", f"Triturado: {os.path.basename(path)} "
                                          f"({res['bytes']} bytes · {res['passes']} pasada/s)")
                _emit_event(self.app, source="fantasma:trituradora",
                            event_type="privacy.file_shredded",
                            payload={"name": os.path.basename(path), "bytes": res["bytes"]})
            else:
                err = res.get("error") if isinstance(res, dict) else res
                self.app.console.log("x", f"Trituradora: {err}")

        self.app.run_task(lambda emit: shred_file(path), done)

    # --- Portapapeles (anti-clipper) ------------------------------------------------------
    def _build_clipboard_card(self) -> QFrame:
        box, lay = make_card("Portapapeles (anti-clipper)",
                             "Vacía el portapapeles al instante y, opcionalmente, vigila si copias datos "
                             "que PARECEN sensibles (frase semilla, dirección cripto, clave, tarjeta). La "
                             "vigilancia avisa y lo registra en la Caja Negra; no guarda el contenido "
                             "copiado.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.clip_clear_btn = QPushButton("Vaciar portapapeles ahora")
        self.clip_clear_btn.setObjectName("Ghost")
        with_icon(self.clip_clear_btn, "fa5s.clipboard", COLORS["muted"])
        self.clip_clear_btn.clicked.connect(self._clear_clipboard)
        self.clip_watch_btn = QPushButton("Vigilar portapapeles: OFF")
        self.clip_watch_btn.setObjectName("Toggle")
        self.clip_watch_btn.setCheckable(True)
        with_icon(self.clip_watch_btn, "fa5s.binoculars", COLORS["muted"])
        self.clip_watch_btn.clicked.connect(self._toggle_clip_watch)
        self.autopurge_btn = QPushButton("Auto-purgar en 15 s: OFF")
        self.autopurge_btn.setObjectName("Toggle")
        self.autopurge_btn.setCheckable(True)
        with_icon(self.autopurge_btn, "fa5s.hourglass-half", COLORS["muted"])
        self.autopurge_btn.clicked.connect(
            lambda: self.autopurge_btn.setText(
                "Auto-purgar en 15 s: " + ("ON" if self.autopurge_btn.isChecked() else "OFF")))
        # Acción inmediata en una fila y los dos interruptores en otra: en una sola fila los tres
        # botones no cabían en la ventana por defecto y aparecía scroll horizontal.
        row.addWidget(self.clip_clear_btn)
        row.addStretch(1)
        toggles = QHBoxLayout()
        toggles.setSpacing(10)
        toggles.addWidget(self.clip_watch_btn)
        toggles.addWidget(self.autopurge_btn)
        toggles.addStretch(1)
        defensa = QLabel("Defensa anti-swap activa mientras vigilas: si el portapapeles pasa de una "
                         "dirección cripto a otra distinta en <1,5 s, se vacía al instante y se graba "
                         "un evento crítico en la Caja Negra.")
        defensa.setObjectName("Tiny")
        defensa.setWordWrap(True)
        lay.addLayout(row)
        lay.addLayout(toggles)
        lay.addWidget(defensa)
        return box

    def _clear_clipboard(self) -> None:
        ok, msg = clear_clipboard()
        self.app.console.log("*" if ok else "x", f"Portapapeles: {msg}")
        self._clip_last = None

    def _toggle_clip_watch(self) -> None:
        on = self.clip_watch_btn.isChecked()
        self.clip_watch_btn.setText("Vigilar portapapeles: " + ("ON" if on else "OFF"))
        if on:
            self._clip_last = read_clipboard_text()  # referencia inicial: no avisa de lo ya copiado
            self._clip_last_time = time.monotonic()
            self._clip_timer.start()
            self.app.log_tactical("Vigilancia del portapapeles activada (anti-clipper)")
        else:
            self._clip_timer.stop()
            self.app.console.log("~", "Vigilancia del portapapeles detenida")

    def _clip_tick(self) -> None:
        text = read_clipboard_text()
        if text is None or text == self._clip_last:
            return
        ahora = time.monotonic()
        prev, prev_t = self._clip_last, self._clip_last_time
        self._clip_last, self._clip_last_time = text, ahora

        # 1) Defensa anti-swap: ¿una dirección cripto cambió por otra en < 1,5 s? → vaciar YA.
        delta = (ahora - prev_t) if prev_t is not None else None
        if is_hijack_swap(prev, text, delta):
            clear_clipboard()
            self._clip_last = None
            self.app.console.log("x", "¡Clipper bloqueado! El portapapeles cambió de dirección cripto; "
                                      "se vació para que no pegaras la del atacante.")
            self.app.record_alert("x", "Clipper bloqueado: el portapapeles cambió de dirección cripto "
                                       "y se vació en el acto.", module="fantasma")
            _emit_event(self.app, source="fantasma:portapapeles",
                        event_type="clipboard.hijack_blocked",
                        observation=(ObservationQuality.COMPLETE if ObservationQuality else None),
                        payload={"motivo": "intercambio de dirección cripto en <1,5 s",
                                 "delta_s": round(delta, 2) if delta is not None else None})
            return

        # 2) Clasificación/aviso y, si procede, auto-purga a los 15 s.
        sensible, etiqueta = looks_sensitive(text)
        if sensible:
            self.app.console.log("!", f"Portapapeles: contenido sensible detectado — {etiqueta}")
            self.app.record_alert("!", f"Portapapeles: contenido sensible — {etiqueta}", module="fantasma")
            _emit_event(self.app, source="fantasma:portapapeles", event_type="clipboard.sensitive",
                        payload={"clasificacion": etiqueta, "longitud": len(text)})
            if self.autopurge_btn.isChecked():
                self.app.console.log("~", "Auto-purga programada: el portapapeles se vaciará en 15 s "
                                          "si sigue igual.")
                QTimer.singleShot(15000, lambda s=text: self._autopurge(s))

    def _autopurge(self, snapshot) -> None:
        if read_clipboard_text() != snapshot:
            return  # el contenido ya cambió: no tocamos lo que la persona copió después
        ok, _msg = clear_clipboard()
        if ok:
            self._clip_last = None
            self.app.console.log("*", "Auto-purga: portapapeles vaciado (dato sensible, 15 s).")
            _emit_event(self.app, source="fantasma:portapapeles",
                        event_type="clipboard.auto_purged", payload={"tras_segundos": 15})

    # --- Optimizar RAM (working sets) -----------------------------------------------------
    def _build_ram_card(self) -> QFrame:
        box, lay = make_card("Optimizar RAM (vaciar working sets)",
                             "Pide a Windows que recorte el working set de los procesos accesibles del "
                             "usuario y muestra los MB realmente liberados. Sin privilegios (los procesos "
                             "del sistema se omiten). Es temporal: la RAM vuelve a crecer según haga falta.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self.ram_btn = QPushButton("Optimizar RAM ahora")
        self.ram_btn.setObjectName("Ghost")
        with_icon(self.ram_btn, "fa5s.memory", COLORS["muted"])
        self.ram_btn.clicked.connect(self._optimize_ram)
        self.ram_status = QLabel("—")
        self.ram_status.setObjectName("Tiny")
        row.addWidget(self.ram_btn)
        row.addWidget(self.ram_status, 1)
        lay.addLayout(row)
        return box

    def _optimize_ram(self) -> None:
        set_busy(self.ram_btn, True, "Optimizando…")
        self.ram_status.setText("Recortando working sets…")
        self.app.log_tactical("Optimizando RAM: vaciando working sets de los procesos del usuario")

        def done(ok, res):
            set_busy(self.ram_btn, False)
            if ok and isinstance(res, dict) and res.get("ok"):
                self.ram_status.setText(f"{res['liberado_mb']} MB liberados · {res['procesos']} "
                                        f"procesos · {res['omitidos']} omitidos")
                self.app.console.log("*", f"RAM: {res['liberado_mb']} MB liberados en "
                                          f"{res['procesos']} procesos ({res['omitidos']} omitidos)")
                _emit_event(self.app, source="fantasma:ram", event_type="privacy.ram_optimized",
                            payload={"liberado_mb": res["liberado_mb"], "procesos": res["procesos"],
                                     "omitidos": res["omitidos"]})
            else:
                err = res.get("error") if isinstance(res, dict) else res
                self.ram_status.setText("no disponible")
                self.app.console.log("x", f"RAM: {err}")

        self.app.run_task(lambda emit: empty_working_sets(), done)

    # --- Limpiar temporales ---------------------------------------------------------------
    def _build_temp_card(self) -> QFrame:
        box, lay = make_card("Limpiar temporales (%TEMP%)",
                             "Borra los archivos de la carpeta de temporales del usuario que no estén en "
                             f"uso y dice cuántos. Los bloqueados se omiten.\nCarpeta: {temp_dir()}")
        row = QHBoxLayout()
        self.temp_btn = QPushButton("Limpiar temporales")
        self.temp_btn.setObjectName("Ghost")
        with_icon(self.temp_btn, "fa5s.broom", COLORS["muted"])
        self.temp_btn.clicked.connect(self._clean_temp)
        row.addWidget(self.temp_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return box

    def _clean_temp(self) -> None:
        if not ConfirmDialog.ask(self.app, "Limpiar temporales",
                                 f"Se borrarán los archivos NO bloqueados de:\n\n{temp_dir()}\n\n"
                                 "Los archivos en uso se omiten automáticamente. ¿Continuar?",
                                 confirm_text="Limpiar", danger=True):
            return
        set_busy(self.temp_btn, True, "Limpiando…")
        self.app.log_tactical("Limpiando la carpeta de temporales del usuario")

        def done(ok, res):
            set_busy(self.temp_btn, False)
            if ok and isinstance(res, dict) and res.get("ok"):
                mb = res["bytes"] / (1024 * 1024)
                self.app.console.log("*", f"Temporales: {res['eliminados']} archivos borrados "
                                          f"({mb:.1f} MB) · {res['omitidos']} omitidos (en uso)")
                _emit_event(self.app, source="fantasma:temporales",
                            event_type="privacy.temp_cleaned",
                            payload={"eliminados": res["eliminados"], "omitidos": res["omitidos"],
                                     "bytes": res["bytes"]})
            else:
                err = res.get("error") if isinstance(res, dict) else res
                self.app.console.log("x", f"Temporales: {err}")

        self.app.run_task(lambda emit: clean_temp(), done)

    # --- Purga completa (comportamiento previo) -------------------------------------------
    def _build_purge_card(self) -> QFrame:
        steps = " · ".join(label for _k, label, *_ in GHOST_STEPS)
        box, lay = make_card("Purga de privacidad completa",
                             "Ejecuta de una vez todos los pasos de limpieza (con recuento previo y "
                             "confirmación): " + steps + ".")
        row = QHBoxLayout()
        self.run_btn = QPushButton("Ejecutar Modo Fantasma")
        self.run_btn.setObjectName("Danger")
        with_icon(self.run_btn, "fa5s.ghost", COLORS["beacon"])
        self.run_btn.clicked.connect(self._run)
        row.addWidget(self.run_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return box

    def _run(self) -> None:
        set_busy(self.run_btn, True, "Calculando…")
        self.app.console.log("~", "Modo Fantasma: calculando lo que se va a limpiar…")
        self.app.run_task(lambda emit: ghost_preview(), self._previewed)

    def _previewed(self, ok: bool, counts) -> None:
        set_busy(self.run_btn, False)
        counts = counts if ok and isinstance(counts, dict) else {}
        contado = bool(counts.get("ok"))  # True solo si el recuento se calculó de verdad

        def _n(key):  # muestra «?» cuando el recuento no se pudo obtener (desconocido, no 0)
            return counts.get(key, 0) if contado else "?"

        aviso = "" if contado else ("• No se pudo calcular el recuento: se limpiará lo que haya "
                                    "(el recuento de arriba es solo informativo)\n")
        logs = ("• Registros de eventos (Application, System, Security) — IRREVERSIBLE\n" if self.app.admin
                else "• Registros de eventos: se omitirán (requieren Administrador)\n")
        msg = ("Borra de ESTE equipo, sin posibilidad de deshacer:\n\n"
               "• Caché DNS y ARP, portapapeles e historial de PowerShell\n"
               f"• {_n('recientes')} archivo(s) reciente(s) y Jump Lists\n"
               f"• Papelera ({_n('papelera')}) y temporales ({_n('temporales')})\n"
               "• Carpeta Prefetch\n" + logs + aviso +
               "\nEs limpieza de privacidad: no toca tus documentos. ¿Continuar?")
        if not ConfirmDialog.ask(self.app, "Activar Modo Fantasma", msg, confirm_text="Limpiar ahora", danger=True):
            self.app.console.log("~", "Modo Fantasma cancelado")
            return
        options = {k: True for k, _l, needs_admin, _d, _r in GHOST_STEPS if not needs_admin or self.app.admin}
        self.app.log_tactical("Modo Fantasma: iniciando purga de privacidad del equipo")
        set_busy(self.run_btn, True, "Purgando…")
        term = TerminalDialog(self.app, "MODO FANTASMA · purga en curso")
        term.show()
        self.app.run_ghost(options, term, lambda: set_busy(self.run_btn, False))

    # --- Salud del portátil (batería, disco, top procesos) ----------------------------------------
    def _build_health_card(self) -> QFrame:
        box, lay = make_card("Salud del portátil",
                             "Batería, espacio en C: y los 5 procesos que más RAM/CPU consumen ahora.")
        row = QHBoxLayout()
        row.setSpacing(10)
        self._health_lbl = QLabel("Pulsa Actualizar para leer.")
        self._health_lbl.setObjectName("CardText")
        self._health_lbl.setWordWrap(True)
        refresh_btn = QPushButton("Actualizar")
        refresh_btn.setObjectName("Ghost")
        with_icon(refresh_btn, "fa5s.sync-alt", COLORS["muted"])
        refresh_btn.clicked.connect(self._refresh_health)
        row.addWidget(self._health_lbl, 1)
        row.addWidget(refresh_btn)
        lay.addLayout(row)
        self._top_table = make_table(["Proceso", "PID", "CPU %", "RAM MB", "Usuario"],
                                     widths=[200, 70, 70, 80])
        self._top_table.setMaximumHeight(180)
        lay.addWidget(self._top_table)
        self._health_terminate_btn = QPushButton("Finalizar proceso seleccionado (usuario)")
        self._health_terminate_btn.setObjectName("Danger")
        with_icon(self._health_terminate_btn, "fa5s.times-circle", COLORS["beacon"])
        self._health_terminate_btn.setEnabled(False)
        self._health_terminate_btn.clicked.connect(self._terminate_selected_proc)
        self._top_table.itemSelectionChanged.connect(self._on_top_select)
        row2 = QHBoxLayout()
        row2.addWidget(self._health_terminate_btn)
        row2.addStretch(1)
        lay.addLayout(row2)
        return box

    def _refresh_health(self) -> None:
        def task(emit):
            out = {}
            try:
                batt = psutil.sensors_battery()
                if batt:
                    out["batt"] = f"{batt.percent:.0f}%  {'enchufado' if batt.power_plugged else 'batería'}"
                else:
                    out["batt"] = "PC de escritorio (sin batería)"
            except Exception:  # noqa: BLE001
                out["batt"] = "N/A"
            try:
                du = psutil.disk_usage("C:\\")
                out["disk_free"] = f"{du.free / 1024**3:.1f} GB libres de {du.total / 1024**3:.1f} GB"
            except Exception:  # noqa: BLE001
                out["disk_free"] = "N/A"
            try:
                procs = []
                for p in psutil.process_iter(["pid", "name", "username", "memory_info", "cpu_percent"]):
                    try:
                        procs.append({"pid": p.info["pid"], "name": p.info["name"] or "",
                                      "user": p.info["username"] or "", "cpu": p.info["cpu_percent"] or 0,
                                      "ram": (p.info["memory_info"].rss / 1024**2) if p.info["memory_info"] else 0})
                    except Exception:  # noqa: BLE001
                        continue
                top5 = sorted(procs, key=lambda x: x["ram"], reverse=True)[:5]
                out["top5"] = top5
            except Exception:  # noqa: BLE001
                out["top5"] = []
            return out

        def done(ok, res):
            if not ok:
                self._health_lbl.setText(f"Error: {res}")
                return
            self._health_lbl.setText(f"Batería: {res.get('batt', 'N/A')}  ·  Disco C: {res.get('disk_free', 'N/A')}")
            top5 = res.get("top5", [])
            self._top_table.setProperty("_health_rows", top5)
            with frozen(self._top_table):
                self._top_table.setRowCount(len(top5))
                for r, p in enumerate(top5):
                    for c, v in enumerate([p["name"], str(p["pid"]), f"{p['cpu']:.1f}", f"{p['ram']:.0f}", p["user"]]):
                        self._top_table.setItem(r, c, QTableWidgetItem(v))

        self.app.run_task(task, done, track=False)

    def _on_top_select(self) -> None:
        self._health_terminate_btn.setEnabled(len(self._top_table.selectedItems()) > 0)

    def _terminate_selected_proc(self) -> None:
        rows = self._top_table.selectedItems()
        if not rows:
            return
        row = self._top_table.currentRow()
        name_item = self._top_table.item(row, 0)
        pid_item = self._top_table.item(row, 1)
        user_item = self._top_table.item(row, 4)
        if not pid_item:
            return
        pid = int(pid_item.text()) if pid_item.text().isdigit() else -1
        name = name_item.text() if name_item else "?"
        user = user_item.text() if user_item else ""
        me = getpass.getuser()
        if user and me and user.lower() != me.lower() and me.lower() not in user.lower():
            self.app.console.log("!", f"Proceso {name} (PID {pid}) pertenece a otro usuario ({user}): no se puede finalizar.")
            return
        if not ConfirmDialog.ask(self.app, "Finalizar proceso",
                                 f"Finalizar el proceso del USUARIO:\n\n{name}  (PID {pid})\n\n"
                                 "No finalices procesos del sistema. ¿Continuar?",
                                 confirm_text="Finalizar", danger=True):
            return
        try:
            psutil.Process(pid).terminate()
            self.app.console.log("*", f"Proceso finalizado: {name} (PID {pid})")
        except Exception as exc:  # noqa: BLE001
            self.app.console.log("x", f"No se pudo finalizar {name}: {exc}")

    # --- Inspector de Inicio de Windows (Autoruns) ------------------------------------------------
    def _build_autoruns_card(self) -> QFrame:
        box, lay = make_card("Inspector de Inicio de Windows (Autoruns)",
                             "Entradas que arrancan automáticamente con el equipo (HKCU Run + carpetas Inicio). "
                             "Solo lectura; ayuda a detectar programas que ralentizan el arranque.")
        row = QHBoxLayout()
        row.setSpacing(10)
        scan_btn = QPushButton("Escanear entradas de inicio")
        scan_btn.setObjectName("Ghost")
        with_icon(scan_btn, "fa5s.search", COLORS["muted"])
        self._autoruns_table = make_table(["Nombre", "Origen", "Ruta del ejecutable", "Existe"],
                                          widths=[180, 200, 300],
                                          empty="Pulsa «Escanear» para listar las entradas de inicio.")
        self._autoruns_table.setMaximumHeight(200)
        scan_btn.clicked.connect(self._scan_autoruns)
        row.addWidget(scan_btn)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addWidget(self._autoruns_table)
        return box

    def _scan_autoruns(self) -> None:
        def done(ok, entries):
            if not ok:
                self.app.console.log("x", f"Autoruns: {entries}")
                return
            with frozen(self._autoruns_table):
                self._autoruns_table.setRowCount(len(entries))
                for r, e in enumerate(entries):
                    existe = "Sí" if e.get("existe") else "No"
                    color = "#22C55E" if e.get("existe") else "#F59E0B"
                    for c, v in enumerate([e.get("nombre", ""), e.get("origen", ""), e.get("ruta", ""), existe]):
                        item = QTableWidgetItem(v)
                        if c == 3:
                            item.setForeground(QColor(color))
                        self._autoruns_table.setItem(r, c, item)
            self.app.console.log("~", f"Autoruns: {len(entries)} entradas de inicio encontradas")
        self.app.run_task(lambda emit: startup_entries(), done, track=False)
