"""
ui/page_command.py · LOZARUS KIT TOOL

Página CENTRO DE COMANDO: salud de los componentes, áreas del producto y acciones rápidas.
"""

from __future__ import annotations

import getpass
import importlib
import importlib.util
import datetime as dt
import os
import socket
import time
from typing import TYPE_CHECKING, Optional

import psutil
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (QCheckBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QProgressBar,
                               QPushButton, QVBoxLayout)

from modulos._alertas import HAS_PLYER
from modulos._contencion import quarantine_active
from modulos._endurecimiento_red import flush_dns
from modulos._privacidad import clean_temp, empty_working_sets
from modulos._forense import list_snapshots
from modulos._obsidian import events_per_minute, health_score, jsonl_size_kb, process_vitals
from modulos._tacticas import sandbox_available
from modulos._puntuacion import LABELS, WEIGHTS
from modulos._utilidades import HAS_PSUTIL, _powershell_exe, is_admin

from ui.theme import (COLORS, MONO_CSS, STATE_STYLE, ST_ALERT, ST_DEGRADED, ST_NOIMPL, ST_OK,
                      ST_STOPPED, badge_qss)
from ui.widgets import (BentoCard, Gauge, HealthBadge, Page, PulseGraph, ScoreRing, Worker, _emit_event,
                        frozen, icon, make_card, set_busy, tech_tip, with_icon)
from ui.chrome import Toast
from ui.informe import REPORTS_DIR, compute_security, export_report

if TYPE_CHECKING:  # solo para las anotaciones; en ejecución evita el import circular
    from gui_qt import MainWindow

# Piloto Automático: umbral de RAM, pausa mínima entre liberaciones y cadencia de la vigilancia
# (una sola lectura de psutil cada 5 s, también con el Centro de Comando oculto).
AP_RAM_THRESHOLD = 80
AP_RAM_COOLDOWN_S = 300
AP_RAM_POLL_MS = 5000

# Componente del panel de salud -> página a la que lleva su mini-botón de acceso (o None).
COMPONENT_PAGE = {
    "Motor de auditoría": "auditoria", "Telemetría de procesos": "monitor", "Honeypot": "honeypot",
    "Persistencia Táctica": "honeypot", "Caja Negra": "historial", "Endurecimiento de Red": "red",
    "Modo Fantasma (herramientas)": "arsenal", "Laboratorio Forense": "historial",
    "Núcleo de eventos (bus)": "historial", "OBSIDIAN (salud de telemetría)": "comando",
}


class ComponentCard(QFrame):
    """Tarjeta compacta de un componente para la rejilla Bento de 2 columnas (sustituye a la fila)."""

    def __init__(self, name: str, state: str, detail: str, on_open):
        super().__init__()
        self.setObjectName("CompCard")
        self.name = name
        self._state = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(3)
        top = QHBoxLayout()
        top.setSpacing(8)
        self.dot = QLabel("●")
        nm = QLabel(name)
        nm.setStyleSheet(f"color:{COLORS['text']}; font-size:12px; font-weight:600;")
        self.badge = QLabel()
        top.addWidget(self.dot)
        top.addWidget(nm)
        top.addStretch(1)
        top.addWidget(self.badge)
        key = COMPONENT_PAGE.get(name)
        if key and on_open is not None:
            go = QPushButton("→")
            go.setObjectName("CompGo")
            go.setFixedSize(22, 22)
            go.setCursor(Qt.CursorShape.PointingHandCursor)
            go.setToolTip(f"Ir a {name}")
            go.clicked.connect(lambda _=False, k=key: on_open(k))
            top.addWidget(go)
        lay.addLayout(top)
        self.detail = QLabel(detail)
        self.detail.setStyleSheet(f"color:{COLORS['text2']}; font-size:11px;")
        self.detail.setWordWrap(True)
        lay.addWidget(self.detail)
        self.set_state(state, detail)

    def set_state(self, state: str, detail: str) -> None:
        if detail != self.detail.text():
            self.detail.setText(detail)
        if state == self._state:
            return
        self._state = state
        color, label = STATE_STYLE.get(state, (COLORS["muted"], "—"))
        self.dot.setStyleSheet(f"color:{color}; font-size:10px;")
        self.badge.setText(label)
        self.badge.setStyleSheet(badge_qss(color, 9))


# Las 8 áreas previstas del producto. `key` = página existente a la que navega, o None si es el
# propio Cuartel General o un área aún no implementada (se marca «Pendiente», sin fingir que va).
AREAS = [
    ("fa5s.tachometer-alt", "Cuartel General", "Resumen de estado y telemetría del equipo.", None),
    ("fa5s.wave-square", "Centinela", "Monitor en vivo de red y procesos.", "monitor"),
    ("fa5s.shield-alt", "Taller Windows", "Auditoría y endurecimiento del sistema.", "auditoria"),
    ("fa5s.eye", "Defensa y engaño", "Honeypot y señuelos defensivos.", "honeypot"),
    ("fa5s.network-wired", "Perímetro y dispositivos", "Red (ICMP) y control de USB.", "red"),
    ("fa5s.fingerprint", "Laboratorio forense", "Snapshots e historial del sistema.", "historial"),
    ("fa5s.ghost", "Arsenal & Modo Fantasma", "Privacidad, anti-telemetría y limpieza.", "arsenal"),
    ("fa5s.vial", "Mesa de Autopsias", "Análisis estático de archivos sospechosos.", "historial"),
]


def collect_component_status(modules, plugin_errors, bus=None, blackbox=None,
                             honeypot=None, tactical_config=None, live=None):
    """
    Comprueba el estado REAL de los componentes de Lozarus en este equipo. Función pensada para
    ejecutarse en un hilo de fondo (hace algún os.stat); no toca la interfaz ni modifica nada.
    `live` es una instantánea barata tomada en el hilo de la UI (vigilancias activas, Vanguardia,
    último diagnóstico) para que esas filas muestren el estado VIVO; si falta una clave, la fila no
    la menciona (nunca se muestra un valor por defecto como si fuera real).
    Devuelve [(nombre, estado, detalle)]. Nunca inventa datos: lo que no existe se marca como tal.
    """
    live = live or {}
    rows = []

    # Privilegios
    if is_admin():
        rows.append(("Privilegios", ST_OK, "Administrador: auditoría y acciones completas"))
    else:
        rows.append(("Privilegios", ST_DEGRADED, "Usuario estándar: auditoría parcial · eleva con UAC"))

    # Motor de auditoría (plugins cargados + último diagnóstico de la sesión)
    n = len(modules)
    audit = live.get("last_audit")
    ultimo = (f" · último diagnóstico {audit[0]}/100 ({audit[1]} CRITICAL, {audit[2]} WARNING)"
              if audit else " · sin diagnóstico en esta sesión")
    if n == 0:
        rows.append(("Motor de auditoría", ST_STOPPED, "ningún plugin cargado"))
    elif plugin_errors:
        rows.append(("Motor de auditoría", ST_DEGRADED,
                     f"{n} plugins · {len(plugin_errors)} con error" + ultimo))
    else:
        rows.append(("Motor de auditoría", ST_OK, f"{n} plugins cargados" + ultimo))

    # Telemetría de procesos (psutil): recuento real de procesos ahora mismo
    if HAS_PSUTIL:
        try:
            rows.append(("Telemetría de procesos", ST_OK,
                         f"psutil · {len(psutil.pids())} procesos en el equipo ahora"))
        except Exception as exc:  # noqa: BLE001
            rows.append(("Telemetría de procesos", ST_DEGRADED, f"psutil con error: {exc}"))
    else:
        rows.append(("Telemetría de procesos", ST_STOPPED, "psutil no disponible"))

    # PowerShell (muchas comprobaciones dependen de él)
    ps = _powershell_exe()
    rows.append(("PowerShell", ST_OK if ps else ST_STOPPED,
                 f"disponible · {ps}" if ps else "no encontrado"))

    # Notificaciones de escritorio (Vanguardia)
    sentinel_on = bool(live.get("sentinel_on"))
    rows.append(("Notificaciones (Vanguardia)", ST_OK if HAS_PLYER else ST_DEGRADED,
                 ("plyer disponible · Vanguardia " + ("ACTIVA" if sentinel_on else "desactivada"))
                 if HAS_PLYER else "sin plyer: avisos nativos desactivados"))

    # Windows Sandbox (detonación aislada)
    ok_sb, _info = sandbox_available()
    rows.append(("Windows Sandbox", ST_OK if ok_sb else ST_STOPPED,
                 "disponible" if ok_sb else "no activado en este Windows"))

    # Cuarentena (estado actual real): activa = el equipo está aislado → ALERTA visible
    q_on = quarantine_active()
    rows.append(("Cuarentena", ST_ALERT if q_on else ST_OK,
                 "ACTIVA ahora: equipo aislado" if q_on else "en reposo (lista)"))

    # Honeypot: estado en vivo del motor de engaño (comprometido = ALERTA en rojo).
    if honeypot is not None:
        st = honeypot.status()
        if not st["active"]:
            rows.append(("Honeypot", ST_STOPPED, "red de trampas retirada (lista para desplegar)"))
        elif not st["integridad"]:
            rows.append(("Honeypot", ST_ALERT,
                         f"{st['comprometidos']} trampa(s) comprometida(s) · "
                         f"{st['incidentes']} incidente(s)"))
        else:
            rows.append(("Honeypot", ST_OK,
                         f"{st['total']} cebos activos · {st['incidentes']} incidente(s) · "
                         f"auto-reconstrucción {'ON' if st.get('auto_rebuild') else 'OFF'}"))
    else:
        rows.append(("Honeypot", ST_NOIMPL, "motor de engaño no disponible"))

    # Persistencia Táctica: configuración que sobrevive al reinicio.
    if tactical_config is not None:
        rows.append(("Persistencia Táctica", ST_OK,
                     f"{len(tactical_config.as_dict())} ajuste(s) guardado(s) · "
                     f"{os.path.basename(tactical_config.path)}"))
    else:
        rows.append(("Persistencia Táctica", ST_STOPPED, "no disponible"))

    # Colector ETW: el código existe y está probado, pero la GUI aún no abre ninguna sesión.
    has_etw = importlib.util.find_spec("etw") is not None
    rows.append(("Colector ETW", ST_STOPPED,
                 "código probado; la GUI no abre sesión"
                 + ("" if has_etw else " · pywintrace no instalado aquí")))

    # Núcleo de eventos (bus): operativo si la GUI lo ha arrancado; si no, solo probado.
    if bus is not None:
        try:
            m = bus.metrics()
            rows.append(("Núcleo de eventos (bus)", ST_OK,
                         f"en ejecución · {m.published} publicados, {m.delivered} entregados, "
                         f"{m.dropped} descartados"))
        except Exception:  # noqa: BLE001
            rows.append(("Núcleo de eventos (bus)", ST_STOPPED, "cargado, sin métricas disponibles"))
    else:
        try:
            importlib.import_module("core.bus")
            rows.append(("Núcleo de eventos (bus)", ST_STOPPED, "implementado y probado; integración pendiente"))
        except Exception:  # noqa: BLE001
            rows.append(("Núcleo de eventos (bus)", ST_STOPPED, "no cargado"))

    # Caja Negra: operativa si está persistiendo eventos; si no, no disponible en esta sesión.
    if blackbox is not None:
        mb = blackbox.metrics()
        detalle = f"{mb['written']} eventos persistidos en esta sesión (JSONL append-only)"
        if mb["dropped"] or mb["write_errors"]:
            detalle += f" · {mb['dropped']} descartados, {mb['write_errors']} errores de escritura"
        rows.append(("Caja Negra", ST_DEGRADED if mb["write_errors"] else ST_OK, detalle))
    else:
        rows.append(("Caja Negra", ST_NOIMPL, "persistencia de eventos no disponible en esta sesión"))

    # Endurecimiento de Red: herramientas + estado real de la vigilancia de puertos (si se conoce).
    detalle_red = "escáner de puertos, flushdns y lectura de Firewall/servicios"
    if "net_watch" in live:
        detalle_red += (f" · vigilancia de puertos ON ({live.get('net_watch_ports', 0)} en escucha "
                        "de referencia)" if live["net_watch"] else " · vigilancia de puertos OFF")
    if not HAS_PSUTIL:
        detalle_red += " · sin psutil: escáner limitado"
    if not is_admin():
        detalle_red += " · servicios/ICMP requieren Admin"
    rows.append(("Endurecimiento de Red", ST_OK if HAS_PSUTIL else ST_DEGRADED, detalle_red))

    # Modo Fantasma: herramientas + estado real de la vigilancia del portapapeles (si se conoce).
    detalle_fantasma = "trituradora, anti-clipper, optimizar RAM y limpieza de temporales"
    if "clip_watch" in live:
        detalle_fantasma += (" · portapapeles vigilado" if live["clip_watch"]
                             else " · portapapeles sin vigilar")
        if live.get("autopurge"):
            detalle_fantasma += " · auto-purga ON"
    rows.append(("Modo Fantasma (herramientas)", ST_OK, detalle_fantasma))

    # Laboratorio Forense: expedientes guardados en disco (dato real) + herramientas.
    try:
        snaps = len(list_snapshots())
    except Exception:  # noqa: BLE001
        snaps = 0
    rows.append(("Laboratorio Forense", ST_OK,
                 f"{snaps} snapshot(s) en disco · visor de la Caja Negra y mesa de autopsias"))

    # OBSIDIAN: salud de la PROPIA telemetría (ritmo del bus, tamaño del JSONL, CPU/RAM/hilos de Lozarus).
    obs = live.get("obsidian")
    if obs is not None:
        v = obs.get("vitals") or {}
        partes = []
        if obs.get("epm") is not None:
            partes.append(f"{obs['epm']:.0f} ev/min")
        if obs.get("jsonl_kb") is not None:
            partes.append(f"eventos.jsonl {obs['jsonl_kb']} KB")
        if v.get("rss_mb") is not None:
            partes.append(f"Lozarus {v['rss_mb']} MB")
        if v.get("cpu") is not None:
            partes.append(f"{v['cpu']}% CPU")
        if v.get("threads") is not None:
            partes.append(f"{v['threads']} hilos")
        rows.append(("OBSIDIAN (salud de telemetría)", ST_OK, " · ".join(partes) or "midiendo…"))
    else:
        rows.append(("OBSIDIAN (salud de telemetría)", ST_STOPPED, "sin datos de telemetría en esta sesión"))

    return rows


class ComponentRow(QFrame):
    """Fila de estado de un componente: punto de color + nombre + detalle + etiqueta de estado."""

    def __init__(self, name: str, state: str, detail: str):
        super().__init__()
        self.setObjectName("CompRow")
        self.name = name
        self._state: Optional[str] = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 7, 12, 7)
        lay.setSpacing(10)
        self.dot = QLabel("●")
        lay.addWidget(self.dot)
        nm = QLabel(name)
        nm.setStyleSheet(f"color:{COLORS['text']}; font-size:13px; font-weight:600;")
        nm.setMinimumWidth(190)
        lay.addWidget(nm)
        self.detail = QLabel(detail)
        self.detail.setStyleSheet(f"color:{COLORS['text2']}; font-size:11px;")
        self.detail.setWordWrap(True)
        lay.addWidget(self.detail, 1)
        self.badge = QLabel()
        lay.addWidget(self.badge)
        self.set_state(state, detail)

    def set_state(self, state: str, detail: str) -> None:
        """Actualiza la fila EN SU SITIO; solo re-aplica estilos si cambió el estado (no el detalle)."""
        if detail != self.detail.text():
            self.detail.setText(detail)
        if state == self._state:
            return
        self._state = state
        color, label = STATE_STYLE.get(state, (COLORS["muted"], "—"))
        self.dot.setStyleSheet(f"color:{color}; font-size:11px;")
        self.badge.setText(label)
        self.badge.setStyleSheet(badge_qss(color))


class CommandPage(Page):
    """Cuartel General: telemetría real (CPU/RAM), estado de componentes y accesos a las 8 áreas."""

    def __init__(self, app: "MainWindow"):
        super().__init__("Centro de Comando",
                         "Telemetría del sistema y acceso rápido a la defensa local.", "fa5s.tachometer-alt")
        self.app = app
        self._sec_last = None          # último estado pintado de la puntuación (evita re-estilizar cada tic)
        self._sec_target = "auditoria"  # página a la que lleva «Mejorar la nota»
        self.root.addWidget(self._build_security_card())

        # --- Cabecera de telemetría en vivo ---
        tele = QFrame()
        tele.setObjectName("Card")
        tlay = QHBoxLayout(tele)
        tlay.setContentsMargins(24, 20, 24, 20)
        tlay.setSpacing(20)
        self.cpu_gauge = Gauge(COLORS["accent"], size=116)
        self.ram_gauge = Gauge(COLORS["accent_2"], size=116)
        for gauge, caption in ((self.cpu_gauge, "CPU"), (self.ram_gauge, "MEMORIA")):
            col = QVBoxLayout()
            col.setSpacing(8)
            col.addWidget(gauge, 0, Qt.AlignmentFlag.AlignHCenter)
            lbl = QLabel(caption)
            lbl.setObjectName("ChipCap")
            lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            col.addWidget(lbl)
            tlay.addLayout(col)
        # Pulso en vivo (CPU/RAM/Red, últimos 60 s) + puntuación de salud del sistema
        pulsecol = QVBoxLayout()
        pulsecol.setSpacing(4)
        pcap = QLabel("PULSO · 60 s")
        pcap.setObjectName("ChipCap")
        self.pulse = PulseGraph()
        self.pulse_legend = QLabel("CPU — · RAM — · RED —")
        self.pulse_legend.setObjectName("Tiny")
        pulsecol.addWidget(pcap)
        pulsecol.addWidget(self.pulse, 1)
        pulsecol.addWidget(self.pulse_legend)
        tlay.addLayout(pulsecol, 1)
        self.health = HealthBadge()
        tlay.addWidget(self.health)
        # Escudo global
        shield = QVBoxLayout()
        shield.setSpacing(8)
        self.shield_icon = QLabel()
        self.shield_icon.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.shield_icon.setFixedHeight(76)
        self.shield_state = QLabel("")
        self.shield_state.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        lbl = QLabel("ESCUDO")
        lbl.setObjectName("ChipCap")
        lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        shield.addWidget(self.shield_icon)
        shield.addWidget(self.shield_state)
        shield.addWidget(lbl)
        tlay.addLayout(shield)
        # Info del equipo
        info = QVBoxLayout()
        info.setSpacing(6)
        info.addStretch(1)
        for label, value in self._system_rows():
            row = QHBoxLayout()
            k = QLabel(label)
            k.setObjectName("CardText")
            k.setFixedWidth(88)
            v = QLabel(value)
            v.setStyleSheet(f"color:{COLORS['text']}; font-family:{MONO_CSS}; font-size:12px;")
            row.addWidget(k)
            row.addWidget(v, 1)
            info.addLayout(row)
        info.addStretch(1)
        tlay.addLayout(info, 1)
        self.root.addWidget(tele)

        # --- Perfiles rápidos de operación (1 clic) ---
        prof_row = QHBoxLayout()
        prof_row.setSpacing(10)
        plabel = QLabel("PERFIL:")
        plabel.setObjectName("ChipCap")
        prof_row.addWidget(plabel)
        self.profile_btns = {}
        for key, text, tip in (
                ("equilibrado", "Equilibrado", "Sondeos a ritmo normal; sin tocar el equipo."),
                ("rendimiento", "Rendimiento / Baja latencia",
                 "Reduce la frecuencia de los sondeos y libera working sets de RAM una vez."),
                ("supervision", "Supervisión total",
                 "Activa todos los monitores disponibles: red, portapapeles y procesos.")):
            b = QPushButton(text)
            b.setObjectName("Toggle")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setToolTip(tip)
            b.clicked.connect(lambda _=False, k=key: self.app.apply_profile(k))
            self.profile_btns[key] = b
            prof_row.addWidget(b)
        self.profile_btns["equilibrado"].setChecked(True)
        prof_row.addStretch(1)
        self.root.addLayout(prof_row)

        # --- Piloto Automático ---
        self.root.addWidget(self._build_autopilot_card())

        # --- Aviso + relanzamiento con UAC (solo si NO somos Administrador) ---
        if not app.admin:
            uac_row = QHBoxLayout()
            uac_row.setSpacing(10)
            self.uac_btn = QPushButton("Relanzar como Administrador (UAC)")
            self.uac_btn.setObjectName("Warn")
            with_icon(self.uac_btn, "fa5s.user-shield", COLORS["beacon"])
            self.uac_btn.clicked.connect(self.app.relaunch_as_admin)
            aviso = QLabel("Sin privilegios: desactivar servicios y el ocultamiento ICMP requieren "
                           "elevación.")
            aviso.setObjectName("Tiny")
            aviso.setWordWrap(True)
            uac_row.addWidget(self.uac_btn)
            uac_row.addWidget(aviso, 1)
            self.root.addLayout(uac_row)

        # --- Panel de estado de componentes (comprobaciones reales, en segundo plano) ---
        comp_card = QFrame()
        comp_card.setObjectName("Card")
        cl = QVBoxLayout(comp_card)
        cl.setContentsMargins(18, 16, 18, 16)
        cl.setSpacing(8)
        ctitle = QLabel("Estado de los componentes de Lozarus")
        ctitle.setObjectName("CardTitle")
        csub = QLabel("Comprobaciones reales de este equipo. Lo que aún no tiene backend se marca como "
                      "detenido o no implementado, sin fingir que funciona.")
        csub.setObjectName("CardText")
        csub.setWordWrap(True)
        cl.addWidget(ctitle)
        cl.addWidget(csub)
        self.comp_grid = QGridLayout()
        self.comp_grid.setSpacing(8)
        self.comp_grid.setColumnStretch(0, 1)
        self.comp_grid.setColumnStretch(1, 1)
        cl.addLayout(self.comp_grid)
        self.comp_loading = QLabel("Comprobando componentes…")
        self.comp_loading.setObjectName("Tiny")
        cl.addWidget(self.comp_loading)
        self.root.addWidget(comp_card)
        self._comp_worker = None

        # --- Rejilla de accesos a las 8 áreas del producto ---
        areas_title = QLabel("Áreas de Lozarus")
        areas_title.setObjectName("CardTitle")
        areas_title.setStyleSheet("margin-top:4px;")
        self.root.addWidget(areas_title)
        grid = QGridLayout()
        grid.setSpacing(14)
        self.cards = []
        for index, (icon_name, title, desc, key) in enumerate(AREAS):
            card = BentoCard(icon_name, title, desc, self._area_status_fn(key, title),
                             (lambda k=key, t=title: self._open_area(k, t)))
            self.cards.append(card)
            grid.addWidget(card, index // 4, index % 4)
        self.root.addLayout(grid)
        self.root.addStretch(1)

        psutil.cpu_percent(interval=None)  # primer muestreo (devuelve 0; los siguientes miden el delta)
        try:
            self._net_io = psutil.net_io_counters()
        except Exception:  # noqa: BLE001
            self._net_io = None
        self._net_t = time.monotonic()
        self._shield_on: Optional[bool] = None   # último estado pintado del escudo
        self._obs_prev = None                     # muestra previa del contador del bus (OBSIDIAN)
        self._obs_prev_t = None
        self._ap_ram_last: Optional[float] = None  # último momento (monotonic) de una liberación automática
        self._comp_rows: list = []               # filas de componentes vivas (se actualizan en su sitio)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        # Los componentes cambian despacio: se recomprueban cada 8 s, en un hilo aparte.
        self._comp_timer = QTimer(self)
        self._comp_timer.setInterval(8000)
        self._comp_timer.timeout.connect(self._load_components)
        self._comp_timer.start()
        # Primer tic y primera carga de componentes diferidos a cuando arranca el bucle de eventos:
        # no bloquean la construcción (así el arranque se mantiene por debajo de 300 ms) y, para
        # entonces, self.app.pages ya existe y las tarjetas de área muestran su estado real.
        QTimer.singleShot(0, self._tick)
        QTimer.singleShot(0, self._load_components)

    # --- Áreas (navegación honesta: disponible vs. pendiente) ---------------------------------
    def _area_status_fn(self, key, title):
        # El estado se evalúa EN CADA LLAMADA (no al construir): self.app.pages todavía no existe
        # mientras se crea esta página, así que no se puede capturar aquí.
        def status():
            pages = getattr(self.app, "pages", {})
            if key is None and title == "Cuartel General":
                return (True, "Área actual")
            if key and key in pages:
                if key == "monitor":
                    running = bool(getattr(pages.get("monitor"), "running", False))
                    return (running, "En directo" if running else "Disponible")
                if key == "honeypot":
                    hp = getattr(self.app, "honeypot", None)
                    if hp is None or not hp.active:
                        return (False, "Disponible")
                    integ = hp.status()["integridad"]
                    return (integ, "Desplegado" if integ else "¡COMPROMETIDO!")
                if key == "historial":
                    return (False, f"{len(list_snapshots())} snapshots")
                if key == "red":
                    return (False, "Reversible · requiere admin")
                return (False, "Disponible")
            return (False, "Pendiente")  # área sin implementar todavía
        return status

    def _open_area(self, key, title):
        pages = getattr(self.app, "pages", {})
        if key and key in pages:
            self.app._select(key)
        elif key is None and title == "Cuartel General":
            return  # ya estás aquí
        else:
            self.app.console.log("!", f"Área «{title}»: aún no implementada en esta versión "
                                      "(prevista en el diseño del producto).")

    # --- Estado de componentes (hilo de fondo) ------------------------------------------------
    def showEvent(self, event) -> None:
        """Al volver a la página se refresca al instante (mientras está oculta no se repinta)."""
        super().showEvent(event)
        self._tick()
        self._load_components()

    def _load_components(self) -> None:
        if not self.isVisible() or getattr(self.app, "_closing", False):
            return  # página oculta o ventana cerrándose: no lanzar comprobaciones
        if self._comp_worker is not None and self._comp_worker.isRunning():
            return  # ya hay una comprobación en curso
        modules, errors = self.app.modules, self.app.plugin_errors
        bus, blackbox = getattr(self.app, "bus", None), getattr(self.app, "blackbox", None)
        hp, cfg = getattr(self.app, "honeypot", None), getattr(self.app, "tactical_config", None)
        live = self._live_snapshot()  # en el hilo de la UI: solo lee el estado de los widgets
        worker = Worker(lambda emit: collect_component_status(modules, errors, bus, blackbox, hp, cfg,
                                                              live=live))
        worker.done.connect(self._components_ready)
        self._comp_worker = worker
        worker.start()

    def _live_snapshot(self) -> dict:
        """
        Estado VIVO que el panel de salud no puede leer desde el hilo de fondo: vigilancias activas
        de las páginas, Vanguardia y el último diagnóstico. Lectura barata de widgets (hilo de la UI).
        Cada clave solo se incluye si su fuente existe; si no, la fila no la menciona.
        """
        pages = getattr(self.app, "pages", {})
        live: dict = {"sentinel_on": bool(getattr(self.app, "sentinel_on", False))}
        net = pages.get("red")
        if net is not None and hasattr(net, "_watch_timer"):
            live["net_watch"] = net._watch_timer.isActive()
            live["net_watch_ports"] = len(net._baseline or ())
        ghost = pages.get("arsenal")
        if ghost is not None and hasattr(ghost, "_clip_timer"):
            live["clip_watch"] = ghost._clip_timer.isActive()
            live["autopurge"] = ghost.autopurge_btn.isChecked()
        audit = pages.get("auditoria")
        if audit is not None and getattr(audit, "last_result", None) is not None:
            live["last_audit"] = audit.last_result
        # OBSIDIAN: salud de la propia telemetría (CPU/RAM/hilos del proceso, ritmo del bus, tamaño JSONL)
        obs = {"vitals": process_vitals()}
        bb = getattr(self.app, "blackbox", None)
        if bb is not None and getattr(bb, "path", None):
            obs["jsonl_kb"] = jsonl_size_kb(bb.path)
        bus = getattr(self.app, "bus", None)
        if bus is not None:
            try:
                cur = bus.metrics().published
            except Exception:  # noqa: BLE001
                cur = None
            if cur is not None:
                now = time.monotonic()
                obs["epm"] = events_per_minute(self._obs_prev, self._obs_prev_t, cur, now)
                self._obs_prev, self._obs_prev_t = cur, now
        live["obsidian"] = obs
        return live

    def _components_ready(self, ok: bool, rows) -> None:
        if not ok or not isinstance(rows, list):
            self.comp_loading.setText("No se pudo comprobar el estado de los componentes.")
            self.comp_loading.show()
            return
        self.comp_loading.hide()
        if [r.name for r in self._comp_rows] == [name for name, _s, _d in rows]:
            # Misma lista de componentes: actualizar en su sitio (sin destruir/recrear las tarjetas
            # cada 8 s, que provocaba un parpadeo del panel).
            for card, (_name, state, detail) in zip(self._comp_rows, rows):
                card.set_state(state, detail)
            return
        with frozen(self):
            while self.comp_grid.count():
                item = self.comp_grid.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            self._comp_rows = [ComponentCard(name, state, detail, self.app._select)
                               for name, state, detail in rows]
            for i, card in enumerate(self._comp_rows):   # rejilla de 2 columnas (sin scroll interno)
                self.comp_grid.addWidget(card, i // 2, i % 2)

    def _system_rows(self):
        try:
            user = getpass.getuser()
        except Exception:
            user = "?"
        return [("Equipo", socket.gethostname()), ("Usuario", user),
                ("Privilegios", "Administrador" if self.app.admin else "Estándar (parcial)"),
                ("Módulos", f"{len(self.app.modules)} plugins")]

    # --- Puntuación de Seguridad del Sistema ---------------------------------------------------
    def _build_security_card(self) -> QFrame:
        box = QFrame()
        box.setObjectName("Card")
        lay = QHBoxLayout(box)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(28)
        self.sec_ring = ScoreRing(150)
        lay.addWidget(self.sec_ring)
        col = QVBoxLayout()
        col.setSpacing(8)
        cap = QLabel("PUNTUACIÓN DE SEGURIDAD DEL SISTEMA")
        cap.setObjectName("ChipCap")
        self.sec_grade = QLabel("SIN DATOS")
        self.sec_grade.setStyleSheet(f"color:{COLORS['faint']}; font-size:20px; font-weight:bold; letter-spacing:1px;")
        col.addWidget(cap)
        col.addWidget(self.sec_grade)
        self.sec_bars = {}
        for key, label in LABELS.items():
            row = QHBoxLayout()
            row.setSpacing(12)
            name = QLabel(f"{label} · {WEIGHTS[key]:.0%}")
            name.setObjectName("CardText")
            name.setFixedWidth(230)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(False)
            val = QLabel("sin datos")
            val.setFixedWidth(76)
            val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            val.setStyleSheet(f"color:{COLORS['muted']}; font-family:{MONO_CSS}; font-size:12px;")
            row.addWidget(name)
            row.addWidget(bar, 1)
            row.addWidget(val)
            col.addLayout(row)
            self.sec_bars[key] = (bar, val)
        self.sec_next = QLabel("")
        self.sec_next.setObjectName("CardText")
        self.sec_next.setWordWrap(True)
        col.addWidget(self.sec_next)
        lay.addLayout(col, 1)
        actions = QVBoxLayout()
        actions.setSpacing(10)
        self.report_btn = QPushButton("Exportar Informe HTML")
        self.report_btn.setObjectName("Primary")
        self.report_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        with_icon(self.report_btn, "fa5s.file-export")
        self.report_btn.setToolTip(tech_tip("Informe de auditoría técnica (HTML)", [REPORTS_DIR],
                                            "Diseño oscuro autocontenido: puntuación, vectores mitigados, "
                                            "riesgos pendientes, Arsenal y puertos."))
        self.report_btn.clicked.connect(lambda: export_report(self.app))
        self.improve_btn = QPushButton("Mejorar la nota")
        self.improve_btn.setObjectName("Ghost")
        self.improve_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        with_icon(self.improve_btn, "fa5s.arrow-up", COLORS["muted"])
        self.improve_btn.clicked.connect(lambda: self.app._select(self._sec_target))
        actions.addStretch(1)
        actions.addWidget(self.report_btn)
        actions.addWidget(self.improve_btn)
        actions.addStretch(1)
        lay.addLayout(actions)
        return box

    def _update_security(self) -> None:
        """Recalcula la nota con el estado VIVO del Escaneo de Vectores y del Arsenal (lectura barata)."""
        result, step, inputs = compute_security(self.app)
        state = (result and (result["score"], tuple(sorted(result["parts"].items()))), step)
        if state == self._sec_last:
            return
        self._sec_last = state
        score = result["score"] if result else None
        self.sec_ring.set_score(score)
        color = ScoreRing.color_for(score)
        self.sec_grade.setText(f"{result['letter']} · {result['label']}" if result else "SIN DATOS")
        self.sec_grade.setStyleSheet(f"color:{color}; font-size:20px; font-weight:bold; letter-spacing:1px;")
        parts = result["parts"] if result else {}
        for key, (bar, val) in self.sec_bars.items():
            v = parts.get(key)
            bar.setValue(v or 0)
            c = ScoreRing.color_for(v)
            bar.setStyleSheet(f"QProgressBar::chunk {{ background:{c}; border-radius:3px; }}")
            val.setText("sin datos" if v is None else f"{v}/100")
            val.setStyleSheet(f"color:{c if v is not None else COLORS['muted']}; font-family:{MONO_CSS}; "
                              "font-size:12px;")
        self.sec_ring.setToolTip(tech_tip("Cómo se calcula", [f"{LABELS[k]}: {v}/100 × {WEIGHTS[k]:.0%}"
                                                              for k, v in parts.items()],
                                          "Media ponderada; lo que aún no se ha medido no cuenta y su peso "
                                          "se reparte entre el resto."))
        self.sec_next.setText(f"➜ {step}")
        self._sec_target = "auditoria" if "audit" not in parts or inputs["pending"] else "arsenal"

    def _tick(self) -> None:
        if not self.isVisible():
            return  # oculta tras otra pestaña: nada que pintar (se refresca en showEvent)
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        self.cpu_gauge.set_value(cpu)
        self.ram_gauge.set_value(ram)
        # Tráfico de red (KB/s) a partir del delta de contadores desde el tic anterior.
        now = time.monotonic()
        net_kbs = 0.0
        try:
            io = psutil.net_io_counters()
            delta_t = now - self._net_t
            if delta_t > 0 and self._net_io is not None:
                total = (io.bytes_sent + io.bytes_recv) - (self._net_io.bytes_sent + self._net_io.bytes_recv)
                net_kbs = max(0.0, total / 1024 / delta_t)
            self._net_io, self._net_t = io, now
        except Exception:  # noqa: BLE001
            pass
        self.pulse.push(cpu, ram, net_kbs)
        self.pulse_legend.setText(f"CPU {cpu:.0f}%  ·  RAM {ram:.0f}%  ·  RED {self.pulse.net_label()}")
        # Puntuación de salud global del sistema.
        audit = getattr(self.app.pages.get("auditoria"), "last_result", None)
        crit, warn = (audit[1], audit[2]) if audit else (0, 0)
        hp = getattr(self.app, "honeypot", None)
        hp_alert = bool(hp is not None and hp.active and not hp.status()["integridad"])
        write_errors = 0
        if self.app.blackbox is not None:
            try:
                write_errors = self.app.blackbox.metrics()["write_errors"]
            except Exception:  # noqa: BLE001
                write_errors = 0
        score, etiqueta = health_score(cpu, ram, critical=crit, warning=warn, honeypot_alert=hp_alert,
                                       bus_ok=self.app.bus is not None, write_errors=write_errors)
        self.health.set_score(score, etiqueta)
        # Escudo global: verde si hay alguna defensa activa (operaciones de lectura rápida, sin PowerShell)
        hp_on = bool(hp is not None and hp.active)
        protected = bool(quarantine_active() or hp_on or self.app.sentinel_on)
        if protected != self._shield_on:  # regenerar icono y estilo SOLO al cambiar de estado
            self._shield_on = protected
            color = COLORS["ok"] if protected else COLORS["muted"]
            self.shield_icon.setPixmap(icon("fa5s.shield-alt", color).pixmap(48, 48))
            self.shield_state.setText("ACTIVO" if protected else "EN REPOSO")
            self.shield_state.setStyleSheet(f"color:{color}; font-size:11px; font-weight:bold;")
        self._update_security()
        for bcard in self.cards:
            bcard.refresh()

    # --- Piloto Automático ---------------------------------------------------------------------
    def _build_autopilot_card(self) -> QFrame:
        box, lay = make_card("Piloto Automático",
                             "Automatizaciones que actúan solas en segundo plano, aunque estés en otra "
                             "sección de Lozarus.")
        tc = self.app.tactical_config
        body = QHBoxLayout()
        body.setSpacing(12)

        auto = QFrame()
        auto.setObjectName("Inset")
        al = QVBoxLayout(auto)
        al.setContentsMargins(14, 12, 14, 12)
        al.setSpacing(4)
        self._ap_ram_switch = self._switch(
            al, f"Auto-Optimizar RAM (>{AP_RAM_THRESHOLD}%)",
            "Si la memoria supera el umbral, libera los working sets de los procesos accesibles "
            f"(como mucho una vez cada {AP_RAM_COOLDOWN_S // 60} min).",
            bool(tc and tc.get("ap_autoram", False)), self._toggle_ap_ram)
        self._ap_defense_switch = self._switch(
            al, "Auto-Defensa al Iniciar",
            "Al abrir Lozarus despliega el Honeypot y activa la vigilancia de puertos.",
            bool(tc and tc.get("ap_autodefense", False)), self._toggle_ap_defense)
        self._ap_status = QLabel("")
        self._ap_status.setObjectName("Tiny")
        self._ap_status.setWordWrap(True)
        al.addWidget(self._ap_status)
        al.addStretch(1)
        body.addWidget(auto, 3)

        tune = QFrame()
        tune.setObjectName("Inset")
        tl = QVBoxLayout(tune)
        tl.setContentsMargins(14, 12, 14, 12)
        tl.setSpacing(8)
        ttl = QLabel("Puesta a Punto Inmediata")
        ttl.setObjectName("CardTitle")
        tdesc = QLabel("Vacía la caché DNS, purga los temporales que no estén en uso y libera RAM, "
                       "todo de una vez.")
        tdesc.setObjectName("CardText")
        tdesc.setWordWrap(True)
        self._maintenance_btn = QPushButton("Ejecutar Puesta a Punto")
        self._maintenance_btn.setObjectName("Primary")
        self._maintenance_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        with_icon(self._maintenance_btn, "fa5s.bolt", COLORS["accent_hover"])
        self._maintenance_btn.clicked.connect(self._quick_maintenance)
        self._maintenance_last = QLabel("Aún no se ha ejecutado en esta sesión.")
        self._maintenance_last.setObjectName("Tiny")
        self._maintenance_last.setWordWrap(True)
        for w in (ttl, tdesc):
            tl.addWidget(w)
        tl.addStretch(1)
        tl.addWidget(self._maintenance_btn, 0, Qt.AlignmentFlag.AlignLeft)
        tl.addWidget(self._maintenance_last)
        body.addWidget(tune, 2)
        lay.addLayout(body)

        self._ap_ram_busy = False
        self._ap_ram_now: Optional[float] = None   # última lectura de RAM del Piloto (%)
        self._ap_ram_result = ""   # «12:30 · 230 MB» de la última liberación automática
        self._ap_timer = QTimer(self)
        self._ap_timer.setInterval(AP_RAM_POLL_MS)
        self._ap_timer.timeout.connect(self._ap_ram_poll)
        if self._ap_ram_switch.isChecked():
            self._ap_timer.start()
        self._ap_update_status()
        return box

    @staticmethod
    def _switch(layout, text: str, hint: str, checked: bool, slot) -> QCheckBox:
        """Interruptor estilizado (QCheckBox#Switch del tema) con su explicación debajo."""
        sw = QCheckBox(text)
        sw.setObjectName("Switch")
        sw.setCursor(Qt.CursorShape.PointingHandCursor)
        sw.setChecked(checked)
        sw.toggled.connect(slot)  # conectado después de setChecked: construir no dispara la acción
        note = QLabel(hint)
        note.setObjectName("Tiny")
        note.setWordWrap(True)
        note.setContentsMargins(46, 0, 0, 6)  # alineado con el texto, no con el interruptor
        layout.addWidget(sw)
        layout.addWidget(note)
        return sw

    def _toggle_ap_ram(self, on: bool) -> None:
        if self.app.tactical_config:
            self.app.tactical_config.set("ap_autoram", on)
        self.app.console.log("~", f"Piloto Auto-RAM {'ACTIVADO' if on else 'desactivado'}")
        if on:
            self._ap_timer.start()
            self._ap_ram_poll()  # comprobación inmediata, sin esperar al primer intervalo
        else:
            self._ap_timer.stop()
            self._ap_update_status()

    def _toggle_ap_defense(self, on: bool) -> None:
        if self.app.tactical_config:
            self.app.tactical_config.set("ap_autodefense", on)
        self.app.console.log("~", f"Piloto Auto-Defensa al Iniciar {'ACTIVADO' if on else 'desactivado'}")

    def _ap_ram_poll(self) -> None:
        """Vigilancia del Piloto: lee la RAM y, por encima del umbral y fuera de la pausa, libera."""
        if getattr(self.app, "_closing", False) or self._ap_ram_busy:
            return
        try:
            ram = psutil.virtual_memory().percent
        except Exception:  # noqa: BLE001
            return
        now = time.monotonic()
        cooled = self._ap_ram_last is None or now - self._ap_ram_last > AP_RAM_COOLDOWN_S
        if ram > AP_RAM_THRESHOLD and cooled:
            self._ap_ram_last = now
            self._ap_ram_busy = True
            self.app.console.log("~", f"Piloto: RAM {ram:.0f}% > {AP_RAM_THRESHOLD}% → liberando working sets…")
            self.app.run_task(lambda emit: empty_working_sets(),
                              lambda ok, res, r=ram: self._ap_ram_done(ok, res, r), track=False)
        self._ap_ram_now = ram
        self._ap_update_status()

    def _ap_ram_done(self, ok: bool, res, ram: float) -> None:
        self._ap_ram_busy = False
        if ok and isinstance(res, dict) and res.get("ok"):
            mb = res.get("liberado_mb", 0)
            self._ap_ram_result = f"{dt.datetime.now():%H:%M} · {mb:.0f} MB"
            text = f"RAM al {ram:.0f}%: {mb:.0f} MB liberados de {res.get('procesos', 0)} procesos."
            kind = "*"
        else:
            text = f"No se pudo liberar RAM: {res.get('error') if isinstance(res, dict) else res}"
            kind = "x"
        self.app.console.log(kind, f"Piloto Auto-RAM: {text}")
        _emit_event(self.app, source="comando:piloto", event_type="autopilot.ram_release",
                    payload={"ram_percent": ram, "ok": kind == "*", "detail": text})
        Toast.notify(self.app, kind, "Piloto Automático", text, "fa5s.memory")
        self._ap_update_status()

    def _ap_update_status(self) -> None:
        if not self._ap_ram_switch.isChecked():
            text = "Vigilancia de RAM en pausa."
        else:
            ram = self._ap_ram_now
            now = f"RAM ahora {ram:.0f}% · " if ram is not None else ""
            last = f" · última liberación: {self._ap_ram_result}" if self._ap_ram_result else ""
            text = f"● Vigilando · {now}umbral {AP_RAM_THRESHOLD}%{last}"
        if text != self._ap_status.text():  # cada 5 s: solo repinta si cambió algo
            self._ap_status.setText(text)

    def _quick_maintenance(self) -> None:
        set_busy(self._maintenance_btn, True, "Ejecutando…")
        self.app.log_tactical("Puesta a Punto Inmediata: caché DNS + temporales + RAM")

        def step(fn):
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001  (un paso que falla no detiene los demás)
                return exc

        self.app.run_task(lambda emit: {"dns": step(flush_dns), "temp": step(clean_temp),
                                        "ram": step(empty_working_sets)}, self._maintenance_done)

    def _maintenance_done(self, ok: bool, res) -> None:
        set_busy(self._maintenance_btn, False)
        if not ok or not isinstance(res, dict):
            self.app.console.log("x", f"Puesta a Punto: {res}")
            Toast.notify(self.app, "x", "Puesta a Punto Inmediata", f"No se pudo completar: {res}",
                         "fa5s.bolt")
            return
        done, failed = [], []
        dns = res["dns"]  # flush_dns() -> (ok, mensaje)
        if isinstance(dns, tuple) and dns[0]:
            done.append("caché DNS vaciada")
        else:
            failed.append(f"DNS: {dns[1] if isinstance(dns, tuple) else dns}")
        temp = res["temp"]  # clean_temp() -> {ok, eliminados, omitidos, bytes, error}
        if isinstance(temp, dict) and temp.get("ok"):
            skipped = f", {temp['omitidos']} en uso omitidos" if temp.get("omitidos") else ""
            done.append(f"{temp.get('bytes', 0) / 1024 ** 2:.1f} MB de temporales "
                        f"({temp.get('eliminados', 0)} archivos{skipped})")
        else:
            failed.append(f"temporales: {temp.get('error') if isinstance(temp, dict) else temp}")
        ram = res["ram"]  # empty_working_sets() -> {ok, procesos, liberado_mb, error}
        if isinstance(ram, dict) and ram.get("ok"):
            done.append(f"{ram.get('liberado_mb', 0):.0f} MB de RAM liberados")
        else:
            failed.append(f"RAM: {ram.get('error') if isinstance(ram, dict) else ram}")
        kind = "*" if not failed else "!" if done else "x"
        text = (" · ".join(done) or "Ningún paso se completó.") + \
            (f"\nSin aplicar: {' · '.join(failed)}" if failed else "")
        self.app.console.log(kind, f"Puesta a Punto: {text}")
        _emit_event(self.app, source="comando:puesta_a_punto", event_type="system.maintenance",
                    payload={"done": done, "failed": failed})
        Toast.notify(self.app, kind, "Puesta a Punto Inmediata", text, "fa5s.bolt")
        estado = "completa" if not failed else "parcial" if done else "fallida"
        self._maintenance_last.setText(f"Última: {dt.datetime.now():%H:%M:%S} · {estado}.")
