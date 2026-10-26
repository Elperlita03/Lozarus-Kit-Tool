# -*- coding: utf-8 -*-
"""
Motor del Monitor en Vivo: instantáneas de conexiones de red y detección de
procesos sospechosos con psutil, en modo solo lectura. gui_qt.py lo ejecuta desde un
hilo aparte cada pocos segundos; aquí no hay nada de interfaz.

Criterios de alerta de procesos (umbrales ajustables al principio del fichero):
  · Suplantación: nombre de proceso del sistema (svchost.exe, lsass.exe...)
    ejecutándose fuera de C:\\Windows\\System32 / SysWOW64.
  · Ubicación: ejecutable en carpetas temporales, públicas, Papelera o Descargas.
  · Firma digital (Authenticode, verificada en segundo plano y cacheada): fichero
    modificado tras firmarse, sin firma, o sin firma y conectado a Internet.
  · Recursos: CPU alta sostenida, pico repentino de CPU, memoria elevada o
    crecimiento repentino de memoria. Estas alertas se mantienen visibles un rato
    (RESOURCE_HOLD) para que un pico breve no pase desapercibido.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ._base import CRITICAL, IS_WINDOWS, WARNING, CheckSkipped, CommandError, Severity
from ._utilidades import HAS_PSUTIL, powershell, ps_string_array, psutil

# --- Umbrales de alerta -------------------------------------------------------
CPU_SUSTAINED = 40.0             # % de la CPU total del equipo en dos muestras seguidas
CPU_SPIKE = 25.0                 # subida en puntos entre dos muestras ("pico repentino")
CPU_SPIKE_MIN = 30.0             # ...siempre que el valor nuevo supere este mínimo
RAM_FRACTION = 0.20              # un solo proceso usando más del 20 % de la RAM total
RAM_GROWTH = 500 * 1024 ** 2     # crecimiento de memoria entre dos muestras
RESOURCE_HOLD = 30.0             # segundos que sigue visible una alerta de recursos
SIGNATURE_BATCH = 40             # rutas por consulta de firmas a PowerShell

# Estados TCP con comunicación en curso (TIME_WAIT y LISTEN quedan fuera)
ACTIVE_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
                 "CLOSE_WAIT", "LAST_ACK", "CLOSING", "NONE"}

WINDIR = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
SYSTEM_DIRS = {WINDIR, os.path.join(WINDIR, "system32"), os.path.join(WINDIR, "syswow64")}
# Procesos del sistema que el malware suele imitar: solo deberían ejecutarse desde SYSTEM_DIRS
SYSTEM_BINARIES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
                   "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe",
                   "lsaiso.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "explorer.exe", "regsvr32.exe"}
# (fragmento de ruta en minúsculas, descripción, ¿grave si además no está firmado?)
SUSPICIOUS_LOCATIONS = [
    ("\\appdata\\local\\temp\\", "carpeta temporal del usuario", True),
    ("\\windows\\temp\\", "carpeta temporal de Windows", True),
    ("\\$recycle.bin\\", "Papelera de reciclaje", True),
    ("\\users\\public\\", "carpeta pública de usuarios", True),
    ("\\downloads\\", "carpeta Descargas", False),
]


# --- Contadores de CPU y memoria de todos los procesos en UNA llamada (Windows) ----------
# psutil consulta cada proceso por separado y, con los servicios del sistema, recurre a
# una ruta lenta que vuelve a enumerar todos los procesos (~8 ms por proceso). Una sola
# llamada a NtQuerySystemInformation, la misma que usa el Administrador de tareas,
# devuelve el tiempo de CPU y la memoria de todos en unos pocos milisegundos.
if IS_WINDOWS:
    import ctypes

    class _UnicodeString(ctypes.Structure):
        _fields_ = [("Length", ctypes.c_ushort), ("MaximumLength", ctypes.c_ushort), ("Buffer", ctypes.c_void_p)]

    class _SystemProcessInformation(ctypes.Structure):
        # Inicio de SYSTEM_PROCESS_INFORMATION (winternl.h); ctypes aplica la misma alineación que C
        _fields_ = [("NextEntryOffset", ctypes.c_ulong), ("NumberOfThreads", ctypes.c_ulong),
                    ("WorkingSetPrivateSize", ctypes.c_longlong), ("HardFaultCount", ctypes.c_ulong),
                    ("NumberOfThreadsHighWatermark", ctypes.c_ulong), ("CycleTime", ctypes.c_ulonglong),
                    ("CreateTime", ctypes.c_longlong), ("UserTime", ctypes.c_longlong),
                    ("KernelTime", ctypes.c_longlong), ("ImageName", _UnicodeString),
                    ("BasePriority", ctypes.c_long), ("UniqueProcessId", ctypes.c_void_p),
                    ("InheritedFromUniqueProcessId", ctypes.c_void_p), ("HandleCount", ctypes.c_ulong),
                    ("SessionId", ctypes.c_ulong), ("UniqueProcessKey", ctypes.c_size_t),
                    ("PeakVirtualSize", ctypes.c_size_t), ("VirtualSize", ctypes.c_size_t),
                    ("PageFaultCount", ctypes.c_ulong), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t)]

    _ntdll = ctypes.WinDLL("ntdll")
    _ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                                ctypes.POINTER(ctypes.c_ulong)]
    _ntdll.NtQuerySystemInformation.restype = ctypes.c_long


def process_counters() -> Optional[Dict[int, Tuple[int, int, int]]]:
    """pid -> (tiempo de CPU acumulado en unidades de 100 ns, memoria residente en bytes,
    instante de creación). None si no está disponible (otros sistemas o fallo): se usa psutil."""
    if not IS_WINDOWS:
        return None
    size = 1024 * 1024
    for _ in range(5):
        buffer = ctypes.create_string_buffer(size)
        needed = ctypes.c_ulong(0)
        status = _ntdll.NtQuerySystemInformation(5, buffer, size, ctypes.byref(needed)) & 0xFFFFFFFF
        if status == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH: el búfer se quedó corto
            size = max(size * 2, needed.value + 256 * 1024)
            continue
        if status != 0:
            return None
        counters: Dict[int, Tuple[int, int, int]] = {}
        offset = 0
        while True:
            entry = _SystemProcessInformation.from_buffer(buffer, offset)
            counters[entry.UniqueProcessId or 0] = (entry.UserTime + entry.KernelTime, entry.WorkingSetSize,
                                                    entry.CreateTime)
            if not entry.NextEntryOffset:
                return counters
            offset += entry.NextEntryOffset
    return None


@dataclass
class Connection:
    key: str
    proto: str
    pid: int
    name: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    scope: str           # "Internet", "LAN" o "Local"


@dataclass
class ProcessAlert:
    pid: int
    name: str
    severity: Severity
    reasons: List[str]
    cpu: float           # % de la CPU total del equipo
    rss: int             # memoria residente en bytes
    path: str
    signature: str       # descripción del estado de la firma
    created: float = 0   # instante de creación: junto al PID identifica al proceso (anti-spam)


@dataclass
class Snapshot:
    taken: dt.datetime
    sample_ms: float                       # lo que tardó en recogerse la muestra
    self_cpu: float                        # CPU que consume el propio programa
    connections: List[Connection]
    alerts: List[ProcessAlert]
    total_processes: int
    hidden_paths: int                      # procesos cuya ruta no se pudo leer (sin privilegios)
    paths: Dict[int, str] = field(default_factory=dict)     # pid -> ruta del ejecutable
    signatures_pending: int = 0


def scope_of(ip: str) -> str:
    """Clasifica un destino: Internet (IP pública), LAN (privada) o Local (loopback)."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "LAN"
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_unspecified:
        return "Local"
    return "Internet" if addr.is_global else "LAN"


def assess_process(name: str, path: str, cpu: float, cpu_prev: Optional[float], rss: int,
                   rss_prev: Optional[int], total_ram: int, signature: Optional[str],
                   internet: bool) -> Tuple[List[Tuple[Severity, str, bool]], Optional[Severity]]:
    """
    Aplica los criterios de alerta a un proceso. Función pura (fácil de probar).
    Devuelve [(severidad, motivo, es_de_recursos)] y la severidad más alta (o None).
    `signature` es el estado Authenticode ('Valid', 'NotSigned'...) o None si aún no se conoce.
    """
    found: List[Tuple[Severity, str, bool]] = []
    low_path, low_name = os.path.normcase(path or ""), (name or "").lower()

    if path and low_name in SYSTEM_BINARIES and os.path.dirname(low_path) not in SYSTEM_DIRS:
        found.append((CRITICAL, f"suplanta un proceso del sistema ({name} fuera de System32)", False))

    for fragment, where, serious in SUSPICIOUS_LOCATIONS:
        if fragment in low_path:
            grave = serious and signature not in (None, "Valid", "Windows")
            found.append((CRITICAL if grave else WARNING, f"se ejecuta desde la {where}", False))
            break

    if signature == "HashMismatch":
        found.append((CRITICAL, "firma digital inválida: el fichero se modificó tras firmarse", False))
    elif signature == "NotSigned":
        found.append((CRITICAL, "sin firma digital y conectado a Internet", False) if internet
                     else (WARNING, "ejecutable sin firma digital", False))
    elif signature in ("NotTrusted", "UnknownError"):
        found.append((WARNING, f"firma digital no confiable ({signature})", False))

    if cpu_prev is not None:
        if cpu >= CPU_SUSTAINED and cpu_prev >= CPU_SUSTAINED:
            found.append((WARNING, f"CPU alta sostenida ({cpu:.0f} %)", True))
        elif cpu - cpu_prev >= CPU_SPIKE and cpu >= CPU_SPIKE_MIN:
            found.append((WARNING, f"pico repentino de CPU ({cpu_prev:.0f} → {cpu:.0f} %)", True))
    if total_ram and rss >= RAM_FRACTION * total_ram:
        found.append((WARNING, f"memoria elevada ({rss / 1024 ** 3:.1f} GB, {100 * rss / total_ram:.0f} % de la RAM)",
                      True))
    if rss_prev is not None and rss - rss_prev >= RAM_GROWTH:
        found.append((WARNING, f"crecimiento repentino de memoria (+{(rss - rss_prev) / 1024 ** 2:.0f} MB)", True))

    worst = CRITICAL if any(s is CRITICAL for s, _, _ in found) else WARNING if found else None
    return found, worst


def describe_signature(status: Optional[str], signer: str) -> str:
    if status is None:
        return "verificando…"
    labels = {"Valid": "válida", "Windows": "binario de Windows (protegido por el sistema)",
              "NotSigned": "sin firma", "HashMismatch": "INVÁLIDA (fichero modificado)",
              "NotTrusted": "no confiable", "UnknownError": "error de verificación",
              "NotSupportedFileFormat": "formato sin firma", "": "desconocida", "Error": "no verificable"}
    text = labels.get(status, status)
    return f"{text} · {signer}" if signer else text


class LiveMonitor:
    """
    Recoge instantáneas del sistema. sample() se llama desde un hilo de muestreo (uno a la
    vez); la verificación de firmas corre en otro hilo y solo procesa rutas nuevas, de modo
    que cada muestra cuesta unas decenas de milisegundos.
    """

    def __init__(self):
        if not HAS_PSUTIL:
            raise CheckSkipped("El Monitor en Vivo necesita psutil:  pip install psutil")
        self.cpu_count = psutil.cpu_count() or 1
        self.total_ram = psutil.virtual_memory().total
        self.me = psutil.Process()
        self.me.cpu_percent(None)
        self.previous: Dict[int, Tuple[float, float, int, int]] = {}  # pid -> (create_time, cpu, rss, tiempo CPU)
        self.last_sample = 0.0
        # alertas de recursos recientes: (pid, create_time) -> {tipo: (momento, severidad, motivo)}
        self.held: Dict[Tuple[int, float], Dict[str, Tuple[float, Severity, str]]] = {}
        self.signatures: Dict[str, Tuple[str, str]] = {}  # ruta -> (estado, firmante)
        self._sig_mtime: Dict[str, float] = {}            # ruta -> mtime cuando se verificó (caducidad)
        self.pending: Set[str] = set()
        self.lock = threading.Lock()
        self.verifier: Optional[threading.Thread] = None

    # --- Firmas digitales (en segundo plano) ------------------------------------------
    def _needs_signature(self, path: str) -> bool:
        low = os.path.normcase(path)
        # Los binarios de Windows están protegidos por el sistema (salvo su carpeta temporal)
        return IS_WINDOWS and bool(path) and (not low.startswith(WINDIR + "\\") or "\\temp\\" in low)

    @staticmethod
    def _mtime(path: str) -> float:
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0.0

    def _request_signatures(self, paths: Iterable[str]) -> None:
        # Una ruta se (re)verifica si no está cacheada o si su mtime cambió desde la última
        # verificación: así un fichero sustituido durante la sesión no conserva una firma obsoleta.
        current = {p: self._mtime(p) for p in paths}
        with self.lock:
            new = set()
            for p, mt in current.items():
                if p in self.pending:
                    continue
                if p not in self.signatures or self._sig_mtime.get(p) != mt:
                    self.signatures.pop(p, None)   # firma obsoleta: se mostrará «verificando…»
                    self._sig_mtime.pop(p, None)
                    new.add(p)
            self.pending |= new
            start = bool(self.pending) and (self.verifier is None or not self.verifier.is_alive())
        if start:
            self.verifier = threading.Thread(target=self._verify_pending, daemon=True, name="firmas")
            self.verifier.start()

    def _verify_pending(self) -> None:
        while True:
            with self.lock:
                batch = sorted(self.pending)[:SIGNATURE_BATCH]
            if not batch:
                return
            script = (
                "$out = foreach ($p in " + ps_string_array(batch) + ") {\n"
                "  $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue\n"
                "  $who = ''\n"
                "  if ($s -and $s.SignerCertificate) { $who = $s.SignerCertificate.GetNameInfo("
                "[System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }\n"
                "  @{ p = $p; s = $(if ($s) { [string]$s.Status } else { '' }); who = $who }\n"
                "}\nOut-Json @($out)\n")
            try:
                results = {r["p"]: (r.get("s") or "", r.get("who") or "")
                           for r in (powershell(script, timeout=120) or []) if isinstance(r, dict)}
            except (CommandError, CheckSkipped):
                results = {}
            with self.lock:
                for path in batch:
                    self.signatures[path] = results.get(path, ("Error", ""))
                    self._sig_mtime[path] = self._mtime(path)
                    self.pending.discard(path)

    # --- Muestra ------------------------------------------------------------------------
    def sample(self) -> Snapshot:
        started = time.perf_counter()
        now = time.time()
        counters = process_counters()  # CPU y memoria de todos los procesos en una llamada (Windows)
        elapsed = started - self.last_sample if self.last_sample else 0.0
        self.last_sample = started
        # Con los contadores nativos, psutil solo aporta nombre y ruta: su create_time recorre
        # la misma ruta lenta (~400 ms en la primera muestra) y aquí ya viene en los contadores
        attrs = ["pid", "name", "exe"] + ([] if counters is not None
                                          else ["create_time", "cpu_percent", "memory_info"])
        procs: Dict[int, dict] = {}
        hidden = 0
        for proc in psutil.process_iter(attrs, ad_value=None):
            info = proc.info
            if info["pid"] == 0:
                continue  # "System Idle Process"
            if not info["exe"]:
                hidden += 1
            procs[info["pid"]] = info

        connections: List[Connection] = []
        internet_pids: Set[int] = set()
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr or conn.status not in ACTIVE_STATES:
                continue
            pid = conn.pid or 0
            scope = scope_of(conn.raddr.ip)
            if scope == "Internet":
                internet_pids.add(pid)
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            name = (procs.get(pid) or {}).get("name") or ("System" if pid == 4 else "—")
            key = f"{proto}|{conn.laddr.ip}|{conn.laddr.port}|{conn.raddr.ip}|{conn.raddr.port}|{pid}"
            connections.append(Connection(key, proto, pid, name, conn.laddr.ip, conn.laddr.port,
                                          conn.raddr.ip, conn.raddr.port,
                                          "UDP" if conn.status == "NONE" else conn.status, scope))
        connections.sort(key=lambda c: (c.name.lower(), c.pid, c.remote_ip, c.remote_port, c.local_port))

        self._request_signatures(info["exe"] for info in procs.values()
                                 if info["exe"] and self._needs_signature(info["exe"]))
        with self.lock:
            signatures = dict(self.signatures)
            pending = len(self.pending)

        alerts: List[ProcessAlert] = []
        current: Dict[int, Tuple[float, float, int, int]] = {}
        for pid, info in procs.items():
            if counters is not None:
                cpu_time, rss, created = counters.get(pid, (0, 0, 0))
            else:
                created = info["create_time"] or 0.0
            prev = self.previous.get(pid)
            same = prev is not None and prev[0] == created  # mismo proceso (el PID no se ha reutilizado)
            if counters is not None:
                # % de la CPU total del equipo = tiempo de CPU consumido / tiempo real / nº de núcleos
                cpu = (100 * (cpu_time - prev[3]) / 1e7 / elapsed / self.cpu_count
                       if same and elapsed > 0 else 0.0)
                cpu = max(0.0, min(100.0, cpu))
            else:
                cpu_time = 0
                cpu = (info["cpu_percent"] or 0.0) / self.cpu_count
                rss = info["memory_info"].rss if info["memory_info"] else 0
            current[pid] = (created, cpu, rss, cpu_time)
            path = info["exe"] or ""
            status, signer = (signatures.get(path, (None, "")) if self._needs_signature(path)
                              else ("Windows", ""))
            found, _ = assess_process(info["name"] or "?", path, cpu, prev[1] if same else None, rss,
                                      prev[2] if same else None, self.total_ram, status, pid in internet_pids)

            # Las alertas de recursos se mantienen RESOURCE_HOLD segundos tras dispararse
            held = self.held.setdefault((pid, created), {})
            for severity, reason, resource in found:
                if resource:
                    held[reason.split(" (")[0]] = (now, severity, reason)
            persistent = [(s, r) for s, r, resource in found if not resource]
            recent = [(sev, reason if now - when < 1 else f"{reason}, hace {now - when:.0f} s")
                      for when, sev, reason in held.values() if now - when <= RESOURCE_HOLD]
            reasons = persistent + recent
            if not reasons:
                continue
            worst = CRITICAL if any(s is CRITICAL for s, _ in reasons) else WARNING
            alerts.append(ProcessAlert(pid, info["name"] or "?", worst, [r for _, r in reasons], cpu, rss, path,
                                       describe_signature(status, signer) if path else "ruta no accesible",
                                       created))
        self.previous = current
        live = {(pid, c[0]) for pid, c in current.items()}
        self.held = {k: v for k, v in self.held.items() if k in live and v}
        alerts.sort(key=lambda a: (a.severity is not CRITICAL, -a.cpu, a.name.lower()))

        return Snapshot(dt.datetime.now(), (time.perf_counter() - started) * 1000,
                        self.me.cpu_percent(None) / self.cpu_count, connections, alerts, len(procs), hidden,
                        {pid: info["exe"] or "" for pid, info in procs.items()}, pending)
