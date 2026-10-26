# -*- coding: utf-8 -*-
"""
Endurecimiento de red (herramientas base, estilo «debloat/privacidad») para Lozarus. Todo LOCAL
sobre el equipo propio y, salvo que se indique, SIN privilegios:

  · enumerar puertos en escucha (LISTEN) y conexiones activas (ESTABLISHED),
  · purgar la caché del solucionador DNS (ipconfig /flushdns),
  · leer el estado del Firewall de Windows por perfil,
  · leer el estado de servicios sensibles (telemetría / superficie de ataque).

Desactivar o restaurar un servicio SÍ exige Administrador: cuando no se tiene, se informa con
honestidad y NO se intenta nada (no se inventa un éxito). Este módulo solo observa el equipo propio
y, a petición de la persona, cambia su configuración local; no ataca ni toca equipos de terceros.

Funciones aisladas de Qt para poder probarlas sin interfaz.
"""

import json
import os
import socket
import subprocess
import sys
from collections import namedtuple

try:
    import psutil
    HAS_PSUTIL = True
except Exception:  # noqa: BLE001
    psutil = None
    HAS_PSUTIL = False

from modulos._utilidades import _powershell_exe, is_admin

# Evita que parpadee una ventana de consola al lanzar subprocess en Windows.
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

# Fila de conexión normalizada (lo que la tabla de la GUI muestra).
Conn = namedtuple("Conn", "proto local_ip local_port remote_ip remote_port status pid proceso")

# Servicios sensibles habituales. Desactivarlos es ENDURECIMIENTO (reduce telemetría o superficie de
# ataque), no desactivar una protección. Reversible con restore_service.
SERVICIOS_SENSIBLES = [
    ("DiagTrack", "Telemetría de Windows (Experiencias del usuario conectado)"),
    ("RemoteRegistry", "Registro remoto (superficie de ataque; suele venir desactivado)"),
    ("LanmanServer", "Servidor: compartir archivos e impresoras por SMB"),
]

# Arranque «por defecto» orientativo de Windows, para el botón Restaurar.
_DEFAULT_START = {"DiagTrack": "auto", "RemoteRegistry": "disabled", "LanmanServer": "auto"}
_SC_MODE = {"auto": "auto", "demand": "demand", "disabled": "disabled"}


# ---------------------------------------------------------------------------------------------
# Enumeración de puertos y conexiones (solo lectura)
# ---------------------------------------------------------------------------------------------
def _proto_name(fam, kind) -> str:
    base = "TCP" if kind == socket.SOCK_STREAM else ("UDP" if kind == socket.SOCK_DGRAM else "?")
    return base + ("6" if fam == socket.AF_INET6 else "")


def scan_connections():
    """
    Enumera las conexiones IP del equipo (LISTEN, ESTABLISHED y demás). Devuelve List[Conn].
    Sin privilegios puede faltar el PID o el nombre de algún proceso ajeno: se marca '—', nunca se
    inventa un dato. Lanza RuntimeError si psutil no está disponible.
    """
    if not HAS_PSUTIL:
        raise RuntimeError("psutil no disponible: no se pueden enumerar conexiones")
    name_cache = {}

    def _name(pid):
        if not pid:
            return "—"
        if pid in name_cache:
            return name_cache[pid]
        try:
            nombre = psutil.Process(pid).name()
        except Exception:  # noqa: BLE001  (proceso ajeno sin permisos o ya terminado)
            nombre = "—"
        name_cache[pid] = nombre
        return nombre

    rows = []
    for c in psutil.net_connections(kind="inet"):
        laddr = c.laddr if c.laddr else None
        raddr = c.raddr if c.raddr else None
        rows.append(Conn(
            proto=_proto_name(c.family, c.type),
            local_ip=laddr.ip if laddr else "—",
            local_port=laddr.port if laddr else 0,
            remote_ip=raddr.ip if raddr else "—",
            remote_port=raddr.port if raddr else 0,
            status=c.status or "—",
            pid=c.pid,
            proceso=_name(c.pid),
        ))
    return rows


def listening_keys(conns):
    """Conjunto de puertos en escucha, como 'TCP:0.0.0.0:445'. Base para vigilar puertos nuevos.
    Función pura: recibe la lista de Conn y no toca el sistema."""
    return {f"{c.proto}:{c.local_ip}:{c.local_port}" for c in conns if c.status == "LISTEN"}


def split_connections(conns):
    """Separa (en_escucha, activas) a partir de una lista de Conn. Pura."""
    escucha = [c for c in conns if c.status == "LISTEN"]
    activas = [c for c in conns if c.status == "ESTABLISHED"]
    return escucha, activas


# ---------------------------------------------------------------------------------------------
# Caché DNS (sin admin)
# ---------------------------------------------------------------------------------------------
def flush_dns():
    """Ejecuta `ipconfig /flushdns`. No requiere Administrador. Devuelve (ok, mensaje)."""
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ipconfig.exe")
    if not os.path.isfile(exe):
        exe = "ipconfig"
    try:
        proc = subprocess.run([exe, "/flushdns"], capture_output=True, text=True,
                              timeout=25, creationflags=_NO_WINDOW)
    except Exception as exc:  # noqa: BLE001
        return False, f"No se pudo ejecutar ipconfig: {exc}"
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    low = out.lower()
    ok = proc.returncode == 0 and any(s in low for s in ("vaciad", "vació", "flushed", "successfully"))
    if ok:
        return True, "Caché del solucionador DNS vaciada correctamente."
    return False, out or "ipconfig devolvió un estado inesperado."


# ---------------------------------------------------------------------------------------------
# Firewall (lectura, sin admin)
# ---------------------------------------------------------------------------------------------
def firewall_status():
    """
    Lee si el Firewall de Windows está activado por perfil (Domain/Private/Public). Sin admin.
    Usa Get-NetFirewallProfile (Enabled es booleano, independiente del idioma). Devuelve
    (ok, {perfil: bool}, mensaje). ok=False si no se pudo determinar (no se finge un estado).
    """
    ps = _powershell_exe()
    if not ps:
        return False, {}, "PowerShell no disponible"
    cmd = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    try:
        proc = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
                              capture_output=True, text=True, timeout=30, creationflags=_NO_WINDOW)
    except Exception as exc:  # noqa: BLE001
        return False, {}, f"No se pudo consultar el Firewall: {exc}"
    try:
        data = json.loads(proc.stdout or "")
    except Exception:  # noqa: BLE001
        return False, {}, (proc.stdout or proc.stderr or "salida no reconocida").strip()
    if isinstance(data, dict):
        data = [data]
    estado = {str(item.get("Name")): bool(item.get("Enabled")) for item in data if isinstance(item, dict)}
    return (bool(estado), estado, "" if estado else "sin datos de perfiles")


# ---------------------------------------------------------------------------------------------
# Servicios (lectura sin admin; cambio con admin)
# ---------------------------------------------------------------------------------------------
def service_status(name):
    """
    Estado de un servicio de Windows (sin admin). Devuelve dict con: name, exists, display, status
    ('running'/'stopped'/…), start_type ('automatic'/'manual'/'disabled'/…). Nunca lanza.
    """
    base = {"name": name, "exists": False, "display": name, "status": "?", "start_type": "?", "error": ""}
    if not HAS_PSUTIL or not hasattr(psutil, "win_service_get"):
        base["error"] = "psutil/servicios no disponible en esta plataforma"
        return base
    try:
        info = psutil.win_service_get(name).as_dict()
        base.update(exists=True, display=info.get("display_name") or name,
                    status=info.get("status") or "?", start_type=info.get("start_type") or "?")
    except Exception as exc:  # noqa: BLE001  (no existe el servicio, etc.)
        base["error"] = f"{type(exc).__name__}: {exc}"
    return base


def services_overview():
    """Estado de los SERVICIOS_SENSIBLES. Lista de dicts (ver service_status) con 'motivo'."""
    out = []
    for name, motivo in SERVICIOS_SENSIBLES:
        info = service_status(name)
        info["motivo"] = motivo
        out.append(info)
    return out


def _run_sc(args):
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "sc.exe")
    if not os.path.isfile(exe):
        exe = "sc"
    proc = subprocess.run([exe] + list(args), capture_output=True, text=True,
                          timeout=30, creationflags=_NO_WINDOW)
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def set_service_startup(name, mode):
    """
    Cambia el arranque de un servicio (`mode`: auto|demand|disabled) y, al desactivarlo, lo detiene.
    REQUIERE Administrador: si no se tiene, devuelve (False, True, mensaje) y NO intenta nada. Con
    privilegios devuelve (ok, False, mensaje). Nunca lanza.
    """
    if mode not in _SC_MODE:
        return False, False, f"Modo de arranque no válido: {mode}"
    if not is_admin():
        return False, True, ("Requiere Administrador. Reinicia Lozarus como administrador para "
                             "cambiar servicios del sistema.")
    try:
        mensajes = []
        if mode == "disabled":
            _rc, out = _run_sc(["stop", name])
            if out:
                mensajes.append(out)
        rc, out = _run_sc(["config", name, "start=", _SC_MODE[mode]])
        if out:
            mensajes.append(out)
        if rc == 0:
            return True, False, f"Servicio «{name}» configurado como «{mode}»."
        return False, False, "\n".join(mensajes) or f"sc devolvió el código {rc}."
    except Exception as exc:  # noqa: BLE001
        return False, False, f"No se pudo cambiar el servicio: {exc}"


def disable_service(name):
    """Desactiva (start=disabled) y detiene un servicio. Requiere admin. (ok, requiere_admin, msg)."""
    return set_service_startup(name, "disabled")


def restore_service(name):
    """Restaura el arranque por defecto orientativo del servicio. Requiere admin."""
    return set_service_startup(name, _DEFAULT_START.get(name, "demand"))
