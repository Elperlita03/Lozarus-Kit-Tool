"""
modulos/_guardia.py · LOZARUS KIT TOOL

Motor de la GUARDIA EN VIVO: vigila la persistencia de arranque (claves Run/RunOnce y carpetas
Inicio) y los puertos TCP en escucha, y compara cada pasada con una REFERENCIA guardada en disco
(guardia_referencia.json), de modo que lo que apareció mientras Lozarus estaba cerrado también se
detecta. Aquí no hay interfaz: ui/page_guard.py lo ejecuta en segundo plano.

Acciones reales sobre un elemento detectado:
  · evidence(): ficha forense (comando, ruta, SHA-256, tamaño, fechas) para la Caja Negra.
  · block(): Run → copia el valor y lo BORRA del registro (winreg); carpeta Inicio → MUEVE el fichero
    a una carpeta de cuarentena (reversible); puerto → regla de entrada de bloqueo en el Firewall
    (netsh advfirewall, sin shell).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import socket
import subprocess
from typing import Dict, Iterable, List, Optional, Set

from ._arsenal import delete_value, read_value
from ._forense import FORENSICS_DIR
from ._inicio import read_run_keys, read_startup_folders
from ._utilidades import HAS_PSUTIL, psutil, run_cmd

BASELINE_FILE = os.path.join(FORENSICS_DIR, "guardia_referencia.json")
QUARANTINE_DIR = os.path.join(FORENSICS_DIR, "Cuarentena_Inicio")
HASH_LIMIT = 256 * 1024 * 1024  # no se calcula el SHA-256 de ficheros mayores (la pasada debe ser ligera)
KIND_LABEL = {"run": "ARRANQUE (Run)", "folder": "CARPETA INICIO", "port": "PUERTO EN ESCUCHA"}


# --- Instantánea ---------------------------------------------------------------------------------
def listening() -> Dict[str, dict]:
    """Puertos TCP en escucha por (protocolo, puerto, proceso): la IP no forma parte de la clave para
    que un mismo servicio en 0.0.0.0 y :: no cuente dos veces."""
    if not HAS_PSUTIL:
        return {}
    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.Error, OSError):
        return {}
    names: Dict[Optional[int], str] = {}
    out: Dict[str, dict] = {}
    for c in conns:
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        if c.pid not in names:
            try:
                names[c.pid] = psutil.Process(c.pid).name() if c.pid else "—"
            except (psutil.Error, OSError):
                names[c.pid] = "—"
        name = names[c.pid]
        key = f"port|TCP:{c.laddr.port}|{name.lower()}"
        out.setdefault(key, {"kind": "port", "label": "Puerto en escucha", "location": f"{c.laddr.ip}:{c.laddr.port}",
                             "name": name, "command": f"PID {c.pid}" if c.pid else "PID desconocido",
                             "path": "", "pid": c.pid, "port": c.laddr.port, "proto": "TCP"})
    return out


def snapshot() -> Dict[str, dict]:
    """Elementos vigilados ahora mismo: {clave estable: ficha}. Solo lectura."""
    items: Dict[str, dict] = {}
    for kind, entries in (("run", read_run_keys()), ("folder", read_startup_folders())):
        for e in entries:
            items[f"{kind}|{e['ubicacion']}|{e['nombre']}".lower()] = {
                "kind": kind, "label": e["origen"], "location": e["ubicacion"], "name": e["nombre"],
                "command": e["comando"], "path": e["ruta"], "exists": e["existe"]}
    items.update(listening())
    return items


def new_items(baseline: Iterable[str], current: Dict[str, dict], seen: Iterable[str] = ()) -> List[str]:
    """Claves presentes ahora que no están en la referencia ni se avisaron ya. Pura."""
    known = set(baseline) | set(seen)
    return sorted(k for k in current if k not in known)


# --- Referencia (guardia_referencia.json) --------------------------------------------------------
def load_baseline() -> Optional[Set[str]]:
    """Referencia guardada, o None si aún no existe (la primera pasada la crea sin avisar)."""
    try:
        with open(BASELINE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return set(data.get("keys", [])) if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def save_baseline(keys: Iterable[str]) -> None:
    os.makedirs(os.path.dirname(BASELINE_FILE), exist_ok=True)
    tmp = BASELINE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"updated": dt.datetime.now().isoformat(timespec="seconds"), "host": socket.gethostname(),
                   "keys": sorted(set(keys))}, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, BASELINE_FILE)


# --- Acciones ------------------------------------------------------------------------------------
def needs_admin(item: dict) -> bool:
    if item["kind"] == "run":
        return item["location"].upper().startswith("HKLM")
    if item["kind"] == "folder":
        return "todos" in item["label"].lower()  # carpeta Inicio común (ProgramData)
    return True  # reglas del Firewall


def describe_block(item: dict) -> str:
    """Lo que hará exactamente block() (para el diálogo de confirmación)."""
    if item["kind"] == "run":
        return f"Borrar el valor «{item['name']}» de {item['location']} (su contenido queda en la Caja Negra)"
    if item["kind"] == "folder":
        return f"Mover {os.path.join(item['location'], item['name'])} a {QUARANTINE_DIR}"
    return subprocess.list2cmdline(_firewall_cmd(item))


def _firewall_cmd(item: dict) -> List[str]:
    return ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Lozarus Guardia - Bloqueo TCP {item['port']}",
            "dir=in", "action=block", "protocol=TCP", f"localport={item['port']}"]


def evidence(item: dict) -> dict:
    """Ficha forense del elemento: sus datos más SHA-256, tamaño y fechas del ejecutable si existe."""
    data = {k: v for k, v in item.items()}
    path = item.get("path") or ""
    if item["kind"] == "port" and item.get("pid") and HAS_PSUTIL:
        try:
            proc = psutil.Process(item["pid"])
            path = proc.exe()
            data.update(path=path, cmdline=" ".join(proc.cmdline()), user=proc.username())
        except (psutil.Error, OSError) as exc:
            data["process_error"] = str(exc)
    if path and os.path.isfile(path):
        st = os.stat(path)
        data.update(size=st.st_size, modified=dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                    created=dt.datetime.fromtimestamp(st.st_ctime).isoformat(timespec="seconds"))
        if st.st_size <= HASH_LIMIT:
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            data["sha256"] = digest.hexdigest()
    return data


def block(item: dict) -> dict:
    """Neutraliza el elemento (ver docstring del módulo). Lanza OSError si no se pudo."""
    if item["kind"] == "run":
        hive, _, subkey = item["location"].partition("\\")
        name = "" if item["name"] == "(predeterminado)" else item["name"]
        exists, data, kind = read_value(hive, subkey, name)
        if not exists:
            raise FileNotFoundError(f"El valor «{item['name']}» ya no existe en {item['location']}")
        delete_value(hive, subkey, name)
        if read_value(hive, subkey, name)[0]:
            raise PermissionError(f"Windows no permitió borrar «{item['name']}»")
        return {"action": "registry_value_deleted", "backup": {"registry": item["location"], "value": item["name"],
                                                               "data": str(data), "type": kind}}
    if item["kind"] == "folder":
        src = os.path.join(item["location"], item["name"])
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        dst = os.path.join(QUARANTINE_DIR, f"{dt.datetime.now():%Y%m%d_%H%M%S}_{item['name']}")
        shutil.move(src, dst)
        return {"action": "moved_to_quarantine", "from": src, "to": dst}
    cmd = _firewall_cmd(item)
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        raise OSError((out or err).strip() or f"netsh devolvió {rc}")
    return {"action": "firewall_rule", "command": subprocess.list2cmdline(cmd)}
