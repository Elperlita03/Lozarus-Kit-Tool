# -*- coding: utf-8 -*-
"""
Herramientas forenses de Lozarus Kit Tool (solo lectura del sistema).

  · forensic_report(): extrae el contexto de un proceso (PID, ruta, hash SHA-256,
    firma, conexiones de red asociadas) y lo guarda como un prompt listo para un
    analista de malware externo, en Lozarus_Forensics/.
  · system_snapshot(): "caja negra" del estado volátil del equipo en un instante
    (procesos, conexiones y tabla ARP) en Lozarus_Forensics/Snapshots/, como imagen
    inmutable con fecha y hora.

Ambas funciones solo leen el sistema y escriben su propio fichero de informe; no
cambian ninguna configuración. Pueden tardar (hash de ficheros, enumeración), así
que la GUI las ejecuta en un hilo aparte.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
from typing import Dict, List, Optional, Tuple

from ._base import IS_WINDOWS
from ._utilidades import HAS_PSUTIL, psutil, run_cmd

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORENSICS_DIR = os.path.join(PROJECT_DIR, "Lozarus_Forensics")
SNAPSHOTS_DIR = os.path.join(FORENSICS_DIR, "Snapshots")


def _ensure(directory: str) -> str:
    os.makedirs(directory, exist_ok=True)
    return directory


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_") or "proceso"


def sha256_of(path: str, max_bytes: int = 512 * 1024 * 1024) -> Tuple[Optional[str], str]:
    """SHA-256 de un fichero. Devuelve (hash, nota). None si no es legible (permisos, tamaño)."""
    if not path or not os.path.isfile(path):
        return None, "ejecutable no accesible desde este usuario"
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return None, f"omitido: el fichero supera {max_bytes // 1024 // 1024} MB"
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest(), f"{size:,} bytes".replace(",", ".")
    except (OSError, PermissionError) as exc:
        return None, f"no se pudo leer: {exc}"


def _process_facts(pid: int) -> Dict[str, object]:
    """Datos del proceso vía psutil (cada campo protegido: un AccessDenied no interrumpe el informe)."""
    facts: Dict[str, object] = {"pid": pid}
    if not HAS_PSUTIL:
        return facts
    try:
        proc = psutil.Process(pid)
    except psutil.Error:
        facts["estado"] = "el proceso ya no existe"
        return facts
    getters = {
        "name": proc.name, "exe": proc.exe, "cmdline": lambda: " ".join(proc.cmdline()),
        "username": proc.username, "ppid": proc.ppid,
        "create_time": lambda: dt.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "cwd": proc.cwd, "num_threads": proc.num_threads,
        "memoria_rss": lambda: f"{proc.memory_info().rss / 1024 / 1024:.1f} MB",
    }
    for key, getter in getters.items():
        try:
            facts[key] = getter()
        except (psutil.AccessDenied, psutil.Error, OSError):
            facts[key] = "(no accesible)"
    try:
        parent = proc.parent()
        facts["padre"] = f"{parent.name()} (PID {parent.pid})" if parent else "(ninguno)"
    except (psutil.Error, OSError):
        facts["padre"] = "(no accesible)"
    return facts


def _connections_for(pid: int) -> List[Dict[str, str]]:
    """Conexiones de red abiertas por el proceso (TCP/UDP con dirección remota)."""
    if not HAS_PSUTIL:
        return []
    result = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid != pid or not conn.raddr:
                continue
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            result.append({"proto": proto, "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                           "remota": f"{conn.raddr.ip}:{conn.raddr.port}", "estado": conn.status})
    except (psutil.AccessDenied, psutil.Error, OSError):
        pass
    return result


def forensic_report(pid: int, name: str = "", path: str = "", signature: str = "",
                    reasons: Optional[List[str]] = None) -> Tuple[str, str]:
    """
    Genera y guarda el reporte forense de un proceso. Devuelve (ruta_del_fichero, texto).
    `name`, `path`, `signature` y `reasons` enriquecen el informe con lo que el monitor ya sabía.
    """
    facts = _process_facts(pid)
    name = name or str(facts.get("name") or "proceso")
    path = path or (facts.get("exe") if isinstance(facts.get("exe"), str) else "") or ""
    digest, hash_note = sha256_of(path)
    connections = _connections_for(pid)
    now = dt.datetime.now()

    lines: List[str] = []
    add = lines.append
    add("Actúa como analista de malware senior. Evalúa el siguiente contexto extraído de un PC")
    add("Windows por la herramienta de auditoría Lozarus Kit Tool (modo solo lectura). Indica si el")
    add("proceso es benigno, sospechoso o malicioso, justifica tu valoración, señala los indicadores")
    add("de compromiso (IoC) relevantes y propón los siguientes pasos de contención y análisis.")
    add("")
    add("=" * 78)
    add("  CONTEXTO DEL EQUIPO")
    add("=" * 78)
    add(f"Equipo         : {socket.gethostname()}")
    add(f"Sistema        : {platform.platform()}")
    add(f"Fecha captura  : {now:%Y-%m-%d %H:%M:%S}")
    add("Herramienta    : Lozarus Kit Tool v.01 (solo lectura)")
    add("")
    add("=" * 78)
    add("  PROCESO BAJO ANÁLISIS")
    add("=" * 78)
    labels = [("PID", "pid"), ("Nombre", "name"), ("Ejecutable", "exe"), ("Línea de comandos", "cmdline"),
              ("Directorio de trabajo", "cwd"), ("Usuario", "username"), ("Proceso padre", "padre"),
              ("Creado", "create_time"), ("Hilos", "num_threads"), ("Memoria", "memoria_rss")]
    for label, key in labels:
        if key in facts:
            add(f"{label:<22}: {facts[key]}")
    if reasons:
        add(f"{'Motivos de la alerta':<22}: " + "; ".join(reasons))
    add("")
    add("=" * 78)
    add("  INTEGRIDAD Y FIRMA")
    add("=" * 78)
    add(f"{'Firma digital':<22}: {signature or '(no evaluada)'}")
    add(f"{'SHA-256':<22}: {digest or 'no disponible'}")
    add(f"{'Nota del fichero':<22}: {hash_note}")
    if digest:
        add(f"{'Consulta sugerida':<22}: busca este hash en VirusTotal u otra base de reputación")
    add("")
    add("=" * 78)
    add("  CONEXIONES DE RED ASOCIADAS")
    add("=" * 78)
    if connections:
        add(f"{'PROTO':<6}{'LOCAL':<24}{'REMOTA':<24}ESTADO")
        for c in connections:
            add(f"{c['proto']:<6}{c['local']:<24}{c['remota']:<24}{c['estado']}")
    else:
        add("(sin conexiones de red abiertas en el momento de la captura)")
    add("")
    add("=" * 78)
    add("Con todo lo anterior, entrega: 1) veredicto (benigno/sospechoso/malicioso) y confianza,")
    add("2) razonamiento e IoC, 3) acciones de contención recomendadas, 4) qué analizar a continuación.")
    text = "\n".join(lines)

    _ensure(FORENSICS_DIR)
    filename = f"Reporte_{_safe_name(name)}_PID{pid}_{now:%Y%m%d_%H%M%S}.txt"
    report_path = os.path.join(FORENSICS_DIR, filename)
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return report_path, text


# ===========================================================================
# SNAPSHOT DE CAJA NEGRA
# ===========================================================================
def _arp_table() -> List[Dict[str, str]]:
    """Tabla ARP (vecinos de red): IP, MAC y tipo."""
    entries = []
    try:
        if IS_WINDOWS:
            _, out, _ = run_cmd(["arp", "-a"])
            for ip, mac, kind in re.findall(
                    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)", out):
                entries.append({"ip": ip, "mac": mac.lower(), "tipo": kind})
        else:
            _, out, _ = run_cmd(["ip", "neigh"])
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3] == "lladdr":
                    entries.append({"ip": parts[0], "mac": parts[4].lower(), "tipo": parts[-1]})
    except Exception:
        pass
    return entries


def _snapshot_processes() -> List[Dict[str, object]]:
    if not HAS_PSUTIL:
        return []
    procs = []
    attrs = ["pid", "name", "exe", "ppid", "username", "create_time", "memory_info"]
    for proc in psutil.process_iter(attrs, ad_value=None):
        info = proc.info
        if info["pid"] == 0:
            continue
        procs.append({
            "pid": info["pid"], "nombre": info["name"], "ejecutable": info["exe"], "ppid": info["ppid"],
            "usuario": info["username"],
            "creado": (dt.datetime.fromtimestamp(info["create_time"]).strftime("%Y-%m-%d %H:%M:%S")
                       if info["create_time"] else None),
            "memoria_rss": info["memory_info"].rss if info["memory_info"] else None,
        })
    return sorted(procs, key=lambda p: p["pid"])


def _snapshot_connections() -> List[Dict[str, object]]:
    if not HAS_PSUTIL:
        return []
    conns = []
    for conn in psutil.net_connections(kind="inet"):
        conns.append({
            "proto": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
            "remota": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
            "estado": conn.status, "pid": conn.pid,
        })
    return conns


def system_snapshot() -> Tuple[str, Dict[str, int]]:
    """
    Captura el estado volátil del equipo (procesos, conexiones, ARP) en un JSON inmutable.
    Devuelve (ruta_del_json, resumen con los recuentos). Solo lectura.
    """
    now = dt.datetime.now()
    processes = _snapshot_processes()
    connections = _snapshot_connections()
    arp = _arp_table()
    data = {
        "herramienta": "Lozarus Kit Tool v.01",
        "tipo": "snapshot_caja_negra",
        "equipo": socket.gethostname(),
        "sistema": platform.platform(),
        "capturado": now.isoformat(timespec="seconds"),
        "resumen": {"procesos": len(processes), "conexiones": len(connections), "arp": len(arp)},
        "procesos": processes,
        "conexiones": connections,
        "arp": arp,
    }
    _ensure(SNAPSHOTS_DIR)
    snapshot_path = os.path.join(SNAPSHOTS_DIR, f"Snapshot_{now:%Y%m%d_%H%M%S}.json")
    with open(snapshot_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
    return snapshot_path, data["resumen"]


def instant_capture(components: Optional[List[Tuple[str, str, str]]] = None,
                    directory: Optional[str] = None) -> Tuple[str, Dict[str, int]]:
    """
    «Protocolo de Captura Instantánea»: expediente JSON del estado del equipo en ESTE segundo —
    procesos activos, conexiones establecidas, puertos en escucha, memoria y estado de los
    componentes de Lozarus (filas (nombre, estado, detalle) que pasa la GUI). Solo lectura del
    sistema; escribe únicamente su propio fichero. Devuelve (ruta, resumen de recuentos).
    """
    now = dt.datetime.now()
    processes = _snapshot_processes()
    connections = _snapshot_connections()
    establecidas = [c for c in connections if c.get("estado") == "ESTABLISHED"]
    escucha = [c for c in connections if c.get("estado") == "LISTEN"]
    memoria = None
    if HAS_PSUTIL:
        vm, sw = psutil.virtual_memory(), psutil.swap_memory()
        memoria = {"total": vm.total, "disponible": vm.available, "usada_pct": vm.percent,
                   "paginacion_total": sw.total, "paginacion_usada_pct": sw.percent}
    componentes = [{"componente": n, "estado": s, "detalle": d} for n, s, d in (components or [])]
    resumen = {"procesos": len(processes), "establecidas": len(establecidas),
               "escucha": len(escucha), "componentes": len(componentes)}
    data = {
        "herramienta": "Lozarus Kit Tool",
        "tipo": "captura_instantanea",
        "esquema": "lozarus.capture.v1",
        "equipo": socket.gethostname(),
        "sistema": platform.platform(),
        "capturado": now.isoformat(timespec="seconds"),
        "resumen": resumen,
        "memoria": memoria,
        "procesos": processes,
        "conexiones_establecidas": establecidas,
        "puertos_escucha": escucha,
        "componentes": componentes,
    }
    folder = _ensure(directory or SNAPSHOTS_DIR)
    base = os.path.join(folder, f"Captura_{now:%Y%m%d_%H%M%S}")
    path, n = base + ".json", 1
    while os.path.exists(path):  # dos capturas en el mismo segundo: no se sobrescribe ninguna
        path, n = f"{base}_{n}.json", n + 1
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
    return path, resumen


def list_snapshots() -> List[Tuple[str, str, dt.datetime]]:
    """Snapshots guardados, del más reciente al más antiguo: (ruta, nombre, fecha)."""
    if not os.path.isdir(SNAPSHOTS_DIR):
        return []
    items = []
    for name in os.listdir(SNAPSHOTS_DIR):
        if name.lower().endswith(".json"):
            full = os.path.join(SNAPSHOTS_DIR, name)
            items.append((full, name, dt.datetime.fromtimestamp(os.path.getmtime(full))))
    return sorted(items, key=lambda item: item[2], reverse=True)


if __name__ == "__main__":  # python -m modulos._forense  -> snapshot de prueba
    path, summary = system_snapshot()
    print("Snapshot guardado en:", path)
    print("Resumen:", summary)
