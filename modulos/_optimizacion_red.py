# -*- coding: utf-8 -*-
"""
Optimización de red y procesos para Lozarus. Todo LOCAL sobre el equipo propio:

  · auditar los adaptadores de red (estado, velocidad, MTU, direcciones y tasa de errores),
  · mantenimiento preventivo de la pila de red (Winsock, TCP/IP, concesión DHCP, caché DNS),
  · escanear los procesos en ejecución (PID, nombre, ruta, CPU, RAM y firma Authenticode),
  · finalizar un proceso bloqueado o con consumo anómalo (nunca uno crítico del sistema).

Las operaciones de mantenimiento son solo de Windows y exigen Administrador: fuera de Windows, o
sin privilegios, se devuelve (False, motivo) SIN ejecutar nada (no se inventa un éxito).

Funciones aisladas de Qt para poder probarlas sin interfaz. Ninguna lanza: devuelven datos o
tuplas (ok, mensaje).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except Exception:  # noqa: BLE001
    psutil = None
    HAS_PSUTIL = False

from modulos._utilidades import authenticode_signatures, is_admin, signature_label

IS_WINDOWS = sys.platform == "win32"
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Umbrales de «consumo anómalo» (CPU normalizada al total de núcleos y memoria residente).
CPU_ANOMALY_PCT = 50.0
RAM_ANOMALY_BYTES = 1536 * 1024 ** 2
ERROR_RATIO_DEGRADED = 0.01  # >1 % de paquetes con error o descartados → adaptador degradado

# Procesos que NUNCA se finalizan desde Lozarus (matarlos cuelga o reinicia el equipo).
PROTECTED_NAMES = frozenset({
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe",
    "dwm.exe", "memory compression", "msmpeng.exe", "secure system",
    "systemd", "init", "kthreadd", "launchd", "kernel_task",
})
PROTECTED_PIDS = frozenset({0, 1, 4})

# Operaciones de mantenimiento: clave -> (descripción, [argv...], requiere_reinicio)
MAINTENANCE_OPS: Dict[str, Tuple[str, List[List[str]], bool]] = {
    "winsock": ("Restablecer catálogo Winsock", [["netsh", "winsock", "reset"]], True),
    "tcpip": ("Restablecer pila TCP/IP", [["netsh", "int", "ip", "reset"],
                                          ["netsh", "int", "ipv6", "reset"]], True),
    "dhcp": ("Renovar concesión DHCP", [["ipconfig", "/release"], ["ipconfig", "/renew"]], False),
    "dns": ("Purgar y re-registrar DNS", [["ipconfig", "/flushdns"], ["ipconfig", "/registerdns"]], False),
}


# ---------------------------------------------------------------------------------------------
# Ejecución de comandos (sin shell)
# ---------------------------------------------------------------------------------------------
def _sys32(exe: str) -> str:
    """Ruta absoluta en System32 (evita secuestro por PATH); si no existe, el nombre tal cual."""
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", exe + ".exe")
    return path if os.path.isfile(path) else exe


def _run(argv: List[str], timeout: int = 60) -> Tuple[int, str]:
    """Ejecuta argv SIN shell y devuelve (código, salida combinada). Nunca lanza."""
    try:
        proc = subprocess.run([_sys32(argv[0])] + argv[1:], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=timeout, creationflags=_NO_WINDOW)
    except FileNotFoundError:
        return 127, f"Comando no disponible: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"«{' '.join(argv)}» superó el tiempo límite de {timeout} s"
    except Exception as exc:  # noqa: BLE001
        return 1, f"{type(exc).__name__}: {exc}"
    enc = "oem" if os.name == "nt" else "utf-8"  # el códec «oem» solo existe en Windows
    out = (proc.stdout or b"").decode(enc, errors="replace") + (proc.stderr or b"").decode(enc, errors="replace")
    return proc.returncode, out.strip()


def run_maintenance(op: str, admin: Optional[bool] = None) -> Dict[str, Any]:
    """
    Ejecuta una operación de MAINTENANCE_OPS. Devuelve {ok, op, title, reboot, message, steps}.
    Fuera de Windows o sin Administrador no ejecuta nada.
    """
    if op not in MAINTENANCE_OPS:
        return {"ok": False, "op": op, "title": op, "reboot": False, "steps": [],
                "message": f"Operación desconocida: {op}"}
    title, commands, reboot = MAINTENANCE_OPS[op]
    base = {"op": op, "title": title, "reboot": reboot, "steps": []}
    if not IS_WINDOWS:
        return {**base, "ok": False, "message": f"{title}: disponible solo en Windows ({sys.platform})."}
    if not (is_admin() if admin is None else admin):
        return {**base, "ok": False, "message": f"{title}: requiere Administrador."}
    ok = True
    for argv in commands:
        rc, out = _run(argv, timeout=90)
        base["steps"].append({"cmd": " ".join(argv), "rc": rc, "output": out[-400:]})
        if rc != 0:
            ok = False
            break
    last = base["steps"][-1] if base["steps"] else {"cmd": "", "rc": 0, "output": ""}
    if ok:
        msg = f"{title}: completado." + (" Reinicia el equipo para aplicar el cambio." if reboot else "")
    else:
        detail = (last["output"].splitlines() or [""])[-1]
        msg = f"{title}: «{last['cmd']}» terminó con código {last['rc']}. {detail}".strip()
    return {**base, "ok": ok, "message": msg}


# ---------------------------------------------------------------------------------------------
# Adaptadores de red (solo lectura)
# ---------------------------------------------------------------------------------------------
def adapter_health(up: bool, io: Optional[Dict[str, int]]) -> Tuple[str, float]:
    """Clasifica un adaptador: ('inactivo'|'degradado'|'ok', tasa de errores). Función pura."""
    if not up:
        return "inactivo", 0.0
    if not io:
        return "ok", 0.0
    packets = io.get("packets_sent", 0) + io.get("packets_recv", 0)
    bad = io.get("errin", 0) + io.get("errout", 0) + io.get("dropin", 0) + io.get("dropout", 0)
    ratio = bad / packets if packets else 0.0
    return ("degradado" if ratio > ERROR_RATIO_DEGRADED else "ok"), ratio


def adapters_overview() -> List[Dict[str, Any]]:
    """Lista de adaptadores con estado, velocidad, MTU, IPv4/MAC y tasa de errores (sin admin)."""
    if not HAS_PSUTIL:
        return []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    try:
        io_all = psutil.net_io_counters(pernic=True)
    except Exception:  # noqa: BLE001
        io_all = {}
    link = getattr(psutil, "AF_LINK", -1)
    out = []
    for name, st in stats.items():
        ipv4, mac, ipv6 = [], "", 0
        for a in addrs.get(name, []):
            fam = getattr(a.family, "name", str(a.family))
            if fam == "AF_INET":
                ipv4.append(a.address)
            elif fam == "AF_INET6":
                ipv6 += 1
            elif a.family == link and a.address:
                mac = a.address
        io = io_all.get(name)
        io_d = io._asdict() if io is not None else None
        health, ratio = adapter_health(bool(st.isup), io_d)
        out.append({"name": name, "up": bool(st.isup), "speed": int(st.speed or 0), "mtu": int(st.mtu or 0),
                    "ipv4": ", ".join(ipv4) or "—", "ipv6": ipv6, "mac": mac or "—",
                    "health": health, "error_ratio": ratio,
                    "sent": io_d["bytes_sent"] if io_d else 0, "recv": io_d["bytes_recv"] if io_d else 0})
    out.sort(key=lambda r: (not r["up"], r["name"].lower()))
    return out


# ---------------------------------------------------------------------------------------------
# Procesos
# ---------------------------------------------------------------------------------------------
def is_protected(pid: int, name: str) -> bool:
    """True si el proceso es crítico del sistema o es el propio Lozarus. Función pura."""
    return pid in PROTECTED_PIDS or pid == os.getpid() or (name or "").strip().lower() in PROTECTED_NAMES


def anomaly_reasons(cpu: float, rss: int, status: str) -> List[str]:
    """Motivos de consumo anómalo o bloqueo. Función pura."""
    reasons = []
    if cpu >= CPU_ANOMALY_PCT:
        reasons.append(f"CPU {cpu:.0f}%")
    if rss >= RAM_ANOMALY_BYTES:
        reasons.append(f"RAM {rss / 1024 ** 3:.1f} GB")
    if status in ("zombie", "stopped", "dead"):
        reasons.append(f"estado {status}")
    return reasons


def signature_state(status: str) -> str:
    """'valid' | 'invalid' | 'unknown' a partir del Status de Authenticode. Función pura."""
    if status == "Valid":
        return "valid"
    if status in ("", "Error", "UnknownError", "N/D"):
        return "unknown"
    return "invalid"


def scan_processes(verify_signatures: bool = True, sample_s: float = 0.6) -> List[Dict[str, Any]]:
    """
    Escanea los procesos: PID, nombre, ruta, usuario, estado, CPU (normalizada), RAM y firma. La CPU
    se mide en dos tomas separadas `sample_s`. La firma solo se verifica en Windows (lento: PowerShell
    en bloque); en otros sistemas queda «N/D».
    """
    if not HAS_PSUTIL:
        return []
    procs = list(psutil.process_iter())
    for p in procs:
        try:
            p.cpu_percent(None)
        except Exception:  # noqa: BLE001
            pass
    time.sleep(sample_s)
    ncpu = psutil.cpu_count() or 1
    rows = []
    for p in procs:
        try:
            with p.oneshot():
                info = p.as_dict(["pid", "name", "exe", "username", "status", "memory_info"], ad_value=None)
                cpu = (p.cpu_percent(None) or 0.0) / ncpu
        except Exception:  # noqa: BLE001  (terminó entre las dos tomas o acceso denegado)
            continue
        rss = info["memory_info"].rss if info.get("memory_info") else 0
        status = str(info.get("status") or "")
        name = info.get("name") or "?"
        rows.append({"pid": info["pid"], "name": name, "exe": info.get("exe") or "",
                     "user": info.get("username") or "", "status": status, "cpu": cpu, "rss": rss,
                     "protected": is_protected(info["pid"], name),
                     "anomalies": anomaly_reasons(cpu, rss, status),
                     "sig_status": "N/D", "sig_signer": "", "sig_label": "N/D", "sig_state": "unknown"})
    if verify_signatures and IS_WINDOWS:
        sigs = authenticode_signatures([r["exe"] for r in rows if r["exe"]])
        for r in rows:
            if r["exe"] in sigs:
                st, who = sigs[r["exe"]]
                r.update(sig_status=st, sig_signer=who, sig_state=signature_state(st),
                         sig_label=signature_label(st, who).removeprefix("firma "))
    elif not IS_WINDOWS:
        for r in rows:
            r["sig_label"] = "N/D (solo Windows)"
    rows.sort(key=lambda r: (not r["anomalies"], -r["cpu"], -r["rss"]))
    return rows


def terminate_process(pid: int, expected_name: str = "", timeout: float = 3.0) -> Tuple[bool, str]:
    """
    Finaliza un proceso (terminate y, si no responde en `timeout`, kill). Se niega con procesos
    protegidos y si el PID ya pertenece a otro programa (reutilización de PID). Devuelve (ok, msg).
    """
    if not HAS_PSUTIL:
        return False, "psutil no está disponible."
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except psutil.NoSuchProcess:
        return False, f"El proceso {pid} ya no existe."
    except Exception as exc:  # noqa: BLE001
        return False, f"No se pudo abrir el PID {pid}: {exc}"
    if expected_name and name.lower() != expected_name.lower():
        return False, f"El PID {pid} ahora es «{name}», no «{expected_name}»: no se finaliza."
    if is_protected(pid, name):
        return False, f"«{name}» es un proceso crítico del sistema: Lozarus no lo finaliza."
    try:
        proc.terminate()
        try:
            proc.wait(timeout)
            return True, f"«{name}» (PID {pid}) finalizado."
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout)
            return True, f"«{name}» (PID {pid}) no respondía: forzado su cierre."
    except psutil.NoSuchProcess:
        return True, f"«{name}» (PID {pid}) ya había terminado."
    except psutil.AccessDenied:
        return False, f"Acceso denegado a «{name}» (PID {pid}): requiere Administrador."
    except Exception as exc:  # noqa: BLE001
        return False, f"No se pudo finalizar «{name}»: {type(exc).__name__}: {exc}"
