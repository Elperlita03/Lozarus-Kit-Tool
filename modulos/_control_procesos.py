# -*- coding: utf-8 -*-
"""
Control ACTIVO y reversible de procesos del equipo propio (Monitor en Vivo de Lozarus):

  · Congelar / reanudar (psutil suspend/resume): el proceso deja de ejecutarse sin perder su
    estado en memoria. Sigue congelado aunque se cierre Lozarus, hasta que se reanude.
  · Prioridad mínima / restaurar: degrada la prioridad de CPU a IDLE y la devuelve a la previa.

Nunca termina procesos. Se niega a actuar sobre los procesos críticos de Windows y de su
protección (congelarlos colgaría la sesión o desactivaría una defensa) y sobre el propio Lozarus.
Sin Administrador solo se controlan procesos del propio usuario: el acceso denegado se informa
tal cual, nunca se finge un éxito. Funciones aisladas de Qt para poder probarlas sin interfaz.
"""

import os
from typing import Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except Exception:  # noqa: BLE001
    psutil = None
    HAS_PSUTIL = False

# Congelar o degradar cualquiera de estos dejaría Windows inutilizable (sesión, seguridad,
# escritorio) o desactivaría una protección del sistema (Defender). Comparación en minúsculas.
PROTEGIDOS = frozenset({
    "system", "system idle process", "idle", "registry", "memory compression", "secure system",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "explorer.exe", "sihost.exe",
    "ctfmon.exe", "audiodg.exe", "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
})

_ACCESO_DENEGADO = ("Acceso denegado: es un proceso de otro usuario o del sistema "
                    "(requiere Administrador).")


def _priority_names():
    if not HAS_PSUTIL or not hasattr(psutil, "IDLE_PRIORITY_CLASS"):
        return {}
    return {psutil.IDLE_PRIORITY_CLASS: "mínima (Idle)",
            psutil.BELOW_NORMAL_PRIORITY_CLASS: "por debajo de lo normal",
            psutil.NORMAL_PRIORITY_CLASS: "normal",
            psutil.ABOVE_NORMAL_PRIORITY_CLASS: "por encima de lo normal",
            psutil.HIGH_PRIORITY_CLASS: "alta",
            psutil.REALTIME_PRIORITY_CLASS: "tiempo real"}


def priority_label(value) -> str:
    """Nombre legible de una clase de prioridad de Windows (o el valor crudo si no se conoce)."""
    return _priority_names().get(value, str(value))


def check_target(pid: Optional[int], name: Optional[str], own_pids=None) -> Tuple[bool, str]:
    """
    ¿Se puede actuar sobre este proceso? Pura: (permitido, motivo_si_no). Rechaza los PID del
    núcleo, el propio Lozarus (y su consola) y los procesos críticos de PROTEGIDOS.
    """
    if pid is None or pid <= 4:
        return False, "Proceso del núcleo de Windows: protegido."
    own = own_pids if own_pids is not None else {os.getpid(), os.getppid()}
    if pid in own:
        return False, "Es el propio Lozarus (o su consola): no puede congelarse a sí mismo."
    if not name:
        return False, "No se pudo identificar el proceso: por seguridad no se actúa sobre él."
    if name.strip().lower() in PROTEGIDOS:
        return False, f"«{name}» es un proceso crítico de Windows o de su protección: protegido."
    return True, ""


def _target(pid: int):
    """(proceso, nombre, error). Comprueba la existencia, la identidad y la lista de protegidos."""
    if not HAS_PSUTIL:
        return None, "", "psutil no disponible"
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except psutil.NoSuchProcess:
        return None, "", "El proceso ya no existe."
    except psutil.AccessDenied:
        return None, "", _ACCESO_DENEGADO
    allowed, reason = check_target(pid, name)
    if not allowed:
        return None, name, reason
    return proc, name, ""


def _run(pid: int, action) -> Tuple[bool, str]:
    proc, name, err = _target(pid)
    if proc is None:
        return False, err
    try:
        return True, action(proc, name)
    except psutil.NoSuchProcess:
        return False, "El proceso ya no existe."
    except psutil.AccessDenied:
        return False, _ACCESO_DENEGADO
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def suspend_process(pid: int) -> Tuple[bool, str]:
    """Congela el proceso (suspende todos sus hilos). Reversible con resume_process. Nunca lanza."""
    def act(proc, name):
        proc.suspend()
        return f"«{name}» (PID {pid}) congelado. Seguirá así hasta que lo reanudes."
    return _run(pid, act)


def resume_process(pid: int) -> Tuple[bool, str]:
    """Reanuda un proceso congelado. Nunca lanza."""
    def act(proc, name):
        proc.resume()
        return f"«{name}» (PID {pid}) reanudado."
    return _run(pid, act)


def lower_priority(pid: int) -> Tuple[bool, str, Optional[int]]:
    """
    Degrada la prioridad de CPU a la mínima (IDLE). Devuelve (ok, mensaje, prioridad_previa) para
    poder restaurarla exactamente después. Nunca lanza.
    """
    previa = {}

    def act(proc, name):
        previa["valor"] = proc.nice()
        idle = getattr(psutil, "IDLE_PRIORITY_CLASS", 19)  # 19 = mínima en sistemas POSIX
        proc.nice(idle)
        return (f"«{name}» (PID {pid}): prioridad {priority_label(previa['valor'])} → "
                f"{priority_label(idle)}.")
    ok, msg = _run(pid, act)
    return ok, msg, previa.get("valor")


def restore_priority(pid: int, previous: Optional[int] = None) -> Tuple[bool, str]:
    """Devuelve la prioridad a la previa (o a NORMAL si no se conoce). Nunca lanza."""
    def act(proc, name):
        target = previous if previous is not None else getattr(psutil, "NORMAL_PRIORITY_CLASS", 0)
        proc.nice(target)
        return f"«{name}» (PID {pid}): prioridad restaurada a {priority_label(target)}."
    return _run(pid, act)
