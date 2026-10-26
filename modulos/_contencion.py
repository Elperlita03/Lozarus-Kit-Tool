# -*- coding: utf-8 -*-
"""
Herramientas de contención de Lozarus Kit Tool. A diferencia del resto del
proyecto, estas funciones SÍ modifican el sistema, pero de forma reversible,
exigiendo privilegios de Administrador y registrando lo que cambian para poder
deshacerlo con exactitud (incluso tras reiniciar la aplicación).

  · USB Killswitch   deshabilita/rehabilita el almacenamiento masivo USB
                     (HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR, Start 4↔3).
  · Aislamiento de red  bloquea el tráfico de salida salvo la LAN con el
                        Firewall de Windows (acción saliente por defecto = Bloquear
                        + regla de permiso para LocalSubnet), reversible.
  · Suspensión de procesos  congela/reanuda procesos concretos (los marcados por
                            el monitor), nunca procesos críticos del sistema.
  · Cuarentena Absoluta  orquesta los tres pasos y los revierte de golpe.

Todas las operaciones de admin lanzan PermissionError / devuelven un estado de
error cuando no hay privilegios; la GUI lo muestra sin cerrarse. El estado de la
cuarentena se guarda en disco para que «Levantar Cuarentena» funcione siempre.
"""

from __future__ import annotations

import ctypes
import datetime as dt
import json
import os
from typing import Dict, List, Optional, Tuple

from ._base import IS_WINDOWS
from ._forense import FORENSICS_DIR
from ._utilidades import HAS_PSUTIL, powershell, psutil

if IS_WINDOWS:
    import winreg

USBSTOR_PATH = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
USB_ENABLED, USB_DISABLED = 3, 4
FIREWALL_GROUP = "Lozarus Quarantine"
STATE_FILE = os.path.join(FORENSICS_DIR, ".cuarentena_estado.json")

# Procesos que NUNCA deben suspenderse: congelarlos puede provocar un cuelgue o un
# pantallazo azul del sistema, aunque el monitor los marque (p. ej. un svchost suplantado).
CRITICAL_NEVER_SUSPEND = {
    "system", "system idle process", "registry", "memory compression", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "fontdrvhost.exe",
    "dwm.exe", "svchost.exe", "spoolsv.exe", "explorer.exe",
}


# ===========================================================================
# ESTADO PERSISTENTE DE LA CUARENTENA
# ===========================================================================
def _load_state() -> Optional[dict]:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _save_state(state: dict) -> None:
    os.makedirs(FORENSICS_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)


def _clear_state() -> None:
    try:
        os.remove(STATE_FILE)
    except OSError:
        pass


def quarantine_active() -> bool:
    state = _load_state()
    return bool(state and state.get("active"))


# ===========================================================================
# USB KILLSWITCH
# ===========================================================================
def usb_storage_state() -> Optional[int]:
    """Valor Start de USBSTOR: 3 = habilitado, 4 = bloqueado. None si no se puede leer."""
    if not IS_WINDOWS:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USBSTOR_PATH, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            return int(winreg.QueryValueEx(key, "Start")[0])
    except (FileNotFoundError, OSError):
        return None


def set_usb_storage(enabled: bool) -> None:
    """Habilita (Start=3) o bloquea (Start=4) el almacenamiento masivo USB. Requiere Administrador.

    No afecta a los dispositivos USB ya conectados y en uso hasta que se desconectan; los
    teclados, ratones y demás periféricos USB NO se ven afectados (solo el almacenamiento)."""
    if not IS_WINDOWS:
        raise OSError("El USB Killswitch solo está disponible en Windows")
    value = USB_ENABLED if enabled else USB_DISABLED
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USBSTOR_PATH, 0,
                            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
    except PermissionError:
        raise PermissionError("Se necesitan privilegios de Administrador para cambiar el USB Killswitch")


# ===========================================================================
# AISLAMIENTO DE RED (Firewall de Windows)
# ===========================================================================
def _firewall_profiles() -> Dict[str, str]:
    """Acción saliente por defecto de cada perfil (Domain/Private/Public): 'Allow' o 'Block'."""
    data = powershell("Out-Json @(Get-NetFirewallProfile | Select-Object Name, "
                      "@{n='Action';e={[string]$_.DefaultOutboundAction}})")
    items = data if isinstance(data, list) else [data] if data else []
    return {p["Name"]: p["Action"] for p in items if isinstance(p, dict)}


def isolate_network() -> Dict[str, str]:
    """
    Bloquea el tráfico saliente salvo la LAN. Pone la acción saliente por defecto en Bloquear y
    añade una regla que permite LocalSubnet. Devuelve las acciones originales (para revertir).
    Requiere Administrador (PowerShell lanza error si no lo hay).
    """
    original = _firewall_profiles()
    script = r"""
try {
    New-NetFirewallRule -DisplayName 'Lozarus Quarantine - Permitir LAN (salida)' -Group '__GROUP__' `
        -Direction Outbound -Action Allow -RemoteAddress LocalSubnet -Profile Any -ErrorAction Stop | Out-Null
    Set-NetFirewallProfile -All -DefaultOutboundAction Block -ErrorAction Stop
    Out-Json @{ ok = $true }
} catch {
    Out-Json @{ ok = $false; error = [string]$_.Exception.Message }
}
""".replace("__GROUP__", FIREWALL_GROUP)
    result = powershell(script, timeout=60) or {}
    if not result.get("ok"):
        raise PermissionError(result.get("error") or "No se pudo modificar el Firewall (requiere Administrador)")
    return original


def restore_network(original: Optional[Dict[str, str]]) -> None:
    """Revierte el aislamiento: restaura la acción saliente por defecto y elimina las reglas de Lozarus."""
    restore = ""
    for name, action in (original or {}).items():
        if action in ("Allow", "Block"):
            restore += (f"Set-NetFirewallProfile -Name '{name}' -DefaultOutboundAction {action} "
                        f"-ErrorAction SilentlyContinue\n")
    if not original:  # sin datos previos, se asume el valor seguro por defecto (permitir salida)
        restore = "Set-NetFirewallProfile -All -DefaultOutboundAction Allow -ErrorAction SilentlyContinue\n"
    script = restore + (f"Remove-NetFirewallRule -Group '{FIREWALL_GROUP}' -ErrorAction SilentlyContinue\n"
                        "Out-Json @{ ok = $true }")
    result = powershell(script, timeout=60) or {}
    if not result.get("ok"):
        raise PermissionError("No se pudo restaurar el Firewall (requiere Administrador)")


# ===========================================================================
# SUSPENSIÓN DE PROCESOS (congelar / reanudar)
# ===========================================================================
if IS_WINDOWS:
    from ctypes import wintypes

    _PROCESS_SUSPEND_RESUME = 0x0800
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    # Declarar las firmas: sin esto, ctypes trunca el HANDLE de 64 bits a un int y lo invalida
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
    _ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]


def _nt(pid: int, resume: bool) -> None:
    """Suspende o reanuda un proceso con NtSuspendProcess/NtResumeProcess. Lanza PermissionError/OSError."""
    handle = _kernel32.OpenProcess(_PROCESS_SUSPEND_RESUME, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        raise PermissionError("acceso denegado") if err == 5 else OSError(f"OpenProcess falló (código {err})")
    try:
        status = (_ntdll.NtResumeProcess if resume else _ntdll.NtSuspendProcess)(handle) & 0xFFFFFFFF
        if status == 0xC0000022:
            raise PermissionError("acceso denegado")
        if status != 0:
            raise OSError(f"operación fallida (NTSTATUS 0x{status:08X})")
    finally:
        _kernel32.CloseHandle(handle)


def _can_suspend(pid: int, name: str) -> Optional[str]:
    """Devuelve el motivo por el que NO se debe suspender un proceso, o None si es seguro."""
    if pid in (0, 4) or pid == os.getpid():
        return "proceso protegido o la propia herramienta"
    if (name or "").lower() in CRITICAL_NEVER_SUSPEND:
        return "proceso crítico del sistema (suspenderlo colgaría Windows)"
    return None


def suspend_process(pid: int, name: str = "") -> None:
    """Congela un proceso concreto. Nunca toca procesos críticos ni la propia herramienta."""
    blocked = _can_suspend(pid, name)
    if blocked:
        raise ValueError(blocked)
    _nt(pid, resume=False)


def resume_process(pid: int) -> None:
    """Reanuda un proceso previamente congelado."""
    _nt(pid, resume=True)


def _create_time(pid: int) -> float:
    if not HAS_PSUTIL:
        return 0.0
    try:
        return psutil.Process(pid).create_time()
    except psutil.Error:
        return 0.0


# ===========================================================================
# CUARENTENA ABSOLUTA (orquestación reversible)
# ===========================================================================
def apply_quarantine(alerts: List) -> dict:
    """
    Aplica la cuarentena: aísla la red, congela los procesos marcados por el monitor (solo esos)
    y activa el USB Killswitch. Cada paso es independiente; el resultado detalla qué se logró y
    qué falló (p. ej. por permisos). Guarda el estado en disco para poder revertirlo.
    `alerts` son objetos con .pid, .name y (opcional) .created.
    """
    now = dt.datetime.now()
    state = {"active": True, "iniciada": now.isoformat(timespec="seconds"),
             "firewall_original": None, "usb_previo": None, "suspendidos": []}
    # Persistimos el marcador ANTES de tocar nada. Si el proceso muere a mitad, «Levantar
    # Cuarentena» encontrará este estado y podrá revertir: restore_network() sin estado original
    # aplica el valor seguro por defecto (permitir salida), así la red nunca queda bloqueada
    # sin forma de deshacerlo desde la propia herramienta.
    _save_state(state)
    steps: List[Tuple[str, bool, str]] = []  # (descripción, ok, detalle)

    # 1) Red: aislar salvo LAN
    try:
        state["firewall_original"] = isolate_network()
        _save_state(state)  # guardar el estado original en cuanto se conoce
        steps.append(("Red aislada (salida bloqueada salvo LAN)", True, ""))
    except Exception as exc:
        steps.append(("Aislamiento de red", False, str(exc)))

    # 2) Software: suspender SOLO los procesos marcados por el monitor
    suspended, skipped, failed = [], 0, 0
    for alert in alerts:
        pid, name = getattr(alert, "pid", 0), getattr(alert, "name", "")
        if _can_suspend(pid, name):
            skipped += 1
            continue
        try:
            _nt(pid, resume=False)
            suspended.append({"pid": pid, "name": name,
                              "created": getattr(alert, "created", None) or _create_time(pid)})
        except (PermissionError, OSError):
            failed += 1
    state["suspendidos"] = suspended
    _save_state(state)  # dejar registro de los procesos congelados por si hay que reanudarlos
    if suspended or failed or skipped:
        detail = ", ".join(filter(None, [f"{failed} sin permiso" if failed else "",
                                         f"{skipped} protegidos omitidos" if skipped else ""]))
        steps.append((f"{len(suspended)} proceso(s) sospechoso(s) congelado(s)", True, detail))
    else:
        steps.append(("Suspensión de procesos", True, "no había procesos sospechosos que congelar"))

    # 3) Hardware: activar el USB Killswitch (guardando el estado previo)
    try:
        state["usb_previo"] = usb_storage_state()
        _save_state(state)  # registrar el estado USB previo ANTES de cambiarlo
        set_usb_storage(enabled=False)
        steps.append(("USB Killswitch activado (almacenamiento USB bloqueado)", True, ""))
    except Exception as exc:
        steps.append(("USB Killswitch", False, str(exc)))

    _save_state(state)
    return {"active": True, "steps": [{"accion": a, "ok": ok, "detalle": d} for a, ok, d in steps]}


def lift_quarantine() -> dict:
    """Revierte la cuarentena: reanuda los procesos, restaura el Firewall y el estado previo del USB."""
    state = _load_state() or {}
    steps: List[Tuple[str, bool, str]] = []

    resumed, failed = 0, 0
    for item in state.get("suspendidos", []):
        pid = item.get("pid")
        ct = _create_time(pid)
        # Solo omitimos cuando PUDIMOS leer el create_time (ct != 0) y NO coincide: en ese caso el
        # PID lo ocupa ahora otro proceso. Si no se pudo leer (ct == 0, p. ej. sin psutil), se
        # reanuda igualmente: dejar un proceso congelado para siempre es peor que el riesgo de
        # reanudar un PID no verificable.
        if item.get("created") and ct and abs(ct - item["created"]) > 1:
            continue
        try:
            _nt(pid, resume=True)
            resumed += 1
        except (PermissionError, OSError):
            failed += 1
    if state.get("suspendidos"):
        steps.append((f"{resumed} proceso(s) reanudado(s)", True,
                      f"{failed} no se pudieron reanudar" if failed else ""))

    try:
        restore_network(state.get("firewall_original"))
        steps.append(("Red restaurada (salida permitida)", True, ""))
    except Exception as exc:
        steps.append(("Restaurar la red", False, str(exc)))

    if state.get("usb_previo") is not None:
        try:
            set_usb_storage(enabled=state["usb_previo"] == USB_ENABLED)
            restored = "bloqueado" if state["usb_previo"] == USB_DISABLED else "habilitado"
            steps.append((f"USB restaurado a su estado previo ({restored})", True, ""))
        except Exception as exc:
            steps.append(("Restaurar el USB", False, str(exc)))

    _clear_state()
    return {"active": False, "steps": [{"accion": a, "ok": ok, "detalle": d} for a, ok, d in steps]}
