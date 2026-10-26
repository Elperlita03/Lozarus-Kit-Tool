# -*- coding: utf-8 -*-
"""
Operaciones tácticas de Lozarus Kit Tool (acciones activas, no de solo lectura).

Arquitectura híbrida: Python orquesta y la interfaz decide; el trabajo nativo de Windows
se delega a PowerShell / herramientas de consola mediante subprocess, capturando stdout y
stderr para mostrarlos tal cual en la consola de Telemetría Interna.

  · Windows Sandbox   «detona» un ejecutable sospechoso en la máquina virtual DESECHABLE
                      de Windows, totalmente aislada del equipo anfitrión. El binario se
                      deja PREPARADO en la VM (carpeta mapeada en SOLO LECTURA, abierta en
                      el Explorador) pero NO se ejecuta solo: así no hay detonación por
                      accidente y el anfitrión queda protegido. Sin red por defecto.

  · Modo Fantasma     limpieza de privacidad de ESTE equipo: caché DNS, portapapeles,
                      archivos recientes (Jump Lists), papelera y temporales y, como paso
                      aparte y solo con Administrador, los registros de eventos. Las
                      acciones destructivas son IRREVERSIBLES: la interfaz muestra antes un
                      recuento (ghost_preview) y pide confirmación explícita.

Todo es local, sobre esta máquina. Las operaciones que modifican el sistema exigen
Administrador y degradan con limpieza (mensaje de error, sin tocar nada) cuando no lo hay.

`emit(kind, text)` es un callback opcional para ir narrando el progreso en la consola de
Lozarus en tiempo real (kind: "+" inicio, "~" en curso, "*" hecho, "!" aviso, "x" error).
Se invoca desde el hilo de trabajo, así que la GUI lo encamina por su cola de eventos.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import threading
import xml.sax.saxutils as xmlutil
from typing import Callable, Dict, List, Optional, Tuple

from ._base import CheckSkipped, IS_WINDOWS
from ._forense import FORENSICS_DIR
from ._utilidades import powershell_argv, powershell_raw

Emit = Optional[Callable[[str, str], None]]

SANDBOX_DIR = os.path.join(FORENSICS_DIR, "Sandbox")
WDAG_DESKTOP = r"C:\Users\WDAGUtilityAccount\Desktop"  # escritorio del usuario de Windows Sandbox


def _emit(emit: Emit, kind: str, text: str) -> None:
    if emit:
        try:
            emit(kind, text)
        except Exception:
            pass


def _stream(argv: List[str], emit: Emit, timeout: int = 120) -> Tuple[int, int]:
    """
    Ejecuta un comando y transmite su salida EN DIRECTO, línea a línea, vía `emit` (para la
    terminal en tiempo real del Modo Fantasma). stderr se mezcla con stdout. Devuelve
    (código de salida, nº de líneas emitidas). Un temporizador mata el proceso si se cuelga.
    """
    flags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
    enc = "oem" if IS_WINDOWS else "utf-8"  # las herramientas de consola de Windows usan la página OEM
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, creationflags=flags, bufsize=1,
                                universal_newlines=True, encoding=enc, errors="replace")
    except FileNotFoundError:
        raise CheckSkipped(f"Comando no disponible: {argv[0]}")
    lines = 0
    killer = threading.Timer(timeout, proc.kill)
    killer.start()
    try:
        for raw in proc.stdout:
            line = raw.rstrip()
            if line:
                lines += 1
                _emit(emit, "~", f"    {line}")
    finally:
        killer.cancel()
        proc.wait()
    return proc.returncode or 0, lines


# ===========================================================================
# WINDOWS SANDBOX  ·  detonación aislada en una VM desechable
# ===========================================================================
def _sandbox_exe() -> Optional[str]:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    exe = os.path.join(root, "System32", "WindowsSandbox.exe")
    return exe if os.path.exists(exe) else None


def sandbox_available() -> Tuple[bool, str]:
    """¿Está Windows Sandbox instalado? Devuelve (disponible, ruta-del-exe-o-motivo)."""
    if not IS_WINDOWS:
        return False, "Windows Sandbox solo existe en Windows"
    exe = _sandbox_exe()
    if exe:
        return True, exe
    return False, ("Windows Sandbox no está activado. Actívalo en «Activar o desactivar las "
                   "características de Windows» → Espacio aislado de Windows (necesita Windows 10/11 "
                   "Pro o Enterprise y la virtualización habilitada en la BIOS/UEFI).")


def build_wsb(folder: str, networking: bool) -> str:
    """
    Genera el XML de configuración .wsb. La carpeta del ejecutable se mapea en la VM en SOLO
    LECTURA (el anfitrión no se puede modificar desde dentro, ni siquiera si el binario se
    ejecuta) y, al arrancar, se abre en el Explorador para dejar la muestra a la vista. La red
    va deshabilitada salvo que se pida: así el sospechoso no puede salir a Internet.
    """
    leaf = os.path.basename(folder.rstrip("\\/")) or "muestra"
    mapped = f"{WDAG_DESKTOP}\\{leaf}"
    return (
        "<Configuration>\n"
        "  <VGpu>Disable</VGpu>\n"
        f"  <Networking>{'Default' if networking else 'Disable'}</Networking>\n"
        "  <MappedFolders>\n"
        "    <MappedFolder>\n"
        f"      <HostFolder>{xmlutil.escape(folder)}</HostFolder>\n"
        "      <ReadOnly>true</ReadOnly>\n"
        "    </MappedFolder>\n"
        "  </MappedFolders>\n"
        "  <LogonCommand>\n"
        f"    <Command>explorer.exe {xmlutil.escape(mapped)}</Command>\n"
        "  </LogonCommand>\n"
        "</Configuration>\n"
    )


def launch_in_sandbox(pid: int, name: str, path: str, networking: bool = False,
                      suspend: bool = True, emit: Emit = None) -> dict:
    """
    Prepara y lanza Windows Sandbox para analizar `path` de forma aislada. Pasos:
      1. (opcional) congela el proceso en el anfitrión para que no actúe mientras tanto.
      2. genera un .wsb que mapea en SOLO LECTURA la carpeta del ejecutable.
      3. lanza WindowsSandbox.exe con esa configuración.
    El binario queda PREPARADO en la VM pero no se ejecuta solo. Devuelve el detalle de cada paso.
    Solo puede haber una instancia de Windows Sandbox a la vez.
    """
    _emit(emit, "+", f"Preparando análisis aislado de {name} (PID {pid}) en Windows Sandbox…")
    ok_avail, info = sandbox_available()
    if not ok_avail:
        _emit(emit, "x", info)
        raise OSError(info)
    if not path or not os.path.isfile(path):
        msg = f"No se encuentra el ejecutable de {name} (ruta: {path or 'no accesible'})"
        _emit(emit, "x", msg)
        raise FileNotFoundError(msg)

    folder = os.path.dirname(os.path.abspath(path))
    steps: List[Tuple[str, bool, str]] = []

    # 1) Congelar el proceso sospechoso en el anfitrión (mejor esfuerzo; nunca procesos críticos)
    suspended = False
    if suspend and pid:
        from ._contencion import suspend_process  # import diferido: _contencion depende de este árbol
        try:
            suspend_process(pid, name)
            suspended = True
            steps.append((f"Proceso PID {pid} congelado en el anfitrión", True, ""))
            _emit(emit, "*", f"Proceso PID {pid} congelado mientras se prepara el análisis")
        except (PermissionError, OSError, ValueError) as exc:
            steps.append((f"No se pudo congelar el PID {pid}", False, str(exc)))
            _emit(emit, "!", f"No se pudo congelar el PID {pid}: {exc}")

    # 2) Generar el .wsb
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    stem = os.path.splitext(name)[0] or "muestra"
    wsb = os.path.join(SANDBOX_DIR, f"Sandbox_{stem}_{dt.datetime.now():%Y%m%d_%H%M%S}.wsb")
    with open(wsb, "w", encoding="utf-8") as fh:
        fh.write(build_wsb(folder, networking))
    steps.append((f"Configuración generada: {os.path.basename(wsb)}", True,
                  f"carpeta mapeada en solo lectura · red {'activada' if networking else 'desactivada'}"))
    _emit(emit, "*", f"Configuración .wsb generada ({os.path.basename(wsb)})")

    # 3) Lanzar Windows Sandbox
    try:
        subprocess.Popen([info, wsb],
                         creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        steps.append(("Windows Sandbox lanzado (VM desechable y aislada)", True, ""))
        _emit(emit, "*", "Windows Sandbox lanzado: la muestra está preparada en la VM, lista para detonar")
    except Exception as exc:
        steps.append(("Lanzar Windows Sandbox", False, str(exc)))
        _emit(emit, "x", f"No se pudo lanzar Windows Sandbox: {exc}")
        raise

    return {"wsb": wsb, "folder": folder, "networking": networking, "suspended": suspended,
            "steps": [{"accion": a, "ok": ok, "detalle": d} for a, ok, d in steps]}


# ===========================================================================
# MODO FANTASMA  ·  limpieza de privacidad del equipo propio
# ===========================================================================
# Cada paso es independiente. "needs_admin" lo omite (con aviso) si no hay privilegios;
# "destructive" marca los que borran datos de forma irreversible (preview antes en la GUI).
_RECENT = r"$env:APPDATA\Microsoft\Windows\Recent"

_SCRIPT_CLIPBOARD = r"""
try { Set-Clipboard -Value ''; Write-Output 'Portapapeles vaciado' }
catch { Write-Output ("Portapapeles: " + $_.Exception.Message) }
"""

_SCRIPT_RECENT = r"""
$paths = @(
    "$env:APPDATA\Microsoft\Windows\Recent\*",
    "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*",
    "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"
)
$n = 0
foreach ($p in $paths) {
    $n += @(Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue).Count
    Remove-Item -Path $p -Force -Recurse -ErrorAction SilentlyContinue
}
Write-Output "Archivos recientes y Jump Lists eliminados: $n"
"""

_SCRIPT_RECYCLE_TEMP = r"""
try { Clear-RecycleBin -Force -ErrorAction Stop; Write-Output 'Papelera de reciclaje vaciada' }
catch { Write-Output ("Papelera: " + $_.Exception.Message) }
$temp = $env:TEMP
$before = @(Get-ChildItem -Path $temp -Force -ErrorAction SilentlyContinue).Count
Get-ChildItem -Path $temp -Force -ErrorAction SilentlyContinue |
    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
$after = @(Get-ChildItem -Path $temp -Force -ErrorAction SilentlyContinue).Count
Write-Output "Temporales del usuario: $($before - $after) elemento(s) liberado(s); $after en uso"
"""

_SCRIPT_PSHISTORY = r"""
try { Clear-History -ErrorAction SilentlyContinue } catch {}
$removed = 0
try {
    $h = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
    if ($h -and (Test-Path $h)) { Remove-Item -Path $h -Force -ErrorAction SilentlyContinue; $removed = 1 }
} catch {}
Write-Output ("Historial de PowerShell limpiado (archivo persistente eliminado: " + $removed + ")")
"""

# Prefetch: rastro de qué ejecutables se han lanzado. Vaciarlo requiere Administrador.
_SCRIPT_PREFETCH = r"""
$pf = "$env:SystemRoot\Prefetch"
$n = @(Get-ChildItem -Path "$pf\*.pf" -Force -ErrorAction SilentlyContinue).Count
Remove-Item -Path "$pf\*" -Force -Recurse -ErrorAction SilentlyContinue
Write-Output ("Prefetch: " + $n + " archivo(s) eliminados")
"""

# Registros de eventos: IRREVERSIBLE y requiere Administrador. Limpiar el registro de
# seguridad elimina también el historial legítimo de diagnóstico y auditoría del equipo.
_SCRIPT_EVENTLOGS = r"""
$logs = 'Application','System','Security'
foreach ($l in $logs) {
    try { Clear-EventLog -LogName $l -ErrorAction Stop; Write-Output ("Registro de eventos '" + $l + "' limpiado") }
    catch { Write-Output ("Registro '" + $l + "': " + $_.Exception.Message) }
}
"""

GHOST_STEPS = [  # (clave, etiqueta, requiere_admin, destructivo, ejecutor: argv(list) o script PS(str))
    ("dns", "Vaciar la caché DNS", False, False, ["ipconfig", "/flushdns"]),
    ("arp", "Vaciar la caché ARP", True, False, ["arp", "-d", "*"]),
    ("clipboard", "Limpiar el portapapeles", False, False, _SCRIPT_CLIPBOARD),
    ("ps_history", "Borrar el historial de PowerShell", False, True, _SCRIPT_PSHISTORY),
    ("recent", "Borrar archivos recientes y Jump Lists", False, True, _SCRIPT_RECENT),
    ("recycle_temp", "Vaciar la papelera y los temporales", False, True, _SCRIPT_RECYCLE_TEMP),
    ("prefetch", "Vaciar la carpeta Prefetch", True, True, _SCRIPT_PREFETCH),
    ("event_logs", "Limpiar los registros de eventos (irreversible)", True, True, _SCRIPT_EVENTLOGS),
]
GHOST_LABELS = {key: label for key, label, *_ in GHOST_STEPS}


def ghost_preview() -> Dict[str, int]:
    """
    Recuento de SOLO LECTURA de lo que borraría el Modo Fantasma, para mostrarlo en la
    confirmación antes de tocar nada. Nunca elimina.

    Devuelve {recientes, papelera, temporales, ok}. `ok` distingue un recuento REAL (True) de un
    fallo al obtenerlo (False): en ese caso los valores quedan en 0 pero NO deben presentarse como
    «no hay nada que limpiar» — son desconocidos, no un cero confirmado. (Retrocompatible: los
    consumidores que solo leen recientes/papelera/temporales siguen funcionando igual.)
    """
    script = r"""
$recent = 0
foreach ($p in @("$env:APPDATA\Microsoft\Windows\Recent\*",
                 "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*",
                 "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*")) {
    $recent += @(Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue).Count
}
$temp = @(Get-ChildItem -Path $env:TEMP -Force -ErrorAction SilentlyContinue).Count
$bin = 0
try {
    $sh = New-Object -ComObject Shell.Application
    $bin = @($sh.Namespace(0x0a).Items()).Count
} catch {}
Write-Output ("" + $recent + ";" + $bin + ";" + $temp)
"""
    counts = {"recientes": 0, "papelera": 0, "temporales": 0, "ok": False}
    try:
        rc, out, _ = powershell_raw(script, timeout=30)
        line = next((ln for ln in reversed(out.splitlines()) if ";" in ln), "")
        if line:
            recent, bin_, temp = (line.strip().split(";") + ["0", "0", "0"])[:3]
            counts = {"recientes": int(recent or 0), "papelera": int(bin_ or 0),
                      "temporales": int(temp or 0), "ok": True}
    except Exception:
        pass  # el recuento queda como no disponible (ok=False), nunca como un cero real
    return counts


def ghost_mode(options: Dict[str, bool], is_admin: bool = False, emit: Emit = None) -> dict:
    """
    Ejecuta la limpieza de privacidad. `options` activa cada paso por su clave (ver GHOST_STEPS).
    Los pasos que requieren Administrador se omiten con aviso si no lo hay. Cada paso captura la
    salida de PowerShell / la herramienta y la vuelca en la consola vía `emit`. Devuelve el detalle.
    """
    _emit(emit, "+", "Modo Fantasma: iniciando limpieza de privacidad de este equipo…")
    steps: List[Tuple[str, bool, str]] = []
    for key, label, needs_admin, _destructive, runner in GHOST_STEPS:
        if not options.get(key):
            continue
        if needs_admin and not is_admin:
            steps.append((label, False, "omitido: requiere Administrador"))
            _emit(emit, "!", f"{label}: omitido (requiere Administrador)")
            continue
        _emit(emit, "~", f"{label}…")
        try:
            # herramienta de consola (ipconfig, arp) o script PowerShell: en ambos casos se
            # transmite la salida línea a línea para la terminal en tiempo real
            argv = runner if isinstance(runner, list) else powershell_argv(runner)
            rc, _nlines = _stream(argv, emit, timeout=120)
            ok = rc == 0
            detail = "" if ok else f"código {rc}"
            steps.append((label, ok, detail))
            _emit(emit, "*" if ok else "x", f"{label}: {'hecho' if ok else detail}")
        except Exception as exc:
            steps.append((label, False, str(exc)))
            _emit(emit, "x", f"{label}: {exc}")
    done = sum(1 for _, ok, _ in steps if ok)
    _emit(emit, "*", f"Modo Fantasma completado: {done}/{len(steps)} pasos")
    return {"steps": [{"accion": a, "ok": ok, "detalle": d} for a, ok, d in steps]}


# ===========================================================================
# PROTOCOLO OMEGA  ·  restablecimiento de fábrica (herramienta nativa de Windows)
# ===========================================================================
def factory_reset(emit: Emit = None) -> dict:
    """
    Lanza la herramienta NATIVA de Windows «Restablecer este PC» (systemreset.exe -factoryreset).

    Este proyecto NO borra nada por su cuenta ni añade ninguna opción silenciosa o de borrado de
    disco: simplemente abre el asistente de restablecimiento de Windows, que vuelve a pedir
    confirmación y deja al usuario elegir si conserva o elimina sus archivos. Requiere Administrador.
    La doble confirmación (incluida la palabra "CONFIRMAR") la impone la interfaz antes de llamar aquí.
    """
    if not IS_WINDOWS:
        raise OSError("systemreset solo existe en Windows")
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "systemreset.exe")
    if not os.path.exists(exe):
        raise FileNotFoundError("No se encuentra systemreset.exe (asistente de restablecimiento de Windows)")
    _emit(emit, "!", "Protocolo Omega: abriendo el asistente de restablecimiento de Windows…")
    # Sin CREATE_NO_WINDOW: systemreset abre su propia interfaz, que vuelve a confirmar antes de actuar
    subprocess.Popen([exe, "-factoryreset"])
    _emit(emit, "*", "Asistente de restablecimiento de Windows lanzado (confirma allí para continuar)")
    return {"launched": True, "exe": exe}
