# -*- coding: utf-8 -*-
"""
Utilidades de solo lectura compartidas por los plugins: comandos y PowerShell,
registro de Windows, ficheros, red y Centro de seguridad de Windows.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import shutil
import socket
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from ._base import IS_LINUX, IS_WINDOWS, AuditContext, CheckSkipped, CommandError, first_line

try:
    import psutil  # pip install psutil  -> enumeración precisa de sockets/procesos
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False

if IS_WINDOWS:
    import winreg

    _HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}


# ===========================================================================
# UTILIDADES DEL SISTEMA (todas de solo lectura)
# ===========================================================================
def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def build_relaunch_command() -> Tuple[str, str]:
    """
    Devuelve (ejecutable, parámetros) para relanzar el proceso ACTUAL. Función pura y testable: NO
    ejecuta nada. `parámetros` ya viene citado para ShellExecuteW (el guion se pasa como ruta
    absoluta). Pensada para el caso habitual `py gui_qt.py`.
    """
    import sys as _sys

    exe = _sys.executable
    argv = list(_sys.argv)
    if argv:
        argv[0] = os.path.abspath(argv[0])
    params = " ".join('"{}"'.format(a) if (not a or " " in a) else a for a in argv)
    return exe, params


def request_admin_relaunch() -> Tuple[bool, str]:
    """
    Relanza el proceso actual con elevación UAC (ShellExecuteW 'runas'). Devuelve (ok, mensaje). NO
    cierra el proceso actual: eso lo decide quien llama. Solo Windows; nunca lanza.
    """
    if not IS_WINDOWS:
        return False, "La elevación UAC solo está disponible en Windows."
    try:
        exe, params = build_relaunch_command()
        ret = int(ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1))
        if ret > 32:
            return True, "Proceso elevado lanzado; cerrando esta instancia."
        # 5 = ERROR_ACCESS_DENIED: la persona canceló el aviso de UAC.
        return False, ("Cancelaste el aviso de UAC." if ret == 5 else f"ShellExecuteW devolvió {ret}.")
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Ejecuta un comando de consulta SIN shell y devuelve (código, stdout, stderr)."""
    encoding = "oem" if IS_WINDOWS else "utf-8"  # las herramientas de consola de Windows usan la página OEM
    # Sin ventana de consola: desde la GUI (o un ejecutable sin consola) cada comando
    # abriría y cerraría una ventana negra
    flags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, creationflags=flags)
    except FileNotFoundError:
        raise CheckSkipped(f"Comando no disponible: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise CommandError(f"'{os.path.basename(cmd[0])}' superó el tiempo límite de {timeout} s")
    return (proc.returncode,
            proc.stdout.decode(encoding, errors="replace"),
            proc.stderr.decode(encoding, errors="replace"))


# Preámbulo común de los scripts PowerShell: sin barras de progreso y una
# función Out-Json que escapa caracteres no ASCII, de modo que la salida no
# depende de la página de códigos de la consola (es-ES, en-US...).
_PS_PRELUDE = r"""
$ProgressPreference = 'SilentlyContinue'
function Out-Json($InputObject) {
    $json = ConvertTo-Json -InputObject $InputObject -Depth 6 -Compress
    [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
}
"""


def _powershell_exe() -> Optional[str]:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    # 'Sysnative' evita la redirección a SysWOW64 si Python es de 32 bits en Windows de 64 bits
    for sub in ("Sysnative", "System32"):
        path = os.path.join(root, sub, "WindowsPowerShell", "v1.0", "powershell.exe")
        if os.path.exists(path):
            return path
    return shutil.which("powershell") or shutil.which("pwsh")


def powershell(script: str, timeout: int = 60) -> Any:
    """Ejecuta un script PowerShell de consulta y devuelve su salida JSON decodificada."""
    exe = _powershell_exe()
    if not exe:
        raise CheckSkipped("PowerShell no está disponible")
    # -EncodedCommand evita cualquier problema de comillas al pasar el script
    encoded = base64.b64encode((_PS_PRELUDE + script).encode("utf-16-le")).decode("ascii")
    rc, out, err = run_cmd([exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           timeout=timeout)
    out = out.strip()
    if not out:
        if rc != 0:
            raise CommandError(first_line(err) or f"PowerShell terminó con código {rc}")
        return None
    try:
        return json.loads(out.splitlines()[-1])
    except json.JSONDecodeError:
        raise CommandError(f"Respuesta inesperada de PowerShell: {out[:150]}")


def powershell_raw(script: str, timeout: int = 90) -> Tuple[int, str, str]:
    """
    Ejecuta un script PowerShell de ACCIÓN y devuelve (código, stdout, stderr) como texto, sin
    interpretar JSON. Para operaciones cuyo resultado se muestra tal cual en la consola de Lozarus
    (a diferencia de powershell(), que es para consultas que devuelven datos). Lanza CheckSkipped
    si no hay PowerShell.
    """
    return run_cmd(powershell_argv(script), timeout=timeout)


def powershell_argv(script: str) -> List[str]:
    """
    Línea de comandos (argv) para ejecutar un script PowerShell. Útil para transmitir la salida
    en directo con subprocess.Popen (consola de terminal en tiempo real), en lugar de esperar al
    final como powershell()/powershell_raw(). Lanza CheckSkipped si no hay PowerShell.
    """
    exe = _powershell_exe()
    if not exe:
        raise CheckSkipped("PowerShell no está disponible")
    encoded = base64.b64encode((_PS_PRELUDE + script).encode("utf-16-le")).decode("ascii")
    return [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


def as_list(value: Any) -> list:
    """ConvertTo-Json devuelve un objeto suelto si hay un solo elemento: normaliza a lista."""
    if value is None or value == {}:  # PS 5.1 serializa una salida vacía como {}
        return []
    if isinstance(value, dict) and set(value) == {"value", "Count"}:  # peculiaridad de PS 5.1
        return list(value["value"])
    return value if isinstance(value, list) else [value]


def reg_get(path: str, name: str, default: Any = None) -> Any:
    """Lee un valor del registro de Windows (vista de 64 bits). Devuelve default si no existe."""
    hive, _, subkey = path.partition("\\")
    try:
        with winreg.OpenKey(_HIVES[hive], subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return default


def reg_key_exists(path: str) -> bool:
    hive, _, subkey = path.partition("\\")
    try:
        with winreg.OpenKey(_HIVES[hive], subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except FileNotFoundError:
        return False
    except PermissionError:
        return True  # existe, aunque no podamos leerla


def windows_build() -> int:
    try:
        return int(reg_get(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild", "0"))
    except (ValueError, OSError):
        return 0


def read_text(path: str) -> Optional[str]:
    """Lee un fichero de texto. None si no existe; PermissionError se propaga."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def tail_text(path: str, max_bytes: int) -> str:
    """Lee solo los últimos max_bytes de un fichero (logs grandes)."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        fh.seek(max(0, fh.tell() - max_bytes))
        return fh.read().decode("utf-8", errors="replace")


def get_local_ip() -> Optional[str]:
    """IP de la interfaz con ruta por defecto (connect UDP: no envía ningún paquete)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))  # TEST-NET-1 (RFC 5737)
            return s.getsockname()[0]
    except OSError:
        return None


def get_default_gateway() -> Optional[str]:
    try:
        if IS_WINDOWS:
            _, out, _ = run_cmd(["route", "print", "-4", "0.0.0.0"])
            routes = re.findall(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(\d+)",
                                out, re.M)
            return min(routes, key=lambda r: int(r[1]))[0] if routes else None
        if IS_LINUX:
            if shutil.which("ip"):
                _, out, _ = run_cmd(["ip", "route", "show", "default"])
                m = re.search(r"default via (\S+)", out)
                if m:
                    return m.group(1)
            for line in (read_text("/proc/net/route") or "").splitlines()[1:]:
                cols = line.split()
                if len(cols) > 2 and cols[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<L", int(cols[2], 16)))
    except (CheckSkipped, CommandError, OSError, ValueError):
        pass
    return None


def security_center(ctx: AuditContext) -> Dict[str, list]:
    """Antivirus/firewalls registrados en el Centro de seguridad de Windows (solo clientes)."""
    def load() -> Dict[str, list]:
        script = r"""
$classes = @{ av = 'AntiVirusProduct'; fw = 'FirewallProduct' }
$r = @{ av = @(); fw = @() }
foreach ($k in @($classes.Keys)) {
    try {
        $r[$k] = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName $classes[$k] -ErrorAction Stop |
            ForEach-Object { @{ name = [string]$_.displayName; state = [int64]$_.productState } })
    } catch {}
}
Out-Json $r
"""
        try:
            data = powershell(script) or {}
        except (CommandError, CheckSkipped):
            data = {}
        return {k: as_list(data.get(k)) for k in ("av", "fw")}

    return ctx.cached("security_center", load)


def wsc_product_enabled(state: int) -> bool:
    """Decodifica productState del Centro de seguridad: byte central 0x10/0x11 = activo."""
    return ((int(state) >> 8) & 0xFF) in (0x10, 0x11)


# ===========================================================================
# FIRMAS DIGITALES Y RUTAS GRABABLES
# (compartido por los plugins de persistencia e inyecciones, de solo lectura)
# ===========================================================================
# Fragmentos de ruta (en minúsculas) grabables por un usuario SIN privilegios: el malware
# suele vivir aquí porque no necesita permisos de administrador para escribir. Una vía de
# arranque o una DLL inyectada que apunte a estas carpetas es muy sospechosa.
WRITABLE_LOCATIONS = [
    ("\\appdata\\", "AppData del usuario"),
    ("\\local\\temp\\", "carpeta temporal del usuario"),
    ("\\windows\\temp\\", "carpeta temporal de Windows"),
    ("\\downloads\\", "carpeta Descargas"),
    ("\\$recycle.bin\\", "Papelera de reciclaje"),
    ("\\users\\public\\", "carpeta pública de usuarios"),
]
# Nota: ProgramData se deja fuera a propósito. Aunque un usuario pueda crear ficheros en su
# raíz, es donde software legítimo (el propio Microsoft Defender, actualizadores...) guarda sus
# ejecutables en subcarpetas protegidas; tratarla como "grabable" generaba falsos positivos.
# El malware que viva en ProgramData se detecta igualmente por carecer de firma válida.


def writable_location(path: str) -> Optional[str]:
    """Si la ruta está en una carpeta grabable sin privilegios (AppData, Temp, Descargas,
    Papelera o carpeta pública), devuelve una etiqueta legible; si no, None."""
    low = os.path.normcase(path or "")
    for fragment, label in WRITABLE_LOCATIONS:
        if fragment in low:
            return label
    return None


_SIGNATURE_BATCH = 60  # rutas por llamada a PowerShell (evita una línea de comando gigante)

# Etiquetas legibles del Status de Get-AuthenticodeSignature (para el detalle del hallazgo)
_SIGNATURE_LABELS = {
    "Valid": "válida", "NotSigned": "sin firma", "HashMismatch": "INVÁLIDA (fichero modificado)",
    "NotTrusted": "no confiable", "UnknownError": "error de verificación",
    "NotSupportedFileFormat": "formato sin firma", "Error": "no verificable", "": "desconocida",
}


def ps_string_array(values) -> str:
    """
    Construye una expresión PowerShell que evalúa a un array de cadenas, pasando cada valor como
    DATO codificado en base64 (nunca como código). Base64 solo contiene [A-Za-z0-9+/=], así que
    ninguna comilla (simple, doble o tipográfica), acento grave, '$(...)' ni salto de línea del
    valor puede cerrar la cadena y ejecutarse: cierra la vía de inyección al pasar rutas no
    confiables (claves Run, tareas, drivers, DLL o ejecutables de procesos) a PowerShell.

    Sustituye al antiguo escape de comillas, que solo neutralizaba la comilla simple ASCII.
    """
    parts = []
    for value in values:
        b64 = base64.b64encode(str(value).encode("utf-16-le")).decode("ascii")
        parts.append("[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + b64 + "'))")
    return "@(" + ",".join(parts) + ")"


def authenticode_signatures(paths, timeout: int = 120) -> Dict[str, Tuple[str, str]]:
    """
    Verifica la firma Authenticode de varias rutas EN BLOQUE (el mismo enfoque que _monitor.py)
    y devuelve {ruta: (estado, firmante)}. `estado` es el Status de Get-AuthenticodeSignature
    ('Valid', 'NotSigned', 'HashMismatch', 'NotTrusted'...) y `firmante`, el nombre común del
    certificado (cadena vacía si no está firmado).

    Verificar firmas es LENTO (hash del fichero + validación de cadena): pásale solo las rutas
    que de verdad quieras comprobar. Si no hay PowerShell, devuelve {} sin lanzar.
    """
    unique = [p for p in dict.fromkeys(paths) if p]  # sin duplicados, conservando el orden
    results: Dict[str, Tuple[str, str]] = {}
    for start in range(0, len(unique), _SIGNATURE_BATCH):
        batch = unique[start:start + _SIGNATURE_BATCH]
        script = (
            "$out = foreach ($p in " + ps_string_array(batch) + ") {\n"
            "  $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue\n"
            "  $who = ''\n"
            "  if ($s -and $s.SignerCertificate) { $who = $s.SignerCertificate.GetNameInfo("
            "[System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }\n"
            "  @{ p = $p; s = $(if ($s) { [string]$s.Status } else { '' }); who = $who }\n"
            "}\nOut-Json @($out)\n")
        try:
            data = powershell(script, timeout=timeout) or []
        except (CommandError, CheckSkipped):
            data = []
        for row in as_list(data):
            if isinstance(row, dict) and row.get("p"):
                results[row["p"]] = (row.get("s") or "", row.get("who") or "")
        for path in batch:
            results.setdefault(path, ("Error", ""))  # la verificación falló: lo tratamos como sin firma fiable
    return results


def is_trusted_microsoft(status: str, signer: str) -> bool:
    """True si la firma es válida y de Microsoft (binario de confianza del sistema)."""
    return status == "Valid" and "microsoft" in (signer or "").lower()


def is_valid_signature(status: str) -> bool:
    """True si el fichero tiene una firma Authenticode válida (de cualquier editor de confianza)."""
    return status == "Valid"


def signature_label(status: str, signer: str) -> str:
    """Descripción legible del estado de la firma para el detalle del hallazgo."""
    text = _SIGNATURE_LABELS.get(status, status or "desconocida")
    return f"firma {text} · {signer}" if signer else f"firma {text}"
