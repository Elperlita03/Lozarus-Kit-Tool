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
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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


# ===========================================================================
# HERRAMIENTAS NATIVAS DE LARGA DURACIÓN (sfc, DISM, defrag): progreso y cancelación
# ===========================================================================
_PERCENT = re.compile(r"(\d{1,3}(?:[.,]\d+)?)\s?%")


def native_exe(name: str) -> str:
    """
    Ruta absoluta de una herramienta de System32 (evita el secuestro por PATH). Con Python de 32 bits
    en Windows de 64 bits, «Sysnative» esquiva la redirección a SysWOW64, donde sfc.exe no existe.
    Si no se encuentra (o fuera de Windows), devuelve el nombre tal cual.
    """
    exe = name if name.lower().endswith(".exe") else name + ".exe"
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for sub in ("Sysnative", "System32"):
        path = os.path.join(root, sub, exe)
        if os.path.isfile(path):
            return path
    return name


def decode_output(data: bytes) -> str:
    """
    Texto de una herramienta de consola de Windows. sfc.exe escribe UTF-16LE cuando su salida va a un
    fichero (con o sin BOM); el resto usa la página OEM de la consola. El caso UTF-16 se reconoce por la
    proporción de bytes NUL (texto ASCII en UTF-16 = un NUL cada dos bytes).
    """
    if not data:
        return ""
    if data[:2] == b"\xff\xfe":  # BOM UTF-16LE
        return data[2:len(data) - (len(data) % 2)].decode("utf-16-le", errors="replace")
    sample = data[:4096]
    if len(sample) >= 4 and sample.count(0) * 3 >= len(sample):
        body = data if sample[1::2].count(0) >= sample[0::2].count(0) else data[1:]
        return body[:len(body) - (len(body) % 2)].decode("utf-16-le", errors="replace")
    return data.decode("oem" if IS_WINDOWS else "utf-8", errors="replace")


def last_percent(text: str) -> Optional[float]:
    """Último porcentaje (0-100) del texto: «Verification 45% complete.», «[===  10.0%  ]», «45 %»."""
    for raw in reversed(_PERCENT.findall(text or "")):
        try:
            value = float(raw.replace(",", "."))
        except ValueError:
            continue
        if 0.0 <= value <= 100.0:
            return value
    return None


def _drain(reader) -> bytes:
    """Lee todo lo nuevo de un fichero que otro proceso sigue escribiendo (lector sin búfer)."""
    chunks = []
    while True:
        try:
            chunk = reader.read(65536)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _tail_text(buf: bytearray, size: int = 4096) -> str:
    """Final decodificado de la salida acumulada, alineado a 2 bytes si es UTF-16 (para leer el progreso)."""
    start = max(0, len(buf) - size)
    head = bytes(buf[:4096])
    if head[:2] == b"\xff\xfe" or (len(head) >= 4 and head.count(0) * 3 >= len(head)):
        start -= start % 2
    return decode_output(bytes(buf[start:]))


def run_tool(argv: List[str], timeout: float = 3600.0, cancel: Any = None,
             on_progress: Optional[Callable[[float], None]] = None, poll_s: float = 0.5) -> Dict[str, Any]:
    """
    Ejecuta una herramienta nativa SIN shell para operaciones largas (sfc, DISM, defrag). La salida va a
    un fichero temporal, no a una tubería: una salida grande nunca bloquea al proceso. Cada `poll_s` se
    lee lo nuevo, se informa del último porcentaje impreso con `on_progress(pct)` y se detiene la
    herramienta si `cancel` (threading.Event) se activa o si supera `timeout` segundos.
    Devuelve {rc, output, cancelled, timed_out, seconds}. Nunca lanza: comando inexistente -> rc 127.
    """
    started = time.monotonic()
    res: Dict[str, Any] = {"rc": None, "output": "", "cancelled": False, "timed_out": False, "seconds": 0.0}
    flags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
    buf = bytearray()
    try:
        fd, path = tempfile.mkstemp(prefix="lozarus_tool_", suffix=".log")
    except OSError as exc:
        res.update(rc=1, output=f"No se pudo crear el fichero de salida: {exc}")
        return res
    try:
        # Lector con su PROPIO descriptor: leer por el mismo que hereda el hijo movería su posición.
        with os.fdopen(fd, "wb") as sink, open(path, "rb", buffering=0) as reader:
            try:
                proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT,
                                        creationflags=flags)
            except FileNotFoundError:
                res.update(rc=127, output=f"Comando no disponible: {argv[0]}")
                return res
            except OSError as exc:
                res.update(rc=1, output=f"{type(exc).__name__}: {exc}")
                return res
            shown = None
            while True:
                rc = proc.poll()
                buf += _drain(reader)
                if on_progress is not None and buf:
                    pct = last_percent(_tail_text(buf))
                    if pct is not None and pct != shown:
                        shown = pct
                        try:
                            on_progress(pct)
                        except Exception:  # noqa: BLE001  (un fallo de quien escucha no detiene la herramienta)
                            pass
                if rc is not None:
                    break
                if cancel is not None and cancel.is_set():
                    res["cancelled"] = True
                elif time.monotonic() - started > timeout:
                    res["timed_out"] = True
                if res["cancelled"] or res["timed_out"]:
                    proc.kill()
                    try:
                        proc.wait(15)
                    except subprocess.TimeoutExpired:
                        pass
                    break
                if cancel is not None:
                    cancel.wait(poll_s)  # despierta al instante si se cancela
                else:
                    time.sleep(poll_s)
            buf += _drain(reader)
            res["rc"] = proc.returncode
    except Exception as exc:  # noqa: BLE001  (E/S del fichero temporal)
        res.update(rc=res["rc"] if res["rc"] is not None else 1, output=f"{type(exc).__name__}: {exc}")
        return res
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
        res["seconds"] = round(time.monotonic() - started, 1)
    res["output"] = decode_output(bytes(buf)).strip()
    return res


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
