# -*- coding: utf-8 -*-
"""
Modo Fantasma — herramientas base de privacidad y limpieza para Lozarus. Todo LOCAL sobre el equipo
propio y SIN privilegios:

  · Trituradora de archivos: sobrescribe con bytes aleatorios un fichero que elige la persona y lo
    borra (irreversible; la GUI confirma antes).
  · Portapapeles (anti-clipper): vaciarlo al instante y vigilar si se copian datos que PARECEN
    sensibles (frase semilla, dirección cripto, clave, tarjeta). La vigilancia solo DETECTA y avisa:
    no intercepta ni impide un clipper; para eso haría falta un driver/privilegios.
  · Limpiar temporales (%TEMP%): borra los ficheros de la carpeta de temporales del usuario que no
    estén bloqueados y cuenta cuántos. Los ficheros en uso se omiten y se informa.

Funciones aisladas de Qt para poder probarlas sin interfaz. Nada se borra sin que la persona lo pida.
"""

import os
import re
import secrets
import sys
import tempfile


# ---------------------------------------------------------------------------------------------
# Trituradora de archivos
# ---------------------------------------------------------------------------------------------
def shred_file(path, passes=1, chunk_size=1 << 20):
    """
    Sobrescribe el contenido del archivo con bytes aleatorios (`passes` pasadas) y lo elimina.
    Solo opera sobre un fichero regular existente. Devuelve dict {ok, path, bytes, passes, error}.
    Irreversible: la persona elige el archivo y confirma en la GUI. Nunca lanza.

    Nota honesta: en discos SSD con wear-leveling la sobrescritura no garantiza el borrado físico de
    todas las copias internas; para eso se requiere cifrado de disco o borrado seguro del fabricante.
    """
    res = {"ok": False, "path": path, "bytes": 0, "passes": max(1, int(passes)),
           "renombrado": False, "error": ""}
    try:
        if not os.path.isfile(path):
            res["error"] = "No es un archivo regular o no existe."
            return res
        size = os.path.getsize(path)
        res["bytes"] = size
        if size > 0:
            with open(path, "r+b", buffering=0) as fh:
                for _ in range(res["passes"]):
                    fh.seek(0)
                    restante = size
                    while restante > 0:
                        n = min(chunk_size, restante)
                        fh.write(secrets.token_bytes(n))
                        restante -= n
                    fh.flush()
                    os.fsync(fh.fileno())
        # Antes de borrar: renombra a un nombre aleatorio y pone atime/mtime a la época 0, para que el
        # nombre y las marcas de tiempo originales no queden a la vista en la MFT tras el borrado.
        destino = path
        carpeta = os.path.dirname(path) or "."
        aleatorio = os.path.join(carpeta, secrets.token_hex(16))
        try:
            os.replace(path, aleatorio)      # renombrado atómico dentro de la misma carpeta
            destino = aleatorio
            res["renombrado"] = True
            try:
                os.utime(aleatorio, (0, 0))  # atime/mtime = 1970-01-01
            except OSError:
                pass
        except OSError:
            pass                              # si no se pudo renombrar, al menos se borra abajo
        os.remove(destino)
        res["ok"] = True
    except PermissionError:
        res["error"] = "Archivo bloqueado o sin permisos (puede estar en uso por otro programa)."
    except Exception as exc:  # noqa: BLE001
        res["error"] = f"{type(exc).__name__}: {exc}"
    return res


# ---------------------------------------------------------------------------------------------
# Portapapeles (anti-clipper)
# ---------------------------------------------------------------------------------------------
def clear_clipboard():
    """Vacía el portapapeles de Windows (sin privilegios). Devuelve (ok, mensaje). Nunca lanza."""
    if sys.platform != "win32":
        return False, "Solo disponible en Windows."
    try:
        _ctypes, u, _k = _clipboard_api()
        if not u.OpenClipboard(None):
            return False, "No se pudo abrir el portapapeles (otro programa lo tiene bloqueado)."
        try:
            u.EmptyClipboard()
        finally:
            u.CloseClipboard()
        return True, "Portapapeles vaciado."
    except Exception as exc:  # noqa: BLE001
        return False, f"No se pudo vaciar el portapapeles: {exc}"


_CLIPBOARD_API = None


def _clipboard_api():
    """
    user32/kernel32 PROPIOS (WinDLL privados) con prototipos correctos para 64 bits. Sin declarar
    restype, ctypes devuelve los HANDLE como int de 32 bits: GetClipboardData truncaba el handle y
    GlobalLock desreferenciaba basura → violación de acceso (segfault) en cuanto el portapapeles
    contenía texto. Al ser instancias privadas no alteran los prototipos de `ctypes.windll`.
    """
    global _CLIPBOARD_API
    if _CLIPBOARD_API is None:
        import ctypes
        from ctypes import wintypes
        u = ctypes.WinDLL("user32", use_last_error=True)
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        u.OpenClipboard.argtypes, u.OpenClipboard.restype = [wintypes.HWND], wintypes.BOOL
        u.CloseClipboard.argtypes, u.CloseClipboard.restype = [], wintypes.BOOL
        u.EmptyClipboard.argtypes, u.EmptyClipboard.restype = [], wintypes.BOOL
        u.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
        u.IsClipboardFormatAvailable.restype = wintypes.BOOL
        u.GetClipboardData.argtypes, u.GetClipboardData.restype = [wintypes.UINT], wintypes.HANDLE
        k.GlobalLock.argtypes, k.GlobalLock.restype = [wintypes.HGLOBAL], wintypes.LPVOID
        k.GlobalUnlock.argtypes, k.GlobalUnlock.restype = [wintypes.HGLOBAL], wintypes.BOOL
        _CLIPBOARD_API = (ctypes, u, k)
    return _CLIPBOARD_API


def read_clipboard_text():
    """Lee el texto Unicode del portapapeles, o None si no hay texto/no se pudo. Best-effort; no lanza."""
    if sys.platform != "win32":
        return None
    try:
        ctypes, u, k = _clipboard_api()
        CF_UNICODETEXT = 13
        if not u.OpenClipboard(None):
            return None
        try:
            if not u.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return None
            handle = u.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None
            ptr = k.GlobalLock(handle)
            if not ptr:
                return None
            try:
                return ctypes.wstring_at(ptr)
            finally:
                k.GlobalUnlock(handle)
        finally:
            u.CloseClipboard()
    except Exception:  # noqa: BLE001
        return None


# Patrones de datos que, al copiarse, conviene avisar (no es prevención: solo detección).
_PATRONES = [
    ("Dirección Bitcoin", re.compile(r"\b(?:bc1[0-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("Dirección/clave Ethereum", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("Clave privada (hex de 64)", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("Token/clave de API", re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")),
    ("Posible tarjeta de crédito", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
]


def looks_sensitive(text):
    """
    Heurística pura: ¿el texto PARECE un dato sensible (frase semilla, dirección cripto, clave,
    tarjeta)? Devuelve (bool, etiqueta). NO previene un clipper; solo clasifica para avisar/registrar.
    """
    if not text or not isinstance(text, str):
        return False, ""
    t = text.strip()
    if not t:
        return False, ""
    muestra = t[:5000]

    # Frase semilla: 12–24 palabras alfabéticas cortas y poco más (típico BIP-39).
    palabras = muestra.split()
    if 12 <= len(palabras) <= 24:
        alfa = [p for p in palabras if re.fullmatch(r"[a-zA-Z]{3,8}", p)]
        if len(alfa) >= max(12, int(len(palabras) * 0.8)):
            return True, "Posible frase semilla (12–24 palabras)"

    for etiqueta, rx in _PATRONES:
        m = rx.search(muestra)
        if not m:
            continue
        if etiqueta == "Posible tarjeta de crédito":
            digitos = re.sub(r"\D", "", m.group())
            if not (13 <= len(digitos) <= 19):
                continue
        return True, etiqueta
    return False, ""


# Direcciones cripto reconocidas como contenido ÚNICO del portapapeles (para el anti-swap).
_RX_BTC = re.compile(r"^(?:bc1[0-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
_RX_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")


def crypto_address(text):
    """
    Si el texto (recortado) es EXACTAMENTE una dirección cripto, devuelve (tipo, dirección); si no,
    (None, ""). Pura. `tipo` ∈ {'BTC','ETH'}. Base del anti-swap (caza de clippers).
    """
    if not text or not isinstance(text, str):
        return None, ""
    t = text.strip()
    if _RX_ETH.match(t):
        return "ETH", t
    if _RX_BTC.match(t):
        return "BTC", t
    return None, ""


def is_hijack_swap(prev, new, delta_seconds, window=1.5):
    """
    ¿El portapapeles pasó de UNA dirección cripto a OTRA distinta en menos de `window` segundos? Es el
    patrón típico de un clipper que sustituye la dirección copiada por la del atacante. Función pura.
    """
    if prev is None or new is None or delta_seconds is None:
        return False
    if delta_seconds > window:
        return False
    k_prev, a_prev = crypto_address(prev)
    k_new, a_new = crypto_address(new)
    return bool(k_prev and k_new and a_prev != a_new)


# ---------------------------------------------------------------------------------------------
# Limpieza de temporales
# ---------------------------------------------------------------------------------------------
def temp_dir():
    """Carpeta de temporales del usuario (%TEMP% / %TMP% / tempfile)."""
    return os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()


def clean_temp(base=None):
    """
    Borra los ficheros de la carpeta de temporales que NO estén bloqueados y quita las subcarpetas
    que queden vacías. Los ficheros en uso se omiten (no se fuerza). Devuelve dict
    {ok, eliminados, omitidos, bytes, dir, error}. Nunca lanza por un fichero suelto.
    """
    base = base or temp_dir()
    res = {"ok": False, "eliminados": 0, "omitidos": 0, "bytes": 0, "dir": base, "error": ""}
    if not base or not os.path.isdir(base):
        res["error"] = "No se encontró la carpeta de temporales."
        return res
    try:
        for root, dirs, files in os.walk(base, topdown=False):
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    sz = os.path.getsize(fp)
                    os.remove(fp)
                    res["eliminados"] += 1
                    res["bytes"] += sz
                except Exception:  # noqa: BLE001  (bloqueado / en uso / sin permisos)
                    res["omitidos"] += 1
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))  # solo si quedó vacía
                except Exception:  # noqa: BLE001
                    pass
        res["ok"] = True
    except Exception as exc:  # noqa: BLE001
        res["error"] = f"{type(exc).__name__}: {exc}"
    return res


# ---------------------------------------------------------------------------------------------
# Optimización de RAM (vaciar working sets)
# ---------------------------------------------------------------------------------------------
def empty_working_sets():
    """
    Pide a Windows que vacíe el working set (RAM física residente) de los procesos del usuario que
    sean accesibles, con EmptyWorkingSet. Sin privilegios: los procesos del sistema se omiten. Mide
    los bytes realmente residentes antes/después y suma el descenso. Devuelve
    {ok, procesos, omitidos, liberado_mb, error}. Nunca lanza.

    Nota honesta: es una optimización TEMPORAL. La RAM «liberada» vuelve a crecer en cuanto cada
    proceso necesita de nuevo sus páginas; no corrige fugas ni acelera de forma permanente.
    """
    res = {"ok": False, "procesos": 0, "omitidos": 0, "liberado_mb": 0.0, "error": ""}
    if sys.platform != "win32":
        res["error"] = "Solo disponible en Windows."
        return res
    try:
        import ctypes

        import psutil
    except Exception as exc:  # noqa: BLE001
        res["error"] = f"psutil/ctypes no disponible: {exc}"
        return res

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_SET_QUOTA = 0x0100
    from ctypes import wintypes
    # WinDLL privados (misma convención que _contencion.py): prototipos de 64 bits correctos sin
    # alterar los de `ctypes.windll`, que usan auditor.py y 01_sistema.py.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL
    psapi.EmptyWorkingSet.argtypes = [ctypes.c_void_p]
    psapi.EmptyWorkingSet.restype = wintypes.BOOL

    liberado = 0
    try:
        for proc in psutil.process_iter(["pid"]):
            pid = proc.info.get("pid")
            if not pid or pid in (0, 4):   # Idle (0) y System (4): no accesibles / sin sentido
                continue
            try:
                antes = proc.memory_info().rss
            except Exception:  # noqa: BLE001
                res["omitidos"] += 1
                continue
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, False, pid)
            if not handle:
                res["omitidos"] += 1
                continue
            try:
                if psapi.EmptyWorkingSet(handle):
                    try:
                        despues = proc.memory_info().rss
                    except Exception:  # noqa: BLE001
                        despues = antes
                    if antes > despues:
                        liberado += (antes - despues)
                    res["procesos"] += 1
                else:
                    res["omitidos"] += 1
            finally:
                kernel32.CloseHandle(handle)
        res["liberado_mb"] = round(liberado / (1024 * 1024), 1)
        res["ok"] = True
    except Exception as exc:  # noqa: BLE001
        res["error"] = f"{type(exc).__name__}: {exc}"
    return res
