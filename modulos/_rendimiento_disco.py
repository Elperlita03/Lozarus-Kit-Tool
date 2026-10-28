# -*- coding: utf-8 -*-
"""
modulos/_rendimiento_disco.py · LOZARUS KIT TOOL

Saneamiento y rendimiento del ALMACENAMIENTO. Todo local, sobre el equipo propio:

  · Análisis de espacio: volúmenes montados (uso, libre, sistema de archivos y nivel), discos físicos
    (SSD/HDD y salud que informa Windows) y consumidores de espacio de la carpeta del usuario (carpetas
    conocidas y archivos más grandes). Solo lectura.
  · Optimización de archivos temporales del SISTEMA: %SystemRoot%\\Temp, descargas antiguas de Windows
    Update (más de 10 días y nunca mientras Windows instala actualizaciones) e informes de errores.
  · Limpieza segura de cachés residuales del USUARIO: %TEMP%, miniaturas del Explorador, INetCache,
    cachés de Chrome / Edge / Brave / Firefox (solo con el navegador cerrado), sombreadores de la GPU y
    volcados de bloqueo (estos últimos desmarcados por defecto: conservan pruebas de los fallos).
  · Optimización nativa de la unidad: defrag /O (TRIM en SSD, desfragmentación en HDD).

Garantías de la limpieza «segura»:
  1. Solo ubicaciones de un catálogo cerrado; cada raíz se valida antes de tocar nada: absoluta, nunca la
     raíz de una unidad, el perfil, Windows, Archivos de programa ni una carpeta personal (Documentos,
     Escritorio, Descargas…), y %TEMP% tiene que parecer una carpeta de temporales.
  2. Nunca se siguen enlaces simbólicos ni uniones (junctions). En Windows cada borrado se hace por
     HANDLE tras comprobar la ruta REAL del archivo abierto (GetFinalPathNameByHandleW): una unión creada
     a mitad de la limpieza no puede desviar el borrado fuera de su carpeta, aunque Lozarus esté elevado.
     En Linux/macOS el recorrido y el borrado van por descriptores de carpeta (os.fwalk + dir_fd).
  3. Antigüedad mínima: los temporales recientes (de un instalador en marcha) se respetan.
  4. Lo bloqueado o sin permisos se omite y se cuenta; nunca se fuerza.
  5. La caché de un navegador abierto no se toca; nunca cookies, historial, sesiones ni contraseñas.
  6. Lo que requiere Administrador se omite sin él: no se intenta ni se inventa un éxito.

Funciones aisladas de Qt (pruebas en tests/test_rendimiento_disco.py). Ninguna lanza: devuelven datos.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import glob
import heapq
import ntpath
import os
import re
import stat as stat_mod
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from ._base import IS_WINDOWS
from ._salud_sistema import physical_disks, summary_lines
from ._utilidades import HAS_PSUTIL, is_admin, native_exe, psutil, run_tool

Emit = Optional[Callable[[str, str], None]]

GB = 1024 ** 3
AGE_CHOICES = (24, 72, 168)       # antigüedad mínima de los temporales que ofrece la interfaz (horas)
DEFAULT_AGE_H = 24
WU_AGE_H = 240                    # Windows Update: solo descargas de más de 10 días
SCAN_DEADLINE_S = 25.0            # tope por categoría: un árbol enorme no congela el análisis
CLEAN_DEADLINE_S = 120.0
SPACE_DEADLINE_S = 30.0
OPTIMIZE_TIMEOUT_S = 4 * 3600     # defrag de un HDD grande puede tardar horas
_REPARSE = 0x400                  # FILE_ATTRIBUTE_REPARSE_POINT
_CLOUD = 0x1000 | 0x40000 | 0x400000   # OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS («solo en línea»)
_SKIP_FS = frozenset({"squashfs", "tmpfs", "devtmpfs", "proc", "sysfs"})


@dataclass(frozen=True)
class Target:
    """Categoría de limpieza del catálogo cerrado."""
    key: str
    scope: str                       # "system" (temporales del sistema) | "user" (cachés del usuario)
    title: str
    desc: str
    admin: bool = False
    age_h: Optional[float] = None    # None: la antigüedad elegida en la interfaz · número: fija (0 = cualquiera)
    default: bool = True             # marcada por defecto en la interfaz
    processes: Tuple[str, ...] = ()  # si alguno está en ejecución, la caché está en uso: se omite
    patterns: Tuple[str, ...] = ()   # comodines del nombre de archivo (vacío = todos)
    recursive: bool = True
    own_files_only: bool = False     # Linux/macOS: solo archivos del usuario actual (/tmp es compartido)


_BROWSER_NOTE = "nunca cookies, historial, sesiones ni contraseñas; requiere el navegador cerrado"
TARGETS: List[Target] = [
    Target("system_temp", "system", "Temporales de Windows",
           r"Archivos temporales de servicios e instaladores en %SystemRoot%\Temp.", admin=True),
    Target("wu_cache", "system", "Descargas de Windows Update",
           "Paquetes ya descargados por Windows Update de más de 10 días; nunca mientras Windows instala.",
           admin=True, age_h=WU_AGE_H, processes=("tiworker.exe", "trustedinstaller.exe")),
    Target("wer_system", "system", "Informes de errores del sistema",
           "Cola y archivo de Windows Error Reporting de todos los usuarios. Desmarcada: sirve para diagnosticar.",
           admin=True, default=False),
    Target("user_temp", "user", "Temporales del usuario",
           "%TEMP%: restos de instaladores, actualizadores y programas.", own_files_only=True),
    Target("thumbnails", "user", "Miniaturas e iconos del Explorador",
           "thumbcache / iconcache: Windows los regenera al volver a abrir las carpetas.", age_h=0,
           patterns=("thumbcache_*.db", "iconcache_*.db") if IS_WINDOWS else (), recursive=not IS_WINDOWS),
    Target("inet_cache", "user", "Caché de Internet de Windows",
           "INetCache: copias temporales de WinINet/WebView y de adjuntos abiertos desde Outlook."),
    Target("chrome", "user", "Caché de Google Chrome", f"Caché web, de código y de GPU de cada perfil; {_BROWSER_NOTE}.",
           age_h=0, processes=("chrome.exe", "chrome")),
    Target("edge", "user", "Caché de Microsoft Edge", f"Caché web, de código y de GPU de cada perfil; {_BROWSER_NOTE}.",
           age_h=0, processes=("msedge.exe", "msedge", "microsoft-edge")),
    Target("brave", "user", "Caché de Brave", f"Caché web, de código y de GPU de cada perfil; {_BROWSER_NOTE}.",
           age_h=0, processes=("brave.exe", "brave")),
    Target("firefox", "user", "Caché de Mozilla Firefox", f"cache2 de cada perfil (datos locales); {_BROWSER_NOTE}.",
           age_h=0, processes=("firefox.exe", "firefox")),
    Target("shader_cache", "user", "Sombreadores de la GPU",
           "DirectX, NVIDIA y AMD. Se regeneran; el primer arranque de cada juego puede tardar algo más.",
           age_h=0, default=False),
    Target("crash_dumps", "user", "Volcados e informes de errores del usuario",
           "CrashDumps y WER del usuario. Desmarcada: conservan pruebas si un programa falla.", default=False),
]
BY_KEY: Dict[str, Target] = {t.key: t for t in TARGETS}


def _chromium(base: str, windows: bool) -> Tuple[Tuple[str, str], ...]:
    if windows:
        return tuple(("LOCALAPPDATA", f"{base}\\{sub}") for sub in
                     (r"*\Cache", r"*\Code Cache", r"*\GPUCache", "ShaderCache", "GrShaderCache"))
    return tuple(("XDG_CACHE_HOME", f"{base}/{sub}") for sub in ("*/Cache", "*/Code Cache", "*/GPUCache"))


# Raíces de cada categoría: (base, ruta relativa con comodines). La base sale del entorno y se escapa para glob.
_ROOTS_WIN: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "system_temp": (("SystemRoot", "Temp"),),
    "wu_cache": (("SystemRoot", r"SoftwareDistribution\Download"),),
    "wer_system": (("ProgramData", r"Microsoft\Windows\WER\ReportArchive"),
                   ("ProgramData", r"Microsoft\Windows\WER\ReportQueue")),
    "user_temp": (("TEMP", ""),),
    "thumbnails": (("LOCALAPPDATA", r"Microsoft\Windows\Explorer"),),
    "inet_cache": (("LOCALAPPDATA", r"Microsoft\Windows\INetCache"),),
    "chrome": _chromium(r"Google\Chrome\User Data", True),
    "edge": _chromium(r"Microsoft\Edge\User Data", True),
    "brave": _chromium(r"BraveSoftware\Brave-Browser\User Data", True),
    "firefox": (("LOCALAPPDATA", r"Mozilla\Firefox\Profiles\*\cache2"),),
    "shader_cache": (("LOCALAPPDATA", "D3DSCache"), ("LOCALAPPDATA", r"NVIDIA\DXCache"),
                     ("LOCALAPPDATA", r"NVIDIA\GLCache"), ("LOCALAPPDATA", r"AMD\DxCache"),
                     ("LOCALAPPDATA", r"AMD\GLCache")),
    "crash_dumps": (("LOCALAPPDATA", "CrashDumps"), ("LOCALAPPDATA", r"Microsoft\Windows\WER\ReportArchive"),
                    ("LOCALAPPDATA", r"Microsoft\Windows\WER\ReportQueue")),
}
_ROOTS_POSIX: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "user_temp": (("TMPDIR", ""),),
    "thumbnails": (("XDG_CACHE_HOME", "thumbnails"),),
    "chrome": _chromium("google-chrome", False) + _chromium("chromium", False),
    "edge": _chromium("microsoft-edge", False),
    "brave": _chromium("BraveSoftware/Brave-Browser", False),
    "firefox": (("XDG_CACHE_HOME", "mozilla/firefox/*/cache2"),),
    "shader_cache": (("XDG_CACHE_HOME", "mesa_shader_cache"), ("XDG_CACHE_HOME", "nvidia/GLCache")),
}
_EXPECT_NAMES = {"user_temp": ("temp", "tmp")}   # %TEMP% tiene que parecer una carpeta de temporales
_PERSONAL = ("Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos")
STATUS_NOTE = {"absent": "No existe en este equipo.", "admin": "Requiere Administrador.",
               "unsafe": "Ruta rechazada por seguridad."}


class _Deadline(Exception):
    """Se agotó el tiempo de la categoría: el resultado es parcial."""


# =============================================================================================
# Utilidades puras
# =============================================================================================
def human_bytes(n: Optional[float]) -> str:
    """«512 B», «12 KB», «340.2 MB», «1.2 GB». None -> «—». Pura."""
    if n is None:
        return "—"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB") else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def volume_level(percent: float, free: int, total: int) -> str:
    """'ok' | 'warn' | 'critical' según el uso. El margen absoluto solo cuenta en volúmenes de 32 GB o más
    (una partición de arranque de 500 MB casi llena es normal). Pura."""
    big = total >= 32 * GB
    if percent >= 95 or (big and free < 2 * GB):
        return "critical"
    if percent >= 85 or (big and free < 10 * GB):
        return "warn"
    return "ok"


def _canon(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _within(child: str, parent: str) -> bool:
    """¿`child` está dentro de `parent` (o es la misma)? Ambas ya canónicas."""
    try:
        return os.path.commonpath([child, parent]) == parent
    except ValueError:  # unidades distintas o rutas mezcladas
        return False


def _home(env: Mapping[str, str]) -> str:
    return env.get("USERPROFILE") or env.get("HOME") or os.path.expanduser("~")


def _guarded_dirs(env: Mapping[str, str], windows: bool) -> List[str]:
    """Carpetas que una raíz de limpieza NUNCA puede contener (sería borrar dentro de ellas)."""
    home = _home(env)
    dirs = [home, os.path.dirname(home.rstrip("\\/")) if home else ""]
    if windows:
        root = env.get("SystemRoot") or env.get("windir") or ""
        dirs += [root, os.path.join(root, "System32") if root else "", env.get("ProgramFiles", ""),
                 env.get("ProgramFiles(x86)", ""), env.get("ProgramData", "")]
    else:
        dirs += ["/usr", "/etc", "/var", "/opt", "/boot", "/home", "/root"]
    return [d for d in dirs if d]


def _personal_dirs(env: Mapping[str, str]) -> List[str]:
    home = _home(env)
    dirs = [os.path.join(home, name) for name in _PERSONAL] if home else []
    return dirs + [env[v] for v in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial") if env.get(v)]


def check_root(path: str, env: Optional[Mapping[str, str]] = None,
               windows: Optional[bool] = None) -> Tuple[bool, str]:
    """
    ¿Es segura esta raíz de limpieza? (ok, motivo). Rechaza rutas relativas, la raíz de una unidad, las que
    CONTIENEN una carpeta protegida (perfil, Windows, Archivos de programa…) y las que están DENTRO de una
    carpeta personal (Documentos, Escritorio, OneDrive…). Se evalúa sobre la ruta real (sin enlaces).
    """
    env = os.environ if env is None else env
    windows = IS_WINDOWS if windows is None else windows
    if not path or not os.path.isabs(path):
        return False, "ruta no absoluta"
    real = _canon(path)
    if os.path.dirname(real) == real:
        return False, "es la raíz de una unidad"
    for guarded in _guarded_dirs(env, windows):
        if _within(_canon(guarded), real):
            return False, f"contiene una carpeta protegida ({guarded})"
    for personal in _personal_dirs(env):
        if _within(real, _canon(personal)):
            return False, f"está dentro de una carpeta personal ({personal})"
    return True, ""


def _expected(key: str, path: str) -> bool:
    names = _EXPECT_NAMES.get(key)
    if not names:
        return True
    parts = [p.lower() for p in re.split(r"[\\/]+", os.path.normpath(path)) if p][-2:]
    return any(p in names for p in parts)


def _base_dir(var: str, env: Mapping[str, str]) -> str:
    if var == "TEMP":
        return env.get("TEMP") or env.get("TMP") or ""
    if var == "TMPDIR":
        return env.get("TMPDIR") or "/tmp"
    if var == "SystemRoot":
        return env.get("SystemRoot") or env.get("windir") or ""
    if var == "XDG_CACHE_HOME":
        home = env.get("HOME") or ""
        return env.get("XDG_CACHE_HOME") or (os.path.join(home, ".cache") if home else "")
    return env.get(var) or ""


def _resolve(target: Target, env: Mapping[str, str], windows: bool) -> List[Tuple[str, str]]:
    """(raíz existente, base de la que sale) de una categoría, expandiendo los comodines de perfiles."""
    out: List[Tuple[str, str]] = []
    for var, rel in (_ROOTS_WIN if windows else _ROOTS_POSIX).get(target.key, ()):
        base = _base_dir(var, env)
        if not base or not os.path.isabs(base):
            continue
        hits = glob.glob(os.path.join(glob.escape(base), rel)) if glob.has_magic(rel) else \
            [os.path.join(base, rel) if rel else base]
        for hit in sorted(hits):
            if os.path.isdir(hit) and hit not in (h for h, _b in out):
                out.append((hit, base))
    return out


def target_roots(target: Target, env: Optional[Mapping[str, str]] = None,
                 windows: Optional[bool] = None) -> List[str]:
    """Carpetas existentes de una categoría en este equipo (sin validar)."""
    return [root for root, _base in _resolve(target, os.environ if env is None else env,
                                             IS_WINDOWS if windows is None else windows)]


def _age_ref(st: os.stat_result) -> float:
    """Instante más reciente entre modificación y creación: un archivo recién extraído puede conservar una
    fecha de modificación antigua, pero su creación lo delata como reciente."""
    ref = max(st.st_mtime, getattr(st, "st_birthtime", 0.0) or 0.0)
    return max(ref, st.st_ctime) if IS_WINDOWS else ref  # en Windows st_ctime es la creación


def _old_enough(ref: float, age_h: float, now_ts: float) -> bool:
    return age_h <= 0 or now_ts - ref >= age_h * 3600


def running_processes() -> frozenset:
    """Nombres (en minúsculas) de los procesos en ejecución; vacío si psutil no está disponible."""
    if not HAS_PSUTIL:
        return frozenset()
    names = set()
    try:
        for proc in psutil.process_iter(["name"]):
            name = (proc.info.get("name") or "").lower()
            if name:
                names.add(name)
    except Exception:  # noqa: BLE001
        pass
    return frozenset(names)


def _is_link(entry: os.DirEntry) -> bool:
    """Enlace simbólico, unión o cualquier punto de reanálisis: nunca se entra ni se borra a través de él."""
    try:
        if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
            return True
        return bool(getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & _REPARSE)
    except OSError:
        return True  # ante la duda, no se entra


def _matches(target: Target, name: str) -> bool:
    return not target.patterns or any(fnmatch.fnmatch(name.lower(), p) for p in target.patterns)


def _owned(target: Target, st: os.stat_result) -> bool:
    return not (target.own_files_only and hasattr(os, "getuid")) or st.st_uid == os.getuid()


def _iter_files(root: str, target: Target, deadline: float,
                dirs: Optional[List[Tuple[str, float]]] = None) -> Iterator[Tuple[str, os.stat_result]]:
    """
    Archivos regulares de la categoría bajo `root` (sin seguir enlaces ni uniones). `dirs` recibe las
    subcarpetas recorridas con su antigüedad ANTES de borrar nada (borrar actualiza su fecha).
    Lanza _Deadline si se agota el tiempo.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            continue  # sin permiso para listar: se omite
        for entry in entries:
            if time.monotonic() > deadline:
                raise _Deadline()
            if _is_link(entry):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if target.recursive:
                        stack.append(entry.path)
                        if dirs is not None:
                            dirs.append((entry.path, _age_ref(entry.stat(follow_symlinks=False))))
                    continue
                if not entry.is_file(follow_symlinks=False) or not _matches(target, entry.name):
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if _owned(target, st):
                yield entry.path, st


# =============================================================================================
# Borrado verificado
# =============================================================================================
_WIN_API = None


def _win_api():
    """kernel32 PRIVADO con prototipos de 64 bits correctos (no altera ctypes.windll de otros módulos)."""
    global _WIN_API
    if _WIN_API is None:
        import ctypes
        from ctypes import wintypes

        class ByHandleInfo(ctypes.Structure):
            _fields_ = [("dwFileAttributes", wintypes.DWORD), ("ftCreationTime", wintypes.FILETIME),
                        ("ftLastAccessTime", wintypes.FILETIME), ("ftLastWriteTime", wintypes.FILETIME),
                        ("dwVolumeSerialNumber", wintypes.DWORD), ("nFileSizeHigh", wintypes.DWORD),
                        ("nFileSizeLow", wintypes.DWORD), ("nNumberOfLinks", wintypes.DWORD),
                        ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD)]

        class DispositionInfo(ctypes.Structure):
            _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        k32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleInfo)]
        k32.GetFileInformationByHandle.restype = wintypes.BOOL
        k32.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        k32.SetFileInformationByHandle.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        _WIN_API = (ctypes, k32, ByHandleInfo, DispositionInfo)
    return _WIN_API


def final_path_inside(final: str, root_canon: str) -> bool:
    """¿La ruta REAL devuelta por GetFinalPathNameByHandleW («\\\\?\\C:\\…», «\\\\?\\UNC\\…») cae dentro de la
    raíz canónica (ntpath.normcase)? Semántica de rutas de Windows: pura y comprobable en cualquier sistema."""
    if not final or not root_canon:
        return False
    if final.startswith("\\\\?\\UNC\\"):
        final = "\\\\" + final[8:]
    elif final.startswith("\\\\?\\"):
        final = final[4:]
    try:
        return ntpath.commonpath([ntpath.normcase(final), root_canon]) == root_canon
    except ValueError:  # otra unidad o mezcla de rutas absolutas y relativas
        return False


def _win_delete(path: str, root_canon: str, is_dir: bool = False) -> str:
    """
    Borra por HANDLE (Windows): abre SIN seguir puntos de reanálisis, comprueba dónde está realmente el
    objeto abierto y solo entonces lo marca para borrar. Una unión colocada a mitad de la limpieza no puede
    desviar el borrado. Devuelve 'ok' | 'gone' | 'locked' | 'outside' | 'changed'.
    """
    ctypes, k32, ByHandleInfo, DispositionInfo = _win_api()
    DELETE, FILE_READ_ATTRIBUTES = 0x00010000, 0x80
    share = 0x1 | 0x2 | 0x4                       # lectura | escritura | borrado
    flags = 0x00200000 | 0x02000000               # OPEN_REPARSE_POINT | BACKUP_SEMANTICS (carpetas)
    handle = k32.CreateFileW(path, DELETE | FILE_READ_ATTRIBUTES, share, None, 3, flags, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        return "gone" if ctypes.get_last_error() in (2, 3) else "locked"
    try:
        size = 1024
        while True:
            buf = ctypes.create_unicode_buffer(size)
            n = k32.GetFinalPathNameByHandleW(handle, buf, size, 0)
            if n == 0:
                return "locked"
            if n < size:
                break
            size = n + 1
        if not final_path_inside(buf.value, root_canon):
            return "outside"
        info = ByHandleInfo()
        if not k32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            return "locked"
        if info.dwFileAttributes & _REPARSE or bool(info.dwFileAttributes & 0x10) != is_dir:
            return "changed"
        disposition = DispositionInfo(True)
        if not k32.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            return "locked"   # en uso, de solo lectura o carpeta no vacía
        return "ok"
    finally:
        k32.CloseHandle(handle)


def _clean_root_windows(root: str, target: Target, age_h: float, now_ts: float, deadline: float,
                        res: Dict[str, Any], dry_run: bool) -> None:
    root_canon = _canon(root)
    dirs: List[Tuple[str, float]] = []
    for path, st in _iter_files(root, target, deadline, dirs):
        if not _old_enough(_age_ref(st), age_h, now_ts):
            res["recent"] += 1
            continue
        outcome = "ok" if dry_run else _win_delete(path, root_canon)
        if outcome == "ok":
            res["deleted"] += 1
            res["freed"] += st.st_size
        elif outcome == "outside":
            res["redirected"] += 1
        elif outcome != "gone":
            res["locked"] += 1
    if dry_run:
        return
    for path, ref in sorted(dirs, key=lambda d: d[0].count(os.sep), reverse=True):  # de dentro afuera
        if _old_enough(ref, age_h, now_ts) and _win_delete(path, root_canon, is_dir=True) == "ok":
            res["dirs_removed"] += 1


def _clean_root_posix(root: str, target: Target, age_h: float, now_ts: float, deadline: float,
                      res: Dict[str, Any], dry_run: bool) -> None:
    """Recorrido y borrado por descriptores de carpeta (os.fwalk + dir_fd): inmune a enlaces cambiados."""
    ages: Dict[Tuple[int, int], float] = {}
    for _dirpath, dirnames, filenames, dirfd in os.fwalk(root, follow_symlinks=False):
        if time.monotonic() > deadline:
            raise _Deadline()
        if not target.recursive:
            dirnames[:] = []
        for name in dirnames:
            try:
                st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                ages[(st.st_dev, st.st_ino)] = _age_ref(st)   # antes de borrar nada dentro
            except OSError:
                pass
        for name in filenames:
            if time.monotonic() > deadline:
                raise _Deadline()
            try:
                st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            except OSError:
                continue
            if not stat_mod.S_ISREG(st.st_mode) or not _matches(target, name) or not _owned(target, st):
                continue
            if not _old_enough(_age_ref(st), age_h, now_ts):
                res["recent"] += 1
                continue
            try:
                if not dry_run:
                    os.unlink(name, dir_fd=dirfd)
                res["deleted"] += 1
                res["freed"] += st.st_size
            except FileNotFoundError:
                pass
            except OSError:
                res["locked"] += 1
    if dry_run or not target.recursive:
        return
    for _dirpath, dirnames, _filenames, dirfd in os.fwalk(root, topdown=False, follow_symlinks=False):
        for name in dirnames:
            try:
                st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                ref = ages.get((st.st_dev, st.st_ino))
                if ref is not None and _old_enough(ref, age_h, now_ts):
                    os.rmdir(name, dir_fd=dirfd)   # solo si quedó vacía
                    res["dirs_removed"] += 1
            except OSError:
                pass


# =============================================================================================
# Análisis y limpieza de las categorías
# =============================================================================================
def _plan(target: Target, roots: Optional[Mapping[str, Sequence[str]]], env: Mapping[str, str],
          admin: bool, running: frozenset) -> Dict[str, Any]:
    """Raíces validadas y estado de una categoría (lo comparten el análisis y la limpieza)."""
    if roots is not None:
        pairs = [(r, "") for r in roots.get(target.key, ()) if os.path.isdir(r)]
    else:
        pairs = _resolve(target, env, IS_WINDOWS)
    good, rejected = [], []
    for root, base in pairs:
        ok, why = check_root(root, env)
        if ok and base and not _within(_canon(root), _canon(base)):
            ok, why = False, "un enlace la saca de su carpeta"
        if ok and not _expected(target.key, root):
            ok, why = False, "no parece una carpeta de temporales"
        if ok:
            good.append(root)
        else:
            rejected.append({"path": root, "reason": why})
    busy = sorted({p for p in target.processes if p.lower() in running})
    if not good:
        status = "unsafe" if rejected else "absent"
    elif target.admin and not admin:
        status = "admin"
    elif busy:
        status = "in_use"
    else:
        status = "ok"
    if status == "in_use":
        note = ("Windows está instalando actualizaciones ahora mismo." if target.key == "wu_cache"
                else f"{busy[0]} está en ejecución: ciérralo para limpiar esta caché.")
    elif status == "unsafe":
        note = f"{STATUS_NOTE['unsafe']} {rejected[0]['reason'].capitalize()}."
    else:
        note = STATUS_NOTE.get(status, "")
    return {"roots": good, "rejected": rejected, "status": status, "note": note, "busy": busy}


def _selected(keys: Optional[Sequence[str]]) -> List[Target]:
    return list(TARGETS) if keys is None else [BY_KEY[k] for k in keys if k in BY_KEY]


def scan_targets(keys: Optional[Sequence[str]] = None, *, age_h: float = DEFAULT_AGE_H,
                 roots: Optional[Mapping[str, Sequence[str]]] = None, env: Optional[Mapping[str, str]] = None,
                 admin: Optional[bool] = None, running: Optional[Sequence[str]] = None,
                 now: Optional[float] = None, deadline_s: float = SCAN_DEADLINE_S) -> Dict[str, Any]:
    """
    Análisis de SOLO LECTURA de las categorías: archivos y bytes totales, cuántos se podrían liberar con la
    antigüedad elegida y por qué una categoría no se limpiaría (no existe, Administrador, en uso, ruta
    rechazada). `roots` sustituye las rutas del sistema (pruebas). No borra nada.
    """
    started = time.monotonic()
    env = os.environ if env is None else env
    admin = is_admin() if admin is None else admin
    running = running_processes() if running is None else frozenset(n.lower() for n in running)
    now_ts = time.time() if now is None else now
    seen: set = set()
    rows = []
    for target in _selected(keys):
        plan = _plan(target, roots, env, admin, running)
        age = target.age_h if target.age_h is not None else age_h
        row = {"key": target.key, "title": target.title, "scope": target.scope, "desc": target.desc,
               "admin": target.admin, "default": target.default, "age_h": age, "roots": plan["roots"],
               "rejected": plan["rejected"], "status": plan["status"], "note": plan["note"], "files": 0,
               "bytes": 0, "eligible_files": 0, "eligible_bytes": 0, "recent_files": 0, "partial": False}
        if plan["status"] not in ("absent", "unsafe"):
            deadline = time.monotonic() + deadline_s
            try:
                for root in plan["roots"]:
                    canon = _canon(root)
                    if canon in seen:
                        continue  # la misma carpeta ya la cuenta otra categoría
                    seen.add(canon)
                    for _path, st in _iter_files(root, target, deadline):
                        row["files"] += 1
                        row["bytes"] += st.st_size
                        if _old_enough(_age_ref(st), age, now_ts):
                            row["eligible_files"] += 1
                            row["eligible_bytes"] += st.st_size
                        else:
                            row["recent_files"] += 1
            except _Deadline:
                row["partial"] = True
        rows.append(row)
    ready = [r for r in rows if r["status"] == "ok"]
    return {"when": dt.datetime.now().isoformat(timespec="seconds"), "age_h": age_h, "targets": rows,
            "eligible_bytes": sum(r["eligible_bytes"] for r in ready),
            "eligible_files": sum(r["eligible_files"] for r in ready),
            "blocked_bytes": sum(r["eligible_bytes"] for r in rows if r["status"] != "ok"),
            "seconds": round(time.monotonic() - started, 1)}


def clean_targets(keys: Sequence[str], *, age_h: float = DEFAULT_AGE_H,
                  roots: Optional[Mapping[str, Sequence[str]]] = None, env: Optional[Mapping[str, str]] = None,
                  admin: Optional[bool] = None, running: Optional[Sequence[str]] = None,
                  now: Optional[float] = None, emit: Emit = None, dry_run: bool = False,
                  deadline_s: float = CLEAN_DEADLINE_S) -> Dict[str, Any]:
    """
    Libera espacio en las categorías `keys` con todas las garantías del módulo. Lo bloqueado se omite y se
    cuenta; las categorías sin Administrador, en uso o con la ruta rechazada no se tocan. `dry_run`
    cuenta lo que se borraría sin borrar. Devuelve el detalle por categoría y los totales.
    """
    started = time.monotonic()
    env = os.environ if env is None else env
    admin = is_admin() if admin is None else admin
    running = running_processes() if running is None else frozenset(n.lower() for n in running)
    now_ts = time.time() if now is None else now
    free_before = _free_bytes(system_mount())
    seen: set = set()
    results = []
    for target in _selected(keys):
        plan = _plan(target, roots, env, admin, running)
        age = target.age_h if target.age_h is not None else age_h
        res = {"key": target.key, "title": target.title, "scope": target.scope, "status": plan["status"],
               "note": plan["note"], "age_h": age, "deleted": 0, "freed": 0, "locked": 0, "recent": 0,
               "redirected": 0, "dirs_removed": 0, "partial": False}
        if plan["status"] != "ok":
            if plan["status"] != "absent":
                _say(emit, "!", f"{target.title}: omitida · {plan['note']}")
            results.append(res)
            continue
        deadline = time.monotonic() + deadline_s
        try:
            for root in plan["roots"]:
                canon = _canon(root)
                if canon in seen:
                    continue
                seen.add(canon)
                clean = _clean_root_windows if IS_WINDOWS else _clean_root_posix
                clean(root, target, age, now_ts, deadline, res, dry_run)
        except _Deadline:
            res["partial"] = True
        extra = [f"{res['locked']} en uso" if res["locked"] else "", f"{res['recent']} recientes" if res["recent"] else "",
                 f"{res['redirected']} desviados por un enlace" if res["redirected"] else ""]
        detail = ", ".join(x for x in extra if x)
        _say(emit, "*" if res["deleted"] else "~",
             f"{target.title}: {res['deleted']} archivos · {human_bytes(res['freed'])}"
             + (f" ({detail} omitidos)" if detail else "") + (" · parcial (tiempo agotado)" if res["partial"] else ""))
        results.append(res)
    free_after = _free_bytes(system_mount())
    return {"ok": True, "dry_run": dry_run, "age_h": age_h, "targets": results,
            "freed": sum(r["freed"] for r in results), "deleted": sum(r["deleted"] for r in results),
            "locked": sum(r["locked"] for r in results), "redirected": sum(r["redirected"] for r in results),
            "skipped": [r["key"] for r in results if r["status"] not in ("ok", "absent")],
            "free_before": free_before, "free_after": free_after,
            "seconds": round(time.monotonic() - started, 1)}


def _say(emit: Emit, kind: str, text: str) -> None:
    if emit is not None:
        try:
            emit(kind, text)
        except Exception:  # noqa: BLE001
            pass


# =============================================================================================
# Volúmenes y discos
# =============================================================================================
def system_mount() -> str:
    """Punto de montaje del sistema: «C:\\» (SystemDrive) en Windows, «/» en el resto."""
    return (os.environ.get("SystemDrive") or "C:") + "\\" if IS_WINDOWS else "/"


def _free_bytes(mount: str) -> Optional[int]:
    if not HAS_PSUTIL:
        return None
    try:
        return int(psutil.disk_usage(mount).free)
    except Exception:  # noqa: BLE001
        return None


def analyze_volumes() -> List[Dict[str, Any]]:
    """Volúmenes montados con su uso real (psutil): unidad, sistema de archivos, total/usado/libre y nivel."""
    if not HAS_PSUTIL:
        return []
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception:  # noqa: BLE001
        return []
    sysmount = os.path.normcase(system_mount())
    out, seen = [], set()
    for part in parts:
        opts, fstype = (part.opts or "").lower(), (part.fstype or "").lower()
        if "cdrom" in opts or not fstype or fstype in _SKIP_FS:
            continue
        mount = part.mountpoint
        key = os.path.normcase(mount)
        if key in seen:
            continue
        try:
            du = psutil.disk_usage(mount)
        except Exception:  # noqa: BLE001  (unidad sin medio, sin permisos…)
            continue
        if not du.total:
            continue
        seen.add(key)
        letter = mount[0].upper() if IS_WINDOWS and len(mount) >= 2 and mount[1] == ":" else ""
        out.append({"device": part.device, "mount": mount, "letter": letter, "fstype": part.fstype,
                    "total": int(du.total), "used": int(du.used), "free": int(du.free),
                    "percent": round(float(du.percent), 1), "level": volume_level(du.percent, du.free, du.total),
                    "system": key == sysmount, "removable": "removable" in opts, "media": "—", "health": None})
    out.sort(key=lambda v: (not v["system"], v["mount"].lower()))
    return out


def attach_disks(volumes: List[Dict[str, Any]], disks: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Añade a cada volumen el medio (SSD/HDD) y la salud del disco físico que lo contiene (por letra). Pura."""
    by_letter = {letter: d for d in disks for letter in d.get("letters", ())}
    for vol in volumes:
        disk = by_letter.get(vol.get("letter") or "")
        if disk:
            vol.update(media=disk["media"], health=disk["label"], health_level=disk["level"], model=disk["model"])
    return volumes


def system_volume(volumes: Optional[Sequence[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """El volumen del sistema (o None si no se pudo leer)."""
    vols = analyze_volumes() if volumes is None else volumes
    return next((v for v in vols if v.get("system")), None)


def volumes_with_disks() -> Dict[str, Any]:
    """Volúmenes + discos físicos (PowerShell en Windows, ~1-2 s): para el análisis en segundo plano."""
    disks = physical_disks()
    return {"volumes": attach_disks(analyze_volumes(), disks), "disks": disks}


# =============================================================================================
# Consumidores de espacio (solo lectura)
# =============================================================================================
_KNOWN_WIN = (("Escritorio", "Desktop"), ("Documentos", "Documents"), ("Descargas", "Downloads"),
              ("Imágenes", "Pictures"), ("Música", "Music"), ("Vídeos", "Videos"),
              ("AppData\\Local", os.path.join("AppData", "Local")),
              ("AppData\\Roaming", os.path.join("AppData", "Roaming")))
_KNOWN_POSIX = (("Escritorio", "Desktop"), ("Documentos", "Documents"), ("Descargas", "Downloads"),
                ("Imágenes", "Pictures"), ("Música", "Music"), ("Vídeos", "Videos"), ("Caché (.cache)", ".cache"),
                ("Datos de apps (.local/share)", os.path.join(".local", "share")))


def space_consumers(home: Optional[str] = None, *, top: int = 12, deadline_s: float = SPACE_DEADLINE_S,
                    folders: Optional[Sequence[Tuple[str, str]]] = None) -> Dict[str, Any]:
    """
    Dónde se va el espacio de la carpeta del usuario: tamaño de cada carpeta conocida y los `top` archivos
    más grandes. Solo lectura; no sigue enlaces y no cuenta los archivos de OneDrive «solo en línea» (no
    ocupan disco; se informan aparte). Con mucho contenido el resultado puede ser parcial (tiempo).
    """
    started = time.monotonic()
    deadline = started + deadline_s
    home = home or os.path.expanduser("~")
    known = folders if folders is not None else (_KNOWN_WIN if IS_WINDOWS else _KNOWN_POSIX)
    rows: List[Dict[str, Any]] = []
    largest: List[Tuple[int, str, float]] = []
    partial = False
    scanned = 0
    for label, rel in known:
        path = os.path.join(home, rel)
        if not os.path.isdir(path) or partial:
            continue
        row = {"label": label, "path": path, "bytes": 0, "files": 0, "cloud_files": 0}
        try:
            for fpath, st in _iter_files_any(path, deadline):
                scanned += 1
                if getattr(st, "st_file_attributes", 0) & _CLOUD:
                    row["cloud_files"] += 1
                    continue
                row["files"] += 1
                row["bytes"] += st.st_size
                item = (st.st_size, fpath, st.st_mtime)
                if len(largest) < top:
                    heapq.heappush(largest, item)
                elif item > largest[0]:
                    heapq.heapreplace(largest, item)
        except _Deadline:
            partial = True
        rows.append(row)
    rows.sort(key=lambda r: -r["bytes"])
    files = [{"path": p, "name": os.path.basename(p), "folder": os.path.dirname(p), "bytes": size,
              "modified": dt.datetime.fromtimestamp(mtime).isoformat(timespec="seconds")}
             for size, p, mtime in sorted(largest, reverse=True)]
    return {"home": home, "folders": rows, "largest": files, "partial": partial, "scanned": scanned,
            "total": sum(r["bytes"] for r in rows), "seconds": round(time.monotonic() - started, 1)}


def _iter_files_any(root: str, deadline: float) -> Iterator[Tuple[str, os.stat_result]]:
    """Como _iter_files, pero los archivos que son puntos de reanálisis (OneDrive, deduplicación) cuentan:
    solo las CARPETAS-enlace se saltan, que es lo que podría sacar el recorrido de su sitio."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            continue
        for entry in entries:
            if time.monotonic() > deadline:
                raise _Deadline()
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if not _is_link(entry):
                        stack.append(entry.path)
                    continue
                if entry.is_file(follow_symlinks=False):
                    yield entry.path, entry.stat(follow_symlinks=False)
            except OSError:
                continue


# =============================================================================================
# Optimización nativa de la unidad (defrag /O)
# =============================================================================================
def optimize_volume(drive: Optional[str] = None, *, admin: Optional[bool] = None, cancel: Any = None,
                    on_progress: Optional[Callable[[float], None]] = None, emit: Emit = None,
                    runner: Optional[Callable[..., Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Optimiza la unidad con la herramienta NATIVA de Windows (`defrag X: /O /U`): TRIM en SSD y
    desfragmentación en HDD, según el tipo que detecte Windows. Requiere Administrador; fuera de Windows
    o sin privilegios no ejecuta nada. Interrumpirla es seguro (defrag deja la unidad consistente).
    """
    drive = (drive or (system_mount()[:2] if IS_WINDOWS else "C:")).upper().rstrip("\\")
    command = f"defrag {drive} /O /U"
    res: Dict[str, Any] = {"drive": drive, "command": command, "ok": False, "rc": None, "seconds": 0.0,
                           "cancelled": False, "timed_out": False, "lines": [], "ran": False}
    if not IS_WINDOWS:
        res["message"] = "La optimización nativa de unidades (defrag) solo existe en Windows."
        return res
    if not re.fullmatch(r"[A-Z]:", drive):
        res["message"] = f"Unidad no válida: «{drive}»."
        return res
    if not (is_admin() if admin is None else admin):
        res["message"] = "Optimizar la unidad requiere Administrador."
        return res
    _say(emit, "+", f"Optimización de la unidad {drive}: {command}")
    out = (runner or run_tool)([native_exe("defrag"), drive, "/O", "/U"], timeout=OPTIMIZE_TIMEOUT_S,
                               cancel=cancel, on_progress=on_progress)
    res.update(rc=out.get("rc"), seconds=out.get("seconds", 0.0), cancelled=bool(out.get("cancelled")),
               timed_out=bool(out.get("timed_out")), lines=summary_lines(out.get("output", "")), ran=True)
    if res["cancelled"]:
        res["message"] = "Optimización cancelada. Es seguro: la unidad queda consistente."
    elif res["timed_out"]:
        res["message"] = "Se superó el tiempo máximo y se detuvo defrag."
    elif res["rc"] == 127:
        res["message"] = "defrag.exe no está disponible en este equipo."
    elif res["rc"] == 0:
        res.update(ok=True, message=f"Unidad {drive} optimizada (TRIM en SSD o desfragmentación en HDD, "
                                    "según su tipo).")
    else:
        res["message"] = f"defrag terminó con código {res['rc']}" + (f": {res['lines'][-1]}" if res["lines"] else ".")
    _say(emit, "*" if res["ok"] else "x", res["message"])
    return res


__all__ = ["TARGETS", "BY_KEY", "Target", "AGE_CHOICES", "DEFAULT_AGE_H", "human_bytes", "volume_level",
           "check_root", "target_roots", "scan_targets", "clean_targets", "analyze_volumes", "attach_disks",
           "system_volume", "system_mount", "volumes_with_disks", "space_consumers", "optimize_volume",
           "final_path_inside", "running_processes"]
