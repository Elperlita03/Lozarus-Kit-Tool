# -*- coding: utf-8 -*-
"""
modulos/_salud_sistema.py · LOZARUS KIT TOOL

Diagnóstico y salud del SISTEMA OPERATIVO. Todo local, sobre el equipo propio:

  · Integridad de los archivos protegidos con las herramientas ESTÁNDAR de Windows:
        DISM /Online /Cleanup-Image /CheckHealth    marca de corrupción del almacén (segundos)
        DISM /Online /Cleanup-Image /ScanHealth     examen profundo del almacén (minutos)
        sfc /verifyonly                             verificación de archivos SIN reparar (minutos)
    y, solo a petición y con confirmación en la interfaz, la reparación oficial de Microsoft:
        DISM /Online /Cleanup-Image /RestoreHealth  ->  sfc /scannow
  · Señales de estabilidad: reinicio pendiente, tiempo encendido, apagados inesperados y pantallazos
    azules de los últimos días (registro System) y estado de salud de los discos físicos.
  · Veredicto global (SALUDABLE / ATENCIÓN / CRÍTICO / SIN VERIFICAR) y métricas de rendimiento del
    equipo para el informe ejecutivo.

Cada verificación ejecutada se guarda en Lozarus_Forensics/salud_sistema.json (último resultado e
historial) para que la supervisión sobreviva a los reinicios; la interfaz además la registra en la
Caja Negra. DISM se ejecuta con /English para interpretar su salida sin depender del idioma; la de sfc
se reconoce en inglés y en español. Un resultado que no se puede interpretar queda INDETERMINADO:
nunca se presenta como «sin infracciones».

Funciones aisladas de Qt (pruebas en tests/test_salud_sistema.py). Ninguna lanza: devuelven datos.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import platform
import re
import unicodedata
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ._base import IS_WINDOWS, CheckSkipped, CommandError
from ._forense import FORENSICS_DIR
from ._utilidades import (HAS_PSUTIL, as_list, is_admin, native_exe, powershell, psutil, reg_get, reg_key_exists,
                          run_tool)

STATE_FILE = os.path.join(FORENSICS_DIR, "salud_sistema.json")
STATE_VERSION = 1
HISTORY_MAX = 40          # verificaciones que conserva el historial
STALE_DAYS = 30           # una verificación más antigua ya no acredita la salud ACTUAL
UPTIME_WARN_DAYS = 30     # encendido más tiempo: parches y fugas pendientes de un reinicio
EVENT_WINDOW_DAYS = 7     # ventana de apagados inesperados y pantallazos azules

Emit = Optional[Callable[[str, str], None]]

_DISM = ["dism", "/English", "/Online", "/Cleanup-Image"]
# Comprobaciones: clave -> (título, argumentos, tiempo máximo en s, herramienta)
CHECKS: Dict[str, Tuple[str, List[str], int, str]] = {
    "dism_check": ("Almacén de componentes · comprobación rápida", _DISM + ["/CheckHealth"], 600, "dism"),
    "dism_scan": ("Almacén de componentes · examen profundo", _DISM + ["/ScanHealth"], 3600, "dism"),
    "sfc_verify": ("Archivos protegidos · verificación", ["sfc", "/verifyonly"], 3600, "sfc"),
    "dism_restore": ("Almacén de componentes · reparación", _DISM + ["/RestoreHealth"], 7200, "dism"),
    "sfc_scan": ("Archivos protegidos · reparación", ["sfc", "/scannow"], 3600, "sfc"),
}
READ_ONLY_CHECKS = ("dism_check", "dism_scan", "sfc_verify")
REPAIR_STEPS = ("dism_restore", "sfc_scan")
FILE_CHECKS = ("sfc_verify", "sfc_scan")
STORE_CHECKS = ("dism_check", "dism_scan", "dism_restore")

# Veredicto -> (nivel, etiqueta). Niveles: ok · warn · critical · unknown (gris: no acredita nada).
VERDICTS: Dict[str, Tuple[str, str]] = {
    "ok": ("ok", "ÍNTEGRO"),
    "repaired": ("ok", "REPARADO"),
    "repairable": ("warn", "REPARABLE"),
    "pending_reboot": ("warn", "REINICIO PENDIENTE"),
    "corrupt": ("critical", "INFRACCIONES"),
    "unrepairable": ("critical", "NO REPARABLE"),
    "failed": ("unknown", "NO COMPLETADA"),
    "requires_admin": ("unknown", "REQUIERE ADMIN"),
    "unavailable": ("unknown", "NO DISPONIBLE"),
    "cancelled": ("unknown", "CANCELADA"),
    "timeout": ("unknown", "TIEMPO AGOTADO"),
    "unknown": ("unknown", "INDETERMINADO"),
}
CONCLUSIVE = frozenset({"ok", "repaired", "repairable", "pending_reboot", "corrupt", "unrepairable"})
LEVEL_RANK = {"ok": 0, "unknown": 1, "warn": 2, "critical": 3}
LEVEL_LABEL = {"ok": "SALUDABLE", "warn": "ATENCIÓN", "critical": "CRÍTICO", "unknown": "SIN VERIFICAR"}

# Frases de la salida (minúsculas y sin tildes). El ORDEN importa: «reparó correctamente» se mira antes que
# «encontró archivos dañados», que aparece en la misma frase.
_SFC_RULES = (
    ("requires_admin", ("must be an administrator", "debe ser administrador")),
    ("pending_reboot", ("repair pending", "reparacion del sistema pendiente", "reparacion pendiente")),
    ("ok", ("did not find any integrity violations", "no encontro ninguna infraccion de integridad",
            "no encontro infracciones de integridad")),
    ("repaired", ("successfully repaired", "reparo correctamente")),
    ("unrepairable", ("unable to fix", "no pudo reparar", "no pudo corregir")),
    ("corrupt", ("found integrity violations", "encontro infracciones de integridad", "found corrupt files",
                 "encontro archivos danados")),
    ("failed", ("could not perform the requested operation", "no pudo realizar la operacion solicitada",
                "could not start the repair service", "no pudo iniciar el servicio de reparacion")),
)
_DISM_RULES = (
    ("requires_admin", ("elevated permissions are required", "error: 740")),
    ("unrepairable", ("cannot be repaired", "can not be repaired")),
    ("repaired", ("corruption was repaired",)),
    ("repairable", ("component store is repairable",)),
    ("ok", ("no component store corruption detected", "restore operation completed successfully")),
    ("failed", ("source files could not be found", "error:")),
)
_PROGRESS_LINE = re.compile(r"^\[[=\s.\d%]*\]$|\d{1,3}(?:[.,]\d+)?\s?%\s*(?:complete|completad|completo|realizad)")

# Mensaje legible por (herramienta, veredicto); si falta, se usa el genérico del veredicto.
MESSAGES = {
    ("sfc", "ok"): "Protección de recursos de Windows no encontró infracciones de integridad.",
    ("sfc", "repaired"): "SFC encontró archivos dañados y los reparó. Reinicia para completar la reparación.",
    ("sfc", "corrupt"): "Hay archivos protegidos del sistema dañados: ejecuta la reparación del sistema.",
    ("sfc", "unrepairable"): "SFC no pudo reparar algunos archivos: repara antes el almacén con DISM y repite.",
    ("dism", "ok"): "El almacén de componentes de Windows está sano.",
    ("dism", "repaired"): "DISM reparó el almacén de componentes.",
    ("dism", "repairable"): "El almacén de componentes está dañado pero es reparable (DISM /RestoreHealth).",
    ("dism", "unrepairable"): "El almacén de componentes no se puede reparar: hace falta un medio de instalación.",
    ("dism", "failed"): "DISM no pudo completar la operación (sin origen de reparación o error del servicio).",
}
GENERIC_MESSAGES = {
    "pending_reboot": "Hay una reparación del sistema pendiente de reinicio: reinicia y repite la verificación.",
    "failed": "La herramienta no pudo completar la operación.",
    "requires_admin": "Requiere ejecutar Lozarus como Administrador.",
    "unavailable": "Disponible solo en Windows.",
    "cancelled": "Cancelada por el usuario antes de terminar.",
    "timeout": "Se superó el tiempo máximo y se detuvo la herramienta.",
    "unknown": "No se pudo interpretar el resultado: revisa la salida de la herramienta.",
}


# =============================================================================================
# Utilidades
# =============================================================================================
def _say(emit: Emit, kind: str, text: str) -> None:
    if emit is not None:
        try:
            emit(kind, text)
        except Exception:  # noqa: BLE001
            pass


def _now(now: Optional[dt.datetime] = None) -> dt.datetime:
    return now or dt.datetime.now()


def _parse_when(value: Any) -> Optional[dt.datetime]:
    try:
        return dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def normalize(text: str) -> str:
    """Minúsculas, sin tildes ni eñes y con los espacios colapsados (para comparar frases)."""
    plain = unicodedata.normalize("NFKD", text or "")
    plain = "".join(ch for ch in plain if not unicodedata.combining(ch))
    return " ".join(plain.lower().split())


def summary_lines(text: str, limit: int = 4) -> List[str]:
    """Últimas líneas con contenido de la salida, sin las barras ni los «45% completado» del progreso."""
    lines: List[str] = []
    for raw in re.split(r"[\r\n]+", text or ""):
        line = " ".join(raw.split())
        if not line or _PROGRESS_LINE.search(normalize(line)) or line in lines:
            continue
        lines.append(line)
    return lines[-limit:]


def classify(tool: str, text: str, rc: Optional[int] = None) -> str:
    """Veredicto de una ejecución de sfc o DISM a partir de su salida. Sin frase reconocible: «unknown»."""
    low = normalize(text)
    for verdict, needles in (_SFC_RULES if tool == "sfc" else _DISM_RULES):
        if any(n in low for n in needles):
            return verdict
    if tool == "dism" and rc == 740:
        return "requires_admin"
    return "unknown"


def message_for(tool: str, verdict: str) -> str:
    return MESSAGES.get((tool, verdict)) or GENERIC_MESSAGES.get(verdict) or VERDICTS[verdict][1].capitalize()


# =============================================================================================
# Ejecución de comprobaciones
# =============================================================================================
def run_check(key: str, *, admin: Optional[bool] = None, cancel: Any = None,
              on_progress: Optional[Callable[[float], None]] = None, emit: Emit = None,
              runner: Optional[Callable[..., Dict[str, Any]]] = None, now: Optional[dt.datetime] = None,
              record_result: bool = True) -> Dict[str, Any]:
    """
    Ejecuta UNA comprobación de CHECKS. Fuera de Windows o sin Administrador no ejecuta nada (veredicto
    «unavailable» / «requires_admin»). Las ejecuciones reales se guardan en el historial (record).
    Devuelve {key, title, tool, command, when, verdict, level, label, message, rc, seconds, lines, ran}.
    """
    title, argv, timeout, tool = CHECKS[key]
    result: Dict[str, Any] = {"key": key, "title": title, "tool": tool, "command": " ".join(argv),
                              "when": _now(now).isoformat(timespec="seconds"), "rc": None, "seconds": 0.0,
                              "lines": [], "ran": False}
    if not IS_WINDOWS:
        verdict = "unavailable"
    elif not (is_admin() if admin is None else admin):
        verdict = "requires_admin"
    else:
        _say(emit, "+", f"{title}: {result['command']}")
        res = (runner or run_tool)([native_exe(argv[0])] + argv[1:], timeout=timeout, cancel=cancel,
                                   on_progress=on_progress)
        result.update(rc=res.get("rc"), seconds=res.get("seconds", 0.0), ran=True,
                      lines=summary_lines(res.get("output", "")))
        if res.get("cancelled"):
            verdict = "cancelled"
        elif res.get("timed_out"):
            verdict = "timeout"
        elif res.get("rc") == 127:
            verdict = "unavailable"
        else:
            verdict = classify(tool, res.get("output", ""), res.get("rc"))
    level, label = VERDICTS[verdict]
    result.update(verdict=verdict, level=level, label=label, message=message_for(tool, verdict))
    if result["ran"]:
        _say(emit, {"ok": "*", "warn": "!", "critical": "x"}.get(level, "~"), f"{title}: {result['message']}")
        if record_result:
            record(result)
    return result


def repair_system(*, admin: Optional[bool] = None, cancel: Any = None,
                  on_progress: Optional[Callable[[float], None]] = None, emit: Emit = None,
                  runner: Optional[Callable[..., Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Reparación oficial en dos pasos: DISM /RestoreHealth (repara el almacén de componentes) y después
    sfc /scannow (repara los archivos protegidos desde ese almacén). Si DISM falla, SFC se ejecuta igual:
    puede reparar con lo que ya hay en el equipo. Si se cancela durante DISM, SFC no se lanza.
    El progreso es global: DISM 0-55 %, SFC 55-100 %. Devuelve {verdict, level, label, message, steps}.
    """
    steps: List[Dict[str, Any]] = []
    spans = {"dism_restore": (0.0, 55.0), "sfc_scan": (55.0, 100.0)}
    for key in REPAIR_STEPS:
        lo, hi = spans[key]

        def scaled(pct: float, lo=lo, hi=hi) -> None:
            if on_progress is not None:
                on_progress(lo + (hi - lo) * pct / 100.0)

        step = run_check(key, admin=admin, cancel=cancel, on_progress=scaled, emit=emit, runner=runner)
        steps.append(step)
        if step["verdict"] in ("cancelled", "requires_admin", "unavailable"):
            break
    # Manda el veredicto de SFC (el último paso); si se paró en DISM, el motivo de esa parada.
    verdict = steps[-1]["verdict"]
    if verdict == "ok" and any(s["verdict"] == "repaired" for s in steps):
        verdict = "repaired"   # SFC no encontró nada porque DISM ya había reparado el almacén
    level, label = VERDICTS[verdict]
    return {"verdict": verdict, "level": level, "label": label, "message": message_for("sfc", verdict),
            "steps": steps, "seconds": round(sum(s.get("seconds") or 0.0 for s in steps), 1)}


# =============================================================================================
# Historial persistente (salud_sistema.json)
# =============================================================================================
def load_state(path: Optional[str] = None) -> Dict[str, Any]:
    """Estado guardado {version, last: {clave: resultado}, history: [...]}; vacío si no existe o es inválido."""
    try:
        with open(path or STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = None
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        return {"version": STATE_VERSION, "last": {}, "history": []}
    data.setdefault("last", {})
    data.setdefault("history", [])
    return data


def save_state(state: Dict[str, Any], path: Optional[str] = None) -> None:
    """Escritura atómica (temporal + os.replace): un corte nunca deja el historial a medias."""
    path = path or STATE_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def record(result: Dict[str, Any], path: Optional[str] = None) -> bool:
    """
    Guarda una ejecución: siempre en el historial; como «último resultado» de su comprobación solo si es
    concluyente (cancelar o agotar el tiempo no borra lo que ya se sabía). Devuelve False si no se pudo.
    """
    entry = {k: result.get(k) for k in ("key", "title", "tool", "command", "when", "verdict", "level", "label",
                                        "message", "rc", "seconds", "lines")}
    try:
        state = load_state(path)
        if entry["verdict"] in CONCLUSIVE:
            state["last"][entry["key"]] = entry
        state["history"] = ([entry] + [h for h in state["history"] if isinstance(h, dict)])[:HISTORY_MAX]
        save_state(state, path)
        return True
    except OSError:
        return False


def latest(state: Dict[str, Any], keys: Sequence[str]) -> Optional[Dict[str, Any]]:
    """Resultado concluyente más reciente entre las comprobaciones `keys`."""
    found = [state.get("last", {}).get(k) for k in keys]
    found = [r for r in found if isinstance(r, dict) and _parse_when(r.get("when"))]
    return max(found, key=lambda r: _parse_when(r["when"])) if found else None


def integrity_status(state: Dict[str, Any], now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    """
    Lo que se sabe de la integridad: último resultado de los ARCHIVOS (sfc) y del ALMACÉN (DISM), y si
    alguno es reciente (menos de STALE_DAYS) para acreditar la salud actual.
    """
    files, store = latest(state, FILE_CHECKS), latest(state, STORE_CHECKS)
    limit = _now(now) - dt.timedelta(days=STALE_DAYS)
    recent = [r for r in (files, store) if r and _parse_when(r["when"]) >= limit]
    when = max((_parse_when(r["when"]) for r in (files, store) if r), default=None)
    return {"files": files, "store": store, "verified": bool(recent),
            "last_when": when.isoformat(timespec="seconds") if when else None}


# =============================================================================================
# Señales de estabilidad (solo lectura)
# =============================================================================================
_PENDING_KEYS = (
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
     "Mantenimiento de componentes (CBS)"),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
     "Windows Update"),
)


def pending_reboot_reasons() -> Optional[List[str]]:
    """Motivos de reinicio pendiente leídos del registro (sin privilegios). None fuera de Windows."""
    if not IS_WINDOWS:
        return None
    reasons = []
    for path, label in _PENDING_KEYS:
        try:
            if reg_key_exists(path):
                reasons.append(label)
        except Exception:  # noqa: BLE001  (clave ilegible: no es motivo)
            pass
    try:
        if reg_get(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations"):
            reasons.append("Renombrado de archivos pendiente")
    except Exception:  # noqa: BLE001
        pass
    return reasons


def parse_stability(data: Any) -> Tuple[Optional[int], Optional[int]]:
    """
    (apagados inesperados, pantallazos azules) a partir del JSON de recent_stability_events. Un -1 (o un
    dato ausente) es DESCONOCIDO -> None, nunca 0. Los eventos 41 y 6008 suelen describir el MISMO apagado:
    se toma el mayor de los dos, no la suma.
    """
    if not isinstance(data, dict):
        return None, None

    def num(key):
        value = data.get(key)
        return value if isinstance(value, int) and value >= 0 else None

    k41, k6008, bug = num("k41"), num("k6008"), num("bug")
    shutdowns = None if k41 is None and k6008 is None else max(k41 or 0, k6008 or 0)
    return shutdowns, bug


def recent_stability_events(days: int = EVENT_WINDOW_DAYS) -> Tuple[Optional[int], Optional[int]]:
    """Apagados inesperados (Kernel-Power 41 / EventLog 6008) y pantallazos azules (BugCheck 1001) recientes."""
    if not IS_WINDOWS:
        return None, None
    script = (
        f"$since = (Get-Date).AddDays(-{int(days)})\n"
        "function N($f) { try { @(Get-WinEvent -FilterHashtable $f -ErrorAction Stop).Count } catch {\n"
        "  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { 0 } else { -1 } } }\n"
        "Out-Json @{\n"
        "  k41 = N @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since }\n"
        "  k6008 = N @{ LogName = 'System'; Id = 6008; StartTime = $since }\n"
        "  bug = N @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001;"
        " StartTime = $since }\n"
        "}\n")
    try:
        return parse_stability(powershell(script, timeout=90))
    except (CheckSkipped, CommandError):
        return None, None


DISK_MEDIA = {"SSD": "SSD", "HDD": "HDD", "SCM": "SCM"}
DISK_HEALTH = {"healthy": ("ok", "SANO"), "warning": ("warn", "ADVERTENCIA"), "unhealthy": ("critical", "EN MAL ESTADO")}


def parse_physical_disks(data: Any) -> List[Dict[str, Any]]:
    """Normaliza el JSON de Get-PhysicalDisk (modelo, medio, bus, salud y letras de unidad). Pura."""
    disks = []
    for row in as_list(data):
        if not isinstance(row, dict):
            continue
        health = str(row.get("health") or "").strip()
        level, label = DISK_HEALTH.get(health.lower(), ("unknown", "DESCONOCIDO"))
        try:
            size = int(row.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        letters = [str(x).strip().upper() for x in as_list(row.get("letters")) if str(x).strip()]
        disks.append({"model": str(row.get("model") or "Disco").strip(),
                      "media": DISK_MEDIA.get(str(row.get("media") or "").upper(), "—"),
                      "bus": str(row.get("bus") or "").strip(), "health": health or "Unknown",
                      "level": level, "label": label, "status": str(row.get("status") or "").strip(),
                      "size": size, "letters": letters})
    return disks


def physical_disks() -> List[Dict[str, Any]]:
    """Discos físicos según Windows (Get-PhysicalDisk): medio SSD/HDD y estado de salud. [] si no se puede."""
    if not IS_WINDOWS:
        return []
    script = (
        "$parts = @(Get-Partition -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter })\n"
        "$out = foreach ($d in @(Get-PhysicalDisk -ErrorAction Stop)) {\n"
        "  $letters = @($parts | Where-Object { [string]$_.DiskNumber -eq [string]$d.DeviceId } |"
        " ForEach-Object { [string]$_.DriveLetter })\n"
        "  @{ model = [string]$d.FriendlyName; media = [string]$d.MediaType; bus = [string]$d.BusType;\n"
        "     health = [string]$d.HealthStatus; status = [string]($d.OperationalStatus -join ', ');\n"
        "     size = [int64]$d.Size; letters = $letters }\n"
        "}\nOut-Json @($out)\n")
    try:
        return parse_physical_disks(powershell(script, timeout=60))
    except (CheckSkipped, CommandError):
        return []


def collect_signals(include_events: bool = True, include_disks: bool = True) -> Dict[str, Any]:
    """Señales de estabilidad del equipo. Lo que no se puede leer queda None (desconocido)."""
    signals: Dict[str, Any] = {"pending_reboot": None, "uptime_s": None, "boot_time": None,
                               "unexpected_shutdowns": None, "bugchecks": None, "disks": None,
                               "window_days": EVENT_WINDOW_DAYS, "windows": IS_WINDOWS}
    if HAS_PSUTIL:
        try:
            boot = psutil.boot_time()
            signals["boot_time"] = dt.datetime.fromtimestamp(boot).isoformat(timespec="seconds")
            signals["uptime_s"] = max(0.0, dt.datetime.now().timestamp() - boot)
        except Exception:  # noqa: BLE001
            pass
    signals["pending_reboot"] = pending_reboot_reasons()
    if include_events:
        signals["unexpected_shutdowns"], signals["bugchecks"] = recent_stability_events()
    if include_disks and IS_WINDOWS:
        signals["disks"] = physical_disks()
    return signals


# =============================================================================================
# Veredicto global
# =============================================================================================
def health_verdict(signals: Optional[Dict[str, Any]], integrity: Optional[Dict[str, Any]],
                   now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    """
    Combina integridad y estabilidad en un veredicto (nivel, etiqueta y motivos [(nivel, texto)]).
    Sin ninguna verificación de integridad reciente el equipo queda SIN VERIFICAR aunque el resto esté
    bien: «no se sabe» nunca se presenta como «sano». Función pura.
    """
    signals, integrity = signals or {}, integrity or {}
    reasons: List[Tuple[str, str]] = []
    limit = _now(now) - dt.timedelta(days=STALE_DAYS)
    for name, result in (("Archivos del sistema", integrity.get("files")),
                         ("Almacén de componentes", integrity.get("store"))):
        if not result:
            continue
        when = _parse_when(result.get("when"))
        stale = when is not None and when < limit
        level = "unknown" if stale and result.get("level") == "ok" else result.get("level", "unknown")
        age = f" · hace {(_now(now) - when).days} días" if when and (_now(now) - when).days >= 1 else ""
        reasons.append((level, f"{name}: {result.get('label', '—').lower()}{age}"
                               + (" (verificación antigua)" if stale else "")))
    if not integrity.get("verified"):
        reasons.append(("unknown", "Integridad sin verificar en los últimos "
                                   f"{STALE_DAYS} días: ejecuta la verificación de SFC o DISM"))
    pending = signals.get("pending_reboot")
    if pending:
        reasons.append(("warn", "Reinicio pendiente: " + ", ".join(pending)))
    shutdowns, bugs = signals.get("unexpected_shutdowns"), signals.get("bugchecks")
    window = signals.get("window_days", EVENT_WINDOW_DAYS)
    if bugs:
        reasons.append(("critical" if bugs >= 2 else "warn",
                        f"{bugs} pantallazo(s) azul(es) en los últimos {window} días"))
    if shutdowns:
        reasons.append(("critical" if shutdowns >= 3 else "warn",
                        f"{shutdowns} apagado(s) inesperado(s) en los últimos {window} días"))
    uptime = signals.get("uptime_s")
    if uptime is not None and uptime > UPTIME_WARN_DAYS * 86400:
        reasons.append(("warn", f"Encendido desde hace {int(uptime // 86400)} días: reinicia para aplicar "
                                "actualizaciones"))
    for disk in signals.get("disks") or ():
        if disk.get("level") in ("warn", "critical"):
            reasons.append((disk["level"], f"Disco «{disk.get('model')}»: {disk.get('label', '').lower()}"))
    worst = max((lvl for lvl, _ in reasons), key=lambda lvl: LEVEL_RANK[lvl], default="ok")
    if worst in ("ok", "unknown"):
        worst = "ok" if integrity.get("verified") else "unknown"
    reasons.sort(key=lambda r: -LEVEL_RANK[r[0]])
    return {"level": worst, "label": LEVEL_LABEL[worst], "reasons": reasons,
            "verified": bool(integrity.get("verified"))}


# =============================================================================================
# Métricas de rendimiento (informe ejecutivo)
# =============================================================================================
def cpu_model() -> str:
    """Nombre comercial del procesador (registro en Windows, /proc/cpuinfo en Linux) o platform.processor()."""
    if IS_WINDOWS:
        try:
            name = reg_get(r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
            if name:
                return " ".join(str(name).split())
        except Exception:  # noqa: BLE001
            pass
    else:
        try:
            with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.lower().startswith("model name"):
                        return " ".join(line.split(":", 1)[1].split())
        except OSError:
            pass
    return platform.processor() or platform.machine() or "—"


def system_performance() -> Dict[str, Any]:
    """
    CPU, memoria, intercambio, arranque y procesos del equipo en este instante (psutil). Nunca lanza;
    lo que no se puede leer queda None. La CPU usa la medición desde la llamada anterior (no bloquea).
    """
    perf: Dict[str, Any] = {"cpu_model": cpu_model(), "cpu_percent": None, "cpu_logical": None,
                            "cpu_physical": None, "cpu_mhz": None, "ram_total": None, "ram_used": None,
                            "ram_percent": None, "swap_percent": None, "boot_time": None, "uptime_s": None,
                            "processes": None, "os": f"{platform.system()} {platform.release()} ({platform.version()})"}
    if not HAS_PSUTIL:
        return perf
    readers = {
        "cpu_percent": lambda: round(psutil.cpu_percent(interval=None), 1),
        "cpu_logical": lambda: psutil.cpu_count(logical=True),
        "cpu_physical": lambda: psutil.cpu_count(logical=False),
        "cpu_mhz": lambda: round(psutil.cpu_freq().current) if psutil.cpu_freq() else None,
        "processes": lambda: len(psutil.pids()),
        "swap_percent": lambda: round(psutil.swap_memory().percent, 1),
    }
    for key, read in readers.items():
        try:
            perf[key] = read()
        except Exception:  # noqa: BLE001
            pass
    try:
        vm = psutil.virtual_memory()
        perf.update(ram_total=vm.total, ram_used=vm.total - vm.available, ram_percent=round(vm.percent, 1))
    except Exception:  # noqa: BLE001
        pass
    try:
        boot = psutil.boot_time()
        perf["boot_time"] = dt.datetime.fromtimestamp(boot).isoformat(timespec="seconds")
        perf["uptime_s"] = max(0.0, dt.datetime.now().timestamp() - boot)
    except Exception:  # noqa: BLE001
        pass
    return perf


def format_duration(seconds: Optional[float]) -> str:
    """«3 d 4 h», «2 h 05 min», «45 s»: duraciones legibles para la interfaz y el informe. Pura."""
    if seconds is None:
        return "—"
    s = int(max(0, seconds))
    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {minutes:02d} min"
    if minutes:
        return f"{minutes} min {secs:02d} s"
    return f"{secs} s"


__all__ = ["CHECKS", "READ_ONLY_CHECKS", "REPAIR_STEPS", "VERDICTS", "LEVEL_LABEL", "STATE_FILE", "classify",
           "summary_lines", "run_check", "repair_system", "load_state", "record", "integrity_status",
           "collect_signals", "physical_disks", "parse_physical_disks", "parse_stability", "health_verdict",
           "system_performance", "format_duration", "pending_reboot_reasons"]
