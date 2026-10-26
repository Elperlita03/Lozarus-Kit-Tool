# -*- coding: utf-8 -*-
"""
Muestreo de procesos para el Monitor en Vivo (SOLO LECTURA / OBSERVACIÓN).

Separado de la interfaz y del motor de detección (`_monitor.py`) para poder probar la lógica sin
privilegios, sin Qt y sin procesos reales: `normalize_proc`, `filter_rows`, `sort_rows` y los
formateadores son funciones puras que aceptan datos inyectados.

Principios:
  · No termina procesos, no cambia prioridades, no inyecta: solo observa.
  · Un valor NO accesible (sin permisos, proceso que desaparece) se conserva como None —nunca se
    inventa un 0—. La CPU se expresa como % de la CPU TOTAL del equipo (0..100).
  · El muestreo real (`sample_processes`) se ejecuta en un hilo de fondo; la GUI filtra y ordena
    sobre la lista ya muestreada, sin volver a consultar el sistema.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:  # la lógica pura se puede probar igualmente sin psutil
    psutil = None
    HAS_PSUTIL = False

# Atributos que se piden a psutil.process_iter. ad_value=None marca como None lo no accesible.
PROC_ATTRS = ["pid", "name", "username", "cpu_percent", "memory_info", "status"]


@dataclass
class ProcRow:
    """Fila normalizada de un proceso. Los campos no accesibles son None (nunca 0 inventado)."""
    pid: Optional[int]
    name: Optional[str]
    user: Optional[str]
    cpu: Optional[float]     # % de la CPU TOTAL del equipo (0..100)
    rss: Optional[int]       # memoria residente en bytes
    status: Optional[str]


def normalize_proc(info: Dict[str, Any], cpu_count: int = 1) -> ProcRow:
    """
    Convierte el dict de `psutil.process_iter(PROC_ATTRS, ad_value=None)` en una `ProcRow` segura.
    Tolera valores ausentes o None; normaliza la CPU por el nº de núcleos (psutil da % por núcleo,
    así que un proceso puede superar el 100 % sin normalizar).
    """
    pid = info.get("pid")
    raw_cpu = info.get("cpu_percent")
    cpu: Optional[float] = None
    if isinstance(raw_cpu, (int, float)):
        cpu = min(100.0, max(0.0, float(raw_cpu)) / max(1, cpu_count))
    mem = info.get("memory_info")
    rss = getattr(mem, "rss", None) if mem is not None else None
    if not isinstance(rss, int) or rss < 0:
        rss = None
    return ProcRow(
        pid=pid if isinstance(pid, int) else None,
        name=(info.get("name") or None),
        user=(info.get("username") or None),
        cpu=cpu,
        rss=rss,
        status=(info.get("status") or None),
    )


def iter_rows(proc_iter: Iterable[Any], cpu_count: int = 1) -> List[ProcRow]:
    """
    Recorre un iterable estilo `psutil.process_iter` (objetos con atributo `.info`) y normaliza cada
    proceso, tolerando los que desaparecen o lanzan durante la consulta (NoSuchProcess, AccessDenied).
    """
    rows: List[ProcRow] = []
    for proc in proc_iter:
        try:
            info = getattr(proc, "info", None)
            if info is None:
                continue
            rows.append(normalize_proc(info, cpu_count))
        except Exception:  # noqa: BLE001  (un proceso que falla no debe tumbar el muestreo)
            continue
    return rows


def sample_processes(cpu_count: Optional[int] = None) -> List[ProcRow]:
    """
    Muestra REAL de procesos con psutil (pensada para el hilo de fondo). Lanza RuntimeError si psutil
    no está disponible, para que la GUI muestre un estado de error claro.
    """
    if not HAS_PSUTIL:
        raise RuntimeError("psutil no está disponible")
    if cpu_count is None:
        cpu_count = psutil.cpu_count() or 1
    return iter_rows(psutil.process_iter(PROC_ATTRS, ad_value=None), cpu_count)


def filter_rows(rows: Iterable[ProcRow], query: str) -> List[ProcRow]:
    """Filtra por subcadena del nombre (sin distinguir mayúsculas) o por coincidencia del PID."""
    q = (query or "").strip().lower()
    if not q:
        return list(rows)
    out: List[ProcRow] = []
    for r in rows:
        if q in (r.name or "").lower() or (r.pid is not None and q in str(r.pid)):
            out.append(r)
    return out


# Claves de ordenación. Los valores desconocidos (None) se tratan como el MÍNIMO, de modo que al
# ordenar de forma descendente quedan al final (lo accesible y con más uso, arriba).
_SORT_KEYS: Dict[str, Callable[[ProcRow], Any]] = {
    "pid": lambda r: r.pid if r.pid is not None else -1,
    "name": lambda r: (r.name or "").lower(),
    "user": lambda r: (r.user or "").lower(),
    "cpu": lambda r: r.cpu if r.cpu is not None else -1.0,
    "rss": lambda r: r.rss if r.rss is not None else -1,
    "status": lambda r: (r.status or "").lower(),
}
SORT_COLUMNS = tuple(_SORT_KEYS)


def sort_rows(rows: Iterable[ProcRow], key: str, descending: bool = False) -> List[ProcRow]:
    """Ordena por una columna conocida; si la clave no existe, devuelve la lista sin cambios."""
    fn = _SORT_KEYS.get(key)
    if fn is None:
        return list(rows)
    return sorted(rows, key=fn, reverse=descending)


# --- Formateadores (puros, para la tabla) ------------------------------------------------------
def fmt_cpu(cpu: Optional[float]) -> str:
    return "—" if cpu is None else f"{cpu:.1f} %"


def fmt_mem(rss: Optional[int]) -> str:
    if rss is None:
        return "—"
    if rss < 1024 ** 3:
        return f"{rss / 1024 ** 2:.0f} MB"
    return f"{rss / 1024 ** 3:.2f} GB"


def fmt_text(value: Optional[str]) -> str:
    return value if value else "—"


def access_summary(rows: Iterable[ProcRow]) -> Dict[str, int]:
    """Cuenta cuántos procesos no exponen usuario o CPU (indicio de que harían falta más permisos)."""
    rows = list(rows)
    return {
        "total": len(rows),
        "sin_usuario": sum(1 for r in rows if r.user is None),
        "sin_cpu": sum(1 for r in rows if r.cpu is None),
    }


def process_detail(pid: int, _proc: Any = None) -> Dict[str, Any]:
    """
    Metadatos ADICIONALES del proceso seleccionado (los que de verdad se puedan leer): ruta del
    ejecutable, línea de comando, nº de hilos, PID padre e instante de creación. Lo no accesible
    queda como None. `_proc` permite inyectar un doble en las pruebas. Solo lectura.
    """
    if _proc is None:
        if not HAS_PSUTIL:
            return {"error": "psutil no disponible"}
        try:
            _proc = psutil.Process(pid)
        except Exception as exc:  # noqa: BLE001
            return {"error": f"{type(exc).__name__}: {exc}"}
    out: Dict[str, Any] = {}
    for field, getter in (("exe", "exe"), ("cmdline", "cmdline"), ("create_time", "create_time"),
                          ("num_threads", "num_threads"), ("ppid", "ppid"), ("status", "status")):
        try:
            out[field] = getattr(_proc, getter)()
        except Exception:  # noqa: BLE001  (AccessDenied u otros: ese dato no está disponible)
            out[field] = None
    # Conexiones IP abiertas por el proceso (psutil ≥ 6: net_connections; antes: connections).
    try:
        getter = getattr(_proc, "net_connections", None) or getattr(_proc, "connections")
        conns = []
        for c in getter(kind="inet")[:20]:
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—"
            remota = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—"
            conns.append(f"{local} → {remota}  {c.status}")
        out["connections"] = conns
    except Exception:  # noqa: BLE001  (sin permisos o no disponible: desconocido, no «0»)
        out["connections"] = None
    return out
