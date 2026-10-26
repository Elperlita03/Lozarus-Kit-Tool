# -*- coding: utf-8 -*-
"""
OBSIDIAN — salud de la telemetría de Lozarus (SOLO LECTURA de métricas propias).

Mide cómo de sana está la tubería de eventos del propio programa, no el equipo:
  · ritmo de eventos del EventBus (eventos/minuto, a partir de dos muestras del contador),
  · tamaño en KB del fichero `eventos.jsonl` de la Caja Negra,
  · CPU y RAM del PROPIO proceso de Lozarus y nº de hilos vivos,
  · una puntuación de salud global del sistema (0-100).

Funciones puras y aisladas de Qt (las de E/S aceptan un proceso/ruta inyectable) para poder
probarlas sin interfaz ni privilegios. No modifican nada.
"""

import os
from typing import Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except Exception:  # noqa: BLE001
    psutil = None
    HAS_PSUTIL = False


def events_per_minute(prev_count: Optional[int], prev_t: Optional[float],
                      cur_count: int, cur_t: float) -> float:
    """
    Ritmo de eventos entre dos muestras (contador, instante monótono). Devuelve eventos/minuto.
    Pura. Devuelve 0.0 si no hay muestra previa, si el tiempo no avanzó o si el contador bajó
    (reinicio): nunca inventa un ritmo negativo.
    """
    if prev_count is None or prev_t is None:
        return 0.0
    delta_t = cur_t - prev_t
    delta_n = cur_count - prev_count
    if delta_t <= 0 or delta_n < 0:
        return 0.0
    return round(delta_n / delta_t * 60.0, 1)


def jsonl_size_kb(path: str) -> float:
    """Tamaño en KB del fichero de eventos (0.0 si no existe). Nunca lanza."""
    try:
        return round(os.path.getsize(path) / 1024, 1)
    except OSError:
        return 0.0


def process_vitals(proc=None) -> dict:
    """
    CPU %, RAM residente (MB) y nº de hilos del PROPIO proceso. `proc` permite inyectar un doble en
    las pruebas. Nunca lanza: lo que no se pueda leer queda como None.
    """
    out = {"cpu": None, "rss_mb": None, "threads": None}
    if proc is None:
        if not HAS_PSUTIL:
            return out
        try:
            proc = psutil.Process(os.getpid())
        except Exception:  # noqa: BLE001
            return out
    try:
        out["cpu"] = round(proc.cpu_percent(interval=None), 1)
    except Exception:  # noqa: BLE001
        pass
    try:
        out["rss_mb"] = round(proc.memory_info().rss / (1024 * 1024), 1)
    except Exception:  # noqa: BLE001
        pass
    try:
        out["threads"] = proc.num_threads()
    except Exception:  # noqa: BLE001
        pass
    return out


def health_score(cpu: Optional[float], ram: Optional[float], *, critical: int = 0, warning: int = 0,
                 honeypot_alert: bool = False, bus_ok: bool = True,
                 write_errors: int = 0) -> Tuple[int, str]:
    """
    Puntuación de salud global del sistema (0-100) + etiqueta. Pura. Parte de 100 y resta penalización
    por carga alta, hallazgos de la última auditoría, honeypot comprometido y fallos de la telemetría.
    """
    score = 100.0
    if cpu is not None and cpu > 85:
        score -= min(20, (cpu - 85) * 1.3)
    if ram is not None and ram > 85:
        score -= min(20, (ram - 85) * 1.3)
    score -= min(40, critical * 12)      # cada hallazgo CRITICAL pesa fuerte
    score -= min(20, warning * 3)
    if honeypot_alert:
        score -= 25                      # una trampa comprometida es un incidente real
    if not bus_ok:
        score -= 15
    score -= min(10, write_errors)
    value = max(0, min(100, int(round(score))))
    if value >= 85:
        etiqueta = "saludable"
    elif value >= 60:
        etiqueta = "aceptable"
    elif value >= 35:
        etiqueta = "degradado"
    else:
        etiqueta = "crítico"
    return value, etiqueta
