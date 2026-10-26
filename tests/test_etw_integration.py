# -*- coding: utf-8 -*-
"""
Prueba de INTEGRACIÓN del colector ETW (específica de Windows). Se SALTA automáticamente si no se
cumplen los requisitos (no Windows, sin Administrador, o sin pywintrace), para no dar falsos positivos.

Cuando se cumplen: arranca EtwCollector sobre Microsoft-Windows-Kernel-Process, genera actividad
lanzando procesos de prueba y verifica que llegan Events normalizados al bus.

Ejecutar (consola de Administrador, en un entorno con pywintrace; p. ej. el venv del spike):
    python tests/test_etw_integration.py
    python -m pytest tests/test_etw_integration.py -v
"""

import ctypes
import os
import platform
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.etw_collector import EtwCollector  # noqa: E402
from core.bus import EventBus  # noqa: E402

try:
    import pytest  # noqa: E402
    _HAS_PYTEST = True
except ImportError:
    _HAS_PYTEST = False


def _requirements():
    if platform.system() != "Windows":
        return False, "no es Windows"
    try:
        __import__("etw")                     # solo sonda de disponibilidad (no se usa el módulo)
    except Exception as exc:  # noqa: BLE001
        return False, f"pywintrace no disponible: {exc}"
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return False, "sin privilegios de Administrador"
    except Exception:
        return False, "no se pudo comprobar el nivel de privilegios"
    return True, ""


def test_etw_real_capture():
    ok, reason = _requirements()
    if not ok:
        msg = f"Requisitos no disponibles: {reason} (PENDIENTE de ejecución en Windows con Administrador)"
        if _HAS_PYTEST:
            pytest.skip(msg)
        print("SALTADA —", msg)
        return

    bus = EventBus(maxsize=1000)
    seen = []
    bus.subscribe(seen.append)
    bus.start()
    collector = EtwCollector(bus, provider="kernel-process")
    collector.start()
    assert collector._started, f"la sesión no arrancó: {collector.health().init_error}"
    try:
        time.sleep(1.0)                       # deja que el consumidor arranque
        for _ in range(5):                    # genera procesos de corta duración
            subprocess.run(["cmd", "/c", "ver"], capture_output=True)
            time.sleep(0.2)
        time.sleep(1.0)
        bus.flush(3.0)
    finally:
        collector.stop()
        bus.stop()

    assert len(seen) >= 1, "no llegó ningún evento ETW real al bus"
    ev = seen[0]
    assert ev.schema_version == "lozarus.event.v1"
    assert ev.provider_guid, "el evento no identifica su proveedor"
    m = collector.metrics()
    print(f"OK: recibidos={m.events_received} publicados={m.events_published} "
          f"bus_dropped={m.bus_dropped} etw_lost={m.source_events_lost} "
          f"stop={m.stop_duration_s}s · ejemplo provider={ev.provider_name} pid={ev.process_id}")


if __name__ == "__main__":
    ok, reason = _requirements()
    if not ok:
        print(f"PENDIENTE — requisitos no disponibles aquí: {reason}")
        print("Ejecuta en un Windows real como Administrador (con pywintrace) para validar la captura.")
        raise SystemExit(0)
    test_etw_real_capture()
    print("Integración OK.")
