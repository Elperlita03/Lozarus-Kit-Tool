# -*- coding: utf-8 -*-
"""
Prueba de INTEGRACIÓN del spike ETW. Se SALTA automáticamente si no se cumplen los requisitos
(no Windows, sin Administrador, o sin pywintrace), para no dar un falso positivo.

Cuando los requisitos están disponibles: inicia una sesión real sobre Microsoft-Windows-Kernel-Process,
genera actividad lanzando un proceso de corta duración y verifica que llega al menos un evento ETW
real, con su proveedor identificado.

Ejecutar (en una consola de Administrador, con pywintrace instalado):
    python -m pytest test_integration.py -v
    # o, sin pytest:
    python test_integration.py
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import etw_spike  # noqa: E402

try:
    import pytest  # noqa: E402
    _HAS_PYTEST = True
except ImportError:
    _HAS_PYTEST = False


def _requirements_ok() -> tuple:
    p = etw_spike.check_prerequisites()
    if not p["is_windows"]:
        return False, "no es Windows"
    if not p["pywintrace_available"]:
        return False, f"pywintrace no disponible: {p['pywintrace_import_error']}"
    if not p["is_admin"]:
        return False, "sin privilegios de Administrador"
    return True, ""


def _capture_with_activity():
    """Lanza la captura en un hilo y genera actividad de proceso para provocar eventos."""
    import threading
    box = {}

    def worker():
        box["result"] = etw_spike.run("kernel-process", seconds=10.0, max_events=10)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    time.sleep(1.5)  # deja que la sesión arranque
    for _ in range(3):  # genera procesos de corta duración
        subprocess.run(["cmd", "/c", "ver"], capture_output=True)
        time.sleep(0.3)
    t.join(timeout=15)
    return box.get("result", {})


def test_etw_real_event_captured():
    ok, reason = _requirements_ok()
    if not ok:
        if _HAS_PYTEST:
            pytest.skip(f"Requisitos no disponibles: {reason} (prueba PENDIENTE de ejecución en admin)")
        print(f"SALTADA: {reason} (PENDIENTE de ejecución en Windows con Administrador)")
        return
    result = _capture_with_activity()
    assert result.get("started") is True, f"la sesión no arrancó: {result.get('error')}"
    assert result.get("count", 0) >= 1, "no se recibió ningún evento ETW real"
    sample = result["events"][0]
    assert sample["schema"] == "lozarus.etw.v0"
    assert sample["provider_guid"], "el evento no identifica su proveedor"
    print(f"OK: {result['count']} eventos reales; ejemplo: {etw_spike.summarize(sample)}")


if __name__ == "__main__":
    ok, reason = _requirements_ok()
    if not ok:
        print(f"PENDIENTE — requisitos no disponibles aquí: {reason}")
        print("Ejecuta este archivo en un Windows real como Administrador para validar la captura.")
        raise SystemExit(0)
    test_etw_real_event_captured()
    print("Integración OK.")
