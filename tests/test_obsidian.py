# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_obsidian.py (salud de la telemetría). Lógica pura y E/S sobre ficheros/dobles
de la propia prueba; no mide el equipo real salvo la vía inocua de process_vitals con el PID propio.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._obsidian import (events_per_minute, health_score, jsonl_size_kb,  # noqa: E402
                               process_vitals)


def test_events_per_minute():
    assert events_per_minute(None, None, 10, 1.0) == 0.0        # sin muestra previa
    assert events_per_minute(0, 0.0, 60, 60.0) == 60.0          # 60 eventos en 60 s = 60/min
    assert events_per_minute(100, 10.0, 130, 25.0) == 120.0     # 30 eventos en 15 s = 120/min
    assert events_per_minute(10, 5.0, 10, 5.0) == 0.0           # tiempo no avanza
    assert events_per_minute(50, 1.0, 10, 2.0) == 0.0           # contador bajó (reinicio) → 0, no negativo


def test_jsonl_size_kb():
    tmp = tempfile.mkdtemp(prefix="obs_")
    try:
        path = os.path.join(tmp, "eventos.jsonl")
        with open(path, "wb") as fh:
            fh.write(b"x" * 2048)
        assert jsonl_size_kb(path) == 2.0
        assert jsonl_size_kb(os.path.join(tmp, "no_existe.jsonl")) == 0.0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


class _FakeProc:
    def cpu_percent(self, interval=None):
        return 3.14159

    def memory_info(self):
        class M:
            rss = 50 * 1024 * 1024
        return M()

    def num_threads(self):
        return 11


def test_process_vitals_con_doble_y_real():
    v = process_vitals(_FakeProc())
    assert v["cpu"] == 3.1 and v["rss_mb"] == 50.0 and v["threads"] == 11
    real = process_vitals()  # proceso propio: inocuo
    assert set(real) == {"cpu", "rss_mb", "threads"}


def test_process_vitals_tolera_errores():
    class Boom:
        def cpu_percent(self, interval=None):
            raise RuntimeError("x")

        def memory_info(self):
            raise RuntimeError("x")

        def num_threads(self):
            raise RuntimeError("x")

    v = process_vitals(Boom())
    assert v == {"cpu": None, "rss_mb": None, "threads": None}


def test_health_score():
    assert health_score(10, 20) == (100, "saludable")
    v, lbl = health_score(10, 20, critical=2)        # 2 CRITICAL = -24
    assert v == 76 and lbl == "aceptable"
    v, lbl = health_score(10, 20, honeypot_alert=True)   # -25
    assert v == 75 and lbl == "aceptable"
    v, lbl = health_score(99, 99, critical=4, warning=5, honeypot_alert=True, bus_ok=False)
    assert v <= 35 and lbl in ("degradado", "crítico")
    assert 0 <= health_score(100, 100, critical=99)[0] <= 100   # nunca fuera de rango


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"OK  {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERR {t.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} OK")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
