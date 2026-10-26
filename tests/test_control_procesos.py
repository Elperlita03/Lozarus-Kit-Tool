# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_control_procesos.py.

  · check_target: lógica PURA de protección (núcleo, propio Lozarus, procesos críticos).
  · Acciones REALES (congelar/reanudar/prioridad) SOLO sobre un proceso hijo que crea la propia
    prueba (`python -c "sleep"`), que se mata al terminar. Nunca se toca otro proceso del equipo.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psutil  # noqa: E402

from modulos._control_procesos import (check_target, lower_priority, priority_label,  # noqa: E402
                                       restore_priority, resume_process, suspend_process)


def test_check_target_protege_nucleo_lozarus_y_criticos():
    assert check_target(0, "System Idle Process")[0] is False
    assert check_target(4, "System")[0] is False
    assert check_target(1234, "lsass.exe")[0] is False
    assert check_target(1234, "CSRSS.EXE")[0] is False          # sin distinguir mayúsculas
    assert check_target(1234, "MsMpEng.exe")[0] is False        # Defender: no se desactiva
    assert check_target(1234, "explorer.exe")[0] is False
    assert check_target(777, "python.exe", own_pids={777})[0] is False   # el propio Lozarus
    assert check_target(1234, "")[0] is False                   # sin nombre: no se actúa
    assert check_target(1234, "notepad.exe", own_pids={1})[0] is True


def _child():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    time.sleep(0.3)
    return proc


def test_congelar_y_reanudar_proceso_hijo_real():
    child = _child()
    try:
        ok, msg = suspend_process(child.pid)
        assert ok, msg
        time.sleep(0.2)
        assert psutil.Process(child.pid).status() == psutil.STATUS_STOPPED  # congelado de verdad
        ok, msg = resume_process(child.pid)
        assert ok, msg
        time.sleep(0.2)
        assert psutil.Process(child.pid).status() != psutil.STATUS_STOPPED
    finally:
        try:
            psutil.Process(child.pid).resume()
        except Exception:  # noqa: BLE001
            pass
        child.kill()


def test_prioridad_minima_y_restauracion_exacta():
    child = _child()
    try:
        previa = psutil.Process(child.pid).nice()
        ok, msg, devuelta = lower_priority(child.pid)
        assert ok, msg
        assert devuelta == previa
        assert psutil.Process(child.pid).nice() == getattr(psutil, "IDLE_PRIORITY_CLASS", 19)
        ok, msg = restore_priority(child.pid, devuelta)
        assert ok, msg
        assert psutil.Process(child.pid).nice() == previa
    finally:
        child.kill()


def test_proceso_inexistente_no_lanza():
    child = _child()
    child.kill()
    child.wait()
    ok, msg = suspend_process(child.pid)
    assert ok is False and msg


def test_priority_label_legible():
    if hasattr(psutil, "IDLE_PRIORITY_CLASS"):
        assert "mínima" in priority_label(psutil.IDLE_PRIORITY_CLASS)
    assert priority_label(999999) == "999999"


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
