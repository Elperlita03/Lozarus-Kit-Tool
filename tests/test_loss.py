# -*- coding: utf-8 -*-
"""
Pruebas de la contabilidad de pérdidas: distingue CERO confirmado, DETECTADA y DESCONOCIDA.
Regla clave: un contador desconocido es None, NUNCA 0. No requiere admin/ETW/PySide6.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.contracts import LossState, SensorHealth  # noqa: E402


def test_lossstate_three_way():
    assert LossState.of(None) is LossState.UNKNOWN       # desconocida ≠ cero
    assert LossState.of(0) is LossState.NONE             # cero confirmado
    assert LossState.of(5) is LossState.DETECTED         # pérdida detectada


def test_sensorhealth_unknown_is_not_zero():
    h = SensorHealth(name="etw", alive=True, started=True, events_total=100,
                     source_events_lost=None, source_buffers_lost=None)
    assert h.events_loss_state is LossState.UNKNOWN
    assert h.source_events_lost is None                  # jamás se convierte en 0
    assert h.to_dict()["events_loss_state"] == "unknown"


def test_sensorhealth_confirmed_zero():
    h = SensorHealth(name="etw", alive=True, started=True, events_total=100,
                     source_events_lost=0, source_buffers_lost=0)
    assert h.events_loss_state is LossState.NONE
    assert h.buffers_loss_state is LossState.NONE


def test_sensorhealth_detected_marks_degraded_via_collector_default():
    # Pérdida detectada en la fuente
    h = SensorHealth(name="etw", alive=True, started=True, events_total=100,
                     source_events_lost=7, source_buffers_lost=0, degraded=True)
    assert h.events_loss_state is LossState.DETECTED
    assert h.degraded is True


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
