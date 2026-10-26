# -*- coding: utf-8 -*-
"""
Pruebas de collectors/etw_control.py (control del colector ETW desde la GUI). Sin Administrador ni
pywintrace: la sesión ETW es un DOBLE (el mismo FakeSession de test_etw_collector.py) y el bus
real de core/. Se comprueba la guía de requisitos, el arranque, la recepción, la parada y el fallo.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.etw_control import EtwController, readiness  # noqa: E402
from core.bus import EventBus  # noqa: E402
from tests.test_etw_collector import factory_with, make_raw  # noqa: E402


def test_readiness_orden_de_avisos():
    assert readiness(True, True, True)[0] is True
    ok, msg = readiness(True, True, False)
    assert ok is False and "núcleo de eventos" in msg
    ok, msg = readiness(True, False, True)
    assert ok is False and "pywintrace" in msg
    ok, msg = readiness(False, True, True)
    assert ok is False and "Administrador" in msg


def test_arranque_recepcion_y_parada():
    bus = EventBus(name="test-etw-control")
    bus.start()
    try:
        ctl = EtwController(bus, session_factory=factory_with(events=[make_raw(), make_raw()]))
        st = ctl.start()
        assert st["running"] is True and ctl.running
        assert st["received"] == 2 and st["published"] == 2   # llegaron al bus
        st = ctl.stop()
        assert st["running"] is False and not ctl.running
        assert st["received"] == 2                            # métricas de la última sesión
        assert ctl.stop()["running"] is False                 # parar dos veces es seguro
    finally:
        bus.stop()


def test_fallo_de_arranque_queda_explicado():
    bus = EventBus(name="test-etw-control-fail")
    bus.start()
    try:
        ctl = EtwController(bus, session_factory=factory_with(fail_start=PermissionError("Access is denied")))
        st = ctl.start()
        assert st["running"] is False and ctl.last_error
    finally:
        bus.stop()


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
