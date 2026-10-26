# -*- coding: utf-8 -*-
"""
Pruebas de la Caja Negra (forensics/blackbox.py): suscripción al EventBus real y persistencia JSONL.

Qué son: pruebas de COMPORTAMIENTO con E/S real en un DIRECTORIO TEMPORAL y el EventBus real del
núcleo. Usan hilos (el escritor de la Caja Negra y el despacho del bus), así que esperan de forma
acotada hasta que los eventos quedan escritos. No usan psutil, no tocan el sistema del usuario y no
dependen de la GUI.
"""

import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bus import EventBus  # noqa: E402
from core.events import Event, ObservationQuality  # noqa: E402
from forensics.blackbox import CajaNegra  # noqa: E402


def _ev(i):
    return Event.create(source="test", observation=ObservationQuality.COMPLETE,
                        event_type="test.event", payload={"i": i})


def _wait_until(fn, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.02)
    return fn()


def test_persiste_eventos_del_bus_en_jsonl():
    tmp = tempfile.mkdtemp(prefix="cn_")
    bus = EventBus(name="test-bus")
    cn = CajaNegra(tmp)
    cn.attach(bus)
    bus.start()
    cn.start()
    try:
        for i in range(5):
            assert bus.publish(_ev(i)) is True
        assert _wait_until(lambda: cn.count() == 5), f"escritos={cn.count()}"
        cn.stop()
        bus.stop()
        # el fichero existe y tiene 5 líneas JSON válidas, en orden
        with open(cn.path, encoding="utf-8") as fh:
            lines = [l for l in fh.read().splitlines() if l.strip()]
        assert len(lines) == 5
        payloads = [json.loads(l)["payload"]["i"] for l in lines]
        assert payloads == [0, 1, 2, 3, 4]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_count_y_metrics_reflejan_lo_escrito():
    tmp = tempfile.mkdtemp(prefix="cn_")
    bus = EventBus(name="test-bus")
    cn = CajaNegra(tmp)
    cn.attach(bus)
    bus.start()
    cn.start()
    try:
        for i in range(3):
            bus.publish(_ev(i))
        assert _wait_until(lambda: cn.count() == 3)
        m = cn.metrics()
        assert m["written"] == 3 and m["received"] >= 3
        assert m["dropped"] == 0 and m["write_errors"] == 0
    finally:
        cn.stop()
        bus.stop()
        shutil.rmtree(tmp, ignore_errors=True)


def test_stop_es_idempotente_y_vacia_la_cola():
    tmp = tempfile.mkdtemp(prefix="cn_")
    bus = EventBus(name="test-bus")
    cn = CajaNegra(tmp)
    cn.attach(bus)
    bus.start()
    cn.start()
    try:
        for i in range(4):
            bus.publish(_ev(i))
        bus.stop()                      # deja de despachar; lo pendiente ya está en la cola de la caja
        cn.stop()                       # debe vaciar su cola antes de cerrar
        cn.stop()                       # segunda llamada: segura
        assert cn.count() == 4
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_evento_sin_to_json_no_rompe_el_escritor():
    # Un objeto raro no debe matar el hilo escritor: se cuenta como error, los demás siguen.
    tmp = tempfile.mkdtemp(prefix="cn_")
    cn = CajaNegra(tmp)
    cn.start()
    try:
        cn._on_event(object())          # sin to_json: no debe escribirse (JSONL válido) ni romper el hilo
        cn._on_event(_ev(99))           # este sí debe escribirse
        assert _wait_until(lambda: cn.count() >= 1)
        cn.stop()
        assert cn.count() == 1                     # solo el evento válido llegó al disco
        assert cn.metrics()["write_errors"] >= 1   # el objeto no serializable se contó como error
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_cola_llena_cuenta_descartes_sin_bloquear():
    tmp = tempfile.mkdtemp(prefix="cn_")
    cn = CajaNegra(tmp, maxsize=2)      # NO se arranca el escritor: la cola se llena
    try:
        for i in range(5):
            cn._on_event(_ev(i))         # no bloquea aunque la cola se llene
        assert cn.received == 5
        assert cn.dropped == 3           # 5 recibidos, 2 caben, 3 descartados
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
