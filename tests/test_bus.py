# -*- coding: utf-8 -*-
"""
Pruebas del bus de eventos: cola acotada, políticas de overflow, métricas, errores de suscriptor,
cierre limpio y saturación concurrente. No requiere admin/ETW/PySide6.
"""

import os
import queue
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bus import EventBus, OverflowPolicy  # noqa: E402
from core.errors import BusError  # noqa: E402
from core.events import Event  # noqa: E402


def test_maxsize_must_be_positive():
    try:
        EventBus(maxsize=0)
    except BusError:
        return
    raise AssertionError("maxsize<=0 debería lanzar BusError (la cola debe estar acotada)")


def test_drop_newest_rejects_when_full():
    bus = EventBus(maxsize=3, policy=OverflowPolicy.DROP_NEWEST)   # sin start: comportamiento de cola
    results = [bus.publish(Event.create("p", payload={"i": i})) for i in range(5)]
    assert results == [True, True, True, False, False]
    m = bus.metrics()
    assert m.enqueued == 3 and m.dropped == 2 and m.published == 5


def test_drop_oldest_keeps_newest():
    bus = EventBus(maxsize=3, policy=OverflowPolicy.DROP_OLDEST)
    for i in range(5):
        bus.publish(Event.create("p", payload={"i": i}))
    m = bus.metrics()
    assert m.dropped == 2
    got = []
    while True:
        try:
            got.append(bus._q.get_nowait().payload["i"])
        except queue.Empty:
            break
    assert got == [2, 3, 4]        # se conservan los 3 más nuevos


def test_block_policy_times_out_without_hanging():
    bus = EventBus(maxsize=1, policy=OverflowPolicy.BLOCK, block_timeout=0.05)
    assert bus.publish(Event.create("p")) is True
    t0 = time.monotonic()
    assert bus.publish(Event.create("p")) is False     # llena → espera finita y descarta
    assert time.monotonic() - t0 < 1.0                 # no se cuelga indefinidamente
    assert bus.metrics().dropped == 1


def test_delivery_to_subscriber():
    bus = EventBus(maxsize=10)
    seen = []
    bus.subscribe(seen.append)
    bus.start()
    bus.publish(Event.create("p", payload={"i": 1}))
    bus.publish(Event.create("p", payload={"i": 2}))
    assert bus.flush(2.0)
    bus.stop()
    assert [e.payload["i"] for e in seen] == [1, 2]    # FIFO
    assert bus.metrics().delivered == 2


def test_subscriber_error_counted_and_bus_survives():
    bus = EventBus(maxsize=10)
    good = []

    def boom(_e):
        raise RuntimeError("fallo del suscriptor")

    bus.subscribe(boom)
    bus.subscribe(good.append)
    bus.start()
    bus.publish(Event.create("p"))
    bus.publish(Event.create("p"))
    assert bus.flush(2.0)
    bus.stop()
    m = bus.metrics()
    assert m.subscriber_errors == 2 and len(good) == 2 and m.delivered == 2


def test_stop_is_idempotent_and_drains():
    bus = EventBus(maxsize=10)
    seen = []
    bus.subscribe(seen.append)
    for _ in range(5):
        bus.publish(Event.create("p"))
    bus.start()
    bus.stop(drain=True)       # drena los 5 pendientes
    bus.stop()                 # idempotente
    assert len(seen) == 5 and bus.metrics().current_depth == 0


def test_saturation_concurrent_no_hang_and_counts_consistent():
    bus = EventBus(maxsize=50, policy=OverflowPolicy.DROP_NEWEST)
    delivered = []

    def slow(ev):
        delivered.append(ev)
        time.sleep(0.0003)     # suscriptor lento → fuerza saturación

    bus.subscribe(slow)
    bus.start()

    def producer():
        for _ in range(500):
            bus.publish(Event.create("p"))

    threads = [threading.Thread(target=producer) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert bus.flush(10.0)
    bus.stop(drain=True)
    m = bus.metrics()
    assert m.published == 3000                         # 6 × 500
    assert m.enqueued + m.dropped == m.published       # cada publicación: encolada o descartada
    assert m.delivered == m.enqueued                   # todo lo encolado se entregó (con drain)
    assert m.dropped > 0                               # hubo saturación real
    assert m.current_depth == 0


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
