# -*- coding: utf-8 -*-
"""
Prueba de CONTRATO del colector: un colector falso (sin Windows) satisface el Protocol, emite al
bus, reporta salud y pérdidas desconocidas, y es idempotente. Verifica además que el núcleo NO
importa PySide6. La prueba ETW real queda como integración específica de Windows (spikes/etw).
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.bus import EventBus  # noqa: E402
from core.contracts import BaseCollector, Collector, EventSink, LossState  # noqa: E402
from core.events import Event, ObservationQuality  # noqa: E402


class FakeCollector(BaseCollector):
    """Colector de prueba: emite N eventos sintéticos al arrancar. No toca Windows ni la GUI."""

    def __init__(self, sink: EventSink, n: int = 5):
        super().__init__("fake", sink)
        self._n = n

    def start(self) -> None:
        if self._started:
            return                      # idempotente: no reemite
        self._started = True
        for i in range(self._n):
            self._emit(Event.create("fake", payload={"i": i},
                                    observation=ObservationQuality.COMPLETE))

    def stop(self) -> None:
        self._started = False


def test_bus_is_eventsink_and_collector_satisfies_protocol():
    bus = EventBus()
    assert isinstance(bus, EventSink)          # el bus cumple el sink estructuralmente
    collector = FakeCollector(bus)
    assert isinstance(collector, Collector)    # el colector cumple el Protocol sin acoplarse


def test_collector_emits_to_bus():
    bus = EventBus(maxsize=100)
    seen = []
    bus.subscribe(seen.append)
    bus.start()
    collector = FakeCollector(bus, n=5)
    collector.start()
    assert bus.flush(2.0)
    bus.stop()
    assert [e.payload["i"] for e in seen] == [0, 1, 2, 3, 4]


def test_collector_health_reports_unknown_loss_by_default():
    bus = EventBus(maxsize=100)
    collector = FakeCollector(bus, n=3)
    collector.start()
    h = collector.health()
    assert h.events_total == 3 and h.started is True
    assert h.source_events_lost is None                    # desconocida, no 0
    assert h.events_loss_state is LossState.UNKNOWN
    assert h.degraded is False                             # sin error de init ni pérdida detectada


def test_start_stop_idempotent():
    bus = EventBus(maxsize=100)
    collector = FakeCollector(bus, n=2)
    collector.start()
    collector.start()                                      # segundo start no reemite
    collector.stop()
    collector.stop()                                       # stop idempotente
    assert collector.health().events_total == 2


def test_core_has_no_gui_dependency():
    # Busca IMPORTS reales de la GUI (no simples menciones en docstrings).
    import ast
    forbidden = {"PySide6", "qtawesome", "PyQt5", "PyQt6"}
    for rel in ("core/__init__.py", "core/events.py", "core/contracts.py", "core/bus.py",
                "core/errors.py"):
        tree = ast.parse(open(os.path.join(ROOT, rel), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = {n.name.split(".")[0] for n in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods = {(node.module or "").split(".")[0]}
            else:
                continue
            clash = mods & forbidden
            assert not clash, f"{rel} importa dependencia de GUI: {clash}"


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
