# -*- coding: utf-8 -*-
"""
Pruebas UNITARIAS del colector ETW de producción. NO requieren Administrador, ETW ni pywintrace:
inyectan una sesión FALSA que entrega eventos sintéticos con la forma real de pywintrace 0.2.0.
La captura ETW real es una prueba de integración aparte (test_etw_integration.py).
"""

import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.etw_collector import (EtwCollector, ETW_CLOCK_QPC, ETW_CLOCK_SYSTEMTIME,  # noqa: E402
                                      normalize_etw)
from core.bus import EventBus, OverflowPolicy  # noqa: E402
from core.contracts import Collector, LossState  # noqa: E402
from core.events import ClockType, ObservationQuality  # noqa: E402

_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
_FT_2026 = int((dt.datetime(2026, 10, 20, 12, 0, 0, tzinfo=dt.timezone.utc) - _EPOCH).total_seconds() * 10 ** 7)


def make_raw(pid=4242, tid=99, ts=_FT_2026, guid="{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
             eid=1, opcode=1, task="PROCESSSTART", payload=None, user_data=None, description="Proc"):
    out = {"EventHeader": {"ProcessId": pid, "ThreadId": tid, "TimeStamp": ts, "ProviderId": guid,
                           "EventDescriptor": {"Id": eid, "Opcode": opcode, "Level": 4, "Keyword": 16,
                                               "Version": 0, "Channel": 0},
                           "ActivityId": "{00000000-0000-0000-0000-000000000000}"},
           "Task Name": task, "Description": description}
    out.update(payload or {})
    if user_data is not None:
        out["UserData"] = user_data
    return (eid, out)


class FakeSession:
    """Sesión ETW falsa: entrega eventos en start() (síncrono) y devuelve una pérdida configurable."""

    def __init__(self, name, pname, pguid, on_event, cc, ring, *, events=None, fail_start=None,
                 loss=(None, None)):
        self.name = name
        self.on_event = on_event
        self._events = events or []
        self._fail_start = fail_start
        self._loss = loss
        self.started = False
        self.stopped = False

    def start(self):
        if self._fail_start is not None:
            raise self._fail_start
        self.started = True
        for ev in self._events:
            self.on_event(ev)

    def stop(self):
        self.stopped = True

    def read_loss(self):
        return self._loss


def factory_with(events=None, fail_start=None, loss=(None, None)):
    captured = {}

    def factory(name, pname, pguid, on_event, cc, ring):
        s = FakeSession(name, pname, pguid, on_event, cc, ring, events=events,
                        fail_start=fail_start, loss=loss)
        captured["session"] = s
        return s
    factory.captured = captured
    return factory


# --- Normalización -----------------------------------------------------------------------------
def test_normalize_process_start_filetime():
    ev = normalize_etw(make_raw(payload={"ImageName": "notepad.exe", "ParentProcessID": 10}),
                       source="etw:test", client_context=ETW_CLOCK_SYSTEMTIME)
    assert ev.source == "etw:test"
    assert ev.provider_name == "PROCESSSTART"
    assert ev.provider_guid == "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
    assert ev.native_event_id == 1 and ev.process_id == 4242 and ev.thread_id == 99
    assert ev.clock_type is ClockType.FILETIME
    assert ev.timestamp_utc is not None and ev.timestamp_utc.year == 2026
    assert ev.timestamp_raw == _FT_2026                      # crudo conservado
    assert ev.payload["ImageName"] == "notepad.exe"          # payload normalizado
    assert "EventHeader" not in ev.payload                   # metadatos separados
    assert ev.raw["opcode"] == 1 and ev.raw["keyword"] == 16  # metadatos en raw
    assert ev.provenance.observation is ObservationQuality.COMPLETE


def test_normalize_qpc_clock_is_not_converted():
    ev = normalize_etw(make_raw(ts=123456789), source="etw:test", client_context=ETW_CLOCK_QPC)
    assert ev.clock_type is ClockType.QPC
    assert ev.timestamp_utc is None                          # no se asume conversión
    assert ev.timestamp_raw == 123456789                     # crudo conservado


def test_normalize_implausible_filetime_is_unknown():
    ev = normalize_etw(make_raw(ts=42), source="etw:test", client_context=ETW_CLOCK_SYSTEMTIME)
    assert ev.clock_type is ClockType.UNKNOWN and ev.timestamp_utc is None and ev.timestamp_raw == 42


def test_normalize_raw_fallback_on_parse_error():
    ev = normalize_etw(make_raw(payload={}, user_data=b"\x01\x02\xff"), source="etw:test")
    assert ev.provenance.observation is ObservationQuality.RAW_ONLY
    assert ev.raw["user_data_hex"] == b"\x01\x02\xff".hex()
    assert ev.payload == {}


def test_normalize_missing_optional_fields():
    raw = (1, {"EventHeader": {"EventDescriptor": {"Id": 7}}, "Task Name": "X"})  # sin pid/tid/ts
    ev = normalize_etw(raw, source="etw:test")
    assert ev.process_id is None and ev.thread_id is None
    assert ev.timestamp_utc is None and ev.timestamp_raw is None
    assert ev.native_event_id == 7


# --- Contrato y ciclo de vida ------------------------------------------------------------------
def test_contract_compliance():
    bus = EventBus()
    c = EtwCollector(bus, provider="kernel-process", session_factory=factory_with())
    assert isinstance(c, Collector)
    assert c.session_name.startswith("Lozarus-ETW-")       # propiedad de sesión inequívoca


def test_start_publishes_to_bus():
    bus = EventBus(maxsize=100)
    seen = []
    bus.subscribe(seen.append)
    bus.start()
    c = EtwCollector(bus, session_factory=factory_with(events=[make_raw(), make_raw(), make_raw()]))
    c.start()
    assert bus.flush(2.0)
    bus.stop()
    m = c.metrics()
    assert m.events_received == 3 and m.events_published == 3 and m.bus_dropped == 0
    assert len(seen) == 3 and c.health().events_total == 3


def test_start_error_is_recorded_not_raised():
    bus = EventBus()
    c = EtwCollector(bus, session_factory=factory_with(fail_start=PermissionError("Access is denied")))
    c.start()                                                # no debe lanzar
    assert c._started is False
    h = c.health()
    assert h.init_error is not None and "denegado" in h.init_error and h.degraded is True


def test_backpressure_counts_bus_drops_separately():
    bus = EventBus(maxsize=3, policy=OverflowPolicy.DROP_NEWEST)   # sin start → no drena
    c = EtwCollector(bus, session_factory=factory_with(events=[make_raw() for _ in range(5)]))
    c.start()
    m = c.metrics()
    assert m.events_received == 5
    assert m.events_published == 3 and m.bus_dropped == 2          # descarte INTERNO del bus
    assert m.events_published + m.bus_dropped == m.events_received


def test_stop_cleans_only_own_session_and_is_idempotent():
    f = factory_with(events=[make_raw()], loss=(0, 0))
    bus = EventBus(maxsize=10)
    c = EtwCollector(bus, session_factory=f)
    c.stop()                                                 # stop sin start: seguro
    c.start()
    c.stop()
    assert f.captured["session"].stopped is True
    c.stop()                                                 # idempotente
    assert c._started is False


def test_loss_unknown_while_running_known_after_stop():
    f = factory_with(events=[make_raw()], loss=(0, 0))
    bus = EventBus(maxsize=10)
    c = EtwCollector(bus, session_factory=f)
    c.start()
    assert c.source_loss() == (None, None)                   # durante el run: DESCONOCIDA, no 0
    assert c.health().events_loss_state is LossState.UNKNOWN
    c.stop()
    assert c.source_loss() == (0, 0)                         # tras STOP: cero confirmado
    assert c.health().events_loss_state is LossState.NONE


def test_metrics_distinguish_etw_loss_from_bus_drops():
    f = factory_with(events=[make_raw() for _ in range(5)], loss=(7, 1))
    bus = EventBus(maxsize=2, policy=OverflowPolicy.DROP_NEWEST)
    c = EtwCollector(bus, session_factory=f)
    c.start()
    c.stop()
    m = c.metrics()
    assert m.source_events_lost == 7 and m.source_buffers_lost == 1   # pérdida de ETW
    assert m.bus_dropped == 3                                         # descartes del bus (distinto)
    assert m.stop_duration_s is not None and m.stop_duration_s >= 0


def test_consumer_error_counted_not_fatal():
    bad = ("no-es-una-tupla-valida", {"roto": True})          # forma inesperada, 2 elementos
    # normalize tolera esto; para forzar un error de consumidor, inyectamos un evento que rompe
    broken = (1, None)                                        # out None → normalize lo tolera (dict vacío)
    bus = EventBus(maxsize=10)
    seen = []
    bus.subscribe(seen.append)
    bus.start()
    c = EtwCollector(bus, session_factory=factory_with(events=[broken, make_raw()]))
    c.start()
    assert bus.flush(2.0)
    bus.stop()
    # ambos se normalizan sin romper el consumidor; el colector sigue publicando
    assert c.metrics().events_received == 2 and c.metrics().consumer_errors == 0
    del bad


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
