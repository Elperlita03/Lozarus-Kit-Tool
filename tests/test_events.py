# -*- coding: utf-8 -*-
"""
Pruebas del modelo común de eventos. No requieren Windows, Administrador, ETW ni PySide6.
Ejecutar:  python tests/test_events.py   (o: pytest tests/test_events.py)
"""

import datetime as dt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.errors import SchemaVersionError, SerializationError, ValidationError  # noqa: E402
from core.events import (EVENT_SCHEMA_VERSION, ClockType, Event, ObservationQuality,  # noqa: E402
                         Provenance)

_UTC = dt.timezone.utc


def test_create_fills_provenance_and_defaults():
    ev = Event.create("etw", payload={"ImageName": "notepad.exe"}, provider_name="PROCESSSTART")
    assert ev.source == "etw"
    assert ev.schema_version == EVENT_SCHEMA_VERSION
    assert ev.event_id and len(ev.event_id) >= 8          # id único autogenerado
    assert ev.provenance is not None and ev.provenance.collector == "etw"
    assert ev.payload["ImageName"] == "notepad.exe"
    # campos ausentes NO se inventan
    assert ev.process_id is None and ev.correlation_id is None and ev.timestamp_utc is None


def test_rejects_naive_timestamp():
    try:
        Event(source="x", timestamp_utc=dt.datetime(2026, 10, 20, 12, 0, 0))  # naive
    except ValidationError:
        return
    raise AssertionError("un timestamp naive debería rechazarse (no se asume UTC)")


def test_accepts_aware_timestamp_and_keeps_raw():
    ts = dt.datetime(2026, 10, 20, 12, 0, 0, tzinfo=_UTC)
    ev = Event(source="etw", timestamp_utc=ts, timestamp_raw=133_700_000_000_000_000,
               clock_type=ClockType.FILETIME)
    assert ev.timestamp_utc == ts
    assert ev.timestamp_raw == 133_700_000_000_000_000   # el crudo se conserva
    assert ev.clock_type is ClockType.FILETIME


def test_ambiguous_clock_has_no_utc_but_keeps_raw():
    ev = Event(source="etw", timestamp_utc=None, timestamp_raw=123456789, clock_type=ClockType.UNKNOWN)
    assert ev.timestamp_utc is None and ev.clock_type is ClockType.UNKNOWN
    assert ev.timestamp_raw == 123456789


def test_rejects_negative_pid():
    for bad in (-1, "4"):
        try:
            Event(source="x", process_id=bad)
        except ValidationError:
            continue
        raise AssertionError(f"process_id inválido debería rechazarse: {bad!r}")


def test_payload_and_raw_are_separate():
    ev = Event(source="etw", payload={"QueryName": "ejemplo.com"},
               raw={"Task Name": "DNSQUERY", "UserData": "ff00"})
    assert "QueryName" in ev.payload and "Task Name" not in ev.payload
    assert ev.raw is not None and ev.raw["Task Name"] == "DNSQUERY"


def test_roundtrip_dict_and_json():
    ts = dt.datetime(2026, 10, 20, 12, 0, 0, tzinfo=_UTC)
    ev = Event.create("etw", payload={"ImageName": "a.exe", "ParentProcessID": 4},
                      provider_name="PROCESSSTART", provider_guid="{GUID}", native_event_id=1,
                      event_type="ProcessStart", timestamp_utc=ts, timestamp_raw=42,
                      clock_type=ClockType.FILETIME, process_id=10, thread_id=20,
                      observation=ObservationQuality.COMPLETE)
    back = Event.from_dict(ev.to_dict())
    assert back.to_dict() == ev.to_dict()                 # ida y vuelta estable (dict)
    assert Event.from_json(ev.to_json()).event_id == ev.event_id  # ida y vuelta (JSON)
    assert back.provenance.observation is ObservationQuality.COMPLETE


def test_from_dict_rejects_incompatible_schema_major():
    d = Event.create("etw").to_dict()
    d["schema_version"] = "lozarus.event.v2"
    try:
        Event.from_dict(d)
    except SchemaVersionError:
        return
    raise AssertionError("una versión mayor distinta debería rechazarse")


def test_from_dict_rejects_naive_iso_timestamp():
    d = Event.create("etw").to_dict()
    d["timestamp_utc"] = "2026-10-20T12:00:00"            # sin zona
    try:
        Event.from_dict(d)
    except SerializationError:
        return
    raise AssertionError("un ISO sin zona debería rechazarse")


def test_unknown_provider_is_allowed_as_none():
    ev = Event.create("procmon")                          # sin proveedor
    assert ev.provider_name is None and ev.provider_guid is None
    assert Event.from_dict(ev.to_dict()).provider_name is None


def test_with_correlation_is_immutable_copy():
    ev = Event.create("etw")
    ev2 = ev.with_correlation("corr-123")
    assert ev.correlation_id is None                      # original intacto (inmutable)
    assert ev2.correlation_id == "corr-123" and ev2.event_id == ev.event_id


def test_provenance_roundtrip():
    p = Provenance(collector="etw", host="PC", observation=ObservationQuality.PARTIAL, note="x")
    assert Provenance.from_dict(p.to_dict()).observation is ObservationQuality.PARTIAL


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
