# -*- coding: utf-8 -*-
"""
Pruebas unitarias de la normalización de eventos ETW. NO requieren Windows, admin ni pywintrace:
alimentan `normalize()` con eventos sintéticos con la MISMA forma que entrega pywintrace 0.2.0.

Ejecutar:  python test_normalize.py        (o: pytest test_normalize.py)
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize import NORMALIZED_SCHEMA, filetime_to_utc, normalize, summarize  # noqa: E402

_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def _to_filetime(dt: datetime.datetime) -> int:
    return int((dt - _EPOCH).total_seconds() * 10 ** 7)


def _header(pid=4242, tid=99, ts=None, guid="{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
            eid=1, opcode=1, level=4):
    return {"EventHeader": {
        "Size": 120, "HeaderType": 0, "Flags": 576, "EventProperty": 0,
        "ThreadId": tid, "ProcessId": pid,
        "TimeStamp": ts if ts is not None else _to_filetime(
            datetime.datetime(2026, 10, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)),
        "ProviderId": guid,
        "EventDescriptor": {"Id": eid, "Version": 0, "Channel": 0, "Level": level,
                            "Opcode": opcode, "Task": 1, "Keyword": 0x8000000000000010},
        "KernelTime": 0, "UserTime": 0, "ActivityId": "{00000000-0000-0000-0000-000000000000}"}}


def process_start_event():
    out = _header(eid=1, opcode=1)
    out["Task Name"] = "PROCESSSTART"
    out["Description"] = "Process %1 started"
    out["ProcessID"] = 7331
    out["ProcessSequenceNumber"] = 120345
    out["CreateTime"] = 133700000000000000
    out["ParentProcessID"] = 4242
    out["ImageName"] = "\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe"
    return (1, out)


def dns_query_event():
    out = _header(guid="{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}", eid=3006, opcode=0)
    out["Task Name"] = "DNSQUERY"
    out["Description"] = ""
    out["QueryName"] = "ejemplo.com"
    out["QueryType"] = 1
    return (3006, out)


def parse_error_event():
    out = _header(eid=99, opcode=0)
    out["Task Name"] = "DESCONOCIDO"
    out["UserData"] = b"\x01\x02\xff\x00rawbytes"
    return (99, out)


# --------------------------------------------------------------------------------------------
def test_schema_and_core_fields():
    n = normalize(process_start_event())
    assert n["schema"] == NORMALIZED_SCHEMA
    assert n["event_id"] == 1
    assert n["provider_guid"] == "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
    assert n["provider_name"] == "PROCESSSTART"
    assert n["process_id"] == 4242 and n["thread_id"] == 99
    assert n["opcode"] == 1 and n["level"] == 4


def test_timestamp_filetime_conversion():
    n = normalize(process_start_event())
    assert n["clock"] == "filetime"
    assert n["timestamp_utc"].startswith("2026-10-20T12:00:00")


def test_payload_fields_separated_from_meta():
    n = normalize(process_start_event())
    assert n["fields"]["ImageName"].endswith("notepad.exe")
    assert n["fields"]["ParentProcessID"] == 4242
    # las claves de metadatos NO deben filtrarse al payload
    for meta in ("EventHeader", "Task Name", "Description", "UserData"):
        assert meta not in n["fields"]
    assert n["parse_complete"] is True and n["raw_user_data_hex"] is None


def test_dns_event():
    n = normalize(dns_query_event())
    assert n["provider_name"] == "DNSQUERY"
    assert n["fields"]["QueryName"] == "ejemplo.com"
    assert n["event_id"] == 3006


def test_parse_error_keeps_raw():
    n = normalize(parse_error_event())
    assert n["parse_complete"] is False
    assert n["raw_user_data_hex"] == b"\x01\x02\xff\x00rawbytes".hex()


def test_ambiguous_clock_for_qpc_like_value():
    # Un valor pequeño (típico de contador QPC) NO es un FILETIME plausible
    iso, clock = filetime_to_utc(123456789)
    assert iso is None and clock == "ambiguous"
    n = normalize((1, _header(ts=123456789)))
    assert n["timestamp_utc"] is None and n["clock"] == "ambiguous"
    assert n["timestamp_raw"] == 123456789  # nunca se pierde el valor crudo


def test_tolerates_malformed_input():
    assert normalize(({}))["event_id"] is None          # solo un dict vacío
    assert normalize((5, {}))["event_id"] == 5          # sin cabecera
    assert normalize("basura")["schema"] == NORMALIZED_SCHEMA  # ni siquiera un dict


def test_summarize_is_readable():
    s = summarize(normalize(process_start_event()))
    assert "PROCESSSTART" in s and "pid=4242" in s


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"OK  {t.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"ERR {t.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERR {t.__name__}: EXCEPCIÓN {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} pruebas OK")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
