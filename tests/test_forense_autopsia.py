# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_forense_autopsia.py. Todo con datos en memoria o ficheros temporales propios de
la prueba; no se ejecuta ningún binario ni se toca la Caja Negra real.

  · shannon_entropy / classify_entropy: valores conocidos (ceros → 0; 0..255 → 8; aviso > 7,2).
  · parse_pe_headers: sobre un búfer PE mínimo fabricado a mano (sin fichero real).
  · extract_indicators: IPs, URLs, rutas de registro y APIs sospechosas en un blob.
  · read_events / event_category / event_row / export_report: sobre un eventos.jsonl de pega con una
    línea corrupta (que debe saltarse).
  · analyze_file: sobre un fichero de texto y sobre un fichero 'MZ' fabricado; hashes contra hashlib.
"""

import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._forense_autopsia import (analyze_file, classify_entropy, event_category,  # noqa: E402
                                       event_row, export_report, extract_indicators,
                                       parse_pe_headers, read_events, shannon_entropy)


def _pe_buffer():
    """Búfer PE mínimo: MZ, e_lfanew=0x80, 'PE\\0\\0', COFF x64 + optional PE32+ consola."""
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)            # e_lfanew
    buf[0x80:0x84] = b"PE\x00\x00"
    # COFF: machine, n_sec, timestamp, psym, nsym, opt_size, characteristics
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 4, 1600000000, 0, 0, 0xF0, 0x2002)
    struct.pack_into("<H", buf, 0x98, 0x20B)           # optional magic (PE32+)
    struct.pack_into("<H", buf, 0x98 + 68, 3)          # subsystem = consola
    return bytes(buf)


def test_shannon_entropy_valores_conocidos():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_classify_entropy_aviso():
    assert classify_entropy(7.5)[1] is True
    assert classify_entropy(7.21)[1] is True
    assert classify_entropy(6.5)[1] is False
    assert classify_entropy(2.0)[1] is False


def test_parse_pe_headers():
    pe = parse_pe_headers(_pe_buffer())
    assert pe is not None
    assert pe["machine"] == 0x8664 and "x64" in pe["machine_name"]
    assert pe["sections"] == 4
    assert pe["magic_name"] == "PE32+"
    assert pe["subsystem"] == 3 and "Consola" in pe["subsystem_name"]
    assert pe["is_dll"] is True and pe["is_exe"] is True
    assert pe["timestamp_utc"] and pe["timestamp_utc"].startswith("2020-")


def test_parse_pe_headers_no_pe():
    assert parse_pe_headers(b"esto no es un PE") is None
    assert parse_pe_headers(b"MZ" + b"\x00" * 4) is None  # demasiado corto / sin firma PE


def test_extract_indicators():
    blob = (b"connect 203.0.113.9 and 1.2.3.4\n"
            b"GET https://malo.example/payload.bin\n"
            b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            b"VirtualAlloc WriteProcessMemory CreateRemoteThread powershell -enc\n")
    ind = extract_indicators(blob)
    assert "1.2.3.4" in ind["ips"] and "203.0.113.9" in ind["ips"]
    assert any("malo.example" in u for u in ind["urls"])
    assert any("Run" in r for r in ind["registry"])
    for api in ("VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "powershell"):
        assert api in ind["apis"], api


def test_read_events_y_categorias():
    tmp = tempfile.mkdtemp(prefix="bb_")
    try:
        path = os.path.join(tmp, "eventos.jsonl")
        evs = [
            {"source": "honeypot", "event_type": "honeypot.triggered", "payload": {"trap": "x"}},
            {"source": "red:puertos", "event_type": "network.new_listen_port",
             "payload": {"port_key": "TCP:0.0.0.0:445"}},
            {"source": "monitor:snapshot", "event_type": "monitor.snapshot", "payload": {"a": 1}},
        ]
        with open(path, "w", encoding="utf-8") as fh:
            for e in evs:
                fh.write(json.dumps(e) + "\n")
            fh.write("{ линия corrupta no-json\n")   # debe saltarse
        todos = read_events(path)
        assert len(todos) == 3
        assert todos[0]["source"] == "monitor:snapshot"   # más reciente primero
        solo_red = read_events(path, source="network")
        assert len(solo_red) == 1 and solo_red[0]["source"] == "red:puertos"
        buscados = read_events(path, text="445")
        assert len(buscados) == 1
        assert read_events(os.path.join(tmp, "no_existe.jsonl")) == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_event_category_y_row():
    assert event_category({"source": "fantasma:portapapeles"}) == "privacy"
    assert event_category({"source": "forensics:autopsia"}) == "forensics"
    assert event_category({"source": "honeypot"}) == "honeypot"
    assert event_category({"source": "desconocido:x"}) == "otros"
    ev = {"source": "red:puertos", "event_type": "network.new_listen_port",
          "payload": {"port_key": "TCP:0.0.0.0:445"},
          "provenance": {"received_utc": "2026-10-21T10:30:00+00:00"}}
    hora, cat, fuente, tipo, resumen = event_row(ev)
    assert hora == "2026-10-21 10:30:00" and cat == "network"
    assert fuente == "red:puertos" and tipo == "network.new_listen_port"
    assert "port_key" in resumen


def test_export_report_json_y_txt():
    tmp = tempfile.mkdtemp(prefix="exp_")
    try:
        evs = [{"source": "honeypot", "payload": {"n": i}} for i in range(3)]
        pj = os.path.join(tmp, "ev.json")
        n = export_report(evs, pj)
        assert n == 3
        with open(pj, encoding="utf-8") as fh:
            assert len(json.load(fh)) == 3
        pt = os.path.join(tmp, "ev.txt")
        export_report(evs, pt)
        with open(pt, encoding="utf-8") as fh:
            assert sum(1 for _ in fh) == 3
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_analyze_file_texto_y_pe():
    tmp = tempfile.mkdtemp(prefix="autop_")
    try:
        # 1) fichero de texto normal
        data = (b"GET https://malo.example/x 10.0.0.9 HKCU\\Software\\Run "
                b"VirtualAlloc CreateRemoteThread\n")
        ft = os.path.join(tmp, "muestra.txt")
        with open(ft, "wb") as fh:
            fh.write(data)
        r = analyze_file(ft)
        assert r["ok"] and r["is_pe"] is False
        assert r["md5"] == hashlib.md5(data).hexdigest()
        assert r["sha256"] == hashlib.sha256(data).hexdigest()
        assert r["size"] == len(data)
        assert "VirtualAlloc" in r["indicators"]["apis"]
        assert "10.0.0.9" in r["indicators"]["ips"]

        # 2) fichero 'MZ' fabricado → PE detectado
        pe_bytes = _pe_buffer()
        fp = os.path.join(tmp, "muestra.bin")
        with open(fp, "wb") as fh:
            fh.write(pe_bytes)
        r2 = analyze_file(fp)
        assert r2["ok"] and r2["is_pe"] is True and r2["pe"] is not None
        assert r2["pe"]["magic_name"] == "PE32+"
        assert r2["sha256"] == hashlib.sha256(pe_bytes).hexdigest()

        # 3) inexistente
        r3 = analyze_file(os.path.join(tmp, "no_existe.bin"))
        assert r3["ok"] is False and r3["error"]
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
