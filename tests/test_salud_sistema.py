# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_salud_sistema.py y del ejecutor de herramientas largas (_utilidades.run_tool).
Nunca se lanza sfc ni DISM: las comprobaciones usan un `runner` doble y el ejecutor real se prueba con
un proceso Python hijo que imita su salida (incluida la de sfc en UTF-16). El historial se guarda en un
JSON temporal de la prueba. Cubren:

  · la interpretación de la salida de sfc (inglés y español) y de DISM (/English), sin dar nunca por
    buena una salida que no se entiende;
  · progreso, cancelación, tiempo máximo y comando inexistente del ejecutor;
  · que fuera de Windows o sin Administrador no se ejecuta nada;
  · la reparación en dos pasos y su progreso global;
  · el historial (último resultado solo si es concluyente) y el veredicto global.
"""

import datetime as dt
import json
import os
import shutil
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos import _salud_sistema as ss  # noqa: E402
from modulos._utilidades import decode_output, last_percent, run_tool  # noqa: E402

NOW = dt.datetime(2026, 10, 28, 12, 0, 0)


def test_classify_sfc_ingles_y_espanol():
    cases = {
        "Windows Resource Protection did not find any integrity violations.": "ok",
        "Protección de recursos de Windows no encontró ninguna infracción de integridad.": "ok",
        "Windows Resource Protection found corrupt files and successfully repaired them.": "repaired",
        "Protección de recursos de Windows encontró archivos dañados y los reparó correctamente.": "repaired",
        "Windows Resource Protection found corrupt files but was unable to fix some of them.": "unrepairable",
        "Protección de recursos de Windows encontró archivos dañados, pero no pudo reparar algunos.": "unrepairable",
        "Windows Resource Protection found integrity violations.": "corrupt",
        "Windows Resource Protection could not perform the requested operation.": "failed",
        "There is a system repair pending which requires reboot to complete.": "pending_reboot",
        "You must be an administrator running a console session in order to use the sfc utility.": "requires_admin",
        "Salida que nadie entiende": "unknown",
        "": "unknown",
    }
    for text, verdict in cases.items():
        assert ss.classify("sfc", text, 0) == verdict, text


def test_classify_dism():
    assert ss.classify("dism", "No component store corruption detected.\nThe operation completed successfully.") == "ok"
    assert ss.classify("dism", "The component store is repairable.\nThe operation completed successfully.") == "repairable"
    assert ss.classify("dism", "The component store cannot be repaired.") == "unrepairable"
    assert ss.classify("dism", "The restore operation completed successfully.\n"
                               "The component store corruption was repaired.") == "repaired"
    assert ss.classify("dism", "The restore operation completed successfully.") == "ok"
    assert ss.classify("dism", "Error: 0x800f081f\n\nThe source files could not be found.") == "failed"
    assert ss.classify("dism", "Error: 740\n\nElevated permissions are required to run DISM.") == "requires_admin"
    assert ss.classify("dism", "", 740) == "requires_admin"
    assert ss.classify("dism", "Deployment Image Servicing and Management tool", 0) == "unknown"


def test_lineas_de_resumen_sin_progreso():
    text = ("Beginning system scan.\r\nVerification 5% complete.\rVerification 45% complete.\r"
            "Verificación 99% completada.\r\n[==========================100.0%==========================]\r\n"
            "Windows Resource Protection did not find any integrity violations.\r\n")
    assert ss.summary_lines(text) == ["Beginning system scan.",
                                      "Windows Resource Protection did not find any integrity violations."]


def test_decode_output_y_porcentajes():
    msg = "Verificación 45% completada."
    assert decode_output(b"\xff\xfe" + msg.encode("utf-16-le")) == msg
    assert decode_output(msg.encode("utf-16-le")) == msg                 # UTF-16 sin BOM (sfc redirigido)
    assert decode_output(b"\x00" + msg.encode("utf-16-le")[:-1]).endswith("completada")  # desalineado
    assert decode_output(b"plain ascii") == "plain ascii"
    assert decode_output(b"") == ""
    assert last_percent("Verification 45% complete.") == 45.0
    assert last_percent("[=====  10.0%  ]\r[=========  25,5 %  ]") == 25.5
    assert last_percent("sin porcentaje") is None
    assert last_percent("999% no es un porcentaje válido") is None


def _child(code):
    return [sys.executable, "-c", code]


def test_run_tool_progreso_y_utf16():
    seen = []
    code = ("import sys, time\n"
            "for p in (10, 60, 100):\n"
            "    sys.stdout.buffer.write(('\\rVerification %d%% complete.' % p).encode('utf-16-le'))\n"
            "    sys.stdout.flush(); time.sleep(0.15)\n"
            "sys.stdout.buffer.write('\\r\\nWindows Resource Protection did not find any integrity violations.'"
            ".encode('utf-16-le'))\n")
    res = run_tool(_child(code), timeout=30, on_progress=seen.append, poll_s=0.05)
    assert res["rc"] == 0 and not res["cancelled"] and not res["timed_out"]
    assert ss.classify("sfc", res["output"], res["rc"]) == "ok"
    assert seen and seen[-1] == 100.0 and seen == sorted(seen)


def test_run_tool_cancelar_tiempo_y_comando_inexistente():
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    res = run_tool(_child("import time; print('Verification 1% complete.', flush=True); time.sleep(30)"),
                   timeout=60, cancel=stop, poll_s=0.05)
    assert res["cancelled"] is True and res["seconds"] < 20
    res = run_tool(_child("import time; time.sleep(30)"), timeout=0.4, poll_s=0.05)
    assert res["timed_out"] is True
    res = run_tool(["lozarus_comando_que_no_existe_zzz"], timeout=5)
    assert res["rc"] == 127 and "no disponible" in res["output"]
    big = run_tool(_child("print('x' * 300000)"), timeout=30, poll_s=0.05)   # más que el búfer de una tubería
    assert big["rc"] == 0 and len(big["output"]) == 300000


class _FakeRunner:
    def __init__(self, outputs):
        self.outputs = outputs     # herramienta -> salida (o dict con la respuesta completa)
        self.calls = []

    def __call__(self, argv, timeout=0, cancel=None, on_progress=None):
        tool = "sfc" if "sfc" in os.path.basename(argv[0]).lower() else "dism"
        self.calls.append(argv)
        out = self.outputs[tool]
        if isinstance(out, dict):
            return out
        if on_progress is not None:
            for pct in (0.0, 50.0, 100.0):
                on_progress(pct)
        return {"rc": 0, "output": out, "cancelled": False, "timed_out": False, "seconds": 3.0}


class _State:
    """Redirige el historial a un JSON temporal y permite simular Windows. Restaura todo al salir."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="lz_salud_")
        self.orig = (ss.STATE_FILE, ss.IS_WINDOWS)
        ss.STATE_FILE = os.path.join(self.dir, "salud_sistema.json")
        ss.IS_WINDOWS = True
        return self

    def __exit__(self, *exc):
        ss.STATE_FILE, ss.IS_WINDOWS = self.orig
        shutil.rmtree(self.dir, ignore_errors=True)


def test_run_check_no_ejecuta_fuera_de_windows_ni_sin_admin():
    fake = _FakeRunner({"sfc": "Windows Resource Protection did not find any integrity violations."})
    with _State():
        ss.IS_WINDOWS = False
        res = ss.run_check("sfc_verify", admin=True, runner=fake)
        assert res["verdict"] == "unavailable" and res["ran"] is False
        ss.IS_WINDOWS = True
        res = ss.run_check("sfc_verify", admin=False, runner=fake)
        assert res["verdict"] == "requires_admin" and res["ran"] is False
        assert fake.calls == [] and not os.path.exists(ss.STATE_FILE)   # nada ejecutado ni guardado


def test_run_check_registra_resultado_e_historial():
    with _State():
        seen = []
        fake = _FakeRunner({"sfc": "Windows Resource Protection found integrity violations.",
                            "dism": "No component store corruption detected."})
        res = ss.run_check("sfc_verify", admin=True, runner=fake, on_progress=seen.append, now=NOW)
        assert res["verdict"] == "corrupt" and res["level"] == "critical" and res["ran"] is True
        assert fake.calls[0][1:] == ["/verifyonly"] and seen == [0.0, 50.0, 100.0]
        ss.run_check("dism_check", admin=True, runner=fake, now=NOW)
        cancelled = _FakeRunner({"sfc": {"rc": 1, "output": "", "cancelled": True, "timed_out": False,
                                         "seconds": 9.0}})
        res = ss.run_check("sfc_verify", admin=True, runner=cancelled, now=NOW)
        assert res["verdict"] == "cancelled"
        state = ss.load_state()
        assert state["last"]["sfc_verify"]["verdict"] == "corrupt"   # cancelar no borra lo que se sabía
        assert state["last"]["dism_check"]["verdict"] == "ok"
        assert [h["verdict"] for h in state["history"]] == ["cancelled", "ok", "corrupt"]
        with open(ss.STATE_FILE, encoding="utf-8") as fh:
            json.load(fh)   # JSON válido
        for _ in range(ss.HISTORY_MAX + 5):
            ss.record({**res, "verdict": "ok"})
        assert len(ss.load_state()["history"]) == ss.HISTORY_MAX


def test_estado_corrupto_vuelve_a_vacio():
    with _State():
        with open(ss.STATE_FILE, "w", encoding="utf-8") as fh:
            fh.write("{esto no es json")
        state = ss.load_state()
        assert state["last"] == {} and state["history"] == []


def test_reparacion_en_dos_pasos():
    with _State():
        progress = []
        fake = _FakeRunner({"dism": "The restore operation completed successfully.\n"
                                    "The component store corruption was repaired.",
                            "sfc": "Windows Resource Protection did not find any integrity violations."})
        res = ss.repair_system(admin=True, runner=fake, on_progress=progress.append)
        assert [s["key"] for s in res["steps"]] == ["dism_restore", "sfc_scan"]
        assert res["verdict"] == "repaired" and res["level"] == "ok"   # DISM reparó y SFC ya no ve nada
        assert progress == sorted(progress) and progress[0] == 0.0 and progress[-1] == 100.0
        assert any(54.0 <= p <= 56.0 for p in progress)                # DISM ocupa hasta el 55 %
        stopped = _FakeRunner({"dism": {"rc": 1, "output": "", "cancelled": True, "timed_out": False,
                                        "seconds": 1.0},
                               "sfc": "Windows Resource Protection did not find any integrity violations."})
        res = ss.repair_system(admin=True, runner=stopped)
        assert res["verdict"] == "cancelled" and len(stopped.calls) == 1   # SFC no se lanza tras cancelar
        none = _FakeRunner({})
        res = ss.repair_system(admin=False, runner=none)
        assert res["verdict"] == "requires_admin" and none.calls == []


def test_integridad_y_veredicto_global():
    fresh = {"key": "sfc_verify", "when": (NOW - dt.timedelta(days=2)).isoformat(), "verdict": "ok", "level": "ok",
             "label": "ÍNTEGRO"}
    old = dict(fresh, when=(NOW - dt.timedelta(days=60)).isoformat())
    calm = {"pending_reboot": [], "uptime_s": 3600.0, "unexpected_shutdowns": 0, "bugchecks": 0, "disks": []}

    status = ss.integrity_status({"last": {"sfc_verify": fresh}}, now=NOW)
    assert status["verified"] is True and status["files"]["verdict"] == "ok"
    verdict = ss.health_verdict(calm, status, now=NOW)
    assert verdict["level"] == "ok" and verdict["label"] == "SALUDABLE"

    stale = ss.integrity_status({"last": {"sfc_verify": old}}, now=NOW)
    assert stale["verified"] is False
    assert ss.health_verdict(calm, stale, now=NOW)["level"] == "unknown"   # «no se sabe» no es «sano»
    assert ss.health_verdict(calm, ss.integrity_status({}, now=NOW), now=NOW)["label"] == "SIN VERIFICAR"

    corrupt = dict(fresh, verdict="corrupt", level="critical", label="INFRACCIONES")
    assert ss.health_verdict(calm, ss.integrity_status({"last": {"sfc_verify": corrupt}}, now=NOW),
                             now=NOW)["level"] == "critical"
    warn = ss.health_verdict(dict(calm, pending_reboot=["Windows Update"]), status, now=NOW)
    assert warn["level"] == "warn" and any("Windows Update" in t for _l, t in warn["reasons"])
    assert ss.health_verdict(dict(calm, bugchecks=2), status, now=NOW)["level"] == "critical"
    assert ss.health_verdict(dict(calm, unexpected_shutdowns=1), status, now=NOW)["level"] == "warn"
    assert ss.health_verdict(dict(calm, uptime_s=40 * 86400.0), status, now=NOW)["level"] == "warn"
    sick = dict(calm, disks=[{"model": "HDD 1TB", "level": "critical", "label": "EN MAL ESTADO"}])
    result = ss.health_verdict(sick, status, now=NOW)
    assert result["level"] == "critical" and result["reasons"][0][0] == "critical"   # lo grave, primero


def test_parsers_de_powershell():
    assert ss.parse_stability({"k41": 2, "k6008": 1, "bug": 0}) == (2, 0)   # mismo apagado: el mayor, no la suma
    assert ss.parse_stability({"k41": -1, "k6008": -1, "bug": -1}) == (None, None)   # desconocido, no 0
    assert ss.parse_stability(None) == (None, None)
    disks = ss.parse_physical_disks([{"model": "Samsung SSD 980", "media": "SSD", "bus": "NVMe", "health": "Healthy",
                                      "status": "OK", "size": 1000204886016, "letters": ["c", "D"]},
                                     {"model": "WD", "media": "Unspecified", "health": "Warning", "letters": "E"}])
    assert disks[0]["media"] == "SSD" and disks[0]["level"] == "ok" and disks[0]["letters"] == ["C", "D"]
    assert disks[1]["media"] == "—" and disks[1]["level"] == "warn" and disks[1]["letters"] == ["E"]
    assert ss.parse_physical_disks({}) == []


def test_rendimiento_y_duraciones():
    perf = ss.system_performance()
    for key in ("cpu_model", "cpu_percent", "ram_total", "ram_percent", "uptime_s", "processes", "os"):
        assert key in perf
    assert ss.format_duration(None) == "—"
    assert ss.format_duration(45) == "45 s"
    assert ss.format_duration(125) == "2 min 05 s"
    assert ss.format_duration(3 * 3600 + 300) == "3 h 05 min"
    assert ss.format_duration(3 * 86400 + 4 * 3600) == "3 d 4 h"


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
