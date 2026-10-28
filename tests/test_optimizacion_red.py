# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_optimizacion_red.py: lógica PURA (salud de adaptadores, anomalías, firmas,
procesos protegidos) y SEGURIDAD de las acciones: sin Windows o sin Administrador no se ejecuta
ningún comando, y los procesos críticos o con PID reutilizado nunca se finalizan. Nada de esto
modifica el equipo: subprocess y psutil se sustituyen por dobles donde haría falta.
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos import _optimizacion_red as opt  # noqa: E402


def test_adapter_health():
    assert opt.adapter_health(False, None) == ("inactivo", 0.0)
    assert opt.adapter_health(True, None) == ("ok", 0.0)
    good = {"packets_sent": 1000, "packets_recv": 1000, "errin": 1, "errout": 0, "dropin": 0, "dropout": 0}
    assert opt.adapter_health(True, good)[0] == "ok"
    bad = dict(good, dropin=100)
    state, ratio = opt.adapter_health(True, bad)
    assert state == "degradado" and ratio > opt.ERROR_RATIO_DEGRADED


def test_anomalias_y_firmas():
    assert opt.anomaly_reasons(1.0, 10 * 1024 ** 2, "running") == []
    reasons = opt.anomaly_reasons(80.0, 2 * 1024 ** 3, "zombie")
    assert len(reasons) == 3 and reasons[0].startswith("CPU")
    assert opt.signature_state("Valid") == "valid"
    assert opt.signature_state("NotSigned") == "invalid"
    assert opt.signature_state("HashMismatch") == "invalid"
    assert opt.signature_state("") == "unknown"


def test_procesos_protegidos():
    assert opt.is_protected(4, "System")
    assert opt.is_protected(1234, "LSASS.EXE")
    assert opt.is_protected(os.getpid(), "python")
    assert not opt.is_protected(99999, "notepad.exe")


def test_mantenimiento_no_ejecuta_sin_windows_o_sin_admin():
    calls = []
    orig_run, orig_win = opt.subprocess.run, opt.IS_WINDOWS
    try:
        opt.subprocess.run = lambda *a, **k: calls.append(a) or types.SimpleNamespace(
            returncode=0, stdout=b"", stderr=b"")
        opt.IS_WINDOWS = False
        res = opt.run_maintenance("winsock", admin=True)
        assert res["ok"] is False and "Windows" in res["message"]
        opt.IS_WINDOWS = True
        res = opt.run_maintenance("tcpip", admin=False)
        assert res["ok"] is False and "Administrador" in res["message"]
        assert calls == []
        res = opt.run_maintenance("nada", admin=True)
        assert res["ok"] is False
        res = opt.run_maintenance("dhcp", admin=True)
        assert res["ok"] is True and len(res["steps"]) == 2 and len(calls) == 2
        opt.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=1, stdout=b"fallo", stderr=b"")
        res = opt.run_maintenance("winsock", admin=True)
        assert res["ok"] is False and "código 1" in res["message"]
    finally:
        opt.subprocess.run, opt.IS_WINDOWS = orig_run, orig_win


def test_terminate_rechaza_protegidos_y_pid_reutilizado():
    if not opt.HAS_PSUTIL:
        return
    ok, msg = opt.terminate_process(os.getpid())
    assert ok is False and "crítico" in msg
    ok, msg = opt.terminate_process(os.getpid(), expected_name="otro_programa.exe")
    assert ok is False and "no se finaliza" in msg


def test_lecturas_de_humo():
    if not opt.HAS_PSUTIL:
        return
    adapters = opt.adapters_overview()
    assert isinstance(adapters, list)
    rows = opt.scan_processes(verify_signatures=False, sample_s=0.05)
    assert any(r["pid"] == os.getpid() and r["protected"] for r in rows)


def _run_all():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"OK  {name}")


if __name__ == "__main__":
    _run_all()
