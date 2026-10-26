# -*- coding: utf-8 -*-
"""
Pruebas de la lógica de muestreo de procesos del Monitor en Vivo (modulos/_procmon.py).

Todo con DOBLES: no llaman a psutil real, no necesitan privilegios ni procesos reales. Prueban la
normalización (valores no accesibles → None, nunca 0), el filtrado, la ordenación (desconocido al
final), los formateadores y la tolerancia a procesos que fallan durante la consulta.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._procmon import (ProcRow, access_summary, filter_rows, fmt_cpu, fmt_mem,  # noqa: E402
                              fmt_text, iter_rows, normalize_proc, process_detail, sort_rows)


class _FakeMem:
    def __init__(self, rss):
        self.rss = rss


class _FakeProc:
    """Imita un psutil.Process de process_iter: expone `.info` (dict)."""
    def __init__(self, info):
        self.info = info


class _BrokenProc:
    @property
    def info(self):
        raise RuntimeError("NoSuchProcess")  # proceso que desaparece durante la consulta


# --- normalize_proc ----------------------------------------------------------------------------
def test_normalize_completo_normaliza_cpu_por_nucleos():
    info = {"pid": 100, "name": "chrome.exe", "username": "EQUIPO\\ana",
            "cpu_percent": 400.0, "memory_info": _FakeMem(500 * 1024 ** 2), "status": "running"}
    r = normalize_proc(info, cpu_count=8)
    assert r.pid == 100 and r.name == "chrome.exe" and r.user == "EQUIPO\\ana"
    assert abs(r.cpu - 50.0) < 1e-6          # 400 % / 8 núcleos
    assert r.rss == 500 * 1024 ** 2 and r.status == "running"


def test_normalize_conserva_none_no_inventa_ceros():
    info = {"pid": 4, "name": None, "username": None, "cpu_percent": None,
            "memory_info": None, "status": None}
    r = normalize_proc(info, cpu_count=4)
    assert r.name is None and r.user is None
    assert r.cpu is None and r.rss is None and r.status is None   # desconocido, NO 0


def test_normalize_cpu_se_limita_a_100():
    r = normalize_proc({"pid": 1, "cpu_percent": 1000.0}, cpu_count=1)
    assert r.cpu == 100.0 and r.rss is None   # memory_info ausente → None


# --- iter_rows ---------------------------------------------------------------------------------
def test_iter_rows_tolera_procesos_rotos():
    procs = [_FakeProc({"pid": 1, "name": "a", "cpu_percent": 10, "memory_info": _FakeMem(1024 ** 2)}),
             _BrokenProc(),
             _FakeProc({"pid": 2, "name": "b", "cpu_percent": 20, "memory_info": None})]
    rows = iter_rows(procs, cpu_count=1)
    assert [r.pid for r in rows] == [1, 2]   # el roto se omite, no rompe el muestreo


# --- filter_rows -------------------------------------------------------------------------------
def _rows():
    return [ProcRow(10, "chrome.exe", "u", 1.0, 100, "running"),
            ProcRow(20, "python.exe", "u", 2.0, 200, "running"),
            ProcRow(305, "svchost.exe", None, None, None, "running")]


def test_filter_por_nombre_y_pid():
    assert [r.pid for r in filter_rows(_rows(), "chrome")] == [10]
    assert [r.pid for r in filter_rows(_rows(), "20")] == [20]
    assert len(filter_rows(_rows(), "")) == 3
    assert filter_rows(_rows(), "zzz") == []


# --- sort_rows ---------------------------------------------------------------------------------
def test_sort_cpu_desc_desconocido_al_final():
    out = sort_rows(_rows(), "cpu", descending=True)
    assert [r.pid for r in out] == [20, 10, 305]   # 2.0, 1.0, None al final


def test_sort_nombre_asc():
    out = sort_rows(_rows(), "name", descending=False)
    assert [r.name for r in out] == ["chrome.exe", "python.exe", "svchost.exe"]


def test_sort_clave_desconocida_no_altera():
    out = sort_rows(_rows(), "inexistente")
    assert [r.pid for r in out] == [10, 20, 305]


# --- formateadores -----------------------------------------------------------------------------
def test_formateadores_muestran_guion_para_none():
    assert fmt_cpu(None) == "—" and fmt_cpu(12.34).startswith("12.3")
    assert fmt_mem(None) == "—"
    assert fmt_mem(500 * 1024 ** 2) == "500 MB"
    assert fmt_mem(2 * 1024 ** 3).endswith("GB")
    assert fmt_text(None) == "—" and fmt_text("x") == "x"


# --- access_summary ----------------------------------------------------------------------------
def test_access_summary_cuenta_incompletos():
    s = access_summary(_rows())
    assert s["total"] == 3 and s["sin_usuario"] == 1 and s["sin_cpu"] == 1


# --- process_detail ----------------------------------------------------------------------------
class _FakeDetail:
    def exe(self):
        return "C:\\app\\a.exe"

    def cmdline(self):
        raise PermissionError("Access is denied")   # AccessDenied: ese dato no está disponible

    def create_time(self):
        return 1_000_000.0

    def num_threads(self):
        return 7

    def ppid(self):
        return 4


def test_process_detail_tolera_access_denied():
    d = process_detail(123, _proc=_FakeDetail())
    assert d["exe"].endswith("a.exe")
    assert d["cmdline"] is None          # lanzó AccessDenied → None, no rompe
    assert d["num_threads"] == 7 and d["ppid"] == 4
    assert "error" not in d


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
