# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_inicio.py (persistencia de inicio de Windows, solo lectura).

  · resolve_exe: lógica pura de extracción del ejecutable de una línea de comando.
  · read_startup_folders / export_entries: sobre carpetas y ficheros TEMPORALES de la prueba.
  · read_run_keys: lectura inocua del registro (solo se comprueba la forma de los datos).
  · open_location: solo los casos negativos (no se abre ninguna ventana del Explorador).
"""

import csv
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._inicio import (RUN_KEYS, export_entries, open_location, read_run_keys,  # noqa: E402
                             read_startup_folders, resolve_exe)


def test_resolve_exe():
    assert resolve_exe('"C:\\Program Files\\App\\app.exe" --min') == "C:\\Program Files\\App\\app.exe"
    assert resolve_exe("C:\\Tools\\t.exe /silent") == "C:\\Tools\\t.exe"
    assert resolve_exe("") == ""
    os.environ["LZ_TEST_DIR"] = "C:\\X"
    assert resolve_exe("%LZ_TEST_DIR%\\y.exe") == "C:\\X\\y.exe"


def test_carpetas_de_inicio_temporales():
    tmp = tempfile.mkdtemp(prefix="startup_")
    try:
        for name in ("a.lnk", "b.bat", "desktop.ini"):
            with open(os.path.join(tmp, name), "w") as fh:
                fh.write("x")
        rows = read_startup_folders([("Carpeta Inicio (prueba)", tmp),
                                     ("inexistente", os.path.join(tmp, "no_hay"))])
        nombres = [r["nombre"] for r in rows]
        assert nombres == ["a.lnk", "b.bat"]            # desktop.ini se omite; inexistente no falla
        assert all(r["existe"] and r["origen"] == "Carpeta Inicio (prueba)" for r in rows)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_export_csv_y_json():
    tmp = tempfile.mkdtemp(prefix="exp_")
    try:
        rows = [{"origen": "HKCU\\...\\Run", "nombre": "Ñandú", "comando": "c.exe", "ruta": "c.exe",
                 "existe": False, "ubicacion": "HKCU\\Software"}]
        pc = os.path.join(tmp, "inicio.csv")
        assert export_entries(rows, pc) == 1
        with open(pc, encoding="utf-8-sig") as fh:
            data = list(csv.DictReader(fh))
        assert data[0]["nombre"] == "Ñandú"
        pj = os.path.join(tmp, "inicio.json")
        export_entries(rows, pj)
        with open(pj, encoding="utf-8") as fh:
            assert json.load(fh)[0]["origen"] == "HKCU\\...\\Run"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_read_run_keys_forma():
    rows = read_run_keys()                              # lectura inocua del registro
    assert isinstance(rows, list)
    for r in rows:
        assert set(r) >= {"origen", "nombre", "comando", "ruta", "existe", "ubicacion"}
    assert len(RUN_KEYS) == 6


def test_open_location_casos_negativos():
    assert open_location("")[0] is False
    ok, msg = open_location("Z:\\no\\existe\\nada.exe")
    assert ok is False and "no existe" in msg


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
