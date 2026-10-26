# -*- coding: utf-8 -*-
"""
Prueba de regresión de C5: ghost_preview (modulos/_tacticas.py) debe distinguir un recuento REAL de
un fallo al obtenerlo. Ante un fallo o una salida vacía, marca ok=False (desconocido) en vez de
presentar ceros como «no hay nada que limpiar».

NO toca el sistema: sustituye powershell_raw por un doble. No ejecuta ninguna limpieza.
"""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

tac = importlib.import_module("modulos._tacticas")


def _con_powershell(fake):
    """Ejecuta ghost_preview() con powershell_raw sustituido por `fake`. Restaura el original."""
    orig = tac.powershell_raw
    tac.powershell_raw = fake
    try:
        return tac.ghost_preview()
    finally:
        tac.powershell_raw = orig


def test_recuento_real_marca_ok_true():
    counts = _con_powershell(lambda script, timeout=30: (0, "5;3;12\n", ""))
    assert counts["ok"] is True
    assert counts["recientes"] == 5 and counts["papelera"] == 3 and counts["temporales"] == 12


def test_fallo_de_powershell_marca_ok_false():
    def boom(script, timeout=30):
        raise RuntimeError("PowerShell no disponible")
    counts = _con_powershell(boom)
    assert counts["ok"] is False
    # los valores quedan en 0, pero 'ok' permite al GUI mostrarlos como desconocidos, no como ceros
    assert counts["recientes"] == 0 and counts["papelera"] == 0 and counts["temporales"] == 0


def test_salida_vacia_marca_ok_false():
    counts = _con_powershell(lambda script, timeout=30: (0, "", ""))
    assert counts["ok"] is False


def test_salida_sin_separador_marca_ok_false():
    # Sin ';' no hay línea parseable: desconocido, no cero confirmado.
    counts = _con_powershell(lambda script, timeout=30: (0, "error inesperado\n", ""))
    assert counts["ok"] is False


def test_valores_parciales_se_completan_a_cero():
    # "7;" -> recientes 7, resto 0, pero el recuento SÍ se obtuvo (ok=True).
    counts = _con_powershell(lambda script, timeout=30: (0, "7;;\n", ""))
    assert counts["ok"] is True
    assert counts["recientes"] == 7 and counts["papelera"] == 0 and counts["temporales"] == 0


def test_retrocompatible_mantiene_las_tres_claves():
    # Un consumidor que solo lee recientes/papelera/temporales sigue funcionando igual.
    counts = _con_powershell(lambda script, timeout=30: (0, "1;2;3\n", ""))
    for clave in ("recientes", "papelera", "temporales"):
        assert clave in counts


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
