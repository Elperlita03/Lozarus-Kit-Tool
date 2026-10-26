# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_listablanca.py (lista blanca de procesos de confianza). Lógica PURA: no toca
disco ni procesos. La persistencia en tactical_config.json la hace la GUI.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._listablanca import add_trusted, is_trusted, normalize, remove_trusted  # noqa: E402


def test_normalize():
    assert normalize("C:\\Users\\x\\uv.exe") == "uv.exe"
    assert normalize("  Chroma-MCP.EXE  ") == "chroma-mcp.exe"
    assert normalize("") == ""
    assert normalize(None) == ""


def test_is_trusted_por_nombre_sin_ruta_ni_mayusculas():
    trusted = ["uv.exe", "chroma-mcp.exe"]
    assert is_trusted("C:\\dev\\UV.EXE", trusted) is True   # ruta + mayúsculas: igualmente confiable
    assert is_trusted("notepad.exe", trusted) is False
    assert is_trusted("", trusted) is False


def test_add_trusted_sin_duplicados():
    lista, cambio = add_trusted("uv.exe", [])
    assert lista == ["uv.exe"] and cambio is True
    lista2, cambio2 = add_trusted("C:\\x\\UV.EXE", lista)      # misma, otra caja/ruta
    assert lista2 == ["uv.exe"] and cambio2 is False
    lista3, cambio3 = add_trusted("chroma-mcp.exe", lista2)
    assert lista3 == ["chroma-mcp.exe", "uv.exe"] and cambio3 is True   # ordenada
    assert add_trusted("", lista3)[1] is False


def test_remove_trusted():
    lista, cambio = remove_trusted("uv.exe", ["uv.exe", "chroma-mcp.exe"])
    assert lista == ["chroma-mcp.exe"] and cambio is True
    assert remove_trusted("no_esta.exe", lista)[1] is False


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
