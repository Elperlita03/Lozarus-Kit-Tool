# -*- coding: utf-8 -*-
"""
Pruebas de regresión de la Fase 1 de seguridad:

  · C1 — ps_string_array() pasa cada ruta a PowerShell como DATO base64, nunca como código, de modo
    que una ruta maliciosa no puede inyectar comandos. Antes, el escape de comillas solo neutralizaba
    la comilla simple ASCII; una comilla tipográfica (U+2019) rompía la cadena y ejecutaba lo que
    viniera detrás.
  · C2 — _dll_classification() trata el estado 'Error' (la verificación de la firma falló) como
    DESCONOCIDO, no como 'sin firma válida', para no acusar a una DLL legítima.

Las pruebas unitarias corren SIN Administrador, SIN psutil y SIN PowerShell. La prueba de integración
que ejecuta PowerShell de verdad se SALTA si no está disponible.
"""

import base64
import importlib
import os
import platform
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._utilidades import ps_string_array  # noqa: E402

# 13_inyecciones empieza por dígito: no es un identificador válido, hay que importarlo por nombre.
_iny = importlib.import_module("modulos.13_inyecciones")

try:
    import pytest  # noqa: E402
    _HAS_PYTEST = True
except ImportError:
    _HAS_PYTEST = False

# Cargas de prueba con los metacaracteres de PowerShell que rompían el escape antiguo,
# más rutas con espacios, Unicode, CJK y emoji (regresión permanente de la Fase 2).
_PAYLOADS = [
    "C:\\x'; Write-Output 'INJECTED-ascii",             # comilla simple ASCII
    "C:\\x\u2019; Write-Output \u2019INJECTED-typo",     # comilla tipográfica (el fallo real)
    "C:\\x`n Write-Output INJECTED-backtick",            # acento grave + salto
    "C:\\x$(Write-Output INJECTED-subexpr)",             # subexpresión $( )
    "C:\\x\"; Write-Output \"INJECTED-double",           # comilla doble
    "C:\\Program Files\\App\\normal.dll",                # ruta normal con espacios
    "C:\\ruta\\\u65e5\u672c\u8a9e\\\u6d4b\u8bd5.dll",    # CJK (japonés + chino)
    "C:\\ruta\\\U0001F512_secreto.dll",                  # emoji (par subrogado UTF-16)
    "C:\\Usuarios\\Jos\u00e9\\A\u00f1o Nuevo\\caf\u00e9.exe",  # acentos latinos
]


# --- C1: construcción del array (puro, sin PowerShell) ------------------------------------------
def test_ps_array_no_filtra_contenido_peligroso_literal():
    """Ningún metacarácter del valor aparece literalmente en la expresión: todo va en base64."""
    expr = ps_string_array(_PAYLOADS)
    for marca in ("INJECTED", "Write-Output", "$(", "`n"):
        assert marca not in expr, f"fuga literal de «{marca}» en la expresión generada"
    # Entre las comillas solo debe haber base64 (alfanumérico, +, /, =); nada de comillas internas.
    for token in re.findall(r"FromBase64String\('([^']*)'\)", expr):
        assert re.fullmatch(r"[A-Za-z0-9+/=]+", token), f"token no base64: {token!r}"


def test_ps_array_roundtrip_conserva_el_valor():
    """Decodificar el base64 recupera exactamente la ruta original (los datos no se corrompen)."""
    expr = ps_string_array(_PAYLOADS)
    tokens = re.findall(r"FromBase64String\('([^']*)'\)", expr)
    decoded = [base64.b64decode(t).decode("utf-16-le") for t in tokens]
    assert decoded == _PAYLOADS


def test_ps_array_vacio():
    assert ps_string_array([]) == "@()"


# --- C2: clasificación de DLL (puro) -----------------------------------------------------------
def test_error_es_no_verificable_no_sin_firma():
    """El fallo de verificación ('Error') NO debe convertirse en alerta crítica de 'sin firma'."""
    assert _iny._dll_classification("Error", None) == "unverifiable"


def test_sin_firma_confirmada_sigue_siendo_critica():
    assert _iny._dll_classification("NotSigned", None) == "critical_unsigned"
    assert _iny._dll_classification("HashMismatch", None) == "critical_unsigned"


def test_firma_valida_es_benigna():
    assert _iny._dll_classification("Valid", None) == "benign"


def test_ubicacion_grabable_manda_sobre_la_firma():
    assert _iny._dll_classification("Valid", "AppData del usuario") == "critical_loc"
    assert _iny._dll_classification("Error", "carpeta temporal") == "critical_loc"


# --- C1: integración real con PowerShell (saltable) --------------------------------------------
def _powershell_disponible():
    if platform.system() != "Windows":
        return False, "no es Windows"
    try:
        from modulos._utilidades import _powershell_exe
        return (True, "") if _powershell_exe() else (False, "PowerShell no encontrado")
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def test_no_hay_inyeccion_ejecutando_powershell():
    """
    Prueba inocua (solo Write-Output): ningún payload se EJECUTA. Si se inyectara, su
    'Write-Output <MARCA>' aparecería como una LÍNEA propia con esa marca. Comprobamos que nunca
    ocurre. (La integridad del dato con caracteres no ASCII la cubre el round-trip puro de arriba;
    aquí la salida pasa por la página OEM de la consola y mangle los no-ASCII, así que no se
    compara el eco carácter a carácter.)
    """
    ok, motivo = _powershell_disponible()
    if not ok:
        msg = f"PowerShell no disponible: {motivo}"
        if _HAS_PYTEST:
            pytest.skip(msg)
        print("SALTADA —", msg)
        return
    from modulos._utilidades import powershell_raw
    payloads = {
        "MARCA-comilla": "Z:/x'; Write-Output 'MARCA-comilla",        # comilla simple ASCII
        "MARCA-puntoycoma": "Z:/x; Write-Output MARCA-puntoycoma",    # separador de sentencias
        "MARCA-subexpr": "Z:/x$(Write-Output MARCA-subexpr)",         # subexpresión $( )
    }
    for marca, payload in payloads.items():
        script = ("foreach ($p in " + ps_string_array([payload]) +
                  ") { Write-Output 'FIN-DE-ITERACION' }\n")
        rc, out, err = powershell_raw(script, timeout=30)
        lineas = [ln.strip() for ln in out.splitlines()]
        assert marca not in lineas, f"¡inyección! «{marca}» se ejecutó como línea propia: {out!r}"
        assert "FIN-DE-ITERACION" in lineas, f"el bucle no se ejecutó con normalidad: {out!r}"


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
