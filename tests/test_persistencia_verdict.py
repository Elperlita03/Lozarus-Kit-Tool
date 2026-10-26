# -*- coding: utf-8 -*-
"""
Prueba de regresión de C-persist: _autorun_verdict (modulos/11_persistencia.py) debe tratar el
estado 'Error' (la verificación de la firma falló) como 'unverifiable' (DESCONOCIDO), nunca como
'warning' («sin firma válida»). Mismo criterio que C2 en el cazador de inyecciones.

Función pura: no necesita Administrador, ni PowerShell, ni psutil.
"""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 11_persistencia empieza por dígito: se importa por nombre.
_persist = importlib.import_module("modulos.11_persistencia")
_veredicto = _persist._autorun_verdict

_EXE = "C:\\Programas\\app\\programa.exe"          # ruta NO grabable (no AppData/Temp/...)
_LOADER = "C:\\Windows\\System32\\rundll32.exe"    # cargador conocido
_GRABABLE = "C:\\Users\\u\\AppData\\Local\\Temp\\carga.dll"   # comando en carpeta grabable


def _v(status, exe=_EXE, exists=True, signer="", command=_EXE):
    return _veredicto(exe, exists, status, signer, command)[0]


# --- El arreglo: Error = no verificable, nunca 'sin firma' --------------------------------------
def test_error_es_unverifiable_no_warning():
    assert _v("Error") == "unverifiable"


def test_timeout_no_se_marca_como_sin_firma():
    # 'Error' es justo lo que devuelve authenticode_signatures cuando la verificación no llega.
    assert _v("Error") != "warning"


# --- Lo que NO debe cambiar ---------------------------------------------------------------------
def test_sin_firma_confirmada_sigue_siendo_warning():
    assert _v("NotSigned") == "warning"
    assert _v("HashMismatch") == "warning"
    assert _v("NotTrusted") == "warning"


def test_firma_valida_es_benigna():
    assert _v("Valid", signer="Acme Corp") == "benign"


def test_microsoft_valido_es_benigno():
    assert _v("Valid", signer="Microsoft Windows") == "benign"


def test_ubicacion_grabable_manda_sobre_error():
    # Una ubicación grabable es crítica aunque la firma no se pudiera verificar: la 'loc' manda.
    assert _veredicto(_EXE, True, "Error", "", _GRABABLE)[0] == "critical"


def test_cargador_en_ubicacion_grabable_es_critico():
    # rundll32 (cargador) firmado por Microsoft pero tirando de algo en Temp: crítico.
    assert _veredicto(_LOADER, True, "Valid", "Microsoft", _GRABABLE)[0] == "critical"


def test_ejecutable_inexistente_no_es_warning():
    # Si el exe no existe, no hay firma que juzgar: no debe ser 'warning'.
    assert _v("", exists=False) == "benign"


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
