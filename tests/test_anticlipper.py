# -*- coding: utf-8 -*-
"""
Pruebas de la defensa anti-clipper (modulos/_privacidad.py: crypto_address, is_hijack_swap) y del
comando de relanzamiento UAC (modulos/_utilidades.build_relaunch_command). Todo es lógica PURA: NO se
toca el portapapeles ni se lanza ningún proceso elevado.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._privacidad import crypto_address, is_hijack_swap  # noqa: E402
from modulos._utilidades import build_relaunch_command  # noqa: E402

BTC1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC2 = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
ETH1 = "0x52908400098527886E0F7030069857D2E4169EE7"


def test_crypto_address():
    assert crypto_address(ETH1) == ("ETH", ETH1)
    assert crypto_address(BTC1)[0] == "BTC"
    assert crypto_address("  " + BTC1 + "  ")[0] == "BTC"   # se recorta
    assert crypto_address("hola mundo")[0] is None
    assert crypto_address("")[0] is None
    assert crypto_address(None)[0] is None


def test_is_hijack_swap():
    # dos direcciones cripto distintas en < 1,5 s → secuestro
    assert is_hijack_swap(BTC1, BTC2, 0.5) is True
    assert is_hijack_swap(BTC1, ETH1, 1.0) is True
    # misma dirección: no es swap
    assert is_hijack_swap(BTC1, BTC1, 0.5) is False
    # fuera de ventana temporal
    assert is_hijack_swap(BTC1, BTC2, 3.0) is False
    # alguno no es dirección cripto
    assert is_hijack_swap("texto normal", BTC2, 0.5) is False
    assert is_hijack_swap(BTC1, "texto normal", 0.5) is False
    # faltan datos
    assert is_hijack_swap(None, BTC2, 0.5) is False
    assert is_hijack_swap(BTC1, BTC2, None) is False


def test_build_relaunch_command_es_puro():
    exe, params = build_relaunch_command()
    assert isinstance(exe, str) and exe == sys.executable
    assert isinstance(params, str) and params
    # el primer argumento (el guion) aparece como ruta absoluta
    assert os.path.abspath(sys.argv[0]) in params


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
