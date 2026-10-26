# -*- coding: utf-8 -*-
"""
Prueba de la lógica de la comprobación «Integridad de memoria (HVCI)» (modulos/05_hardening.py).

Prueba la función pura `_hvci_verdict`, que interpreta los datos de Win32_DeviceGuard sin consultar
el sistema: no necesita Windows, ni PowerShell, ni privilegios. Verifica las distinciones
correcto / advertencia y que un error de consulta NO se confunde con una configuración insegura (ese
caso lo maneja el método con CheckSkipped, aquí se comprueba que el veredicto solo juzga datos reales).
"""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_hard = importlib.import_module("modulos.05_hardening")
from modulos._base import PASS, WARNING  # noqa: E402

_verdict = _hard._hvci_verdict


def test_hvci_en_ejecucion_es_pass():
    sev, title, detail, rec = _verdict(2, [2])      # HVCI en SecurityServicesRunning
    assert sev is PASS
    assert "activa" in title.lower() and rec == ""


def test_hvci_con_credential_guard_menciona_ambos():
    sev, title, detail, rec = _verdict(2, [1, 2])   # Credential Guard + HVCI
    assert sev is PASS
    assert "Credential Guard" in detail


def test_vbs_corre_pero_sin_hvci_es_warning():
    sev, title, detail, rec = _verdict(2, [1])      # VBS en ejecución, HVCI no
    assert sev is WARNING
    assert "VBS" in title or "virtualización" in detail.lower()
    assert rec  # hay recomendación de activar


def test_vbs_inactiva_es_warning():
    sev, title, detail, rec = _verdict(0, [])
    assert sev is WARNING
    assert "inactiva" in detail.lower()
    assert rec


def test_vbs_habilitada_sin_ejecutar_es_warning():
    sev, title, detail, rec = _verdict(1, [])
    assert sev is WARNING
    assert "no en ejecución" in detail.lower()


def test_status_desconocido_no_revienta():
    sev, title, detail, rec = _verdict(None, [])
    assert sev is WARNING  # desconocido → advertencia prudente, nunca PASS silencioso


def test_running_vacio_o_none_es_seguro():
    assert _verdict(0, None)[0] is WARNING          # None no debe lanzar
    assert _verdict(2, [])[0] is WARNING


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
