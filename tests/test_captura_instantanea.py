# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_forense.instant_capture («Protocolo de Captura Instantánea»). Escribe SOLO en
un directorio temporal de la prueba (nunca en Lozarus_Forensics). Lee el estado real del equipo
(procesos/conexiones/memoria), que es inocuo.
"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._forense import instant_capture  # noqa: E402


def test_captura_escribe_expediente_completo():
    tmp = tempfile.mkdtemp(prefix="cap_")
    try:
        comps = [("Caja Negra", "operativo", "3 eventos"), ("Honeypot", "detenido", "retirado")]
        path, resumen = instant_capture(comps, directory=tmp)
        assert os.path.isfile(path) and os.path.basename(path).startswith("Captura_")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["tipo"] == "captura_instantanea" and data["esquema"] == "lozarus.capture.v1"
        for key in ("procesos", "conexiones_establecidas", "puertos_escucha", "memoria", "componentes"):
            assert key in data, key
        assert resumen["procesos"] == len(data["procesos"]) > 0
        assert resumen["componentes"] == 2 and data["componentes"][0]["componente"] == "Caja Negra"
        assert all(c["estado"] == "ESTABLISHED" for c in data["conexiones_establecidas"])
        assert all(c["estado"] == "LISTEN" for c in data["puertos_escucha"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_dos_capturas_seguidas_no_se_sobrescriben():
    tmp = tempfile.mkdtemp(prefix="cap_")
    try:
        p1, _ = instant_capture([], directory=tmp)
        p2, _ = instant_capture([], directory=tmp)
        assert p1 != p2 and os.path.isfile(p1) and os.path.isfile(p2)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
