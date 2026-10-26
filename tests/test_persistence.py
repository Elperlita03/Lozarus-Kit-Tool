# -*- coding: utf-8 -*-
"""
Pruebas del motor de persistencia táctica (storage/persistence.py). E/S real en directorio temporal;
sin privilegios, sin GUI.
"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.persistence import TacticalConfig  # noqa: E402


def test_guarda_y_restaura_estado():
    tmp = tempfile.mkdtemp(prefix="cfg_")
    try:
        path = os.path.join(tmp, "sub", "tactical_config.json")
        cfg = TacticalConfig(path)
        cfg.set("honeypot_active", True)
        cfg.set("auto_rebuild", False)
        # una instancia nueva (como reabrir el programa) debe leer lo guardado
        cfg2 = TacticalConfig(path)
        assert cfg2.get("honeypot_active") is True
        assert cfg2.get("auto_rebuild") is False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_fichero_ausente_es_config_vacia():
    cfg = TacticalConfig(os.path.join(tempfile.gettempdir(), "no_existe_lozarus_xyz.json"))
    assert cfg.as_dict() == {}
    assert cfg.get("lo_que_sea", "defecto") == "defecto"


def test_json_corrupto_no_lanza():
    tmp = tempfile.mkdtemp(prefix="cfg_")
    try:
        path = os.path.join(tmp, "c.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{ esto no es json")
        cfg = TacticalConfig(path)   # no debe lanzar
        assert cfg.as_dict() == {}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_escritura_atomica_deja_json_valido():
    tmp = tempfile.mkdtemp(prefix="cfg_")
    try:
        path = os.path.join(tmp, "c.json")
        cfg = TacticalConfig(path)
        cfg.update({"a": 1, "b": [1, 2, 3], "c": "texto con acentos: ñ"})
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["a"] == 1 and data["b"] == [1, 2, 3] and "ñ" in data["c"]
        assert not os.path.exists(path + ".tmp")  # el temporal se renombró, no queda basura
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
