# -*- coding: utf-8 -*-
"""
Pruebas del motor de Honeypot (deception/honeypot_engine.py). E/S real en directorio temporal, sin
privilegios, sin hilos de fondo (se llama a `scan_once()` directamente para que sea determinista).
El bus se sustituye por un doble que registra los Events. No se terminan procesos ni se toca nada
del sistema del usuario.
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deception.honeypot_engine import (CREDENCIAL, ELIMINADO, INTACTO, MODIFICADO,  # noqa: E402
                                       TRAP_SPECS, HoneypotEngine)


class FakeBus:
    def __init__(self):
        self.events = []

    def publish(self, event):
        self.events.append(event)
        return True


def _engine(tmp, **kw):
    # event_factory sencillo: construye un objeto-evento mínimo con to_json (no depende de core).
    def factory(**fields):
        class _E:
            def __init__(self, f):
                self.f = f

            def to_json(self):
                import json
                return json.dumps(self.f, ensure_ascii=False, default=str)
        return _E(fields)
    return HoneypotEngine(os.path.join(tmp, "Vault_Decoy"), event_factory=factory, **kw)


def test_deploy_crea_las_trampas_con_linea_base():
    tmp = tempfile.mkdtemp(prefix="hp_")
    try:
        eng = _engine(tmp)
        res = eng.deploy()
        assert res["desplegadas"] == len(TRAP_SPECS)
        traps = eng.trap_list()
        assert len(traps) == len(TRAP_SPECS)
        for t in traps:
            assert t["state"] == INTACTO and t["hash"] and os.path.exists(t["path"])
        # las credenciales existen y llevan tokens (contenido no vacío)
        cred = [t for t in traps if t["tipo"] == CREDENCIAL]
        assert cred and all(os.path.getsize(t["path"]) > 0 for t in cred)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_modificacion_se_detecta_y_emite_event():
    tmp = tempfile.mkdtemp(prefix="hp_")
    try:
        bus = FakeBus()
        eng = _engine(tmp, bus=bus)
        eng.deploy()
        victima = eng.trap_list()[0]["path"]
        with open(victima, "ab") as fh:        # alterar el cebo
            fh.write(b"intruso")
        eng.scan_once()
        estado = next(t for t in eng.trap_list() if t["path"] == victima)
        assert estado["state"] == MODIFICADO
        assert len(bus.events) == 1            # se emitió un Event al bus (→ Caja Negra)
        assert eng.incident_count() == 1
        assert eng.status()["integridad"] is False and eng.status()["comprometidos"] == 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_borrado_se_detecta():
    tmp = tempfile.mkdtemp(prefix="hp_")
    try:
        bus = FakeBus()
        eng = _engine(tmp, bus=bus)
        eng.deploy()
        victima = eng.trap_list()[0]["path"]
        os.remove(victima)
        eng.scan_once()
        estado = next(t for t in eng.trap_list() if t["path"] == victima)
        assert estado["state"] == ELIMINADO
        assert len(bus.events) == 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_auto_reconstruccion_regenera_el_cebo():
    tmp = tempfile.mkdtemp(prefix="hp_")
    try:
        bus = FakeBus()
        eng = _engine(tmp, bus=bus, auto_rebuild=True)
        eng.deploy()
        victima = eng.trap_list()[0]["path"]
        os.remove(victima)
        assert not os.path.exists(victima)
        eng.scan_once()                        # detecta el borrado y reconstruye
        assert os.path.exists(victima)         # el cebo volvió
        estado = next(t for t in eng.trap_list() if t["path"] == victima)
        assert estado["state"] == INTACTO      # línea base restablecida
        assert eng.incident_count() == 1       # el ataque quedó registrado igualmente
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_no_duplica_incidente_mientras_siga_comprometido():
    tmp = tempfile.mkdtemp(prefix="hp_")
    try:
        bus = FakeBus()
        eng = _engine(tmp, bus=bus)            # sin auto_rebuild
        eng.deploy()
        victima = eng.trap_list()[0]["path"]
        os.remove(victima)
        eng.scan_once()
        eng.scan_once()                        # segundo escaneo: ya está ELIMINADO, no re-incidenta
        assert eng.incident_count() == 1 and len(bus.events) == 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_new_incidents_para_la_consola():
    tmp = tempfile.mkdtemp(prefix="hp_")
    try:
        eng = _engine(tmp, bus=FakeBus())
        eng.deploy()
        assert eng.new_incidents(0) == []
        os.remove(eng.trap_list()[0]["path"])
        eng.scan_once()
        incs = eng.new_incidents(0)
        assert len(incs) == 1 and incs[0]["change"] == ELIMINADO
        assert eng.new_incidents(1) == []      # ya consumidos
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_retract_borra_todo():
    tmp = tempfile.mkdtemp(prefix="hp_")
    try:
        eng = _engine(tmp)
        eng.deploy()
        eng.retract()
        assert eng.trap_list() == [] and eng.active is False
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
