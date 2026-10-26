# -*- coding: utf-8 -*-
"""
Pruebas de regresión de la Fase 2 — fiabilidad de la cuarentena (modulos/_contencion.py).

NO tocan el sistema real: redirigen STATE_FILE/FORENSICS_DIR a un directorio temporal y SUSTITUYEN
por dobles las funciones que modificarían el equipo (isolate_network, restore_network,
set_usb_storage, usb_storage_state, _nt, _create_time). Así se ejercita SOLO la lógica de estado.

Cubren:
  · C3 — el estado se persiste ANTES del primer paso irreversible, de modo que un fallo a mitad
    deja un estado recuperable y «Levantar Cuarentena» siempre puede revertir.
  · S2 — al levantar la cuarentena, un create_time ilegible (0.0) NO impide reanudar un proceso
    congelado; un create_time distinto SÍ evita tocar un PID reutilizado.
"""

import contextlib
import importlib
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

cont = importlib.import_module("modulos._contencion")

# Funciones del módulo que tocarían el sistema real; en las pruebas se sustituyen por dobles.
_SISTEMA = ("isolate_network", "restore_network", "set_usb_storage", "usb_storage_state",
            "_nt", "_create_time")


@contextlib.contextmanager
def sandbox(**fakes):
    """Redirige el estado a un temp y sustituye las funciones del sistema por `fakes`. Restaura todo."""
    tmp = tempfile.mkdtemp(prefix="lozarus_test_")
    originales = {"STATE_FILE": cont.STATE_FILE, "FORENSICS_DIR": cont.FORENSICS_DIR}
    cont.FORENSICS_DIR = tmp
    cont.STATE_FILE = os.path.join(tmp, "estado.json")
    # Por seguridad, cualquier función del sistema no simulada explícitamente queda neutralizada.
    for name in _SISTEMA:
        originales[name] = getattr(cont, name)
        setattr(cont, name, fakes.get(name, _neutro(name)))
    try:
        yield cont.STATE_FILE
    finally:
        for name, val in originales.items():
            setattr(cont, name, val)
        shutil.rmtree(tmp, ignore_errors=True)


def _neutro(name):
    if name == "usb_storage_state":
        return lambda: cont.USB_ENABLED
    if name == "_create_time":
        return lambda pid: 0.0
    return lambda *a, **k: None


class _Alerta:
    def __init__(self, pid, name="x", created=0.0):
        self.pid = pid
        self.name = name
        self.created = created


# --- C3: persistencia antes del paso irreversible ----------------------------------------------
def test_estado_persiste_antes_de_tocar_el_firewall():
    """Cuando se llama a isolate_network, el marcador de estado ya debe existir en disco."""
    visto = {}

    def fake_isolate():
        visto["existe_al_aislar"] = os.path.exists(cont.STATE_FILE)
        return {"Public": "Allow"}

    with sandbox(isolate_network=fake_isolate):
        cont.apply_quarantine([])
    assert visto.get("existe_al_aislar") is True, "el estado NO se persistió antes de tocar el firewall"


def test_fallo_al_aislar_deja_estado_recuperable():
    """Si isolate_network falla, debe quedar un estado activo en disco para poder revertir."""
    def boom():
        raise PermissionError("sin privilegios de Administrador")

    with sandbox(isolate_network=boom):
        cont.apply_quarantine([])
        assert os.path.exists(cont.STATE_FILE), "no quedó estado tras el fallo"
        st = json.load(open(cont.STATE_FILE, encoding="utf-8"))
    assert st["active"] is True
    assert st["firewall_original"] is None  # no se pudo capturar, pero el marcador existe


def test_lift_sin_original_restaura_con_seguridad():
    """Levantar la cuarentena sin estado de firewall previo invoca restore_network(None)
    (que aplica el valor seguro: permitir salida)."""
    restaurado = []

    with sandbox(restore_network=lambda original: restaurado.append(original)):
        cont._save_state({"active": True, "firewall_original": None,
                          "usb_previo": None, "suspendidos": []})
        cont.lift_quarantine()
    assert restaurado == [None], "restore_network no se llamó con el valor seguro por defecto"


def test_lift_limpia_el_estado():
    """Tras levantar la cuarentena, el fichero de estado debe desaparecer."""
    with sandbox():
        cont._save_state({"active": True, "firewall_original": {"Public": "Allow"},
                          "usb_previo": cont.USB_ENABLED, "suspendidos": []})
        cont.lift_quarantine()
        assert not os.path.exists(cont.STATE_FILE), "el estado no se limpió al levantar la cuarentena"


# --- S2: reanudación segura cuando no se puede verificar el create_time -------------------------
def test_create_time_ilegible_reanuda_igualmente():
    """ct == 0.0 (no se pudo leer) NO debe impedir reanudar un proceso congelado."""
    reanudados = []

    with sandbox(_nt=lambda pid, resume: reanudados.append((pid, resume)),
                 _create_time=lambda pid: 0.0):
        cont._save_state({"active": True, "firewall_original": None, "usb_previo": None,
                          "suspendidos": [{"pid": 4242, "name": "x", "created": 111111.0}]})
        cont.lift_quarantine()
    assert (4242, True) in reanudados, "no se reanudó un proceso cuyo create_time no se pudo leer"


def test_create_time_distinto_no_reanuda_pid_reutilizado():
    """Si el create_time se leyó y DIFIERE, el PID lo ocupa otro proceso: no se debe tocar."""
    reanudados = []

    with sandbox(_nt=lambda pid, resume: reanudados.append((pid, resume)),
                 _create_time=lambda pid: 999999.0):   # distinto del guardado (111111.0)
        cont._save_state({"active": True, "firewall_original": None, "usb_previo": None,
                          "suspendidos": [{"pid": 4242, "name": "x", "created": 111111.0}]})
        cont.lift_quarantine()
    assert (4242, True) not in reanudados, "se reanudó un PID que ahora ocupa otro proceso distinto"


def test_create_time_coincide_reanuda():
    """Si el create_time coincide (mismo proceso), se reanuda."""
    reanudados = []

    with sandbox(_nt=lambda pid, resume: reanudados.append((pid, resume)),
                 _create_time=lambda pid: 111111.0):   # igual al guardado
        cont._save_state({"active": True, "firewall_original": None, "usb_previo": None,
                          "suspendidos": [{"pid": 4242, "name": "x", "created": 111111.0}]})
        cont.lift_quarantine()
    assert (4242, True) in reanudados


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
