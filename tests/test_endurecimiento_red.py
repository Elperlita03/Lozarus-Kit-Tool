# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_endurecimiento_red.py. Se centran en la lógica PURA y en la SEGURIDAD de las
acciones que tocan el sistema:

  · listening_keys / split_connections: puras, con una lista de Conn de pega.
  · flush_dns / firewall_status: se sustituye subprocess.run por un doble para probar el parseo
    SIN ejecutar nada en el equipo.
  · set_service_startup SIN privilegios: debe devolver (False, True, …) y NO intentar ningún `sc`
    (se comprueba sustituyendo is_admin por una función que devuelve False).
  · scan_connections / service_status: una comprobación de humo de solo lectura (no modifica nada).

Nunca se desactiva un servicio real ni se cambia la configuración del equipo.
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos import _endurecimiento_red as er  # noqa: E402
from modulos._endurecimiento_red import (Conn, firewall_status, flush_dns,  # noqa: E402
                                         listening_keys, scan_connections, service_status,
                                         set_service_startup, split_connections)


def _conn(proto, lip, lport, rip, rport, status, pid=1, proc="x"):
    return Conn(proto, lip, lport, rip, rport, status, pid, proc)


def test_listening_keys_y_split():
    conns = [
        _conn("TCP", "0.0.0.0", 445, "—", 0, "LISTEN"),
        _conn("TCP", "0.0.0.0", 139, "—", 0, "LISTEN"),
        _conn("TCP", "10.0.0.2", 51000, "1.1.1.1", 443, "ESTABLISHED"),
        _conn("UDP", "0.0.0.0", 5353, "—", 0, "—"),
    ]
    keys = listening_keys(conns)
    assert keys == {"TCP:0.0.0.0:445", "TCP:0.0.0.0:139"}
    escucha, activas = split_connections(conns)
    assert len(escucha) == 2 and len(activas) == 1


def test_flush_dns_parsea_exito_y_fallo():
    orig = er.subprocess.run
    try:
        er.subprocess.run = lambda *a, **k: types.SimpleNamespace(
            returncode=0, stdout="Se vació correctamente la caché de resolución de DNS.", stderr="")
        ok, msg = flush_dns()
        assert ok is True and "vaciada" in msg.lower()

        er.subprocess.run = lambda *a, **k: types.SimpleNamespace(
            returncode=1, stdout="", stderr="algo falló")
        ok, msg = flush_dns()
        assert ok is False and msg
    finally:
        er.subprocess.run = orig


def test_firewall_status_parsea_json():
    orig = er.subprocess.run
    try:
        payload = '[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":true},' \
                  '{"Name":"Public","Enabled":false}]'
        er.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=payload, stderr="")
        ok, estado, msg = firewall_status()
        assert ok is True
        assert estado == {"Domain": True, "Private": True, "Public": False}

        er.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="no-json", stderr="")
        ok, estado, msg = firewall_status()
        assert ok is False and estado == {} and msg
    finally:
        er.subprocess.run = orig


def test_set_service_sin_admin_no_actua():
    orig_admin = er.is_admin
    orig_sc = er._run_sc
    llamado = {"sc": False}
    try:
        er.is_admin = lambda: False
        er._run_sc = lambda args: llamado.__setitem__("sc", True) or (0, "")  # no debería invocarse
        ok, requiere_admin, msg = set_service_startup("DiagTrack", "disabled")
        assert ok is False and requiere_admin is True and "Administrador" in msg
        assert llamado["sc"] is False  # NO se tocó el sistema
    finally:
        er.is_admin = orig_admin
        er._run_sc = orig_sc


def test_modo_de_arranque_invalido():
    ok, requiere_admin, msg = set_service_startup("DiagTrack", "turbo")
    assert ok is False and requiere_admin is False and "no válido" in msg


def test_scan_connections_smoke_solo_lectura():
    # Lectura inocua del propio equipo (como el Monitor). Solo comprobamos forma y tipos.
    conns = scan_connections()
    assert isinstance(conns, list)
    for c in conns[:20]:
        assert isinstance(c, Conn)
        assert isinstance(c.proto, str) and isinstance(c.status, str)
    assert isinstance(listening_keys(conns), set)


def test_service_status_forma():
    info = service_status("DiagTrack")
    assert isinstance(info, dict)
    assert set(info) >= {"name", "exists", "status", "start_type"}
    assert info["name"] == "DiagTrack"


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
