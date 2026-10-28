# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_perimetro.py y de las operaciones de rescate de _optimizacion_red. Lógica PURA
(veredicto del perímetro, comandos netsh, clasificación de reglas, exposición) y seguridad de las
acciones: solo se retiran reglas «Lozarus…», el nombre viaja como DATO (base64) y fuera de Windows no
se ejecuta nada. PowerShell y subprocess se sustituyen por dobles.
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos import _optimizacion_red as opt  # noqa: E402
from modulos import _perimetro as per  # noqa: E402


def _p(name, enabled=True, inbound="Block", outbound="Allow"):
    return per._normalize(name, enabled, inbound, outbound)


def test_veredicto_y_comandos_de_perfil():
    ok = [_p("Domain"), _p("Private"), _p("Public")]
    assert per.perimeter_verdict(ok)["protected"] and per.profile_fix_commands(ok) == []
    mixed = [_p("Domain"), _p("Private", enabled=False), _p("Public", inbound="Allow", outbound="Block")]
    verdict = per.perimeter_verdict(mixed)
    assert verdict["active"] == 2 and verdict["off"] == ["Privado"] and verdict["open_inbound"] == ["Público"]
    assert not verdict["protected"]
    assert per.profile_fix_commands(mixed) == [
        ("netsh", "advfirewall", "set", "privateprofile", "state", "on"),
        ("netsh", "advfirewall", "set", "publicprofile", "firewallpolicy", "blockinbound,blockoutbound")]
    assert _p("Public", inbound="NotConfigured")["inbound_block"]  # NotConfigured = bloquear


def test_clasificacion_de_reglas():
    assert per.rule_kind({"name": "Lozarus - Ocultar en red", "group": per.ICMP_GROUP}) == "Ocultamiento ICMP"
    quarantine = {"name": "Lozarus Quarantine - Permitir LAN (salida)", "group": per.QUARANTINE_GROUP}
    assert per.rule_kind(quarantine) == "Cuarentena" and not per.removable(quarantine)
    port = {"name": "Lozarus - Bloqueo TCP 445", "group": ""}
    assert per.rule_kind(port) == "Bloqueo de puerto" and per.removable(port)
    assert per.rule_kind({"name": "Lozarus Guardia - Bloqueo TCP 4444", "group": ""}) == "Guardia en Vivo"
    assert not per.removable({"name": "Regla ajena", "group": ""})


def test_reglas_y_retirada_con_powershell_simulado():
    calls = []
    orig_ps, orig_win = per.powershell, per.IS_WINDOWS
    try:
        per.IS_WINDOWS = True
        per.powershell = lambda script, timeout=60: calls.append(script) or [
            {"name": "Lozarus - Bloqueo TCP 445", "group": "", "dir": "Inbound", "action": "Block",
             "enabled": "True", "proto": "TCP", "port": "445"},
            {"name": "Otra regla", "group": "", "dir": "Inbound"}]
        rules = per.containment_rules()
        assert [r["name"] for r in rules] == ["Lozarus - Bloqueo TCP 445"] and rules[0]["kind"] == "Bloqueo de puerto"
        per.powershell = lambda script, timeout=60: calls.append(script) or {"ok": True}
        assert per.remove_rule("Lozarus - Bloqueo TCP 445") == {"removed": "Lozarus - Bloqueo TCP 445"}
        assert "Lozarus - Bloqueo" not in calls[-1] and "FromBase64String" in calls[-1]  # el nombre va como dato
        per.powershell = lambda script, timeout=60: {"ok": False, "error": "Acceso denegado"}
        try:
            per.remove_rule("Lozarus - Bloqueo TCP 445")
            raise AssertionError("debía fallar sin privilegios")
        except PermissionError as exc:
            assert "Acceso denegado" in str(exc)
        try:
            per.remove_rule("Regla de otra aplicación")
            raise AssertionError("no debe tocar reglas ajenas")
        except ValueError:
            pass
    finally:
        per.powershell, per.IS_WINDOWS = orig_ps, orig_win


def test_fuera_de_windows_no_hace_nada():
    if per.IS_WINDOWS:
        return
    for fn in (per.firewall_profiles, per.containment_rules):
        try:
            fn()
            raise AssertionError(f"{fn.__name__} debía lanzar OSError fuera de Windows")
        except OSError:
            pass


def test_exposicion():
    assert per.exposed("0.0.0.0") and per.exposed("::") and per.exposed("192.168.1.20")
    assert not per.exposed("127.0.0.1") and not per.exposed("::1") and not per.exposed("—")


def test_rescate_dns_arp_winsock():
    assert opt.RESCUE_OPS == ("flushdns", "arp", "winsock")
    assert opt.MAINTENANCE_OPS["arp"][1] == [["netsh", "interface", "ip", "delete", "arpcache"]]
    calls = []
    orig_run, orig_win = opt.subprocess.run, opt.IS_WINDOWS
    try:
        opt.IS_WINDOWS = True
        opt.subprocess.run = lambda argv, **k: calls.append(argv) or types.SimpleNamespace(
            returncode=0, stdout=b"Aceptar.", stderr=b"")
        for op in opt.RESCUE_OPS:
            res = opt.run_maintenance(op, admin=True)
            assert res["ok"], res
        assert [os.path.basename(c[0]).lower().replace(".exe", "") for c in calls] == ["ipconfig", "netsh", "netsh"]
        assert opt.run_maintenance("arp", admin=False)["ok"] is False  # sin admin no se ejecuta
        assert len(calls) == 3
    finally:
        opt.subprocess.run, opt.IS_WINDOWS = orig_run, orig_win


def _run_all():
    ok = 0
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        try:
            fn()
            ok += 1
            print(f"OK  {name}")
        except Exception as exc:  # noqa: BLE001
            print(f"ERR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{ok}/{len(tests)} OK")
    return ok == len(tests)


if __name__ == "__main__":
    sys.exit(0 if _run_all() else 1)
