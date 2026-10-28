# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_mitigacion.py con un backend FALSO en memoria (registro, comandos, PowerShell,
secedit y Arsenal simulados): nunca se toca el sistema. Cubren el catálogo hallazgo -> remedio, la
transacción (si un paso falla se deshacen los anteriores), la verificación tras escribir, el deshacer
quirúrgico y que el resumen para la Caja Negra sea JSON-serializable.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos import _mitigacion as mit  # noqa: E402
from modulos._base import ADMIN_NAME, CRITICAL, INFO, PASS, SKIP, WARNING, Finding  # noqa: E402


class FakeBackend:
    def __init__(self, build=22631):
        self.reg = {}
        self.calls = []
        self.fail = set()          # argv (tupla) o script que deben fallar
        self.readonly = set()      # (hive, subkey, name) cuya escritura lanza PermissionError
        self.sticky = set()        # escrituras que «no se quedan» (para probar la verificación)
        self.policy = {"PasswordComplexity": "0", "ClearTextPassword": "1", "LSAAnonymousNameLookup": "1",
                       "MinimumPasswordLength": "0", "LockoutBadCount": "0"}
        self.secedit_ignores = False
        self.arsenal = set()
        self.build = build

    @staticmethod
    def _k(hive, subkey, name):
        return hive, subkey.lower(), name.lower()

    def reg_read(self, hive, subkey, name):
        value = self.reg.get(self._k(hive, subkey, name))
        return (True, value[0], value[1]) if value else (False, None, None)

    def reg_write(self, hive, subkey, name, data, kind):
        key = self._k(hive, subkey, name)
        if key in self.readonly:
            raise PermissionError("Acceso denegado")
        if key not in self.sticky:
            self.reg[key] = (data, kind)

    def reg_delete(self, hive, subkey, name):
        self.reg.pop(self._k(hive, subkey, name), None)

    def run(self, argv, timeout=120):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv in self.fail:
            return 1, "Error: acceso denegado"
        if argv[:2] == ("net", "accounts"):
            flag, _, value = argv[2].lstrip("/").partition(":")
            setting = {"minpwlen": "MinimumPasswordLength", "lockoutthreshold": "LockoutBadCount"}[flag]
            self.policy[setting] = value
        return 0, "Aceptar."

    def powershell(self, script, timeout=300):
        self.calls.append(script)
        return (1, "Set-MpPreference : Acceso denegado") if script in self.fail else (0, "")

    def secedit_read(self):
        return dict(self.policy)

    def secedit_write(self, settings):
        if not self.secedit_ignores:
            self.policy.update({k: str(v) for k, v in settings.items()})
        return 0, "La tarea se completó correctamente."

    def arsenal_apply(self, key):
        self.arsenal.add(key)
        return {"tweak": key, "backup": {"values": [{"data": b"\x01\x02"}]}}

    def arsenal_revert(self, key):
        self.arsenal.discard(key)
        return {"tweak": key}

    def arsenal_is_applied(self, key):
        return key in self.arsenal

    def windows_build(self):
        return self.build


def finding(severity, title, check="", key="", detail="", module="hardening"):
    return Finding(module, severity, title, detail, "", check=check, key=key)


def test_uac_aplica_verifica_y_deshace():
    be = FakeBackend()
    remedy = mit.remedy_for(finding(CRITICAL, "UAC (Control de cuentas de usuario) DESACTIVADO", "check_uac"), be)
    assert remedy.key == "uac:lua" and remedy.reboot and remedy.admin and remedy.undoable
    assert remedy.targets() == [rf"HKLM\{mit.UAC_KEY}\EnableLUA = 1 (DWORD)"]
    result = mit.apply_remedy(remedy, be)
    assert result["ok"] and be.reg_read("HKLM", mit.UAC_KEY, "EnableLUA")[1] == 1
    json.dumps(mit.event_payload(remedy, result))  # Caja Negra: serializable
    assert mit.undo_preview(remedy, result["records"]) == [rf"HKLM\{mit.UAC_KEY}\EnableLUA → se elimina (no existía)"]
    assert mit.undo_remedy(remedy, result["records"], be)["ok"]
    assert be.reg_read("HKLM", mit.UAC_KEY, "EnableLUA")[0] is False  # no existía: se borra


def test_transaccion_revierte_pasos_previos():
    be = FakeBackend()
    be.reg_write("HKLM", mit.RDP_TCP_KEY, "UserAuthentication", 0, mit.REG_DWORD)
    be.reg_write("HKLM", mit.TS_POLICY_KEY, "UserAuthentication", 0, mit.REG_DWORD)
    be.readonly.add(be._k("HKLM", mit.TS_POLICY_KEY, "UserAuthentication"))
    remedy = mit.remedy_for(finding(CRITICAL, "RDP habilitado SIN autenticación a nivel de red (NLA), puerto 3389",
                                    "check_rdp"), be)
    assert len(remedy.steps) == 2  # la directiva existe: también se corrige
    result = mit.apply_remedy(remedy, be)
    assert not result["ok"] and result["rolled_back"] and "PermissionError" in result["error"]
    assert be.reg_read("HKLM", mit.RDP_TCP_KEY, "UserAuthentication")[1] == 0  # primer paso deshecho


def test_verificacion_detecta_escritura_que_no_queda():
    be = FakeBackend()
    be.sticky.add(be._k("HKLM", mit.WDIGEST_KEY, "UseLogonCredential"))
    remedy = mit.remedy_for(finding(CRITICAL, "WDigest almacena contraseñas EN CLARO en memoria",
                                    "check_wdigest"), be)
    result = mit.apply_remedy(remedy, be)
    assert not result["ok"] and "no quedó escrito" in result["error"]


def test_entrada_de_arranque_con_copia_y_restauracion():
    be = FakeBackend()
    label, hive, subkey = next(r for r in mit.RUN_KEYS if r[1] == "HKCU")
    be.reg_write(hive, subkey, "Updater", r"C:\Users\x\AppData\evil.exe", mit.REG_SZ)
    remedy = mit.remedy_for(finding(CRITICAL, "Arranque automático sospechoso: Updater", key=f"persist:run:{label}:Updater",
                                    module="persistencia"), be)
    assert remedy.admin is False and remedy.undoable
    result = mit.apply_remedy(remedy, be)
    assert result["ok"] and not be.reg_read(hive, subkey, "Updater")[0]
    assert result["records"][0]["before"]["data"].endswith("evil.exe")
    assert mit.undo_remedy(remedy, result["records"], be)["ok"]
    assert be.reg_read(hive, subkey, "Updater") == (True, r"C:\Users\x\AppData\evil.exe", mit.REG_SZ)


def test_bloqueo_de_puerto_y_deshacer_borra_la_regla():
    be = FakeBackend()
    remedy = mit.port_block_remedy("TCP", 445)
    assert "name=Lozarus - Bloqueo TCP 445" in remedy.targets()[0]
    assert mit.apply_remedy(remedy, be)["ok"]
    assert be.calls[-1][:5] == ("netsh", "advfirewall", "firewall", "add", "rule")
    assert mit.undo_remedy(remedy, [{}], be)["ok"]
    assert be.calls[-1] == ("netsh", "advfirewall", "firewall", "delete", "rule", "name=Lozarus - Bloqueo TCP 445")


def test_comando_que_falla_se_informa():
    be = FakeBackend()
    remedy = mit.remedy_for(finding(CRITICAL, "Firewall DESACTIVADO en el perfil Público", "check_windows_firewall",
                                    "firewall:Public", "El equipo acepta conexiones entrantes sin ningún filtrado."), be)
    assert remedy.targets() == ["netsh advfirewall set publicprofile state on"] and not remedy.undoable
    be.fail.add(("netsh", "advfirewall", "set", "publicprofile", "state", "on"))
    result = mit.apply_remedy(remedy, be)
    assert not result["ok"] and "código 1" in result["error"]


def test_firewall_de_terceros_no_se_toca():
    f = finding(WARNING, "Firewall de Windows desactivado en el perfil Privado", "check_windows_firewall",
                "firewall:Private", "Firewall de terceros activo: ESET")
    assert mit.remedy_for(f, FakeBackend()) is None


def test_directivas_de_seguridad_secedit():
    be = FakeBackend()
    remedy = mit.remedy_for(finding(CRITICAL, "Contraseñas almacenadas con cifrado reversible",
                                    "check_security_policy", module="cuentas"), be)
    result = mit.apply_remedy(remedy, be)
    assert result["ok"] and be.policy["ClearTextPassword"] == "0" and result["records"][0]["before"] == "1"
    assert mit.undo_remedy(remedy, result["records"], be)["ok"] and be.policy["ClearTextPassword"] == "1"
    be.secedit_ignores = True  # secedit «termina» pero no aplica: la verificación lo detecta
    complexity = mit.remedy_for(finding(WARNING, "Requisitos de complejidad de contraseña deshabilitados",
                                        "check_security_policy", module="cuentas"), be)
    assert not mit.apply_remedy(complexity, be)["ok"]


def test_politica_de_cuentas_net_accounts():
    be = FakeBackend()
    remedy = mit.remedy_for(finding(CRITICAL, "Sin longitud mínima de contraseña: se permiten contraseñas vacías",
                                    "check_password_policy", module="cuentas"), be)
    assert remedy.targets() == ["net accounts /minpwlen:14"]
    result = mit.apply_remedy(remedy, be)
    assert result["ok"] and be.policy["MinimumPasswordLength"] == "14"
    assert mit.undo_remedy(remedy, result["records"], be)["ok"] and be.policy["MinimumPasswordLength"] == "0"
    lockout = mit.remedy_for(finding(WARNING, "Umbral de bloqueo de cuenta alto (50 intentos)", "check_password_policy",
                                     module="cuentas"), be)
    assert lockout.targets() == ["net accounts /lockoutthreshold:10"]


def test_lsa_ppl_segun_version():
    f = finding(WARNING, "Protección de LSA no habilitada", "check_lsa_protection")
    modern = mit.remedy_for(f, FakeBackend(build=22631))
    assert modern.steps[0].data == 2 and modern.undoable
    legacy = mit.remedy_for(f, FakeBackend(build=19045))
    assert legacy.steps[0].data == 1 and not legacy.undoable and "firmware" in legacy.impact


def test_hvci_no_rebaja_proteccion_dma_y_es_individual():
    be = FakeBackend()
    be.reg_write("HKLM", mit.DEVICEGUARD_KEY, "RequirePlatformSecurityFeatures", 3, mit.REG_DWORD)
    remedy = mit.remedy_for(finding(WARNING, "Integridad de memoria (HVCI) no activa", "check_memory_integrity",
                                    "hardening:hvci"), be)
    names = [s.name for s in remedy.steps]
    assert "RequirePlatformSecurityFeatures" not in names and "Enabled" in names
    assert remedy.batch is False and remedy.reboot


def test_autorun_hklm_o_arsenal():
    f = finding(WARNING, "AutoRun no está deshabilitado para todas las unidades", "check_autorun")
    be = FakeBackend()
    remedy = mit.remedy_for(f, be)
    assert isinstance(remedy.steps[0], mit.ArsenalTweak) and remedy.admin is False
    result = mit.apply_remedy(remedy, be)
    assert result["ok"] and "autorun" in be.arsenal
    json.dumps(mit.event_payload(remedy, result))  # bytes del respaldo convertidos a hex
    be.reg_write("HKLM", mit.AUTORUN_KEY, "NoDriveTypeAutoRun", 0x91, mit.REG_DWORD)
    remedy = mit.remedy_for(f, be)
    assert isinstance(remedy.steps[0], mit.RegSet) and remedy.steps[0].data == 255 and remedy.admin


def test_smbv1_servidor_y_cliente():
    remedy = mit.remedy_for(finding(CRITICAL, "SMBv1 HABILITADO (servidor y cliente)", "check_smbv1"), FakeBackend())
    assert [s.mechanism for s in remedy.steps] == ["WINREG", "DISM"] and remedy.mechanisms == ["WINREG", "DISM"]
    assert remedy.undoable and remedy.reboot


def test_cuenta_invitado_y_tarea_programada():
    guest = mit.remedy_for(finding(CRITICAL, "Cuenta de invitado HABILITADA (Invitado)", "check_local_accounts",
                                   module="cuentas"), FakeBackend())
    assert guest.steps[0].argv == ("net", "user", "Invitado", "/active:no") and guest.undoable
    admin = finding(WARNING, "Cuenta Administrador integrada habilitada (Administrador)", "check_local_accounts")
    assert mit.remedy_for(admin, FakeBackend()) is None  # podría dejar el equipo sin administrador
    task = mit.remedy_for(finding(CRITICAL, "Tarea programada sospechosa (carpeta grabable): upd",
                                  key=r"persist:task:\upd", module="persistencia"), FakeBackend())
    assert task.steps[0].argv == ("schtasks", "/Change", "/TN", r"\upd", "/Disable")


def test_rdp_con_nla_solo_individual_y_defender():
    rdp = mit.remedy_for(finding(WARNING, "RDP habilitado (con NLA) en el puerto 3389", "check_rdp"), FakeBackend())
    assert rdp.key == "rdp:off" and rdp.batch is False
    be = FakeBackend()
    rtp = mit.remedy_for(finding(CRITICAL, "Protección en tiempo real de Defender DESACTIVADA", key="telemetria:rtp",
                                 module="telemetria"), be)
    be.fail.add(rtp.steps[0].script)
    result = mit.apply_remedy(rtp, be)
    assert not result["ok"] and "Acceso denegado" in result["error"]


def test_sin_remedio_y_elevacion():
    be = FakeBackend()
    assert mit.remedy_for(finding(PASS, "UAC activo", "check_uac"), be) is None
    assert mit.remedy_for(finding(INFO, "Inventario", "check_scheduled_tasks"), be) is None
    assert mit.remedy_for(finding(WARNING, "Secure Boot DESACTIVADO", "check_secure_boot"), be) is None
    skip = finding(SKIP, "Política de contraseñas", "check_security_policy",
                   detail=f"Requiere privilegios de {ADMIN_NAME}. Vuelve a ejecutar el script elevado.")
    assert mit.needs_elevation(skip) and not mit.needs_elevation(finding(SKIP, "x", detail="Sin datos"))


def test_todos_los_pasos_describen_su_deshacer():
    for cls in (mit.RegSet, mit.RegDelete, mit.Command, mit.PowerShell, mit.SecPolicy, mit.AccountPolicy,
                mit.ArsenalTweak):
        assert callable(getattr(cls, "undo_describe", None)), cls.__name__
    be = FakeBackend()
    remedy = mit.remedy_for(finding(WARNING, "LLMNR habilitado", "check_llmnr"), be)
    result = mit.apply_remedy(remedy, be)
    assert mit.undo_preview(remedy, result["records"]) == ["Arsenal · revertir «llmnr» desde rollback_state.json"]


def test_inf_secedit_puro():
    text = "[System Access]\nMinimumPasswordLength = 8\nPasswordComplexity = 1\n"
    assert mit.parse_inf(text) == {"MinimumPasswordLength": "8", "PasswordComplexity": "1"}
    inf = mit.build_inf({"ClearTextPassword": 0})
    assert "[System Access]\nClearTextPassword = 0\n" in inf and 'signature="$CHICAGO$"' in inf


def test_backend_real_secedit_sin_ejecutar_nada():
    """El backend real escribe una plantilla UTF-16 válida y limpia sus temporales (solo se simula el proceso)."""
    be = mit.WindowsBackend()
    seen = {}

    def fake_run(argv, timeout=120):
        argv = list(argv)
        cfg = argv[argv.index("/cfg") + 1]
        seen.setdefault("dirs", []).append(os.path.dirname(cfg))
        if argv[1] == "/configure":
            seen["configure"] = argv
            with open(cfg, encoding="utf-16") as fh:
                seen["inf"] = fh.read()
        else:
            with open(cfg, "w", encoding="utf-16") as fh:
                fh.write("[System Access]\nPasswordComplexity = 1\n")
        return 0, ""

    be.run = fake_run
    be.secedit_write({"PasswordComplexity": 1})
    assert seen["configure"][:2] == ["secedit", "/configure"] and "/db" in seen["configure"]
    assert "PasswordComplexity = 1" in seen["inf"] and seen["inf"].startswith("[Unicode]")
    assert be.secedit_read() == {"PasswordComplexity": "1"}
    assert not any(os.path.exists(d) for d in seen["dirs"])  # temporales borrados
    assert mit._sys32("python") == "python"


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
