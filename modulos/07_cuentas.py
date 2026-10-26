# -*- coding: utf-8 -*-
"""Plugin CUENTAS: política de contraseñas, bloqueo de cuentas y cuentas privilegiadas."""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import tempfile
from typing import Dict

from ._base import IS_LINUX, IS_WINDOWS, CRITICAL, INFO, PASS, WARNING, AuditModule, CheckSkipped, CommandError, first_line
from ._utilidades import as_list, powershell, read_text, run_cmd


# ===========================================================================
# MÓDULO 7 · CUENTAS Y POLÍTICAS DE CONTRASEÑAS
# ===========================================================================
TIMEQ_FOREVER = 0xFFFFFFFF


def net_user_modals(level: int) -> Dict[str, int]:
    """Lee la política de cuentas local con la API NetUserModalsGet (no requiere Administrador
    y, a diferencia de 'net accounts', no depende del idioma del sistema)."""
    from ctypes import wintypes

    class USER_MODALS_INFO_0(ctypes.Structure):
        _fields_ = [("min_passwd_len", wintypes.DWORD), ("max_passwd_age", wintypes.DWORD),
                    ("min_passwd_age", wintypes.DWORD), ("force_logoff", wintypes.DWORD),
                    ("password_hist_len", wintypes.DWORD)]

    class USER_MODALS_INFO_3(ctypes.Structure):
        _fields_ = [("lockout_duration", wintypes.DWORD), ("lockout_observation_window", wintypes.DWORD),
                    ("lockout_threshold", wintypes.DWORD)]

    struct_type = {0: USER_MODALS_INFO_0, 3: USER_MODALS_INFO_3}[level]
    netapi32 = ctypes.WinDLL("netapi32")
    netapi32.NetUserModalsGet.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    netapi32.NetUserModalsGet.restype = wintypes.DWORD
    netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    buffer = ctypes.c_void_p()
    status = netapi32.NetUserModalsGet(None, level, ctypes.byref(buffer))
    if status != 0:
        raise CommandError(f"NetUserModalsGet (nivel {level}) devolvió el código {status}")
    try:
        info = ctypes.cast(buffer, ctypes.POINTER(struct_type)).contents
        return {name: int(getattr(info, name)) for name, _ in struct_type._fields_}
    finally:
        netapi32.NetApiBufferFree(buffer)


class CuentasModule(AuditModule):
    key = "cuentas"
    title = "CUENTAS Y CONTRASEÑAS"
    description = "Política de contraseñas, bloqueo de cuentas y cuentas privilegiadas"

    def checks(self):
        if IS_WINDOWS:
            return [self.check_password_policy, self.check_security_policy,
                    self.check_local_accounts, self.check_admin_group]
        if IS_LINUX:
            return [self.check_linux_password_policy, self.check_uid0, self.check_empty_passwords]
        return []

    # ---------------------------- Windows -----------------------------------
    def check_password_policy(self):
        """Política local de contraseñas y bloqueo"""
        m0, m3 = net_user_modals(0), net_user_modals(3)
        min_len, threshold = m0["min_passwd_len"], m3["lockout_threshold"]
        max_age = "nunca" if m0["max_passwd_age"] == TIMEQ_FOREVER else f"{m0['max_passwd_age'] // 86400} días"
        duration = ("hasta desbloqueo manual" if m3["lockout_duration"] == TIMEQ_FOREVER
                    else f"{m3['lockout_duration'] // 60} min")
        detail = (f"Longitud mínima: {min_len} · Caducidad: {max_age} · Historial: {m0['password_hist_len']} · "
                  f"Umbral de bloqueo: {threshold or 'sin bloqueo'} · Duración del bloqueo: {duration}")

        if min_len == 0:
            self.add(CRITICAL, "Sin longitud mínima de contraseña: se permiten contraseñas vacías", detail,
                     "Exige al menos 12-14 caracteres: 'net accounts /minpwlen:14' (Administrador) o por GPO.")
        elif min_len < 12:
            self.add(WARNING, f"Longitud mínima de contraseña baja ({min_len} caracteres)", detail,
                     "Se recomiendan 12-14 caracteres o más (CIS / NIST SP 800-63B).")
        else:
            self.add(PASS, f"Longitud mínima de contraseña adecuada ({min_len} caracteres)", detail)

        if threshold == 0:
            self.add(WARNING, "Sin bloqueo de cuenta tras intentos fallidos",
                     "Permite ataques de fuerza bruta ilimitados contra las cuentas locales.",
                     "Configura un umbral de 5-10 intentos: 'net accounts /lockoutthreshold:10'.")
        elif threshold > 10:
            self.add(WARNING, f"Umbral de bloqueo de cuenta alto ({threshold} intentos)", "",
                     "Redúcelo a 10 intentos o menos.")
        else:
            self.add(PASS, f"Bloqueo de cuenta tras {threshold} intentos fallidos")

    def check_security_policy(self):
        """Complejidad y almacenamiento de contraseñas (secedit)"""
        self.require_admin()
        workdir = tempfile.mkdtemp(prefix="auditor_")
        cfg = os.path.join(workdir, "secpol.inf")
        try:
            # /export solo VUELCA la política a un fichero temporal: no modifica nada
            rc, out, err = run_cmd(["secedit", "/export", "/cfg", cfg, "/areas", "SECURITYPOLICY", "/quiet"], timeout=60)
            if not os.path.exists(cfg):
                raise CommandError(first_line(out or err) or f"secedit devolvió {rc}")
            with open(cfg, encoding="utf-16") as fh:
                values = dict(re.findall(r"^\s*(\w+)\s*=\s*(.*?)\s*$", fh.read(), re.M))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        if values.get("ClearTextPassword") == "1":
            self.add(CRITICAL, "Contraseñas almacenadas con cifrado reversible",
                     "Equivale a guardar las contraseñas en claro.",
                     "Deshabilita 'Almacenar contraseñas con cifrado reversible'.")
        if values.get("PasswordComplexity") == "1":
            self.add(PASS, "Requisitos de complejidad de contraseña habilitados")
        else:
            self.add(WARNING, "Requisitos de complejidad de contraseña deshabilitados", "",
                     "Habilita 'La contraseña debe cumplir los requisitos de complejidad' (secpol.msc) "
                     "o, mejor, exige frases de contraseña largas.")
        if values.get("LSAAnonymousNameLookup") == "1":
            self.add(WARNING, "Se permite la traducción anónima SID/nombre", "",
                     "Deshabilita 'Acceso de red: permitir traducción SID/nombre anónima'.")

    def check_local_accounts(self):
        """Cuentas locales (Invitado, Administrador integrado)"""
        data = powershell("Out-Json @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | "
                          "Select-Object Name, SID, Disabled, PasswordRequired)", timeout=90)
        users = as_list(data)
        if not users:
            raise CommandError("No se obtuvieron cuentas locales")
        by_rid = {str(u.get("SID", "")).rsplit("-", 1)[-1]: u for u in users}
        enabled = [u for u in users if not u.get("Disabled")]

        guest = by_rid.get("501")
        if guest and not guest.get("Disabled"):
            self.add(CRITICAL, f"Cuenta de invitado HABILITADA ({guest['Name']})",
                     "Permite acceso sin credenciales personales.",
                     f"Deshabilítala: 'net user \"{guest['Name']}\" /active:no' (Administrador).")
        else:
            self.add(PASS, "Cuenta de invitado deshabilitada")

        admin = by_rid.get("500")
        if admin and not admin.get("Disabled"):
            self.add(WARNING, f"Cuenta Administrador integrada habilitada ({admin['Name']})",
                     "Su SID (-500) es conocido y por defecto no se bloquea por intentos fallidos.",
                     "Deshabilítala y usa una cuenta administrativa nominal.")
        else:
            self.add(PASS, "Cuenta Administrador integrada deshabilitada")

        no_password = [u["Name"] for u in enabled if u.get("PasswordRequired") is False]
        if no_password:
            self.add(WARNING, f"Cuentas habilitadas que no requieren contraseña: {', '.join(no_password)}",
                     "El indicador PASSWD_NOTREQD permite asignarles una contraseña vacía.",
                     "Ejecuta 'net user <cuenta> /passwordreq:yes' y asigna una contraseña robusta.")
        self.add(INFO, f"Cuentas locales habilitadas ({len(enabled)}): " +
                 ", ".join(u["Name"] for u in enabled))

    def check_admin_group(self):
        """Miembros del grupo Administradores"""
        data = powershell(r"""
try { $m = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name }) }
catch {
    $g = Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'"
    $m = @(Get-CimAssociatedInstance -InputObject $g -Association Win32_GroupUser | ForEach-Object { "$($_.Domain)\$($_.Name)" })
}
Out-Json $m
""", timeout=90)
        members = [m for m in as_list(data) if m]
        detail = ", ".join(members) or "(ninguno)"
        if len(members) > 3:
            self.add(WARNING, f"{len(members)} miembros en el grupo Administradores", detail,
                     "Aplica mínimo privilegio: usa cuentas estándar para el día a día.")
        else:
            self.add(INFO, f"Miembros del grupo Administradores ({len(members)})", detail)

    # ----------------------------- Linux ------------------------------------
    def check_linux_password_policy(self):
        """Política de contraseñas (pwquality / login.defs)"""
        pwquality = read_text("/etc/security/pwquality.conf") or ""
        m = re.search(r"^\s*minlen\s*=\s*(\d+)", pwquality, re.M)
        if not m:
            self.add(WARNING, "No hay longitud mínima de contraseña definida en pam_pwquality", "",
                     "Instala libpam-pwquality y define 'minlen = 14' en /etc/security/pwquality.conf.")
        elif int(m.group(1)) < 12:
            self.add(WARNING, f"Longitud mínima de contraseña baja (minlen = {m.group(1)})", "",
                     "Se recomiendan 12-14 caracteres o más.")
        else:
            self.add(PASS, f"Longitud mínima de contraseña adecuada (minlen = {m.group(1)})")
        m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", read_text("/etc/login.defs") or "", re.M)
        if m:
            self.add(INFO, f"Caducidad de contraseñas: {m.group(1)} días (PASS_MAX_DAYS)")

    def check_uid0(self):
        """Cuentas con UID 0 (privilegios de root)"""
        users = [line.split(":")[0] for line in (read_text("/etc/passwd") or "").splitlines()
                 if len(line.split(":")) > 2 and line.split(":")[2] == "0"]
        extra = [u for u in users if u != "root"]
        if extra:
            self.add(CRITICAL, f"Cuentas adicionales con UID 0: {', '.join(extra)}",
                     "Tienen privilegios de root; es una técnica habitual de persistencia.",
                     "Verifica su origen y elimínalas o cámbiales el UID.")
        else:
            self.add(PASS, "Solo 'root' tiene UID 0")

    def check_empty_passwords(self):
        """Cuentas con contraseña vacía"""
        try:
            shadow = read_text("/etc/shadow") or ""
        except PermissionError:
            raise CheckSkipped("Leer /etc/shadow requiere root")
        empty = [line.split(":")[0] for line in shadow.splitlines()
                 if len(line.split(":")) > 1 and line.split(":")[1] == ""]
        if empty:
            self.add(CRITICAL, f"Cuentas SIN contraseña: {', '.join(empty)}", "",
                     "Asigna una contraseña ('passwd <usuario>') o bloquéalas ('passwd -l <usuario>').")
        else:
            self.add(PASS, "Ninguna cuenta tiene la contraseña vacía")
