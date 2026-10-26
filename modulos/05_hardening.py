# -*- coding: utf-8 -*-
"""Plugin HARDENING: configuraciones de bastionado del sistema operativo."""

from __future__ import annotations

import datetime as dt
import glob
import os
from typing import Dict

from ._base import ADMIN_NAME, IS_LINUX, IS_WINDOWS, CRITICAL, INFO, PASS, WARNING, AuditModule, CheckSkipped, CommandError
from ._utilidades import as_list, powershell, read_text, reg_get, reg_key_exists, security_center, windows_build, wsc_product_enabled


# Servicios de seguridad basada en virtualización (Win32_DeviceGuard.SecurityServicesRunning).
_SVC_CREDENTIAL_GUARD = 1
_SVC_HVCI = 2  # Hypervisor-enforced Code Integrity = «Integridad de memoria» (Aislamiento del núcleo)


def _vbs_label(status) -> str:
    return {0: "inactiva", 1: "habilitada pero no en ejecución", 2: "en ejecución"}.get(
        status, f"desconocida ({status})")


def _hvci_verdict(vbs_status, running):
    """
    Función PURA: interpreta Win32_DeviceGuard y decide la severidad de la Integridad de memoria.
    `vbs_status` = VirtualizationBasedSecurityStatus (0 inactiva, 1 habilitada-sin-ejecutar, 2 en
    ejecución). `running` = lista de SecurityServicesRunning (1 Credential Guard, 2 HVCI).
    Devuelve (severidad, título, detalle, recomendación). No consulta nada: es testable sin Windows.
    """
    running = set(running or [])
    cg = " · Credential Guard activo" if _SVC_CREDENTIAL_GUARD in running else ""
    if _SVC_HVCI in running:
        return (PASS, "Integridad de memoria (HVCI) activa",
                "El hipervisor refuerza la integridad del código del núcleo (HVCI/Aislamiento del "
                "núcleo)." + cg, "")
    if vbs_status == 2:
        return (WARNING, "Integridad de memoria (HVCI) inactiva (VBS sí está en ejecución)",
                "La seguridad basada en virtualización está en ejecución, pero el servicio HVCI no." + cg,
                "Activa «Integridad de memoria» en Seguridad de Windows → Seguridad del dispositivo → "
                "Aislamiento del núcleo, y reinicia.")
    return (WARNING, "Integridad de memoria (HVCI) no activa",
            f"Seguridad basada en virtualización: {_vbs_label(vbs_status)}." + cg,
            "Si tu hardware lo admite, activa «Aislamiento del núcleo → Integridad de memoria» en "
            "Seguridad de Windows para frenar controladores maliciosos en el kernel.")


# ===========================================================================
# MÓDULO 5 · HARDENING DEL SISTEMA
# ===========================================================================
# (ruta en /proc/sys, valores válidos, severidad si falla, descripción)
SYSCTL_CHECKS = [
    ("kernel/randomize_va_space", ("2",), CRITICAL, "ASLR completo (aleatorización de memoria)."),
    ("net/ipv4/tcp_syncookies", ("1",), WARNING, "Protección frente a SYN flood."),
    ("net/ipv4/conf/all/accept_redirects", ("0",), WARNING, "Rechazar redirecciones ICMP (MITM)."),
    ("net/ipv4/conf/all/send_redirects", ("0",), WARNING, "No enviar redirecciones ICMP."),
    ("net/ipv4/conf/all/accept_source_route", ("0",), WARNING, "Rechazar paquetes con source routing."),
    ("net/ipv4/conf/all/rp_filter", ("1", "2"), WARNING, "Filtro de ruta inversa (anti-spoofing)."),
    ("net/ipv4/ip_forward", ("0",), WARNING, "Reenvío IP desactivado (Docker/VPN lo activan legítimamente)."),
    ("kernel/kptr_restrict", ("1", "2"), WARNING, "Ocultar direcciones del kernel a usuarios sin privilegios."),
    ("kernel/dmesg_restrict", ("1",), WARNING, "Restringir dmesg a root."),
    ("fs/protected_symlinks", ("1",), WARNING, "Protección de enlaces simbólicos en directorios compartidos."),
    ("fs/protected_hardlinks", ("1",), WARNING, "Protección de enlaces duros."),
    ("fs/suid_dumpable", ("0",), WARNING, "Sin volcados de memoria de binarios SUID."),
]


class HardeningModule(AuditModule):
    key = "hardening"
    title = "HARDENING DEL SISTEMA"
    description = "Configuraciones de bastionado del sistema operativo"

    def checks(self):
        if IS_WINDOWS:
            return [self.check_uac, self.check_defender, self.check_updates, self.check_bitlocker,
                    self.check_secure_boot, self.check_memory_integrity, self.check_smbv1,
                    self.check_smb_signing, self.check_rdp, self.check_llmnr, self.check_wdigest,
                    self.check_lsa_protection, self.check_ntlm, self.check_autorun]
        if IS_LINUX:
            return [self.check_kernel_params, self.check_mac, self.check_ssh]
        return []

    # ---------------------------- Windows -----------------------------------
    def check_uac(self):
        """Control de cuentas de usuario (UAC)"""
        base = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        lua = reg_get(base, "EnableLUA", 1)
        consent = reg_get(base, "ConsentPromptBehaviorAdmin", 5)
        secure_desktop = reg_get(base, "PromptOnSecureDesktop", 1)
        if lua == 0:
            self.add(CRITICAL, "UAC (Control de cuentas de usuario) DESACTIVADO",
                     "Todo proceso de un administrador se ejecuta con privilegios completos.",
                     "Activa UAC (EnableLUA = 1) y reinicia.")
        elif consent == 0:
            self.add(CRITICAL, "UAC eleva privilegios SIN preguntar a los administradores",
                     "ConsentPromptBehaviorAdmin = 0: el malware puede elevarse en silencio.",
                     "Sube el nivel de UAC a 'Notificarme solo cuando una aplicación intente realizar cambios' o superior.")
        elif secure_desktop == 0:
            self.add(WARNING, "UAC activo, pero sin escritorio seguro",
                     "El aviso de elevación podría ser manipulado por otro proceso.",
                     "Activa PromptOnSecureDesktop (nivel predeterminado de UAC).")
        else:
            level = "Notificar siempre" if consent == 2 else "predeterminado"
            self.add(PASS, f"UAC activo (nivel {level})")

    def check_defender(self):
        """Protección antivirus"""
        status = None
        try:
            status = powershell("Out-Json (Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, "
                                "AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, "
                                "IsTamperProtected, AntivirusSignatureAge)")
        except (CommandError, CheckSkipped):
            pass
        products = security_center(self.ctx)["av"]
        third_party = [p["name"] for p in products
                       if "defender" not in p["name"].lower() and wsc_product_enabled(p["state"])]

        if status and status.get("AntivirusEnabled") and status.get("RealTimeProtectionEnabled"):
            age = int(status.get("AntivirusSignatureAge") or 0)
            if age > 7:
                self.add(WARNING, f"Microsoft Defender activo, pero sus firmas tienen {age} días",
                         "", "Actualiza las definiciones desde Windows Update o con 'Update-MpSignature'.")
            else:
                behavior = "sí" if status.get("BehaviorMonitorEnabled") else "no"
                self.add(PASS, "Microsoft Defender activo con protección en tiempo real",
                         f"Antigüedad de firmas: {age} día(s) · Monitor de comportamiento: {behavior}")
            if status.get("IsTamperProtected") is False:
                self.add(WARNING, "Protección contra alteraciones (Tamper Protection) desactivada",
                         "El malware con privilegios podría desactivar Defender.",
                         "Actívala en Seguridad de Windows > Protección antivirus y contra amenazas.")
        elif third_party:
            self.add(PASS, f"Antivirus de terceros activo: {', '.join(third_party)}")
        elif status is None and not products:
            raise CheckSkipped("No se pudo consultar el estado del antivirus")
        else:
            self.add(CRITICAL, "No hay protección antivirus en tiempo real activa", "",
                     "Activa la protección en tiempo real de Microsoft Defender o instala un antivirus.")

    def check_updates(self):
        """Actualizaciones de Windows"""
        if reg_get(r"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv", "Start") == 4:
            self.add(CRITICAL, "El servicio Windows Update está DESHABILITADO",
                     "El sistema no recibirá parches de seguridad.",
                     "Restablece el inicio del servicio 'wuauserv' a Manual/Automático.")
        if reg_get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate") == 1:
            self.add(WARNING, "Actualizaciones automáticas desactivadas por directiva", "",
                     "Revisa la GPO 'Configurar actualizaciones automáticas'.")

        data = powershell(r"""
$o = @{}
try {
    $h = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($h) { $o.kb = $h.HotFixID; $o.kb_date = $h.InstalledOn.ToString('yyyy-MM-dd') }
} catch {}
try {
    $d = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
    if ($d -and $d.Year -gt 2000) { $o.wu_date = $d.ToString('yyyy-MM-dd') }
} catch {}
Out-Json $o
""", timeout=90) or {}
        # La fecha del último KB refleja los parches del SO; la de Windows Update puede incluir
        # solo firmas de Defender, por eso es secundaria.
        date_str = data.get("kb_date") or data.get("wu_date")
        if not date_str:
            raise CheckSkipped("No se pudo determinar la fecha de la última actualización")
        last = dt.date.fromisoformat(date_str)
        days = (dt.date.today() - last).days
        detail = f"Último parche: {data.get('kb', '?')} ({data.get('kb_date', '?')}) · " \
                 f"Última instalación vía Windows Update: {data.get('wu_date', '?')}"
        if days > 90:
            self.add(CRITICAL, f"Último parche de seguridad instalado hace {days} días", detail,
                     "Ejecuta Windows Update cuanto antes: el sistema acumula vulnerabilidades públicas.")
        elif days > 45:
            self.add(WARNING, f"Último parche instalado hace {days} días", detail,
                     "Microsoft publica parches cada mes (Patch Tuesday). Busca actualizaciones.")
        else:
            self.add(PASS, f"Sistema parcheado recientemente (hace {days} días)", detail)

    def check_bitlocker(self):
        """Cifrado de disco (BitLocker)"""
        drive = os.environ.get("SystemDrive", "C:")
        # La propiedad de shell 'System.Volume.BitLockerProtection' no requiere Administrador
        script = r"""
$v = (New-Object -ComObject Shell.Application).NameSpace('__DRIVE__\').Self.ExtendedProperty('System.Volume.BitLockerProtection')
if ($null -eq $v) { Out-Json $null } else { Out-Json ([int]$v) }
""".replace("__DRIVE__", drive)
        value = powershell(script)
        if value in (1, 6):
            self.add(PASS, f"Unidad del sistema ({drive}) cifrada con BitLocker")
        elif value == 3:
            self.add(INFO, f"BitLocker: cifrado de {drive} en curso")
        elif value == 5:
            self.add(WARNING, f"BitLocker SUSPENDIDO en {drive}", "El disco está cifrado pero la clave está en claro.",
                     f"Reanuda la protección: 'Resume-BitLocker -MountPoint {drive}' (Administrador).")
        elif value in (2, 4):
            self.add(WARNING, f"La unidad del sistema ({drive}) NO está cifrada",
                     "Si roban o pierdes el equipo, los datos se pueden leer extrayendo el disco.",
                     "Activa BitLocker o 'Cifrado de dispositivo' (Configuración > Privacidad y seguridad).")
        else:
            self.add(WARNING, "Cifrado de disco no disponible o no detectado",
                     "La edición o el hardware pueden no admitir BitLocker.",
                     "Usa 'Cifrado de dispositivo' si está disponible o una alternativa como VeraCrypt.")

    def check_secure_boot(self):
        """Arranque seguro (Secure Boot)"""
        value = reg_get(r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
        if value == 1:
            self.add(PASS, "Secure Boot activado")
        elif value == 0:
            self.add(WARNING, "Secure Boot DESACTIVADO", "Permite cargar bootkits antes que el sistema operativo.",
                     "Actívalo en la configuración UEFI del equipo.")
        else:
            self.add(WARNING, "Secure Boot no soportado (BIOS heredada / MBR)", "",
                     "Migra a UEFI + GPT para poder habilitar Secure Boot.")

    def check_memory_integrity(self):
        """Integridad de memoria (HVCI) y seguridad basada en virtualización (VBS)"""
        # Solo lectura, sin privilegios: consulta la clase WMI documentada Win32_DeviceGuard.
        script = (r"Out-Json (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard "
                  r"-ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object "
                  r"VirtualizationBasedSecurityStatus, @{n='Running';e={@($_.SecurityServicesRunning)}})")
        try:
            data = powershell(script)
        except CommandError as exc:
            # Error al CONSULTAR: no se confunde con una configuración insegura.
            raise CheckSkipped(f"no se pudo consultar DeviceGuard (error de consulta): {exc}")
        if not isinstance(data, dict):
            # No DISPONIBLE (edición de Windows sin VBS, sin virtualización o clase ausente).
            raise CheckSkipped("Integridad de memoria no disponible: Win32_DeviceGuard no devolvió "
                               "datos (edición de Windows sin VBS o virtualización no habilitada)")
        status = data.get("VirtualizationBasedSecurityStatus")
        running = [int(x) for x in as_list(data.get("Running")) if isinstance(x, (int, float))]
        severity, title, detail, recommendation = _hvci_verdict(status, running)
        self.add(severity, title, detail, recommendation, key="hardening:hvci")

    def check_smbv1(self):
        """Protocolo SMBv1"""
        server = None
        if self.ctx.is_admin:
            try:
                server = powershell("Out-Json (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol")
            except (CommandError, CheckSkipped):
                server = None
        if server is None:
            value = reg_get(r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
            server = bool(value) if value is not None else None
        client_key = r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"
        client = reg_key_exists(client_key) and reg_get(client_key, "Start", 4) != 4

        if server or client:
            parts = [name for name, on in (("servidor", server), ("cliente", client)) if on]
            self.add(CRITICAL, f"SMBv1 HABILITADO ({' y '.join(parts)})",
                     "Protocolo obsoleto explotado por WannaCry y NotPetya (EternalBlue).",
                     "Desactívalo: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' (Administrador).")
        elif server is None:
            self.add(PASS, "Cliente SMBv1 no instalado",
                     f"El estado del servidor SMBv1 se verifica con más precisión como {ADMIN_NAME}.")
        else:
            self.add(PASS, "SMBv1 deshabilitado (cliente y servidor)")

    def check_smb_signing(self):
        """Firma SMB obligatoria"""
        required = reg_get(r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                           "RequireSecuritySignature")
        # Windows 11 24H2 (build 26100) exige firma SMB por defecto
        if required == 1 or (required is None and windows_build() >= 26100):
            self.add(PASS, "Firma SMB obligatoria en el servidor")
        else:
            self.add(WARNING, "La firma SMB no es obligatoria",
                     "Sin firma, un atacante en la LAN puede retransmitir autenticaciones NTLM (NTLM relay).",
                     "Ejecuta 'Set-SmbServerConfiguration -RequireSecuritySignature $true' o aplícalo por GPO.")

    def check_rdp(self):
        """Escritorio remoto (RDP) y NLA"""
        ts = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
        policy = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        deny = reg_get(policy, "fDenyTSConnections")
        if deny is None:
            deny = reg_get(ts, "fDenyTSConnections", 1)
        self.ctx.facts["rdp_enabled"] = deny == 0
        if deny != 0:
            self.add(PASS, "Escritorio remoto (RDP) deshabilitado")
            return
        rdp_tcp = ts + r"\WinStations\RDP-Tcp"
        nla = reg_get(policy, "UserAuthentication")
        if nla is None:
            nla = reg_get(rdp_tcp, "UserAuthentication", 1)
        port = reg_get(rdp_tcp, "PortNumber", 3389)
        if nla == 0:
            self.add(CRITICAL, f"RDP habilitado SIN autenticación a nivel de red (NLA), puerto {port}",
                     "La pantalla de inicio de sesión queda expuesta antes de autenticar (fuerza bruta, BlueKeep).",
                     "Activa NLA y limita RDP a una VPN o a IPs de confianza.")
        else:
            self.add(WARNING, f"RDP habilitado (con NLA) en el puerto {port}", "",
                     "Si no lo usas, desactívalo. Si lo usas, no lo expongas a Internet: VPN, MFA y bloqueo de cuentas.")

    def check_llmnr(self):
        """Resolución de nombres LLMNR"""
        value = reg_get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast")
        if value == 0:
            self.add(PASS, "LLMNR deshabilitado")
        else:
            self.add(WARNING, "LLMNR habilitado",
                     "Permite envenenar respuestas de nombres en la LAN y capturar hashes NTLM (Responder).",
                     "Deshabilítalo por GPO: Configuración del equipo > Plantillas administrativas > Red > "
                     "Cliente DNS > Desactivar resolución de nombres de multidifusión.")

    def check_wdigest(self):
        """Credenciales en claro en memoria (WDigest)"""
        value = reg_get(r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential")
        if value == 1:
            self.add(CRITICAL, "WDigest almacena contraseñas EN CLARO en memoria",
                     "UseLogonCredential = 1: herramientas como Mimikatz pueden extraerlas de LSASS.",
                     "Establece UseLogonCredential = 0 (o elimina el valor).")
        else:
            self.add(PASS, "WDigest no guarda contraseñas en claro")

    def check_lsa_protection(self):
        """Protección de LSA (RunAsPPL)"""
        lsa = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        value = reg_get(lsa, "RunAsPPL")
        if value is None:
            value = reg_get(lsa, "RunAsPPLBoot")
        if value in (1, 2):
            self.add(PASS, "LSASS se ejecuta como proceso protegido (RunAsPPL)")
        else:
            self.add(WARNING, "Protección de LSA no habilitada",
                     "Sin RunAsPPL es más fácil volcar credenciales desde la memoria de LSASS.",
                     "Activa 'Protección de la autoridad de seguridad local' en Seguridad de Windows > "
                     "Seguridad del dispositivo > Aislamiento del núcleo.")

    def check_ntlm(self):
        """Nivel de autenticación LAN Manager (NTLMv1)"""
        value = reg_get(r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel")
        if value is not None and value < 3:
            self.add(WARNING, f"Se permiten respuestas LM/NTLMv1 (LmCompatibilityLevel = {value})",
                     "LM y NTLMv1 se pueden romper con facilidad.",
                     "Establece 'Enviar solo respuesta NTLMv2' (nivel 5 recomendado).")
        else:
            self.add(PASS, "Solo se usa NTLMv2 (LM/NTLMv1 deshabilitados)",
                     f"LmCompatibilityLevel = {value if value is not None else 'predeterminado (3)'}")

    def check_autorun(self):
        """Ejecución automática (AutoRun) de medios extraíbles"""
        path = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        value = reg_get("HKLM\\" + path, "NoDriveTypeAutoRun")
        if value is None:
            value = reg_get("HKCU\\" + path, "NoDriveTypeAutoRun")
        if value == 0xFF:
            self.add(PASS, "AutoRun deshabilitado para todas las unidades")
        else:
            self.add(WARNING, "AutoRun no está deshabilitado para todas las unidades",
                     f"NoDriveTypeAutoRun = {hex(value) if value is not None else 'predeterminado (0x91)'}",
                     "Establece NoDriveTypeAutoRun = 0xFF por GPO ('Desactivar reproducción automática: Todas las unidades').")

    # ----------------------------- Linux ------------------------------------
    def check_kernel_params(self):
        """Parámetros de seguridad del kernel (sysctl)"""
        good = []
        for path, expected, severity, description in SYSCTL_CHECKS:
            value = read_text(f"/proc/sys/{path}")
            if value is None:
                continue
            value, name = value.strip(), path.replace("/", ".")
            if value in expected:
                good.append(name)
                continue
            if path == "kernel/randomize_va_space" and value == "1":
                severity = WARNING  # ASLR parcial
            self.add(severity, f"{name} = {value} (recomendado: {' o '.join(expected)})", description,
                     f"Añade '{name} = {expected[0]}' a /etc/sysctl.d/99-hardening.conf y aplica con 'sysctl --system'.")
        if good:
            self.add(PASS, f"{len(good)} parámetros del kernel con valor seguro", ", ".join(good))

    def check_mac(self):
        """Control de acceso obligatorio (SELinux / AppArmor)"""
        selinux = read_text("/sys/fs/selinux/enforce")
        apparmor = read_text("/sys/module/apparmor/parameters/enabled")
        if selinux is not None:
            if selinux.strip() == "1":
                self.add(PASS, "SELinux en modo enforcing")
            else:
                self.add(WARNING, "SELinux en modo permisivo", "Registra violaciones pero no las bloquea.",
                         "Activa el modo enforcing ('setenforce 1' y SELINUX=enforcing en /etc/selinux/config).")
        elif apparmor and apparmor.strip().upper().startswith("Y"):
            self.add(PASS, "AppArmor habilitado")
        else:
            self.add(WARNING, "No hay SELinux ni AppArmor activos", "",
                     "Habilita AppArmor (Debian/Ubuntu) o SELinux (RHEL/Fedora) para confinar servicios.")

    def check_ssh(self):
        """Configuración del servidor SSH"""
        main = "/etc/ssh/sshd_config"
        if not os.path.exists(main):
            self.add(INFO, "Servidor SSH no instalado (no existe /etc/ssh/sshd_config)")
            return
        # sshd usa el PRIMER valor encontrado; los .d/ se incluyen al principio en la mayoría de distros
        settings: Dict[str, str] = {}
        for path in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")) + [main]:
            for line in (read_text(path) or "").splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) != 2 or parts[0].startswith("#"):
                    continue
                if parts[0].lower() == "match":
                    break  # los bloques Match quedan fuera del alcance de esta comprobación
                settings.setdefault(parts[0].lower(), parts[1].strip().lower())
        root = settings.get("permitrootlogin", "prohibit-password")
        if root == "yes":
            self.add(CRITICAL, "SSH permite el inicio de sesión de root con contraseña", "PermitRootLogin yes",
                     "Establece 'PermitRootLogin no' y usa sudo.")
        else:
            self.add(PASS, f"SSH: login directo de root restringido (PermitRootLogin {root})")
        if settings.get("permitemptypasswords", "no") == "yes":
            self.add(CRITICAL, "SSH permite contraseñas vacías", "PermitEmptyPasswords yes",
                     "Establece 'PermitEmptyPasswords no'.")
        if settings.get("passwordauthentication", "yes") == "yes":
            self.add(WARNING, "SSH acepta autenticación por contraseña", "Expuesto a fuerza bruta.",
                     "Usa claves públicas y establece 'PasswordAuthentication no'.")
        else:
            self.add(PASS, "SSH solo admite autenticación por clave")
