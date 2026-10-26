# -*- coding: utf-8 -*-
"""Plugin SERVICIOS: servicios peligrosos en ejecución y rutas de servicio sin comillas."""

from __future__ import annotations

import re
import shutil
from typing import Dict, Tuple

from ._base import IS_LINUX, IS_WINDOWS, CRITICAL, INFO, PASS, WARNING, AuditModule, CheckSkipped, Severity
from ._utilidades import as_list, powershell, run_cmd


# ===========================================================================
# MÓDULO 6 · SERVICIOS
# ===========================================================================
WINDOWS_RISKY_SERVICES: Dict[str, Tuple[Severity, str]] = {
    "TlntSvr": (CRITICAL, "Servidor Telnet: acceso remoto sin cifrar."),
    "RemoteRegistry": (WARNING, "Permite consultar y modificar el registro desde la red."),
    "SNMP": (WARNING, "SNMP v1/v2c envía las 'community strings' en texto plano."),
    "FTPSVC": (WARNING, "Servidor FTP de IIS: credenciales en claro si no usa FTPS."),
    "upnphost": (WARNING, "Publica dispositivos UPnP en la red local."),
    "WinRM": (WARNING, "Administración remota de Windows (PowerShell Remoting)."),
    "WebClient": (WARNING, "Cliente WebDAV: aprovechado en ataques de relay NTLM."),
    "TeamViewer": (WARNING, "Acceso remoto: verifica que es legítimo y está protegido con 2FA."),
    "AnyDesk": (WARNING, "Acceso remoto: verifica que es legítimo y está protegido con contraseña/2FA."),
    "tvnserver": (WARNING, "Servidor TightVNC: acceso remoto, a menudo sin cifrado."),
    "uvnc_service": (WARNING, "Servidor UltraVNC: acceso remoto, a menudo sin cifrado."),
    "vncserver": (WARNING, "Servidor RealVNC: acceso remoto."),
    "TermService": (INFO, "Servicios de Escritorio remoto (revisa el resultado de RDP en 'hardening')."),
    "sshd": (INFO, "Servidor OpenSSH: usa autenticación por clave."),
    "W3SVC": (INFO, "Servidor web IIS: verifica que es necesario."),
    "Spooler": (INFO, "Cola de impresión: si no imprimes, deshabilitarla reduce la superficie (PrintNightmare)."),
    "SharedAccess": (INFO, "Conexión compartida a Internet (ICS / zona con cobertura inalámbrica móvil)."),
}

LINUX_RISKY_UNITS: Dict[str, Tuple[Severity, str]] = {
    "telnet.socket": (CRITICAL, "Telnet: acceso remoto sin cifrar."),
    "rsh.socket": (CRITICAL, "rsh: shell remota sin cifrar."),
    "rlogin.socket": (CRITICAL, "rlogin: login remoto sin cifrar."),
    "rexec.socket": (CRITICAL, "rexec: ejecución remota sin cifrar."),
    "tftpd-hpa.service": (CRITICAL, "TFTP: transferencia de ficheros sin autenticación."),
    "xinetd.service": (WARNING, "Superservidor heredado: revisa qué servicios lanza."),
    "inetd.service": (WARNING, "Superservidor heredado: revisa qué servicios lanza."),
    "vsftpd.service": (WARNING, "Servidor FTP: usa SFTP/FTPS."),
    "proftpd.service": (WARNING, "Servidor FTP: usa SFTP/FTPS."),
    "snmpd.service": (WARNING, "SNMP: community strings en claro (v1/v2c)."),
    "rpcbind.service": (WARNING, "Portmapper RPC (NFS): enumerable desde la red."),
    "nfs-server.service": (WARNING, "Servidor NFS: revisa /etc/exports."),
    "smbd.service": (WARNING, "Samba: revisa los recursos compartidos."),
    "x11vnc.service": (WARNING, "Servidor VNC."),
    "avahi-daemon.service": (INFO, "mDNS/DNS-SD: anuncia el equipo en la red local."),
    "cups.service": (INFO, "Servidor de impresión CUPS."),
}


class ServiciosModule(AuditModule):
    key = "servicios"
    title = "SERVICIOS"
    description = "Servicios potencialmente peligrosos en ejecución y configuraciones de servicio inseguras"

    def checks(self):
        if IS_WINDOWS:
            return [self.check_windows_services, self.check_unquoted_paths]
        if IS_LINUX:
            return [self.check_linux_services]
        return []

    def check_windows_services(self):
        """Servicios de riesgo en ejecución"""
        names = ",".join(f"'{n}'" for n in WINDOWS_RISKY_SERVICES)
        data = powershell(f"Out-Json @(Get-Service -Name {names} -ErrorAction SilentlyContinue | "
                          "Select-Object Name, DisplayName, @{n='Status';e={[string]$_.Status}}, "
                          "@{n='StartType';e={[string]$_.StartType}})")
        running = [s for s in as_list(data) if s.get("Status") == "Running"]
        risky_found = False
        for svc in running:
            severity, reason = WINDOWS_RISKY_SERVICES.get(svc["Name"], (INFO, ""))
            risky_found |= severity in (WARNING, CRITICAL)
            self.add(severity, f"En ejecución: {svc.get('DisplayName')} ({svc['Name']})",
                     f"{reason}\nTipo de inicio: {svc.get('StartType')}",
                     "Si no lo necesitas, detenlo y establece su inicio en 'Deshabilitado' (services.msc).")
        if not risky_found:
            self.add(PASS, "Ningún servicio de alto riesgo en ejecución",
                     f"Revisados: {', '.join(WINDOWS_RISKY_SERVICES)}")

    def check_unquoted_paths(self):
        """Rutas de servicio sin comillas (escalada de privilegios)"""
        data = powershell("Out-Json @(Get-CimInstance Win32_Service | Select-Object Name, PathName, StartMode)",
                          timeout=90)
        vulnerable = []
        for svc in as_list(data):
            path = (svc.get("PathName") or "").strip()
            if not path or path.startswith('"'):
                continue
            m = re.match(r"^([a-z]:\\.*?\.exe)\b", path, re.I)
            if m and " " in m.group(1):  # ruta con espacios sin comillas
                vulnerable.append(f"{svc['Name']} [{svc.get('StartMode')}]: {path}")
        if vulnerable:
            self.add(WARNING, f"{len(vulnerable)} servicio(s) con ruta sin comillas que contiene espacios",
                     "\n".join(vulnerable[:10]),
                     "Entrecomilla la ruta en HKLM\\SYSTEM\\CurrentControlSet\\Services\\<servicio>\\ImagePath. "
                     "Quien pueda escribir en una carpeta intermedia podría ejecutar código como SYSTEM.")
        else:
            self.add(PASS, "Todas las rutas de servicio están correctamente entrecomilladas")

    def check_linux_services(self):
        """Servicios de riesgo activos (systemd)"""
        if not shutil.which("systemctl"):
            raise CheckSkipped("systemctl no disponible (sistema sin systemd)")
        units = list(LINUX_RISKY_UNITS)
        _, out, _ = run_cmd(["systemctl", "is-active", *units])
        states = out.split()
        risky_found = False
        for unit, state in zip(units, states):
            if state != "active":
                continue
            severity, reason = LINUX_RISKY_UNITS[unit]
            risky_found |= severity in (WARNING, CRITICAL)
            self.add(severity, f"Servicio activo: {unit}", reason,
                     f"Si no lo necesitas: 'sudo systemctl disable --now {unit}'.")
        if not risky_found:
            self.add(PASS, "Ningún servicio de alto riesgo activo")
