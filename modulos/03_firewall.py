# -*- coding: utf-8 -*-
"""Plugin FIREWALL: estado del cortafuegos y acción predeterminada para el tráfico entrante."""

from __future__ import annotations

import re
import shutil
from typing import List

from ._base import IS_LINUX, IS_WINDOWS, CRITICAL, PASS, WARNING, AuditModule, CheckSkipped, CommandError
from ._utilidades import as_list, powershell, reg_get, run_cmd, security_center, wsc_product_enabled


# ===========================================================================
# MÓDULO 3 · FIREWALL
# ===========================================================================
class FirewallModule(AuditModule):
    key = "firewall"
    title = "FIREWALL"
    description = "Estado del cortafuegos y acción predeterminada para el tráfico entrante"

    def checks(self):
        if IS_WINDOWS:
            return [self.check_windows_firewall]
        if IS_LINUX:
            return [self.check_linux_firewall]
        return []

    def check_windows_firewall(self):
        """Estado del Firewall de Windows por perfil"""
        try:
            data = powershell("Out-Json @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, "
                              "@{n='Enabled';e={[string]$_.Enabled}}, @{n='Inbound';e={[string]$_.DefaultInboundAction}})")
            profiles = [{"name": p["Name"], "enabled": p["Enabled"] == "True", "inbound": p["Inbound"]}
                        for p in as_list(data)]
        except (CommandError, CheckSkipped):
            profiles = []
        if not profiles:
            profiles = self._profiles_from_registry()

        third_party = [p["name"] for p in security_center(self.ctx)["fw"] if wsc_product_enabled(p["state"])]
        names = {"Domain": "Dominio", "Private": "Privado", "Public": "Público"}
        for p in profiles:
            label = names.get(p["name"], p["name"])
            key = f"firewall:{p['name']}"  # mismo elemento para --diff aunque cambie el estado
            if not p["enabled"]:
                if third_party:
                    self.add(WARNING, f"Firewall de Windows desactivado en el perfil {label}",
                             f"Firewall de terceros activo: {', '.join(third_party)}",
                             "Verifica que el firewall de terceros filtra correctamente el tráfico entrante.", key=key)
                else:
                    # El perfil de Dominio solo se aplica en equipos unidos a un dominio
                    self.add(WARNING if p["name"] == "Domain" else CRITICAL,
                             f"Firewall DESACTIVADO en el perfil {label}",
                             "El equipo acepta conexiones entrantes sin ningún filtrado.",
                             f"Actívalo en Seguridad de Windows > Firewall y protección de red, o con "
                             f"'Set-NetFirewallProfile -Profile {p['name']} -Enabled True' (Administrador).", key=key)
            elif p["inbound"] == "Allow":
                self.add(CRITICAL, f"Perfil {label}: firewall activo pero PERMITE todo el tráfico entrante",
                         "La acción predeterminada de entrada es 'Permitir'.",
                         "Cambia la acción predeterminada de entrada a 'Bloquear'.", key=key)
            else:
                self.add(PASS, f"Firewall activo en el perfil {label} (entrada bloqueada por defecto)", key=key)

    @staticmethod
    def _profiles_from_registry() -> List[dict]:
        """Alternativa sin PowerShell: lee la configuración (y la GPO) directamente del registro."""
        base = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        gpo = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"
        result = []
        for name, key, gpo_key in (("Domain", "DomainProfile", "DomainProfile"),
                                   ("Private", "StandardProfile", "PrivateProfile"),
                                   ("Public", "PublicProfile", "PublicProfile")):
            enabled = reg_get(f"{gpo}\\{gpo_key}", "EnableFirewall")
            if enabled is None:
                enabled = reg_get(f"{base}\\{key}", "EnableFirewall", 1)
            inbound = reg_get(f"{gpo}\\{gpo_key}", "DefaultInboundAction")
            if inbound is None:
                inbound = reg_get(f"{base}\\{key}", "DefaultInboundAction", 1)
            result.append({"name": name, "enabled": bool(enabled), "inbound": "Allow" if inbound == 0 else "Block"})
        return result

    def check_linux_firewall(self):
        """Estado del cortafuegos (ufw / firewalld / nftables / iptables)"""
        if shutil.which("ufw"):
            rc, out, _ = run_cmd(["ufw", "status", "verbose"])
            if rc == 0 and re.search(r"Status:\s*active", out):
                m = re.search(r"Default:\s*(\w+)\s*\(incoming\)", out)
                if m and m.group(1).lower() == "allow":
                    self.add(CRITICAL, "ufw activo pero PERMITE el tráfico entrante por defecto", "",
                             "Ejecuta 'sudo ufw default deny incoming'.")
                else:
                    self.add(PASS, "ufw activo (entrada denegada por defecto)")
                return
        if shutil.which("firewall-cmd"):
            _, out, _ = run_cmd(["firewall-cmd", "--state"])
            if out.strip() == "running":
                self.add(PASS, "firewalld en ejecución")
                return
        if shutil.which("nft"):
            rc, out, _ = run_cmd(["nft", "list", "ruleset"])
            if rc == 0 and re.search(r"hook\s+input", out):
                self.add(PASS, "nftables con cadena de entrada configurada")
                return
        if shutil.which("iptables"):
            rc, out, _ = run_cmd(["iptables", "-S", "INPUT"])
            if rc == 0 and (re.search(r"^-P INPUT (DROP|REJECT)", out, re.M) or "-A INPUT" in out):
                self.add(PASS, "iptables con reglas/política de entrada configuradas")
                return
        if not self.ctx.is_admin:
            raise CheckSkipped("No concluyente sin root: ufw, nft e iptables requieren privilegios.")
        self.add(CRITICAL, "No se detectó ningún cortafuegos activo", "",
                 "Activa ufw ('sudo ufw enable') o firewalld y deniega el tráfico entrante por defecto.")
