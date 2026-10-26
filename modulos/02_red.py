# -*- coding: utf-8 -*-
"""Plugin RED LOCAL: direccionamiento, DNS, perfil de red, Wi-Fi y detección de ARP spoofing."""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
from typing import Dict, List, Optional, Tuple

from ._base import IS_LINUX, IS_WINDOWS, CRITICAL, INFO, PASS, WARNING, AuditModule, CheckSkipped, first_line
from ._utilidades import as_list, get_default_gateway, get_local_ip, powershell, read_text, run_cmd


# ===========================================================================
# MÓDULO 2 · RED LOCAL
# ===========================================================================
KNOWN_DNS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google", "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS", "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
}


class RedModule(AuditModule):
    key = "red"
    title = "RED LOCAL"
    description = "Direccionamiento, DNS, perfil de red, seguridad Wi-Fi y detección de ARP spoofing"

    def checks(self):
        if IS_WINDOWS:
            return [self.check_addressing, self.check_dns, self.check_network_profile,
                    self.check_wifi, self.check_arp]
        if IS_LINUX:
            return [self.check_addressing, self.check_dns, self.check_wifi, self.check_arp]
        return [self.check_addressing]

    def check_addressing(self):
        """Direccionamiento IP y puerta de enlace"""
        ip, gateway = get_local_ip(), get_default_gateway()
        self.ctx.facts.update(local_ip=ip, gateway=gateway)
        if not ip:
            self.add(INFO, "No se detectó conectividad IPv4 con ruta por defecto")
            return
        detail = f"IP local: {ip} · Puerta de enlace: {gateway or 'desconocida'} · Equipo: {socket.gethostname()}"
        if not ipaddress.ip_address(ip).is_global:
            self.add(PASS, "El equipo usa direccionamiento privado (detrás de router/NAT)", detail)
        else:
            self.add(WARNING, f"El equipo tiene una IP pública asignada directamente ({ip})", detail,
                     "Sin NAT, cualquier servicio en escucha puede ser accesible desde Internet. "
                     "Asegura el firewall o sitúa el equipo detrás de un router.")

    def check_dns(self):
        """Servidores DNS configurados"""
        if IS_WINDOWS:
            data = powershell("Out-Json @(Get-DnsClientServerAddress -AddressFamily IPv4 | "
                              "ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)")
            servers = [s for s in as_list(data) if s]
        else:
            servers = re.findall(r"^\s*nameserver\s+(\S+)", read_text("/etc/resolv.conf") or "", re.M)
        if not servers:
            self.add(INFO, "No hay servidores DNS configurados")
            return
        described = []
        for server in servers:
            try:
                local = not ipaddress.ip_address(server).is_global
            except ValueError:
                local = False
            described.append(f"{server} ({KNOWN_DNS.get(server, 'red local' if local else 'ISP / no reconocido')})")
        self.add(INFO, f"Servidores DNS: {', '.join(servers)}",
                 "Clasificación: " + ", ".join(described) + "\nUn DNS desconocido que no hayas configurado "
                 "tú (ni tu ISP) puede indicar secuestro de DNS (DNS hijacking).")

    def check_network_profile(self):
        """Perfil de red de Windows (Público / Privado / Dominio)"""
        data = powershell("Out-Json @(Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, "
                          "@{n='Category';e={[string]$_.NetworkCategory}})")
        profiles = as_list(data)
        if not profiles:
            self.add(INFO, "No hay conexiones de red activas")
            return
        for p in profiles:
            name = f"{p.get('InterfaceAlias')} («{p.get('Name')}»)"
            category = p.get("Category")
            if category == "Public":
                self.add(PASS, f"Perfil de red Público en {name}",
                         "El perfil Público aplica las reglas de firewall más restrictivas.")
            elif category == "DomainAuthenticated":
                self.add(PASS, f"Perfil de red de Dominio en {name}")
            else:
                self.add(INFO, f"Perfil de red Privado en {name}",
                         "Correcto solo en redes de confianza (casa/oficina). En redes públicas "
                         "(hoteles, cafeterías) usa el perfil Público.")

    def check_wifi(self):
        """Seguridad de la conexión Wi-Fi"""
        if IS_WINDOWS:
            rc, out, err = run_cmd(["netsh", "wlan", "show", "interfaces"])
            if re.search(r"location|ubicaci", out + err, re.I) and "SSID" not in out:
                raise CheckSkipped("Windows exige permiso de ubicación para consultar la Wi-Fi "
                                   "(Configuración > Privacidad > Ubicación).")
            if rc != 0:
                raise CheckSkipped(first_line(out or err) or "Servicio WLAN no disponible")
            ssid = auth = cipher = None
            for line in out.splitlines():
                key, sep, value = line.partition(":")
                if not sep:
                    continue
                key, value = key.strip().lower(), value.strip()
                if key == "ssid" and ssid is None:
                    ssid = value
                elif re.match(r"authentication|autenticaci", key) and auth is None:
                    auth = value
                elif re.match(r"cipher|cifrado", key) and cipher is None:
                    cipher = value
            if not ssid:
                self.add(INFO, "No hay ninguna conexión Wi-Fi activa")
                return
            self._evaluate_wifi(ssid, auth, cipher)
        else:
            if not shutil.which("nmcli"):
                raise CheckSkipped("nmcli (NetworkManager) no disponible")
            _, out, _ = run_cmd(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"])
            for line in out.splitlines():
                cols = re.split(r"(?<!\\):", line)
                if len(cols) >= 3 and cols[0] == "yes":
                    self._evaluate_wifi(cols[1].replace("\\:", ":"), cols[2] or "Open", "")
                    return
            self.add(INFO, "No hay ninguna conexión Wi-Fi activa")

    def _evaluate_wifi(self, ssid: str, auth: Optional[str], cipher: Optional[str]):
        detail = f"SSID: {ssid} · Autenticación: {auth or '?'} · Cifrado: {cipher or '?'}"
        if auth is None:  # idioma no reconocido: no arriesgamos un falso positivo
            self.add(INFO, f"Conectado a la Wi-Fi «{ssid}» (no se pudo interpretar el tipo de seguridad)", detail)
            return
        sec = f"{auth} {cipher or ''}".upper()
        if "WEP" in sec:
            self.add(CRITICAL, f"Wi-Fi «{ssid}» con cifrado WEP (roto en minutos)", detail,
                     "Configura WPA2-AES o WPA3 en el punto de acceso.")
        elif re.search(r"OPEN|ABIERT|NONE|NINGUNO|^--", sec):
            self.add(CRITICAL, f"Conectado a una Wi-Fi ABIERTA sin cifrado («{ssid}»)", detail,
                     "El tráfico puede ser interceptado. Evita redes abiertas o usa una VPN.")
        elif "WPA3" in sec or "SAE" in sec:
            self.add(PASS, f"Wi-Fi «{ssid}» protegida con WPA3", detail)
        elif "WPA2" in sec and "TKIP" not in sec:
            self.add(PASS, f"Wi-Fi «{ssid}» protegida con WPA2", detail)
        else:
            self.add(WARNING, f"Wi-Fi «{ssid}» con seguridad obsoleta (WPA/TKIP)", detail,
                     "Usa WPA2-AES (CCMP) o, mejor, WPA3.")

    def check_arp(self):
        """Tabla ARP: detección de posible ARP spoofing"""
        entries: List[Tuple[str, str]] = []
        if IS_WINDOWS:
            _, out, _ = run_cmd(["arp", "-a"])
            for ip, mac in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out):
                entries.append((ip, mac.replace("-", ":").lower()))
        else:
            for line in (read_text("/proc/net/arp") or "").splitlines()[1:]:
                cols = line.split()
                if len(cols) >= 4:
                    entries.append((cols[0], cols[3].lower()))

        by_mac: Dict[str, set] = {}
        for ip, mac in entries:
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or int(mac[:2], 16) & 1:
                continue  # broadcast / multicast / incompleta
            addr = ipaddress.ip_address(ip)
            if addr.is_multicast or ip.endswith(".255"):
                continue
            by_mac.setdefault(mac, set()).add(ip)

        gateway = self.ctx.facts.get("gateway") or get_default_gateway()
        duplicates = {mac: ips for mac, ips in by_mac.items() if len(ips) > 1}
        if not duplicates:
            self.add(PASS, "Tabla ARP sin MACs duplicadas (sin indicios de ARP spoofing)",
                     f"{len(by_mac)} vecinos analizados.")
            return
        for mac, ips in duplicates.items():
            listing = ", ".join(sorted(ips, key=ipaddress.ip_address))
            if gateway in ips:
                self.add(CRITICAL, f"Posible ARP spoofing: la MAC del gateway ({mac}) responde también por otras IPs",
                         f"IPs con la misma MAC: {listing}",
                         "Comprueba la MAC real del router: un equipo de la LAN podría estar interceptando "
                         "tu tráfico (MITM). Los repetidores Wi-Fi con proxy ARP pueden dar falsos positivos.")
            else:
                self.add(WARNING, f"La MAC {mac} aparece asociada a varias IPs", f"IPs: {listing}",
                         "Puede ser legítimo (máquinas virtuales, repetidores) o indicar suplantación ARP.")
