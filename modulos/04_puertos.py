# -*- coding: utf-8 -*-
"""Plugin PUERTOS: sockets en escucha, servicios de riesgo expuestos y escaneo TCP opcional."""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ._base import IS_LINUX, IS_WINDOWS, CRITICAL, INFO, PASS, WARNING, AuditModule, CheckSkipped, CommandError, Severity, first_line
from ._utilidades import HAS_PSUTIL, get_default_gateway, get_local_ip, psutil, run_cmd


# ===========================================================================
# MÓDULO 4 · PUERTOS Y SERVICIOS DE RED
# ===========================================================================
@dataclass(frozen=True)
class PortRule:
    service: str
    severity: Severity
    reason: str
    protos: Tuple[str, ...] = ("TCP",)
    advice: str = ("Si no lo necesitas, detén y deshabilita el servicio. Si lo necesitas, limita el acceso "
                   "con el firewall a IPs de confianza o a través de VPN.")


_NETBIOS = ("NetBIOS sobre TCP/IP (nombres 137, datagramas 138, sesión 139): protocolo heredado que "
            "permite enumerar el equipo y sus recursos compartidos.")
_NETBIOS_ADVICE = ("Desactiva 'NetBIOS sobre TCP/IP' en las propiedades IPv4 > WINS de cada adaptador "
                   "si no usas equipos o recursos compartidos antiguos.")

# Puertos cuya exposición en red supone un riesgo (protocolos inseguros o muy atacados).
# Los puertos con el mismo 'service' se agrupan en un único hallazgo.
RISKY_PORTS: Dict[int, PortRule] = {
    21: PortRule("FTP", CRITICAL, "Protocolo sin cifrar: credenciales y datos viajan en texto plano."),
    23: PortRule("Telnet", CRITICAL, "Acceso remoto sin cifrar.", advice="Sustitúyelo por SSH."),
    69: PortRule("TFTP", CRITICAL, "Transferencia de ficheros sin autenticación.", ("UDP",)),
    80: PortRule("HTTP", WARNING, "Servicio web sin cifrar."),
    111: PortRule("RPCbind", WARNING, "Portmapper RPC; permite enumerar servicios RPC/NFS.", ("TCP", "UDP")),
    135: PortRule("MS-RPC", WARNING, "Endpoint mapper de RPC; vector habitual de movimiento lateral."),
    137: PortRule("NetBIOS", WARNING, _NETBIOS, ("UDP",), _NETBIOS_ADVICE),
    138: PortRule("NetBIOS", WARNING, _NETBIOS, ("UDP",), _NETBIOS_ADVICE),
    139: PortRule("NetBIOS", WARNING, _NETBIOS, ("TCP",), _NETBIOS_ADVICE),
    161: PortRule("SNMP", WARNING, "SNMP v1/v2c usa 'community strings' en texto plano.", ("UDP",)),
    445: PortRule("SMB", WARNING, "Compartición de ficheros, históricamente explotada (EternalBlue/WannaCry).",
                  advice="Bloquéalo en perfiles públicos, exige firma SMB y desactiva SMBv1."),
    512: PortRule("rexec", CRITICAL, "Ejecución remota heredada sin cifrado."),
    513: PortRule("rlogin", CRITICAL, "Login remoto heredado sin cifrado."),
    514: PortRule("rsh", CRITICAL, "Shell remota heredada sin cifrado."),
    873: PortRule("rsync", WARNING, "Módulos rsync a menudo accesibles sin autenticación."),
    1433: PortRule("MS SQL Server", WARNING, "Base de datos expuesta en la red."),
    1723: PortRule("PPTP", WARNING, "VPN con cifrado roto (MS-CHAPv2)."),
    1883: PortRule("MQTT", WARNING, "Broker IoT habitualmente sin autenticación ni TLS."),
    1900: PortRule("SSDP/UPnP", WARNING, "Descubrimiento UPnP; amplía la superficie de ataque en la LAN.", ("UDP",)),
    2049: PortRule("NFS", WARNING, "Recursos NFS compartidos en red."),
    2375: PortRule("Docker API sin TLS", CRITICAL, "Control total del host sin autenticación."),
    3306: PortRule("MySQL/MariaDB", WARNING, "Base de datos expuesta en la red."),
    3389: PortRule("RDP", WARNING, "Escritorio remoto: objetivo prioritario de fuerza bruta y ransomware.",
                   advice="No lo expongas a Internet: usa VPN, NLA, MFA y bloqueo de cuentas."),
    5432: PortRule("PostgreSQL", WARNING, "Base de datos expuesta en la red."),
    5900: PortRule("VNC", CRITICAL, "Escritorio remoto a menudo sin cifrado ni autenticación robusta."),
    5985: PortRule("WinRM (HTTP)", WARNING, "Administración remota de Windows."),
    5986: PortRule("WinRM (HTTPS)", WARNING, "Administración remota de Windows."),
    6379: PortRule("Redis", CRITICAL, "Sin autenticación por defecto; permite ejecución remota de código."),
    7547: PortRule("TR-069", WARNING, "Gestión remota del ISP en routers; históricamente explotada (Mirai)."),
    8080: PortRule("HTTP alternativo", WARNING, "Servicio web/proxy sin cifrar."),
    9200: PortRule("Elasticsearch", CRITICAL, "API sin autenticación por defecto: fuga de datos."),
    11211: PortRule("Memcached", CRITICAL, "Sin autenticación; usado en ataques DDoS de amplificación.",
                    ("TCP", "UDP")),
    27017: PortRule("MongoDB", CRITICAL, "Instancias sin autenticación, fuente habitual de fugas de datos."),
}

COMMON_SERVICES = {22: "SSH", 25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
                   554: "RTSP", 587: "SMTP-Submission", 631: "IPP", 993: "IMAPS", 995: "POP3S",
                   5000: "UPnP/HTTP", 8000: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt", 9100: "JetDirect"}

SCAN_PORTS = sorted({p for p, r in RISKY_PORTS.items() if "TCP" in r.protos} | set(COMMON_SERVICES))


@dataclass(frozen=True)
class ListeningSocket:
    proto: str
    ip: str
    port: int
    pid: Optional[int]
    process: str

    @property
    def exposed(self) -> bool:
        """True si escucha en una interfaz accesible desde la red (no solo loopback)."""
        return not (self.ip.startswith("127.") or self.ip in ("::1", "localhost"))


def fmt_endpoint(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _split_hostport(value: str) -> Tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host.strip("[]").split("%")[0], int(port)


def _sockets_psutil() -> List[ListeningSocket]:
    names: Dict[Optional[int], str] = {}

    def process_name(pid: Optional[int]) -> str:
        if pid is None:
            return "?"
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                names[pid] = "?"
        return names[pid]

    result = set()
    for conn in psutil.net_connections(kind="inet"):
        if not conn.laddr:
            continue
        if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
            proto = "TCP"
        elif conn.type == socket.SOCK_DGRAM and not conn.raddr:
            proto = "UDP"
        else:
            continue
        result.add(ListeningSocket(proto, conn.laddr.ip, conn.laddr.port, conn.pid, process_name(conn.pid)))
    return list(result)


def _sockets_netstat() -> List[ListeningSocket]:
    """Alternativa Windows sin psutil: netstat -ano (independiente del idioma)."""
    rc, out, err = run_cmd(["netstat", "-ano"])
    if rc != 0:
        raise CommandError(first_line(err) or "netstat falló")
    _, tasks, _ = run_cmd(["tasklist", "/FO", "CSV", "/NH"])
    names = {int(row[1]): row[0] for row in csv.reader(io.StringIO(tasks)) if len(row) > 1 and row[1].isdigit()}
    result = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 4 or cols[0] not in ("TCP", "UDP"):
            continue
        if cols[0] == "TCP":
            # Un socket TCP en escucha tiene como dirección remota 0.0.0.0:0 o [::]:0
            if len(cols) < 5 or not re.fullmatch(r"(0\.0\.0\.0|\[::\]):0", cols[2]):
                continue
            pid = cols[4]
        else:
            if cols[2] != "*:*":
                continue
            pid = cols[3]
        try:
            ip, port = _split_hostport(cols[1])
        except ValueError:
            continue
        pid_num = int(pid) if pid.isdigit() else None
        result.add(ListeningSocket(cols[0], ip, port, pid_num, names.get(pid_num, "?")))
    return list(result)


def _sockets_ss() -> List[ListeningSocket]:
    """Alternativa Linux sin psutil: ss -tulnp."""
    rc, out, err = run_cmd(["ss", "-tulnp"])
    if rc != 0:
        raise CommandError(first_line(err) or "ss falló")
    result = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0] not in ("tcp", "udp"):
            continue
        if cols[0] == "tcp" and cols[1] != "LISTEN":
            continue
        try:
            ip, port = _split_hostport(cols[4])
        except ValueError:
            continue
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        result.add(ListeningSocket(cols[0].upper(), ip if ip != "*" else "0.0.0.0", port,
                                   int(m.group(2)) if m else None, m.group(1) if m else "?"))
    return list(result)


def get_listening_sockets() -> List[ListeningSocket]:
    sockets = None
    if HAS_PSUTIL:
        try:
            sockets = _sockets_psutil()
        except (psutil.AccessDenied, PermissionError):
            sockets = None  # p. ej. macOS sin root -> probamos la alternativa
    if sockets is None:
        if IS_WINDOWS:
            sockets = _sockets_netstat()
        elif IS_LINUX:
            sockets = _sockets_ss()
        else:
            raise CheckSkipped("Instala psutil para enumerar puertos en este sistema (pip install psutil)")
    return sorted(sockets, key=lambda s: (s.port, s.proto, s.ip))


def resolve_scan_target(value: str) -> str:
    """Traduce 'gateway' / 'local' / IP / nombre a una IP y exige que sea privada."""
    v = value.strip().lower()
    if v in ("gateway", "router"):
        ip = get_default_gateway()
        if not ip:
            raise CheckSkipped("No se pudo determinar la puerta de enlace")
    elif v in ("local", "self", "localhost"):
        ip = get_local_ip() or "127.0.0.1"
    else:
        try:
            ip = socket.gethostbyname(value)
        except OSError:
            raise CheckSkipped(f"No se pudo resolver el objetivo '{value}'")
    if ipaddress.ip_address(ip).is_global:
        raise CheckSkipped(f"{ip} es una IP pública. Por seguridad, la herramienta solo escanea "
                           "direcciones privadas/locales de tu propia red.")
    return ip


def tcp_connect_scan(ip: str, ports: List[int], timeout: float, workers: int = 64) -> List[int]:
    """Escaneo TCP connect() concurrente: solo intenta abrir y cerrar la conexión."""
    def probe(port: int) -> Optional[int]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return port if s.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return sorted(p for p in pool.map(probe, ports) if p)


class PuertosModule(AuditModule):
    key = "puertos"
    title = "PUERTOS Y SERVICIOS DE RED"
    description = "Sockets en escucha, servicios de riesgo expuestos y escaneo TCP opcional"

    def checks(self):
        return [self.check_listening, self.check_scan]

    def check_listening(self):
        """Puertos en escucha en este equipo"""
        sockets = get_listening_sockets()
        exposed = [s for s in sockets if s.exposed]
        self.ctx.facts["exposed_ports"] = {s.port for s in exposed}
        self.add(INFO, f"{len(sockets)} sockets en escucha: {len(exposed)} accesibles desde la red, "
                       f"{len(sockets) - len(exposed)} solo locales",
                 "" if HAS_PSUTIL else "Fuente: netstat/ss (instala psutil para mayor precisión).")

        # 1) Servicios de riesgo escuchando en interfaces de red, agrupados por servicio
        risky: Dict[str, List[ListeningSocket]] = {}
        for s in exposed:
            rule = RISKY_PORTS.get(s.port)
            if rule and s.proto in rule.protos:
                risky.setdefault(rule.service, []).append(s)
        for service, socks in sorted(risky.items(), key=lambda item: min(s.port for s in item[1])):
            ports = sorted({s.port for s in socks})
            rule = RISKY_PORTS[ports[0]]
            endpoints = sorted({f"{s.proto} {fmt_endpoint(s.ip, s.port)}" for s in socks})
            binds = ", ".join(endpoints[:8]) + (f" y {len(endpoints) - 8} más" if len(endpoints) > 8 else "")
            procs = ", ".join(sorted({f"{s.process} (PID {s.pid})" if s.pid else s.process for s in socks}))
            label = (f"Puerto {ports[0]} ({service}) expuesto" if len(ports) == 1
                     else f"Puertos {', '.join(map(str, ports))} ({service}) expuestos")
            self.add(rule.severity, f"{label} en la red",
                     f"{rule.reason}\nEscuchando en: {binds}\nProceso: {procs}", rule.advice,
                     key=f"escucha:{service}")
        if not risky:
            self.add(PASS, "Ningún servicio de la lista de riesgo escucha en interfaces de red")

        # 2) Servicios sensibles limitados a localhost: correcto
        local_risky = sorted({s.port for s in sockets if not s.exposed and s.port in RISKY_PORTS
                              and s.proto in RISKY_PORTS[s.port].protos})
        if local_risky:
            self.add(PASS, "Servicios sensibles limitados a localhost: " +
                     ", ".join(f"{p} ({RISKY_PORTS[p].service})" for p in local_risky),
                     "No son accesibles desde otros equipos de la red.")

        # 3) Resto de puertos TCP expuestos (informativo)
        risky_ports = {s.port for socks in risky.values() for s in socks}
        others = sorted({(s.port, s.process) for s in exposed if s.proto == "TCP" and s.port not in risky_ports})
        static = [f"{p} ({name})" for p, name in others if p < 49152]
        dynamic = {p for p, _ in others if p >= 49152}
        if static or dynamic:
            text = ", ".join(static) if static else "ninguno"
            if dynamic:
                text += f" + {len(dynamic)} puertos dinámicos (≥49152, normalmente RPC)"
            udp = len({s.port for s in exposed if s.proto == "UDP"})
            self.add(INFO, "Otros puertos TCP expuestos", f"{text}\nSockets UDP expuestos: {udp}. "
                     "Revisa que cada servicio sea necesario.")

    def check_scan(self):
        """Escaneo TCP activo de puertos comunes"""
        target = self.ctx.args.escanear
        if not target:
            self.add(INFO, "Escaneo activo desactivado",
                     "Usa --escanear gateway | local | <IP privada> para comprobar qué puertos responden.")
            return
        ip = resolve_scan_target(target)
        started = time.time()
        open_ports = tcp_connect_scan(ip, SCAN_PORTS, self.ctx.args.timeout)
        note = f"{len(SCAN_PORTS)} puertos TCP analizados en {time.time() - started:.1f} s."
        if not open_ports:
            self.add(PASS, f"Escaneo de {ip}: ningún puerto común responde", note)
            return
        names = [f"{p} ({RISKY_PORTS[p].service if p in RISKY_PORTS else COMMON_SERVICES.get(p, '?')})"
                 for p in open_ports]

        if ip.startswith("127.") or ip == (self.ctx.facts.get("local_ip") or get_local_ip()):
            # Escanear el propio equipo repite lo que ya muestra la lista de puertos en escucha
            self.add(INFO, f"Escaneo de {ip} (este equipo): {len(open_ports)} puertos abiertos",
                     f"{', '.join(names)}\n{note} El tráfico local no atraviesa el firewall: para medir "
                     "la exposición real, ejecuta el escaneo desde otro equipo de la red.")
            return

        self.add(INFO, f"Escaneo de {ip}: {len(open_ports)} puertos abiertos", f"{', '.join(names)}\n{note}")
        for port in open_ports:
            rule = RISKY_PORTS.get(port)
            if rule:
                self.add(rule.severity, f"{ip}: puerto {port} ({rule.service}) ABIERTO", rule.reason, rule.advice,
                         key=f"escaneo:{ip}:{port}")
