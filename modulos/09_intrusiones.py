# -*- coding: utf-8 -*-
"""Plugin INTRUSIONES: log de Seguridad (7 días): fuerza bruta, bloqueos y borrado del log."""

from __future__ import annotations

import ipaddress
from typing import Optional

from ._base import ADMIN_NAME, IS_WINDOWS, CRITICAL, INFO, PASS, SKIP, WARNING, AuditModule, CheckSkipped, CommandError
from ._utilidades import as_list, get_local_ip, powershell


# ===========================================================================
# MÓDULO 9 · DETECCIÓN DE INTRUSIONES (Registro de Seguridad de Windows)
# ===========================================================================
# Consulta los eventos 4625, 4740 y 1102 de los últimos __DAYS__ días y los
# devuelve ya agrupados en JSON. Con -FilterHashtable, un acceso denegado se
# disfraza de "No events were found", por eso antes se comprueba el acceso al
# log con -LogName.
_INTRUSION_EVENTS_SCRIPT = r"""
$since = (Get-Date).AddDays(-__DAYS__)
$r = @{ denied = $false }
try { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null; $ok = $true }
catch {
    $ok = $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'
    if ($_.Exception -is [System.UnauthorizedAccessException]) { $r.denied = $true }
    elseif (-not $ok) { $r.error = [string]$_.Exception.Message }
}
function Get-SecEv([int]$Id, [int]$Max) {
    try { return ,@(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Id; StartTime = $since } -MaxEvents $Max -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return ,@() }; throw }
}
if ($ok) {
    # 4625: IpAddress = Properties[19], TargetUserName = [5], LogonType = [10]
    $failed = Get-SecEv 4625 __MAX__
    $r.failed_total = $failed.Count
    $r.failed = @($failed | Group-Object { [string]$_.Properties[19].Value } | ForEach-Object {
        @{
            ip    = $_.Name
            n     = $_.Count
            users = @($_.Group | ForEach-Object { [string]$_.Properties[5].Value } | Sort-Object -Unique | Select-Object -First 5)
            types = @($_.Group | ForEach-Object { [string]$_.Properties[10].Value } | Sort-Object -Unique)
        }
    })
    # 4740: TargetUserName = Properties[0], equipo que originó el bloqueo = [1]
    $locked = Get-SecEv 4740 200
    $r.lockouts = @($locked | ForEach-Object {
        @{ user = [string]$_.Properties[0].Value; source = [string]$_.Properties[1].Value; time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }
    })
    # 1102: los datos van en UserData/LogFileCleared, no en EventData
    $cleared = Get-SecEv 1102 50
    $r.cleared = @($cleared | ForEach-Object {
        $x = ([xml]$_.ToXml()).Event.UserData.LogFileCleared
        @{ by = "$($x.SubjectDomainName)\$($x.SubjectUserName)"; time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }
    })
}
Out-Json $r
"""

LOGON_TYPES = {"2": "interactivo", "3": "red (SMB/NTLM)", "7": "desbloqueo", "8": "red en texto claro",
               "10": "RDP", "11": "credenciales en caché"}


class IntrusionesModule(AuditModule):
    key = "intrusiones"
    title = "DETECCIÓN DE INTRUSIONES"
    description = "Registro de Seguridad de Windows (7 días): fuerza bruta, bloqueos de cuenta y borrado de logs"

    DAYS = 7
    MAX_FAILED = 10000        # tope de eventos 4625 a leer (protege ante logs enormes)
    EXTERNAL_THRESHOLD = 5    # intentos desde IPs externas a partir de los cuales se considera ataque
    SEVERITY_CODE = {PASS: 0, INFO: 0, SKIP: 0, WARNING: 1, CRITICAL: 2}

    def checks(self):
        return [self.check_security_log] if IS_WINDOWS else []

    def add(self, severity, title, detail="", recommendation="", **kwargs):
        """Igual que AuditModule.add, pero recuerda la peor severidad emitida (0/1/2)."""
        self.worst = max(getattr(self, "worst", 0), self.SEVERITY_CODE[severity])
        super().add(severity, title, detail, recommendation, **kwargs)

    def check_security_log(self) -> int:
        """Registro de Seguridad de Windows (eventos 4625, 4740 y 1102)

        Devuelve 0 (sin hallazgos / omitido), 1 (WARNING) o 2 (CRITICAL).
        """
        self.worst = 0
        label = "Registro de Seguridad de Windows"
        script = (_INTRUSION_EVENTS_SCRIPT.replace("__DAYS__", str(self.DAYS))
                  .replace("__MAX__", str(self.MAX_FAILED)))
        try:
            data = powershell(script, timeout=180) or {}
        except (CommandError, CheckSkipped) as exc:
            self.add(SKIP, label, f"No se pudo consultar: {exc}")
            return 0
        if data.get("denied"):
            self.add(SKIP, label, f"Acceso denegado: leer el log de Seguridad requiere privilegios de "
                                  f"{ADMIN_NAME}. Vuelve a ejecutar el script elevado.")
            return 0
        if data.get("error"):
            self.add(SKIP, label, f"No se pudo consultar: {data['error']}")
            return 0

        self._evaluate_failed(data)
        self._evaluate_lockouts(as_list(data.get("lockouts")))
        self._evaluate_cleared(as_list(data.get("cleared")))
        return self.worst

    @staticmethod
    def _origin(ip: str, own_ip: Optional[str]) -> str:
        """Clasifica el origen de un intento: 'local' (este equipo), 'lan' (red privada) o 'internet'."""
        if ip in ("", "-") or ip == own_ip:
            return "local"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "local"
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if addr.is_loopback:
            return "local"
        return "internet" if addr.is_global else "lan"

    def _evaluate_failed(self, data: dict) -> None:
        """4625: separa los intentos locales de los que llegan desde otras IPs."""
        total = int(data.get("failed_total") or 0)
        if not total:
            self.add(PASS, f"Sin inicios de sesión fallidos en los últimos {self.DAYS} días", key="4625-externos")
            return

        own_ip = self.ctx.facts.get("local_ip") or get_local_ip()
        local, external = [], []
        for group in as_list(data.get("failed")):
            origin = self._origin(str(group.get("ip") or ""), own_ip)
            (local if origin == "local" else external).append((origin, group))

        def describe(origin: str, group: dict) -> str:
            where = {"internet": "Internet", "lan": "LAN", "local": "este equipo"}[origin]
            users = ", ".join(u for u in as_list(group.get("users")) if u) or "-"
            types = ", ".join(LOGON_TYPES.get(t, t) for t in as_list(group.get("types")) if t) or "?"
            ip = group.get("ip") if group.get("ip") not in (None, "", "-") else "sin IP (consola/servicio)"
            return f"{ip} [{where}]: {group['n']} intentos · cuentas: {users} · tipo: {types}"

        capped = " (límite de lectura alcanzado)" if total >= self.MAX_FAILED else ""
        if external:
            external.sort(key=lambda item: -int(item[1]["n"]))
            ext_total = sum(int(g["n"]) for _, g in external)
            public = sum(1 for origin, _ in external if origin == "internet")
            detail = "\n".join(describe(o, g) for o, g in external[:8])
            if ext_total >= self.EXTERNAL_THRESHOLD:
                self.add(CRITICAL, f"{ext_total} inicios de sesión fallidos desde {len(external)} IP(s) externa(s), "
                                   f"{public} de Internet: posible fuerza bruta{capped}", detail,
                         "Bloquea esas IPs en el firewall, no expongas RDP/SMB a Internet (usa VPN) y comprueba "
                         "que no haya un inicio de sesión correcto posterior (evento 4624) desde ellas.",
                         key="4625-externos", metric=ext_total)
            else:
                self.add(WARNING, f"{ext_total} inicio(s) de sesión fallido(s) aislado(s) desde la red", detail,
                         "Comprueba si corresponden a equipos o usuarios conocidos de tu red.",
                         key="4625-externos", metric=ext_total)
        else:
            self.add(PASS, f"Sin inicios de sesión fallidos desde otras IPs en {self.DAYS} días", key="4625-externos")

        local_total = sum(int(g["n"]) for _, g in local)
        if local_total:
            self.add(WARNING, f"{local_total} inicio(s) de sesión fallido(s) locales en {self.DAYS} días{capped}",
                     "\n".join(describe(o, g) for o, g in local),
                     "Suelen ser contraseñas mal tecleadas; si no los reconoces, alguien pudo intentar "
                     "acceder físicamente al equipo.", key="4625-locales", metric=local_total)

    def _evaluate_lockouts(self, items: list) -> None:
        """4740: cualquier bloqueo de cuenta es CRITICAL."""
        if not items:
            self.add(PASS, f"Sin bloqueos de cuenta en los últimos {self.DAYS} días", key="4740")
            return
        self.add(CRITICAL, f"{len(items)} bloqueo(s) de cuenta en los últimos {self.DAYS} días",
                 "\n".join(f"{i['time']} · cuenta: {i['user']} · origen: {i['source'] or '?'}" for i in items[:10]),
                 "Un bloqueo significa que se superó el umbral de intentos fallidos: identifica el equipo de "
                 "origen y cambia la contraseña de la cuenta si el intento no fue legítimo.",
                 key="4740", metric=len(items))

    def _evaluate_cleared(self, items: list) -> None:
        """1102: el borrado del log de auditoría es CRITICAL."""
        if not items:
            self.add(PASS, f"El registro de auditoría no se ha borrado en los últimos {self.DAYS} días", key="1102")
            return
        self.add(CRITICAL, f"Registro de auditoría BORRADO {len(items)} vez/veces (evento 1102)",
                 "\n".join(f"{i['time']} · por {i['by']}" for i in items),
                 "Borrar el log de Seguridad es una técnica anti-forense habitual (MITRE ATT&CK T1070.001). "
                 "Si no fue una tarea administrativa conocida, trata el equipo como comprometido.",
                 key="1102", metric=len(items))
