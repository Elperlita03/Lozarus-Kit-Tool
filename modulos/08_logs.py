# -*- coding: utf-8 -*-
"""Plugin LOGS: borrado del log System, persistencia, malware y registro de PowerShell."""

from __future__ import annotations

import os
import re
import shutil
from typing import Any, Dict, Tuple

from ._base import ADMIN_NAME, IS_LINUX, IS_WINDOWS, CRITICAL, PASS, SKIP, WARNING, AuditModule, CheckSkipped, first_line
from ._utilidades import as_list, powershell, reg_get, run_cmd, tail_text


# ===========================================================================
# MÓDULO 8 · ANÁLISIS DE LOGS
# ===========================================================================
# Un único script PowerShell consulta todos los eventos y devuelve un JSON con
# el resultado de cada consulta, indicando si hubo acceso denegado.
_WINDOWS_EVENTS_SCRIPT = r"""
$now = Get-Date
$out = @{}
$access = @{}
# Con -FilterHashtable, un acceso denegado se disfraza de "No events were found":
# por eso se comprueba antes el acceso a cada log con -LogName.
function Test-Log([string]$Log) {
    if (-not $access.ContainsKey($Log)) {
        try { Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction Stop | Out-Null; $access[$Log] = 'ok' }
        catch {
            if ($_.Exception -is [System.UnauthorizedAccessException]) { $access[$Log] = 'ACCESS_DENIED' }
            elseif ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $access[$Log] = 'ok' }
            else { $access[$Log] = [string]$_.Exception.Message }
        }
    }
    if ($access[$Log] -ne 'ok') { throw $access[$Log] }
}
function Get-Ev([hashtable]$Filter, [int]$Max) {
    Test-Log $Filter.LogName
    try { return ,@(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return ,@() }
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.FullyQualifiedErrorId -like '*Unauthorized*') { throw 'ACCESS_DENIED' }
        throw $_.Exception.Message
    }
}
function Field($Ev, [string]$Name) {
    $node = ([xml]$Ev.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($node) { [string]$node.'#text' } else { '' }
}
function Stamp($Ev) { $Ev.TimeCreated.ToString('yyyy-MM-dd HH:mm') }
function Run-Query([string]$Name, [scriptblock]$Body) {
    try {
        $d = & $Body
        if ($null -eq $d) { $d = $null }  # AutomationNull se serializaría como {}
        $out[$Name] = @{ ok = $true; data = $d }
    }
    catch {
        $msg = [string]$_.Exception.Message
        if ($msg -eq 'ACCESS_DENIED') { $out[$Name] = @{ ok = $false; denied = $true } }
        else { $out[$Name] = @{ ok = $false; error = $msg } }
    }
}

# Los eventos 4625, 4740 y 1102 (log de Seguridad) los analiza el módulo 'intrusiones'
Run-Query 'cleared_system' {
    $ev = Get-Ev @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $now.AddDays(-30) } 20
    @(foreach ($e in $ev) { Stamp $e })
}
Run-Query 'users_created' {
    $ev = Get-Ev @{ LogName = 'Security'; Id = 4720; StartTime = $now.AddDays(-7) } 50
    @(foreach ($e in $ev) { @{ user = (Field $e 'TargetUserName'); by = (Field $e 'SubjectUserName'); time = (Stamp $e) } })
}
Run-Query 'admins_added' {
    $ev = Get-Ev @{ LogName = 'Security'; Id = 4732; StartTime = $now.AddDays(-7) } 100
    @(foreach ($e in $ev) {
        if ((Field $e 'TargetSid') -eq 'S-1-5-32-544') {
            $sid = Field $e 'MemberSid'
            try { $member = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value }
            catch { $member = $sid }
            @{ member = $member; by = (Field $e 'SubjectUserName'); time = (Stamp $e) }
        }
    })
}
Run-Query 'new_services' {
    $ev = Get-Ev @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7045; StartTime = $now.AddDays(-7) } 50
    @(foreach ($e in $ev) { @{ name = (Field $e 'ServiceName'); path = (Field $e 'ImagePath'); time = (Stamp $e) } })
}
Run-Query 'defender' {
    $ev = Get-Ev @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117; StartTime = $now.AddDays(-7) } 50
    @(foreach ($e in $ev) { @{ threat = (Field $e 'Threat Name'); path = (Field $e 'Path'); action = (Field $e 'Action Name'); time = (Stamp $e) } })
}
Out-Json $out
"""


class LogsModule(AuditModule):
    key = "logs"
    title = "ANÁLISIS DE LOGS"
    description = "Eventos recientes: borrado del log System, persistencia, malware y registro de PowerShell"

    def checks(self):
        if IS_WINDOWS:
            return [self.check_windows_events, self.check_powershell_logging]
        if IS_LINUX:
            return [self.check_auth_log]
        return []

    # ---------------------------- Windows -----------------------------------
    def _entry(self, data: dict, key: str, label: str) -> Tuple[bool, Any]:
        """Extrae el resultado de una consulta; si falló, registra un SKIP con el motivo."""
        entry = (data or {}).get(key) or {}
        if entry.get("ok"):
            return True, entry.get("data")
        if entry.get("denied"):
            self.add(SKIP, label, f"Acceso denegado al registro de eventos: requiere {ADMIN_NAME}.")
        else:
            self.add(SKIP, label, f"No se pudo consultar: {entry.get('error', 'sin datos')}")
        return False, None

    def check_windows_events(self):
        """Registro de eventos de Windows"""
        data = powershell(_WINDOWS_EVENTS_SCRIPT, timeout=180)
        # Fuerza bruta (4625), bloqueos (4740) y borrado del log de Seguridad (1102):
        # ver IntrusionesModule. Aquí solo queda el borrado del log System (104).

        # --- Borrado del registro System (104): técnica anti-forense ---
        ok, d = self._entry(data, "cleared_system", "Borrado del registro System (30 días)")
        if ok:
            cleared = as_list(d)
            if cleared:
                self.add(CRITICAL, f"Registro System BORRADO {len(cleared)} vez/veces en 30 días",
                         "Fechas: " + ", ".join(sorted(cleared)),
                         "Si no fue una acción administrativa conocida, puede indicar que un atacante ocultó su rastro.",
                         metric=len(cleared))
            else:
                self.add(PASS, "El registro System no se ha borrado en los últimos 30 días")

        # --- Persistencia: cuentas creadas, altas en Administradores, servicios nuevos ---
        ok, d = self._entry(data, "users_created", "Cuentas de usuario creadas (7 días)")
        if ok:
            items = as_list(d)
            if items:
                self.add(WARNING, f"{len(items)} cuenta(s) de usuario creada(s) en los últimos 7 días",
                         "\n".join(f"{i['time']} · {i['user']} (creada por {i['by']})" for i in items),
                         "Confirma que cada alta es legítima.", metric=len(items))
            else:
                self.add(PASS, "No se han creado cuentas de usuario en los últimos 7 días")

        ok, d = self._entry(data, "admins_added", "Altas en el grupo Administradores (7 días)")
        if ok:
            items = as_list(d)
            if items:
                self.add(WARNING, f"{len(items)} alta(s) en el grupo Administradores en los últimos 7 días",
                         "\n".join(f"{i['time']} · {i['member']} (por {i['by']})" for i in items),
                         "Confirma que cada elevación de privilegios es legítima.", metric=len(items))
            else:
                self.add(PASS, "Sin altas en el grupo Administradores en los últimos 7 días")

        ok, d = self._entry(data, "new_services", "Servicios instalados (7 días)")
        if ok:
            items = as_list(d)
            if items:
                self.add(WARNING, f"{len(items)} servicio(s) instalado(s) en los últimos 7 días",
                         "\n".join(f"{i['time']} · {i['name']}: {i['path']}" for i in items[:10]),
                         "Los servicios son un mecanismo de persistencia habitual: verifica los que no reconozcas.",
                         metric=len(items))
            else:
                self.add(PASS, "No se han instalado servicios nuevos en los últimos 7 días")

        # --- Detecciones de malware de Defender (1116/1117) ---
        ok, d = self._entry(data, "defender", "Detecciones de Microsoft Defender (7 días)")
        if ok:
            items = as_list(d)
            if items:
                self.add(CRITICAL, f"{len(items)} detección(es) de malware en los últimos 7 días",
                         "\n".join(f"{i['time']} · {i['threat']} · {i['action'] or 'detectado'} · {i['path']}"
                                   for i in items[:10]),
                         "Revisa el historial de protección en Seguridad de Windows y ejecuta un examen completo.",
                         metric=len(items))
            else:
                self.add(PASS, "Sin detecciones de malware en los últimos 7 días")

    def check_powershell_logging(self):
        """Registro de bloques de script de PowerShell"""
        value = reg_get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                        "EnableScriptBlockLogging")
        if value == 1:
            self.add(PASS, "Registro de bloques de script de PowerShell habilitado")
        else:
            self.add(WARNING, "Registro de bloques de script de PowerShell deshabilitado",
                     "Dificulta detectar y analizar ataques basados en PowerShell (malware sin fichero).",
                     "Habilítalo por GPO: Plantillas administrativas > Componentes de Windows > "
                     "Windows PowerShell > Activar el registro de bloques de script.")

    # ----------------------------- Linux ------------------------------------
    def check_auth_log(self):
        """Intentos de autenticación (auth.log / secure / journal)"""
        text, source = None, ""
        path = next((p for p in ("/var/log/auth.log", "/var/log/secure") if os.path.exists(p)), None)
        if path:
            try:
                text, source = tail_text(path, 5 * 1024 * 1024), path
            except PermissionError:
                pass
        if text is None and shutil.which("journalctl"):
            rc, out, _ = run_cmd(["journalctl", "-q", "--no-pager", "--since", "24 hours ago",
                                  "-u", "ssh", "-u", "sshd"], timeout=60)
            if rc == 0:
                text, source = out, "journalctl (24 h)"
        if text is None:
            raise CheckSkipped(f"No se pudo leer auth.log/secure ni el journal: requiere {ADMIN_NAME} o el grupo 'adm'")

        failed = [l for l in text.splitlines() if "Failed password" in l or "Invalid user" in l]
        ips: Dict[str, int] = {}
        for line in failed:
            m = re.search(r"from (\S+)", line)
            if m:
                ips[m.group(1)] = ips.get(m.group(1), 0) + 1
        top = ", ".join(f"{ip} ({n})" for ip, n in sorted(ips.items(), key=lambda x: -x[1])[:5]) or "-"
        detail = f"Fuente: {source}\nIPs de origen: {top}"
        if len(failed) >= 50:
            self.add(CRITICAL, f"{len(failed)} intentos de autenticación fallidos: posible fuerza bruta", detail,
                     "Instala fail2ban, desactiva el login por contraseña en SSH y limita el acceso por firewall.",
                     key="auth-fallidos", metric=len(failed))
        elif failed:
            self.add(WARNING, f"{len(failed)} intentos de autenticación fallidos", detail,
                     "Revisa su origen y considera fail2ban.", key="auth-fallidos", metric=len(failed))
        else:
            self.add(PASS, "Sin intentos de autenticación fallidos", f"Fuente: {source}")

        root_logins = [l for l in text.splitlines() if re.search(r"Accepted \S+ for root from", l)]
        if root_logins:
            self.add(WARNING, f"{len(root_logins)} inicio(s) de sesión de root por SSH", first_line(root_logins[-1]),
                     "Desactiva el acceso directo de root (PermitRootLogin no).")
