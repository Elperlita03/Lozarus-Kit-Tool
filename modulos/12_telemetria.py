# -*- coding: utf-8 -*-
"""
Plugin TELEMETRÍA E INTEGRIDAD: estado de los servicios de telemetría y detección de
manipulaciones de Microsoft Defender (SOLO LECTURA).

Comprueba, sin modificar nada:
  · Servicios de telemetría y mantenimiento: DiagTrack (telemetría), wuauserv (Windows Update)
    y SysMain (SuperFetch). Informa de su estado y tipo de inicio. OJO: desactivar wuauserv
    deja el equipo sin parches de seguridad, así que avisa de ello en la recomendación.
  · Exclusiones de Microsoft Defender (Get-MpPreference y, si se puede, el registro). Las
    exclusiones de carpetas grabables (AppData, Temp, Descargas), de la raíz de una unidad o
    del perfil de usuario completo son un truco clásico del malware para que Defender no mire
    donde se esconde: se marcan como CRITICAL.
  · Manipulación de Defender: protección en tiempo real desactivada y protección contra
    alteraciones (Tamper Protection) apagada.

Sin privilegios de Administrador muchos cmdlets Get-Mp* no responden: en ese caso la
comprobación se marca como [SKIP] con un mensaje claro, nunca como error.
"""

from __future__ import annotations

import os
import re
from typing import List, Tuple

from ._base import (CRITICAL, INFO, IS_WINDOWS, PASS, WARNING, AuditModule, CheckSkipped,
                    CommandError)
from ._utilidades import as_list, powershell, writable_location

if IS_WINDOWS:
    import winreg

WINDIR = os.environ.get("SystemRoot", r"C:\Windows")

# Servicios vigilados: nombre -> (nombre legible, descripción de qué hace)
TELEMETRY_SERVICES = {
    "DiagTrack": ("Experiencias del usuario conectado y telemetría (DiagTrack)",
                  "Recopila datos de diagnóstico y telemetría del equipo y los envía a Microsoft."),
    "wuauserv": ("Windows Update (wuauserv)",
                 "Descarga e instala las actualizaciones y parches de seguridad del sistema."),
    "SysMain": ("SysMain / SuperFetch",
                "Precarga en memoria las aplicaciones de uso frecuente para acelerar su arranque."),
}


def _classify_exclusion(path: str) -> Tuple[object, str]:
    """Clasifica una exclusión de carpeta de Defender. Devuelve (severidad, motivo), o (None, '')
    si la exclusión es específica y no llama la atención."""
    raw = (path or "").strip().strip('"')
    expanded = os.path.expandvars(raw)
    low = os.path.normcase(expanded)
    if raw in ("", "*") or low.endswith("\\*") or "*" in os.path.splitdrive(low)[0]:
        return CRITICAL, "comodín: deja fuera del análisis una gama enorme de ficheros"
    if re.fullmatch(r"[a-z]:\\?", low):
        return CRITICAL, "raíz de una unidad completa"
    if re.fullmatch(r"[a-z]:\\users(\\[^\\]+)?\\?", low):
        return CRITICAL, "perfil de usuario completo"
    loc = writable_location(low if low.endswith("\\") else low + "\\")
    if loc:
        return CRITICAL, f"carpeta grabable sin privilegios ({loc})"
    if low.rstrip("\\") == os.path.normcase(WINDIR).rstrip("\\") or low.startswith(os.path.normcase(WINDIR) + "\\"):
        return WARNING, "dentro de la carpeta de Windows"
    return None, ""


def _registry_exclusion_paths() -> List[str]:
    """Exclusiones de carpeta en el registro. La clave suele tener una ACL que solo deja leer a
    SYSTEM: sin privilegios devolverá una lista vacía (lo normal)."""
    out: List[str] = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            index = 0
            while True:
                try:
                    name, _, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                if name:
                    out.append(name)
    except OSError:
        pass  # clave inexistente o sin permiso de lectura
    return out


class TelemetriaModule(AuditModule):
    key = "telemetria"
    title = "TELEMETRÍA E INTEGRIDAD"
    description = ("Servicios de telemetría (DiagTrack, Windows Update, SysMain) y manipulación de "
                  "Microsoft Defender: exclusiones y protección desactivada")

    def checks(self):
        if IS_WINDOWS:
            return [self.check_telemetry_services, self.check_defender_exclusions, self.check_defender_integrity]
        return []

    # ------------------------------------------------------------------ servicios
    def check_telemetry_services(self):
        """Servicios de telemetría y mantenimiento"""
        names = ",".join(f"'{n}'" for n in TELEMETRY_SERVICES)
        data = powershell(f"Out-Json @(Get-Service -Name {names} -ErrorAction SilentlyContinue | "
                          "Select-Object Name, @{n='Status';e={[string]$_.Status}}, "
                          "@{n='StartType';e={[string]$_.StartType}})")
        services = {s.get("Name"): s for s in as_list(data)}
        if not services:
            raise CheckSkipped("No se pudo consultar el estado de los servicios")

        for name, (label, what) in TELEMETRY_SERVICES.items():
            svc = services.get(name)
            if not svc:
                self.add(INFO, f"{label}: no está presente en el sistema", what)
                continue
            status = svc.get("Status") or "?"
            start = svc.get("StartType") or "?"
            detail = f"{what}\nEstado: {status} · Inicio: {start}"
            if name == "wuauserv":
                # Windows Update es de SEGURIDAD: desactivarlo deja el equipo sin parches.
                if status != "Running" and start.lower() == "disabled":
                    self.add(WARNING, "Windows Update DESHABILITADO", detail,
                             "Mantén wuauserv en Manual o Automático: desactivar Windows Update deja el equipo "
                             "sin parches de seguridad, lo que a medio plazo es más peligroso que la telemetría.",
                             key="telemetria:wuauserv")
                else:
                    self.add(PASS, "Windows Update operativo", detail)
            elif name == "DiagTrack":
                if status == "Running":
                    self.add(INFO, "Telemetría de Windows (DiagTrack) activa", detail,
                             "Es el servicio de telemetría de Microsoft. Si prefieres reducir el envío de datos "
                             "de diagnóstico puedes ponerlo en Manual; no afecta a la seguridad del equipo.",
                             key="telemetria:diagtrack")
                else:
                    self.add(INFO, "Telemetría de Windows (DiagTrack) detenida", detail, key="telemetria:diagtrack")
            else:  # SysMain: solo rendimiento
                self.add(INFO, f"{label}: {status}", detail, key=f"telemetria:{name.lower()}")

    # ------------------------------------------------------------------ exclusiones de Defender
    def check_defender_exclusions(self):
        """Exclusiones de carpeta de Microsoft Defender"""
        ps_paths: List[str] = []
        ps_ok = False
        try:
            data = powershell("Out-Json @((Get-MpPreference -ErrorAction Stop).ExclusionPath)")
            ps_paths = [str(p) for p in as_list(data) if p]
            ps_ok = True
        except (CommandError, CheckSkipped):
            ps_ok = False

        reg_paths = _registry_exclusion_paths()

        # Unimos ambas fuentes sin duplicar (sin distinguir mayúsculas)
        merged = {}
        for p in ps_paths + reg_paths:
            merged.setdefault(os.path.normcase(p), p)
        exclusions = list(merged.values())

        if not ps_ok and not reg_paths:
            raise CheckSkipped("No se pudieron leer las exclusiones de Defender "
                               "(Get-MpPreference requiere normalmente privilegios de Administrador)")

        if not exclusions:
            self.add(PASS, "Microsoft Defender no tiene exclusiones de carpeta configuradas",
                     "No hay carpetas fuera del análisis antivirus.")
            return

        suspicious = 0
        normales: List[str] = []
        for path in sorted(exclusions, key=str.lower):
            severity, reason = _classify_exclusion(path)
            if severity is None:
                normales.append(path)
                continue
            suspicious += 1
            self.add(severity, f"Exclusión de Defender sospechosa: {path}",
                     f"Ruta excluida del análisis antivirus: {path}\nMotivo: {reason}.",
                     "El malware añade exclusiones para que Defender ignore donde se esconde. Si no reconoces "
                     "esta exclusión, revísala en Seguridad de Windows > Protección antivirus y contra amenazas "
                     "> Exclusiones, y elimínala.",
                     key=f"telemetria:exclusion:{os.path.normcase(path)}")

        resumen = f"{len(exclusions)} exclusión(es) de carpeta configuradas."
        if normales:
            resumen += "\nExclusiones específicas (sin incidencias): " + ", ".join(normales[:15])
            if len(normales) > 15:
                resumen += ", ..."
        if not ps_ok:
            resumen += "\n(Solo se pudo leer el registro; ejecuta como Administrador para la lista completa.)"
        self.add(INFO if suspicious else PASS,
                 "Inventario de exclusiones de Defender" if suspicious
                 else "Exclusiones de Defender sin rutas sospechosas", resumen)

    # ------------------------------------------------------------------ manipulación de Defender
    def check_defender_integrity(self):
        """Manipulación de Defender (protección en tiempo real y Tamper Protection)"""
        status = None
        try:
            status = powershell("Out-Json (Get-MpComputerStatus -ErrorAction Stop | Select-Object "
                                "AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, "
                                "BehaviorMonitorEnabled, IsTamperProtected)")
        except (CommandError, CheckSkipped):
            status = None
        prefs = None
        try:
            prefs = powershell("Out-Json (Get-MpPreference -ErrorAction Stop | Select-Object "
                               "DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, "
                               "DisableScriptScanning)")
        except (CommandError, CheckSkipped):
            prefs = None

        if not status and not prefs:
            raise CheckSkipped("No se pudo consultar el estado de Microsoft Defender "
                               "(los cmdlets Get-Mp* suelen requerir privilegios de Administrador)")
        status = status or {}
        prefs = prefs or {}

        rtp_off = status.get("RealTimeProtectionEnabled") is False or prefs.get("DisableRealtimeMonitoring") is True
        issues = False
        if rtp_off:
            issues = True
            self.add(CRITICAL, "Protección en tiempo real de Defender DESACTIVADA",
                     "Un valor habitual tras una infección: el malware apaga la protección en tiempo real para "
                     "operar sin ser detectado.",
                     "Reactívala en Seguridad de Windows > Protección antivirus y contra amenazas. Si se vuelve "
                     "a desactivar sola, trata el equipo como comprometido.",
                     key="telemetria:rtp")

        if status.get("IsTamperProtected") is False:
            issues = True
            self.add(WARNING, "Protección contra alteraciones (Tamper Protection) desactivada",
                     "Sin Tamper Protection, un proceso con privilegios puede apagar Defender sin resistencia.",
                     "Actívala en Seguridad de Windows > Protección antivirus y contra amenazas > "
                     "Administrar la configuración.",
                     key="telemetria:tamper")

        flags = {
            "DisableBehaviorMonitoring": "monitor de comportamiento",
            "DisableIOAVProtection": "análisis de descargas y adjuntos",
            "DisableScriptScanning": "análisis de scripts",
        }
        apagadas = [desc for key, desc in flags.items() if prefs.get(key) is True]
        if apagadas:
            issues = True
            self.add(WARNING, "Componentes de Defender desactivados por configuración",
                     "Desactivado(s): " + ", ".join(apagadas) + ".",
                     "Revisa por qué están desactivados estos componentes de Defender; el malware suele apagarlos.",
                     key="telemetria:componentes")

        if not issues:
            tamper = "sí" if status.get("IsTamperProtected") else "n/d"
            self.add(PASS, "Microsoft Defender sin señales de manipulación",
                     f"Protección en tiempo real activa · Tamper Protection: {tamper}")
