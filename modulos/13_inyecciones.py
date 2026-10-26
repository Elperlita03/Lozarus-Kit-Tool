# -*- coding: utf-8 -*-
"""
Plugin INYECCIONES: cazador de inyección de código en procesos sensibles (SOLO LECTURA).

Busca señales de DLL injection y process hollowing en los procesos que el malware suele
usar como anfitriones (svchost.exe, explorer.exe, lsass.exe, winlogon.exe, services.exe,
rundll32.exe...). Para cada uno enumera los módulos (DLL) cargados con psutil y marca como
CRITICAL cuando un proceso legítimo o protegido ha cargado:
  · una DLL desde una carpeta grabable por el usuario (Temp, AppData, Descargas...), o
  · una DLL sin firma digital válida.
También avisa si el propio ejecutable del proceso corre desde una ruta grabable (indicio de
suplantación / hollowing).

RENDIMIENTO: verificar firmas es lento, así que el alcance se limita a conciencia:
  · solo procesos anfitriones sensibles;
  · se ignoran las DLL dentro de C:\\Windows (protegidas por el sistema y firmadas);
  · se eliminan rutas duplicadas y se verifican en bloque con un tiempo límite;
  · hay topes de procesos y de DLL para que la comprobación no se alargue.

Sin privilegios de Administrador no se puede leer la memoria de los procesos del sistema
(svchost, lsass...): se cuentan como inaccesibles y se recomienda repetir elevado, sin error.
"""

from __future__ import annotations

import os
from typing import Dict, List, Set

from ._base import CRITICAL, INFO, IS_WINDOWS, PASS, AuditModule, CheckSkipped
from ._utilidades import (HAS_PSUTIL, authenticode_signatures, is_valid_signature, psutil,
                          signature_label, writable_location)

WINDIR = os.environ.get("SystemRoot", r"C:\Windows")

# Procesos anfitriones sensibles: objetivos habituales de inyección o suplantación
SENSITIVE_PROCESSES = {
    "svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe", "services.exe", "csrss.exe",
    "wininit.exe", "smss.exe", "spoolsv.exe", "rundll32.exe", "dllhost.exe", "taskhostw.exe",
    "regsvr32.exe", "lsaiso.exe", "sihost.exe",
}

MAX_PROCESOS = 120   # tope de procesos a inspeccionar (puede haber muchos svchost)
MAX_DLLS = 400       # tope de DLL candidatas cuya firma se verifica


def _dll_classification(status: str, loc) -> str:
    """
    Clasifica una DLL candidata para decidir la alerta. Función pura (testable sin psutil).

    'Error' significa que la verificación de la firma FALLÓ (p. ej. tiempo agotado), no que la DLL
    carezca de firma: es DESCONOCIDO y NUNCA debe tratarse como 'sin firma válida', para no acusar
    a una DLL legítima cuando la comprobación no pudo completarse.

    Devuelve: 'critical_loc' (carpeta grabable), 'critical_unsigned' (sin firma válida confirmada),
    'unverifiable' (no se pudo verificar) o 'benign' (firma válida).
    """
    if loc:
        return "critical_loc"       # ubicación grabable: crítico con independencia de la firma
    if status == "Error":
        return "unverifiable"       # no se pudo verificar: desconocido, no 'sin firma'
    if not is_valid_signature(status):
        return "critical_unsigned"
    return "benign"


class InyeccionesModule(AuditModule):
    key = "inyecciones"
    title = "INYECCIÓN DE CÓDIGO"
    description = ("Caza de DLL injection y process hollowing: DLL sin firma o en rutas grabables "
                  "cargadas en procesos del sistema")

    def checks(self):
        if IS_WINDOWS:
            return [self.check_injected_modules]
        return []

    def check_injected_modules(self):
        """DLL inyectadas en procesos sensibles"""
        if not HAS_PSUTIL:
            raise CheckSkipped("El cazador de inyecciones necesita psutil:  pip install psutil")

        windir_prefix = os.path.normcase(WINDIR) + "\\"
        candidates: Dict[str, Set[str]] = {}   # ruta de DLL -> {proceso (PID)}
        hollowing: List[str] = []              # ejecutables de procesos sensibles en rutas grabables
        examined = 0
        inaccessible = 0

        targets = []
        for proc in psutil.process_iter(["pid", "name"]):
            if (proc.info.get("name") or "").lower() in SENSITIVE_PROCESSES:
                targets.append(proc)

        for proc in targets[:MAX_PROCESOS]:
            pname = proc.info.get("name") or "?"
            pid = proc.info.get("pid") or 0
            etiqueta = f"{pname} (PID {pid})"

            # ¿El propio ejecutable corre desde una carpeta grabable? (suplantación / hollowing)
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.Error, OSError):
                exe = ""
            if exe:
                loc = writable_location(exe)
                if loc:
                    hollowing.append(f"{etiqueta} → {exe} ({loc})")

            # Módulos (DLL) cargados en el proceso
            try:
                maps = proc.memory_maps()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.Error, OSError):
                inaccessible += 1
                continue
            examined += 1
            for mapping in maps:
                path = getattr(mapping, "path", "") or ""
                low = os.path.normcase(path)
                if not (low.endswith(".dll") or low.endswith(".exe")):
                    continue
                if low.startswith(windir_prefix):
                    continue  # DLL del sistema: protegida y firmada, se ignora (rendimiento y ruido)
                if not os.path.isfile(path):
                    continue
                candidates.setdefault(path, set()).add(etiqueta)

        # Verificación de firmas en bloque, solo de las DLL candidatas (fuera de C:\Windows)
        to_verify = list(candidates)[:MAX_DLLS]
        sigs = authenticode_signatures(to_verify, timeout=120)

        criticos = 0
        benignas = 0
        no_verificables = 0
        for path in to_verify:
            procs = ", ".join(sorted(candidates[path]))
            status, signer = sigs.get(path, ("Error", ""))
            loc = writable_location(path)
            detalle = f"DLL: {path}\n{signature_label(status, signer)}\nCargada en: {procs}"
            verdict = _dll_classification(status, loc)
            if verdict == "critical_loc":
                self.add(CRITICAL, f"DLL cargada desde carpeta grabable en proceso sensible: {os.path.basename(path)}",
                         detalle + f"\nUbicación grabable: {loc}",
                         "Una DLL cargada desde una carpeta de usuario (Temp, AppData, Descargas) dentro de un "
                         "proceso del sistema es un patrón claro de inyección de código. Trata el equipo como "
                         "posiblemente comprometido e investiga el origen de esa DLL.",
                         key=f"inyeccion:{os.path.normcase(path)}")
                criticos += 1
            elif verdict == "critical_unsigned":
                self.add(CRITICAL, f"DLL sin firma válida en proceso sensible: {os.path.basename(path)}",
                         detalle,
                         "Un proceso legítimo que carga una DLL sin firma digital válida puede haber sido objeto "
                         "de inyección. Verifica de qué programa procede esa DLL.",
                         key=f"inyeccion:{os.path.normcase(path)}")
                criticos += 1
            elif verdict == "unverifiable":
                no_verificables += 1  # la verificación de la firma falló: desconocido, no 'sin firma'
            else:
                benignas += 1  # firma válida (aunque sea de terceros): módulo normal (extensión de shell, etc.)

        for item in hollowing:
            self.add(CRITICAL, "Proceso del sistema ejecutándose desde una ruta grabable",
                     f"{item}\nLos procesos del sistema solo deberían ejecutarse desde C:\\Windows\\System32.",
                     "Un proceso con nombre de sistema que corre desde una carpeta de usuario es un indicio de "
                     "suplantación (process hollowing). Investígalo de inmediato.",
                     key=f"inyeccion:hollow:{item.split(' ')[0].lower()}")

        resumen = (f"{examined} proceso(s) sensible(s) inspeccionado(s), {inaccessible} inaccesible(s), "
                   f"{len(to_verify)} DLL fuera de C:\\Windows ({benignas} con firma válida"
                   + (f", {no_verificables} no verificables" if no_verificables else "") + ").")
        if inaccessible and not self.ctx.is_admin:
            resumen += ("\nMuchos procesos del sistema (svchost, lsass...) solo son legibles como Administrador: "
                        "ejecuta la auditoría elevada para un análisis completo.")
        if candidates and len(candidates) > MAX_DLLS:
            resumen += f"\n(Se verificaron las primeras {MAX_DLLS} de {len(candidates)} DLL candidatas.)"

        if criticos == 0 and not hollowing:
            self.add(PASS, "Sin señales de inyección de DLL en los procesos sensibles", resumen)
        else:
            self.add(INFO, "Resumen del análisis de inyecciones", resumen)
