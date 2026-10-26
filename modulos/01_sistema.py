# -*- coding: utf-8 -*-
"""Plugin SISTEMA: versión del SO, privilegios, tiempo de actividad y reinicios pendientes."""

from __future__ import annotations

import ctypes
import os
import platform
import re
import time

from ._base import ADMIN_NAME, IS_LINUX, IS_WINDOWS, CRITICAL, INFO, PASS, WARNING, AuditModule, CheckSkipped
from ._utilidades import HAS_PSUTIL, psutil, read_text, reg_get, reg_key_exists, windows_build


# ===========================================================================
# MÓDULO 1 · SISTEMA
# ===========================================================================
class SistemaModule(AuditModule):
    key = "sistema"
    title = "SISTEMA"
    description = "Versión del sistema operativo, privilegios, uptime y reinicios pendientes"

    def checks(self):
        return [self.check_os, self.check_privileges, self.check_uptime, self.check_pending_reboot]

    def check_os(self):
        """Versión del sistema operativo"""
        u = platform.uname()
        if IS_WINDOWS:
            self._windows_version(u)
            return
        distro = ""
        if IS_LINUX:
            m = re.search(r'^PRETTY_NAME="?([^"\n]+)', read_text("/etc/os-release") or "", re.M)
            distro = m.group(1) if m else ""
        self.add(INFO, f"{distro or u.system} (kernel {u.release})",
                 f"Equipo: {u.node} · Arquitectura: {u.machine}")

    def _windows_version(self, u):
        cv = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        build = windows_build()
        edition = reg_get(cv, "EditionID", "") or ""
        display = reg_get(cv, "DisplayVersion", "") or reg_get(cv, "ReleaseId", "") or ""
        client = (reg_get(cv, "InstallationType", "Client") or "Client") == "Client"
        product = reg_get(cv, "ProductName", "Windows") or "Windows"
        if client and build >= 22000:  # ProductName sigue diciendo "Windows 10" en Windows 11
            product = product.replace("Windows 10", "Windows 11")
        title = f"{product} {display}".strip()
        detail = (f"Equipo: {u.node} · Edición: {edition} · Build: {build}.{reg_get(cv, 'UBR', 0)}"
                  f" · Arquitectura: {u.machine}")
        is_ltsc = "EnterpriseS" in edition  # ediciones LTSC tienen ciclo de soporte extendido

        if build and build < 10240:
            self.add(CRITICAL, f"{title}: versión de Windows sin soporte", detail,
                     "Ya no recibe parches de seguridad. Migra a una versión soportada.")
        elif client and build < 22000 and not is_ltsc:
            self.add(WARNING, f"{title}: Windows 10 sin soporte general desde el 14/10/2025", detail,
                     "Actualiza a Windows 11 o inscríbete en ESU para seguir recibiendo parches.")
        else:
            self.add(INFO, title, detail)

    def check_privileges(self):
        """Privilegios de ejecución"""
        if self.ctx.is_admin:
            self.add(INFO, f"Ejecutando con privilegios de {ADMIN_NAME}: auditoría completa")
        else:
            self.add(INFO, f"Ejecutando SIN privilegios de {ADMIN_NAME}: algunas comprobaciones se omitirán",
                     f"Aparecerán como [SKIP]. Para un análisis completo ejecuta el script como {ADMIN_NAME}.")

    def check_uptime(self):
        """Tiempo de actividad del sistema"""
        if HAS_PSUTIL:
            seconds = time.time() - psutil.boot_time()
        elif IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32
            kernel32.GetTickCount64.restype = ctypes.c_ulonglong
            seconds = kernel32.GetTickCount64() / 1000
        elif IS_LINUX:
            seconds = float((read_text("/proc/uptime") or "0").split()[0])
        else:
            raise CheckSkipped("No se pudo determinar el tiempo de actividad")
        days = seconds / 86400
        text = f"{int(days)} días y {int(seconds % 86400 // 3600)} h"
        note = "Nota: con 'Inicio rápido' de Windows, apagar no reinicia el kernel." if IS_WINDOWS else ""
        if days > 30:
            self.add(WARNING, f"Equipo sin reiniciar desde hace {text}", note,
                     "Reinicia periódicamente: muchos parches (kernel, drivers) solo se aplican tras reiniciar.")
        else:
            self.add(PASS, f"Tiempo de actividad: {text}")

    def check_pending_reboot(self):
        """Reinicio pendiente por actualizaciones"""
        if IS_WINDOWS:
            keys = (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
            pending = any(reg_key_exists(k) for k in keys)
        elif IS_LINUX:
            pending = os.path.exists("/var/run/reboot-required")  # Debian/Ubuntu
        else:
            raise CheckSkipped("No soportado en este sistema")
        if pending:
            self.add(WARNING, "Hay un reinicio pendiente para completar actualizaciones", "",
                     "Reinicia el equipo para que los parches instalados entren en vigor.")
        else:
            self.add(PASS, "No hay reinicios pendientes por actualizaciones")
