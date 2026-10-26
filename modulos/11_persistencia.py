# -*- coding: utf-8 -*-
"""
Plugin PERSISTENCIA: autoruns profundo y caza de rootkits (SOLO LECTURA).

Enumera, sin tocar el sistema, las principales vías por las que el malware consigue
arrancar con Windows y sobrevivir a los reinicios:

  · Claves de arranque del registro: Run y RunOnce en HKLM (64 y 32 bits) y HKCU,
    y las entradas de Winlogon (Shell, Userinit), un secuestro clásico.
  · Tareas programadas (Get-ScheduledTask), con atención a las que lanzan ejecutables
    desde carpetas grabables por el usuario.
  · Controladores del kernel (.sys, Win32_SystemDriver): marca los que NO están firmados
    por Microsoft, la forma más grave de persistencia (un driver corre en anillo 0).

Reglas de severidad:
  · CRITICAL · un driver sin firma válida, o una entrada de arranque/tarea que apunta a
    AppData, Temp, Descargas... (carpetas grabables sin privilegios, típicas del malware).
  · WARNING · binarios de arranque sin firma, controladores firmados por terceros o
    configuraciones de Winlogon inusuales.
  · INFO/PASS · lo normal (programas de arranque firmados, drivers de Microsoft).

La verificación de firmas se delega en authenticode_signatures() de _utilidades.py (el mismo
enfoque que el Monitor en Vivo) y se limita a los ficheros que de verdad conviene comprobar.
"""

from __future__ import annotations

import os
from typing import Dict, List

from ._base import CRITICAL, INFO, IS_WINDOWS, PASS, WARNING, AuditModule, CheckSkipped, CommandError
from ._utilidades import (as_list, authenticode_signatures, is_trusted_microsoft, powershell,
                          reg_get, signature_label, writable_location)

if IS_WINDOWS:
    import winreg

    _HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}

WINDIR = os.environ.get("SystemRoot", r"C:\Windows")

# Binarios "cargadores" firmados por Microsoft que el malware usa para ejecutar su carga útil
# (una DLL o un script que SÍ vive en una carpeta de usuario). Si el ejecutable es uno de estos,
# su firma válida no nos tranquiliza: lo que importa es de dónde sale lo que carga.
LOADERS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "powershell.exe", "pwsh.exe",
           "wscript.exe", "cscript.exe", "cmd.exe"}


def _autorun_verdict(exe: str, exists: bool, status: str, signer: str, command: str):
    """Decide la severidad de una vía de arranque en función de la firma y la ubicación.

    Un ejecutable FIRMADO (p. ej. Discord o Brave en AppData) es un programa por usuario normal,
    no una alarma; el peligro real es un binario SIN firma válida en una carpeta grabable, o un
    cargador (rundll32, powershell...) que tira de algo alojado en una de esas carpetas.

    Devuelve (veredicto, ubicacion_grabable_o_None) con veredicto en
    {'critical','warning','unverifiable','benign'}. 'unverifiable' = no se pudo comprobar la firma
    (p. ej. tiempo agotado): es DESCONOCIDO y NUNCA se trata como 'sin firma válida', para no acusar
    a un programa legítimo cuando la verificación falló (mismo criterio que el cazador de inyecciones).
    """
    loc = writable_location(command)  # la ruta grabable puede estar en una DLL/script de la línea
    loader = os.path.basename(exe or "").lower() in LOADERS
    trusted_app = exists and status == "Valid" and not loader
    if loc:
        return ("benign" if trusted_app else "critical"), loc
    if exists and status == "Error":
        return "unverifiable", None  # la verificación de la firma falló: desconocido, no 'sin firma'
    if exists and status and status != "Valid" and not is_trusted_microsoft(status, signer):
        return "warning", None
    return "benign", None

# Claves Run/RunOnce y resolución del ejecutable: fuente única en _inicio.py (también la usa la
# vista «Inicio de Windows» de la GUI), para no mantener dos listas de claves.
from ._inicio import RUN_KEYS  # noqa: E402
from ._inicio import resolve_exe as _resolve_exe  # noqa: E402


def _normalize_driver_path(raw: str) -> str:
    """Normaliza el PathName de un driver (\\??\\, \\SystemRoot\\, System32\\...) a una ruta real."""
    path = (raw or "").strip().strip('"')
    if not path:
        return ""
    if path.lower().startswith("\\??\\"):
        path = path[4:]
    low = path.lower()
    if low.startswith("\\systemroot\\"):
        path = WINDIR + path[len("\\systemroot"):]
    elif low.startswith("systemroot\\"):
        path = WINDIR + "\\" + path[len("systemroot\\"):]
    elif low.startswith("system32\\"):
        path = os.path.join(WINDIR, path)
    elif low.startswith("\\windows\\"):
        path = os.path.splitdrive(WINDIR)[0] + path
    return os.path.expandvars(path)


class PersistenciaModule(AuditModule):
    key = "persistencia"
    title = "PERSISTENCIA Y ROOTKITS"
    description = ("Autoruns profundo: claves de arranque, Winlogon, tareas programadas y "
                  "controladores del kernel sin firmar")

    def checks(self):
        if IS_WINDOWS:
            return [self.check_run_keys, self.check_winlogon, self.check_scheduled_tasks, self.check_drivers]
        return []

    # ------------------------------------------------------------------ claves Run / RunOnce
    def check_run_keys(self):
        """Claves de arranque automático (Run / RunOnce)"""
        entries: List[Dict[str, str]] = []  # {origin, name, command, exe}
        failed: List[str] = []
        for label, hive, subkey in RUN_KEYS:
            try:
                with winreg.OpenKey(_HIVES[hive], subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        index += 1
                        command = str(value).strip()
                        if command:
                            entries.append({"origin": label, "name": name, "command": command,
                                            "exe": _resolve_exe(command)})
            except FileNotFoundError:
                continue  # la clave no existe (p. ej. WOW6432Node en un Windows de 32 bits)
            except OSError as exc:
                failed.append(f"{label} ({exc.strerror or exc})")

        # Verificamos la firma solo de los ejecutables que existen (una sola consulta en bloque)
        sigs = authenticode_signatures([e["exe"] for e in entries
                                        if e["exe"] and os.path.isfile(e["exe"])])

        benign: List[str] = []
        flagged = 0
        for e in entries:
            exe, command, name, origin = e["exe"], e["command"], e["name"], e["origin"]
            exists = bool(exe) and os.path.isfile(exe)
            status, signer = sigs.get(exe, ("", ""))
            verdict, loc = _autorun_verdict(exe, exists, status, signer, command)
            firma = signature_label(status, signer) if exists else "ejecutable no encontrado"
            detalle = f"Origen: {origin}\nEntrada: {name}\nComando: {command}\n{firma}"
            if verdict == "critical":
                self.add(CRITICAL, f"Arranque automático sospechoso desde carpeta grabable: {name}",
                         detalle + f"\nUbicación grabable: {loc}",
                         "Un programa SIN firma válida (o un cargador como rundll32/powershell) que arranca "
                         "desde una carpeta donde cualquiera puede escribir es un patrón típico de malware. "
                         "Revisa qué es; si no lo reconoces, analízalo y elimina la entrada desde el "
                         "Administrador de tareas > Inicio.",
                         key=f"persist:run:{origin}:{name}")
                flagged += 1
            elif verdict == "warning":
                self.add(WARNING, f"Programa de arranque sin firma válida: {name}", detalle,
                         "Un ejecutable de arranque sin firma digital válida merece revisión. Comprueba que "
                         "procede de un fabricante de confianza.",
                         key=f"persist:run:{origin}:{name}")
                flagged += 1
            elif verdict == "unverifiable":
                benign.append(f"{name} [firma no verificable]")  # desconocido: no es alarma ni «sin incidencias»
            else:
                etiqueta = name
                if is_trusted_microsoft(status, signer):
                    etiqueta += " (Microsoft)"
                elif signer:
                    etiqueta += f" ({signer})"
                if loc:  # programa firmado por usuario que arranca desde una carpeta grabable (normal)
                    etiqueta += f" [firmado, en {loc}]"
                benign.append(etiqueta)

        if not entries and failed:
            raise CheckSkipped("No se pudieron leer las claves de arranque: " + "; ".join(failed))
        resumen = f"{len(entries)} entrada(s) de arranque en Run/RunOnce (HKLM 64/32 bits y HKCU)."
        if failed:
            resumen += " Ramas no accesibles: " + "; ".join(failed) + "."
        if benign:
            resumen += "\nEntradas sin incidencias: " + ", ".join(sorted(benign))
        if flagged == 0:
            self.add(PASS, "Ninguna entrada de arranque sospechosa en Run/RunOnce", resumen)
        else:
            self.add(INFO, "Inventario de arranque automático", resumen)

    # ------------------------------------------------------------------ Winlogon
    def check_winlogon(self):
        """Secuestro de Winlogon (Shell / Userinit)"""
        base = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        shell = str(reg_get(base, "Shell", "") or "").strip()
        userinit = str(reg_get(base, "Userinit", "") or "").strip()
        issues = False

        # Shell normal = "explorer.exe". Cualquier añadido es sospechoso (secuestro del shell).
        shell_tokens = [t.strip() for t in shell.split(",") if t.strip()]
        extra_shell = [t for t in shell_tokens if os.path.basename(_resolve_exe(t)).lower() != "explorer.exe"]
        if shell and extra_shell:
            loc = writable_location(shell)
            issues = True
            self.add(CRITICAL if loc else WARNING, "Shell de Winlogon modificado",
                     f"Valor actual: {shell}\nLo normal es únicamente 'explorer.exe'."
                     + (f"\nUbicación grabable: {loc}" if loc else ""),
                     "Un Shell de Winlogon alterado hace que Windows ejecute un programa extra en cada inicio "
                     "de sesión. Restáuralo a 'explorer.exe' si no reconoces el añadido.",
                     key="persist:winlogon:shell")

        # Userinit normal = "<System32>\userinit.exe,". Entradas adicionales son persistencia.
        userinit_tokens = [t.strip() for t in userinit.split(",") if t.strip()]
        extra_userinit = [t for t in userinit_tokens
                          if os.path.basename(_resolve_exe(t)).lower() != "userinit.exe"]
        if userinit and extra_userinit:
            loc = writable_location(userinit)
            issues = True
            self.add(CRITICAL if loc else WARNING, "Userinit de Winlogon con entradas adicionales",
                     f"Valor actual: {userinit}\nLo normal es solo 'userinit.exe' de System32."
                     + (f"\nUbicación grabable: {loc}" if loc else ""),
                     "Userinit se ejecuta al iniciar sesión; añadir programas aquí es una técnica de persistencia. "
                     "Deja únicamente el userinit.exe del sistema.",
                     key="persist:winlogon:userinit")

        if not issues:
            self.add(PASS, "Winlogon sin modificaciones sospechosas",
                     f"Shell: {shell or '(predeterminado)'} · Userinit: {userinit or '(predeterminado)'}")

    # ------------------------------------------------------------------ tareas programadas
    def check_scheduled_tasks(self):
        """Tareas programadas que lanzan ejecutables de rutas de usuario"""
        script = r"""
Out-Json @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $_
    foreach ($a in @($t.Actions)) {
        if ($a.Execute) {
            @{ name = [string]$t.TaskName; path = [string]$t.TaskPath; state = [string]$t.State;
               exe = [string]$a.Execute; args = [string]$a.Arguments }
        }
    }
})
"""
        try:
            data = powershell(script, timeout=120)
        except CommandError as exc:
            raise CheckSkipped(f"No se pudieron enumerar las tareas programadas: {exc}")
        actions = as_list(data)
        if not actions:
            self.add(INFO, "No se encontraron tareas programadas con acción de ejecución")
            return

        # Resolvemos rutas y reunimos los ejecutables fuera de C:\Windows para verificar su firma
        windir_low = os.path.normcase(WINDIR)
        to_verify = []
        for a in actions:
            exe = os.path.expandvars((a.get("exe") or "").strip().strip('"'))
            a["_exe"] = exe
            if exe and os.path.isfile(exe) and not os.path.normcase(exe).startswith(windir_low):
                to_verify.append(exe)
        sigs = authenticode_signatures(to_verify)

        flagged = 0
        for a in actions:
            exe, args = a["_exe"], (a.get("args") or "").strip()
            name = (a.get("path") or "") + (a.get("name") or "")
            command = (exe + " " + args).strip()
            exists = bool(exe) and os.path.isfile(exe)
            status, signer = sigs.get(exe, ("", ""))
            verdict, loc = _autorun_verdict(exe, exists, status, signer, command)
            detalle = (f"Tarea: {name}\nEstado: {a.get('state')}\nEjecuta: {exe or a.get('exe')}"
                       + (f" {args}" if args else ""))
            if verdict == "critical":
                self.add(CRITICAL, f"Tarea programada sospechosa (carpeta grabable): {a.get('name')}",
                         detalle + f"\nUbicación grabable: {loc}",
                         "Una tarea que ejecuta un binario sin firma válida (o un cargador como "
                         "rundll32/powershell) desde AppData, Temp o Descargas es una vía de persistencia "
                         "habitual del malware. Revísala en el Programador de tareas (taskschd.msc) y "
                         "deshabilítala si no la reconoces.",
                         key=f"persist:task:{name}")
                flagged += 1
            elif verdict == "warning":
                self.add(WARNING, f"Tarea programada con ejecutable sin firma válida: {a.get('name')}",
                         detalle + f"\n{signature_label(status, signer)}",
                         "Comprueba que el programa que lanza esta tarea procede de un fabricante de confianza.",
                         key=f"persist:task:{name}")
                flagged += 1

        enabled = sum(1 for a in actions if (a.get("state") or "").lower() != "disabled")
        resumen = f"{len(actions)} acción(es) de ejecución en tareas programadas ({enabled} habilitadas)."
        if flagged == 0:
            self.add(PASS, "Ninguna tarea programada arranca desde rutas de usuario sospechosas", resumen)
        else:
            self.add(INFO, "Inventario de tareas programadas", resumen)

    # ------------------------------------------------------------------ controladores (.sys)
    def check_drivers(self):
        """Controladores del kernel (.sys) sin firma de Microsoft"""
        data = powershell(
            "Out-Json @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | "
            "Select-Object Name, @{n='DisplayName';e={[string]$_.DisplayName}}, "
            "@{n='State';e={[string]$_.State}}, @{n='Path';e={[string]$_.PathName}})",
            timeout=90)
        drivers = as_list(data)
        if not drivers:
            raise CheckSkipped("No se pudo enumerar la lista de controladores (Win32_SystemDriver)")

        # Normalizamos rutas y verificamos la firma de TODOS los drivers con fichero accesible
        paths: Dict[str, str] = {}  # ruta normalizada -> ruta original
        for d in drivers:
            norm = _normalize_driver_path(d.get("Path") or "")
            d["_path"] = norm
            if norm and os.path.isfile(norm):
                paths[norm] = d.get("Path") or ""
        sigs = authenticode_signatures(list(paths), timeout=180)

        unsigned: List[str] = []       # CRITICAL: sin firma válida (o fichero modificado)
        third_party: List[str] = []    # WARNING: firma válida pero no de Microsoft
        microsoft = 0
        unknown = 0                    # ruta no accesible: no podemos verificar
        for d in drivers:
            norm, name = d["_path"], d.get("Name")
            label = f"{name} [{d.get('State')}] — {norm or d.get('Path') or '(ruta desconocida)'}"
            if not norm or not os.path.isfile(norm):
                unknown += 1
                continue
            status, signer = sigs.get(norm, ("Error", ""))
            if is_trusted_microsoft(status, signer):
                microsoft += 1
            elif status == "Valid":
                third_party.append(f"{label} · {signer or 'editor desconocido'}")
            else:
                unsigned.append(f"{label} · {signature_label(status, signer)}")

        resumen = (f"{len(drivers)} controladores: {microsoft} firmados por Microsoft, "
                   f"{len(third_party)} por terceros, {len(unsigned)} sin firma válida.")
        if unknown:
            resumen += f" {unknown} con ruta no accesible (verifica como Administrador)."
        self.add(INFO, "Inventario de controladores del kernel", resumen)

        if unsigned:
            self.add(CRITICAL, f"{len(unsigned)} controlador(es) del kernel SIN firma válida",
                     "\n".join(unsigned[:20]) + ("\n..." if len(unsigned) > 20 else ""),
                     "Un controlador corre en el núcleo (anillo 0): uno sin firma válida puede ser un rootkit o un "
                     "driver vulnerable usado para desactivar defensas. Identifícalo y, si no lo reconoces, "
                     "investígalo antes de confiar en el equipo.",
                     key="persist:drivers:unsigned")
        if third_party:
            self.add(WARNING, f"{len(third_party)} controlador(es) firmados por terceros (no Microsoft)",
                     "\n".join(third_party[:20]) + ("\n..." if len(third_party) > 20 else ""),
                     "Es normal tener drivers de terceros (GPU, red, periféricos, antivirus). Revisa que todos "
                     "correspondan a hardware o software que de verdad tengas instalado.",
                     key="persist:drivers:thirdparty")
        if not unsigned and not third_party:
            self.add(PASS, "Todos los controladores con fichero accesible están firmados por Microsoft")
