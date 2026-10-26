# -*- coding: utf-8 -*-
"""
Persistencia de inicio de Windows (SOLO LECTURA): qué programas arrancan solos con el equipo.

  · Claves Run / RunOnce del registro en HKLM (vistas de 64 y 32 bits) y HKCU.
  · Carpetas «Inicio» del usuario y de todos los usuarios.

Fuente ÚNICA de RUN_KEYS y resolve_exe: el plugin 11_persistencia (auditoría con veredicto de
firma) los importa de aquí, así no hay dos listas de claves que mantener. Este módulo no modifica
nada del sistema: exportar escribe solo el fichero elegido y «abrir ubicación» abre el Explorador.
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
from typing import Dict, List, Tuple

from ._base import IS_WINDOWS

if IS_WINDOWS:
    import winreg

    _HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}

# Claves de ejecución automática: (etiqueta legible, colmena, subclave). La vista de 64 bits
# también lee WOW6432Node, por eso basta con enumerar las rutas explícitas.
RUN_KEYS: List[Tuple[str, str, str]] = [
    ("HKLM\\...\\Run",         "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM\\...\\RunOnce",     "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM 32 bits\\...\\Run", "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM 32 bits\\RunOnce",  "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU\\...\\Run",         "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU\\...\\RunOnce",     "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def resolve_exe(command: str) -> str:
    """Extrae la ruta del ejecutable de una línea de comando (respeta las comillas) y expande
    las variables de entorno. Devuelve "" si no se puede determinar."""
    command = (command or "").strip()
    if not command:
        return ""
    if command[0] == '"':
        end = command.find('"', 1)
        raw = command[1:end] if end != -1 else command[1:]
    else:
        raw = command.split(" ", 1)[0]
    return os.path.expandvars(raw.strip())


def startup_folders() -> List[Tuple[str, str]]:
    """Carpetas «Inicio» (etiqueta, ruta): la del usuario y la común a todos los usuarios."""
    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    return [
        ("Carpeta Inicio (usuario)",
         os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")),
        ("Carpeta Inicio (todos)",
         os.path.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp")),
    ]


def _entry(origen: str, ubicacion: str, nombre: str, comando: str, ruta: str) -> Dict[str, object]:
    return {"origen": origen, "ubicacion": ubicacion, "nombre": nombre, "comando": comando,
            "ruta": ruta, "existe": bool(ruta) and os.path.exists(ruta)}


def read_run_keys() -> List[Dict[str, object]]:
    """Valores de las claves Run/RunOnce. Las claves ausentes o ilegibles se omiten (no fallan)."""
    entries: List[Dict[str, object]] = []
    if not IS_WINDOWS:
        return entries
    for label, hive, subkey in RUN_KEYS:
        try:
            with winreg.OpenKey(_HIVES[hive], subkey, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                index = 0
                while True:
                    try:
                        name, value, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        break  # no quedan más valores
                    index += 1
                    command = str(value)
                    entries.append(_entry(label, f"{hive}\\{subkey}", name or "(predeterminado)",
                                          command, resolve_exe(command)))
        except OSError:  # la clave no existe o no se puede leer: se omite
            continue
    return entries


def read_startup_folders(folders: List[Tuple[str, str]] = None) -> List[Dict[str, object]]:
    """Ficheros de las carpetas Inicio (los .lnk se listan tal cual: su destino exige COM)."""
    entries: List[Dict[str, object]] = []
    for label, folder in (folders if folders is not None else startup_folders()):
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            if name.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, name)
            entries.append(_entry(label, folder, name, full, full))
    return entries


def startup_entries() -> List[Dict[str, object]]:
    """Todas las entradas de inicio automático (registro + carpetas Inicio). Solo lectura."""
    return read_run_keys() + read_startup_folders()


def export_entries(entries: List[Dict[str, object]], path: str) -> int:
    """Exporta las entradas: `.csv` → CSV con cabecera; cualquier otra extensión → JSON indentado.
    Devuelve el número de entradas escritas."""
    columnas = ["origen", "nombre", "comando", "ruta", "existe", "ubicacion"]
    if path.lower().endswith(".csv"):
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:  # BOM: Excel abre bien los acentos
            writer = csv.DictWriter(fh, fieldnames=columnas, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(list(entries), fh, ensure_ascii=False, indent=2)
    return len(entries)


def open_location(path: str) -> Tuple[bool, str]:
    """
    Abre en el Explorador la ubicación del ejecutable (seleccionándolo). Si el fichero no existe pero
    su carpeta sí, abre la carpeta. Devuelve (ok, mensaje). Las rutas de Windows no pueden contener
    comillas, y solo se usa una ruta comprobada en disco: no hay inyección posible en la orden.
    """
    if not path:
        return False, "Esta entrada no tiene una ruta de ejecutable reconocible."
    path = os.path.normpath(path)
    try:
        if os.path.isfile(path):
            subprocess.Popen(f'explorer.exe /select,"{path}"')  # noqa: S603
            return True, f"Abierta la ubicación de {os.path.basename(path)}"
        folder = os.path.dirname(path)
        if folder and os.path.isdir(folder):
            os.startfile(folder)  # noqa: S606
            return True, f"El fichero no existe; abierta su carpeta: {folder}"
    except Exception as exc:  # noqa: BLE001
        return False, f"No se pudo abrir el Explorador: {exc}"
    return False, f"La ruta no existe en disco: {path}"
