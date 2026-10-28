"""
modulos/_arsenal.py · LOZARUS KIT TOOL

Motor del ARSENAL: ajustes de privacidad, red/USB y UX aplicados en el registro con ROLLBACK. Antes
de escribir nada se guarda el valor original en rollback_state.json; «Revertir» lo restaura (o, si
el ajuste no lo aplicó Lozarus, borra el valor para volver al comportamiento por defecto de Windows).
Incluye además dos acciones sin estado: purga de temporales y debloater de paquetes Appx.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ._base import IS_WINDOWS
from ._forense import FORENSICS_DIR
from ._privacidad import clean_temp, temp_dir
from ._utilidades import powershell_raw

STATE_FILE = os.path.join(FORENSICS_DIR, "rollback_state.json")

# (colmena, subclave, nombre del valor, dato deseado): int -> REG_DWORD, str -> REG_SZ ("" = predeterminado)
RegValue = Tuple[str, str, str, object]
CLASSIC_MENU = r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"


@dataclass(frozen=True)
class Tweak:
    key: str
    card: str            # privacy | network | ux
    title: str
    desc: str
    values: Tuple[RegValue, ...]
    own_keys: Tuple[Tuple[str, str], ...] = ()  # claves que se borran al revertir si Lozarus las creó

    @property
    def admin(self) -> bool:
        return any(hive == "HKLM" for hive, *_ in self.values)


TWEAKS: List[Tweak] = [
    Tweak("telemetry", "privacy", "Bloquear Telemetría de Windows",
          "Nivel de diagnóstico mínimo: Windows deja de enviar datos de uso a Microsoft.",
          (("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),)),
    Tweak("bing", "privacy", "Desactivar Bing y Búsqueda Web en Inicio",
          "Lo que escribes en el menú Inicio deja de enviarse a Bing.",
          (("HKCU", r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1),)),
    Tweak("adid", "privacy", "Bloquear ID Publicitario",
          "Las apps no pueden perfilarte entre sí con un identificador publicitario común.",
          (("HKCU", r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),)),
    Tweak("activity", "privacy", "Desactivar Historial de Actividad",
          "Windows deja de registrar la línea de tiempo de apps, documentos y webs que usas.",
          (("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0),)),
    Tweak("llmnr", "network", "Desactivar LLMNR",
          "Evita el envenenamiento de nombres en la red local (Responder) que roba hashes NTLM.",
          (("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0),)),
    Tweak("autorun", "network", "Bloquear AutoRun / AutoPlay",
          "Un USB malicioso no puede ejecutar nada al conectarlo, en ningún tipo de unidad.",
          (("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255),)),
    Tweak("smb1", "network", "Desactivar SMBv1",
          "Protocolo obsoleto explotado por WannaCry y EternalBlue. Efectivo tras reiniciar.",
          (("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0),)),
    Tweak("wpad", "network", "Endurecer WPAD",
          "Impide que un equipo de la red se anuncie como proxy automático e intercepte tu tráfico.",
          (("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad", "WpadOverride", 1),)),
    Tweak("extensions", "ux", "Revelar Extensiones y Ocultos",
          "Desenmascara «factura.pdf.exe». Reinicia el Explorador para verlo.",
          (("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 0),
           ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", 1))),
    Tweak("classic_menu", "ux", "Menú Contextual Clásico (Windows 11)",
          "Recupera el menú del botón derecho completo. Reinicia el Explorador para verlo.",
          (("HKCU", CLASSIC_MENU + r"\InprocServer32", "", ""),),
          own_keys=(("HKCU", CLASSIC_MENU + r"\InprocServer32"), ("HKCU", CLASSIC_MENU))),
]
BY_KEY: Dict[str, Tweak] = {t.key: t for t in TWEAKS}

BLOATWARE = ("Microsoft.BingNews", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.WindowsFeedbackHub",
             "Microsoft.MicrosoftSolitaireCollection")


def _winreg():
    import winreg  # solo Windows: se importa al usar el motor
    return winreg


def _root(hive: str):
    wr = _winreg()
    return {"HKLM": wr.HKEY_LOCAL_MACHINE, "HKCU": wr.HKEY_CURRENT_USER}[hive]


def describe(value: RegValue) -> str:
    hive, subkey, name, data = value
    return f"{hive}\\{subkey}\\{name or '(predeterminado)'} = {data!r}"


def read_value(hive: str, subkey: str, name: str) -> Tuple[bool, object, Optional[int]]:
    """(existe, dato, tipo) del valor; (False, None, None) si la clave o el valor no existen."""
    wr = _winreg()
    try:
        with wr.OpenKey(_root(hive), subkey, 0, wr.KEY_READ | wr.KEY_WOW64_64KEY) as key:
            data, kind = wr.QueryValueEx(key, name)
            return True, data, kind
    except FileNotFoundError:
        return False, None, None


def key_exists(hive: str, subkey: str) -> bool:
    wr = _winreg()
    try:
        with wr.OpenKey(_root(hive), subkey, 0, wr.KEY_READ | wr.KEY_WOW64_64KEY):
            return True
    except FileNotFoundError:
        return False


def write_value(hive: str, subkey: str, name: str, data, kind: Optional[int] = None) -> None:
    wr = _winreg()
    kind = kind if kind is not None else (wr.REG_SZ if isinstance(data, str) else wr.REG_DWORD)
    with wr.CreateKeyEx(_root(hive), subkey, 0, wr.KEY_SET_VALUE | wr.KEY_WOW64_64KEY) as key:
        wr.SetValueEx(key, name, 0, kind, data)


def delete_value(hive: str, subkey: str, name: str) -> None:
    wr = _winreg()
    try:
        with wr.OpenKey(_root(hive), subkey, 0, wr.KEY_SET_VALUE | wr.KEY_WOW64_64KEY) as key:
            wr.DeleteValue(key, name)
    except FileNotFoundError:
        pass  # ya no existe: nada que borrar


def is_applied(tweak: Tweak) -> bool:
    for hive, subkey, name, data in tweak.values:
        exists, current, _kind = read_value(hive, subkey, name)
        if not exists or current != data:
            return False
    return True


# --- Respaldo (rollback_state.json) -------------------------------------------------------------
def load_state() -> dict:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_FILE)  # escritura atómica: un corte no deja el respaldo a medias


def snapshot() -> dict:
    """Estado en vivo de cada ajuste ({clave: aplicado}) y las claves con respaldo pendiente."""
    return {"applied": {t.key: is_applied(t) for t in TWEAKS}, "backed_up": sorted(load_state())}


def apply(tweak: Tweak) -> dict:
    """Guarda los originales en el JSON (si aún no hay respaldo) y DESPUÉS escribe el registro."""
    state = load_state()
    if tweak.key not in state:
        originals = []
        for hive, subkey, name, _data in tweak.values:
            exists, data, kind = read_value(hive, subkey, name)
            originals.append({"hive": hive, "subkey": subkey, "name": name, "exists": exists,
                              "data": data, "type": kind})
        state[tweak.key] = {"values": originals,
                            "created_keys": [[h, s] for h, s in tweak.own_keys if not key_exists(h, s)]}
        save_state(state)
    for hive, subkey, name, data in tweak.values:
        write_value(hive, subkey, name, data)
    return {"tweak": tweak.key, "applied": [describe(v) for v in tweak.values], "backup": state[tweak.key]}


def revert(tweak: Tweak) -> dict:
    """Restaura el respaldo; sin respaldo, borra los valores (comportamiento por defecto de Windows)."""
    state = load_state()
    backup = state.get(tweak.key)
    if backup:
        for item in backup["values"]:
            if item["exists"]:
                write_value(item["hive"], item["subkey"], item["name"], item["data"], item["type"])
            else:
                delete_value(item["hive"], item["subkey"], item["name"])
        drop = [tuple(k) for k in backup.get("created_keys", [])]
    else:
        for hive, subkey, name, _data in tweak.values:
            delete_value(hive, subkey, name)
        drop = list(tweak.own_keys)
    wr = _winreg()
    for hive, subkey in drop:  # de la más profunda a la raíz; solo si está vacía
        try:
            wr.DeleteKey(_root(hive), subkey)
        except OSError:
            pass
    state.pop(tweak.key, None)
    save_state(state)
    return {"tweak": tweak.key, "restored": backup or "valores por defecto de Windows"}


# --- Acciones sin estado ------------------------------------------------------------------------
def purge_temp() -> dict:
    """Ficheros no bloqueados de %TEMP% y C:\\Windows\\Temp (los que estén en uso se omiten)."""
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    total = {"eliminados": 0, "omitidos": 0, "bytes": 0, "dirs": []}
    for base in dict.fromkeys((temp_dir(), os.path.join(windir, "Temp"))):
        res = clean_temp(base)
        if res.get("ok"):
            total["dirs"].append(base)
            for k in ("eliminados", "omitidos", "bytes"):
                total[k] += res[k]
    return total


def debloat() -> dict:
    """Quita para el usuario actual los paquetes Appx de BLOATWARE que estén instalados."""
    names = ",".join(f"'{n}'" for n in BLOATWARE)
    script = (f"$removed = @(); foreach ($n in @({names})) {{ Get-AppxPackage -Name $n | ForEach-Object {{ "
              "try { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction Stop; $removed += $n } "
              "catch {} } }; Write-Output ($removed -join ',')")
    rc, out, err = powershell_raw(script, timeout=300)
    if rc != 0:
        raise OSError(err.strip() or f"PowerShell terminó con código {rc}")
    removed = [n for n in out.strip().split(",") if n]
    return {"removed": removed, "requested": list(BLOATWARE)}


__all__ = ["IS_WINDOWS", "TWEAKS", "BY_KEY", "BLOATWARE", "STATE_FILE", "Tweak", "apply", "revert",
           "snapshot", "load_state", "describe", "purge_temp", "debloat"]
