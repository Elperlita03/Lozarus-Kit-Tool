# -*- coding: utf-8 -*-
"""
Defensa local de Lozarus Kit Tool: endurecimiento y detección, puramente defensivos y sobre
ESTE equipo. Nada de esto ataca, atrapa ni toma represalias contra otros: solo endurece el host
y detecta/avisa.

  · Endurecimiento de red (ICMP)   oculta el equipo en la red local añadiendo una regla del
                                   Firewall de Windows que bloquea el eco ICMP entrante (ping).
                                   Reversible (elimina la regla). Requiere Administrador.

  · Honeypot de detección          despliega archivos señuelo («canary files») y los vigila: si
                                   alguno se modifica o se elimina, lo registra y lo reporta. No
                                   realiza NINGUNA acción contra el proceso que los toque.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from typing import Dict, List, Optional

from ._base import CheckSkipped, CommandError, IS_WINDOWS
from ._forense import FORENSICS_DIR, sha256_of
from ._utilidades import as_list, powershell

# ===========================================================================
# ENDURECIMIENTO DE RED · ocultar el equipo (bloquear eco ICMP entrante)
# ===========================================================================
ICMP_GROUP = "Lozarus Defensa Local"
ICMP_RULE = "Lozarus - Ocultar en red (eco ICMP entrante)"


def icmp_block_active() -> bool:
    """¿Está puesta la regla que oculta el equipo frente a ping? (solo lectura)."""
    if not IS_WINDOWS:
        return False
    try:
        data = powershell("Out-Json @(Get-NetFirewallRule -Group '__GROUP__' -ErrorAction SilentlyContinue | "
                          "Select-Object -First 1 @{n='n';e={[string]$_.DisplayName}})".replace("__GROUP__", ICMP_GROUP))
        return bool(as_list(data))
    except (CommandError, CheckSkipped):
        return False


def set_icmp_block(block: bool) -> dict:
    """
    Activa o quita el ocultamiento en red. Al activarlo añade una regla de Firewall que bloquea
    el eco ICMPv4 entrante (tipo 8); al desactivarlo la elimina. Requiere Administrador.
    """
    if not IS_WINDOWS:
        raise OSError("El endurecimiento ICMP solo está disponible en Windows")
    if block:
        script = r"""
try {
    if (-not (Get-NetFirewallRule -Group '__GROUP__' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName '__RULE__' -Group '__GROUP__' -Direction Inbound `
            -Protocol ICMPv4 -IcmpType 8 -Action Block -Profile Any -ErrorAction Stop | Out-Null
    }
    Out-Json @{ ok = $true }
} catch { Out-Json @{ ok = $false; error = [string]$_.Exception.Message } }
"""
    else:
        script = r"""
try {
    Remove-NetFirewallRule -Group '__GROUP__' -ErrorAction SilentlyContinue
    Out-Json @{ ok = $true }
} catch { Out-Json @{ ok = $false; error = [string]$_.Exception.Message } }
"""
    script = script.replace("__GROUP__", ICMP_GROUP).replace("__RULE__", ICMP_RULE)
    result = powershell(script, timeout=60) or {}
    if not result.get("ok"):
        raise PermissionError(result.get("error") or "No se pudo cambiar la regla ICMP (requiere Administrador)")
    return {"blocked": block}


# ===========================================================================
# HONEYPOT DE DETECCIÓN · archivos señuelo (canary files)
# ===========================================================================
HONEYPOT_DIR = os.path.join(FORENSICS_DIR, "Honeypot")
STATE_FILE = os.path.join(FORENSICS_DIR, ".honeypot_estado.json")

# Señuelos con nombres «apetecibles» para un intruso. Son inofensivos: texto de relleno.
DECOYS = [
    ("Credenciales_Banco.txt", "Entidad: ****\nUsuario: ****\nClave: ****\n(fichero señuelo de Lozarus)\n"),
    ("Passwords_Export.csv", "sitio,usuario,clave\n(fichero señuelo de Lozarus)\n"),
    ("Backup_Wallet.dat", "<respaldo de cartera - fichero señuelo de Lozarus>\n"),
    ("Config_VPN_Empresa.txt", "servidor=****\nclave_precompartida=****\n(fichero señuelo de Lozarus)\n"),
]


def _load() -> Optional[dict]:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _save(state: dict) -> None:
    os.makedirs(FORENSICS_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)


def honeypot_active() -> bool:
    return bool(_load())


def deploy_canaries() -> dict:
    """Crea los archivos señuelo y guarda su huella (SHA-256, tamaño, fecha) como línea base."""
    os.makedirs(HONEYPOT_DIR, exist_ok=True)
    baseline: Dict[str, dict] = {}
    for name, content in DECOYS:
        path = os.path.join(HONEYPOT_DIR, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        st = os.stat(path)
        baseline[path] = {"sha256": sha256_of(path)[0], "size": st.st_size, "mtime": st.st_mtime}
    _save({"desplegado": dt.datetime.now().isoformat(timespec="seconds"), "canarios": baseline})
    return {"count": len(baseline), "dir": HONEYPOT_DIR}


def scan_canaries() -> dict:
    """
    Revisa los señuelos y devuelve el estado de cada uno. Detecta MODIFICACIÓN (cambia el hash,
    el tamaño o la fecha) y ELIMINACIÓN. Es puramente observación: no toca ningún proceso.
    """
    state = _load()
    if not state:
        return {"active": False, "eventos": []}
    eventos: List[dict] = []
    for path, base in state.get("canarios", {}).items():
        name = os.path.basename(path)
        if not os.path.exists(path):
            eventos.append({"canario": name, "estado": "ELIMINADO", "alerta": True})
            continue
        st = os.stat(path)
        changed = (st.st_size != base["size"] or abs(st.st_mtime - base["mtime"]) > 1
                   or sha256_of(path)[0] != base["sha256"])
        eventos.append({"canario": name, "estado": "MODIFICADO" if changed else "intacto", "alerta": changed})
    return {"active": True, "desplegado": state.get("desplegado"), "eventos": eventos}


def remove_canaries() -> dict:
    """Retira los señuelos y limpia el estado."""
    state = _load() or {}
    removed = 0
    for path in state.get("canarios", {}):
        try:
            os.remove(path)
            removed += 1
        except OSError:
            pass
    try:
        os.remove(STATE_FILE)
    except OSError:
        pass
    return {"removed": removed}
