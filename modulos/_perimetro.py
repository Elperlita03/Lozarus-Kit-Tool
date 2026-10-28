"""
modulos/_perimetro.py · LOZARUS KIT TOOL

Motor del PERÍMETRO de red (página «Endurecimiento de Red y Perímetro»):
  · firewall_profiles(): estado REAL de cada perfil del Firewall de Windows (activado y acciones
    predeterminadas de entrada y salida) desde el almacén activo; el registro como alternativa.
  · profile_fix_commands(): comandos netsh exactos para encender los perfiles apagados y bloquear la
    entrada por defecto, conservando la política de salida que haya.
  · containment_rules() / remove_rule(): reglas de contención creadas por Lozarus (bloqueos de puerto,
    ocultamiento ICMP, Guardia y cuarentena) y su retirada quirúrgica. Nunca toca reglas ajenas.
Las funciones puras (clasificación, comandos, veredicto) se prueban sin Windows. Sin Qt.
"""

from __future__ import annotations

import subprocess
from typing import Dict, List, Sequence, Tuple

from ._base import CheckSkipped, CommandError, IS_WINDOWS
from ._contencion import FIREWALL_GROUP as QUARANTINE_GROUP
from ._defensa_local import ICMP_GROUP
from ._utilidades import as_list, powershell, ps_string_array, reg_get, run_cmd

# (nombre en Windows, etiqueta, perfil de netsh)
PROFILES = (("Domain", "Dominio", "domainprofile"), ("Private", "Privado", "privateprofile"),
            ("Public", "Público", "publicprofile"))
RULE_PREFIX = "Lozarus"
LOOPBACK = ("127.", "::1", "localhost")


def _normalize(name: str, enabled: bool, inbound: str, outbound: str) -> dict:
    label, netsh = next(((lbl, ns) for n, lbl, ns in PROFILES if n == name), (name, ""))
    return {"name": name, "label": label, "netsh": netsh, "enabled": bool(enabled),
            "inbound_block": str(inbound) != "Allow",      # NotConfigured = Block (valor por defecto)
            "outbound_block": str(outbound) == "Block"}


def _profiles_from_registry() -> List[dict]:
    """Alternativa sin PowerShell: configuración local y GPO leídas del registro (sin privilegios)."""
    base = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    gpo = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"
    rows = []
    for name, local_key, gpo_key in (("Domain", "DomainProfile", "DomainProfile"),
                                     ("Private", "StandardProfile", "PrivateProfile"),
                                     ("Public", "PublicProfile", "PublicProfile")):
        def value(field, default):
            current = reg_get(f"{gpo}\\{gpo_key}", field)
            return current if current is not None else reg_get(f"{base}\\{local_key}", field, default)
        rows.append(_normalize(name, value("EnableFirewall", 1),
                               "Allow" if value("DefaultInboundAction", 1) == 0 else "Block",
                               "Block" if value("DefaultOutboundAction", 0) == 1 else "Allow"))
    return rows


def firewall_profiles() -> List[dict]:
    """Perfiles Dominio/Privado/Público con su estado real. Lanza OSError fuera de Windows."""
    if not IS_WINDOWS:
        raise OSError("El Firewall de Windows solo existe en Windows")
    try:
        data = powershell("Out-Json @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, "
                          "@{n='Enabled';e={[string]$_.Enabled}}, @{n='In';e={[string]$_.DefaultInboundAction}}, "
                          "@{n='Out';e={[string]$_.DefaultOutboundAction}})")
        rows = [_normalize(str(p.get("Name")), p.get("Enabled") == "True", p.get("In"), p.get("Out"))
                for p in as_list(data) if isinstance(p, dict)]
    except (CommandError, CheckSkipped):
        rows = []
    rows = rows or _profiles_from_registry()
    order = [name for name, _l, _n in PROFILES]
    return sorted(rows, key=lambda r: order.index(r["name"]) if r["name"] in order else 9)


def perimeter_verdict(profiles: Sequence[dict]) -> dict:
    """Resumen puro: perfiles activos, apagados y con la entrada abierta."""
    off = [p["label"] for p in profiles if not p["enabled"]]
    open_in = [p["label"] for p in profiles if p["enabled"] and not p["inbound_block"]]
    active = sum(1 for p in profiles if p["enabled"])
    return {"active": active, "total": len(profiles), "off": off, "open_inbound": open_in,
            "protected": bool(profiles) and not off and not open_in}


def profile_fix_commands(profiles: Sequence[dict]) -> List[Tuple[str, ...]]:
    """netsh exacto para cada perfil con problemas (la salida conserva su política actual)."""
    cmds: List[Tuple[str, ...]] = []
    for p in profiles:
        if not p.get("netsh"):
            continue
        if not p["enabled"]:
            cmds.append(("netsh", "advfirewall", "set", p["netsh"], "state", "on"))
        if not p["inbound_block"]:
            out = "blockoutbound" if p["outbound_block"] else "allowoutbound"
            cmds.append(("netsh", "advfirewall", "set", p["netsh"], "firewallpolicy", f"blockinbound,{out}"))
    return cmds


def run_commands(cmds: Sequence[Sequence[str]]) -> List[Tuple[str, bool, str]]:
    """Ejecuta cada comando (un fallo no detiene los demás). [(comando, ok, mensaje)]. No lanza."""
    from ._mitigacion import _sys32
    results = []
    for cmd in cmds:
        line = subprocess.list2cmdline(cmd)
        try:
            rc, out, err = run_cmd([_sys32(cmd[0])] + list(cmd[1:]), timeout=60)
            text = [ln.strip() for ln in (out + "\n" + err).splitlines() if ln.strip()]
            results.append((line, rc == 0, text[-1] if (text and rc) else ""))
        except Exception as exc:  # noqa: BLE001  (herramienta ausente o tiempo agotado)
            results.append((line, False, f"{type(exc).__name__}: {exc}"))
    return results


# --- Reglas de contención de Lozarus -------------------------------------------------------------
def rule_kind(rule: dict) -> str:
    name, group = rule.get("name", ""), rule.get("group", "")
    if group == ICMP_GROUP:
        return "Ocultamiento ICMP"
    if group == QUARANTINE_GROUP or name.startswith("Lozarus Quarantine"):
        return "Cuarentena"
    if "Guardia" in name:
        return "Guardia en Vivo"
    if "Bloqueo" in name:
        return "Bloqueo de puerto"
    return "Regla de Lozarus"


def removable(rule: dict) -> bool:
    """La cuarentena se levanta desde su propio control (restaura los perfiles): aquí no se toca."""
    return rule.get("name", "").startswith(RULE_PREFIX) and rule_kind(rule) != "Cuarentena"


def containment_rules() -> List[dict]:
    """Reglas del firewall cuyo nombre empieza por «Lozarus», con su filtro de protocolo y puerto."""
    if not IS_WINDOWS:
        raise OSError("El Firewall de Windows solo existe en Windows")
    data = powershell(r"""
Out-Json @(Get-NetFirewallRule -DisplayName 'Lozarus*' -ErrorAction SilentlyContinue | ForEach-Object {
    $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    @{ name = [string]$_.DisplayName; group = [string]$_.Group; dir = [string]$_.Direction;
       action = [string]$_.Action; enabled = [string]$_.Enabled; proto = [string]$pf.Protocol;
       port = [string](@($pf.LocalPort) -join ',') }
})
""", timeout=90)
    rules = []
    for item in as_list(data):
        if isinstance(item, dict) and str(item.get("name", "")).startswith(RULE_PREFIX):
            rule = {k: str(item.get(k) or "") for k in ("name", "group", "dir", "action", "enabled", "proto", "port")}
            rule["kind"] = rule_kind(rule)
            rules.append(rule)
    return sorted(rules, key=lambda r: (r["kind"], r["name"]))


def remove_rule(display_name: str) -> Dict[str, str]:
    """Elimina las reglas con ese nombre EXACTO (sin comodines). Solo reglas «Lozarus…»."""
    if not display_name.startswith(RULE_PREFIX):
        raise ValueError(f"Solo se retiran reglas creadas por Lozarus, no «{display_name}»")
    if not IS_WINDOWS:
        raise OSError("El Firewall de Windows solo existe en Windows")
    script = ("try { foreach ($n in " + ps_string_array([display_name]) + ") { "
              "Remove-NetFirewallRule -DisplayName ([WildcardPattern]::Escape($n)) -ErrorAction Stop }; "
              "Out-Json @{ ok = $true } } catch { Out-Json @{ ok = $false; error = [string]$_.Exception.Message } }")
    result = powershell(script, timeout=60) or {}
    if not result.get("ok"):
        raise PermissionError(result.get("error") or "No se pudo retirar la regla (requiere Administrador)")
    return {"removed": display_name}


def exposed(ip: str) -> bool:
    """¿Escucha fuera de este equipo? 0.0.0.0 y :: = todas las interfaces. Función pura."""
    ip = (ip or "").strip().lower()
    return bool(ip) and ip not in ("—", "-") and not ip.startswith(LOOPBACK)


__all__ = ["PROFILES", "firewall_profiles", "perimeter_verdict", "profile_fix_commands", "run_commands",
           "containment_rules", "remove_rule", "rule_kind", "removable", "exposed"]
