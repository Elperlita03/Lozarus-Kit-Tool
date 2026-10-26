# -*- coding: utf-8 -*-
"""
Plugin SOFTWARE: inventario de programas instalados y detección de software de riesgo.

Lee (solo lectura) las entradas de desinstalación del registro, las mismas que
muestra "Aplicaciones instaladas" de Windows:
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall               (64 bits)
    HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall   (32 bits)
    HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall               (usuario actual)
y las compara con la lista negra RISK_RULES. Para ampliarla basta con añadir
una regla a la lista: la primera regla que coincide con un programa es la que
se aplica, por eso las CRITICAL van primero.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ._base import CRITICAL, INFO, IS_WINDOWS, PASS, WARNING, AuditModule, CheckSkipped, Severity

if IS_WINDOWS:
    import winreg

_UNINSTALL_ADVICE = ("Si no lo necesitas, desinstálalo desde Configuración > Aplicaciones > "
                     "Aplicaciones instaladas.")


@dataclass(frozen=True)
class RiskRule:
    name: str                                # nombre legible en el informe
    pattern: str                             # regex (sin distinguir mayúsculas) contra el nombre del programa
    severity: Severity
    reason: str
    advice: str = _UNINSTALL_ADVICE
    below: Optional[Tuple[int, ...]] = None  # solo es de riesgo si su versión es inferior a esta


# Patrón común de Java: captura la versión principal en el grupo "v"
# ("Java 8 Update 401", "Java(TM) 7 Update 80", "Java SE Development Kit 8 Update 202"...)
_JAVA = r"^java(?:\(tm\))?(?:\s+se)?(?:\s+development\s+kit|\s+runtime\s+environment)?\s+(?P<v>\d+)\b"

RISK_RULES: List[RiskRule] = [
    # --- CRITICAL: software obsoleto sin soporte ni parches de seguridad -------------------
    RiskRule("Adobe Flash Player", r"\bflash\s+player\b", CRITICAL,
             "Sin soporte desde el 31/12/2020: acumula vulnerabilidades críticas que nunca se corregirán.",
             "Desinstálalo con el desinstalador oficial de Adobe Flash Player."),
    RiskRule("Java 7 o anterior", _JAVA, CRITICAL,
             "Java SE 7 y anteriores no reciben actualizaciones públicas: vulnerabilidades explotables "
             "desde el navegador y documentos.",
             "Desinstálalo; si una aplicación lo necesita, migra a una versión LTS actual (Java 21 o 25).",
             below=(8,)),
    RiskRule("Adobe Shockwave Player", r"\bshockwave\b", CRITICAL, "Sin soporte desde abril de 2019."),
    RiskRule("Microsoft Silverlight", r"\bsilverlight\b", CRITICAL, "Sin soporte desde octubre de 2021."),
    RiskRule("Apple QuickTime para Windows", r"\bquicktime\b", CRITICAL,
             "Abandonado por Apple en 2016 con vulnerabilidades conocidas sin parchear."),
    RiskRule("Adobe Reader 7 a XI", r"\badobe reader (?:xi|x|9|8|7)\b", CRITICAL,
             "Versión de Adobe Reader sin soporte (la XI terminó en 2017).",
             "Desinstálalo y usa Adobe Acrobat Reader actual o el lector de PDF del navegador."),

    # --- WARNING: software dudoso, innecesario o en versión vulnerable ---------------------
    RiskRule("Java 8", _JAVA, WARNING,
             "Oracle aún publica parches de Java 8, pero el runtime amplía mucho la superficie de "
             "ataque y suele quedarse sin actualizar.",
             "Desinstálalo si no lo necesitas; si lo usas, mantenlo al día o migra a Java 21/25.",
             below=(9,)),
    RiskRule("uTorrent", r"(?:µ|μ|\bu)torrent\b", WARNING,
             "Cliente P2P que ha incluido adware y mineros de criptomonedas; las descargas P2P son un "
             "vector habitual de malware."),
    RiskRule("BitTorrent", r"\bbittorrent\b", WARNING,
             "Cliente P2P del mismo fabricante que uTorrent, con el mismo historial de software incluido."),
    RiskRule("CCleaner", r"\bccleaner\b", WARNING,
             "Se distribuyó con una puerta trasera en 2017 (versión 5.33) y ofrece software adicional "
             "al instalar; Windows ya incluye 'Liberar espacio'."),
    RiskRule("Bonjour", r"\bbonjour\b", WARNING,
             "Servicio mDNS de Apple que se instala con iTunes y otros programas: anuncia el equipo en "
             "la red y abre puertos; innecesario si no usas dispositivos Apple en red."),
    RiskRule("Actualizador de drivers de terceros",
             r"\bdriver\s*(?:booster|easy|genius|reviver|support)\b|\bdriverpack\b", WARNING,
             "Instalan controladores no verificados y software adicional (programa potencialmente no deseado).",
             "Desinstálalo y actualiza los drivers con Windows Update o desde la web del fabricante."),
    RiskRule("Optimizador 'milagro' (PUP)", r"\badvanced\s+systemcare\b|\brestoro\b|\breimage\b", WARNING,
             "Programa potencialmente no deseado: alertas exageradas para vender licencias y cambios "
             "agresivos en el sistema."),
    RiskRule("WinRAR anterior a 7.13", r"^winrar\b", WARNING,
             "Las versiones anteriores a 7.13 tienen vulnerabilidades explotadas activamente "
             "(p. ej. CVE-2025-8088) y WinRAR no se actualiza solo.",
             "Actualiza WinRAR a la última versión desde rarlab.com.", below=(7, 13)),
    RiskRule("7-Zip anterior a 24.09", r"^7-zip\b", WARNING,
             "Las versiones anteriores a 24.09 permiten saltarse la protección Mark-of-the-Web "
             "(CVE-2025-0411), explotada activamente; 7-Zip no se actualiza solo.",
             "Actualiza 7-Zip a la última versión desde 7-zip.org.", below=(24, 9)),
]

# Ramas del registro con los programas instalados: (etiqueta, colmena, ruta)
UNINSTALL_ROOTS = [
    ("HKLM 64 bits", "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM 32 bits", "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("usuario actual", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def _value(key, name: str):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def read_installed_programs() -> Tuple[List[Dict[str, str]], List[str], int]:
    """
    Lee las entradas de desinstalación en modo solo lectura (KEY_READ). Igual que
    "Aplicaciones instaladas", omite componentes del sistema y actualizaciones.
    Devuelve (programas sin duplicados, ramas inaccesibles, entradas ilegibles).
    """
    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY  # vista de 64 bits aunque Python sea de 32
    programs: Dict[Tuple[str, str], Dict[str, str]] = {}
    failed_roots: List[str] = []
    unreadable = 0
    for label, hive, path in UNINSTALL_ROOTS:
        try:
            root = winreg.OpenKey(hives[hive], path, 0, access)
        except FileNotFoundError:
            continue  # p. ej. WOW6432Node no existe en Windows de 32 bits
        except OSError as exc:
            failed_roots.append(f"{label} ({exc.strerror or exc})")
            continue
        with root:
            index = 0
            while True:
                try:
                    subkey = winreg.EnumKey(root, index)
                except OSError:
                    break  # no quedan subclaves
                index += 1
                try:
                    with winreg.OpenKey(root, subkey, 0, access) as entry:
                        name = str(_value(entry, "DisplayName") or "").strip()
                        if (not name or _value(entry, "SystemComponent") == 1 or _value(entry, "ParentKeyName")
                                or str(_value(entry, "ReleaseType") or "") in ("Update", "Hotfix", "Security Update")):
                            continue
                        version = str(_value(entry, "DisplayVersion") or "").strip()
                        programs.setdefault((name.lower(), version), {
                            "name": name, "version": version,
                            "publisher": str(_value(entry, "Publisher") or "").strip(), "origin": label})
                except OSError:
                    unreadable += 1
    return list(programs.values()), failed_roots, unreadable


def _version_tuple(text: str) -> Optional[Tuple[int, ...]]:
    numbers = re.findall(r"\d+", text or "")
    return tuple(int(n) for n in numbers[:4]) or None


def match_rule(program: Dict[str, str]) -> Optional[RiskRule]:
    """Primera regla de la lista negra que coincide con el programa (o None)."""
    for rule in RISK_RULES:
        found = re.search(rule.pattern, program["name"], re.IGNORECASE)
        if not found:
            continue
        if rule.below:
            raw = found.groupdict().get("v") or program["version"] or program["name"][found.end():]
            version = _version_tuple(raw)
            if version is None or version >= rule.below:
                continue  # versión desconocida o suficientemente reciente
        return rule
    return None


class SoftwareModule(AuditModule):
    key = "software"
    title = "SOFTWARE INSTALADO"
    description = "Programas instalados: software obsoleto sin soporte, dudoso o en versión vulnerable"

    def checks(self):
        return [self.check_installed_software] if IS_WINDOWS else []

    def check_installed_software(self):
        """Software instalado de riesgo"""
        programs, failed_roots, unreadable = read_installed_programs()
        if not programs and failed_roots:
            raise CheckSkipped("No se pudo leer el registro de programas instalados: " + "; ".join(failed_roots))

        notes = ["Fuentes: HKLM (64 y 32 bits) y HKCU (usuario que ejecuta la auditoría)."]
        if failed_roots:
            notes.append("Ramas no accesibles: " + "; ".join(failed_roots))
        if unreadable:
            notes.append(f"{unreadable} entrada(s) no se pudieron leer.")
        self.add(INFO, f"Inventario: {len(programs)} programas instalados analizados", "\n".join(notes))

        hits: Dict[str, Tuple[RiskRule, List[str]]] = {}
        for program in sorted(programs, key=lambda p: p["name"].lower()):
            rule = match_rule(program)
            if rule:
                label = f"{program['name']} {program['version']}".strip()
                if program["publisher"]:
                    label += f" ({program['publisher']})"
                hits.setdefault(rule.name, (rule, []))[1].append(label)

        if not hits:
            self.add(PASS, "No hay software de riesgo instalado",
                     "Lista negra revisada: " + ", ".join(rule.name for rule in RISK_RULES) + ".")
            return
        prefix = {CRITICAL: "Software sin soporte instalado", WARNING: "Software de riesgo instalado"}
        for rule, entries in sorted(hits.values(), key=lambda hit: hit[0].severity is not CRITICAL):
            self.add(rule.severity, f"{prefix[rule.severity]}: {rule.name}",
                     f"{rule.reason}\nDetectado: " + "; ".join(entries), rule.advice,
                     key=f"software:{rule.name}")
