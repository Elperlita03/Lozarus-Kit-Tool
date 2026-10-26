# -*- coding: utf-8 -*-
"""
Cargador dinámico de plugins, compartido por todas las interfaces (auditor.py y gui_qt.py).
Este fichero empieza por "_", así que el propio cargador no lo trata como un plugin.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

from ._base import AuditModule

KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


@dataclass
class PluginError:
    """Fichero o clase de modulos/ que no se ha podido cargar, y por qué."""
    origin: str
    reason: str


def discover_modules() -> Tuple[List[type], List[PluginError]]:
    """
    Escanea la carpeta del paquete e importa cada fichero .py que no empiece por "_"
    (los que empiezan por "_" son utilidades compartidas, plantillas o plugins
    desactivados). Registra cada subclase de AuditModule con `key` definida en ese
    fichero, por orden de nombre de fichero (el prefijo numérico fija el orden de
    ejecución) y, dentro de cada fichero, por orden de definición. Un plugin roto no
    impide que funcionen los demás: se devuelve en la lista de errores.
    """
    package = importlib.import_module(__package__)
    found: List[type] = []
    errors: List[PluginError] = []
    owners: Dict[str, str] = {}  # clave -> fichero que la registró
    for info in sorted(pkgutil.iter_modules(package.__path__), key=lambda m: m.name):
        if info.name.startswith("_") or info.ispkg:
            continue
        filename = f"{info.name}.py"
        try:
            plugin = importlib.import_module(f"{__package__}.{info.name}")
        except Exception as exc:
            errors.append(PluginError(filename, f"no se pudo importar ({type(exc).__name__}: {exc})"))
            continue
        # vars() conserva el orden de definición; se descartan las clases importadas de otro fichero
        classes = [obj for obj in vars(plugin).values()
                   if inspect.isclass(obj) and issubclass(obj, AuditModule)
                   and obj.__module__ == plugin.__name__ and obj.key]
        if not classes:
            errors.append(PluginError(filename, "no define ningún módulo (subclase de AuditModule con 'key')"))
            continue
        for cls in classes:
            where = f"{filename} · {cls.__name__}"
            if not KEY_PATTERN.match(cls.key):
                errors.append(PluginError(where, f"clave '{cls.key}' no válida (usa minúsculas, números, '-' o '_')"))
            elif cls.key in owners:
                errors.append(PluginError(where, f"clave '{cls.key}' duplicada: ya la usa {owners[cls.key]}"))
            else:
                cls.origin = filename
                owners[cls.key] = filename
                found.append(cls)
    return found, errors


def count_checks(module_cls: type) -> str:
    """Nº de comprobaciones que el módulo aplica en este SO (checks() no ejecuta nada)."""
    try:
        return str(len(module_cls(None).checks()))
    except Exception:
        return "?"
