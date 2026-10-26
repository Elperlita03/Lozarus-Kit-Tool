# -*- coding: utf-8 -*-
"""
Núcleo común de los plugins: modelo de datos (severidades y hallazgos), excepciones,
contexto de auditoría y la clase base AuditModule de la que heredan todos los módulos.
Este fichero empieza por "_", así que el cargador no lo trata como un plugin.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
ADMIN_NAME = "Administrador" if IS_WINDOWS else "root"


# ===========================================================================
# MODELO DE DATOS: severidades, hallazgos y excepciones
# ===========================================================================
class Severity(Enum):
    PASS = "PASS"
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    SKIP = "SKIP"


# Alias cortos para que los módulos sean más legibles
PASS, INFO, WARNING, CRITICAL, SKIP = (
    Severity.PASS, Severity.INFO, Severity.WARNING, Severity.CRITICAL, Severity.SKIP,
)


@dataclass
class Finding:
    """Resultado individual de una comprobación."""
    module: str
    severity: Severity
    title: str
    detail: str = ""
    recommendation: str = ""
    check: str = ""                 # comprobación que lo generó (la rellena AuditModule.run)
    key: str = ""                   # identificador estable opcional para el modo --diff
    metric: Optional[int] = None    # valor comparable entre ejecuciones (p. ej. nº de intentos)

    def identity(self) -> str:
        """Identificador estable entre ejecuciones: la clave explícita o el título sin cifras."""
        if self.key:
            return self.key
        return re.sub(r"\s+", " ", re.sub(r"\d+", "#", self.title.lower())).strip()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(module=data.get("module", ""), severity=Severity(data["severity"]),
                   title=data.get("title", ""), detail=data.get("detail") or "",
                   recommendation=data.get("recommendation") or "", check=data.get("check") or "",
                   key=data.get("key") or "", metric=data.get("metric"))


class CheckSkipped(Exception):
    """La comprobación no puede ejecutarse (permisos, SO o herramienta ausente)."""


class CommandError(Exception):
    """Un comando del sistema falló o devolvió una salida inesperada."""


class Report:
    """
    Acumula los hallazgos de una auditoría y calcula la puntuación. Cada hallazgo se
    notifica en tiempo real a `console`, la interfaz que esté en uso: la consola de
    auditor.py o el puente de eventos de gui_qt.py (solo necesita finding() y check_started()).
    """

    def __init__(self, console: Any):
        self.console = console
        self.findings: List[Finding] = []
        self.modules: Dict[str, str] = {}  # clave -> título, en orden de ejecución

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.console.finding(finding)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    def score(self) -> int:
        """Puntuación heurística: % de comprobaciones superadas, donde cada WARNING pesa 1
        y cada CRITICAL pesa 3 (INFO y SKIP no cuentan)."""
        passed, warn, crit = self.count(PASS), self.count(WARNING), self.count(CRITICAL)
        total = passed + warn + 3 * crit
        return round(100 * passed / total) if total else 100


@dataclass
class AuditContext:
    """Estado compartido entre módulos (argumentos, informe y datos cacheados)."""
    args: argparse.Namespace
    report: Any  # auditor.Report: acumula hallazgos y conoce la consola
    is_admin: bool
    facts: Dict[str, Any] = field(default_factory=dict)

    def cached(self, key: str, factory: Callable[[], Any]) -> Any:
        if key not in self.facts:
            self.facts[key] = factory()
        return self.facts[key]


def first_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


# ===========================================================================
# CLASE BASE DE LOS MÓDULOS
# ===========================================================================
class AuditModule:
    """
    Clase base de todos los plugins. Cada plugin es una subclase con un `key`
    único (lo que se escribe en -m), un `title` y una `description`, y define
    `checks()`, la lista de métodos de comprobación aplicables al SO actual.

    La primera línea del docstring de cada método sirve de etiqueta si la
    comprobación falla. `run()` aísla cada comprobación: un error de permisos
    o un comando ausente produce un [SKIP] y la auditoría continúa.

    `add()` acepta dos datos opcionales para el modo --diff: `key`, un
    identificador estable cuando una comprobación emite varios hallazgos, y
    `metric`, un número comparable entre ejecuciones (p. ej. nº de intentos).

    Las subclases sin `key` se consideran clases intermedias y el cargador no
    las ejecuta. Plantilla de ejemplo: modulos/_plantilla.py.
    """
    key = ""
    title = ""
    description = ""
    origin = ""  # fichero del que se cargó (lo rellena el cargador de auditor.py)

    def __init__(self, ctx: AuditContext):
        self.ctx = ctx
        self._check = ""  # nombre del método de comprobación en curso

    def add(self, severity: Severity, title: str, detail: str = "", recommendation: str = "",
            key: str = "", metric: Optional[int] = None) -> None:
        self.ctx.report.add(Finding(self.key, severity, title, detail, recommendation,
                                    check=self._check, key=key, metric=metric))

    def require_admin(self) -> None:
        if not self.ctx.is_admin:
            raise CheckSkipped(f"Requiere privilegios de {ADMIN_NAME}. Vuelve a ejecutar el script elevado.")

    def checks(self) -> List[Callable[[], None]]:
        return []

    def run(self) -> None:
        self.ctx.report.modules[self.key] = self.title
        console = self.ctx.report.console
        checks = self.checks()
        if not checks:
            self.add(SKIP, "Módulo no compatible con este sistema operativo", platform.system())
            return
        for check in checks:
            label = first_line(check.__doc__ or check.__name__)
            self._check = check.__name__
            console.check_started(self.title, label)  # alimenta el spinner de progreso
            try:
                check()
            except CheckSkipped as exc:
                self.add(SKIP, label, str(exc))
            except PermissionError as exc:
                self.add(SKIP, label, f"Permiso denegado ({exc}). Ejecuta como {ADMIN_NAME}.")
            except CommandError as exc:
                self.add(SKIP, label, f"No se pudo consultar: {exc}")
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # nunca dejamos que una comprobación tumbe la auditoría
                self.add(SKIP, label, f"Error inesperado ({type(exc).__name__}): {exc}")
