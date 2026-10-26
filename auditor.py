#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auditor.py · Auditor de seguridad local en modo SOLO LECTURA (núcleo y CLI)
==========================================================================

Herramienta de diagnóstico de ciberseguridad para Windows (soporte completo)
y Linux (soporte parcial) con arquitectura de plugins:

    AuditorTool/
    ├── auditor.py          núcleo: cargador de plugins, interfaz, informes y CLI
    └── modulos/            plugins de escaneo (se detectan automáticamente)
        ├── _base.py        clase base AuditModule y modelo de datos
        ├── _utilidades.py  utilidades de solo lectura compartidas
        ├── _plantilla.py   plantilla para crear un plugin nuevo
        ├── 01_sistema.py
        └── ...

Al arrancar, el núcleo importa cada fichero .py de modulos/ que no empiece
por "_" y registra las subclases de AuditModule que define. El prefijo
numérico del fichero fija el orden de ejecución. Para añadir una capacidad
basta con soltar un fichero nuevo en modulos/; para desactivarla, renombrarlo
con "_" delante. Un plugin con errores no detiene el programa: se avisa y se
continúa con el resto.

Niveles del informe:
    🟢 [PASS]      configuración segura
    🟡 [WARNING]   riesgo potencial o configuración mejorable
    🔴 [CRITICAL]  vulnerabilidad alta o servicio peligroso expuesto
    🔵 [INFO]      dato informativo
    ⚪ [SKIP]      comprobación omitida (permisos, SO o herramienta ausente)

Modos de uso:
    sin argumentos        menú interactivo
    -a  /  -m MÓDULO...   ejecución directa, sin menú
    --listar              muestra los módulos detectados y sale
    --diff                solo las novedades respecto a la ejecución anterior
    --html / --json       exporta el informe (dashboard HTML autónomo / JSON)

Dependencias: solo biblioteca estándar. Opcionales (mejoran el resultado):
    pip install rich psutil
      rich    interfaz avanzada: banner, barra de progreso, paneles y tablas
              (sin ella se usa la salida ANSI clásica)
      psutil  enumeración precisa de sockets y procesos

Garantía de solo lectura: los plugins únicamente consultan el registro, leen
ficheros de configuración/log y ejecutan comandos de consulta. No se cambia
ninguna configuración del sistema. El programa solo escribe sus propios
ficheros: los informes que pidas (--html / --json) y el estado de --diff.
El escaneo de red solo se hace si se pide con --escanear y únicamente contra
direcciones privadas o locales.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import getpass
import html
import json
import os
import platform
import re
import shutil
import socket
import sys
import textwrap
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# La carpeta de plugins va junto a este fichero, se ejecute desde donde se ejecute
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Motor compartido con gui_qt.py: modelo de datos, informe y cargador de plugins
from modulos._base import (ADMIN_NAME, CRITICAL, INFO, IS_WINDOWS, PASS, SKIP, WARNING,  # noqa: E402
                           AuditContext, AuditModule, Finding, Report, Severity)
from modulos._cargador import count_checks, discover_modules  # noqa: E402
from modulos._utilidades import HAS_PSUTIL, is_admin  # noqa: E402

# ---------------------------------------------------------------------------
# Dependencia opcional: rich (sin ella se usa la salida ANSI clásica)
# ---------------------------------------------------------------------------
try:
    from rich import box
    from rich.console import Console as RichTerminal, Group
    from rich.markup import escape
    from rich.padding import Padding
    from rich.panel import Panel
    from rich.progress import (BarColumn, MofNCompleteColumn, Progress, SpinnerColumn,
                               TextColumn, TimeElapsedColumn)
    from rich.progress_bar import ProgressBar
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

__version__ = "2.0.0"


# ===========================================================================
# SALIDA POR CONSOLA (rich si está instalado; si no, colores ANSI)
# ===========================================================================
class Console:
    """
    Salida clásica con secuencias ANSI. Se usa cuando 'rich' no está instalado y
    define la interfaz común: RichConsole redefine estos mismos métodos.
    """

    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    CYAN, MAGENTA = "\033[96m", "\033[95m"
    STYLE = {
        PASS: ("\033[92m", "🟢"),
        INFO: ("\033[96m", "🔵"),
        WARNING: ("\033[93m", "🟡"),
        CRITICAL: ("\033[91m", "🔴"),
        SKIP: ("\033[90m", "⚪"),
    }

    def __init__(self, color: bool = True, emoji: bool = True):
        encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
        self.unicode = "utf" in encoding          # si no, usamos caracteres ASCII
        self.emoji = emoji and self.unicode
        self.color = color and not os.environ.get("NO_COLOR") and self._enable_ansi()
        self.only_issues = False                  # --solo-problemas: oculta PASS e INFO
        self.show_findings = True                 # False en --diff: solo se muestran las novedades
        self.width = max(70, min(118, shutil.get_terminal_size((100, 24)).columns - 2))
        self.hline = "═" if self.unicode else "="
        self.arrow = "➜" if self.unicode else "->"
        self.ellipsis = "…" if self.unicode else "..."

    @staticmethod
    def _enable_ansi() -> bool:
        """Activa las secuencias ANSI (en Windows: ENABLE_VIRTUAL_TERMINAL_PROCESSING)."""
        if not sys.stdout.isatty():
            return False
        if not IS_WINDOWS:
            return True
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
        except Exception:
            pass
        return False

    def paint(self, text: str, *codes: str) -> str:
        if not self.color or not codes:
            return text
        return "".join(codes) + text + self.RESET

    def _fill(self, text: str, indent: int) -> str:
        return textwrap.fill(text, self.width, initial_indent=" " * indent,
                             subsequent_indent=" " * (indent + 2))

    def _icon(self, severity: Severity) -> str:
        return f"{self.STYLE[severity][1]} " if self.emoji else ""

    def _visible(self, f: Finding) -> bool:
        return self.show_findings and not (self.only_issues and f.severity in (PASS, INFO))

    def message(self, text: str, dim: bool = False) -> None:
        print(self.paint(f"  {text}", self.DIM) if dim else f"  {text}")

    def warn(self, text: str) -> None:
        print(f"  {self._icon(WARNING)}{self.paint(text, self.STYLE[WARNING][0])}")

    def plugin_table(self, rows: List[Tuple[str, str, str, str, str, str]]) -> None:
        """rows: (nº, clave, título, fichero, nº de comprobaciones en este SO, descripción)."""
        print()
        print(self.paint(f"  Módulos detectados en modulos/ ({len(rows)})", self.BOLD))
        for number, key, _title, origin, checks, description in rows:
            print(f"   {self.paint(number.rjust(2), self.CYAN, self.BOLD)}  {key.ljust(12)} {origin.ljust(18)} "
                  f"{checks.rjust(2)} comprob.  {self.paint(description, self.DIM)}")

    # --- Cabecera y menú interactivo ------------------------------------------
    def banner(self, info: List[Tuple[str, str, str]]) -> None:
        """info: filas (etiqueta, valor, tono) con tono '', 'ok' o 'warn'."""
        rule = self.hline * self.width
        print(self.paint(rule, self.CYAN))
        print(self.paint(f"  AUDITOR DE SEGURIDAD LOCAL v{__version__}  ·  modo solo lectura", self.BOLD))
        print(self.paint(rule, self.CYAN))
        tones = {"ok": self.STYLE[PASS][0], "warn": self.STYLE[WARNING][0]}
        for label, value, tone in info:
            print(f"  {label.rjust(11)}: {self.paint(value, tones[tone]) if tone in tones else value}")

    def menu(self, title: str, rows: List[Tuple[str, str, str]]) -> None:
        print()
        print(self.paint(f"  {title}", self.BOLD))
        for number, name, description in rows:
            print(f"   {self.paint(number.rjust(2), self.CYAN, self.BOLD)}  {name.ljust(20)} "
                  f"{self.paint(description, self.DIM)}")

    def ask(self, prompt: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        return input(f"  {prompt}{suffix}: ").strip() or default

    def confirm(self, prompt: str, default: bool = False) -> bool:
        return self.ask(f"{prompt} (s/n)", "s" if default else "n").lower().startswith(("s", "y"))

    # --- Progreso de la auditoría ---------------------------------------------
    def start(self, total: int) -> None:
        """Comienza la auditoría (RichConsole muestra aquí la barra de progreso)."""

    def module_started(self, index: int, total: int, module: "AuditModule") -> None:
        if not self.show_findings:  # modo --diff: una sola línea de progreso por módulo
            print(self.paint(f"  [{index}/{total}] {module.title}{self.ellipsis}", self.DIM))
            return
        head = f" [{index}/{total}] {module.title} "
        print()
        print(self.paint(head + self.hline * max(3, self.width - len(head)), self.BOLD, self.MAGENTA))
        print(self.paint(f"  {module.description}", self.DIM))

    def check_started(self, module_title: str, label: str) -> None:
        """Se llama antes de cada comprobación (RichConsole actualiza el spinner)."""

    def module_finished(self) -> None:
        """Se llama al terminar cada módulo (RichConsole avanza la barra)."""

    def stop(self) -> None:
        """Termina la auditoría (RichConsole retira la barra de progreso)."""

    # --- Resultados -------------------------------------------------------------
    def finding(self, f: Finding) -> None:
        if not self._visible(f):
            return
        color = self.STYLE[f.severity][0]
        label = self.paint(f"[{f.severity.value}]".ljust(11), color, self.BOLD)
        print(f"  {self._icon(f.severity)}{label} {f.title}")
        indent = 2 + (3 if self.emoji else 0) + 12
        for line in f.detail.splitlines():
            if line.strip():
                print(self._fill(line, indent))
        if f.recommendation and f.severity in (WARNING, CRITICAL):
            print(self.paint(self._fill(f"{self.arrow} {f.recommendation}", indent), color))

    def _heading(self, title: str) -> None:
        side = self.hline * ((self.width - len(title)) // 2)
        print()
        print(self.paint(side + title + side, self.BOLD, self.CYAN))

    def summary(self, report: "Report", elapsed: float, compact: bool = False) -> None:
        self._heading(" RESUMEN ")
        parts = [self._icon(sev) + self.paint(f"{sev.value}: {report.count(sev)}", self.STYLE[sev][0], self.BOLD)
                 for sev in (PASS, WARNING, CRITICAL, INFO, SKIP)]
        print("  " + "   ".join(parts))

        score = report.score()
        sev_color = self.STYLE[PASS if score >= 80 else WARNING if score >= 50 else CRITICAL][0]
        full, empty = ("█", "░") if self.unicode else ("#", "-")
        filled = round(30 * score / 100)
        bar = self.paint(full * filled, sev_color) + empty * (30 - filled)
        print(f"  Puntuación orientativa: {self.paint(f'{score}/100', sev_color, self.BOLD)}  [{bar}]")

        if not compact:
            for sev, heading in ((CRITICAL, "Hallazgos críticos (prioridad alta)"), (WARNING, "Advertencias")):
                items = [f for f in report.findings if f.severity is sev]
                if not items:
                    continue
                icon = self._icon(sev) or "- "
                print()
                print(self.paint(f"  {heading}:", self.BOLD))
                for f in items:
                    print(f"    {icon}{self.paint(f'[{f.module}]', self.STYLE[sev][0])} {f.title}")
        print()
        print(self.paint(f"  Duración: {elapsed:.1f} s · Resultados: {len(report.findings)}", self.DIM))

    def diff(self, changes: List["Change"], since: str) -> None:
        self._heading(" NOVEDADES ")
        if not changes:
            print("  " + self.paint(f"Sin novedades respecto a la ejecución de {since}.", self.STYLE[PASS][0]))
            return
        print(self.paint(f"  Cambios desde la ejecución de {since}:", self.DIM))
        indent = 2 + (3 if self.emoji else 0) + 10
        for c in changes:
            sev = c.severity if c.alert else PASS
            color = self.STYLE[sev][0]
            print(f"  {self._icon(sev)}{self.paint(c.kind.ljust(9), color, self.BOLD)} [{c.module}] {c.title}")
            print(self._fill(c.detail, indent))


class RichConsole(Console):
    """Interfaz avanzada con 'rich': banner, barra de progreso, paneles y tablas."""

    RICH = {PASS: "green", INFO: "cyan", WARNING: "yellow", CRITICAL: "red", SKIP: "bright_black"}

    def __init__(self, color: bool = True, emoji: bool = True):
        super().__init__(color=False, emoji=emoji)  # los colores los gestiona rich
        self.rc = RichTerminal(highlight=False, color_system="auto" if color else None)
        self.progress: Optional[Progress] = None
        self.task = None

    def _label(self, severity: Severity) -> Text:
        return Text(f"{self._icon(severity)}[{severity.value}]", style=f"bold {self.RICH[severity]}")

    def message(self, text: str, dim: bool = False) -> None:
        self.rc.print(Text(f"  {text}", style="bright_black" if dim else ""))

    def warn(self, text: str) -> None:
        self.rc.print(Text(f"  {self._icon(WARNING)}{text}", style="yellow"))

    def plugin_table(self, rows: List[Tuple[str, str, str, str, str, str]]) -> None:
        table = Table(title=f"Módulos detectados en modulos/ ({len(rows)})", title_justify="left",
                      title_style="bold", box=box.ROUNDED, header_style="bold")
        table.add_column("#", justify="right", style="bold cyan", no_wrap=True)
        table.add_column("Clave (-m)", style="bold", no_wrap=True)
        table.add_column("Fichero", style="bright_black", no_wrap=True)
        table.add_column("Checks", justify="right", no_wrap=True)
        table.add_column("Descripción", ratio=1, min_width=24)
        for number, key, _title, origin, checks, description in rows:
            table.add_row(number, key, origin, checks, description)
        self.rc.print()
        self.rc.print(table)

    # --- Cabecera y menú interactivo ------------------------------------------
    def banner(self, info: List[Tuple[str, str, str]]) -> None:
        head = Text.assemble(("AUDITOR DE SEGURIDAD LOCAL", "bold cyan"), (f"   v{__version__}", "bright_black"))
        sub = Text("Diagnóstico de ciberseguridad en modo solo lectura: no se modifica ninguna configuración",
                   style="italic bright_black")
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold", justify="right")
        grid.add_column()
        tones = {"ok": "green", "warn": "yellow"}
        for label, value, tone in info:
            grid.add_row(label, Text(value, style=tones.get(tone, "")))
        self.rc.print(Panel(Group(head, sub, Text(), grid), box=box.DOUBLE, border_style="cyan",
                            padding=(1, 3), expand=False))

    def menu(self, title: str, rows: List[Tuple[str, str, str]]) -> None:
        table = Table(box=box.ROUNDED, show_header=False, border_style="cyan", padding=(0, 1),
                      title=title, title_style="bold", title_justify="left")
        table.add_column(style="bold cyan", justify="right", no_wrap=True)
        table.add_column(style="bold", no_wrap=True)
        table.add_column(style="bright_black")
        for number, name, description in rows:
            table.add_row(number, name, description)
        self.rc.print()
        self.rc.print(table)

    def ask(self, prompt: str, default: str = "") -> str:
        answer = Prompt.ask(Text(f"  {prompt}", style="bold"), console=self.rc,
                            default=default, show_default=bool(default))
        return (answer or "").strip()

    # --- Progreso de la auditoría ---------------------------------------------
    def start(self, total: int) -> None:
        self.progress = Progress(SpinnerColumn(style="cyan"), TextColumn("{task.description}"),
                                 BarColumn(bar_width=28), MofNCompleteColumn(), TimeElapsedColumn(),
                                 console=self.rc, transient=True)
        self.task = self.progress.add_task("Preparando la auditoría", total=total)
        self.progress.start()

    def module_started(self, index: int, total: int, module: "AuditModule") -> None:
        if self.show_findings:
            self.rc.print()
            self.rc.rule(Text(f" [{index}/{total}] {module.title} ", style="bold magenta"),
                         align="left", style="magenta")
            self.rc.print(Text(f"  {module.description}", style="bright_black"))

    def check_started(self, module_title: str, label: str) -> None:
        if self.progress is not None:
            text = f"{module_title} › {label}"
            if len(text) > 64:
                text = text[:63] + "…"
            self.progress.update(self.task, description=f"[bold]{escape(text)}")

    def module_finished(self) -> None:
        if self.progress is not None:
            self.progress.advance(self.task)

    def stop(self) -> None:
        if self.progress is not None:
            self.progress.stop()
            self.progress = None

    # --- Resultados -------------------------------------------------------------
    def finding(self, f: Finding) -> None:
        if not self._visible(f):
            return
        color = self.RICH[f.severity]
        body = Text(f.title, style="bold")
        for line in f.detail.splitlines():
            if line.strip():
                body.append("\n" + line.strip())
        if f.recommendation and f.severity in (WARNING, CRITICAL):
            body.append(f"\n{self.arrow} {f.recommendation}", style=color)
        grid = Table.grid(padding=(0, 1))
        grid.add_column(width=14 if self.emoji else 11, no_wrap=True)
        grid.add_column(ratio=1)
        grid.add_row(self._label(f.severity), body)
        self.rc.print(Padding(grid, (0, 0, 0, 2)))

    def summary(self, report: "Report", elapsed: float, compact: bool = False) -> None:
        score = report.score()
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        counts = Text()
        for sev in (PASS, WARNING, CRITICAL, INFO, SKIP):
            counts.append(self._icon(sev))
            counts.append(f"{sev.value} {report.count(sev)}", style=f"bold {self.RICH[sev]}")
            counts.append("    ")
        score_row = Table.grid(padding=(0, 2))
        score_row.add_column(no_wrap=True)
        score_row.add_column(width=32)
        score_row.add_row(Text.assemble(("Puntuación orientativa  ", "bold"), (f"{score}/100", f"bold {color}")),
                          ProgressBar(total=100, completed=score, width=30, complete_style=color,
                                      finished_style=color))
        footer = Text(f"Duración: {elapsed:.1f} s · Resultados: {len(report.findings)}", style="bright_black")
        self.rc.print()
        self.rc.print(Panel(Group(counts, Text(), score_row, Text(), footer), title="[bold]RESUMEN",
                            title_align="left", border_style=color, padding=(1, 2)))
        if compact:
            return

        order = (PASS, WARNING, CRITICAL, INFO, SKIP)
        modules = Table(title="Resultados por módulo", title_justify="left", title_style="bold",
                        box=box.SIMPLE_HEAVY, header_style="bold")
        modules.add_column("Módulo")
        for sev in order:
            modules.add_column(sev.value, justify="right", style=self.RICH[sev])
        for key, title in report.modules.items():
            items = [f for f in report.findings if f.module == key]
            modules.add_row(title, *[str(sum(1 for f in items if f.severity is sev) or "·") for sev in order])
        self.rc.print(modules)

        issues = ([f for f in report.findings if f.severity is CRITICAL] +
                  [f for f in report.findings if f.severity is WARNING])
        if issues:
            table = Table(title="Hallazgos prioritarios", title_justify="left", title_style="bold",
                          box=box.ROUNDED, header_style="bold", expand=True)
            table.add_column("Nivel", no_wrap=True)
            table.add_column("Módulo", style="bright_black", no_wrap=True)
            table.add_column("Hallazgo", ratio=2)
            table.add_column("Qué hacer", ratio=3, style="bright_black")
            for f in issues:
                table.add_row(self._label(f.severity), f.module, Text(f.title), Text(f.recommendation))
            self.rc.print(table)

    def diff(self, changes: List["Change"], since: str) -> None:
        self.rc.print()
        if not changes:
            self.rc.print(Panel(Text(f"Sin novedades respecto a la ejecución de {since}.", style="green"),
                                title="[bold]NOVEDADES", title_align="left", border_style="green", padding=(1, 2)))
            return
        table = Table(title=f"Novedades desde la ejecución de {since}", title_justify="left", title_style="bold",
                      box=box.ROUNDED, header_style="bold", expand=True)
        table.add_column("Cambio", no_wrap=True)
        table.add_column("Nivel", no_wrap=True)
        table.add_column("Módulo", style="bright_black", no_wrap=True)
        table.add_column("Hallazgo", ratio=2)
        table.add_column("Detalle", ratio=2, style="bright_black")
        for c in changes:
            color = self.RICH[c.severity] if c.alert else "green"
            table.add_row(Text(c.kind, style=f"bold {color}"), self._label(c.severity), c.module,
                          Text(c.title), Text(c.detail))
        self.rc.print(table)


def make_console(color: bool = True, emoji: bool = True) -> Console:
    """Usa la interfaz rich si la librería está instalada; si no, la salida ANSI clásica."""
    return RichConsole(color, emoji) if HAS_RICH else Console(color, emoji)


# ===========================================================================
# MODO DIFERENCIAL (--diff): estado de referencia y comparación
# ===========================================================================
SEVERITY_RANK = {SKIP: -1, INFO: 0, PASS: 0, WARNING: 1, CRITICAL: 2}
STATE_VERSION = 1


@dataclass
class Change:
    """Diferencia entre la ejecución actual y el estado de referencia."""
    kind: str            # NUEVO, EMPEORA, AUMENTA (alertas) · MEJORA, RESUELTO (buenas noticias)
    severity: Severity
    module: str
    title: str
    detail: str

    @property
    def alert(self) -> bool:
        return self.kind in ("NUEVO", "EMPEORA", "AUMENTA")

    def to_dict(self) -> Dict[str, str]:
        return {"tipo": self.kind, "severidad": self.severity.value, "modulo": self.module,
                "titulo": self.title, "detalle": self.detail}


def default_state_path() -> str:
    """Carpeta de datos del usuario: %LOCALAPPDATA%\\AuditorSeguridad o ~/.local/state/auditor_seguridad."""
    if IS_WINDOWS:
        base = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "AuditorSeguridad")
    else:
        base = os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"),
                            "auditor_seguridad")
    return os.path.join(base, "estado_anterior.json")


def load_state(path: str) -> Optional[dict]:
    """Lee el estado de referencia. None si no existe o no es válido."""
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION or not isinstance(state.get("checks"), dict):
        return None
    return state


def _group_by_check(findings: List[Finding]) -> Dict[str, List[Finding]]:
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        groups.setdefault(f"{f.module}/{f.check}", []).append(f)
    return groups


def save_state(path: str, previous: Optional[dict], ctx: AuditContext) -> None:
    """
    Guarda la ejecución actual como referencia, comprobación a comprobación. Las
    comprobaciones que no se han ejecutado conservan su estado anterior, y si una
    se ha omitido ahora (p. ej. por falta de permisos) se mantiene su último
    resultado válido para no perder la referencia.
    """
    now = dt.datetime.now().isoformat(timespec="seconds")
    checks = dict((previous or {}).get("checks", {}))
    for check_id, findings in _group_by_check(ctx.report.findings).items():
        old = checks.get(check_id) or {}
        if (all(f.severity is SKIP for f in findings)
                and any(h.get("severity") != "SKIP" for h in old.get("hallazgos", []))):
            continue
        checks[check_id] = {"fecha": now, "administrador": ctx.is_admin,
                            "hallazgos": [f.to_dict() for f in findings]}
    state = {"version": STATE_VERSION, "equipo": socket.gethostname(), "actualizado": now, "checks": checks}
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)  # escritura atómica: nunca queda un estado a medias


def describe_when(iso: Optional[str]) -> str:
    """Fecha legible y relativa: 'hoy a las 09:15', 'ayer a las 21:48', '15/10/2026 08:00 (hace 3 días)'."""
    if not iso:
        return "la ejecución anterior"
    try:
        when = dt.datetime.fromisoformat(iso)
    except ValueError:
        return iso
    days = (dt.date.today() - when.date()).days
    if days == 0:
        return f"hoy a las {when:%H:%M}"
    if days == 1:
        return f"ayer a las {when:%H:%M}"
    return f"{when:%d/%m/%Y %H:%M} (hace {days} días)"


def compute_diff(previous: dict, findings: List[Finding]) -> List[Change]:
    """Compara la ejecución actual con el estado de referencia, comprobación a comprobación."""
    changes: List[Change] = []
    for check_id, current in _group_by_check(findings).items():
        current = [f for f in current if f.severity is not SKIP]
        if not current:
            continue  # comprobación omitida ahora (permisos, SO...): no se puede comparar
        entry = previous["checks"].get(check_id) or {}
        when = describe_when(entry.get("fecha"))
        try:
            before = [Finding.from_dict(h) for h in entry.get("hallazgos", [])]
        except (KeyError, ValueError, TypeError):
            before = []
        before = [f for f in before if f.severity is not SKIP]
        if not before:
            changes += [Change("NUEVO", f.severity, f.module, f.title, "Primera vez que se evalúa esta comprobación.")
                        for f in current if SEVERITY_RANK[f.severity] >= 1]
            continue

        prev_by_id = {f.identity(): f for f in before}
        cur_by_id = {f.identity(): f for f in current}
        pairs = [(prev_by_id[i], f) for i, f in cur_by_id.items() if i in prev_by_id]
        added = [f for i, f in cur_by_id.items() if i not in prev_by_id]
        gone = [f for i, f in prev_by_id.items() if i not in cur_by_id]
        if len(added) == 1 and len(gone) == 1:
            # Comprobación con un único resultado cuyo texto cambió: es el mismo elemento
            pairs.append((gone[0], added[0]))
            added, gone = [], []

        for old, new in pairs:
            r_old, r_new = SEVERITY_RANK[old.severity], SEVERITY_RANK[new.severity]
            if r_new > r_old:
                changes.append(Change("EMPEORA", new.severity, new.module, new.title,
                                      f"Antes ({when}): {old.severity.value} · {old.title}"))
            elif r_new < r_old:
                changes.append(Change("MEJORA", new.severity, new.module, new.title,
                                      f"Antes ({when}): {old.severity.value} · {old.title}"))
            elif r_new >= 1 and new.metric is not None and old.metric is not None and new.metric > old.metric:
                changes.append(Change("AUMENTA", new.severity, new.module, new.title,
                                      f"De {old.metric} a {new.metric} desde {when}."))
        changes += [Change("NUEVO", f.severity, f.module, f.title, f"No aparecía en la ejecución de {when}.")
                    for f in added if SEVERITY_RANK[f.severity] >= 1]
        changes += [Change("RESUELTO", PASS, f.module, f.title, f"Aparecía {when} como {f.severity.value}; ya no.")
                    for f in gone if SEVERITY_RANK[f.severity] >= 1]

    order = {"EMPEORA": 0, "NUEVO": 1, "AUMENTA": 2, "MEJORA": 3, "RESUELTO": 4}
    changes.sort(key=lambda c: (not c.alert, -SEVERITY_RANK[c.severity], order[c.kind]))
    return changes


def diff_exit_code(changes: List[Change]) -> int:
    """En modo --diff: 0 = sin novedades graves · 1 = nuevos WARNING · 2 = nuevos CRITICAL."""
    return max([SEVERITY_RANK[c.severity] for c in changes if c.alert] + [0])


# ===========================================================================
# DASHBOARD HTML AUTÓNOMO (--html)
# ===========================================================================
_HTML_CSS = """
:root{--bg:#0d1117;--panel:#151b24;--panel2:#1c2330;--border:#283244;--text:#e6e9ef;--muted:#96a0b2;
--pass:#3fb950;--info:#58a6ff;--warn:#e3b341;--crit:#f85149;--skip:#8b949e;--radius:14px}
*{box-sizing:border-box}
html{color-scheme:dark}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,"Helvetica Neue",sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:36px 20px 56px}
header{display:flex;flex-wrap:wrap;gap:14px 28px;align-items:flex-end;justify-content:space-between;margin-bottom:26px}
.eyebrow{font-size:12px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--info);margin:0 0 6px}
h1{font-size:26px;line-height:1.2;margin:0}
h2{font-size:17px;margin:0 0 14px;display:flex;align-items:center;gap:10px}
h2 .count{font-size:12px;font-weight:600;color:var(--muted);background:var(--panel2);border-radius:999px;padding:2px 10px}
.meta{display:flex;flex-wrap:wrap;gap:8px}
.chip{background:var(--panel);border:1px solid var(--border);border-radius:999px;padding:4px 12px;font-size:13px;color:var(--muted)}
.chip b{color:var(--text);font-weight:600}
.chip.ok b{color:var(--pass)} .chip.warn b{color:var(--warn)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:22px}
section{margin-top:28px}
.hero{display:grid;grid-template-columns:240px minmax(0,1fr);gap:18px}
.score{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;text-align:center}
.ring{width:156px;height:156px;border-radius:50%;display:grid;place-items:center;
background:conic-gradient(var(--c) calc(var(--p) * 1%),var(--panel2) 0)}
.ring::before{content:"";grid-area:1/1;width:124px;height:124px;border-radius:50%;background:var(--panel)}
.ring span{grid-area:1/1;font-size:40px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1}
.ring small{display:block;font-size:13px;font-weight:500;color:var(--muted);margin-top:4px}
.score p{margin:0;color:var(--muted);font-size:13px;max-width:200px}
.counters{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}
.counter{all:unset;cursor:pointer;background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
padding:18px;display:flex;flex-direction:column;gap:4px;border-top:3px solid var(--c);transition:transform .12s,border-color .12s}
.counter:hover{transform:translateY(-2px)}
.counter:focus-visible{outline:2px solid var(--info);outline-offset:2px}
.counter.active{border-color:var(--c);box-shadow:0 0 0 1px var(--c) inset}
.counter .n{font-size:32px;font-weight:700;font-variant-numeric:tabular-nums;color:var(--c);line-height:1.1}
.counter .l{font-size:12px;font-weight:600;letter-spacing:.1em;color:var(--muted)}
.hint{font-size:13px;color:var(--muted);margin:10px 2px 0}
.dist{display:flex;height:10px;border-radius:999px;overflow:hidden;background:var(--panel2);margin-top:18px}
.dist span{background:var(--c);height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:10px;font-size:12.5px;color:var(--muted)}
.legend span::before{content:"";display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--c);margin-right:6px}
.pass{--c:var(--pass)} .info{--c:var(--info)} .warn{--c:var(--warn)} .crit{--c:var(--crit)} .skip{--c:var(--skip)}
.list{display:flex;flex-direction:column;gap:10px}
.finding,.change{display:grid;grid-template-columns:96px minmax(0,1fr);gap:14px;background:var(--panel);
border:1px solid var(--border);border-left:3px solid var(--c);border-radius:10px;padding:14px 16px}
.finding[hidden]{display:none}
.badge{align-self:start;justify-self:start;font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--c);
background:color-mix(in srgb,var(--c) 14%,transparent);border-radius:6px;padding:3px 8px}
.finding h3,.change h3{font-size:15px;margin:0;font-weight:600;overflow-wrap:anywhere}
.finding h3 em,.change h3 em{font-style:normal;font-weight:500;color:var(--muted);font-size:13px}
.detail{margin:6px 0 0;color:var(--muted);font-size:13.5px;white-space:pre-line;overflow-wrap:anywhere}
.rec{margin:8px 0 0;font-size:13.5px;color:var(--c)}
details.module{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px}
details.module[hidden]{display:none}
details.module>summary{cursor:pointer;list-style:none;padding:16px 20px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;font-weight:600}
details.module>summary::-webkit-details-marker{display:none}
details.module>summary::before{content:"▸";color:var(--muted);transition:transform .15s}
details.module[open]>summary::before{transform:rotate(90deg)}
.mini{display:flex;gap:6px;margin-left:auto;font-size:12px;font-weight:600}
.mini span{color:var(--c);background:var(--panel2);border-radius:999px;padding:1px 9px}
details.module .list{padding:0 16px 16px}
details.module .finding{background:var(--panel2)}
.empty{color:var(--muted);margin:0}
footer{margin-top:40px;color:var(--muted);font-size:12.5px;text-align:center}
@media (max-width:780px){
  .hero{grid-template-columns:minmax(0,1fr)}
  .counters{grid-template-columns:repeat(3,minmax(0,1fr))}
  .finding,.change{grid-template-columns:minmax(0,1fr);gap:8px}
  .mini{margin-left:0}
}
@media print{body{background:#fff;color:#111}.card,.finding,details.module,.counter{break-inside:avoid}}
"""

_HTML_JS = """
const buttons = document.querySelectorAll('[data-filter]');
buttons.forEach(btn => btn.addEventListener('click', () => {
  const sev = btn.classList.contains('active') ? 'ALL' : btn.dataset.filter;
  buttons.forEach(b => b.classList.toggle('active', b === btn && sev !== 'ALL'));
  document.querySelectorAll('#modulos .finding').forEach(f => { f.hidden = sev !== 'ALL' && f.dataset.sev !== sev; });
  document.querySelectorAll('#modulos details.module').forEach(m => {
    const visible = m.querySelectorAll('.finding:not([hidden])').length;
    m.hidden = visible === 0;
    if (sev !== 'ALL' && visible) m.open = true;
  });
}));
"""

_SEV_CLASS = {PASS: "pass", INFO: "info", WARNING: "warn", CRITICAL: "crit", SKIP: "skip"}


def export_html(path: str, ctx: AuditContext, elapsed: float,
                changes: Optional[List[Change]] = None, since: Optional[str] = None) -> None:
    """Genera un dashboard HTML5 autónomo (CSS y JS en línea, sin recursos externos)."""
    esc = html.escape
    report = ctx.report
    score = report.score()
    score_class = "pass" if score >= 80 else "warn" if score >= 50 else "crit"
    titles = report.modules

    def finding_html(f: Finding, show_module: bool = False) -> str:
        where = f" <em>· {esc(titles.get(f.module, f.module))}</em>" if show_module else ""
        out = [f'<article class="finding {_SEV_CLASS[f.severity]}" data-sev="{f.severity.value}">',
               f'<span class="badge">{f.severity.value}</span><div>',
               f"<h3>{esc(f.title)}{where}</h3>"]
        if f.detail:
            out.append(f'<p class="detail">{esc(f.detail)}</p>')
        if f.recommendation and f.severity in (WARNING, CRITICAL):
            out.append(f'<p class="rec">➜ {esc(f.recommendation)}</p>')
        out.append("</div></article>")
        return "".join(out)

    def mini_counts(items: List[Finding]) -> str:
        spans = [f'<span class="{_SEV_CLASS[sev]}" title="{sev.value}">{n} {sev.value}</span>'
                 for sev in (CRITICAL, WARNING, PASS, INFO, SKIP)
                 if (n := sum(1 for f in items if f.severity is sev))]
        return f'<span class="mini">{"".join(spans)}</span>'

    try:
        user = getpass.getuser()
    except Exception:
        user = "?"
    chips = [("Equipo", socket.gethostname(), ""), ("Sistema", f"{platform.system()} {platform.release()}", ""),
             ("Usuario", user, ""),
             ("Privilegios", ADMIN_NAME if ctx.is_admin else "estándar (parcial)", "ok" if ctx.is_admin else "warn"),
             ("Fecha", f"{dt.datetime.now():%d/%m/%Y %H:%M}", ""), ("Duración", f"{elapsed:.1f} s", "")]
    chips_html = "".join(f'<span class="chip {tone}">{esc(label)}: <b>{esc(value)}</b></span>'
                         for label, value, tone in chips)

    counters = "".join(
        f'<button class="counter {_SEV_CLASS[sev]}" data-filter="{sev.value}" type="button">'
        f'<span class="n">{report.count(sev)}</span><span class="l">{sev.value}</span></button>'
        for sev in (CRITICAL, WARNING, PASS, INFO, SKIP))

    # Barra de distribución de resultados (proporciones de cada estado)
    total = len(report.findings) or 1
    dist = "".join(f'<span class="{_SEV_CLASS[sev]}" style="width:{100 * report.count(sev) / total:.2f}%" '
                   f'title="{sev.value}: {report.count(sev)}"></span>' for sev in (CRITICAL, WARNING, PASS, INFO, SKIP))
    legend = "".join(f'<span class="{_SEV_CLASS[sev]}">{sev.value} {100 * report.count(sev) / total:.0f}%</span>'
                     for sev in (CRITICAL, WARNING, PASS, INFO, SKIP) if report.count(sev))

    sections = []
    if changes is not None:
        if changes:
            rows = "".join(
                f'<div class="change {_SEV_CLASS[c.severity] if c.alert else "pass"}">'
                f'<span class="badge">{esc(c.kind)}</span><div><h3>{esc(c.title)} '
                f'<em>· {esc(titles.get(c.module, c.module))} · {c.severity.value}</em></h3>'
                f'<p class="detail">{esc(c.detail)}</p></div></div>' for c in changes)
        else:
            rows = '<p class="empty">Sin novedades respecto a la ejecución anterior.</p>'
        sections.append(f'<section><h2>Novedades desde {esc(since or "la ejecución anterior")} '
                        f'<span class="count">{len(changes)}</span></h2><div class="list">{rows}</div></section>')

    issues = ([f for f in report.findings if f.severity is CRITICAL] +
              [f for f in report.findings if f.severity is WARNING])
    issues_html = ("".join(finding_html(f, show_module=True) for f in issues)
                   or '<p class="empty">No hay hallazgos CRITICAL ni WARNING.</p>')
    sections.append(f'<section><h2>Prioridades <span class="count">{len(issues)}</span></h2>'
                    f'<div class="list">{issues_html}</div></section>')

    modules_html = []
    for key, title in titles.items():
        items = [f for f in report.findings if f.module == key]
        is_open = " open" if any(f.severity in (WARNING, CRITICAL) for f in items) else ""
        modules_html.append(f'<details class="module"{is_open}><summary>{esc(title)}{mini_counts(items)}</summary>'
                            f'<div class="list">{"".join(finding_html(f) for f in items)}</div></details>')
    sections.append(f'<section id="modulos"><h2>Detalle por módulo</h2>{"".join(modules_html)}</section>')
    body = "".join(sections)

    page = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de seguridad · {esc(socket.gethostname())}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <div><p class="eyebrow">Auditor de seguridad local · v{__version__}</p><h1>Informe de seguridad</h1></div>
  <div class="meta">{chips_html}</div>
</header>
<div class="hero">
  <div class="card score">
    <div class="ring {score_class}" style="--p:{score}"><span>{score}<small>de 100</small></span></div>
    <p>Puntuación orientativa: % de comprobaciones superadas (WARNING pesa 1, CRITICAL pesa 3)</p>
  </div>
  <div>
    <div class="counters">{counters}</div>
    <p class="hint">Pulsa un contador para filtrar el detalle por módulo; vuelve a pulsarlo para ver todo.</p>
    <div class="dist" role="img" aria-label="Distribución de resultados">{dist}</div>
    <div class="legend">{legend}</div>
  </div>
</div>
{body}
<footer>Generado en modo solo lectura: la auditoría no modifica ninguna configuración del sistema.</footer>
</div>
<script>{_HTML_JS}</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)


# ===========================================================================
# PROGRAMA PRINCIPAL: menú interactivo, argumentos y orquestación
# ===========================================================================
def interactive_menu(console: Console, modules: List[type]) -> Optional[List[str]]:
    """Menú para ejecuciones sin argumentos. Devuelve los argumentos equivalentes, o None para salir."""
    console.menu("¿Qué quieres hacer?", [
        ("1", "Auditoría completa", "todos los módulos"),
        ("2", "Modo diferencial", "solo las novedades desde la última ejecución (--diff)"),
        ("3", "Elegir módulos", "auditoría a medida"),
        ("0", "Salir", ""),
    ])
    choice = console.ask("Opción", "1")
    while choice not in ("0", "1", "2", "3"):
        console.message("Opción no válida: escribe 0, 1, 2 o 3.")
        choice = console.ask("Opción", "1")
    if choice == "0":
        return None

    argv = {"1": ["--completo"], "2": ["--diff"]}.get(choice, [])
    if choice == "3":
        console.menu("Módulos disponibles", [(str(i), m.key, m.description) for i, m in enumerate(modules, 1)])
        while True:
            numbers = [int(n) for n in re.findall(r"\d+", console.ask("Números separados por espacios o comas"))]
            if numbers and all(1 <= n <= len(modules) for n in numbers):
                break
            console.message(f"Selección no válida: usa números del 1 al {len(modules)} (por ejemplo: 1 3 4).")
        argv = ["-m", *dict.fromkeys(modules[n - 1].key for n in numbers)]

    if console.confirm("¿Generar también un dashboard HTML?", False):
        argv += ["--html", console.ask("Nombre del fichero", f"informe_seguridad_{dt.datetime.now():%Y%m%d_%H%M}.html")]
    shown = " ".join(f'"{a}"' if " " in a else a for a in argv)
    console.message(f"Equivalente sin menú: python {os.path.basename(sys.argv[0] or 'auditor.py')} {shown}",
                    dim=True)
    return argv


def parse_args(argv: Optional[List[str]], modules: List[type]) -> argparse.Namespace:
    keys = [m.key for m in modules]  # las opciones de -m salen de los plugins detectados
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Auditoría de seguridad local en modo solo lectura (Windows / Linux). "
                    "Sin argumentos muestra un menú interactivo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            ejemplos:
              python auditor.py                       (menú interactivo)
              python auditor.py --listar              (módulos detectados en modulos/)
              python auditor.py -a                    (auditoría completa)
              python auditor.py -m puertos firewall
              python auditor.py -a --html informe.html --json informe.json
              python auditor.py --diff                (uso diario: solo novedades)

            plugins: cada fichero .py de {os.path.join(BASE_DIR, 'modulos')}
            que no empiece por "_" se carga automáticamente (plantilla: modulos/_plantilla.py)

            estado de referencia de --diff: {default_state_path()}
            (se actualiza al final de cada ejecución completa salvo con --sin-guardar)

            códigos de salida: 0 = sin incidencias · 1 = hay WARNING · 2 = hay CRITICAL
            con --diff solo cuentan las novedades: 1 = nuevos WARNING · 2 = nuevos CRITICAL
        """))
    parser.add_argument("-a", "--completo", action="store_true", help="auditoría completa sin pasar por el menú")
    parser.add_argument("-l", "--listar", action="store_true", help="muestra los módulos detectados y sale")
    parser.add_argument("-m", "--modulos", nargs="+", choices=keys, metavar="MÓDULO",
                        help=f"módulos a ejecutar: {', '.join(keys)}")
    parser.add_argument("--diff", action="store_true",
                        help="muestra solo las novedades respecto a la ejecución anterior")
    parser.add_argument("--estado", metavar="FICHERO", help="fichero de estado de referencia alternativo")
    parser.add_argument("--sin-guardar", action="store_true",
                        help="no actualiza el estado de referencia al terminar")
    parser.add_argument("-e", "--escanear", metavar="OBJETIVO",
                        help="escaneo TCP de puertos comunes contra 'gateway', 'local' o una IP privada")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="tiempo de espera por puerto en el escaneo, en segundos (por defecto 0.5)")
    parser.add_argument("--html", metavar="FICHERO", help="genera un dashboard HTML autónomo")
    parser.add_argument("--json", metavar="FICHERO", help="exporta el informe completo a un fichero JSON")
    parser.add_argument("--solo-problemas", action="store_true",
                        help="muestra solo WARNING, CRITICAL y SKIP (el resumen y los informes siguen completos)")
    parser.add_argument("--sin-color", action="store_true", help="desactiva los colores")
    parser.add_argument("--sin-emoji", action="store_true", help="desactiva los iconos de colores")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def export_json(path: str, ctx: AuditContext, elapsed: float, changes: Optional[List[Change]] = None) -> None:
    report = ctx.report
    data = {
        "herramienta": "auditor_seguridad",
        "version": __version__,
        "fecha": dt.datetime.now().isoformat(timespec="seconds"),
        "equipo": socket.gethostname(),
        "sistema": platform.platform(),
        "administrador": ctx.is_admin,
        "duracion_s": round(elapsed, 1),
        "puntuacion": report.score(),
        "resumen": {sev.value: report.count(sev) for sev in Severity},
        "hallazgos": [f.to_dict() for f in report.findings],
    }
    if changes is not None:
        data["novedades"] = [c.to_dict() for c in changes]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")  # evita fallos si la salida se redirige a un fichero
    except (AttributeError, ValueError):
        pass
    argv = sys.argv[1:] if argv is None else list(argv)
    interactive = not argv
    modules, plugin_errors = discover_modules()  # carga dinámica de modulos/
    args = parse_args(argv, modules)
    console = make_console(color=not args.sin_color, emoji=not args.sin_emoji)
    admin = is_admin()

    try:
        user = getpass.getuser()
    except Exception:
        user = "?"
    console.banner([
        ("Equipo", socket.gethostname(), ""),
        ("Usuario", user, ""),
        ("Privilegios", f"{ADMIN_NAME} (auditoría completa)" if admin else "usuario estándar (auditoría parcial)",
         "ok" if admin else "warn"),
        ("Sistema", f"{platform.system()} {platform.release()} · Python {platform.python_version()}", ""),
        ("Extras", f"rich: {'sí' if HAS_RICH else 'no'} · psutil: {'sí' if HAS_PSUTIL else 'no'}", ""),
        ("Módulos", f"{len(modules)} cargados desde modulos/"
                    + (f" · {len(plugin_errors)} con errores" if plugin_errors else ""),
         "warn" if plugin_errors or not modules else ""),
        ("Fecha", f"{dt.datetime.now():%d/%m/%Y %H:%M}", ""),
    ])
    for error in plugin_errors:
        console.warn(f"Plugin ignorado · {error.origin}: {error.reason}")

    if args.listar:
        console.plugin_table([(str(i), m.key, m.title, m.origin, count_checks(m), m.description)
                              for i, m in enumerate(modules, 1)])
        print()
        return 1 if plugin_errors else 0
    if not modules:
        console.warn(f"No hay ningún módulo válido en {os.path.join(BASE_DIR, 'modulos')}: nada que auditar.")
        return 1

    # --- Sin argumentos: menú interactivo ---
    if interactive:
        if not sys.stdin.isatty():
            console.message("Sin argumentos y sin terminal interactiva: usa -a (completa) o -m MÓDULO... (ver --help).")
            return 64
        try:
            menu_argv = interactive_menu(console, modules)
        except (EOFError, KeyboardInterrupt):
            print()
            console.message("Cancelado.")
            return 0
        if menu_argv is None:
            return 0
        args = parse_args(menu_argv, modules)

    console.only_issues = args.solo_problemas
    console.show_findings = not args.diff
    ctx = AuditContext(args=args, report=Report(console), is_admin=admin)
    state_path = args.estado or default_state_path()
    previous = load_state(state_path)

    selected = [m for m in modules if args.completo or not args.modulos or m.key in args.modulos]
    started = time.time()
    interrupted = False
    console.start(len(selected))
    try:
        for index, module_cls in enumerate(selected, 1):
            module = module_cls(ctx)
            console.module_started(index, len(selected), module)
            module.run()
            console.module_finished()
    except KeyboardInterrupt:
        interrupted = True
    finally:
        console.stop()
    if interrupted:
        console.message("Auditoría interrumpida por el usuario: se muestran resultados parciales.")
    elapsed = time.time() - started

    # --- Modo diferencial: solo novedades ---
    changes, since = None, None
    if args.diff:
        if previous:
            since = describe_when(previous.get("actualizado"))
            changes = compute_diff(previous, ctx.report.findings)
            if previous.get("equipo") not in (None, socket.gethostname()):
                console.message(f"Aviso: el estado de referencia es de otro equipo ({previous['equipo']}).")
            console.diff(changes, since)
        else:
            console.message("No hay estado anterior: esta ejecución queda como referencia y la próxima "
                            "con --diff mostrará solo las novedades.")
    console.summary(ctx.report, elapsed, compact=args.diff)

    # --- Exportaciones ---
    for flag, exporter in ((args.json, lambda p: export_json(p, ctx, elapsed, changes)),
                           (args.html, lambda p: export_html(p, ctx, elapsed, changes, since))):
        if flag:
            try:
                exporter(flag)
                console.message(f"Informe guardado en: {os.path.abspath(flag)}")
            except OSError as exc:
                console.message(f"No se pudo guardar {flag}: {exc}")

    # --- Estado de referencia para el próximo --diff ---
    if not interrupted and not args.sin_guardar:
        try:
            save_state(state_path, previous, ctx)
            console.message(f"Estado de referencia actualizado: {state_path}", dim=True)
        except OSError as exc:
            console.message(f"No se pudo guardar el estado de referencia: {exc}")
    print()

    if interrupted:
        return 130
    if changes is not None:
        return diff_exit_code(changes)
    if ctx.report.count(CRITICAL):
        return 2
    return 1 if ctx.report.count(WARNING) else 0


if __name__ == "__main__":
    sys.exit(main())
