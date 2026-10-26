# -*- coding: utf-8 -*-
"""
Contexto de ejecución de la beta: modo demostración, registro visual de interacciones y lectura de
métricas reales del propio equipo.

Principios que esta clase hace cumplir:
  - La beta **nunca** ejecuta operaciones privilegiadas ni toca el sistema. `BetaContext.act()` solo
    registra lo que *haría* una versión conectada.
  - Un dato real y un dato de demostración no se confunden: `Metrics.available` distingue «no hay
    dato» de «el dato es 0», igual que `LossState` en `core/contracts.py`.
"""

from __future__ import annotations

import datetime as dt
import platform
from dataclasses import dataclass
from typing import Optional

from PySide6.QtCore import QObject, Signal

try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    psutil = None
    HAS_PSUTIL = False


@dataclass(frozen=True)
class Metrics:
    """Métricas del equipo. `available=False` significa DESCONOCIDO, nunca 0."""
    available: bool
    cpu_percent: Optional[float] = None
    ram_percent: Optional[float] = None
    ram_used_gb: Optional[float] = None
    ram_total_gb: Optional[float] = None
    processes: Optional[int] = None
    reason: str = ""

    def fmt(self, value: Optional[float], unit: str = "%") -> str:
        return "—" if value is None else f"{value:.0f}{unit}"


def read_metrics() -> Metrics:
    """Lee CPU/RAM reales con psutil. Si no está o falla, devuelve «no disponible» con el motivo."""
    if not HAS_PSUTIL:
        return Metrics(False, reason="psutil no está instalado")
    try:
        vm = psutil.virtual_memory()
        return Metrics(
            True,
            cpu_percent=psutil.cpu_percent(interval=None),
            ram_percent=vm.percent,
            ram_used_gb=vm.used / 1024 ** 3,
            ram_total_gb=vm.total / 1024 ** 3,
            processes=len(psutil.pids()),
        )
    except Exception as exc:                                  # noqa: BLE001
        return Metrics(False, reason=f"psutil falló: {type(exc).__name__}")


def host_label() -> str:
    try:
        return f"{platform.node()} · {platform.system()} {platform.release()}"
    except Exception:
        return "equipo desconocido"


class BetaContext(QObject):
    """Estado compartido por todas las secciones. Las secciones no hablan entre ellas: hablan aquí."""

    demo_changed = Signal(bool)
    logged = Signal(str, str, str)        # (marca de tiempo, tipo, mensaje)
    navigate = Signal(str)                # clave de sección a la que saltar

    KINDS = {"nav": "·", "demo": "~", "info": "i", "block": "!", "ok": "+"}

    def __init__(self) -> None:
        super().__init__()
        self._demo = False
        self.history: list[tuple[str, str, str]] = []

    # --- modo demostración ---------------------------------------------------------------
    @property
    def demo(self) -> bool:
        return self._demo

    def set_demo(self, on: bool) -> None:
        if on == self._demo:
            return
        self._demo = on
        self.demo_changed.emit(on)
        self.log("demo", f"Modo demostración {'ACTIVADO' if on else 'detenido'} "
                         f"— los datos marcados DEMO son simulados, no observados")

    # --- registro visual -----------------------------------------------------------------
    def log(self, kind: str, message: str) -> None:
        stamp = dt.datetime.now().strftime("%H:%M:%S")
        self.history.append((stamp, kind, message))
        self.logged.emit(stamp, kind, message)

    def act(self, what: str, note: str = "") -> None:
        """
        Registra una acción de demostración. **No ejecuta nada en el sistema.**
        Es el único camino por el que un botón de la beta «hace» algo.
        """
        tail = f" · {note}" if note else ""
        self.log("block", f"DEMOSTRACIÓN: «{what}» no se ejecuta en esta beta{tail}")
