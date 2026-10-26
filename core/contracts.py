# -*- coding: utf-8 -*-
"""
Contratos del núcleo: interfaz de los colectores (sensores), destino de eventos (sink) y estado de
salud/pérdidas. Son independientes de la implementación y, sobre todo, **independientes de la GUI**:
un colector NUNCA importa PySide6 ni ejecuta respuestas defensivas; solo observa y publica eventos.

Decisión de diseño (Protocol vs ABC): se usan **ambos**.
  - `Collector` y `EventSink` son `typing.Protocol` (contrato ESTRUCTURAL): cualquier objeto con los
    métodos adecuados cumple, sin herencia. Así los dobles de prueba y los colectores se mantienen
    desacoplados del núcleo y se pueden testear sin Windows.
  - `BaseCollector` es una ABC OPCIONAL que aporta el andamiaje repetitivo (contadores, cableado del
    sink, salud por defecto). Un colector puede heredar de ella o simplemente satisfacer el Protocol.
Se evita así tanto el acoplamiento por herencia obligatoria como la duplicación de código.
"""

from __future__ import annotations

import datetime as _dt
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Protocol, Tuple, runtime_checkable

from .events import Event

# Convención de pérdidas/cobertura en todo el núcleo:
#   None  -> DESCONOCIDO / no medible (nunca interpretar como 0)
#   0     -> cero confirmado
#   >0    -> pérdida detectada
UNKNOWN = None


class LossState(str, Enum):
    """Clasificación de un contador de pérdidas en tres estados bien diferenciados."""
    UNKNOWN = "unknown"      # la fuente no lo reporta o no se ha medido
    NONE = "none"            # cero confirmado
    DETECTED = "detected"    # se detectaron pérdidas (> 0)

    @classmethod
    def of(cls, value: Optional[int]) -> "LossState":
        if value is None:
            return cls.UNKNOWN
        return cls.NONE if value == 0 else cls.DETECTED


@dataclass(frozen=True)
class SensorHealth:
    """
    Estado de salud de un colector, pensado para alimentar OBSIDIAN. Distingue explícitamente la
    pérdida de la FUENTE (p. ej. EventsLost de ETW, que puede ser desconocida) de los descartes
    INTERNOS de la cola del bus (que se contabilizan aparte, en `BusMetrics`).
    """
    name: str
    alive: bool
    started: bool
    events_total: int
    source_events_lost: Optional[int]      # None=desconocido · 0=cero confirmado · >0=detectado
    source_buffers_lost: Optional[int]
    last_event_utc: Optional[_dt.datetime] = None
    init_error: Optional[str] = None
    degraded: bool = False
    note: str = ""

    @property
    def events_loss_state(self) -> LossState:
        return LossState.of(self.source_events_lost)

    @property
    def buffers_loss_state(self) -> LossState:
        return LossState.of(self.source_buffers_lost)

    def to_dict(self) -> dict:
        return {
            "name": self.name, "alive": self.alive, "started": self.started,
            "events_total": self.events_total,
            "source_events_lost": self.source_events_lost,
            "source_buffers_lost": self.source_buffers_lost,
            "events_loss_state": self.events_loss_state.value,
            "buffers_loss_state": self.buffers_loss_state.value,
            "last_event_utc": self.last_event_utc.isoformat() if self.last_event_utc else None,
            "init_error": self.init_error, "degraded": self.degraded, "note": self.note,
        }


@runtime_checkable
class EventSink(Protocol):
    """Destino al que un colector entrega eventos. El bus lo implementa."""

    def publish(self, event: Event) -> bool:
        """Entrega un evento. Devuelve False si se descartó (p. ej. cola llena)."""
        ...


@runtime_checkable
class Collector(Protocol):
    """
    Contrato estructural de un sensor. Un colector se construye con un `EventSink` y publica en él;
    no devuelve los eventos ni llama a la GUI. `health()` expone cobertura y pérdidas.
    """
    name: str

    def start(self) -> None: ...
    def stop(self) -> None: ...
    def health(self) -> SensorHealth: ...


class BaseCollector(ABC):
    """
    Base OPCIONAL para colectores: gestiona el sink, los contadores y una salud por defecto.
    Las subclases implementan `start()`/`stop()` y emiten con `self._emit(event)`. Si un colector
    puede medir la pérdida de su fuente, sobrescribe `source_loss()`.
    """

    def __init__(self, name: str, sink: EventSink):
        self.name = name
        self._sink = sink
        self._events_total = 0
        self._started = False
        self._last_event_utc: Optional[_dt.datetime] = None
        self._init_error: Optional[str] = None

    @abstractmethod
    def start(self) -> None:
        """Arranca la captura. Debe ser idempotente y no lanzar por falta de permisos: registrar
        el motivo en `self._init_error` y dejar `self._started=False`."""

    @abstractmethod
    def stop(self) -> None:
        """Detiene la captura y libera recursos. Idempotente; seguro de llamar aunque no se arrancara."""

    def _emit(self, event: Event) -> bool:
        """Publica un evento en el sink y actualiza los contadores. Nunca lanza por el sink."""
        self._events_total += 1
        if event.timestamp_utc is not None:
            self._last_event_utc = event.timestamp_utc
        try:
            return bool(self._sink.publish(event))
        except Exception:
            return False

    def source_loss(self) -> Tuple[Optional[int], Optional[int]]:
        """(eventos_perdidos, búferes_perdidos) de la FUENTE. Por defecto desconocido (None, None)."""
        return (UNKNOWN, UNKNOWN)

    def health(self) -> SensorHealth:
        events_lost, buffers_lost = self.source_loss()
        degraded = self._init_error is not None or LossState.of(events_lost) is LossState.DETECTED
        return SensorHealth(
            name=self.name, alive=self._started, started=self._started,
            events_total=self._events_total, source_events_lost=events_lost,
            source_buffers_lost=buffers_lost, last_event_utc=self._last_event_utc,
            init_error=self._init_error, degraded=degraded,
        )
