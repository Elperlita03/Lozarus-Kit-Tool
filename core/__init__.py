# -*- coding: utf-8 -*-
"""
Núcleo de Lozarus: modelos comunes, contratos y bus de eventos. No depende de PySide6 ni de Windows;
se puede importar y probar en cualquier plataforma. Es la base sobre la que se conectan colectores
(ETW y futuros) y motores de detección, con la GUI siempre separada de las operaciones privilegiadas.
"""

from .bus import BusMetrics, EventBus, OverflowPolicy
from .contracts import (UNKNOWN, BaseCollector, Collector, EventSink, LossState, SensorHealth)
from .errors import (BusError, CollectorError, LozarusError, SchemaVersionError,
                     SerializationError, ValidationError)
from .events import (EVENT_SCHEMA_VERSION, ClockType, Event, ObservationQuality, Provenance, now_utc)

__all__ = [
    "BusMetrics", "EventBus", "OverflowPolicy",
    "UNKNOWN", "BaseCollector", "Collector", "EventSink", "LossState", "SensorHealth",
    "BusError", "CollectorError", "LozarusError", "SchemaVersionError", "SerializationError",
    "ValidationError",
    "EVENT_SCHEMA_VERSION", "ClockType", "Event", "ObservationQuality", "Provenance", "now_utc",
]
