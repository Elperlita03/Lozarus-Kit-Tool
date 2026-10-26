# -*- coding: utf-8 -*-
"""
Modelo común de eventos de Lozarus: tipado, versionado, validado y agnóstico del colector.

No es un modelo de ETW: ETW es solo el primer productor. Cualquier colector futuro (Event Log,
procesos, red, dispositivos, sistema de archivos) produce el MISMO `Event`. El colector ETW del
spike (`spikes/etw/normalize.py`, esquema `lozarus.etw.v0`) se MAPEARÁ a este modelo en una fase
posterior; aquí no se toca.

Principios (de la Fase 2):
  - Las marcas temporales se manejan de forma EXPLÍCITA: `timestamp_utc` es un `datetime` consciente
    de zona o `None`. Nunca se asume UTC sobre un valor ambiguo de forma silenciosa.
  - El valor temporal ORIGINAL (`timestamp_raw`) y su reloj (`clock_type`) se conservan siempre que
    existan, para auditoría.
  - No se inventan campos: PID, TID, correlación y demás son `None` si el evento no los trae.
  - Los campos NORMALIZADOS (`payload`) se separan de los DATOS ORIGINALES del proveedor (`raw`).
  - Serialización JSON determinista y reconstrucción con comprobación de versión de esquema.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Mapping, Optional
from uuid import uuid4

from .errors import SchemaVersionError, SerializationError, ValidationError

EVENT_SCHEMA = "lozarus.event"
EVENT_SCHEMA_MAJOR = 1
EVENT_SCHEMA_VERSION = f"{EVENT_SCHEMA}.v{EVENT_SCHEMA_MAJOR}"


def now_utc() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


class ClockType(str, Enum):
    """Reloj del que procede `timestamp_raw`. UNKNOWN cuando no puede determinarse con fiabilidad."""
    FILETIME = "filetime"        # 100 ns desde 1601-01-01 UTC (ETW ClientContext=2 / hora de sistema)
    QPC = "qpc"                  # contador de alto rendimiento; necesita LogfileHeader para convertir
    CPU_CYCLES = "cpu_cycles"    # contador de ciclos de CPU
    UNKNOWN = "unknown"          # desconocido/ambiguo: NO convertir a UTC por suposición


class ObservationQuality(str, Enum):
    """Calidad de la observación de un evento (de cara a la confianza y a OBSIDIAN)."""
    COMPLETE = "complete"        # parseado por completo
    PARTIAL = "partial"          # parseado en parte (faltan campos)
    RAW_ONLY = "raw_only"        # no se pudo parsear; solo datos crudos
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Provenance:
    """De dónde y cómo llegó el evento. `received_*` las fija el núcleo al recibirlo."""
    collector: str
    host: Optional[str] = None
    received_utc: _dt.datetime = field(default_factory=now_utc)
    received_monotonic: Optional[float] = None
    observation: ObservationQuality = ObservationQuality.UNKNOWN
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector": self.collector,
            "host": self.host,
            "received_utc": self.received_utc.isoformat() if self.received_utc else None,
            "received_monotonic": self.received_monotonic,
            "observation": self.observation.value,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Provenance":
        return cls(
            collector=d.get("collector", ""),
            host=d.get("host"),
            received_utc=_parse_dt(d.get("received_utc"), "received_utc") or now_utc(),
            received_monotonic=d.get("received_monotonic"),
            observation=_enum(ObservationQuality, d.get("observation"), ObservationQuality.UNKNOWN),
            note=d.get("note", "") or "",
        )


@dataclass(frozen=True)
class Event:
    """
    Un evento observado, normalizado y autocontenido. Inmutable (los eventos son hechos). Construir
    preferentemente con `Event.create(...)`, que rellena la procedencia de forma coherente.
    """
    source: str                                  # nombre del colector que lo produjo
    schema_version: str = EVENT_SCHEMA_VERSION
    event_id: str = field(default_factory=lambda: uuid4().hex)   # identificador ÚNICO del evento
    provider_name: Optional[str] = None
    provider_guid: Optional[str] = None
    event_type: Optional[str] = None             # tipo legible (opcode/tarea), si se conoce
    native_event_id: Optional[int] = None        # id de evento del propio proveedor, si existe
    timestamp_utc: Optional[_dt.datetime] = None  # tz-aware o None (nunca naive)
    timestamp_raw: Optional[int] = None          # valor original sin convertir
    clock_type: ClockType = ClockType.UNKNOWN
    monotonic_timestamp: Optional[float] = None  # time.monotonic() de recepción, si se dispone
    process_id: Optional[int] = None
    thread_id: Optional[int] = None
    correlation_id: Optional[str] = None
    payload: Mapping[str, Any] = field(default_factory=dict)   # campos NORMALIZADOS
    raw: Optional[Mapping[str, Any]] = None                    # datos ORIGINALES del proveedor
    provenance: Optional[Provenance] = None

    def __post_init__(self) -> None:
        if not self.source:
            raise ValidationError("Event.source es obligatorio")
        if not self.event_id:
            raise ValidationError("Event.event_id no puede estar vacío")
        if not str(self.schema_version).startswith(EVENT_SCHEMA + ".v"):
            raise ValidationError(f"schema_version desconocido: {self.schema_version!r}")
        if self.timestamp_utc is not None:
            if self.timestamp_utc.tzinfo is None or self.timestamp_utc.utcoffset() is None:
                raise ValidationError("timestamp_utc debe ser consciente de zona (no naive); "
                                      "no se asume UTC sobre un valor ambiguo")
        for name in ("process_id", "thread_id", "native_event_id"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or value < 0):
                raise ValidationError(f"{name} debe ser un entero >= 0 o None (recibido {value!r})")
        if self.provenance is None:
            object.__setattr__(self, "provenance", Provenance(collector=self.source,
                                                              received_monotonic=self.monotonic_timestamp))

    # --- Construcción -------------------------------------------------------------------------
    @classmethod
    def create(cls, source: str, *, payload: Optional[Mapping[str, Any]] = None,
               observation: ObservationQuality = ObservationQuality.UNKNOWN,
               host: Optional[str] = None, note: str = "", **kwargs: Any) -> "Event":
        """Crea un evento rellenando la procedencia (collector=source, calidad de observación)."""
        mono = kwargs.pop("monotonic_timestamp", None)
        prov = Provenance(collector=source, host=host, received_monotonic=mono,
                          observation=observation, note=note)
        return cls(source=source, payload=dict(payload or {}), monotonic_timestamp=mono,
                   provenance=prov, **kwargs)

    def with_correlation(self, correlation_id: str) -> "Event":
        """Devuelve una copia con `correlation_id` (los eventos son inmutables)."""
        return replace(self, correlation_id=correlation_id)

    # --- Serialización ------------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """Dict JSON-serializable. `payload`/`raw` deben contener ya tipos serializables."""
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "source": self.source,
            "provider_name": self.provider_name,
            "provider_guid": self.provider_guid,
            "event_type": self.event_type,
            "native_event_id": self.native_event_id,
            "timestamp_utc": self.timestamp_utc.isoformat() if self.timestamp_utc else None,
            "timestamp_raw": self.timestamp_raw,
            "clock_type": self.clock_type.value,
            "monotonic_timestamp": self.monotonic_timestamp,
            "process_id": self.process_id,
            "thread_id": self.thread_id,
            "correlation_id": self.correlation_id,
            "payload": dict(self.payload),
            "raw": dict(self.raw) if self.raw is not None else None,
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }

    def to_json(self, **json_kwargs: Any) -> str:
        try:
            return json.dumps(self.to_dict(), ensure_ascii=False, **json_kwargs)
        except (TypeError, ValueError) as exc:
            raise SerializationError(f"no se pudo serializar el evento a JSON: {exc}") from exc

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Event":
        """Reconstruye un evento comprobando la compatibilidad de versión de esquema."""
        if not isinstance(d, Mapping):
            raise SerializationError("se esperaba un objeto/dict para reconstruir el evento")
        version = str(d.get("schema_version", ""))
        _check_schema_major(version)
        prov = d.get("provenance")
        return cls(
            source=d.get("source", ""),
            schema_version=version or EVENT_SCHEMA_VERSION,
            event_id=d.get("event_id") or uuid4().hex,
            provider_name=d.get("provider_name"),
            provider_guid=d.get("provider_guid"),
            event_type=d.get("event_type"),
            native_event_id=d.get("native_event_id"),
            timestamp_utc=_parse_dt(d.get("timestamp_utc"), "timestamp_utc"),
            timestamp_raw=d.get("timestamp_raw"),
            clock_type=_enum(ClockType, d.get("clock_type"), ClockType.UNKNOWN),
            monotonic_timestamp=d.get("monotonic_timestamp"),
            process_id=d.get("process_id"),
            thread_id=d.get("thread_id"),
            correlation_id=d.get("correlation_id"),
            payload=dict(d.get("payload") or {}),
            raw=(dict(d["raw"]) if d.get("raw") is not None else None),
            provenance=Provenance.from_dict(prov) if isinstance(prov, Mapping) else None,
        )

    @classmethod
    def from_json(cls, text: str) -> "Event":
        try:
            return cls.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise SerializationError(f"JSON inválido: {exc}") from exc


# --- Utilidades internas ----------------------------------------------------------------------
def _check_schema_major(version: str) -> None:
    if not version.startswith(EVENT_SCHEMA + ".v"):
        raise SchemaVersionError(f"esquema desconocido: {version!r}")
    try:
        major = int(version.rsplit(".v", 1)[1].split(".")[0])
    except (ValueError, IndexError) as exc:
        raise SchemaVersionError(f"no se pudo leer la versión mayor de {version!r}") from exc
    if major != EVENT_SCHEMA_MAJOR:
        raise SchemaVersionError(
            f"versión de esquema incompatible: {version} (este núcleo entiende la v{EVENT_SCHEMA_MAJOR})")


def _parse_dt(value: Any, field_name: str) -> Optional[_dt.datetime]:
    if value is None:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise SerializationError(f"{field_name} no es ISO-8601 válido: {value!r}") from exc
    if parsed.tzinfo is None:
        raise SerializationError(f"{field_name} debe incluir zona horaria: {value!r}")
    return parsed


def _enum(enum_cls, value, default):
    if value is None:
        return default
    try:
        return enum_cls(value)
    except ValueError:
        return default
