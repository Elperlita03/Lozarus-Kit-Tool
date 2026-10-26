# -*- coding: utf-8 -*-
"""
Normalización de eventos ETW crudos (formato de pywintrace) a un modelo sencillo y estable para
Lozarus. ESTE módulo es puro (solo stdlib): no importa pywintrace ni toca Windows, así que puede
probarse en cualquier sistema. El prototipo `etw_spike.py` le pasa lo que entrega pywintrace.

Formato de entrada (verificado en pywintrace 0.2.0): el callback recibe una tupla
`(event_id, out)` donde `out` es un dict con:
  - out['EventHeader'] = { Size, HeaderType, Flags, EventProperty, ThreadId, ProcessId,
                           TimeStamp, ProviderId, EventDescriptor{Id,Version,Channel,Level,
                           Opcode,Task,Keyword}, KernelTime, UserTime, ActivityId }
  - out['Task Name']   = nombre de tarea/proveedor en mayúsculas (p. ej. 'PROCESSSTART')
  - out['Description']  = mensaje del evento (puede ser '')
  - resto de claves de primer nivel = propiedades TDH ya parseadas (payload del evento)
  - out['UserData']     = bytes crudos SOLO si hubo fallo de parseo y se pidió el volcado crudo

Salida: un dict con esquema 'lozarus.etw.v0' (ver NORMALIZED_SCHEMA).
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, Optional, Tuple

NORMALIZED_SCHEMA = "lozarus.etw.v0"

# Claves de `out` que son metadatos/cabecera y NO forman parte del payload del evento
_META_KEYS = {"EventHeader", "Task Name", "Description", "EventExtendedData", "UserData"}

# Rango plausible para interpretar TimeStamp como FILETIME (100 ns desde 1601-01-01 UTC).
# Fuera de él, lo más probable es que el reloj de la sesión sea QPC/ciclos de CPU y la
# conversión directa no sea válida: se deja timestamp_utc=None y clock='ambiguous'.
_FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
_YEAR_MIN, _YEAR_MAX = 1980, 2200


def filetime_to_utc(timestamp_raw: int) -> Tuple[Optional[str], str]:
    """
    Convierte EventHeader.TimeStamp a ISO-8601 UTC si es plausible como FILETIME.
    Devuelve (iso_o_None, clock) donde clock ∈ {'filetime', 'ambiguous'}.

    Nota: pywintrace no fija Wnode.ClientContext, así que el reloj de la sesión queda en el valor
    por defecto del sistema y puede NO ser hora de sistema (FILETIME). Por eso se valida el rango.
    Para el colector de producción se recomienda fijar ClientContext=2 (EVENT_TRACE_CLOCK_SYSTEMTIME)
    y así obtener siempre FILETIME convertible de forma determinista.
    """
    if not isinstance(timestamp_raw, int) or timestamp_raw <= 0:
        return None, "ambiguous"
    try:
        when = _FILETIME_EPOCH + _dt.timedelta(microseconds=timestamp_raw / 10)
    except (OverflowError, OSError, ValueError):
        return None, "ambiguous"
    if _YEAR_MIN <= when.year <= _YEAR_MAX:
        return when.isoformat(), "filetime"
    return None, "ambiguous"


def normalize(event: Tuple[int, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Convierte un evento crudo de pywintrace `(event_id, out)` al modelo normalizado de Lozarus.
    Es defensivo: tolera claves ausentes y nunca lanza por un evento mal formado (devuelve lo que
    puede y marca parse_complete=False si detecta datos crudos sin parsear).
    """
    if isinstance(event, tuple) and len(event) == 2:
        event_id, out = event
    else:                         # tolera que se pase solo el dict
        event_id, out = None, event
    out = out if isinstance(out, dict) else {}

    header = out.get("EventHeader", {}) if isinstance(out.get("EventHeader"), dict) else {}
    descriptor = header.get("EventDescriptor", {}) if isinstance(header.get("EventDescriptor"), dict) else {}

    timestamp_raw = header.get("TimeStamp")
    timestamp_utc, clock = filetime_to_utc(timestamp_raw) if timestamp_raw is not None else (None, "ambiguous")

    # El payload son las claves de primer nivel que no son metadatos conocidos
    fields = {k: v for k, v in out.items() if k not in _META_KEYS}

    raw = out.get("UserData")
    parse_complete = raw is None
    raw_hex = raw.hex() if isinstance(raw, (bytes, bytearray)) else None

    return {
        "schema": NORMALIZED_SCHEMA,
        "event_id": descriptor.get("Id", event_id),
        "provider_guid": header.get("ProviderId"),
        "provider_name": out.get("Task Name"),      # pywintrace coloca aquí el nombre de tarea/proveedor
        "task_name": out.get("Task Name"),
        "opcode": descriptor.get("Opcode"),
        "level": descriptor.get("Level"),
        "version": descriptor.get("Version"),
        "keyword": descriptor.get("Keyword"),
        "timestamp_raw": timestamp_raw,
        "timestamp_utc": timestamp_utc,
        "clock": clock,
        "process_id": header.get("ProcessId"),
        "thread_id": header.get("ThreadId"),
        "activity_id": header.get("ActivityId"),
        "description": out.get("Description", ""),
        "fields": fields,
        "parse_complete": parse_complete,
        "raw_user_data_hex": raw_hex,
    }


def summarize(normalized: Dict[str, Any], max_fields: int = 6) -> str:
    """Una línea legible de un evento normalizado, para la muestra por consola."""
    ts = normalized.get("timestamp_utc") or f"raw={normalized.get('timestamp_raw')}"
    name = normalized.get("provider_name") or normalized.get("provider_guid") or "?"
    pid = normalized.get("process_id")
    field_items = list(normalized.get("fields", {}).items())[:max_fields]
    fields = "  ".join(f"{k}={v}" for k, v in field_items)
    tail = "" if normalized.get("parse_complete") else "  [parseo incompleto]"
    return f"{ts}  {name}  id={normalized.get('event_id')} op={normalized.get('opcode')} pid={pid}  {fields}{tail}"
