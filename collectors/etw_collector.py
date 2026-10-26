# -*- coding: utf-8 -*-
"""
Colector ETW de producción: implementa el contrato `BaseCollector` y publica eventos `Event`
normalizados en el bus de Lozarus. Porta la vía validada en `spikes/etw/` a los contratos de la
Fase 2, con ciclo de vida y propiedad de sesión explícitos.

Diseño clave (para poder probarlo sin Administrador ni pywintrace):
  - La creación de la sesión ETW se inyecta mediante una `session_factory`. La real
    (`pywintrace_session_factory`) importa pywintrace de forma PEREZOSA (solo al arrancar); las
    pruebas inyectan una sesión falsa y ejercitan todo el ciclo de vida, la normalización y las
    métricas sin tocar Windows.
  - La normalización ETW→Event (`normalize_etw`) es pura y testable con eventos sintéticos con la
    forma real que entrega pywintrace 0.2.0 (verificada).

Propiedad de la sesión (crítico): cada instancia crea una sesión con nombre ÚNICO
`Lozarus-ETW-<pid>-<uuid8>` y `ignore_exists_error=False`, de modo que NUNCA adopta ni detiene una
sesión que no haya creado. `stop()` solo actúa sobre el objeto de sesión propio; jamás se recorren ni
se detienen las sesiones de `logman query -ets`.
"""

from __future__ import annotations

import datetime as _dt
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol, Tuple
from uuid import uuid4

from core.contracts import BaseCollector, EventSink
from core.events import ClockType, Event, ObservationQuality

# Proveedores documentados, NO restringidos a procesos antimalware protegidos (igual que el spike).
ETW_PROVIDERS: Dict[str, Dict[str, str]] = {
    "kernel-process": {"name": "Microsoft-Windows-Kernel-Process",
                       "guid": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"},
    "dns-client": {"name": "Microsoft-Windows-DNS-Client",
                   "guid": "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"},
    "powershell": {"name": "Microsoft-Windows-PowerShell",
                   "guid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"},
}

# Clave de reloj de ETW (WNODE_HEADER.ClientContext). 2 = hora de sistema (FILETIME), documentado por
# Microsoft. pywintrace no define la constante; se usa el literal con esta nota.
ETW_CLOCK_SYSTEMTIME = 2
ETW_CLOCK_QPC = 1

# Claves de metadatos del dict de pywintrace que NO forman parte del payload del evento.
_META_KEYS = {"EventHeader", "Task Name", "Description", "EventExtendedData", "UserData"}

_FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
_YEAR_MIN, _YEAR_MAX = 1980, 2200


def _filetime_to_utc(raw: Any) -> Tuple[Optional[_dt.datetime], ClockType]:
    """Convierte un TimeStamp a UTC si es un FILETIME plausible; si no, (None, UNKNOWN)."""
    if not isinstance(raw, int) or raw <= 0:
        return None, ClockType.UNKNOWN
    try:
        when = _FILETIME_EPOCH + _dt.timedelta(microseconds=raw / 10)
    except (OverflowError, OSError, ValueError):
        return None, ClockType.UNKNOWN
    if _YEAR_MIN <= when.year <= _YEAR_MAX:
        return when, ClockType.FILETIME
    return None, ClockType.UNKNOWN


def normalize_etw(raw_event: Tuple[int, Dict[str, Any]], source: str,
                  host: Optional[str] = None, recv_monotonic: Optional[float] = None,
                  client_context: int = ETW_CLOCK_SYSTEMTIME) -> Event:
    """
    Convierte un evento crudo de pywintrace `(event_id, out)` en un `Event` del núcleo. Separa el
    payload (propiedades TDH normalizadas) de los metadatos (que van a `raw`), conserva la marca
    temporal original y trata el reloj con honestidad: solo calcula `timestamp_utc` cuando puede.
    """
    if isinstance(raw_event, tuple) and len(raw_event) == 2:
        _event_id, out = raw_event
    else:
        _event_id, out = None, raw_event
    out = out if isinstance(out, dict) else {}

    header = out.get("EventHeader", {}) if isinstance(out.get("EventHeader"), dict) else {}
    desc = header.get("EventDescriptor", {}) if isinstance(header.get("EventDescriptor"), dict) else {}

    # Marca temporal: con ClientContext=2 el TimeStamp es FILETIME; en otro caso no se asume.
    ts_raw = header.get("TimeStamp")
    if client_context == ETW_CLOCK_SYSTEMTIME:
        ts_utc, clock = _filetime_to_utc(ts_raw)
    elif client_context == ETW_CLOCK_QPC:
        ts_utc, clock = None, ClockType.QPC          # QPC: requiere LogfileHeader; no se convierte aquí
    else:
        ts_utc, clock = None, ClockType.UNKNOWN

    payload = {k: v for k, v in out.items() if k not in _META_KEYS}
    user_data = out.get("UserData")
    if user_data is None:
        observation = ObservationQuality.COMPLETE if payload else ObservationQuality.PARTIAL
    else:
        observation = ObservationQuality.RAW_ONLY   # pywintrace no pudo parsear: solo datos crudos

    raw_meta: Dict[str, Any] = {
        "opcode": desc.get("Opcode"), "level": desc.get("Level"),
        "keyword": desc.get("Keyword"), "version": desc.get("Version"),
        "channel": desc.get("Channel"), "activity_id": header.get("ActivityId"),
        "description": out.get("Description", ""),
    }
    if isinstance(user_data, (bytes, bytearray)):
        raw_meta["user_data_hex"] = bytes(user_data).hex()

    return Event.create(
        source=source, payload=payload, host=host, observation=observation,
        monotonic_timestamp=recv_monotonic,
        provider_name=out.get("Task Name"),
        provider_guid=header.get("ProviderId"),
        event_type=out.get("Task Name"),
        native_event_id=desc.get("Id", _event_id),
        timestamp_utc=ts_utc, timestamp_raw=ts_raw if isinstance(ts_raw, int) else None,
        clock_type=clock,
        process_id=header.get("ProcessId"), thread_id=header.get("ThreadId"),
        raw=raw_meta,
    )


# ============================================================================================
# Sesión ETW (inyectable): protocolo + adaptador real de pywintrace
# ============================================================================================
class EtwSession(Protocol):
    """Lo que el colector necesita de una sesión ETW. Permite inyectar una falsa en las pruebas."""
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def read_loss(self) -> Tuple[Optional[int], Optional[int]]: ...  # (events_lost, buffers_lost)


class PywintraceSession:
    """
    Adaptador real sobre pywintrace. Importa la librería de forma PEREZOSA (en `start()`), fija
    `ClientContext` en las propiedades de la sesión y entrega los eventos crudos al callback del
    colector. `read_loss()` lee EventsLost/RealTimeBuffersLost de las propiedades (válido tras STOP).
    """

    def __init__(self, session_name: str, provider_name: str, provider_guid: str,
                 on_event: Callable[[Any], None], client_context: int, ring_buf_kb: int):
        self._name = session_name
        self._pname = provider_name
        self._pguid = provider_guid
        self._cb = on_event
        self._cc = client_context
        self._ring_kb = ring_buf_kb
        self._job = None

    def start(self) -> None:
        from etw import ETW, ProviderInfo              # import perezoso: solo al arrancar de verdad
        from etw.GUID import GUID
        from etw.etw import TraceProperties
        props = TraceProperties(ring_buf_size=self._ring_kb)
        try:
            props.get().contents.Wnode.ClientContext = self._cc   # 2 = hora de sistema (FILETIME)
        except Exception:
            pass  # si la implementación no lo permite, normalize_etw tratará el reloj como ambiguo
        self._job = ETW(session_name=self._name,
                        providers=[ProviderInfo(self._pname, GUID(self._pguid))],
                        properties=props, event_callback=self._cb, ignore_exists_error=False)
        self._job.start()

    def stop(self) -> None:
        if self._job is not None:
            self._job.stop()

    def read_loss(self) -> Tuple[Optional[int], Optional[int]]:
        if self._job is None:
            return (None, None)
        try:
            p = self._job.properties.get().contents
            return (int(p.EventsLost), int(p.RealTimeBuffersLost))
        except Exception:
            return (None, None)


def pywintrace_session_factory(session_name, provider_name, provider_guid, on_event,
                               client_context, ring_buf_kb) -> EtwSession:
    return PywintraceSession(session_name, provider_name, provider_guid, on_event,
                             client_context, ring_buf_kb)


def _describe_error(exc: Exception) -> str:
    winerr = getattr(exc, "winerror", None)
    if winerr == 5 or "denied" in str(exc).lower() or "denegado" in str(exc).lower():
        return "acceso denegado: iniciar la sesión ETW requiere Administrador o «Performance Log Users»"
    if isinstance(exc, ImportError):
        return f"pywintrace no disponible: {exc}"
    return f"{type(exc).__name__}: {exc}" + (f" (winerror={winerr})" if winerr is not None else "")


@dataclass
class EtwCollectorMetrics:
    """Métricas del colector. Pérdida de ETW y descartes del bus se cuentan POR SEPARADO."""
    started: bool
    session_name: str
    events_received: int        # callbacks recibidos del consumidor ETW
    events_published: int       # aceptados por el bus (publish True)
    bus_dropped: int            # descartados por la cola del bus (publish False) — descarte INTERNO
    consumer_errors: int        # excepciones al normalizar/procesar un evento
    source_events_lost: Optional[int]    # EventsLost de ETW (None mientras corre; conocido tras STOP)
    source_buffers_lost: Optional[int]   # RealTimeBuffersLost de ETW (idem)
    init_error: Optional[str]
    stop_duration_s: Optional[float]


# ============================================================================================
# Colector
# ============================================================================================
class EtwCollector(BaseCollector):
    """Colector ETW de producción. Cumple el contrato `BaseCollector`/`Collector`."""

    def __init__(self, sink: EventSink, provider: str = "kernel-process", *,
                 provider_name: Optional[str] = None, provider_guid: Optional[str] = None,
                 session_factory: Optional[Callable[..., EtwSession]] = None,
                 client_context: int = ETW_CLOCK_SYSTEMTIME, ring_buf_kb: int = 1024,
                 host: Optional[str] = None, name: Optional[str] = None):
        if provider_name and provider_guid:
            self._provider = {"name": provider_name, "guid": provider_guid}
            prov_key = provider_name
        else:
            if provider not in ETW_PROVIDERS:
                raise ValueError(f"proveedor desconocido: {provider} (usa uno de {list(ETW_PROVIDERS)})")
            self._provider = ETW_PROVIDERS[provider]
            prov_key = provider
        super().__init__(name or f"etw:{prov_key}", sink)
        self._client_context = client_context
        self._ring_kb = ring_buf_kb
        self._host = host
        self._factory = session_factory or pywintrace_session_factory
        self._session: Optional[EtwSession] = None
        # Nombre de sesión ÚNICO e inequívoco → propiedad clara, sin colisiones entre instancias.
        self._session_name = f"Lozarus-ETW-{os.getpid()}-{uuid4().hex[:8]}"
        # Métricas (separadas): recepción / publicación / descartes del bus / errores / pérdida ETW
        self._received = 0
        self._published = 0
        self._bus_dropped = 0
        self._consumer_errors = 0
        self._final_events_lost: Optional[int] = None
        self._final_buffers_lost: Optional[int] = None
        self._stop_duration_s: Optional[float] = None

    @property
    def session_name(self) -> str:
        return self._session_name

    # --- Callback del consumidor ETW ---------------------------------------------------------
    def _on_event(self, raw_event: Any) -> None:
        """Ruta de recepción: normaliza y publica. Nunca bloquea (publish del bus es no bloqueante)
        ni lanza (un evento mal formado solo incrementa consumer_errors)."""
        self._received += 1
        try:
            event = normalize_etw(raw_event, self.name, self._host, time.monotonic(),
                                  self._client_context)
        except Exception:
            self._consumer_errors += 1
            return
        if self._emit(event):      # BaseCollector._emit → sink.publish; cuenta events_total
            self._published += 1
        else:
            self._bus_dropped += 1  # descarte INTERNO del bus (distinto de la pérdida de ETW)

    # --- Ciclo de vida -----------------------------------------------------------------------
    def start(self) -> None:
        """Arranca la sesión. Idempotente. No lanza por permisos: registra `init_error` y no arranca."""
        if self._started:
            return
        try:
            self._session = self._factory(self._session_name, self._provider["name"],
                                          self._provider["guid"], self._on_event,
                                          self._client_context, self._ring_kb)
            self._session.start()
            self._started = True
            self._init_error = None
        except Exception as exc:
            self._init_error = _describe_error(exc)
            self._started = False
            self._session = None

    def stop(self) -> None:
        """Detiene y libera SOLO la sesión propia. Idempotente y seguro aunque no se arrancara."""
        session = self._session
        if session is None:
            self._started = False
            return
        t0 = time.monotonic()
        try:
            session.stop()
        except Exception as exc:
            if not self._init_error:
                self._init_error = f"al parar la sesión: {_describe_error(exc)}"
        try:
            self._final_events_lost, self._final_buffers_lost = session.read_loss()
        except Exception:
            pass  # si no se pudo leer, queda en None (desconocida), nunca 0
        self._stop_duration_s = round(time.monotonic() - t0, 4)
        self._started = False
        self._session = None

    # --- Salud / pérdidas --------------------------------------------------------------------
    def source_loss(self) -> Tuple[Optional[int], Optional[int]]:
        """Pérdida de la FUENTE (ETW). LIMITACIÓN: con pywintrace solo se conoce tras STOP; mientras
        la sesión corre es DESCONOCIDA (None), nunca 0."""
        return (self._final_events_lost, self._final_buffers_lost)

    def metrics(self) -> EtwCollectorMetrics:
        ev, bf = self.source_loss()
        return EtwCollectorMetrics(
            started=self._started, session_name=self._session_name,
            events_received=self._received, events_published=self._published,
            bus_dropped=self._bus_dropped, consumer_errors=self._consumer_errors,
            source_events_lost=ev, source_buffers_lost=bf,
            init_error=self._init_error, stop_duration_s=self._stop_duration_s,
        )
