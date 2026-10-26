# Lozarus — Contratos y modelo de eventos (Entregable C)

> Contratos entre colectores, bus de eventos y motores de detección; modelos de datos, estados,
> errores y ejemplos serializados. Implementado en `core/` y cubierto por `tests/` (29 pruebas, sin
> admin/ETW/PySide6).

## 1. Modelo común de evento — `core.events.Event` (`lozarus.event.v1`)

Inmutable (`frozen dataclass`). Agnóstico del colector: ETW es solo el primer productor.

| Campo | Tipo | Regla |
|---|---|---|
| `event_id` | `str` | Identificador **único** (uuid4 por defecto). |
| `schema_version` | `str` | `lozarus.event.v1`. Versión mayor incompatible → se rechaza al reconstruir. |
| `source` | `str` | Nombre del colector (obligatorio). |
| `provider_name` / `provider_guid` | `str?` | Del proveedor, si existen; si no, `None`. |
| `event_type` | `str?` | Tipo legible (opcode/tarea), si se conoce. |
| `native_event_id` | `int?` | Id de evento del propio proveedor (p. ej. 1 = ProcessStart). |
| `timestamp_utc` | `datetime?` | **Consciente de zona** o `None`. **Nunca** naive; nunca se asume UTC. |
| `timestamp_raw` | `int?` | Valor temporal **original** sin convertir (auditoría). |
| `clock_type` | `ClockType` | Reloj de `timestamp_raw` (ver §2). |
| `monotonic_timestamp` | `float?` | `time.monotonic()` de recepción, si se dispone. |
| `process_id` / `thread_id` | `int?` | `>= 0` o `None`. **No se inventan.** |
| `correlation_id` | `str?` | Solo si hay una correlación **justificada**. |
| `payload` | `dict` | Campos **normalizados** (separados de los metadatos). |
| `raw` | `dict?` | Datos **originales** del proveedor (auditoría), separados del payload. |
| `provenance` | `Provenance` | Procedencia y calidad de observación (ver §3). |

**Reglas (verificadas por pruebas):** marcas temporales explícitas y con zona; se conserva el crudo;
no se inventan campos ausentes; `payload` (normalizado) separado de `raw` (original); serialización
JSON determinista con comprobación de versión de esquema.

**Compatibilidad de esquema:** `lozarus.event.vN`. Cambios **aditivos** (campos nuevos opcionales)
mantienen la versión mayor; `from_dict` ignora claves de sobre desconocidas. Un cambio **incompatible**
sube la mayor y `from_dict` de otra mayor lanza `SchemaVersionError`.

## 2. `ClockType`
`filetime` (100 ns desde 1601, hora de sistema / ETW ClientContext=2) · `qpc` (contador de alto
rendimiento; requiere el `LogfileHeader` para convertir) · `cpu_cycles` · **`unknown`** (ambiguo: **no**
convertir a UTC por suposición; dejar `timestamp_utc=None` y conservar el crudo).

## 3. `Provenance` y `ObservationQuality`
`Provenance`: `collector`, `host?`, `received_utc`, `received_monotonic?`, `observation`, `note`.
`ObservationQuality`: `complete` · `partial` · `raw_only` · `unknown`. Es la base de la confianza del
evento y de OBSIDIAN.

## 4. Contabilidad de pérdidas y calidad de observación (prioritario)

Tres estados **siempre** diferenciados (`core.contracts.LossState`):

| Estado | Valor | Significado |
|---|---|---|
| `UNKNOWN` | `None` | La fuente no lo reporta o no se ha medido. **Nunca es 0.** |
| `NONE` | `0` | **Cero confirmado.** |
| `DETECTED` | `> 0` | Pérdidas **detectadas**. |

Y dos orígenes **con contadores distintos**:
- **Pérdida de la FUENTE** (p. ej. `EventsLost` / `RealTimeBuffersLost` de ETW) → en `SensorHealth`
  (`source_events_lost`, `source_buffers_lost`), de tipo `Optional[int]` (puede ser desconocida).
- **Descartes INTERNOS del bus** (cola llena) → en `BusMetrics.dropped`, `int` (siempre conocido).

`SensorHealth` (de `core.contracts`): `name`, `alive`, `started`, `events_total`, `source_events_lost`,
`source_buffers_lost`, `last_event_utc?`, `init_error?`, `degraded`, `note` + propiedades
`events_loss_state` / `buffers_loss_state`.

## 5. Contrato de los colectores (`core.contracts`)

**Decisión Protocol + ABC (justificada):**
- `Collector` y `EventSink` son `typing.Protocol` (contrato **estructural**): los dobles de prueba y
  los colectores cumplen sin heredar → desacoplamiento y pruebas sin Windows.
- `BaseCollector` es una **ABC opcional** con el andamiaje (sink, contadores, `health()` por defecto,
  `_emit()`). Se evita la herencia obligatoria y la duplicación.

```python
class EventSink(Protocol):
    def publish(self, event: Event) -> bool: ...        # False si se descartó

class Collector(Protocol):
    name: str
    def start(self) -> None: ...                        # idempotente; no lanza por permisos
    def stop(self) -> None: ...                         # idempotente; libera recursos
    def health(self) -> SensorHealth: ...               # cobertura y pérdidas

class BaseCollector(ABC):                               # opcional
    def _emit(self, event) -> bool: ...                 # publica + cuenta; nunca lanza por el sink
    def source_loss(self) -> tuple[int|None, int|None]: # por defecto (None, None) = desconocida
    def health(self) -> SensorHealth: ...
```
Reglas: un colector **no** importa la GUI ni ejecuta respuestas; recibe un `EventSink` y publica en él.

## 6. Bus de eventos (`core.bus.EventBus`) — garantías REALES

- **Cola acotada** (`maxsize`) + **política de overflow** explícita: `DROP_NEWEST` (defecto),
  `DROP_OLDEST`, `BLOCK` (timeout finito). Nunca se bloquea indefinidamente.
- **Orden:** FIFO dentro del bus (no reordena por tiempo de evento).
- **Entrega:** **como máximo una vez** por evento encolado (no «exactamente una vez»: no existe tal
  mecanismo). Ante cola llena se descarta y se cuenta en `dropped`.
- **Duplicados:** el bus no los introduce.
- **Despacho desacoplado de Qt:** los suscriptores corren en el hilo del bus; un adaptador de `ui/`
  marshalea al hilo de la interfaz. El bus no importa PySide6.
- **Cierre ordenado:** `stop(drain=True)` procesa lo pendiente y termina el hilo; idempotente.
- **Métricas** (`BusMetrics`): `published`, `enqueued`, `delivered`, `dropped`, `subscriber_errors`,
  `max_depth`, `current_depth`. Invariante probado: `enqueued + dropped == published` y, con `drain`,
  `delivered == enqueued`.

## 7. Errores (`core.errors`)
`LozarusError` → `ValidationError`, `SerializationError` → `SchemaVersionError`, `CollectorError`,
`BusError`. El núcleo nunca lanza excepciones genéricas sin contexto.

## 8. Ejemplos de evento serializado

**Ejemplo 1 — ProcessStart (ETW) normalizado, reloj FILETIME, parseo completo:**
```json
{
  "schema_version": "lozarus.event.v1",
  "event_id": "7f3a…",
  "source": "etw",
  "provider_name": "PROCESSSTART",
  "provider_guid": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
  "event_type": "ProcessStart",
  "native_event_id": 1,
  "timestamp_utc": "2026-10-20T12:00:00+00:00",
  "timestamp_raw": 133700000000000000,
  "clock_type": "filetime",
  "monotonic_timestamp": null,
  "process_id": 4242, "thread_id": 99, "correlation_id": null,
  "payload": { "ImageName": "notepad.exe", "ParentProcessID": 4242 },
  "raw": null,
  "provenance": { "collector": "etw", "host": null, "received_utc": "<fijado al recibir>",
                  "received_monotonic": null, "observation": "complete", "note": "" }
}
```

**Ejemplo 2 — evento con reloj DESCONOCIDO (sin UTC) y parseo solo-crudo:**
```json
{
  "schema_version": "lozarus.event.v1",
  "event_id": "b91c…",
  "source": "etw",
  "provider_name": null, "provider_guid": "{…}",
  "event_type": null, "native_event_id": null,
  "timestamp_utc": null,
  "timestamp_raw": 123456789,
  "clock_type": "unknown",
  "monotonic_timestamp": null,
  "process_id": null, "thread_id": null, "correlation_id": null,
  "payload": {},
  "raw": { "UserData": "0102ff00" },
  "provenance": { "collector": "etw", "host": null, "received_utc": "<fijado al recibir>",
                  "received_monotonic": null, "observation": "raw_only", "note": "" }
}
```
Nótese: sin marca fiable → `timestamp_utc=null` y `clock_type="unknown"`, pero `timestamp_raw` se
conserva; el payload vacío no se inventa y el dato crudo va en `raw`.

## 9. Guía de integración del colector ETW de producción (fase siguiente)

1. `collectors/etw_collector.py` hereda de `BaseCollector`, recibe el `EventBus` como sink.
2. Encapsula pywintrace (o un consumidor ctypes propio) tras la interfaz; crea la sesión con
   `ClientContext=2` (FILETIME determinista).
3. En el callback: mapea el dict `lozarus.etw.v0` del spike → `Event` (`Event.create('etw', …)`),
   separando `payload` (normalizado) de `raw` (original), y publica con `self._emit(event)`.
4. `source_loss()` lee `EventsLost`/`RealTimeBuffersLost` de las propiedades de la sesión (como el
   spike); si no se puede medir, devuelve `(None, None)` (desconocida, nunca 0).
5. `start()` degrada sin lanzar si falta Administrador (registra `init_error`); `stop()` cierra la
   sesión (sin dejarla huérfana).
