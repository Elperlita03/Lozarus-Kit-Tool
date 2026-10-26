# 03 — Colector ETW de producción

> Fase 3A. Porta la vía validada en `spikes/etw/` a los contratos de la Fase 2
> ([`core/contracts.py`](../core/contracts.py), [`core/events.py`](../core/events.py),
> [`core/bus.py`](../core/bus.py)). Un colector observa **una** fuente (ETW) y publica eventos
> `Event` normalizados en el bus. **No** importa la GUI ni ejecuta respuestas.
>
> Archivo: [`collectors/etw_collector.py`](../collectors/etw_collector.py).

---

## 1. Diseño interno

Tres piezas separadas para poder probar sin Administrador ni `pywintrace`:

| Pieza | Responsabilidad | Testable sin ETW |
|---|---|---|
| `normalize_etw(raw_event, source, …)` | Función **pura** ETW→`Event`. Separa payload de metadatos, trata el reloj con honestidad. | Sí (eventos sintéticos con la forma real de pywintrace 0.2.0). |
| `EtwSession` (Protocol) + `PywintraceSession` | Adaptador real de la sesión ETW. Import **perezoso** de pywintrace (solo en `start()`). | Se inyecta una sesión falsa. |
| `EtwCollector(BaseCollector)` | Ciclo de vida, propiedad de sesión, métricas, ruta de recepción→publicación. | Sí (vía `session_factory`). |

La sesión se crea mediante una **`session_factory` inyectable**. En producción es
`pywintrace_session_factory`; en las pruebas se inyecta una falsa que entrega eventos sintéticos y
devuelve una pérdida configurable. Así el ciclo de vida completo, la normalización y las métricas se
ejercitan en CI sin tocar Windows ni requerir privilegios.

### Modelo de datos

Se reutiliza el `Event` del núcleo (`lozarus.event.v1`, dataclass congelada). El colector **no**
define un formato propio:

- **payload** = propiedades TDH ya parseadas por pywintrace (todo lo que no es metadato).
- **raw** = metadatos del `EventDescriptor`/`EventHeader`: `opcode`, `level`, `keyword`, `version`,
  `channel`, `activity_id`, `description`, y `user_data_hex` solo si pywintrace no pudo parsear.
- **provenance** = `collector`, `host`, `received_utc`, `received_monotonic`, `observation`.
- Campos de identidad del evento: `provider_name`, `provider_guid`, `native_event_id`,
  `process_id`, `thread_id`, `timestamp_raw`, `timestamp_utc`, `clock_type`.

---

## 2. Configuración de proveedor y sesión

### Proveedores (`ETW_PROVIDERS`)

Proveedores **manifest** documentados y accesibles, **no** proveedores protegidos (antimalware/PPL):

| Clave | Nombre | GUID |
|---|---|---|
| `kernel-process` (por defecto) | `Microsoft-Windows-Kernel-Process` | `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` |
| `dns-client` | `Microsoft-Windows-DNS-Client` | `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}` |
| `powershell` | `Microsoft-Windows-PowerShell` | `{A0C1853B-5C40-4B15-8766-3CF1C58F985A}` |

También se puede pasar `provider_name=` + `provider_guid=` para un proveedor arbitrario documentado.

### Sesión

- **Nombre único e inequívoco:** `Lozarus-ETW-<pid>-<uuid8>`. No es «NT Kernel Logger», por lo que
  pywintrace abre una **sesión ordinaria de tiempo real** (`kernel_trace=False`), no la sesión de
  kernel heredada. → No requiere `SeSystemProfilePrivilege`.
- `ignore_exists_error=False`: si por lo que fuera el nombre ya existiera, se **falla**, nunca se
  adopta una sesión ajena.
- Búfer en anillo configurable (`ring_buf_kb`, por defecto 1024 KB).
- `ClientContext` de `WNODE_HEADER` fijado explícitamente (ver §5).

---

## 3. Privilegios

**Iniciar una sesión ETW de tiempo real ordinaria como la nuestra requiere Administrador o
pertenencia al grupo «Performance Log Users».** No se generaliza: este es el requisito de **esta**
sesión concreta (proveedor manifest, sesión propia con nombre único), no de «todas las sesiones del
kernel».

Sin privilegios, `StartTrace`/`EnableTraceEx2` devuelve `ERROR_ACCESS_DENIED` (winerror 5). El
colector **no lanza**: registra `init_error` (`"acceso denegado: … requiere Administrador o
«Performance Log Users»"`), deja `started=False` y queda `degraded`.

### Comando elevado de referencia

En una consola **como Administrador** (p. ej. el venv del spike con pywintrace instalado):

```bash
python tests/test_etw_integration.py
python tests/bench_etw_collector.py --seconds 20
```

El entorno principal de desarrollo es **no-admin** y **no** tiene pywintrace instalado, así que estas
pruebas se **SALTAN** de forma explícita (imprimen `PENDIENTE`); no se fabrican resultados.

### Límite duro

Un EDR en **modo usuario** (Python) **no** puede consumir la ETW de *Threat-Intelligence*
(`Microsoft-Windows-Threat-Intelligence`): exige un driver firmado PPL/ELAM. Queda fuera de alcance
y así está documentado.

---

## 4. Ciclo de vida y propiedad de sesión

```
__init__  →  (nombre de sesión único reservado)  →  start()  →  [callbacks _on_event]  →  stop()
```

- **`start()`** — idempotente (si ya arrancó, no hace nada). Crea la sesión vía factory y la arranca.
  Ante **cualquier** excepción (permisos, pywintrace ausente, etc.) **no propaga**: clasifica el
  error en `init_error`, deja `started=False` y `self._session=None` (sin sesión huérfana).
- **`stop()`** — detiene y libera **solo** el objeto de sesión propio. Idempotente y seguro aunque
  nunca se arrancara (`stop()` sin `start()` no hace nada). Tras `stop()` lee la pérdida de ETW
  (§6), mide la duración de parada y limpia `self._session=None`.
- **Propiedad inequívoca:** jamás se recorren las sesiones de `logman query -ets` ni se detiene
  ninguna por nombre/patrón. Solo se actúa sobre el objeto `EtwSession` que esta instancia creó. Dos
  instancias **no** pueden controlar la misma sesión porque cada una genera un nombre único y
  `ignore_exists_error=False` impide adoptar una existente.
- **Sin huérfanas tras parada normal o error recuperable:** en el camino de error de `start()` no
  queda sesión creada; tras `stop()` normal la sesión se detiene y se olvida.

### Recursos que podrían persistir ante terminación ABRUPTA

Si el proceso muere **sin** llegar a `stop()` (p. ej. `kill -9`, corte de energía), la sesión ETW del
kernel **sobrevive al proceso** (es un recurso del sistema, no del proceso). El nombre único evita
colisiones en el próximo arranque, pero la sesión anterior quedaría activa consumiendo un búfer hasta
reinicio o parada manual. **Limpieza manual** (solo sesiones `Lozarus-ETW-*`, nunca ajenas):

```bash
logman query -ets                      # localizar sesiones Lozarus-ETW-<pid>-<uuid>
logman stop "Lozarus-ETW-<pid>-<uuid>" -ets
```

Mitigación futura (fuera de alcance 3A): barrido de arranque que pare **únicamente** sesiones con el
prefijo `Lozarus-ETW-` cuyo `<pid>` ya no exista.

---

## 5. Semántica de tiempo

El `TimeStamp` de un evento ETW **no** es siempre FILETIME: su reloj lo fija `ClientContext` de la
sesión. Microsoft documenta: `1` = QPC, `2` = hora de sistema (FILETIME, 100 ns desde 1601 UTC),
`3` = ciclos de CPU. **pywintrace no lo fija por defecto.**

El adaptador fija `props.get().contents.Wnode.ClientContext = 2` (hora de sistema) de forma explícita
y tolerante: si la implementación no lo permitiera, se captura la excepción y la normalización trata
el reloj como ambiguo en lugar de asumir.

`normalize_etw` nunca asume:

| `client_context` | `clock_type` | `timestamp_utc` | `timestamp_raw` |
|---|---|---|---|
| `2` y FILETIME **plausible** (año 1980–2200) | `FILETIME` | UTC calculado | crudo conservado |
| `2` pero valor implausible | `UNKNOWN` | `None` | crudo conservado |
| `1` (QPC) | `QPC` | `None` (QPC necesita `LogfileHeader`; no se convierte aquí) | crudo conservado |
| cualquier otro | `UNKNOWN` | `None` | crudo conservado |

Siempre se conservan: **marca original** (`timestamp_raw`) + **tipo de reloj conocido**
(`clock_type`) + **UTC normalizado solo cuando es fiable** (`timestamp_utc`) + **recepción monótona**
(`provenance.received_monotonic`, vía `time.monotonic()`). Si la semántica no es segura, se marca
ambiguo (`UNKNOWN`) y se mantiene el crudo.

---

## 6. Pérdida: observable y no observable

Se miden **cinco cosas distintas, nunca sumadas entre sí**:

| Métrica | Tipo | Significado |
|---|---|---|
| `events_received` | int | callbacks recibidos del consumidor ETW |
| `events_published` | int | aceptados por el bus (`publish → True`) |
| `bus_dropped` | int | descartados por la cola del bus (`publish → False`) — **descarte INTERNO** |
| `consumer_errors` | int | excepciones al normalizar/procesar un evento |
| `source_events_lost` / `source_buffers_lost` | `Optional[int]` | `EventsLost` / `RealTimeBuffersLost` de **ETW** |

Invariante de la ruta de recepción: `events_published + bus_dropped == events_received`
(menos los `consumer_errors`, que no llegan a publicarse).

### Pérdida de ETW: mecanismo soportado y su limitación

`EventsLost`/`RealTimeBuffersLost` viven en `EVENT_TRACE_PROPERTIES` y pywintrace los expone en
`job.properties.get().contents`. **Limitación documentada:** con pywintrace estos contadores solo son
fiables **tras `ControlTrace(STOP)`**. Por eso:

- Mientras la sesión **corre**, `source_loss()` devuelve `(None, None)` → **DESCONOCIDA**.
- Tras `stop()`, devuelve el valor leído → `0` es **cero confirmado**, `>0` es pérdida detectada.
- Si la lectura falla, queda en `None`. **Nunca** se convierte un desconocido en `0`.

Esto se refleja en `SensorHealth` vía `LossState` (`UNKNOWN` / `NONE` / `DETECTED`).

> **No se mezclan** la pérdida de ETW (fuente) y los descartes del bus (interno). Son causas
> distintas (desbordamiento de búfer del kernel vs. cola del consumidor saturada) y se reportan por
> separado.

---

## 7. Política de backpressure

La ruta de recepción (`_on_event`) **nunca bloquea** ni lanza:

- Publica con `self._emit(event)` → `sink.publish(event)`, que es **no bloqueante** (el bus aplica su
  `OverflowPolicy`, por defecto `DROP_NEWEST`). Si el bus rechaza, se cuenta en `bus_dropped`.
- Un evento mal formado solo incrementa `consumer_errors` y se descarta; el consumidor ETW sigue.

Así el consumidor ETW no se queda atascado detrás de un consumidor lento del bus: el desacople es del
bus, y la pérdida por saturación se **mide** en lugar de bloquear la sesión (lo que causaría pérdida
en el propio kernel).

---

## 8. Comandos de uso y prueba

```bash
# Pruebas UNITARIAS (sin admin, sin pywintrace) — ejecutan siempre:
python tests/test_etw_collector.py           # 13/13 (sesión falsa inyectada)
python tests/test_events.py                  # 12/12
python tests/test_loss.py                     # 4/4
python tests/test_bus.py                      # 8/8
python tests/test_collector_contract.py       # 5/5

# Lint:
python -m pyflakes collectors core tests

# INTEGRACIÓN real (requiere Windows + Administrador + pywintrace); si no, SALTA (PENDIENTE):
python tests/test_etw_integration.py

# BENCHMARK de carga (mismos requisitos; si no, PENDIENTE):
python tests/bench_etw_collector.py --seconds 20
```

### Uso programático

```python
from core.bus import EventBus
from collectors.etw_collector import EtwCollector

bus = EventBus(maxsize=4096)
bus.subscribe(lambda ev: ...)        # un detector/consumidor
bus.start()

col = EtwCollector(bus, provider="kernel-process")
col.start()
if not col.health().alive:
    print("no arrancó:", col.health().init_error)   # p. ej. acceso denegado
...
col.stop()                            # idempotente; libera solo la sesión propia
bus.stop()
print(col.metrics())                  # pérdida de ETW conocida aquí
```

---

## 9. Resultados observados

**En este entorno (no-admin, sin pywintrace), 2026-10-20:**

| Comprobación | Resultado |
|---|---|
| `test_etw_collector.py` | **13/13 OK** |
| Núcleo (`events`+`loss`+`bus`+`contract`) | **29/29 OK** (12+4+8+5) |
| `pyflakes` sobre `collectors/`, `core/`, `tests/` | **limpio** |
| `test_etw_integration.py` | **SALTADA** → `PENDIENTE` (pywintrace ausente), exit 0 |
| `bench_etw_collector.py` | **SALTADA** → `PENDIENTE` (pywintrace ausente), exit 0 |

Total unitario: **42/42**. Las pruebas que requieren ETW real se autodescartan de forma honesta; **no
se fabrican métricas**.

> **Captura real:** en la Fase ETW anterior (spike), con la sesión elevada, el usuario reportó la
> recepción de ~100 eventos reales con 0 pérdida y terminación limpia (sin sesión huérfana en
> `logman query -ets`). Eso valida la **vía** (proveedor accesible, recepción, parada limpia), pero
> **no** es prueba de capacidad sostenida: fue una ráfaga corta y limitada. La medición de
> rendimiento sostenido queda **pendiente** del benchmark elevado (§10).

---

## 10. Limitaciones pendientes

1. **Captura real del colector de producción:** `test_etw_integration.py` aún no se ha ejecutado con
   Administrador en **este** colector (solo el spike previo). Pendiente de una corrida elevada.
2. **Rendimiento sostenido:** el benchmark (`bench_etw_collector.py`) está listo pero **no medido**
   aquí. Falta correr una ventana larga con carga para obtener eventos/s, CPU, RAM, `bus_dropped` y
   `EventsLost` reales. **El límite de 100 eventos del spike no sirve como prueba de capacidad.**
3. **Latencia por evento (recepción→publicación):** no instrumentada todavía; requiere marcas de
   tiempo por evento. Marcada `PENDIENTE` en el benchmark, no estimada.
4. **Pérdida de ETW solo tras STOP:** limitación de pywintrace; durante el run la pérdida de la fuente
   es `None` (desconocida), nunca 0.
5. **Sesiones huérfanas ante terminación abrupta:** sobreviven al proceso; limpieza manual documentada
   (§4). El barrido automático de arranque (solo prefijo `Lozarus-ETW-`) queda fuera de alcance 3A.
6. **Threat-Intelligence ETW:** inaccesible desde modo usuario (requiere driver PPL/ELAM). Límite duro.

---

## 11. Alcance y siguiente paso

**Hecho en 3A:** un colector ETW de producción integrado con los contratos de la Fase 2, con ciclo de
vida y propiedad de sesión explícitos, tiempo honesto, pérdida diferenciada, pruebas unitarias sin
admin + integración/benchmark saltables, y esta documentación.

**No tocado (fuera de alcance, intacto):** GUI (`gui_qt.py`, `gui.py` — retirado después, el
2026-10-21), CLI (`auditor.py`), los 41
módulos de `modulos/`, y el prototipo del spike (`spikes/etw/`). No se implementó el servicio
privilegiado ni el IPC.

**Siguiente paso preparado (no iniciado):** conectar el bus con la **Caja Negra** (persistencia
append-only de eventos) y con **OBSIDIAN** (motor de detección que se suscribe al bus). El contrato ya
lo permite: ambos son `subscribe()` del `EventBus`; el colector no cambia.
