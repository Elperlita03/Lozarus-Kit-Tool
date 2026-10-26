# Spike ETW — Informe de resultados

**Fecha:** 2026-10-20 · **Entorno:** Windows 11 IoT Enterprise LTSC (build 26200), Python 3.13.15 x64,
usuario **sin** privilegios de Administrador.

## 1. Veredicto

La vía técnica **es viable**: `pywintrace` consume ETW desde Python puro (ctypes sobre APIs
documentadas) y funciona en Python 3.13 x64. La **normalización** a un modelo estable para Lozarus
está implementada y probada. La **captura de un evento real queda pendiente de una ejecución con
Administrador** (este equipo corre sin privilegios); el prototipo lo detecta y lo informa sin simular
éxito. No hay señales de bloqueo: la decisión de usar ETW desde Python para el colector de telemetría
puede sostenerse, con las salvedades de la sección 6.

## 2. Archivos creados

| Archivo | Propósito |
|---|---|
| `normalize.py` | Normalización pura (solo stdlib) del evento de pywintrace al esquema `lozarus.etw.v0`. |
| `etw_spike.py` | Prototipo ejecutable: requisitos, registro de proveedores, consumo, cierre limpio, CLI. |
| `test_normalize.py` | 8 pruebas unitarias de normalización (sin admin, sin ETW). |
| `test_integration.py` | Prueba de integración real; se **salta** si falta Windows/admin/pywintrace. |
| `requirements-spike.txt` | Dependencia aislada: `pywintrace==0.2.0`. |
| `README.md` | Requisitos, instalación, ejecución, criterios de aceptación. |
| `INFORME.md` | Este documento. |

No se modificó la GUI ni la estructura del proyecto. No se añadieron dependencias al proyecto principal.

## 3. Comandos ejecutados y resultados **reales**

```
$ python test_normalize.py
  OK en las 8 pruebas  →  "8/8 pruebas OK"

$ python etw_spike.py --check
  SO            : Windows 11 (10.0.26200) IoTEnterpriseSEval
  Python        : 3.13.15 64bit
  ¿Windows?     : sí
  ¿Administrador? : NO — no se podrá iniciar una sesión en tiempo real
  pywintrace    : disponible
  Veredicto     : NO listo (ver arriba)

$ python etw_spike.py --provider kernel-process --seconds 4 --max 5
  Iniciada : False
  Eventos  : 0  (en 0.0s)
  Error    : acceso denegado (ERROR_ACCESS_DENIED): iniciar una sesión ETW en tiempo real
             requiere Administrador o pertenecer a «Performance Log Users».
  (exit code 3; sin crash; la sesión no queda abierta)

$ python etw_spike.py --provider kernel-process --seconds 3 --max 5    (2ª ejecución)
  Pérdida  : eventos=desconocida · buffers=desconocida      ← nunca 0 sin medir

$ logman query -ets                                          (tras los intentos sin admin)
  (sin Data Collector Sets en ejecución → el prototipo NO dejó ninguna sesión ETW huérfana)

$ python test_integration.py
  PENDIENTE — requisitos no disponibles aquí: sin privilegios de Administrador
  (exit 0; la prueba se salta correctamente, no hay falso positivo)

$ python -m pyflakes normalize.py etw_spike.py test_normalize.py test_integration.py
  pyflakes OK
```

**Comprobado también:** `pip install --target … pywintrace` → **0.2.0** instala e importa en Python
3.13.15 sin errores; el callback de pywintrace entrega `(event_id, dict)` con el formato que
`normalize.py` consume (verificado leyendo el código de `etw.etw._processEvent`).

**Hallazgo adicional:** la consola de Windows (cp1252/OEM) **rompe** al imprimir caracteres no-ASCII
(`UnicodeEncodeError` con `→`). Se corrigió forzando UTF-8 en `stdout`/`stderr`. → El futuro colector
**no debe asumir la codificación de la consola**.

## 4. Proveedor y TIPO DE SESIÓN usados, y requisitos de acceso (precisado)

- Proveedor de referencia: **Microsoft-Windows-Kernel-Process**
  `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` (creación/fin de procesos, imágenes, hilos — la telemetría
  EDR más básica). Es un proveedor **manifest-based** (moderno), no el proveedor clásico del kernel.
- **Tipo de sesión (verificado leyendo pywintrace):** el prototipo abre una **sesión de trazado en
  tiempo real ORDINARIA** (`EVENT_TRACE_REAL_TIME_MODE`) con **nombre de sesión propio (UUID)** y
  habilita el proveedor vía `EnableTraceEx2`. En pywintrace, `kernel_trace` solo se activa si el nombre
  de sesión es exactamente «NT Kernel Logger»; aquí **no** lo es, así que **NO** se usa
  `EVENT_TRACE_SYSTEM_LOGGER_MODE` ni el NT Kernel Logger.
- **Requisito de privilegios (preciso, sin generalizar):** para una sesión en tiempo real ordinaria
  basta **Administrador** *o* pertenecer al grupo **«Performance Log Users»**. **NO** requiere
  `SeSystemProfilePrivilege`. → *Importante:* ese privilegio y la sesión única global **solo** aplicarían
  si cambiáramos al **NT Kernel Logger / System Trace Provider** (`SystemTraceControlGuid`) para eventos
  de más bajo nivel — un camino **distinto** que este prototipo no toma. No generalizar los requisitos
  de una sesión a la otra.
- **Observado en este equipo (sin admin):** `StartTraceW` → `ERROR_ACCESS_DENIED (5)`, manejado sin
  crash (exit 3). *Hecho verificado.*
- Ninguno de los proveedores de ejemplo está restringido a procesos antimalware protegidos. (El proveedor
  **Threat-Intelligence**, el de la telemetría a prueba de manipulación, **sí** lo está y queda fuera de
  alcance para un consumidor en modo usuario — como ya concluyó la auditoría.)

### 4.1. Comando exacto para la captura real (consola ELEVADA de Windows)

> El entorno automatizado de Claude corre **sin** privilegios y **no puede** elevar (UAC es interactivo).
> Por eso la captura real está **pendiente de que la ejecutes tú**. Pasos reproducibles:

```bat
:: 1) Abre "Símbolo del sistema" o PowerShell COMO ADMINISTRADOR (clic derecho → Ejecutar como admin)
cd C:\Users\Voltio\Documents\AuditorTool\spikes\etw
python -m venv .venv & .venv\Scripts\activate & pip install -r requirements-spike.txt

:: 2a) Captura en vivo (Kernel-Process emite en cada inicio/fin de proceso del sistema):
python etw_spike.py --provider kernel-process --seconds 8 --max 15 --json
::     Para forzar eventos, abre y cierra el Bloc de notas mientras corre.

:: 2b) O la prueba de integración, que DISPARA procesos de prueba y verifica automáticamente:
python test_integration.py
::     (o: python -m pytest test_integration.py -v)
```

Criterio de éxito: ver `Iniciada: True`, `Eventos: >=1` y una muestra con `provider_guid` y campos
reales (p. ej. `ImageName`, `ProcessID`). Pega aquí esa salida y damos por aprobados los criterios 1 y 2.

## 5. Dependencias, consumo de recursos y limitaciones

- **Dependencia:** `pywintrace==0.2.0`. Python puro + ctypes; sin binarios que compilar; sin
  dependencias transitivas relevantes. Última versión de 2021 pero funcional en 3.13 (verificado).
- **Consumo:** no medible aquí sin captura real. El coste dominante es el **búfer en anillo** de la
  sesión (`ring_buf_size`, por defecto 1024 KB en pywintrace) y el ritmo de eventos del proveedor
  (Kernel-Process es moderado; Kernel-File o Registry serían ruidosos). El parseo TDH por evento es el
  trabajo de CPU principal. **Pendiente de medir** en la ejecución con admin (latencia por evento,
  RAM del proceso, % CPU bajo carga).
- **Limitaciones detectadas / conocidas:**
  1. **Privilegios:** sin admin no hay sesión en tiempo real. *(verificado)*
  2. **Reloj de marcas temporales:** pywintrace **no** fija `Wnode.ClientContext`, así que el reloj
     de la sesión queda en el valor por defecto del sistema y `EventHeader.TimeStamp` puede no ser
     FILETIME. La normalización lo trata con cautela (valida el rango; si no parece FILETIME, deja
     `timestamp_utc=None`, `clock="ambiguous"` y conserva el valor crudo). *(ver §6, recomendación.)*
  3. **Pérdida de eventos (vía resuelta e implementada):** pywintrace no la expone como atributo,
     pero tras `ControlTrace(STOP)` (que pywintrace ya llama) Windows deja `EventsLost` y
     `RealTimeBuffersLost` en la estructura `EVENT_TRACE_PROPERTIES` de la sesión. El prototipo las lee
     de `job.properties` y las publica en el resultado. **Sin sesión arrancada se reportan como
     «desconocida» (None), nunca como 0** (verificado en la ejecución sin admin). El valor cuantitativo
     real está **pendiente** de una captura con Administrador. Es justo la señal que necesita OBSIDIAN.
  4. **Fidelidad de parseo:** con `callback_data_flag=0`, pywintrace no marca de forma fiable el
     parseo incompleto en la salida; la detección por `UserData` crudo solo aparece en los modos RAW.
     Para producción conviene fijar un modo que distinga parseado/crudo.
  5. **Mantenimiento:** pywintrace está poco mantenido. Riesgo a vigilar; mitigable encapsulándolo
     tras el contrato del §7 (se podría sustituir por un consumidor ctypes propio sin tocar el resto).

## 6. Estado: APROBADO / PENDIENTE / LIMITACIONES

**Aprobado (observado en este equipo):**
- La librería `pywintrace` 0.2.0 instala, importa y expone el formato de evento esperado (Python 3.13 x64).
- La **normalización** al esquema `lozarus.etw.v0` funciona (8/8 unitarias).
- **Manejo de errores de permisos:** `ERROR_ACCESS_DENIED` capturado y reportado sin crash (exit 3).
- **Cierre limpio / sin sesión huérfana:** verificado con `logman query -ets` (no queda sesión del
  prototipo); el cierre está en `finally` e idempotente.
- **Pérdida de eventos representada como «desconocida» (None)** cuando no hay medición — nunca 0.
- **Tipo de sesión y privilegios** determinados con precisión (sesión en tiempo real ordinaria →
  admin o Performance Log Users; **no** SeSystemProfilePrivilege).

**Pendiente (bloqueante, requiere Administrador — no ejecutable en este entorno):**
1. **Capturar ≥1 evento ETW real** y pegar la salida (criterios de aceptación 1 y 2). Comando en §4.1.
   *Mientras no se haga, el spike está validado a medias: la recepción+normalización de un evento real
   no se ha observado todavía.*
2. **Medir** cuantitativamente la pérdida de eventos (`EventsLost`), la latencia por evento y el consumo
   de RAM/CPU (sesión real, proveedor moderado y uno ruidoso).
3. **Confirmar empíricamente el reloj** de la sesión (ver §5): comparar `timestamp_utc` con la hora de
   pared en la captura real para decidir si fijar `ClientContext=2` (FILETIME) en el colector.

## 7. Recomendaciones para `collectors/etw_collector.py` y contrato con el bus

### 7.1. Diseño del colector
- Encapsular pywintrace (o un consumidor ctypes propio) **detrás de una interfaz estable**, de modo
  que la elección de librería sea un detalle sustituible.
- Un colector por **sesión** (o una sesión multi-proveedor), con su propio hilo de consumo. El
  callback hace lo mínimo: `normalize()` + `put()` en una cola; el parseo pesado nunca bloquea el bus.
- **Salud y pérdidas:** exponer `health()` (sesión viva, eventos recibidos, `EventsLost`, última marca)
  para que **OBSIDIAN** sepa si la cobertura está degradada. No afirmar «sin eventos = limpio».
- **Reloj determinista:** crear la sesión con `ClientContext=2`.
- **Cierre garantizado:** `ControlTrace(STOP)` en `close()` y en el finalizador; idempotente.
- **Privilegios:** detectar la falta de admin y degradar con un estado explícito, no con una excepción
  silenciosa (como hace el spike).

### 7.2. Esquema del evento normalizado (`lozarus.etw.v0`)
Implementado en `normalize.py`. Campos: `schema`, `event_id`, `provider_guid`, `provider_name`,
`task_name`, `opcode`, `level`, `version`, `keyword`, `timestamp_raw`, `timestamp_utc`, `clock`,
`process_id`, `thread_id`, `activity_id`, `description`, `fields{…}`, `parse_complete`,
`raw_user_data_hex`.

### 7.3. Contrato propuesto colector → bus de eventos

```python
# core/contracts.py  (borrador — se consolidará en el Entregable C)
class Collector(Protocol):
    name: str
    def start(self) -> None: ...                 # abre la sesión; lanza/arranca el hilo de consumo
    def stop(self) -> None: ...                  # cierre idempotente y garantizado
    def health(self) -> SensorHealth: ...        # vivo?, eventos, EventsLost, última marca, degradado?

# El colector NO llama al bus directamente: publica en una cola que el núcleo drena.
class EventBus(Protocol):
    def publish(self, event: dict) -> None: ...  # event = esquema lozarus.etw.v0 (u otro *.v0)

@dataclass
class SensorHealth:
    name: str
    alive: bool
    events_total: int
    events_lost: int | None        # None si la fuente no lo reporta (incertidumbre explícita)
    last_event_utc: str | None
    degraded: bool                 # True si falta admin, hay pérdidas o la sesión cayó
    note: str = ""
```

**Reglas del contrato:**
- Todo evento lleva `timestamp_raw` (nunca se pierde) y, si es posible, `timestamp_utc` + `clock`.
- `events_lost=None` significa «desconocido», **no** «cero». OBSIDIAN debe tratarlo como cobertura
  incierta.
- El bus ordena por `timestamp_raw` dentro de una fuente; entre fuentes, correlación por ventana
  temporal **con tolerancia**, nunca atribución causal por simple cercanía (regla de la auditoría).
- Backpressure: si la cola se llena, el colector incrementa un contador de descartes propios (que
  también es «pérdida de cobertura» para OBSIDIAN) en lugar de bloquear el hilo de ETW.

---

**Conclusión:** la adquisición ETW desde Python es viable y el modelo de normalización está listo y
probado. Queda **una** validación bloqueante —capturar un evento real con Administrador— y cuatro
mediciones/decisiones (reloj, pérdidas, rendimiento, modo de parseo) antes de promover este spike a
`collectors/etw_collector.py`. Con eso cerrado, podemos abordar los Entregables **B** (árbol de
carpetas) y **C** (contratos y bus) sobre una base técnica comprobada.
