# Lozarus — Arquitectura del proyecto (Entregable B)

> Árbol de carpetas definitivo, responsabilidades de cada paquete, **dependencias permitidas** y la
> regla que impide que la interfaz acceda directamente a operaciones privilegiadas. Esta fase (Fase 2)
> implementa solo `core/` y `tests/`; el resto es **estructura prevista**, no código ya escrito.

## 1. Árbol del proyecto

Leyenda: **(hoy)** existe ya · **(prev.)** previsto para fases siguientes.

```
AuditorTool/
├─ core/                      (hoy)  Núcleo: modelos, contratos, errores, bus. Sin GUI ni Windows.
│  ├─ errors.py                      Jerarquía de errores (LozarusError…).
│  ├─ events.py                      Modelo común de evento (lozarus.event.v1), reloj, serialización.
│  ├─ contracts.py                   Collector (Protocol) + BaseCollector (ABC), EventSink, SensorHealth.
│  └─ bus.py                         EventBus: cola acotada, backpressure, métricas, cierre ordenado.
├─ collectors/                (prev.) Sensores. Uno por fuente; dependen SOLO de core/ y windows/.
│  ├─ etw_collector.py                (producción; se portará desde spikes/etw).
│  ├─ eventlog_collector.py           Windows Event Log.
│  ├─ process_collector.py            Procesos (psutil / APIs).
│  ├─ network_collector.py            Red.
│  ├─ device_collector.py             Dispositivos (USB/HID).
│  └─ filesystem_collector.py         Sistema de archivos.
├─ detection/                 (prev.) Reglas, correlación, líneas base y estado de observabilidad.
│  ├─ rules.py  correlation.py  baselines.py  observability.py   (OBSIDIAN vive aquí)
├─ response/                  (prev.) Respuesta: plan/validate/apply/verify/rollback. Delega lo
│  │                                  privilegiado en service/. Nunca acciones destructivas por defecto.
│  └─ engine.py  actions.py  authorization.py
├─ forensics/                 (prev.) Caja Negra (búfer circular), evidencia, hashing, snapshots,
│  │                                  cadena de custodia. CHRONOS e IRONCLAD se apoyan aquí.
│  └─ blackbox.py  evidence.py  chain_of_custody.py
├─ deception/                 (prev.) Señuelos y laboratorios AUTORIZADOS (honeypot de detección).
├─ windows/                   (prev.) Adaptadores de APIs nativas (ctypes/pywin32, WFP, Job Objects).
│  │                                  Aísla todo lo específico de Windows; probado con dobles.
│  └─ etw.py  wfp.py  jobobjects.py  mitigations.py  tokens.py
├─ service/                   (prev.) Servicio privilegiado + IPC (Named Pipes + ACL). Superficie mínima.
│  └─ server.py  ipc.py  authz.py
├─ storage/                   (prev.) Configuración, secretos (DPAPI), SQLite y migraciones.
├─ reporting/                 (prev.) Informes, cronologías y manifiestos.
├─ policies/                  (prev.) Reglas y perfiles VERSIONADOS (p. ej. blocklist de drivers).
├─ ui/                        (prev.) Interfaz desacoplada. Hoy la GUI vive en gui_qt.py (ver nota).
│  └─ main_window.py  tabs/  widgets/  bus_adapter.py
├─ tests/                     (hoy)  Unitarias (sin admin/ETW/PySide6), integración y seguridad.
│  ├─ test_events.py  test_loss.py  test_bus.py  test_collector_contract.py
├─ spikes/                    (hoy)  Prototipos aislados.
│  └─ etw/                            Spike ETW validado (NO es producción).
├─ docs/                      (hoy)  Arquitectura, contratos, permisos, modelo de amenazas, retención.
├─ modulos/                   (hoy)  Motor de auditoría de solo lectura (plugins) — base actual.
├─ gui_qt.py                  (hoy)  Interfaz gráfica única (PySide6). → migrará a ui/ sin reescribir lógica.
├─ auditor.py                 (hoy)  CLI de auditoría.
└─ Lozarus_Forensics/         (hoy)  Salida en disco (snapshots, reportes, señuelos).
```

> **No se crean carpetas vacías.** Los paquetes `(prev.)` se añaden cuando tengan código real; aquí se
> listan para fijar responsabilidades y dependencias, no para andamiaje vacío.

## 2. Responsabilidades por paquete

| Paquete | Responsabilidad | Puede importar | NO debe importar |
|---|---|---|---|
| `core/` | Modelos, contratos, bus. Verdad común del sistema. | solo stdlib | colectores, GUI, Windows, servicio |
| `collectors/` | Observar una fuente y publicar `Event` en el bus. | `core`, `windows` | GUI, `response`, `service` |
| `detection/` | Reglas, correlación, líneas base, observabilidad (OBSIDIAN). | `core` | GUI, `windows`, `service` |
| `response/` | Planificar/validar/ejecutar/verificar/revertir respuestas. | `core`, `service` (IPC) | GUI; operaciones privilegiadas directas |
| `forensics/` | Caja Negra, evidencia, hashing, cadena de custodia. | `core`, `windows` (lectura) | GUI |
| `deception/` | Señuelos y laboratorios autorizados. | `core`, `windows` | GUI, respuestas destructivas |
| `windows/` | Adaptadores de API nativa (aísla ctypes/pywin32/WFP/Job Objects). | stdlib, ctypes, pywin32 | GUI, `core` (lo usa `core`, no al revés) |
| `service/` | Servicio privilegiado e IPC. Superficie mínima y auditada. | `core`, `windows` | GUI |
| `storage/` | Config, secretos, SQLite, migraciones. | `core` | GUI |
| `reporting/` | Informes, cronologías, manifiestos. | `core`, `storage` | GUI |
| `policies/` | Datos versionados (reglas, perfiles, blocklists). | — (datos) | — |
| `ui/` | Presentación y navegación. | `core` (modelos, bus vía adaptador) | `windows`, `service`, `collectors` directos |
| `tests/` | Pruebas. | todo lo que prueba | — |

## 3. Reglas de dependencia (lo que impide los acoplamientos peligrosos)

1. **El flujo de dependencias apunta hacia `core/`.** `core` no importa nada del proyecto (solo
   stdlib). Todo lo demás depende de `core`, nunca al revés. *(Verificado por una prueba:
   `test_core_has_no_gui_dependency`.)*
2. **La GUI no ejecuta operaciones privilegiadas ni toca Windows directamente.** `ui/` solo conoce
   `core` (modelos y un **adaptador del bus** que marshalea eventos al hilo de Qt). Para actuar sobre
   el sistema, la GUI **pide** una respuesta a `response/`, que decide, autoriza y **delega** lo
   privilegiado en `service/` por IPC. La GUI nunca importa `windows/`, `service/` ni `collectors/`.
3. **Observación ≠ ejecución.** Los colectores solo observan y publican; no ejecutan respuestas. Los
   motores de detección solo leen y puntúan; no actúan. Solo `response/` actúa, y lo privilegiado pasa
   por el servicio.
4. **Los colectores no dependen de PySide6.** Así el núcleo de adquisición y detección se prueba sin
   GUI, sin Windows y sin privilegios. *(Verificado: las pruebas del núcleo corren sin elevación.)*
5. **El bus desacopla productores y consumidores.** Ningún colector llama a un widget de Qt; publican
   en el bus, y un adaptador de `ui/` se suscribe y marshalea al hilo de la interfaz.

## 4. Separación de privilegios (preparada, no implementada aún)

- La **GUI corre con privilegios normales**. Solo las acciones que lo necesiten se delegan a un
  **servicio auxiliar** con una interfaz pequeña y controlada (Named Pipes + ACL).
- Reglas de seguridad del futuro IPC (se detallan en `docs/03_*` en la fase de servicio):
  autenticación del cliente local, **autorización por operación**, validación estricta de argumentos,
  auditoría de cada acción privilegiada, y separación entre el canal de observación y el de ejecución.
  Un token efímero **no** basta como autorización.
- En esta fase solo se fija el **contrato**: `response/` planifica y, cuando una acción requiere
  elevación, la enruta al `service/`. No se implementa el servicio ni las acciones todavía.

## 5. Estado tras la Fase 2

Implementado y probado: `core/` (errores, eventos, contratos, bus) y `tests/` (29 pruebas, sin
elevación). Intactos: la GUI (`gui_qt.py`, `gui.py` — este último retirado el 2026-10-21), el CLI y
el spike ETW. El detalle de los
contratos y modelos está en `docs/02_CONTRATOS_EVENTOS.md`.
