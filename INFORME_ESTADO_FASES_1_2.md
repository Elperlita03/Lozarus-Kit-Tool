# Informe de estado — Fases 1 y 2

> Punto de referencia para congelar y retomar el proyecto. Documenta el estado **local** tras las
> Fases 1 (seguridad) y 2 (fiabilidad). **Nada se ha publicado ni commiteado**; todos los cambios
> están en el árbol de trabajo local.
>
> Fecha: 2026-10-20 · Entorno: Windows 11 · Python 3.13.15 x64 · repositorio **solo local** (sin remotos).

---

## 1. Estado local de los cambios

Repositorio Git **local**, sin remotos y **sin ningún commit**: todo lo de abajo son cambios en el
árbol de trabajo (modificados o nuevos sin seguimiento).

### Archivos de producción modificados (6)
| Archivo | Cambio | Fase |
|---|---|---|
| `modulos/_utilidades.py` | Helper `ps_string_array` (base64) | 1 (C1) |
| `modulos/_monitor.py` | Usa `ps_string_array` + caché de firmas con caducidad por mtime | 1 (C1) + 2 (C6) |
| `modulos/13_inyecciones.py` | `_dll_classification`: `Error` = no verificable | 1 (C2) |
| `modulos/11_persistencia.py` | `_autorun_verdict`: `Error` = no verificable | 2 (C-persist) |
| `modulos/_contencion.py` | Persistencia incremental de la cuarentena + reanudación segura | 2 (C3, S2) |
| `modulos/_tacticas.py` | `ghost_preview` distingue recuento real de fallo (`ok`) | 2 (C5) |

### Archivo de interfaz modificado (1)
| Archivo | Cambio | Fase |
|---|---|---|
| `gui_qt.py` | `_previewed`: muestra «?» + aviso cuando el recuento no se pudo calcular | 2 (C5) |

### Archivos nuevos de prueba (5)
| Archivo | Cubre |
|---|---|
| `tests/test_powershell_quoting.py` | C1 (inyección) + C2 (clasificación) + Unicode/CJK/emoji |
| `tests/test_contencion_estado.py` | C3 + S2 (cuarentena, en sandbox) |
| `tests/test_persistencia_verdict.py` | C-persist (veredicto de autoruns) |
| `tests/test_monitor_cache.py` | C6 (caducidad de la caché de firmas) |
| `tests/test_ghost_preview.py` | C5 (recuento real vs. desconocido) |

> Nota: `tests/test_powershell_quoting.py` figura como *modificado* (no nuevo) porque se añadió al
> índice en la Fase 1 con `git add -N`; su contenido es íntegramente de las Fases 1–2.

### Archivos nuevos de documentación / configuración (2)
| Archivo | Contenido |
|---|---|
| `pyproject.toml` | Declaración de las 7 dependencias externas (C9) |
| `docs/06_ENDURECIMIENTO_DESPLIEGUE.md` | Nota de despliegue de C8 |

### Resumen de líneas (producción + gui, vs. estado inicial)
```
 gui_qt.py                  |  13 +++-
 modulos/11_persistencia.py |   9 ++-
 modulos/13_inyecciones.py  |  31 +++++++-
 modulos/_contencion.py     |  17 ++++-
 modulos/_monitor.py        |  26 +++++--
 modulos/_tacticas.py       |  17 +++--
 modulos/_utilidades.py     |  20 +++++-
```
**Fuera de alcance, intactos:** `gui.py` (GUI de respaldo; retirado después, el 2026-10-21),
`auditor.py` (CLI), `core/`,
`collectors/`, `spikes/`.

---

## 2. Pruebas ejecutadas (resultados reales)

Ejecución real del 2026-10-20 19:51. Reproducible con `python tests/<archivo>.py` (cada archivo
tiene un `_run_all()`; también funcionan con `pytest`).

| Suite | Resultado |
|---|---|
| `test_events.py` | 12/12 |
| `test_loss.py` | 4/4 |
| `test_bus.py` | 8/8 |
| `test_collector_contract.py` | 5/5 |
| `test_etw_collector.py` | 13/13 |
| `test_powershell_quoting.py` | 8/8 |
| `test_contencion_estado.py` | 7/7 |
| `test_persistencia_verdict.py` | 8/8 |
| `test_monitor_cache.py` | 3/3 |
| `test_ghost_preview.py` | 6/6 |
| **TOTAL** | **74/74** |

`pyflakes` sobre todo el repositorio (sin `.venv`/`__pycache__`): **limpio**.

### Limitaciones de las pruebas (honestas)
- **Cuarentena** (`_contencion`): probada con **dobles** (firewall/USB/procesos simulados) y estado
  en directorio temporal. La reversión segura está verificada a nivel de **lógica de estado**, no
  contra el Firewall de Windows real (habría modificado el sistema).
- **Inyección** (`test_powershell_quoting`): la prueba de integración ejecuta PowerShell real y aquí
  pasó; en un entorno sin Windows/PowerShell se **salta** (no falla). La integridad de datos con
  Unicode/CJK/emoji está cubierta por la prueba pura de round-trip, independiente de la consola.
- **GUI** (`gui_qt._previewed`): su formateo no tiene prueba unitaria (requeriría Qt); la lógica real
  (distinguir recuento de desconocido) se prueba en `ghost_preview`. `gui_qt.py` solo se validó por
  **análisis sintáctico** (AST), no en ejecución de ventana.
- La verificación extendida de `ps_string_array` con 12 casos difíciles se hizo con un script
  temporal fuera del repositorio; en la suite permanente quedan los casos de
  `test_powershell_quoting.py` (incluidos CJK y emoji).

---

## 3. Hallazgos corregidos

| ID | Problema | Corrección | Archivos | Prueba |
|---|---|---|---|---|
| **C1** | Inyección de comandos en PowerShell: el escape de comillas no neutralizaba la comilla tipográfica (U+2019). Rutas no confiables (Run, tareas, drivers, DLL, procesos) llegaban como código. | `ps_string_array()` pasa cada ruta como **dato base64**, nunca como código. | `_utilidades.py`, `_monitor.py` | `test_powershell_quoting.py` (8/8, con integración real) |
| **C2** | Un fallo de verificación de firma (`Error`) se marcaba como alerta CRÍTICA «sin firma válida». | `_dll_classification()`: `Error` = `unverifiable` (desconocido). | `13_inyecciones.py` | `test_powershell_quoting.py` |
| **C-persist** | El mismo patrón `Error → WARNING «sin firma»` en autoruns. | `_autorun_verdict()`: `Error` = `unverifiable`; entrada etiquetada «firma no verificable». | `11_persistencia.py` | `test_persistencia_verdict.py` (8/8) |
| **C3** | `apply_quarantine` guardaba el estado solo al final: un fallo a mitad dejaba la red bloqueada sin registro para revertir. | Persistir el estado **antes** del primer paso irreversible y tras cada campo conocido. | `_contencion.py` | `test_contencion_estado.py` (7/7) |
| **S2** | `lift_quarantine` no reanudaba un proceso si no podía leer su `create_time` (0.0) → congelado para siempre. | Omitir solo cuando `create_time` se leyó **y** difiere; si es ilegible, reanudar. | `_contencion.py` | `test_contencion_estado.py` |
| **C6** | La caché de firmas no caducaba: un binario sustituido conservaba su firma antigua toda la sesión. | Cachear el `mtime`; re-verificar cuando cambia y descartar la firma obsoleta. | `_monitor.py` | `test_monitor_cache.py` (3/3) |
| **C5** | `ghost_preview` devolvía 0 al fallar: el diálogo mostraba «0» como si no hubiera nada que limpiar. | Clave `ok` (retrocompatible); el GUI muestra «?» + aviso cuando no se pudo contar. | `_tacticas.py`, `gui_qt.py` | `test_ghost_preview.py` (6/6) |

**Principio común a C2, C-persist, C5 y C6:** un dato **desconocido** (verificación fallida, recuento
no obtenido, firma caducada) nunca se presenta como un valor confirmado (0, «sin firma» o la firma
antigua).

---

## 4. C8 — Módulos ejecutados desde carpeta escribible por el usuario

**Hallazgo:** el cargador de plugins ([`modulos/_cargador.py`](docs/06_ENDURECIMIENTO_DESPLIEGUE.md),
`discover_modules`, líneas 37 y 46) importa —y ejecuta— todo `.py` de `modulos/`. **Cualquier proceso
con permiso de escritura en esa carpeta puede plantar un plugin y lograr ejecución de código** dentro
de Lozarus (y con sus privilegios si corre como Administrador).

**Matiz clave:** mientras Lozarus se ejecute desde una **carpeta del usuario** (como ahora,
`Documents\AuditorTool`), el propio usuario —y el malware que corra como él— ya tiene escritura ahí
por diseño, así que restringir permisos **no** cierra el riesgo. La mitigación real es instalar en una
ruta que **solo los administradores** puedan modificar.

**Decisión:** la instalación protegida (p. ej. `C:\Program Files\Lozarus`) y el endurecimiento de ACL
se abordarán en una **fase de despliegue posterior**. No es un cambio de código. Detalle, comandos de
referencia `icacls` y la opción de un manifiesto de integridad al arranque están en
[`docs/06_ENDURECIMIENTO_DESPLIEGUE.md`](docs/06_ENDURECIMIENTO_DESPLIEGUE.md).

**Límite honesto:** nada de esto protege frente a un administrador local comprometido (ver
[`docs/00`](docs/00_AUDITORIA_ARQUITECTURA.md) §1.1).

---

## 5. Clasificación del estado

### 5.1. Corregido (con prueba) — Fases 1 y 2
C1, C2, C-persist, C3, S2, C6, C5. Todo local, sin commit. Suite 74/74.

### 5.2. Riesgos conocidos, aún abiertos
| ID | Tipo | Estado |
|---|---|---|
| **C8** | Despliegue | Documentado (`docs/06`). Requiere decidir ubicación de instalación + ACL en fase de despliegue. No es código. |
| **C9** | Configuración | `pyproject.toml` creado. Falta, si se quiere, un entorno instalado desde él (no se ha instalado nada). |
| Cuarentena vs. Firewall real | Prueba | La reversión segura está probada por lógica, no contra el Firewall real. |
| Autodefensa (módulo 38) | Arquitectura | Mejor esfuerzo; no resiste a un administrador comprometido (límite documentado). |

### 5.3. No implementado todavía (diseño o pendiente)
- **Caja Negra, OBSIDIAN** — diseñados (`docs/00` §4.1); sin código. Siguiente gran paso de telemetría.
- **CHRONOS, IRONCLAD** — diseñados; sin código.
- **Servicio privilegiado + IPC** — previsto (`docs/01` §4); sin implementar. Hoy la GUI llama a
  PowerShell directamente (deuda reconocida).
- **Integración del bus/colector ETW con la GUI** — el colector existe y está probado, pero ninguna
  interfaz lo consume.
- **Lozarus Rescue (WinPE)** — diseñado (`docs/05`); pendiente de validar PySide6 en WinPE (decisión D1).
- **Manifiesto de integridad de `modulos/`** (mitigación §4 de C8) — solo diseño.
- **36 de los 41 módulos** de la arquitectura — sin pruebas automáticas; varios solo diseñados o
  parcialmente implementados (ver el catálogo en `spikes/ui_preview/`).

---

## 6. Confirmación de no intervención

- **No se ha hecho ningún commit** (el repositorio local no tiene commits; los cambios están en el
  árbol de trabajo).
- **No hay remotos** configurados; **nada se ha publicado ni sincronizado**.
- En **esta** tarea de cierre **no se ha modificado código ni configuración**: solo se ha generado
  este informe. Las correcciones descritas son de las Fases 1 y 2, ya revisadas.
- **No se han instalado dependencias** ni cambiado permisos de Windows.

---

## 7. Para retomar (siguiente etapa, no iniciada)

Candidato natural de la Fase 3: **Caja Negra + OBSIDIAN** (persistencia de eventos y salud de la
telemetría sobre el bus ya existente). Alternativas documentadas: integrar el colector ETW con una
interfaz (modo de conexión real, explícito), o el servicio privilegiado + IPC para sacar las
operaciones elevadas del proceso de la GUI.

**No iniciar la Fase 3 sin tu aprobación.**
