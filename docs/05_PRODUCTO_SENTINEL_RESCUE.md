# 05 — Producto dual: LOZARUS SENTINEL + LOZARUS RESCUE

> Documento de **diseño de producto y viabilidad**. No es implementación: en esta fase **no** se
> modifica la GUI ni se construye la imagen USB.
>
> Fecha: 2026-10-20 · Alcance: Windows 10/11 x64 (host propio o autorizado) + medio de rescate WinPE amd64.
>
> Separa explícitamente **hecho verificado** (código leído en este repo, o documentación oficial
> citada en §12) de **recomendación de diseño** y de **pendiente de verificar**.

---

## 0. Estado real del repositorio (verificado, leído hoy)

Antes de diseñar, lo que **de verdad** existe. Esto corrige cualquier suposición posterior.

| Componente | Estado | Evidencia |
|---|---|---|
| `core/` — `events.py`, `contracts.py`, `bus.py`, `errors.py` | **Existe y probado** (29 pruebas, sin elevación) | 615 líneas; `docs/02` |
| `collectors/etw_collector.py` | **Existe y probado** (13 pruebas unitarias sin admin) | 316 líneas; `docs/03` |
| **Integración ETW ↔ GUI** | **NO existe** | la GUI no importa `core/` ni `collectors/` |
| Caja Negra, OBSIDIAN | **NO existen** (solo diseñados) | `docs/00` §4.1, `docs/01` |
| `service/`, IPC, `detection/`, `response/`, `forensics/`, `storage/`, `reporting/`, `policies/`, `ui/` | **NO existen** como paquetes | `docs/01` los marca `(prev.)` |
| CHRONOS ($MFT/USN), IRONCLAD | **NO existen** | sin coincidencias de `$MFT`/`usn` en el código |
| `gui_qt.py` (PySide6, principal) | Existe, 2076 líneas, **7** páginas de navegación | `MainWindow.NAV`: comando, monitor, auditoria, historial, red, honeypot, fantasma |
| `gui.py` (CustomTkinter, respaldo) | **Retirado el 2026-10-21** (tenía 3028 líneas) | Sustituido por `gui_qt.py` |
| `auditor.py` (CLI) | Existe, 1053 líneas | — |
| `modulos/` | 13 módulos de auditoría numerados + 10 auxiliares (`_forense`, `_monitor`, `_tacticas`, `_contencion`, `_defensa_local`, `_alertas`, `_utilidades`, `_base`, `_cargador`, `_plantilla`) | 5103 líneas |
| Evidencia en disco | `Lozarus_Forensics/` con `Honeypot/`, `Sandbox/`, `Snapshots/` y reportes `.txt` | — |
| BitLocker | **Solo lectura de estado**, vía COM `Shell.Application` (sin admin). **No** hay desbloqueo. | `modulos/05_hardening.py:147` |
| `requirements.txt` en la raíz | **NO existe** — las dependencias (PySide6, psutil, qtawesome, plyer) están **sin declarar** | solo `spikes/etw/requirements-spike.txt` |

> **Deuda ya conocida y documentada:** la GUI actual invoca PowerShell directamente
> (`modulos/_utilidades.py: powershell_raw/powershell_argv`). Aceptable en un prototipo, **no** en el
> producto (`docs/00` §1.2). El producto dual no la agrava: la encapsula.
>
> **Inconsistencia menor detectada:** `docs/01` §4 remite el contrato de IPC a «`docs/03_*`», pero
> `docs/03` acabó siendo el colector ETW. El documento de servicio/IPC será `docs/06`.

---

## 1. Visión y objetivos de producto

**Lozarus es un asistente portátil de observabilidad, endurecimiento reversible, forense de solo
lectura y recuperación, para equipos propios o explícitamente autorizados.** No es un antivirus, no
es un EDR de kernel y no promete protección absoluta.

### 1.1. El problema que resuelve

Hay dos momentos en la vida de un incidente, y hoy ninguna herramienta amateur los cubre bien a la vez:

1. **Antes y durante** — el equipo arranca y funciona: hace falta *ver* qué pasa (telemetría honesta),
   endurecer de forma reversible y contener sin destruir evidencia. → **SENTINEL**.
2. **Después** — el equipo está comprometido, inestable o no arranca: hace falta analizarlo **sin
   ejecutar su Windows**, preservar evidencia y repararlo. → **RESCUE**.

### 1.2. Objetivos

| # | Objetivo | Criterio de éxito |
|---|---|---|
| O1 | Telemetría que no miente | Toda ventana sin observabilidad se declara. Nunca «limpio» sobre un hueco. |
| O2 | Portabilidad real | Sentinel se ejecuta sin instalación. Rescue arranca en hardware ajeno al Windows instalado. |
| O3 | Evidencia antes que limpieza | Ninguna acción de contención/reparación se ejecuta sin preservar evidencia, cuando sea viable. |
| O4 | Reversibilidad por defecto | Toda acción declara su reversibilidad; lo irreversible se etiqueta y confirma aparte. |
| O5 | Claridad bajo estrés | Un usuario asustado llega a «evidencia preservada» en ≤ 5 pasos guiados. |
| O6 | Honestidad de capacidades | La UI muestra qué **no** puede ver y por qué (privilegios, PPL, offline). |

### 1.3. No-objetivos (perímetro firme)

- No es un EDR de kernel: sin driver firmado no hay telemetría a prueba de manipulación ni
  `Microsoft-Windows-Threat-Intelligence` (`docs/00` §1.1). **Límite duro, verificado.**
- No hay sabotaje remoto, destrucción de datos ajenos ni contramedidas ofensivas contra terceros.
- No hay falsificación de identificadores de hardware ni biometría de pulsaciones (`docs/00` §3.5, §3.6).
- No se promete reparación automática garantizada ni recuperación de datos siempre posible.
- Rescue **no** recupera RAM ni estado de procesos de un Windows apagado (§4.4).

---

## 2. Arquitectura dual

### 2.1. Principio rector

> **Un solo núcleo de modelos y políticas. Dos capas de adquisición y dos capas de presentación.**
> Se comparte lo que es *verdad común* (qué es un evento, un hallazgo, una evidencia, una acción).
> **No** se comparte lo que depende de APIs, hardware o privilegios distintos.

```
                    ┌─────────────────────────────────────────┐
                    │  NÚCLEO COMPARTIDO (stdlib puro)        │
                    │  core/        modelos, contratos, bus   │
                    │  evidence/    hashing, manifiesto, CoC  │
                    │  analysis/    PE estático, YARA-lite    │
                    │  reporting/   informes, cronologías     │
                    │  policies/    reglas versionadas        │
                    └───────────────┬─────────────────────────┘
                                    │  (depende solo de stdlib;
                                    │   sin PySide6, sin Windows)
              ┌─────────────────────┴──────────────────────┐
              │                                            │
   ┌──────────▼───────────┐                   ┌────────────▼──────────┐
   │  SENTINEL (live)     │                   │  RESCUE (offline)     │
   │  collectors/  ETW…   │                   │  offline/  volúmenes  │
   │  detection/   OBSIDIAN│                  │            BitLocker  │
   │  response/    acciones│                  │            hives      │
   │  service/     IPC     │                  │            artefactos │
   │  deception/   señuelos│                  │  repair/   sfc/DISM   │
   │  ui_qt/       PySide6 │                  │  ui_rescue/ A o B §6  │
   └──────────────────────┘                   └───────────────────────┘
```

### 2.2. Componentes compartidos

| Paquete | Qué comparte | Por qué es compartible |
|---|---|---|
| `core/` | `Event`, `Provenance`, `ClockType`, `EventBus`, `SensorHealth`, `LossState`, errores | **Ya es stdlib puro y está probado.** Verificado: `core` no importa nada del proyecto. |
| `evidence/` (nuevo) | SHA-256, manifiesto, cadena de custodia, sellado | `hashlib`/`json` puros. Base reutilizable: `modulos/_forense.py: sha256_of` |
| `analysis/` (nuevo) | Análisis **estático** de PE: cabeceras, secciones, entropía, firmas, hashes | Opera sobre **ficheros**, da igual si el sistema está vivo o no. Ideal para Rescue. |
| `reporting/` (nuevo) | Informe de incidente (Markdown/HTML/JSON) | Puro formato sobre modelos del núcleo. |
| `policies/` (nuevo) | Reglas de detección, blocklist de drivers, perfiles — **versionados con fecha y hash** | Datos, no código. La UI muestra su antigüedad (`docs/00` §1.2.5). |

**Regla de compartición (nueva, verificable con prueba):** `core/`, `evidence/`, `analysis/`,
`reporting/` **no** pueden importar `PySide6`, `psutil`, `pywintrace`, `pywin32` ni `ctypes.windll`.
Así se garantiza que corren en WinPE, donde esas dependencias pueden no existir. Se hará cumplir con
una prueba AST equivalente a la ya existente `test_core_has_no_gui_dependency`.

### 2.3. Componentes exclusivos de Sentinel

| Paquete | Contenido | Por qué no va en Rescue |
|---|---|---|
| `collectors/` | ETW, Event Log, procesos, red, dispositivos, FS | Requieren un **Windows en ejecución**; no hay nada que observar en un sistema apagado. |
| `detection/` | OBSIDIAN (salud de telemetría), correlación, líneas base | Mide cobertura **en vivo**; el concepto no aplica a un disco quieto. |
| `response/` + `service/` | Acciones y el servicio privilegiado + IPC | En WinPE todo corre ya como SYSTEM: el modelo de delegación no tiene sentido (§7.2). |
| `deception/` | Señuelos, canary files, SACL | Un señuelo solo detecta si hay alguien ejecutándose. |
| `ui_qt/` | GUI PySide6 completa, bandeja del sistema, medidores en vivo | Depende de Qt + GPU/tema; en WinPE es exactamente la incógnita (§6). |

### 2.4. Componentes exclusivos de Rescue

| Paquete | Contenido | Nota |
|---|---|---|
| `offline/volumes.py` | Enumerar discos/particiones/volúmenes, identificar instalaciones de Windows | Vía `diskpart`, WMI (`WinPE-WMI`) y APIs Win32 |
| `offline/bitlocker.py` | Detectar bloqueo y **guiar** el desbloqueo con la clave legítima del usuario | `manage-bde`; requiere `WinPE-SecureStartup` (§8.2) |
| `offline/hives.py` | Cargar/parsear hives offline (`SOFTWARE`, `SYSTEM`, `SAM`, `NTUSER.DAT`) | Persistencia: Run/RunOnce, Servicios, Winlogon, IFEO |
| `offline/artifacts.py` | Prefetch, Amcache, `.evtx`, tareas programadas, `$MFT`/USN (lectura cruda) | **Solo lectura.** Es la base real para CHRONOS. |
| `offline/quarantine.py` | Cuarentena verificable: hash → copia de evidencia → mover/renombrar → manifiesto de restauración | Reversible por diseño (§9.4) |
| `repair/` | `sfc /offbootdir`, `DISM /image:`, `bcdboot`, `bootrec`, `chkdsk`, recuperación de ficheros | Cada una con reversibilidad declarada (§10) |
| `ui_rescue/` | Front-end de rescate — **Pista A o Pista B según §6.5** | Decisión con puerta de validación |

### 2.5. Lo que explícitamente **no** se fuerza a compartir

- **Un único binario para los dos entornos.** Son dos empaquetados distintos del mismo núcleo.
- **El acceso a BitLocker.** En Sentinel es *lectura de estado* (ya existe, vía COM Shell). En Rescue
  es *desbloqueo con clave* (`manage-bde`). **La implementación actual de Sentinel NO sirve en
  WinPE**: `Shell.Application` depende del shell de Windows, que WinPE no incluye (§6.3).
- **El modelo de privilegios.** Sentinel tiene frontera usuario↔admin; Rescue es SYSTEM de principio
  a fin (§7).
- **La telemetría.** Sentinel la produce; Rescue solo consume artefactos ya escritos en disco.

---

## 3. Menús y navegación definitivos

### 3.1. Estructura (9 apartados) y a qué entorno pertenecen

| # | Apartado | Sentinel | Rescue | Mapeo con lo que ya existe |
|---|---|:--:|:--:|---|
| 1 | **Cuartel general** | ✔ | ✔ (variante) | `CommandPage` (hoy «Centro de Comando») |
| 2 | **Centinela en vivo** | ✔ | ✖ | `MonitorPage` + Vanguardia; aquí entran ETW/bus/Caja Negra/OBSIDIAN |
| 3 | **Análisis del equipo** | ✔ | ✔ | `AuditPage` + los 13 módulos de `modulos/` |
| 4 | **Defensa y contención** | ✔ | ◐ (cuarentena offline) | `NetworkPage`, `GhostPage`, Cuarentena Absoluta, `_contencion.py` |
| 5 | **Campo de señuelos** | ✔ | ✖ | `HoneypotPage` + `Lozarus_Forensics/Honeypot/` |
| 6 | **Laboratorio forense** | ✔ | ✔ | `HistorialPage` + `_forense.py` + `Snapshots/` |
| 7 | **Recuperación y reparación** | ◐ (reversión de cambios propios) | ✔ | Nuevo en su mayor parte |
| 8 | **Preparación y validación del USB** | ✔ | ✖ (se autovalida) | Nuevo |
| 9 | **Ajustes, permisos y auditoría** | ✔ | ✔ | Nuevo como apartado propio |

Leyenda: ✔ completo · ◐ parcial · ✖ no aplica.

### 3.2. Pantalla principal — Cuartel general

Seis zonas fijas, en este orden de lectura (arriba-izquierda → abajo-derecha):

```
┌────────────────────────────────────────────────────────────────────────────┐
│  ESTADO GENERAL        [ PROTEGIDO / ATENCIÓN / INCIDENTE / SIN DATOS ]    │
│  «Qué significa»  ·  última verificación: hace 3 min                       │
├──────────────────────────────┬─────────────────────────────────────────────┤
│  ESTADO DE LA TELEMETRÍA     │  INCIDENTES ACTIVOS                         │
│  ETW ............ activo     │  ▸ 2 hallazgos sin revisar                  │
│  Event Log ...... activo     │  ▸ 0 incidentes abiertos                    │
│  Cobertura 14:02→ahora  98 % │  (lista con severidad y antigüedad)         │
│  Huecos: 1 (12 s, 14:01)     │                                             │
├──────────────────────────────┼─────────────────────────────────────────────┤
│  CPU / RAM  (medidores+spark)│  ACCIONES RECOMENDADAS                      │
│  CPU 14 %   RAM 41 %         │  1. Activar BitLocker  (impacto: medio)     │
│  (ya implementado: Gauge,    │  2. Revisar 2 hallazgos (impacto: ninguno)  │
│   Sparkline)                 │  3. Crear USB de rescate (impacto: ninguno) │
├──────────────────────────────┴─────────────────────────────────────────────┤
│  [ ⚠ ASISTENTE GUIADO DE EMERGENCIA ]   ← botón ancho, siempre visible     │
└────────────────────────────────────────────────────────────────────────────┘
```

Reglas de la pantalla principal:

- **`SIN DATOS` es un estado de primera clase**, distinto de `PROTEGIDO`. Si la telemetría no está
  activa, el estado general **no puede** decir «protegido» (objetivo O1). Implementa el principio
  OBSIDIAN en la cara visible del producto.
- «Cobertura» y «Huecos» salen de `SensorHealth` + `LossState` del núcleo **ya implementados**:
  `None` = desconocido se pinta como `—`, nunca como `0`.
- «Acciones recomendadas» muestra **siempre** el impacto y la reversibilidad antes de ejecutar.

### 3.3. Navegación y accesibilidad

- **Barra lateral persistente** (ya existe: 264 px, `NavButton` con iconos `qtawesome`) + migas de pan
  dentro de cada apartado. Máximo **dos niveles** de profundidad.
- **Consola de telemetría** siempre visible abajo (ya existe, `TelemetryConsole`): es el registro
  auditable de lo que la herramienta hace. No se oculta nunca.
- **Teclado completo:** `Ctrl+1..9` salta a cada apartado; `Tab` recorre en orden lógico; `Esc`
  cancela cualquier operación cancelable. Toda acción destructiva es alcanzable solo con confirmación
  explícita, nunca con `Enter` por defecto.
- **Sin señalización únicamente por color.** Cada estado lleva **icono + texto** además del color
  (requisito de accesibilidad y de daltonismo). Verificar contraste ≥ 4.5:1 sobre la paleta oscura
  actual (`#0B0B0E` / `#18181C`) — **pendiente de medir**.
- **Lenguaje:** español claro. Cada término técnico tiene un «¿qué significa?» desplegable. El texto
  de un riesgo nunca se abrevia para que quepa.

### 3.4. Modo normal vs modo incidente

| | **Uso normal** | **Respuesta a incidente** |
|---|---|---|
| Entrada | Navegación libre por los 9 apartados | Botón de emergencia, o automático al abrirse un incidente grave |
| Disposición | Dashboard + barra lateral | **Secuencia guiada a pantalla completa**, un paso a la vez |
| Barra lateral | Visible | Atenuada pero accesible («salir del asistente») |
| Lenguaje | Técnico con ayuda | Llano, orientado a la acción, sin jerga |
| Prioridad | Información | **Preservar evidencia → contener → recuperar** |
| Acciones | Todas | Solo las del paso actual; el resto bloqueadas |
| Gamificación | Permitida (postura, progreso de preparación) | **Desactivada por completo** |

### 3.5. Reglas de gamificación (lo que sí y lo que no)

**Permitido:** progreso de endurecimiento («12 de 18 comprobaciones superadas»), insignias de
*preparación* (USB de rescate creado y validado, línea base guardada, evidencia probada), paneles e
indicadores vistosos, misiones de *configuración*.

**Prohibido:**
- Convertir una acción peligrosa en un botón de videojuego, o premiar su ejecución.
- Ocultar o abreviar un riesgo para que la interfaz quede limpia.
- Rachas, cuentas atrás o puntuaciones que presionen a actuar rápido durante un incidente.
- Barras de progreso falsas en operaciones cuyo avance real no se conoce (se usa indeterminado).

> El criterio: **la estética puede ser un centro de mando; las consecuencias se cuentan en prosa llana.**

---

## 4. Flujos de emergencia y recuperación

### 4.1. Asistente de emergencia en Sentinel (equipo aún arranca)

```
P0  TRIAJE          ¿Qué observas? [lentitud] [ventanas raras] [archivos cifrados]
                    [cuentas ajenas] [no sé]            → elige rama, no obliga a diagnosticar
P1  PRESERVAR       Snapshot volátil + hash + manifiesto     (lectura; sin impacto)
     ↓              Base ya existente: _forense.system_snapshot()
P2  ESTABILIZAR     Propone contención reversible, con impacto explicado:
                    · aislar red (reversible, pierdes conectividad)
                    · congelar proceso sospechoso (reversible)
                    NUNCA: apagar, borrar, formatear
P3  INVESTIGAR      Hallazgos con nivel de confianza: observación / inferencia / conclusión
P4  DECIDIR         [seguir en caliente]  |  [pasar a RESCUE]  ← si hay sospecha de persistencia
                    profunda, rootkit o el sistema es inestable
P5  INFORME         Exporta informe + evidencia a destino elegido por el usuario
```

**Regla de oro de P1→P2:** si la preservación de evidencia falla o no se puede verificar, el asistente
**lo dice y pregunta** antes de continuar. No contiene a ciegas (objetivo O3).

### 4.2. Cuándo recomendar el salto a Rescue

El asistente propone arrancar con el USB cuando concurre alguna de estas (explicando el porqué):

- El sistema no arranca, o arranca de forma inestable.
- Hay indicios de persistencia a nivel de arranque/driver que no se pueden evaluar en caliente.
- Se necesita leer o copiar ficheros que el Windows en ejecución tiene bloqueados.
- Hay sospecha de que el propio sistema operativo está mintiendo (procesos/ficheros ocultos).
- Se requiere cuarentena de un fichero que se vuelve a ejecutar siempre que Windows arranca.

### 4.3. Flujo en Rescue (equipo apagado, arrancado desde USB)

```
R0  ARRANQUE        WinPE arranca. Lozarus Rescue se autoverifica:
                    hash de su propio payload vs manifiesto firmado → muestra OK / ALTERADO
R1  INVENTARIO      Discos, particiones, volúmenes. Identifica instalaciones de Windows.
                    Marca: [NTFS legible] [BitLocker BLOQUEADO] [sin reconocer] [dañado]
R2  DESBLOQUEO      Solo si hay BitLocker: guía al usuario con SU clave legítima
                    (contraseña / clave de recuperación de 48 dígitos / llave USB).
                    Si no la tiene: se detiene y explica dónde buscarla. NO se intenta romper.
R3  MONTAJE RO      Monta el volumen objetivo en SOLO LECTURA por defecto.
                    Escribir exige un paso explícito y separado (§7.2).
R4  TRIAJE OFFLINE  Persistencia (hives), artefactos de ejecución, análisis estático de PE,
                    cronología. Todo solo lectura, con procedencia por dato.
R5  PRESERVAR       Copia de evidencia + SHA-256 + manifiesto al DESTINO ELEGIDO
                    (nunca al volumen investigado) → verificación de hash tras copiar
R6  CUARENTENA      Solo tras R5 verificado. Copia → mover/renombrar → manifiesto de restauración.
R7  REPARAR         sfc/DISM offline, BCD, chkdsk, recuperación de archivos.
                    Cada acción: impacto + reversibilidad + punto de restauración si cabe.
R8  INFORME         Informe del incidente al destino elegido. Registro completo de operaciones.
```

### 4.4. Lo que Rescue **no** puede hacer (honestidad obligatoria en la UI)

> **Un Windows apagado no tiene RAM ni procesos.** Rescue analiza una **instalación offline**: un
> conjunto de ficheros en un disco. No existe «capturar la memoria» ni «ver los procesos» de ese
> sistema, porque no hay nada ejecutándose. Esto es una diferencia de naturaleza, no una limitación
> que se pueda mejorar.

Lo que **sí** queda en disco, y cómo hay que presentarlo:

| Artefacto | Qué es realmente | Advertencia obligatoria |
|---|---|---|
| `hiberfil.sys` | Imagen **comprimida** de memoria de una hibernación **pasada** | Puede no existir, estar obsoleta, o ser parcial con *Inicio rápido*. **No** es la RAM del momento del incidente. |
| `pagefile.sys` / `swapfile.sys` | Páginas paginadas a disco, fragmentarias y sin contexto | Sin estructura de proceso; hallazgos = cadenas sueltas, no prueba. |
| `MEMORY.DMP` / minidumps | Volcado de un fallo **concreto** del pasado | Solo el estado de ese fallo. Puede estar desactivado. |
| `.evtx`, Prefetch, Amcache, `$MFT`/USN | **Registro histórico** de actividad | Sujetos a rotación, borrado y manipulación. Detectar lagunas (`docs/00` §4.3). |

La UI de Rescue mostrará, en el apartado forense, un aviso permanente: *«Análisis de instalación
offline. No hay monitorización en vivo ni estado de procesos.»*

### 4.5. Recuperación y reparación — orden de menor a mayor impacto

Rescue **siempre** ofrece las opciones en este orden, y nunca salta sola a la siguiente:

1. **Leer y copiar** (impacto nulo): rescatar los archivos del usuario a un destino externo. *Esto se
   ofrece primero, siempre.* Es lo que más le importa a quien ha perdido su equipo.
2. **Reparar arranque** (reversible con respaldo de BCD): `bcdboot`, `bootrec`.
3. **Reparar sistema de archivos** (`chkdsk`): **parcialmente irreversible** — puede descartar datos
   corruptos. Exige confirmación reforzada y, si hay espacio, imagen previa.
4. **Reparar componentes** (`sfc /offbootdir`, `DISM /image: /RestoreHealth`): reversible solo con
   respaldo previo de los ficheros sustituidos.
5. **Cuarentena / eliminación de persistencia**: tras evidencia verificada, con manifiesto de
   restauración.
6. **Reinstalación / formateo**: fuera del alcance automático de Rescue. Se informa y se deriva; no
   se ofrece como botón.

---

## 5. Matriz de funcionalidades: Sentinel vs Rescue

Estado: **✅ existe hoy** · **🔨 a implementar** · **◐ parcial/condicionado** · **✖ no aplica**

| Capacidad | Sentinel | Rescue | Notas de viabilidad |
|---|:--:|:--:|---|
| Dashboard de estado | ✅ `CommandPage` | 🔨 variante | Rescue sin telemetría en vivo |
| Medidores CPU/RAM | ✅ `Gauge`+`Sparkline` | ◐ | En Rescue mide **WinPE**, no el sistema investigado → etiquetar |
| Vigilancia en tiempo real | 🔨 (ETW listo, sin integrar) | ✖ | Nada que vigilar en un sistema apagado |
| Minimizar a bandeja manteniendo vigilancia | 🔨 | ✖ | WinPE no tiene shell ni bandeja (§6.3) |
| Estado de sensores y huecos de observabilidad | 🔨 (OBSIDIAN) | ✖ | Contratos `SensorHealth`/`LossState` **ya existen** |
| Caja Negra (búfer + persistencia) | 🔨 | ◐ lectura | Rescue puede **leer** una Caja Negra dejada por Sentinel |
| Colector ETW | ✅ (probado, sin integrar) | ✖ | `collectors/etw_collector.py` |
| 13 módulos de auditoría | ✅ | ◐ | Los que leen el **registro en vivo** no aplican; adaptar a hives offline |
| Análisis de procesos | ✅ `ProcBoard` | ✖ | §4.4 |
| Análisis de conexiones | ✅ | ✖ | Sin red del sistema investigado |
| Análisis de persistencia | ✅ `11_persistencia` | 🔨 offline | Offline es **más fiable**: el SO no puede ocultar |
| Análisis estático de ficheros/PE | 🔨 `analysis/` | 🔨 | **Compartido.** Igual de válido en ambos |
| Hash + firma de ejecutables | ✅ `sha256_of` | 🔨 | Verificación de firma offline: requiere cuidado (cadena/revocación) |
| Señuelos defensivos inocuos | ✅ `HoneypotPage` | ✖ | Sin credenciales reales (regla de seguridad) |
| Contención reversible (red/procesos/USB) | ✅ Cuarentena Absoluta | ✖ | — |
| Cuarentena de ficheros | ◐ | 🔨 | Offline es donde de verdad funciona (fichero no en uso) |
| Snapshot de evidencia | ✅ `system_snapshot` | 🔨 | Modelo y manifiesto **compartidos** |
| Cadena de custodia + manifiesto | 🔨 `evidence/` | 🔨 | **Compartido** |
| Enumerar volúmenes y particiones | ◐ | 🔨 | — |
| Detectar BitLocker | ✅ solo estado (COM Shell) | 🔨 | **La implementación actual no sirve en WinPE** (§6.3) |
| Desbloquear BitLocker con clave legítima | ✖ | 🔨 | `manage-bde` + `WinPE-SecureStartup` |
| Leer registro offline (hives) | ✖ | 🔨 | `SOFTWARE`/`SYSTEM`/`SAM`/`NTUSER.DAT` |
| Cronología NTFS ($MFT/USN) — CHRONOS | 🔨 | 🔨 | Offline evita bloqueos y manipulación en vuelo |
| Recuperación de archivos del usuario | ✖ | 🔨 | **Prioridad nº 1 del usuario real** (§4.5) |
| Reparación del sistema (sfc/DISM/BCD) | ◐ en vivo | 🔨 offline | Offline: `/offbootdir`, `/image:` |
| Exportar informe del incidente | ◐ `.txt` | 🔨 | **Compartido** `reporting/` |
| Modo sin red (offline) | ◐ | 🔨 | Rescue: por defecto **sin red** |
| Autoverificación de integridad propia | ✖ | 🔨 | Rescue valida su payload al arrancar (R0) |
| Creación y validación del USB | 🔨 apartado 8 | ✖ | Sentinel construye; Rescue se usa |
| Servicio de Windows permanente | ✖ **no en v1** | ✖ | Ventajas/costes en §7.4 |

---

## 6. Viabilidad de Python/PySide6 en WinPE

> **Esta es la decisión técnica más arriesgada del producto y está SIN VERIFICAR.** La búsqueda
> documental no encontró ninguna fuente oficial ni comunitaria que confirme PySide6 funcionando en
> WinPE. Lo que sigue son los obstáculos **concretos** y el procedimiento para resolverlos — no una
> promesa de que funcione.

### 6.1. Hechos verificados sobre WinPE (fuentes en §12)

| Hecho | Consecuencia para Lozarus |
|---|---|
| WinPE es un **add-on del Windows ADK** (descarga aparte desde Win10 1809) | La construcción exige una máquina Windows con ADK + WinPE add-on |
| Soporta **APIs Win32**, scripts, DISM, NTFS/DiskPart/BCDBoot, y **opcionalmente** PowerShell, BitLocker/TPM | Hay base suficiente para un front-end Win32 y para `manage-bde` |
| **Se reinicia automáticamente** tras un periodo continuo de uso: 72 h en Win10 ≤1709, **240 h** en 1803+. **No configurable** | Irrelevante para una sesión de rescate; se documenta y se avisa |
| **Todos los cambios se pierden al reiniciar** (disco RAM) | La evidencia **debe** escribirse a un destino persistente, nunca «al sistema» |
| La base requiere **512 MB de RAM**; el arranque por disco RAM necesita memoria física **contigua** para toda la imagen WIM | Un payload grande sube el mínimo de RAM. Medir el tamaño final |
| El espacio de trabajo (*scratch space*) por defecto es **512 MB** con >1 GB de RAM (32 MB si menos). Valores válidos: 32/64/128/256/512 MB | **Decisivo:** un `.exe` *onefile* se extrae a temporal → consume scratch. → usar **onedir** (§6.4) |
| La instalación por defecto usa **FAT32**: máximo **4 GB por fichero** y **32 GB de volumen** | Obliga a **dos particiones** en el USB (§9.1) y limita el tamaño de la evidencia |
| **No soporta ficheros `.MSI`** | **No se puede instalar el VC++ Redistributable con su MSI**: hay que copiar las DLL o integrarlas en la imagen |
| No soporta Escritorio remoto, unión a dominio, NIC teaming, ni ejecutar apps de otra arquitectura | Rescue debe ser **amd64 puro** y sin dependencia de red |
| Para lanzar el programa de instalación de Windows 11 desde WinPE hacen falta `WinPE-WMI` **y** `WinPE-SecureStartup` | Los mismos componentes que necesitamos para WMI y BitLocker |
| `WinPE-SecureStartup` aporta gestión de **BitLocker y TPM** y **depende de `WinPE-WMI`** | Orden de instalación obligatorio (§8.2) |
| Licencia: WinPE «no puede usarse para otro propósito que despliegue y recuperación» | **Rescue encaja** (recuperación/forense). Refuerza que la *monitorización* no vaya en WinPE. **Confirmar con el EULA del ADK** antes de distribuir |

### 6.2. Lo que PySide6 necesita y WinPE no garantiza

| Dependencia | Riesgo en WinPE | Mitigación propuesta |
|---|---|---|
| `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`, `MSVCP140.dll` | **Alto** — WinPE no trae el VC++ Redistributable, y **no se puede instalar por MSI** | Copiar las DLL junto al ejecutable (modelo *app-local*), o integrarlas en la imagen con DISM |
| Universal CRT (`api-ms-win-crt-*`, `ucrtbase.dll`) | **Medio** — Python 3.13 depende de UCRT; WinPE moderno debería traerlo, **sin confirmar** | Verificar con `dumpbin /dependents`; si falta, añadir los *api-sets* a la imagen |
| Plugin de plataforma Qt `platforms/qwindows.dll` | **Alto si se empaqueta mal** | Empaquetar el árbol de plugins y fijar `QT_QPA_PLATFORM_PLUGIN_PATH` |
| Aceleración gráfica / OpenGL | **Alto** — WinPE usa el controlador de vídeo básico, sin GPU | Forzar software: `QT_OPENGL=software` + `opengl32sw.dll`. **Usar solo Qt Widgets, nunca QML/QtQuick** |
| Temas/efectos del shell (`uxtheme`, `dwmapi`) | **Medio** — WinPE no tiene shell de Windows | Evitar marco nativo y efectos; la GUI actual ya es `FramelessWindowHint`, lo cual **ayuda** |
| `.NET Framework` | **Ninguno para Qt** (Qt no lo usa) | `WinPE-NetFx` solo si algo más lo pidiera |
| `psutil` | **Medio** — funciona sobre Win32, pero mediría **WinPE**, no el sistema investigado | Permitido solo para los medidores locales, claramente etiquetados |
| COM `Shell.Application` | **Alto — rotura conocida** | La comprobación actual de BitLocker (`modulos/05_hardening.py:147`) **no es portable a WinPE**. Reimplementar con `manage-bde`/WMI |
| Fuentes e iconos (`qtawesome`) | **Bajo/medio** — WinPE trae pocas fuentes | Empaquetar las fuentes necesarias; no depender de fuentes del sistema |

### 6.3. Diferencias de entorno que rompen suposiciones de la GUI actual

1. **No hay shell de Windows** → nada de `explorer.exe`, diálogos de shell, bandeja del sistema ni
   notificaciones (`plyer`). → **Vanguardia y «minimizar a bandeja» no existen en Rescue.**
2. **No hay perfil de usuario normal** → rutas como `%LOCALAPPDATA%` apuntan al disco RAM volátil.
   Toda ruta de escritura debe ser **explícita y elegida por el usuario**.
3. **PowerShell es opcional** → si `modulos/` se reutiliza en Rescue, sus llamadas a PowerShell
   requieren `WinPE-PowerShell` en la imagen, o reescritura. **Decisión pendiente** (§11).
4. **Todo corre como SYSTEM** → `is_admin()` siempre dará verdadero; la lógica de la UI que degrada
   funciones por falta de privilegios **no se puede probar** ahí (§7.2).

### 6.4. Estrategia de empaquetado recomendada

- **Python embebido** (`python-3.13-embed-amd64`) o **PyInstaller en modo `onedir`**.
  **Nunca `onefile`:** se autoextrae en el temporal, que en WinPE es el *scratch space* de 512 MB
  en RAM — riesgo de agotarlo y de ralentizar el arranque.
- Payload en la **partición NTFS** del USB, no en la FAT32 de arranque (límite de 4 GB).
- Arquitectura **amd64** en todo: WinPE no ejecuta aplicaciones de otra arquitectura.
- Manifiesto de hashes del payload, verificado por Rescue al arrancar (paso R0).

### 6.5. Veredicto y puerta de decisión

**Veredicto honesto: viabilidad probable pero NO demostrada.** Hay un camino técnico razonable
(empaquetado app-local + render software + solo Widgets), pero cada punto de §6.2 es un fallo
potencial y no hay precedente documentado que lo confirme.

Por eso el diseño **no apuesta todo a Qt**:

| | **Pista A — PySide6 en WinPE** | **Pista B — Front-end sin Qt** |
|---|---|---|
| Qué es | La misma base de código visual que Sentinel | Interfaz de consola/TUI + informe HTML, solo stdlib |
| Ventaja | Una sola experiencia, una sola base | **Funciona con casi total seguridad** |
| Riesgo | Cualquier punto de §6.2 puede bloquearla | Experiencia más pobre en el momento más estresante |
| Esfuerzo | Alto e incierto | Bajo y predecible |

**Puerta de decisión (criterio objetivo, no opinión):** en la fase P0 se construye un USB con un
*smoke test* mínimo — una `QApplication` con una ventana y un botón. Se concede un **presupuesto
acotado de 3 días** de depuración de dependencias.
- Si la ventana aparece en una VM UEFI → **Pista A** para v1.
- Si no, → **Pista B** para v1, y la Pista A se reevalúa después, sin bloquear el producto.

El núcleo compartido (§2.2) es idéntico en ambas pistas, así que **la decisión no afecta a la lógica**,
solo a la capa de presentación de Rescue. Esa es la razón de ser de la regla de compartición.

---

## 7. Modelo de privilegios

### 7.1. Sentinel — frontera usuario ↔ administrador

Se mantiene el diseño ya fijado en `docs/01` §4, sin cambios:

```
 GUI (usuario normal)  ──pide──▶  response/  ──autoriza y delega──▶  service/ (admin)
        │                                                                  │
        └── nunca importa windows/, service/ ni collectors/ ───────────────┘
```

- La GUI corre como **usuario normal** y nunca ejecuta operaciones privilegiadas directamente.
- Lo que requiere elevación va por un servicio auxiliar de superficie mínima (Named Pipes + ACL),
  con **autorización por operación**, validación estricta de argumentos y auditoría de cada acción.
  Un token efímero **no** basta como autorización.
- **Hoy esto no está implementado** y la GUI llama a PowerShell directamente: deuda documentada, a
  resolver en `docs/06` (servicio e IPC).
- Degradación honesta: sin privilegios, cada función indica **qué** no puede hacer y **por qué**;
  nunca falla en silencio ni finge éxito.

### 7.2. Rescue — la asimetría que lo cambia todo

> **En WinPE no hay frontera de privilegios: todo se ejecuta como SYSTEM.** No hay nada que elevar ni
> a quién delegar. El modelo de autorización de Sentinel **no aplica**.

Esto invierte el riesgo: el peligro ya no es la *escalada*, es la **destrucción accidental con
privilegio total sobre el disco de alguien**. Las salvaguardas se rediseñan en consecuencia:

| Salvaguarda | Regla |
|---|---|
| **Solo lectura por defecto** | Los volúmenes objetivo se montan RO. Escribir es un paso **separado y explícito** por volumen, con aviso de que se va a modificar un sistema ajeno. |
| **Nunca escribir en el volumen investigado** | Evidencia e informes van al destino elegido. Si el usuario insiste, aviso de contaminación de evidencia. |
| **Simulación primero** | Toda operación de escritura ofrece `--dry-run` que enumera exactamente qué tocaría. |
| **Registro previo a la acción** | Cada operación se escribe en el diario de evidencia **antes** de ejecutarse, no después. |
| **Confirmación proporcional al impacto** | Reversible: confirmación simple. Irreversible: mantener pulsado + escribir una palabra clave (ya existe el patrón: `HoldButton`, `ResetConfirmDialog`). |
| **Identificación del objetivo** | Antes de cualquier escritura, la UI repite en voz alta qué volumen, qué etiqueta, qué tamaño y qué instalación de Windows. Confundir de disco es el fallo más probable. |

### 7.3. Operador y trazabilidad

Rescue no tiene cuentas de usuario, así que la identidad no puede autenticarse. Se registra lo que
honestamente se puede: un **identificador de operador introducido a mano** (texto libre, marcado como
*declarado, no verificado*), marcas de tiempo UTC, versión de la herramienta y hash de su payload,
identificadores de hardware y volúmenes. **No se presenta como prueba de identidad.**

### 7.4. Servicio permanente de Windows — ventajas, costes y veredicto

**No es requisito de v1** (aplicación portátil, vigilancia solo mientras Lozarus esté abierto).
Evaluación para el futuro:

| | Aplicación portátil (v1) | Servicio permanente (futuro) |
|---|---|---|
| Cobertura | Solo con la app abierta → **huecos de observabilidad conocidos y declarados** | Continua, también antes del inicio de sesión |
| Arranque temprano | No ve nada previo al lanzamiento manual | Ve el arranque, donde vive la persistencia interesante |
| Privilegios | Pide elevación por acción | Ya elevado; habilita el modelo `service/`+IPC |
| Portabilidad | **Total**: USB, sin instalación, sin huella | Requiere instalación, se registra en el sistema |
| Superficie de ataque | Mínima | Un servicio SYSTEM siempre activo **es** un objetivo |
| Mantenimiento | Trivial | Actualizaciones, recuperación ante fallos, desinstalación limpia |
| Confianza del usuario | Alta («lo ejecuto cuando quiero») | Exige justificar por qué debe residir siempre |
| Honestidad | Los huecos son evidentes y se muestran | Tienta a prometer cobertura total que tampoco es cierta |

**Veredicto:** portátil en v1. El servicio se evalúa **solo cuando** OBSIDIAN esté en producción y
pueda cuantificar exactamente cuánta observabilidad se pierde por no tenerlo — es decir, cuando la
decisión pueda tomarse con datos y no con intuición. Si se adopta, debe ser **opcional**,
desinstalable por completo y con el modelo IPC de `docs/06` ya implementado.

---

## 8. Evidencia, BitLocker y almacenamiento

### 8.1. Política de evidencia

| Regla | Detalle |
|---|---|
| **Destino separado** | Nunca el volumen investigado. Por defecto, la partición de datos del USB o un medio externo elegido. |
| **Hash en origen y destino** | SHA-256 antes de copiar y **después** de copiar; se registran ambos. Si difieren → se marca la copia como **no verificada** y se avisa. |
| **Manifiesto append-only** | JSONL con una línea por artefacto: ruta origen, tamaño, hash, marcas temporales, cómo se obtuvo, operador declarado, versión de herramienta. |
| **Sellado del manifiesto** | Al cerrar el caso, hash del manifiesto completo + recuento. Detecta truncamientos posteriores. |
| **Marcas de tiempo honestas** | Se reutiliza el modelo **ya implementado**: marca original + `ClockType` + UTC **solo si es fiable** + monotónica. Nada de inventar husos horarios. Los tiempos NTFS son UTC; los del registro, no siempre → se etiqueta. |
| **Procedencia por dato** | Cada hallazgo indica de qué artefacto sale y si es *observación*, *inferencia* o *conclusión*. |
| **Nunca borrar antes de verificar** | Cuarentena y limpieza exigen copia de evidencia con hash verificado. Si no cabe, se avisa y se pide decisión. |
| **Lagunas explícitas** | Si un artefacto falta, está rotado o es ilegible, se registra como **laguna**, no se omite. |

### 8.2. BitLocker

**Lo que hay hoy (verificado):** solo detección de estado en Sentinel, vía la propiedad COM
`System.Volume.BitLockerProtection` de `Shell.Application`, sin admin
(`modulos/05_hardening.py:147`). **No sirve en WinPE** (sin shell de Windows).

**Diseño para Rescue:**

1. **Requisito de imagen:** `WinPE-WMI` **y luego** `WinPE-SecureStartup` (dependencia verificada:
   SecureStartup requiere WMI). Sin ellos, WinPE **no** gestiona BitLocker.
2. **Detección:** por volumen, estado de cifrado y de bloqueo (`manage-bde -status`). La UI distingue
   claramente **cifrado** de **bloqueado**: un volumen cifrado pero desbloqueado es legible.
3. **Desbloqueo guiado, con la clave legítima del usuario**, en este orden de preguntas:
   - contraseña del volumen, o
   - **clave de recuperación de 48 dígitos** (y dónde encontrarla: cuenta Microsoft en
     `account.microsoft.com/devices/recoverykey`, impresión, fichero `.BEK`, Active Directory/Entra,
     o copia guardada por el propio usuario), o
   - llave de arranque USB (`.BEK`).
4. **Si el usuario no tiene la clave: la herramienta se detiene y lo explica.** No se intenta ni se
   sugiere eludir el cifrado. Sin clave, los datos son irrecuperables **por diseño de BitLocker**, y
   decir lo contrario sería mentir.
5. **Desbloqueo ≠ descifrado.** Se desbloquea para leer en esa sesión; no se descifra el volumen.
6. **TPM:** en WinPE el desbloqueo automático por TPM **no** se da por hecho (el sellado depende del
   estado de arranque medido). Se asume **siempre** que hará falta clave o contraseña.
7. **Registro:** se anota que el volumen estaba cifrado y que el desbloqueo lo autorizó el operador.
   **Nunca se escribe la clave** en el informe, el manifiesto ni los registros.

### 8.3. Almacenamiento y sus límites duros

| Límite (verificado) | Impacto | Decisión de diseño |
|---|---|---|
| FAT32: **4 GB** por fichero | Una imagen de disco o un `hiberfil.sys` grande **no cabe** | Evidencia en **NTFS/exFAT**. Si el destino es FAT32, la UI lo detecta, avisa y ofrece trocear |
| FAT32: **32 GB** de volumen | La partición de arranque no sirve como almacén | **Dos particiones** en el USB (§9.1) |
| Disco RAM de WinPE: cambios **perdidos al reiniciar** | Evidencia en el disco de WinPE = evidencia perdida | Prohibido por diseño: el destino se elige y se comprueba que es persistente |
| *Scratch space* 512 MB (máx.) | Operaciones con mucho temporal fallan | Procesamiento en flujo (*streaming*), sin extracciones grandes a temporal |
| RAM mínima 512 MB + WIM contiguo | Un payload grande sube el mínimo real | Medir el tamaño del WIM final y publicar el requisito **medido** |

**Estimación de espacio para evidencia** (orientativa, a validar): triaje de artefactos sin volcados
grandes ≈ 200 MB–2 GB; con `hiberfil.sys`/`pagefile.sys` ≈ tamaño de la RAM del equipo; imagen
completa de volumen = tamaño del volumen. La UI **calcula y muestra el espacio necesario antes de
empezar**, y no inicia una copia que no va a caber.

---

## 9. Construcción y validación del USB

### 9.1. Esquema del medio

```
USB (GPT, para arranque UEFI)
├─ Partición 1: FAT32, ~1–2 GB, booteable   ← exigido por UEFI; límite de 4 GB/fichero
│   └─ EFI/, sources/boot.wim, bootmgr…       (cadena de arranque firmada por Microsoft)
└─ Partición 2: NTFS, el resto                ← sin límite práctico de tamaño de fichero
    ├─ Lozarus/            payload (onedir) + manifiesto de hashes
    ├─ Policies/           reglas versionadas (con fecha y hash)
    └─ Evidencia/          destino por defecto de la evidencia
```

Dos particiones **no** son una preferencia estética: son consecuencia directa de los límites FAT32
verificados y de la necesidad de un destino de escritura persistente.

### 9.2. Proceso de construcción (en una máquina Windows con ADK + WinPE add-on)

```
1. copype amd64 C:\WinPE_amd64
2. Dism /Mount-Image  (boot.wim, índice 1)
3. Componentes opcionales, EN ORDEN DE DEPENDENCIA:
      WinPE-WMI            → base para lo demás
      WinPE-SecureStartup  → BitLocker/TPM   (requiere WinPE-WMI)
      WinPE-PowerShell     → solo si se reutilizan los módulos actuales  (decisión pendiente)
      WinPE-FMAPI          → recuperación de ficheros
      + los paquetes de idioma correspondientes a cada componente
4. Dism /Set-ScratchSpace:512
5. Controladores de almacenamiento y red (Dism /Add-Driver /Recurse)
6. Copiar el payload de Lozarus + manifiesto de hashes
7. Arranque automático de Rescue (winpeshl.ini), con salida a línea de comandos como respaldo
8. Dism /Unmount-Image /Commit
9. MakeWinPEMedia /UFD  (y luego crear/poblar la partición NTFS)
10. Publicar SHA-256 del boot.wim, del ISO y del manifiesto del payload
```

> El orden del paso 3 **no es opcional**: está verificado que `WinPE-SecureStartup` depende de
> `WinPE-WMI`, y que `WinPE-PlatformID` requiere ambos. Instalarlos al revés falla.

### 9.3. Firma, integridad y arranque seguro

- **Arranque seguro:** se conserva la cadena de arranque **firmada por Microsoft**
  (`bootmgfw.efi`, `boot.wim`); Lozarus es carga útil dentro de la imagen, **no** un componente de
  arranque, así que no se reemplaza nada firmado. **Pendiente de verificar** en una VM con Secure
  Boot activo (es un criterio de aceptación de P0, §10).
- **No se pedirá desactivar el Arranque seguro.** Si una prueba lo exigiera, es señal de que el medio
  está mal construido.
- **Firma del payload:** firmar el ejecutable con Authenticode si hay certificado. Se documentará con
  honestidad que un certificado autofirmado **no aporta confianza a terceros**, solo detección de
  modificación frente a una copia conocida.
- **Autoverificación (paso R0):** al arrancar, Rescue recalcula los hashes de su payload contra el
  manifiesto y **muestra el resultado en pantalla**. Si no coincide, lo dice y pasa a modo
  degradado de solo lectura. Es el principio OBSIDIAN aplicado a la propia herramienta.
- **Cadena de confianza del medio:** el apartado 8 de Sentinel («Preparación y validación del USB»)
  guarda el hash del medio creado y permite **revalidarlo** más tarde para detectar manipulación.

### 9.4. Validación en máquinas virtuales

| Escenario | Qué valida | Cómo |
|---|---|---|
| VM UEFI Gen2 + **Secure Boot activo** | Que el medio arranca sin tocar la configuración de firmware | Hyper-V Gen2 |
| VM BIOS/heredada | Compatibilidad con equipos antiguos | Hyper-V Gen1 |
| Volumen NTFS sin cifrar | Inventario, lectura RO, hash, manifiesto | Disco de datos sintético |
| **Volumen con BitLocker bloqueado** | Detección + desbloqueo con clave de recuperación conocida | Cifrar una VM de laboratorio y **guardar la clave** |
| Arranque roto (BCD dañado) | Reparación de arranque y su reversión | Dañar el BCD en una instantánea desechable |
| `hiberfil.sys` presente (Inicio rápido) | Que se trata como artefacto, **no** como «memoria en vivo» (§4.4) | Hibernar la VM antes de apagarla |
| Destino FAT32 con fichero > 4 GB | Que el límite se detecta y se avisa **antes** de copiar | USB FAT32 sintético |
| RAM mínima (512 MB / 1 GB) | Arranque real y comportamiento del scratch space | Limitar la RAM de la VM |
| Varios discos y etiquetas iguales | Que **no** se confunde el volumen objetivo | VM con 3 discos parecidos |

**Reglas de laboratorio:** toda prueba destructiva, sobre **instantánea desechable**; nunca el primer
ensayo en un equipo real; cada escenario con criterio de paso escrito antes de ejecutarlo. Las
pruebas sobre hardware físico, solo tras pasar todas las de VM, y sobre un equipo de laboratorio.

---

## 10. Plan de implementación por fases y criterios de aceptación

Las fases 0–3 de este plan son de **Lozarus en su conjunto**; el documento `docs/00` §5.4 ya fijó la
prioridad: primero la base de confianza, después lo vistoso.

| Fase | Contenido | Criterios de aceptación (objetivos y comprobables) |
|---|---|---|
| **P0 · Prototipo mínimo de Rescue** *(lo siguiente a hacer en este frente)* | USB WinPE + *smoke test* de GUI + acceso RO a una instalación offline | 1. El medio arranca en VM UEFI **con Secure Boot activo**, sin cambiar el firmware.<br>2. Se ejecuta el *smoke test* (Pista A: ventana Qt con un botón; si falla en ≤3 días, Pista B: TUI).<br>3. Enumera discos/volúmenes e **identifica la instalación de Windows**.<br>4. Lee un fichero del volumen offline **en solo lectura** y calcula su SHA-256.<br>5. Escribe un manifiesto en un **destino elegido** y verifica el hash tras copiar.<br>6. Detecta y **declara** un volumen BitLocker bloqueado (sin desbloquearlo todavía).<br>7. Informe con el tamaño del WIM, la RAM mínima **medida** y las DLL que hubo que añadir. |
| **P1 · Sentinel: cerrar el lazo de telemetría** | Caja Negra + OBSIDIAN + integrar el bus con la GUI | Un evento ETW real llega a la GUI y se persiste. OBSIDIAN declara huecos y pérdidas (`None` ≠ `0`). La pantalla principal nunca dice «protegido» sin telemetría. |
| **P2 · Núcleo compartido extraído** | `evidence/`, `analysis/`, `reporting/`, `policies/` | Prueba AST que impide importar PySide6/psutil/pywin32/ctypes.windll en los paquetes compartidos. Todas sus pruebas pasan **sin** Windows. |
| **P3 · Rescue: triaje offline** | Hives, persistencia, artefactos, análisis estático de PE | Sobre una VM con persistencia **sembrada a propósito**, Rescue la encuentra y la clasifica con procedencia y nivel de confianza. Cero escrituras en el volumen objetivo (verificado por hash del volumen antes y después). |
| **P4 · Rescue: BitLocker + recuperación de archivos** | Desbloqueo guiado y rescate de datos del usuario | Desbloquea una VM cifrada con la clave de recuperación. Copia un árbol de ficheros al destino con hash verificado. Sin clave: se detiene con una explicación clara. La clave **no** aparece en ningún registro. |
| **P5 · Rescue: cuarentena y reparación** | Cuarentena reversible, sfc/DISM/BCD offline | Cuarentena restaurable desde su manifiesto. Reparación de arranque con respaldo de BCD y reversión probada. Toda acción irreversible, etiquetada y con confirmación reforzada. |
| **P6 · UX de incidente** | Asistente de emergencia en los dos entornos | Prueba con usuario: desde la pantalla principal hasta «evidencia preservada y verificada» en **≤ 5 pasos**, sin jerga, con el impacto de cada paso explicado antes de ejecutarlo. |
| **P7 · Apartado 8 de Sentinel** | Crear y validar el USB desde la GUI | Construye un medio y lo **revalida** por hash. Detecta un medio manipulado. |

**Criterio transversal de todas las fases:** ninguna función se declara terminada si no muestra
honestamente lo que **no** puede ver, y ninguna acción de escritura se declara terminada sin su
camino de reversión o su etiqueta explícita de irreversibilidad.

---

## 11. Decisiones pendientes (hay que resolverlas antes de construir)

| # | Decisión | Opciones | Recomendación | Cuándo |
|---|---|---|---|---|
| D1 | **GUI de Rescue** | Pista A (PySide6) / Pista B (TUI + HTML) | Puerta objetiva de 3 días en P0 (§6.5) | **P0, bloqueante** |
| D2 | **Distribución de Python en WinPE** | Embebido / PyInstaller `onedir` | Embebido: más control, sin autoextracción | P0 |
| D3 | **¿Reutilizar `modulos/` en Rescue?** | Incluir `WinPE-PowerShell` / reescribir con APIs / no reutilizar | No reutilizar en v1: están pensados para un sistema **en vivo** y dependen de PowerShell | P3 |
| D4 | **Base del medio** | WinPE / WinRE / Windows IoT | WinPE: es el soportado por el ADK para recuperación | P0 |
| D5 | **Licencia de redistribución del ADK/WinPE** | — | **Leer el EULA del ADK antes de distribuir el USB a terceros.** El uso de recuperación encaja, pero hay que confirmarlo por escrito | Antes de cualquier distribución |
| D6 | **Parser de registro offline** | `reg load` (nativo) / parser en Python puro | Python puro: no monta el hive en el WinPE y no lo modifica | P3 |
| D7 | **Certificado de firma de código** | Ninguno / autofirmado / OV-EV | Documentar el alcance real de cada opción; no exagerar el autofirmado | P7 |
| D8 | **Formato exigido al destino de evidencia** | Exigir NTFS/exFAT / permitir FAT32 troceando | Exigir NTFS/exFAT y avisar; trocear solo como último recurso | P0 |
| D9 | **`requirements.txt` del proyecto principal** | — | **Crearlo ya**: hoy PySide6/psutil/qtawesome/plyer están sin declarar, y el USB necesita versiones fijadas | Inmediato |
| D10 | **Servicio permanente de Windows** | Nunca / tras OBSIDIAN | Decidir solo con los datos de cobertura de OBSIDIAN (§7.4) | Después de P1 |

---

## 12. Fuentes

Documentación oficial consultada para los hechos de §6.1, §8.2 y §9:

- [Windows PE (WinPE) — introducción, requisitos y limitaciones](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-intro?view=windows-11) — reinicio automático (72 h / 240 h), pérdida de cambios, RAM mínima de 512 MB y disco RAM contiguo, límites FAT32 (4 GB / 32 GB), falta de soporte de `.MSI`/RDP/dominio/multiarquitectura, APIs Win32 y componentes opcionales, requisito de `WinPE-WMI` + `WinPE-SecureStartup`, y la limitación de uso a despliegue y recuperación.
- [WinPE: Add packages (Optional Components Reference)](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-add-packages--optional-components-reference?view=windows-11) — `WinPE-SecureStartup` (BitLocker/TPM) y su dependencia de `WinPE-WMI`; dependencias de `WinPE-PlatformID`; *scratch space* por defecto de 512 MB (32 MB con ≤1 GB de RAM) y valores válidos.
- [WinPE: Mount and Customize](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-mount-and-customize?view=windows-11) y [WinPE: Create bootable media](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-create-usb-bootable-drive?view=windows-11) — `copype`, montaje con DISM, `Set-ScratchSpace`, `MakeWinPEMedia`.
- [Download and install the ADK](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install) — WinPE como add-on independiente del ADK desde Windows 10 1809.

**Sin fuente que lo respalde:** no se encontró documentación oficial ni comunitaria sobre **PySide6/Qt
ejecutándose en WinPE**. Las dependencias de §6.2 (VC++ runtime, UCRT, `qwindows.dll`,
`opengl32sw.dll`) provienen de la documentación general de empaquetado de Qt en Windows y del
análisis de este repositorio, **no** de una validación en WinPE. Por eso D1 es una puerta de decisión
con prototipo y no una afirmación de diseño.

---

## 13. Alcance de esta fase

**Entregado:** este documento de diseño.

**No tocado (por indicación expresa):** la GUI (`gui_qt.py`, `gui.py` — retirado después, el
2026-10-21), el CLI (`auditor.py`), los
módulos de `modulos/`, `core/`, `collectors/` y el spike. **No** se ha construido ninguna imagen USB.

**Siguiente paso recomendado:** P0, el prototipo mínimo de Rescue, cuyo único fin es **resolver D1**
(¿funciona PySide6 en WinPE?) y demostrar lectura offline verificada. Hasta que P0 responda, cualquier
diseño visual de Rescue es especulativo.
