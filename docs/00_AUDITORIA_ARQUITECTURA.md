# LOZARUS EDR — Auditoría de Arquitectura (Entregable A)

> Documento de **diseño y viabilidad**, no de implementación. Separa hechos verificados de
> recomendaciones de diseño. Cubre: resumen ejecutivo, matriz de viabilidad de los 41 módulos,
> revisión de las decisiones problemáticas, veredicto de los 3 módulos nuevos y riesgos a resolver
> antes de desarrollar. Los entregables B–G (árbol de carpetas, contratos, IPC, flujo de Eclipse,
> pruebas y hoja de ruta) se abordan después, por partes.

Fecha: 2026-10-20 · Alcance: Windows 10/11 x64, host local, operación offline.

---

## 1. Resumen ejecutivo y valoración de la arquitectura

### 1.1. El límite que define todo el producto

Lozarus es, en la práctica, un **EDR/forense en modo usuario escrito en Python**. Esa decisión fija
el techo de lo que es honesto prometer:

- **Un EDR de usuario no es un EDR de kernel.** La telemetría "de grado EDR" (aperturas de handle a
  LSASS, inyecciones, callbacks de creación de procesos/hilos a prueba de manipulación) procede del
  proveedor ETW **Microsoft-Windows-Threat-Intelligence**, que está **restringido a procesos
  anti-malware protegidos (PPL/ELAM)**. Sin un driver anti-malware firmado por Microsoft, Lozarus
  **no puede** suscribirse a esa fuente. → *Hecho verificado.* Es el límite más importante del
  proyecto.
- **No puedes defenderte por completo de un administrador local comprometido.** Un admin puede
  matar tu servicio, descargar drivers, desactivar auditoría o borrar logs antes de que los leas.
  La "autodefensa" (módulo 38) es **mejor esfuerzo**, nunca garantía. El producto debe decirlo.
- **Mucha "detección" de bajo nivel desde usuario es heurística, no prueba.** Process hollowing,
  hooking, comparación disco/memoria: se infieren con señales parciales y fallan contra procesos
  protegidos (PPL, Credential Guard) o de mayor integridad. Hay que **etiquetarlas como heurísticas**
  con nivel de confianza, nunca como veredictos.

**Conclusión de arquitectura:** Lozarus debe posicionarse como **asistente de observabilidad,
endurecimiento reversible y forense de solo lectura**, con una capa fina de respuesta local
autorizada — no como un EDR que "protege totalmente". Esa honestidad no es una debilidad: es
exactamente lo que distingue una herramienta auditable de una caja de humo.

### 1.2. Pilares arquitectónicos recomendados

1. **Núcleo dirigido por eventos.** Sensores → *Evento normalizado* → bus → correlación/scoring →
   hallazgos → (opcional) respuesta. SQLite como almacén de eventos/metadatos; nada de lógica de
   seguridad en la GUI.
2. **La GUI nunca toca el sistema peligroso directamente.** Toda acción elevada pasa por el núcleo
   y, si requiere privilegios, por un **servicio auxiliar** con interfaz mínima vía Named Pipe con
   ACL. (Hoy `gui_qt.py` llama a PowerShell directamente —igual que `gui.py`, retirado el
   2026-10-21—: aceptable para un prototipo, **no** para el producto.)
3. **Todo lo que modifica el sistema es reversible y auditado.** `plan() → validate() → apply() →
   verify() → rollback()`. Si algo no es técnicamente reversible, se marca como irreversible y pide
   confirmación reforzada (ya hay precedente: *hold-to-execute* + palabra clave).
4. **Primero solo lectura.** Las fases forenses y de telemetría arrancan en modo observación. La
   respuesta activa llega al final, acotada y simulable.
5. **Offline con versiones.** Firmas, blocklists de drivers, reglas y perfiles se **aprovisionan**
   empaquetados y versionados (p. ej. `policies/driver_blocklist/2026.10.json`), con fecha y hash.
   La UI debe mostrar la antigüedad de cada conjunto ("blocklist: 47 días") para no dar falsa
   sensación de cobertura.
6. **Observabilidad de la propia observabilidad (OBSIDIAN).** Si una fuente cae o pierde eventos, el
   producto lo dice; nunca afirma "limpio" sobre una ventana ciega.

### 1.3. Veredicto global

Arquitectura **ambiciosa y, en su mayoría, viable** si se aceptan los límites anteriores y se
**rediseñan o excluyen** ~6 funciones de engaño/evasión que no aportan valor defensivo o que solo
tienen sentido en laboratorio aislado. El riesgo principal del proyecto no es técnico sino de
**alcance**: 41 módulos es un producto de años. La matriz de abajo prioriza para que la base de
confianza (telemetría, evidencia, privilegios) se construya antes que las funciones vistosas.

---

## 2. Matriz de viabilidad de los 41 módulos

Clasificación:
- **P** — Viable directamente en Python.
- **W** — Viable con APIs de Windows (ctypes / pywin32 / WMI / DeviceIoControl).
- **S** — Necesita un servicio auxiliar privilegiado.
- **N** — Requiere un componente nativo especializado (driver / ELAM / proveedor protegido).
- **E** — Experimental, con limitaciones importantes.
- **X** — Rediseñar o excluir del producto.

Prioridad: **1** (base de confianza) … **5** (opcional/experimental).

| # | Módulo | Clase | Privilegios | Prioridad | Nota clave (límite real) |
|---|--------|:----:|:----:|:----:|--------|
| 1 | Medidores CPU/RAM | P | usuario | 1 | Hecho (psutil + QTimer). |
| 2 | Bento Cards | P | usuario | 1 | Hecho. |
| 3 | Protocolo Cero (captura evidencia/IR) | W | admin parcial | 1 | Snapshot volátil read-only; hashing + manifiesto. Ya existe base (`_forense`). |
| 4 | Motor de Persistencia (config cifrada) | P | usuario | 1 | DPAPI (`win32crypt.CryptProtectData`) atado al usuario/equipo. No es secreto frente a ese mismo usuario. |
| 5 | Guillotina de Contexto (perfiles) | W/S | admin | 3 | Conmutar ajustes reversibles; guardar estado previo. Evitar "perfiles" que rompan servicios críticos. |
| 6 | Caja Negra (búfer circular telemetría) | P/W | usuario/admin | 2 | psutil + ETW consumido; ventana limitada por RAM; marcar huecos. |
| 7 | Eclipse Engine (respuesta) | S | admin (vía servicio) | 4 | Orquestación; acciones peligrosas delegadas y simulables. |
| 8 | Matriz de desinfección/hardening | W/S | admin | 2 | Registro/servicios reversibles con restauración. Base: el actual kit. |
| 9 | **Debloat Trampa (señuelos de servicios)** | **X→E** | admin | 4 | **Rediseñar**: no sustituir servicios reales por falsos. Ver §3.1. |
| 10 | Reparación del sistema | W | admin | 3 | Envoltura de `sfc`, `DISM`, `netsh`; nunca ocultar fallos. |
| 11 | Congelador de Persistencia (Run/Tareas) | W | usuario/admin | 2 | Línea base + diff de autoruns. Ya prototipado (`11_persistencia`). |
| 12 | Blindaje de Sombras (VSS) | W/E | admin | 3 | Puedes **detectar** `vssadmin delete shadows` (ETW/4688/4104), no **impedirlo** ante admin. |
| 13 | Cortafuegos de Intención Humana | E | usuario | 4 | Correlación heurística salida↔sesión; alto FP; solo alerta, nunca bloqueo automático. |
| 14 | Honeypots de credenciales sintéticas | W/E | admin | 4 | Honeytokens; en host aislado la detección de *uso* es limitada (sin telemetría de dominio). |
| 15 | Poisoned Handles (archivos señuelo) | W | admin (SACL) | 2 | Canary files + auditoría SACL → Evento 4663. Base: honeypot actual. **Solo detecta/avisa.** |
| 16 | Detección/contención de exfiltración | E | admin | 4 | Heurística de volumen/destino + bloqueo por regla de firewall autorizada. |
| 17 | **Shell Spoofing (señuelo aislado)** | **X→E** | — | 5 | **Solo laboratorio aislado**, nunca en el host. Ver §3.2. |
| 18 | **Tarpitting (labs)** | **E** | admin | 5 | Solo en entorno controlado/autorizado. Fuera del host productivo. |
| 19 | **Red de Espejismos (red virtual)** | **E/N** | admin | 5 | Requiere virtualización; alcance de laboratorio. |
| 20 | Protección webcam/micrófono | W | usuario/admin | 3 | Detectar uso vía *Consent Store* del Registro; "proteger" = conmutar privacidad del SO. |
| 21 | Phantom Map (disco vs memoria) | W/E | admin | 4 | Comparar secciones mapeadas; **falla en procesos protegidos**; heurístico. Ver §3.3. |
| 22 | Cámara de Asfixia (Job Objects) | W | admin | 3 | `CreateJobObject`+límites CPU/mem; asignar proceso ajeno tiene requisitos (breakaway/anidamiento). |
| 23 | **Process Hollowing detection** | **E** | admin | 4 | Heurística de usuario (imagen vs secciones, RWX, entropía). Sin proveedor Threat-Intel = sin prueba. |
| 24 | Time-Dilation (throttling) | W | admin | 4 | Job Objects (CPU rate). Nunca aplicar a procesos críticos del SO. |
| 25 | Integridad de módulos / hooking | E/N | admin | 4 | IAT/inline hooks solo en procesos accesibles; cobertura parcial. |
| 26 | Telemetría de excepciones/bajo nivel | N/E | admin | 4 | ETW kernel/Threat-Intel; lo profundo exige driver AM. |
| 27 | Escudo Anti-BYOVD | W(+config) | admin | 2 | **Auditar** drivers (hash/firma) vs blocklist provisionada. **Aplicar** = WDAC/HVCI (política), no Python. Ver §3.4. |
| 28 | Protección de LSASS | W(+N) | admin | 2 | **Verificar/recomendar** RunAsPPL y Credential Guard (VBS/HVCI). **Detectar** accesos = Threat-Intel ETW = N. |
| 29 | Inventario/control USB-HID | W | admin | 2 | SetupAPI/WMI; bloqueo `USBSTOR`/políticas de instalación. Base: el killswitch actual. |
| 30 | **Patrones de interacción (biometría)** | **X→E** | usuario | 5 | **Excluir por defecto**: biometría de pulsaciones es invasiva y de valor dudoso. Ver §3.5. |
| 31 | Radar Wi-Fi (Evil Twin) | E/N | admin | 5 | Requiere Npcap + adaptador en **modo monitor** (raro en Windows). Experimental/hardware. |
| 32 | Contención de conexiones | W/S | admin | 3 | Reglas de firewall (ya) o WFP nativo para granularidad por flujo. |
| 33 | **Hardware Sub-GHz/NFC** | **E/X** | — | 5 | Fuera del núcleo de un EDR de software; módulo opcional condicionado a hardware. |
| 34 | Mirror Lab (Sandbox/Hyper-V diff) | W/E | admin | 4 | Windows Sandbox `.wsb` (ya) o Hyper-V (requiere rol). Diff reproducible. |
| 35 | Mesa de Autopsias (PE estático) | P | usuario | 2 | `pefile`/`lief` en solo lectura; sandbox de parsing. |
| 36 | **Identidad seudónima / HW-ID** | **P / X** | — | 4 | Gestión de identidad de prueba: **P**. Falsificación de IDs de hardware: **excluir**. Ver §3.6. |
| 37 | Saneamiento NIST 800-88 + portapapeles | W/E | usuario/admin | 3 | Borrado de ficheros/espacio libre: viable. Purga total: destructivo, con guardas. SSD ≠ garantía (ver §3.7). |
| 38 | Autodefensa de Lozarus | S/E | admin | 2 | Named Pipes+ACL, `SetProcessMitigationPolicy`. PPL real = solo con firma AM (N). **Mejor esfuerzo.** |
| 39 | **OBSIDIAN** (integridad de telemetría) | W/E | admin parcial | 1 | Salud ETW, pérdidas de eventos cuando la fuente las reporta, estado de auditoría. Ver §4.1. |
| 40 | **IRONCLAD** (confianza arranque/drivers) | W | admin | 2 | SecureBoot/VBS/HVCI (WMI) + inventario drivers + CodeIntegrity + WDAC auditoría. Ver §4.2. |
| 41 | **CHRONOS** (cronología forense NTFS) | W | admin/backup | 2 | USN Journal, $MFT, Prefetch, Amcache, logs. **Solo lectura**, correlación con procedencia. Ver §4.3. |

**Reparto:** P/W (viable ya o con APIs): la mayoría de la base forense y de telemetría. S (servicio
privilegiado): respuesta y endurecimiento. N (nativo/driver): la telemetría a prueba de manipulación
y la protección PPL — **asúmelas como no disponibles en v1**. X/E a rediseñar o acotar: 9, 17, 18,
19, 30, 33, 36(parte).

---

## 3. Revisión técnica de las decisiones problemáticas

### 3.1. Módulo 9 — "Debloat Trampa" (señuelos de servicios) → rediseñar
**Problema.** Sustituir servicios reales de Windows por "señuelos" rompe dependencias, Windows Update
y la recuperación, y es indistinguible de malware que secuestra servicios. Alto riesgo de dejar el
equipo inarrancable.
**Alternativa segura (conserva la finalidad).** "Debloat" clásico y **reversible**: detener/deshabilitar
servicios de telemetría/bloatware guardando el `StartType` previo (ya lo hace el kit), con restauración
de un clic y lista blanca de servicios críticos que nunca se tocan. El "engaño" útil aquí no es falsear
servicios: es **vigilar** si algo reactiva lo que desactivaste (señal de persistencia).

### 3.2. Módulos 17–19 — Shell Spoofing, Tarpitting, Red de Espejismos → solo laboratorio
**Problema.** Un *shell señuelo*, el *tarpitting* y las redes de espejismo son técnicas de **engagement**
(engañar activamente a un intruso). En un host productivo introducen superficie de ataque, pueden
atrapar tráfico legítimo y su valor defensivo real es bajo frente al coste.
**Alternativa segura.** Mantenerlas **exclusivamente** dentro del Mirror Lab (módulo 34), en VM/Sandbox
desechable y claramente etiquetado como entorno autorizado. Fuera del laboratorio: excluir. La detección
inocua (canary files, módulo 15) cubre el 90 % del valor sin el riesgo.

### 3.3. Módulo 21 — Phantom Map (disco vs memoria)
**Límite real.** Comparar la imagen de un ejecutable en disco con sus secciones en memoria exige
`PROCESS_VM_READ`. **Falla** contra procesos PPL (LSASS con RunAsPPL, antimalware) y da acceso parcial
a procesos de mayor integridad. Lo que detectas son **anomalías** (regiones RWX, imágenes sin fichero
de respaldo, discrepancias de encabezado PE), no una prueba de inyección.
**Diseño.** Enuméralo como heurística con *confidence*; lista explícitamente los PIDs **no inspeccionables**
(para no dar por "limpio" lo que no pudiste ver — principio OBSIDIAN).

### 3.4. Módulo 27 — Anti-BYOVD
**Hecho.** Python puede **inventariar** drivers cargados (`EnumDeviceDrivers`, WMI `Win32_SystemDriver`),
hashear y comparar su firma/procedencia contra una **blocklist provisionada** (p. ej. la *Microsoft
Vulnerable Driver Blocklist* / dataset tipo LOLDrivers, versionado offline). **La aplicación** (impedir
que se cargue un driver vulnerable) **no es de Python**: es **WDAC/App Control for Business + HVCI**
(política de bloqueo de drivers). → *Separar claramente: auditoría (Lozarus) vs enforcement (política del
SO).* Modo auditoría antes de endurecer.

### 3.5. Módulo 30 — Patrones de interacción (biometría de pulsaciones) → excluir por defecto
**Problema.** Perfilar la cadencia de tecleo/ratón es **biometría conductual**: invasivo, con sesgos, y
de valor defensivo marginal en un producto local. Riesgo de privacidad y de percibirse como keylogger.
**Alternativa.** Excluir del producto base. Si se quiere "actividad de sesión" para correlación (módulo
13), basta con señales no biométricas: bloqueo/desbloqueo, inactividad, sesión interactiva vs servicio —
sin registrar pulsaciones.

### 3.6. Módulo 36 — Identidad seudónima / falsificación de HW-ID → dividir
**Dividir en dos.** (a) *Gestión de identidad seudónima para pruebas* (etiquetas, inventario de activos
de laboratorio): **viable y útil**. (b) *Falsificar identificadores de hardware* (seriales, MAC, SMBIOS):
**excluir**. No es defensivo — es evasión; rompe licenciamiento, inventario y la propia integridad de la
telemetría de Lozarus. Tú mismo lo marcas para evaluar: el veredicto es excluirlo del producto defensivo.

### 3.7. Módulo 37 — Saneamiento NIST 800-88
**Matices honestos.** El borrado por sobrescritura garantiza el *clear/purge* en **HDD**. En **SSD/NVMe**,
la nivelación de desgaste y el sobreaprovisionamiento hacen que la sobrescritura por software **no**
garantice la destrucción; el método correcto es el **comando de sanitización del propio dispositivo**
(ATA Secure Erase / NVMe Sanitize), que no siempre está expuesto. → La UI debe decir qué garantía real
ofrece según el medio, y no prometer "borrado irrecuperable" en SSD. Portapapeles: trivial y seguro.

### 3.8. Módulo 38 — Autodefensa
**Realismo.** Puedes subir el coste de manipular Lozarus: Named Pipes con ACL restrictiva, validación de
cliente, `SetProcessMitigationPolicy` (CIG/ACG/bloqueo de binarios no firmados), verificación de
integridad de los propios binarios. **No** puedes convertirte en PPL sin firma anti-malware de Microsoft,
ni sobrevivir a un admin decidido. Diséñalo como **resiliencia y detección de manipulación**, no como
invulnerabilidad.

---

## 4. Veredicto de viabilidad de OBSIDIAN, IRONCLAD y CHRONOS

*(Diseño detallado con contratos: Entregable siguiente. Aquí, viabilidad y enfoque.)*

### 4.1. OBSIDIAN — Integridad de la telemetría (clase W/E, prioridad 1)
**Qué es fiable.** Estado de las sesiones ETW que **tú** controlas (propiedades de la sesión, buffers,
`EventsLost`/`BuffersLost` que el runtime de ETW sí reporta por sesión); estado de las políticas de
auditoría (`auditpol /get`), canales de Event Log habilitados y su tamaño/antigüedad; detección de
**huecos temporales** por discontinuidad de marcas monotónicas/secuencias.
**Qué NO afirmar.** Que "no pasó nada" en una ventana sin cobertura. OBSIDIAN produce **indicadores de
cobertura** (fuentes activas, % de huecos, pérdidas) y un registro auditable de caídas/recuperaciones.
Es, correctamente, el módulo que impide que el resto del producto mienta. **Prioridad máxima.**

### 4.2. IRONCLAD — Grafo de confianza de arranque/drivers (clase W, prioridad 2)
**Fiable en Python/APIs.** SecureBoot (`Confirm-SecureBootUEFI` / Registro `UEFISecureBootEnabled`,
admin), VBS/HVCI (`Win32_DeviceGuard` por WMI: `SecurityServicesConfigured/Running`,
`VirtualizationBasedSecurityStatus`), inventario de drivers con hash+firma, eventos de **Code Integrity**
(`Microsoft-Windows-CodeIntegrity/Operational`), y evaluación de reglas **WDAC** en modo auditoría.
**Límite.** Correlacionar "carga de driver ↔ validación" a prueba de manipulación es más robusto con el
proveedor protegido; desde usuario es un grafo **observacional**. Útil igualmente para postura y BYOVD.
**No propongas un driver propio:** las interfaces documentadas (WMI DeviceGuard, CI log, WDAC) cubren el
inventario y la política.

### 4.3. CHRONOS — Cronología forense diferencial NTFS (clase W, prioridad 2)
**Fiable y de alto valor, en SOLO LECTURA.** USN Change Journal (`FSCTL_QUERY_USN_JOURNAL` /
`FSCTL_ENUM_USN_DATA` por `DeviceIoControl` sobre `\\.\C:`, requiere admin/`SeBackupPrivilege`); parseo
de `$MFT`/`$J` por lectura cruda del volumen; Prefetch (`.pf`), Amcache (`Amcache.hve`, hive offline),
Event Logs y la Caja Negra. Normalización de marcas (UTC + monotónica).
**Reglas de rigor (tú las pides, son correctas).** Detectar **lagunas** y posibles **reinicios del
journal**; **no atribuir** un cambio de fichero a un proceso solo por cercanía temporal — distinguir
*observación* / *inferencia* / *conclusión*; exportar cronología reproducible con **procedencia** de cada
dato; proteger la evidencia original (trabajar sobre copia + hash). Arranca read-only: es el mejor primer
desarrollo forense serio.

---

## 5. Riesgos técnicos y decisiones a resolver ANTES de desarrollar

1. **¿Habrá componente nativo/driver?** Si **no** (recomendado para v1), hay que aceptar por escrito que
   Threat-Intelligence ETW, PPL real y la telemetría a prueba de manipulación **quedan fuera**, y ajustar
   las promesas de la UI. Si **sí**, es un proyecto distinto (firma, WHQL/EV, mantenimiento de un driver)
   y debe decidirse ya, no a mitad.
2. **Consumo de ETW en Python.** No hay un estándar perfecto; evalúa una vía (p. ej. envoltura de TDH vía
   ctypes o una librería madura) **con un prototipo** antes de comprometer el diseño de los `collectors/`.
   Es el primer *spike* obligatorio.
3. **Modelo de privilegios.** Definir la frontera GUI(usuario) ↔ servicio(admin) y el contrato IPC
   **antes** de escribir respuestas. Un token efímero no autoriza por sí solo (lo dices, y es correcto).
4. **Alcance.** 41 módulos no caben en v1. Propuesta: v1 = base de confianza (OBSIDIAN, Caja Negra,
   CHRONOS read-only, IRONCLAD auditoría, hardening reversible, honeypot de detección). El engaño activo
   y la respuesta automática, mucho más tarde y acotados.
5. **Exclusiones firmes** (recomendadas): 9 (como señuelo de servicios), 17/18/19 fuera del lab, 30
   (biometría), 36b (HW-ID spoofing), 33 como opcional. Confírmalas para cerrar el perímetro ético/técnico.
6. **Falsos positivos.** Cada heurística (13, 21, 23, 25) necesita una métrica de FP objetivo y un modo
   "solo observación" prolongado antes de habilitar cualquier respuesta.

---

## Próximos entregables (a petición)

- **B** — Árbol de carpetas definitivo y responsabilidades (ui/core/collectors/detection/response/
  forensics/deception/windows/service/storage/reporting/policies/native/tests/deployment/docs).
- **C** — Contratos y modelos de evento (Evento normalizado, Hallazgo, Evidencia, Acción, Resultado,
  Salud de sensor, Política) + reglas de orden/duplicados/incertidumbre, y las interfaces
  `plan/validate/apply/verify/rollback`.
- **D** — Servicio privilegiado e IPC (Named Pipes + ACL, autorización por operación, validación de
  argumentos, auditoría).
- **E** — Flujo de respuesta de Eclipse Engine (simulación / asistida / automática restringida).
- **F** — Plan de pruebas y métricas de aceptación.
- **G** — Hoja de ruta por fases con criterios de paso.

Dime por cuál seguimos (recomiendo **B** y luego **C**).

---

## Anexo — Redundancias a unificar

> Incorporado desde el borrador previo de este mismo entregable (`docs/LOZARUS_EDR_AUDITORIA.md`,
> retirado en la limpieza de release del 2026-10-21). Era la única sección de aquel borrador sin
> equivalente en este documento.

- **6 (resource limiting implícito) / 22 (Cámara de Asfixia) / 24 (Time-Dilation)** → un único
  **motor de contención de recursos** sobre Job Objects (memoria + CPU rate + suspensión), con una
  sola política y una sola lista de protegidos.
- **11 (Congelador de Persistencia) / 12 (Blindaje de Sombras) / parte de 8** → un único
  **vigilante de persistencia e integridad** (registro + tareas + servicios + VSS) que emite
  hallazgos normalizados, en vez de tres monitores separados.
- **13 (Intención Humana) / 16 (exfiltración) / 32 (contención)** → comparten el mismo pipeline
  red↔proceso↔política; unificar en un **motor de red** con detección + acción por política.
