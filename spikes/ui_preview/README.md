# LOZARUS · BETA VISUAL

Primera versión navegable de la interfaz de Lozarus. Es un **prototipo de exploración visual**,
aislado en `spikes/`, pensado para ver todo el alcance del proyecto en una sola ventana y decidir
qué queremos cambiar. **No es el diseño definitivo y no es producción.**

---

## Cómo abrirla

Desde la raíz del proyecto (`C:\Users\Voltio\Documents\AuditorTool`):

```bash
python spikes/ui_preview/app.py
```

No hace falta Administrador, ni conexión a Internet, ni instalar nada nuevo.

### Dependencias

Ya están todas instaladas en este equipo (verificado): **PySide6 6.12.0**, **qtawesome 1.4.2**,
**psutil 7.2.2**, Python 3.13.15.

La beta **degrada con elegancia**: sin `qtawesome` pierde los iconos y sin `psutil` muestra «—» en
las métricas, pero sigue abriéndose y siendo navegable. Solo PySide6 es imprescindible.

---

## Qué NO hace (por diseño)

Es un prototipo visual, así que se le han puesto límites estrictos:

- **No abre sesiones ETW** ni ejecuta ninguna operación privilegiada.
- **No termina procesos, no borra archivos, no toca el Registro ni el cortafuegos.**
- **No ejecuta los módulos de auditoría** de `modulos/`.
- **No guarda configuración** en disco ni escribe nada fuera de la propia ventana.
- **No construye imágenes USB** ni repara ningún Windows.

Todo botón de acción pasa por `BetaContext.act()`, que **solo registra** lo que haría una versión
conectada y lo anota en la consola inferior.

### Lo único real que verás

CPU, RAM y número de procesos **de este equipo**, leídos con `psutil`. Nada más. Todo lo demás
(incidentes, procesos sospechosos, conexiones, cronologías, señuelos) está marcado con una etiqueta
violeta **«DATO DE DEMOSTRACIÓN»**.

---

## Qué puedes recorrer

| # | Sección | Qué encontrarás |
|---|---|---|
| 1 | **Cuartel general** | Estado general, CPU/RAM reales, telemetría, incidentes, accesos a todas las áreas y el botón de vigilancia demostrativa. |
| 2 | **Centinela** | La cadena real de telemetría (colector ETW → bus → Caja Negra → OBSIDIAN), el estado de los sensores y cómo se cuentan las pérdidas. |
| 3 | **Analizar equipo** | Árbol de procesos, conexiones, archivos y persistencia, más los 13 módulos de auditoría reales con sus comprobaciones. |
| 4 | **Defensa y contención** | Incidentes, cronología y respuestas ordenadas por impacto, con su reversibilidad siempre declarada. |
| 5 | **Campo de señuelos** | Inventario de cebos, cómo funcionan, sus límites y las tres técnicas de engaño activo descartadas. |
| 6 | **Memoria** | Phantom Map, módulos inyectados y, sobre todo, la tabla de lo que **no se pudo inspeccionar**. |
| 7 | **Perímetro** | Red, conexiones, dispositivos USB y periféricos sensibles. |
| 8 | **Laboratorio forense** | OBSIDIAN, CHRONOS, IRONCLAD, la Caja Negra, cronologías, análisis PE y política de evidencia. |
| 9 | **Rescue USB** | El entorno arrancable: flujo de 9 pasos, límites reales y restricciones verificadas de WinPE. |
| 10 | **Ajustes** | Entorno, dependencias, deuda detectada, estado global del proyecto y registro de sesión. |
| + | **Catálogo** | Las 41 capacidades + 6 piezas de infraestructura, con filtros y ficha completa. |

### Atajos de teclado

| Atajo | Acción |
|---|---|
| `Ctrl+1` … `Ctrl+9` | Saltar a las secciones 1 a 9 |
| `Ctrl+0` | Ajustes |
| `Ctrl+L` | Catálogo |
| `Ctrl+D` | Activar/detener el modo demostración |
| `Esc` | Volver al Cuartel general |

También hay un botón **«Cuartel general»** arriba a la derecha en todas las secciones.

---

## Cambio de navegación respecto a lo propuesto

La propuesta tenía 10 secciones. Se ha añadido **una undécima: «Catálogo»**, en un grupo aparte de
la barra lateral llamado `EXPLORAR`.

**Por qué:** el catálogo de las 41 capacidades con filtros, lista y ficha de detalle es una
herramienta de exploración por sí misma y no cabía dentro de «Ajustes y auditoría» sin ahogar las dos
cosas. Se ha dejado visualmente separado para que quede claro que es un añadido y no una de las diez
áreas funcionales del producto.

El resto de la navegación respeta el orden propuesto. Algunas etiquetas de la barra lateral usan un
nombre corto (`NAV_LABEL`) para que no se corten: «Perímetro», «Memoria», «Ajustes», «Catálogo».

---

## Estructura del código

```
spikes/ui_preview/
├─ app.py              Ventana principal: barra de título, lateral, pilas de secciones y consola.
├─ theme.py            Identidad visual: paleta, los 7 estados, iconos y la hoja de estilo (QSS).
├─ runtime.py          Contexto compartido: modo demostración, registro y lectura real de CPU/RAM.
├─ widgets.py          Componentes reutilizables (tarjetas, medidores, cronologías, diagramas…).
├─ catalog.py          DATOS: las 41 capacidades + infraestructura, con su estado verificado.
├─ demodata.py         DATOS: todo lo simulado, en un único archivo claramente marcado.
├─ smoke_test.py       Validación automática sin pantalla.
└─ sections/
   ├─ base.py          Clase base: cabecera, botón de vuelta y área con scroll.
   ├─ _shared.py       Tablas, avisos y cabeceras de demostración.
   └─ hq.py · sentinel.py · analyze.py · defense.py · decoys.py · memory.py
      perimeter.py · forensics.py · rescue.py · settings.py · catalog_view.py
```

Para cambiar los colores, toca **solo** `theme.py`. Para cambiar los datos simulados, **solo**
`demodata.py`. Para cambiar un estado del catálogo, **solo** `catalog.py`.

---

## Validación

```bash
# Recorre las 11 secciones en los 2 modos y comprueba que nada falla (sin abrir ventana):
python spikes/ui_preview/smoke_test.py

# Lo mismo, pero además guarda un PNG de cada sección y modo:
python spikes/ui_preview/smoke_test.py --render capturas

# Lint:
python -m pyflakes spikes/ui_preview/*.py spikes/ui_preview/sections/*.py
```

El `smoke_test` usa el backend gráfico `offscreen`, así que funciona sin pantalla. Además de recorrer
las secciones, abre las 47 fichas del catálogo y ejercita todos los filtros.

---

## Lo que NO se ha tocado

Este prototipo está aislado a propósito. **No se ha modificado nada** de:

`gui_qt.py` · `gui.py` (retirado después, el 2026-10-21) · `auditor.py` · `modulos/` · `core/` · `collectors/` · `tests/` ·
`spikes/etw/` · `docs/`

La interfaz de producción (`python gui_qt.py`) sigue funcionando exactamente igual que antes.
