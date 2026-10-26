# Informe de la beta visual

Fecha: 2026-10-20 · Prototipo: `spikes/ui_preview/` · Estado: **primera versión navegable**

---

## 1. Qué se ha implementado

| Entregable pedido | Estado | Dónde |
|---|---|---|
| Ventana principal | ✅ | `app.py` — sin marco, barra de título propia, redimensionable |
| Barra lateral | ✅ | 10 áreas + grupo `EXPLORAR` con el catálogo |
| Identidad visual inicial | ✅ | `theme.py` — carbón + azul eléctrico + cian |
| Diez áreas navegables | ✅ | `sections/` — las 10 propuestas, todas con contenido |
| Cuartel general desarrollado | ✅ | `sections/hq.py` — la pantalla más trabajada |
| Catálogo de módulos | ✅ | `sections/catalog_view.py` — 41 + 6, filtros y ficha |
| Datos demostrativos identificados | ✅ | `demodata.py` + etiqueta violeta `DemoBadge` |
| Fichas explicativas | ✅ | 9 campos por capacidad, más diálogos en cada sección |
| README de ejecución | ✅ | `README.md` |
| Informe | ✅ | este archivo |

### Comportamiento exigido

| Requisito | Estado |
|---|---|
| Navegación entre todas las secciones | ✅ 11 secciones, barra lateral + atajos `Ctrl+1..9/0/L` |
| Selección y detalle de módulos | ✅ clic en cualquier fila abre su ficha completa |
| Filtros por estado y categoría | ✅ 7 estados + 9 áreas + búsqueda por texto + alternar infraestructura |
| Diálogos explicativos | ✅ 8 diálogos, uno por concepto difícil |
| Tarjetas interactivas | ✅ accesos del Cuartel general y filas del catálogo |
| Modo demostración con datos marcados | ✅ `Ctrl+D`; cambia estado general, incidentes, series y sensores |
| Registro visual de interacciones | ✅ consola inferior, siempre visible |
| Mensajes cuando algo no está disponible | ✅ «—» para dato desconocido; avisos por sección |
| Botón para volver al Cuartel general | ✅ en la cabecera de las 10 secciones + `Esc` |
| Ningún control que parezca funcional y no haga nada | ✅ todo botón registra en consola y/o abre un diálogo |

---

## 2. Decisiones de diseño que conviene revisar juntos

1. **El estado general nunca dice «protegido».** Con los sensores parados muestra `SIN VIGILANCIA`,
   y en demostración `DEMOSTRACIÓN EN CURSO`. Es deliberado: declarar «protegido» sin telemetría
   sería justo lo que el producto quiere evitar.
2. **Siete estados, nunca solo color.** Cada estado lleva color + icono + código de texto
   (`PROBADO`, `PARCIAL`, `PROTOTIPO`, `DISEÑADO`, `VALIDAR`, `DEMO`, `REDISEÑO`).
3. **Violeta = demostración, siempre.** Ese color no significa ninguna otra cosa en toda la interfaz.
4. **Las pérdidas se muestran separadas** (origen ETW vs. bus interno) y nunca sumadas, como en
   `core/contracts.py`.
5. **El catálogo tiene sitio propio** en la barra lateral (ver README, «Cambio de navegación»).
6. **Las acciones declaran impacto y reversibilidad antes de ejecutarse**, y lo irreversible va
   último y marcado aparte.

---

## 3. Lo que el catálogo revela sobre el proyecto

Estados verificados leyendo el repositorio, no estimados:

| | Los 41 módulos | Infraestructura (6) |
|---|---|---|
| Implementado y probado | **0** | **4** |
| Implementado parcialmente | 12 | 0 |
| Prototipo probado | 0 | 1 |
| Diseñado, pendiente | 15 | 0 |
| Pendiente de validación técnica | 8 | 1 |
| Rediseño pendiente | 6 | 0 |

**Conclusión honesta:** ninguno de los 41 módulos tiene pruebas automáticas todavía. Lo único
probado son `core/events.py` (12), `core/contracts.py` (9), `core/bus.py` (8) y
`collectors/etw_collector.py` (13) — **42 pruebas en total** — más el prototipo ETW (8 + integración).

---

## 4. Validación realizada

| Comprobación | Resultado |
|---|---|
| Importar las dependencias | **OK** — PySide6 6.12.0, qtawesome 1.4.2, psutil 7.2.2 |
| La aplicación arranca | **OK** — la ventana se construye sin errores |
| Las 11 secciones se abren | **OK** — recorridas en los 2 modos |
| Cambiar de panel sin errores | **OK** — 22 transiciones, ninguna excepción |
| Modo demostración | **OK** — activado y detenido, propagado a todas las secciones |
| Fichas del catálogo | **OK** — 47 abiertas sin error |
| Filtros del catálogo | **OK** — 8 estados, áreas y búsqueda ejercitados |
| Lint (`pyflakes`) | **limpio** |
| Backend y GUI de producción sin modificar | **OK** — ver §6 |

Reproducible con:

```bash
python spikes/ui_preview/smoke_test.py --render capturas
```

### Cómo se ha validado visualmente

Con el backend `offscreen` se ha renderizado **cada sección a PNG** y se han revisado las imágenes.
Gracias a eso se detectaron y corrigieron cuatro defectos reales:

1. Textos de la barra lateral cortados → se añadieron nombres cortos y se ensanchó el panel a 274 px.
2. Etiquetas de las barras de reparto cortadas → ahora ajustan de línea.
3. **La ficha del catálogo se superponía con el texto anterior** → `deleteLater()` no basta: hay que
   desvincular del padre en el momento (`setParent(None)`). Corregido en `widgets.clear_layout()`.
4. Las etiquetas de estado de la lista se recortaban → se simplificó la fila.

---

## 5. Limitaciones conocidas y pendientes

### No verificado

- **Tipografía en pantalla real.** Las capturas se hicieron con el renderizador `offscreen`, que no
  resuelve «Segoe UI» y sustituye por una fuente que parte los acentos (`CONTENCIÓ N`) y lo pinta
  todo en mayúsculas. **Creo que es un artefacto del renderizador sin pantalla, no de la interfaz,
  pero no lo puedo confirmar sin verla en tu monitor.** Es lo primero que conviene mirar al abrirla.
- **Contraste medido.** La paleta se ha elegido a ojo; falta comprobar que cumple 4.5:1.
- **Comportamiento al redimensionar** a tamaños muy pequeños o en pantallas de alta densidad.

### Pendiente para iteraciones siguientes

- Animaciones: solo hay un realce de opacidad al pasar el ratón. Faltan transiciones entre secciones.
- Las secciones 3 a 7 están menos trabajadas que el Cuartel general, el Centinela y el Catálogo.
- No hay estado persistente: al cerrar se pierde el modo demostración y el registro.
- El árbol de procesos no permite ordenar ni filtrar.
- Falta una vista de comparación Sentinel ↔ Rescue más visual (hoy es una tabla).

### Fuera de alcance deliberadamente

Conectar la telemetría real, ejecutar auditorías, construir el USB. Cuando se conecte algo, será un
**modo explícito y separado** del demostrativo, nunca implícito por abrir la ventana.

---

## 6. Aislamiento: lo que no se ha tocado

Verificado: **no se ha modificado ningún archivo fuera de `spikes/ui_preview/`.**

`gui_qt.py` · `gui.py` (retirado después, el 2026-10-21) · `auditor.py` · `modulos/` (24 archivos) · `core/` · `collectors/` ·
`tests/` · `spikes/etw/` · `docs/`

La interfaz de producción sigue arrancando igual (`python gui_qt.py`), y las 42 pruebas del núcleo y
del colector siguen pasando.

---

## 7. Siguiente paso propuesto

Abrir la beta, recorrerla y decirme qué cambiar. Lo más útil ahora sería tu opinión sobre:

1. **La paleta** — ¿el azul eléctrico + cian funciona, o lo quieres más frío/más oscuro/más contrastado?
2. **La densidad** — ¿sobra o falta información por pantalla?
3. **El orden de la barra lateral** — ¿las diez áreas están en el orden en que las usarías?
4. **El Cuartel general** — ¿qué quitarías de la primera pantalla y qué echas en falta?
5. **El catálogo** — ¿la ficha tiene los campos que necesitas, o sobra/falta alguno?
