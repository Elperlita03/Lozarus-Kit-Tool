# 06 — Endurecimiento de despliegue (C8: carga dinámica de plugins)

> Nota de **despliegue**, no de código. Documenta el hallazgo C8 de la auditoría y cómo mitigarlo al
> instalar Lozarus. No hay cambio de código asociado: es una decisión sobre **dónde y con qué
> permisos** se ejecuta la herramienta. Fecha: 2026-10-20.

---

## 1. El hallazgo (C8)

**Qué:** el cargador de plugins importa —y por tanto **ejecuta**— todo fichero `.py` de `modulos/`
que no empiece por `_`.

**Dónde:** [`modulos/_cargador.py`](../modulos/_cargador.py), `discover_modules()`:
- línea 37: `importlib.import_module(__package__)` (importa el paquete `modulos`).
- línea 46: `importlib.import_module(f"{__package__}.{info.name}")` (importa cada plugin).

**Impacto:** quien consiga **escribir un `.py` en la carpeta `modulos/`** logra ejecución de código
dentro del proceso de Lozarus. Si Lozarus se ejecuta como Administrador (como recomienda para la
auditoría completa), ese código hereda privilegios de Administrador.

**No es un fallo de código.** Es el patrón normal de un sistema de plugins: cargar los módulos de su
propia carpeta. El riesgo no está en el `import`, sino en **quién puede escribir en esa carpeta**.

---

## 2. Modelo de amenaza (condiciones para que ocurra)

Para abusar de C8, un atacante necesita **permiso de escritura en `modulos/` antes de que Lozarus
arranque**. De ahí se derivan dos escenarios muy distintos según dónde esté instalado:

| Ubicación de instalación | ¿Quién puede escribir en `modulos/`? | Qué protege restringir permisos |
|---|---|---|
| **Carpeta del usuario** (p. ej. `%USERPROFILE%\Documents\AuditorTool`, la actual) | El propio usuario **y cualquier código que corra como ese usuario** (incluido malware sin privilegios) | **Poco**: el usuario ya puede escribir ahí por diseño; restringir ACLs no frena a un proceso que ya corre como él |
| **Carpeta solo para administradores** (p. ej. `C:\Program Files\Lozarus`) | Solo administradores | **Mucho**: el malware que corre como usuario estándar **no** puede plantar un plugin |

> **Conclusión honesta y la más importante de esta nota:** mientras Lozarus se ejecute desde una
> carpeta escribible por el usuario, C8 **no se puede cerrar solo con permisos**, porque el mismo
> usuario (y el malware que actúe en su nombre) ya tiene escritura ahí. La mitigación real es
> **mover la instalación a una ruta que solo los administradores puedan modificar.**

---

## 3. Mitigación 1 — Instalar en una ubicación protegida + ACL (recomendada)

Desplegar Lozarus bajo una ruta escribible solo por administradores, por ejemplo
`C:\Program Files\Lozarus`. Al estar ahí, Windows ya impide que un usuario estándar escriba en
`modulos/`, que es justo la precondición de C8.

**Comprobar quién puede escribir hoy** (solo lectura; ejecútalo tú como quieras):
```bat
icacls "C:\Program Files\Lozarus\modulos"
```
Busca entradas con permiso de escritura (`(W)`, `(M)` o `(F)`) para grupos amplios como
`BUILTIN\Usuarios` (`Users`) o `Todos` (`Everyone`): no deberían existir en una carpeta de programa.

**Endurecer (solo un administrador del despliegue, y conviene probarlo antes):**
```bat
icacls "C:\Program Files\Lozarus\modulos" /inheritance:r /grant:r "SYSTEM:(OI)(CI)(RX)" "Administradores:(OI)(CI)(F)" "Usuarios:(OI)(CI)(RX)"
```
Esto deja a `Usuarios` solo lectura y ejecución (`RX`) y reserva la escritura (`F`) a
`Administradores`. **Advertencia:** `icacls` modifica permisos del sistema de ficheros; pruébalo en
una copia o con un punto de restauración, y ajusta los nombres de los grupos a tu idioma de Windows
(`Administrators`/`Users` en inglés).

> Lozarus **no** aplica estos permisos por su cuenta: cambiar ACLs es una acción administrativa que
> corresponde a quien instala, no a la herramienta.

---

## 4. Mitigación 2 — Verificación de integridad al arranque (trabajo futuro, no implementado)

Como complemento (o alternativa cuando no se pueda instalar en `Program Files`), el cargador podría
**verificar un manifiesto de hashes** de `modulos/` antes de importar: calcular el SHA-256 de cada
`.py`, compararlo con una lista firmada/fijada y negarse a cargar (o avisar) si algo no coincide o
si aparece un fichero nuevo no listado.

- **Estado:** solo diseño; **no hay código** para esto y esta fase no lo añade.
- **Alcance de código (cuando se decida):** un paso de verificación en `discover_modules()` y un
  fichero de manifiesto versionado. Es coherente con el principio OBSIDIAN (detectar manipulación de
  la propia herramienta) y con el módulo 38 (autodefensa).
- **Límite honesto:** un manifiesto detecta manipulación, pero **no** la impide frente a quien pueda
  además reescribir el propio manifiesto o el ejecutable de Lozarus. Es detección, no invulnerabilidad.

---

## 5. Lo que NO se debe prometer

- Esto **no** protege frente a un administrador local comprometido: quien ya es Administrador puede
  escribir en `Program Files`, cambiar las ACLs o sustituir la propia herramienta. Es el límite de
  arquitectura ya documentado en [`docs/00`](00_AUDITORIA_ARQUITECTURA.md) §1.1.
- Las ACLs de una carpeta **escribible por el usuario** no frenan al malware que corre como ese
  usuario (ver §2).
- Ninguna de estas medidas convierte a Lozarus en «a prueba de manipulación»; suben el coste de
  atacarlo, no lo eliminan.

---

## 6. Recomendación

1. **Para uso real:** instalar Lozarus bajo `C:\Program Files\Lozarus` (o similar, solo-admin) y
   verificar con `icacls` que `modulos/` no es escribible por `Usuarios`. Cierra la precondición de
   C8 para el malware sin privilegios.
2. **Mientras se ejecute desde la carpeta del usuario** (desarrollo actual): asumir que C8 está
   abierto por diseño del entorno y no dar por «protegida» la carpeta; es aceptable para desarrollo,
   no para despliegue.
3. **Más adelante:** evaluar la verificación de integridad (§4) junto con la autodefensa (módulo 38),
   como detección de manipulación, no como garantía.

---

## 7. Estado

- **C8:** documentado aquí. Sin cambio de código. Acción pendiente: decisión de ubicación de
  instalación por parte de quien despliegue; opcionalmente, implementar §4 en una fase futura.
- Esta nota no modifica ningún comportamiento de Lozarus.
