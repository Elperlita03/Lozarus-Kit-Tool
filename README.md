# LOZARUS KIT TOOL

Kit de seguridad **defensiva**, auditoría y endurecimiento para Windows. El análisis es de
**solo lectura**; las acciones de contención y defensa (aislamiento, USB, honeypot, ICMP, Modo
Fantasma, Sandbox…) son **reversibles o acotadas**, piden confirmación y, cuando tocan el
sistema, requieren Administrador. Todo opera **en local, sobre tu propio equipo**.

## Puntos de entrada

| Comando | Qué es |
|---------|--------|
| `python gui_qt.py` | **Interfaz principal** (PySide6): Centro de Comando, Monitor en Vivo, Escaneo de Vectores, Historial, Endurecimiento de Red, Honeypot y Modo Fantasma. |
| `python auditor.py` | **CLI** de auditoría (los mismos plugins de `modulos/`). Admite `--listar`, `--html`, `--diff`, `-m <modulo>`… |

Ejecuta como **Administrador** para la auditoría completa y para las acciones que modifican el
sistema.

## Requisitos

- Python 3.13
- `pip install PySide6 psutil plyer`
  - `PySide6` → interfaz gráfica
  - `psutil` → monitor en vivo · `plyer` → notificaciones del Modo Centinela/Vanguardia

## Estructura

- `modulos/` — motor de plugins de auditoría (solo lectura) más los módulos de apoyo:
  monitor en vivo, forense, contención, operaciones tácticas y defensa local.
- `Lozarus_Forensics/` — salida en disco: snapshots de «caja negra», reportes forenses,
  configuraciones de Sandbox y archivos señuelo del honeypot.

## Qué hace cada sección (interfaz principal)

- **Centro de Comando** — resumen del estado y privilegios.
- **Monitor en Vivo** — conexiones de red y procesos sospechosos en tiempo real, con
  sparklines de CPU/RAM; desde aquí se analiza un proceso en **Windows Sandbox** o se genera
  un **reporte forense**.
- **Escaneo de Vectores** — ejecuta los plugins de `modulos/` y muestra los hallazgos por
  severidad.
- **Historial** — snapshots de «caja negra» del sistema.
- **Endurecimiento de Red** — oculta el equipo ante ping (regla ICMP, reversible).
- **Honeypot** — despliega archivos señuelo y avisa si se modifican o eliminan (solo detecta).
- **Modo Fantasma** — limpieza de privacidad del equipo con terminal en vivo.
