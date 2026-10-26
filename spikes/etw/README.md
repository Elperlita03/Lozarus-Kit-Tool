# Spike ETW — Adquisición de telemetría ETW desde Python

Prototipo **aislado** para validar si Lozarus puede consumir eventos **ETW reales** de Windows y
normalizarlos. No es el colector de producción ni se integra con la GUI: solo prueba la vía técnica.

- **Vía:** librería [`pywintrace`](https://pypi.org/project/pywintrace/) (import `etw`), que envuelve
  las APIs documentadas de consumo ETW (`StartTrace` / `EnableTraceEx2` / `OpenTrace` / `ProcessTrace`
  / TDH). **Sin driver de kernel. Sin proveedores protegidos (antimalware/PPL). Sin tocar otros procesos.**
- **Verificado aquí:** instala e importa en **Python 3.13.15 x64 / Windows 11**; la normalización
  pasa sus 8 pruebas unitarias; el manejo del error de permisos funciona.
- **Pendiente (requiere Administrador):** la captura de un evento real. Documentado abajo, sin simular.

## Requisitos

- Windows 10/11 x64.
- Python 3.13 x64.
- Para la **captura real**: consola como **Administrador** (o usuario en el grupo
  *Performance Log Users*). Iniciar una sesión ETW en tiempo real sin privilegios falla con
  `ERROR_ACCESS_DENIED` (el prototipo lo detecta y lo informa).

## Instalación (entorno aislado, sin tocar el proyecto principal)

```bat
cd spikes\etw
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-spike.txt
```

## Uso

```bat
python etw_spike.py --check        :: solo comprobar requisitos (no inicia nada)
python etw_spike.py --list         :: proveedores de ejemplo y sus GUID

:: Captura real (en consola de Administrador). Ctrl+C detiene y cierra la sesión limpiamente:
python etw_spike.py --provider kernel-process --seconds 8 --max 15
python etw_spike.py --provider dns-client --seconds 10 --max 20 --json
```

Proveedores de ejemplo (documentados, no restringidos): `kernel-process` (creación/fin de procesos),
`dns-client` (consultas DNS), `powershell` (actividad de PowerShell). Para generar eventos, realiza la
acción sugerida (abrir un proceso, una resolución DNS, etc.).

**Detener:** `Ctrl+C`, o se detiene solo al alcanzar `--seconds` o `--max`. La sesión ETW se cierra
siempre (bloque `finally`), incluso ante excepción o interrupción.

## Pruebas

```bat
python test_normalize.py                 :: unitarias de normalización (no requieren admin ni ETW)
python -m pytest test_normalize.py -v     :: (igual, con pytest)
python test_integration.py                :: integración; se SALTA si no hay admin/pywintrace
python -m pytest test_integration.py -v   :: (igual, con marca skip)
```

## Criterios de aceptación (estado)

| # | Criterio | Estado |
|---|----------|--------|
| 1 | Captura de ≥1 evento ETW real | **Pendiente** (requiere Administrador; comando en `INFORME.md` §4.1) |
| 2 | Identifica proveedor y campos observados | Normalización verificada (8/8 unitarias); falta confirmar con evento real |
| 3 | Tratamiento correcto de errores de permisos | **Cumplido** (`ERROR_ACCESS_DENIED` manejado, exit 3) |
| 4 | Cierre limpio de la sesión (sin huérfanas) | **Cumplido** (cierre en `finally`; `logman query -ets` sin sesión residual) |
| 5 | Estado de pérdida de eventos documentado | **Cumplido** (se lee de `EVENT_TRACE_PROPERTIES` tras STOP; «desconocida» hasta medir, nunca 0) |
| 6 | Instrucciones reproducibles | **Cumplido** (este README + `INFORME.md` §4.1) |

El detalle de resultados, el tipo de sesión y privilegios exactos, la semántica del reloj, los límites y
la propuesta de contrato para `collectors/etw_collector.py` están en **`INFORME.md`**.
