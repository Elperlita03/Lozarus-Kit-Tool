# -*- coding: utf-8 -*-
"""
ETW SPIKE · prototipo aislado de adquisición de telemetría ETW desde Python (para Lozarus).

Objetivo: demostrar de forma REPRODUCIBLE si podemos consumir eventos ETW reales de Windows y
normalizarlos. NO es el colector de producción: valida la vía técnica antes de diseñarla.

Vía elegida: librería `pywintrace` (paquete import `etw`), que envuelve las APIs documentadas de
consumo ETW (StartTrace / EnableTraceEx2 / OpenTrace / ProcessTrace / TDH). No usa driver de kernel,
no accede a proveedores protegidos (antimalware/PPL) ni altera otros procesos: solo abre una sesión
de trazado en tiempo real sobre un proveedor documentado y lee sus eventos.

Requisito clave: iniciar una sesión ETW en tiempo real exige, por lo general, privilegios de
Administrador (o pertenecer al grupo «Performance Log Users»). Sin ellos, StartTrace devuelve
ERROR_ACCESS_DENIED (5); el prototipo lo detecta y lo informa sin bloquearse ni simular éxito.

Uso:
    python etw_spike.py --check                      # solo comprueba requisitos previos
    python etw_spike.py --list                       # lista los proveedores de ejemplo
    python etw_spike.py --provider kernel-process --seconds 8 --max 15
    (Ctrl+C detiene y cierra la sesión limpiamente)
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import sys
import threading
import time

# La consola de Windows suele ir en cp1252/OEM y revienta con caracteres no-ASCII. Forzamos UTF-8
# en la salida para no fallar (hallazgo del spike: el colector no debe asumir la codificación).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize import NORMALIZED_SCHEMA, normalize, summarize  # noqa: E402

try:
    from etw import ETW, ProviderInfo
    from etw.GUID import GUID
    ETW_AVAILABLE, ETW_IMPORT_ERROR = True, ""
except Exception as exc:  # ImportError u otros fallos de carga (p. ej. no Windows)
    ETW = ProviderInfo = GUID = None
    ETW_AVAILABLE, ETW_IMPORT_ERROR = False, f"{type(exc).__name__}: {exc}"

# Proveedores de ejemplo: documentados, NO restringidos a procesos antimalware protegidos.
PROVIDERS = {
    "kernel-process": {
        "name": "Microsoft-Windows-Kernel-Process",
        "guid": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
        "needs_admin": True,
        "desc": "Creación/fin de procesos, carga de imágenes y hilos. Telemetría EDR básica.",
        "trigger": "Lanza o cierra un proceso (p. ej. abrir y cerrar el Bloc de notas).",
    },
    "dns-client": {
        "name": "Microsoft-Windows-DNS-Client",
        "guid": "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}",
        "needs_admin": True,
        "desc": "Consultas DNS del cliente. Útil para telemetría de red.",
        "trigger": "Fuerza una resolución DNS (nslookup ejemplo.com, o abre una web nueva).",
    },
    "powershell": {
        "name": "Microsoft-Windows-PowerShell",
        "guid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
        "needs_admin": True,
        "desc": "Actividad de PowerShell (incluido el registro de bloques de script).",
        "trigger": "Ejecuta cualquier comando en una ventana de PowerShell.",
    },
}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_prerequisites() -> dict:
    """Comprueba (sin iniciar ninguna sesión) si el entorno puede consumir ETW."""
    return {
        "os": platform.system(),
        "windows_release": platform.release(),
        "windows_version": platform.version(),
        "windows_edition": platform.win32_edition() if hasattr(platform, "win32_edition") else None,
        "python_version": platform.python_version(),
        "python_arch": platform.architecture()[0],
        "is_windows": platform.system() == "Windows",
        "is_admin": is_admin(),
        "pywintrace_available": ETW_AVAILABLE,
        "pywintrace_import_error": ETW_IMPORT_ERROR or None,
    }


def print_prerequisites(p: dict) -> None:
    print("== Requisitos previos (ETW spike) ==")
    print(f"  SO                : {p['os']} {p['windows_release']} ({p['windows_version']}) "
          f"{p['windows_edition'] or ''}")
    print(f"  Python            : {p['python_version']} {p['python_arch']}")
    print(f"  ¿Windows?         : {'sí' if p['is_windows'] else 'NO — ETW no está disponible'}")
    print(f"  ¿Administrador?   : {'sí' if p['is_admin'] else 'NO — no se podrá iniciar una sesión en tiempo real'}")
    print(f"  pywintrace (etw)  : {'disponible' if p['pywintrace_available'] else 'NO: ' + str(p['pywintrace_import_error'])}")
    ready = p["is_windows"] and p["is_admin"] and p["pywintrace_available"]
    print(f"  Veredicto         : {'LISTO para capturar' if ready else 'NO listo (ver arriba)'}")
    if p["is_windows"] and not p["is_admin"]:
        print("                      → Ejecuta una consola como Administrador para la captura real.")


def _classify_error(exc: Exception) -> str:
    winerr = getattr(exc, "winerror", None)
    if winerr == 5 or "access is denied" in str(exc).lower() or "denegado" in str(exc).lower():
        return ("acceso denegado (ERROR_ACCESS_DENIED): iniciar una sesión ETW en tiempo real "
                "requiere Administrador o pertenecer a «Performance Log Users».")
    if winerr == 4201:  # ERROR_WMI_INSTANCE_NOT_FOUND
        return "instancia WMI/ETW no encontrada: el proveedor podría no estar registrado en este Windows."
    return f"{type(exc).__name__}: {exc}" + (f" (winerror={winerr})" if winerr is not None else "")


def run(provider_key: str, seconds: float, max_events: int) -> dict:
    """
    Inicia una sesión ETW en tiempo real sobre `provider_key`, recoge hasta `max_events` eventos o
    hasta agotar `seconds`, los normaliza y devuelve un resumen. Cierra SIEMPRE la sesión (finally),
    incluso ante excepción o Ctrl+C. Devuelve un dict con el resultado (nunca lanza al llamador).
    """
    result = {"provider": provider_key, "started": False, "count": 0, "events": [],
              "error": None, "interrupted": False, "elapsed_s": 0.0,
              "events_lost": None, "buffers_lost": None}  # None = desconocido (nunca 0 sin medir)
    if not ETW_AVAILABLE:
        result["error"] = f"pywintrace no disponible: {ETW_IMPORT_ERROR}"
        return result
    prov = PROVIDERS.get(provider_key)
    if prov is None:
        result["error"] = f"proveedor desconocido: {provider_key} (usa --list)"
        return result

    collected = []
    lock = threading.Lock()

    def on_event(evt):
        try:
            n = normalize(evt)
        except Exception:
            return  # un evento mal formado nunca debe tumbar el consumidor
        with lock:
            if len(collected) < max_events:
                collected.append(n)

    providers = [ProviderInfo(prov["name"], GUID(prov["guid"]))]
    job = ETW(providers=providers, event_callback=on_event)

    started_at = time.time()
    try:
        job.start()
        result["started"] = True
        print(f"[spike] Sesión iniciada sobre {prov['name']}. Sugerencia: {prov['trigger']}")
        print(f"[spike] Escuchando hasta {seconds:.0f}s o {max_events} eventos… (Ctrl+C para detener)")
        deadline = started_at + seconds
        while time.time() < deadline:
            with lock:
                enough = len(collected) >= max_events
            if enough:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        result["interrupted"] = True
        print("\n[spike] Interrumpido por el usuario, cerrando la sesión…")
    except Exception as exc:
        result["error"] = _classify_error(exc)
    finally:
        try:
            job.stop()
        except Exception as exc:
            if not result["error"]:
                result["error"] = f"al cerrar la sesión: {_classify_error(exc)}"

    with lock:
        result["count"] = len(collected)
        result["events"] = collected

    # Pérdida de eventos: tras ControlTrace(STOP), Windows deja EventsLost / RealTimeBuffersLost en
    # las propiedades de la sesión (EVENT_TRACE_PROPERTIES). Es la vía compatible de consultarlo con
    # esta librería. Si la sesión NUNCA arrancó, se deja como desconocida (None), jamás como cero.
    if result["started"]:
        try:
            props = job.properties.get().contents
            result["events_lost"] = int(props.EventsLost)
            result["buffers_lost"] = int(props.RealTimeBuffersLost)
        except Exception:
            pass  # si no se pudo leer, se queda en None (desconocida), no en 0

    result["elapsed_s"] = round(time.time() - started_at, 2)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Prototipo aislado de adquisición ETW para Lozarus.")
    parser.add_argument("--check", action="store_true", help="Solo comprobar requisitos previos y salir.")
    parser.add_argument("--list", action="store_true", help="Listar proveedores de ejemplo y salir.")
    parser.add_argument("--provider", default="kernel-process", choices=list(PROVIDERS),
                        help="Proveedor a consumir (por defecto: kernel-process).")
    parser.add_argument("--seconds", type=float, default=8.0, help="Duración máxima de escucha.")
    parser.add_argument("--max", type=int, default=15, dest="max_events", help="Máximo de eventos a recoger.")
    parser.add_argument("--json", action="store_true", help="Imprimir el resultado como JSON.")
    args = parser.parse_args(argv)

    prereqs = check_prerequisites()

    if args.list:
        print("== Proveedores de ejemplo (documentados, no protegidos) ==")
        for key, p in PROVIDERS.items():
            print(f"  {key:16s} {p['name']}")
            print(f"  {'':16s}   {p['desc']}")
            print(f"  {'':16s}   admin: {'sí' if p['needs_admin'] else 'no'} · {p['guid']}")
        return 0

    print_prerequisites(prereqs)
    if args.check:
        if args.json:
            print(json.dumps(prereqs, ensure_ascii=False, indent=2))
        return 0

    if not prereqs["is_windows"]:
        print("[spike] No es Windows: nada que capturar. Ejecuta esto en un Windows real.")
        return 2
    if not prereqs["pywintrace_available"]:
        print("[spike] Falta pywintrace. Instala: pip install -r requirements-spike.txt")
        return 2
    if not prereqs["is_admin"]:
        print("[spike] Sin privilegios de Administrador: la captura real está PENDIENTE. "
              "Se intentará igualmente para mostrar el manejo del error de permisos.")

    print()
    result = run(args.provider, args.seconds, args.max_events)
    print()
    print("== Resultado ==")
    print(f"  Proveedor   : {PROVIDERS[args.provider]['name']}")
    print(f"  Iniciada    : {result['started']}")
    print(f"  Eventos     : {result['count']}  (en {result['elapsed_s']}s)")
    el, bl = result.get("events_lost"), result.get("buffers_lost")
    print(f"  Pérdida     : eventos={'desconocida' if el is None else el} · "
          f"buffers={'desconocida' if bl is None else bl}")
    if result["interrupted"]:
        print("  Nota        : detenido por el usuario.")
    if result["error"]:
        print(f"  Error       : {result['error']}")
    if result["events"]:
        print(f"  Muestra (esquema {NORMALIZED_SCHEMA}):")
        for ev in result["events"][:10]:
            print("   ·", summarize(ev))
    if args.json:
        slim = dict(result)
        slim["events"] = result["events"][:5]
        print(json.dumps(slim, ensure_ascii=False, indent=2, default=str))

    if result["started"] and result["count"] > 0:
        return 0           # éxito: se recibieron eventos reales
    if result["error"] and "acceso denegado" in result["error"]:
        return 3           # bloqueado por permisos: captura pendiente, manejado correctamente
    return 1               # iniciada pero sin eventos, u otro fallo


if __name__ == "__main__":
    raise SystemExit(main())
