# -*- coding: utf-8 -*-
"""
Benchmark de carga reproducible del colector ETW (NO es una prueba unitaria; pytest no lo recoge por
el prefijo `bench_`). Requiere Windows + Administrador + pywintrace. Si faltan, imprime PENDIENTE y no
inventa resultados.

Mide, sobre una ventana de captura con carga controlada (procesos de corta duración generados a ritmo
constante), distinguiendo lo MEDIDO de lo PENDIENTE:
  - eventos recibidos/s y entregados/s,
  - descartes del bus (interno) y EventsLost de ETW (fuente, conocido TRAS stop),
  - CPU% y RAM del proceso,
  - tiempo de parada/liberación.

Uso (consola de Administrador, con pywintrace; p. ej. el venv del spike):
    python tests/bench_etw_collector.py --seconds 20
"""

import argparse
import ctypes
import os
import platform
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.etw_collector import EtwCollector  # noqa: E402
from core.bus import EventBus, OverflowPolicy  # noqa: E402


def _requirements():
    if platform.system() != "Windows":
        return False, "no es Windows"
    try:
        __import__("etw")                     # solo sonda de disponibilidad (no se usa el módulo)
    except Exception as exc:  # noqa: BLE001
        return False, f"pywintrace no disponible: {exc}"
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return False, "sin privilegios de Administrador"
    except Exception:
        return False, "no se pudo comprobar privilegios"
    return True, ""


def run(seconds: float, load_interval: float, maxsize: int) -> int:
    import psutil

    bus = EventBus(maxsize=maxsize, policy=OverflowPolicy.DROP_NEWEST)
    delivered = {"n": 0}
    bus.subscribe(lambda _e: delivered.__setitem__("n", delivered["n"] + 1))
    bus.start()

    collector = EtwCollector(bus, provider="kernel-process")
    proc = psutil.Process()
    proc.cpu_percent(None)                    # primer muestreo (base para el % de la ventana)

    collector.start()
    if not collector._started:
        print(f"[bench] No se pudo arrancar el colector: {collector.health().init_error}")
        bus.stop()
        return 2

    stop_load = threading.Event()

    def loadgen():
        while not stop_load.is_set():
            subprocess.run(["cmd", "/c", "ver"], capture_output=True)
            time.sleep(load_interval)

    t = threading.Thread(target=loadgen, daemon=True, name="loadgen")
    t.start()
    print(f"[bench] Capturando {seconds:.0f}s con carga (proceso cada {load_interval:.2f}s)…")
    t0 = time.monotonic()
    time.sleep(seconds)
    window = time.monotonic() - t0

    cpu_pct = proc.cpu_percent(None)          # % de CPU durante la ventana
    rss_mb = proc.memory_info().rss / 1024 ** 2
    stop_load.set()
    t.join(timeout=5)
    bus.flush(timeout=10)
    collector.stop()                          # read_loss ocurre aquí
    bus.stop()

    m = collector.metrics()
    bm = bus.metrics()
    recv_s = m.events_received / window if window else 0.0
    deliv_s = delivered["n"] / window if window else 0.0

    print("\n== Benchmark ETW (MEDIDO) ==")
    print(f"  Ventana                 : {window:.2f} s")
    print(f"  Eventos recibidos       : {m.events_received}  ({recv_s:.1f}/s)")
    print(f"  Eventos entregados      : {delivered['n']}  ({deliv_s:.1f}/s)")
    print(f"  Descartes del BUS (int) : {m.bus_dropped}   (publicados {m.events_published})")
    print(f"  EventsLost de ETW (src) : {m.source_events_lost}  · BuffersLost: {m.source_buffers_lost}"
          "   (conocido TRAS stop)")
    print(f"  Errores de consumidor   : {m.consumer_errors}")
    print(f"  CPU del proceso         : {cpu_pct:.1f} %")
    print(f"  RAM del proceso (RSS)   : {rss_mb:.1f} MB")
    print(f"  Tiempo de parada        : {m.stop_duration_s} s")
    print(f"  (bus) published/enqueued/delivered/dropped: "
          f"{bm.published}/{bm.enqueued}/{bm.delivered}/{bm.dropped}  max_depth={bm.max_depth}")
    print("\n== PENDIENTE (no medido aquí) ==")
    print("  Latencia por evento (recepción→publicación): requiere instrumentar marcas por evento.")
    print("  Pérdida sostenida bajo carga alta: repetir con --seconds mayor y carga más agresiva.")
    print("\nNota: EventsLost/BuffersLost de ETW solo se conocen al PARAR la sesión (limitación de "
          "pywintrace); durante el run la pérdida de la fuente es DESCONOCIDA (None), nunca 0.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark de carga del colector ETW de Lozarus.")
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--load-interval", type=float, default=0.05)
    parser.add_argument("--maxsize", type=int, default=4096)
    args = parser.parse_args(argv)

    ok, reason = _requirements()
    if not ok:
        print(f"PENDIENTE — requisitos no disponibles: {reason}")
        print("Ejecuta en Windows como Administrador (con pywintrace) para obtener mediciones reales.")
        return 0
    return run(args.seconds, args.load_interval, args.maxsize)


if __name__ == "__main__":
    raise SystemExit(main())
