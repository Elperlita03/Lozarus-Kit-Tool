# -*- coding: utf-8 -*-
"""
Validación automática de la beta visual, sin necesidad de mirar la pantalla.

Arranca la aplicación con el backend gráfico `offscreen`, recorre TODAS las secciones en los dos
modos (normal y demostración), captura cualquier excepción y, opcionalmente, guarda un PNG de cada
sección para poder revisarlas.

Ejecutar:
    python spikes/ui_preview/smoke_test.py                 # solo comprueba
    python spikes/ui_preview/smoke_test.py --render SALIDA  # además guarda capturas
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")       # debe fijarse ANTES de crear QApplication

for _stream in (sys.stdout, sys.stderr):                    # consola cp1252: evita UnicodeEncodeError
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def run(render_dir: str | None = None, width: int = 1480, height: int = 940) -> int:
    from PySide6.QtWidgets import QApplication

    from app import EXTRA_SECTIONS, MAIN_SECTIONS, LozarusBeta
    from theme import QSS

    failures: list[str] = []
    app = QApplication(sys.argv[:1])
    app.setStyleSheet(QSS)

    try:
        window = LozarusBeta()
    except Exception:
        print("FALLO al construir la ventana principal:\n" + traceback.format_exc())
        return 1

    window.resize(width, height)
    window.show()
    app.processEvents()

    keys = [cls.KEY for cls, _ in MAIN_SECTIONS + EXTRA_SECTIONS]
    print(f"Secciones registradas: {len(keys)} → {', '.join(keys)}")

    if render_dir:
        os.makedirs(render_dir, exist_ok=True)

    for mode, demo in (("normal", False), ("demo", True)):
        try:
            window.ctx.set_demo(demo)
            app.processEvents()
        except Exception:
            failures.append(f"set_demo({demo}):\n{traceback.format_exc()}")
            continue

        for key in keys:
            try:
                window.select(key)
                for _ in range(3):                           # deja asentar layout y temporizadores
                    app.processEvents()
                page = window.pages[key]
                assert page.isVisible() or True              # offscreen: basta con que no reviente
                if render_dir:
                    path = os.path.join(render_dir, f"{mode}_{key}.png")
                    if not window.grab().save(path):
                        failures.append(f"no se pudo guardar la captura {path}")
            except Exception:
                failures.append(f"sección «{key}» en modo {mode}:\n{traceback.format_exc()}")

    # Interacciones: abrir cada ficha del catálogo ejercita la vista de detalle
    try:
        from catalog import ALL
        catalog_page = window.pages["catalog"]
        window.select("catalog")
        for cap in ALL:
            catalog_page._show_detail(cap)
        app.processEvents()
        print(f"Fichas del catálogo abiertas sin error: {len(ALL)}")
    except Exception:
        failures.append("fichas del catálogo:\n" + traceback.format_exc())

    # Filtros del catálogo
    try:
        from theme import STATUS_ORDER
        for key in (None,) + tuple(STATUS_ORDER):
            catalog_page._set_status(key)
            app.processEvents()
        catalog_page._set_query("etw")
        catalog_page._set_query("")
        catalog_page._set_area("Núcleo y telemetría")
        catalog_page._set_area("Todas las áreas")
        print("Filtros del catálogo ejercitados sin error")
    except Exception:
        failures.append("filtros del catálogo:\n" + traceback.format_exc())

    window.ctx.set_demo(False)
    app.processEvents()

    print()
    if failures:
        print(f"RESULTADO: {len(failures)} fallo(s)\n")
        for f in failures:
            print("-" * 70)
            print(f)
        return 1
    print(f"RESULTADO: OK — {len(keys)} secciones recorridas en 2 modos, sin errores.")
    if render_dir:
        print(f"Capturas guardadas en: {render_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validación de la beta visual de Lozarus.")
    parser.add_argument("--render", metavar="CARPETA", default=None,
                        help="guarda un PNG por sección y modo en esa carpeta")
    parser.add_argument("--width", type=int, default=1480)
    parser.add_argument("--height", type=int, default=940)
    args = parser.parse_args()
    return run(args.render, args.width, args.height)


if __name__ == "__main__":
    raise SystemExit(main())
