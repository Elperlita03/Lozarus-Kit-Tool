# -*- coding: utf-8 -*-
"""
Pruebas de regresión de C6 — caducidad de la caché de firmas (modulos/_monitor.py).

NO tocan el sistema: usan ficheros TEMPORALES y sustituyen `powershell` por un doble. Verifican que
una ruta cuya fecha de modificación cambia se vuelve a verificar (no conserva una firma obsoleta), y
que una ruta estable se sigue sirviendo de la caché sin re-encolarse.

Requiere psutil (para construir LiveMonitor); está presente en este equipo. Si faltara, la prueba se
salta en lugar de fallar.
"""

import importlib
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

mon = importlib.import_module("modulos._monitor")

try:
    import pytest  # noqa: E402
    _HAS_PYTEST = True
except ImportError:
    _HAS_PYTEST = False


def _skip(msg):
    if _HAS_PYTEST:
        pytest.skip(msg)
    print("SALTADA —", msg)


def _nuevo_monitor():
    """Construye un LiveMonitor o salta si no hay psutil. No arranca ningún hilo de fondo."""
    if not mon.HAS_PSUTIL:
        return None
    return mon.LiveMonitor()


def _con_firma_falsa(estado, firmante="Editor Falso"):
    """Devuelve un doble de `powershell` que responde con la misma firma para toda ruta pedida."""
    def fake_powershell(script, timeout=120):
        # El script incrusta las rutas en base64; no las parseamos: devolvemos la firma para las
        # rutas que el monitor tenga pendientes (se las pasamos por un atributo del propio doble).
        return [{"p": p, "s": estado, "who": firmante} for p in fake_powershell.rutas]
    fake_powershell.rutas = []
    return fake_powershell


def _verificar_sincrono(monitor, fake):
    """Ejecuta una ronda de verificación de forma SÍNCRONA (sin el hilo de fondo)."""
    fake.rutas = sorted(monitor.pending)
    orig = mon.powershell
    mon.powershell = fake
    try:
        monitor._verify_pending()
    finally:
        mon.powershell = orig


def test_mtime_cambiado_fuerza_reverificacion():
    monitor = _nuevo_monitor()
    if monitor is None:
        return _skip("psutil no disponible")
    fd, ruta = tempfile.mkstemp(suffix=".dll")
    os.close(fd)
    try:
        # 1ª verificación: queda cacheada como 'Valid'
        monitor._request_signatures([ruta])
        assert ruta in monitor.pending
        _verificar_sincrono(monitor, _con_firma_falsa("Valid"))
        assert monitor.signatures[ruta] == ("Valid", "Editor Falso")
        assert ruta not in monitor.pending
        mt1 = monitor._sig_mtime[ruta]

        # Sin cambios: NO se re-encola (sigue cacheada)
        monitor._request_signatures([ruta])
        assert ruta not in monitor.pending, "se re-verificó un fichero que no cambió"

        # Cambiamos el fichero (nuevo mtime) -> debe re-encolarse y descartar la firma obsoleta
        time.sleep(0.01)
        with open(ruta, "w", encoding="utf-8") as fh:
            fh.write("contenido nuevo")
        os.utime(ruta, (mt1 + 5, mt1 + 5))  # fuerza un mtime distinto, de forma determinista
        monitor._request_signatures([ruta])
        assert ruta in monitor.pending, "un fichero sustituido NO se volvió a verificar"
        assert ruta not in monitor.signatures, "se conservó la firma obsoleta tras el cambio"

        # 2ª verificación: ahora refleja la nueva firma
        _verificar_sincrono(monitor, _con_firma_falsa("NotSigned", ""))
        assert monitor.signatures[ruta] == ("NotSigned", "")
    finally:
        os.remove(ruta)


def test_fichero_estable_se_sirve_de_cache():
    monitor = _nuevo_monitor()
    if monitor is None:
        return _skip("psutil no disponible")
    fd, ruta = tempfile.mkstemp(suffix=".dll")
    os.close(fd)
    try:
        monitor._request_signatures([ruta])
        _verificar_sincrono(monitor, _con_firma_falsa("Valid"))
        llamadas = {"n": 0}
        fake = _con_firma_falsa("Valid")
        orig_fake = fake

        def contador(script, timeout=120):
            llamadas["n"] += 1
            return orig_fake(script, timeout)
        # Varias peticiones sin cambiar el fichero: no debe re-encolarse ni llamar a PowerShell.
        for _ in range(3):
            monitor._request_signatures([ruta])
            assert ruta not in monitor.pending
        assert llamadas["n"] == 0
    finally:
        os.remove(ruta)


def test_ruta_inexistente_mtime_cero():
    monitor = _nuevo_monitor()
    if monitor is None:
        return _skip("psutil no disponible")
    assert monitor._mtime("Z:\\no\\existe\\fantasma.dll") == 0.0


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"OK  {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"ERR {t.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} OK")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
