# -*- coding: utf-8 -*-
"""
Pruebas de COMPORTAMIENTO del widget ProcessMonitor (gui_qt.py) del Monitor en Vivo.

Qué son y qué NO son:
  · Son pruebas automatizadas de la LÓGICA del widget (estado de temporizadores, filtrado, orden,
    manejo de errores) usando DOBLES: una `FakeApp` que ejecuta las tareas de fondo de forma
    SÍNCRONA y una muestra de procesos SIMULADA (se sustituye `_procmon.sample_processes`).
  · Para poder construir un QWidget hace falta una QApplication; se usa el backend **offscreen**
    (sin ventana visible y SIN renderizado). No se comprueba nada visual ni se usan procesos reales.
  · No se ejecuta la GUI real, no se tocan procesos del equipo ni configuraciones de Windows.

Cubren: enumeración con datos simulados, errores de permisos / datos incompletos, filtrado y orden,
inicio/detención/reanudación sin temporizadores duplicados, y liberación del temporizador al parar.
"""

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # ANTES de importar Qt: sin ventana ni render

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import gui_qt  # noqa: E402
from modulos import _procmon  # noqa: E402
from modulos._procmon import ProcRow  # noqa: E402

_app = QApplication.instance() or QApplication([])  # una sola instancia para todas las pruebas
_MB = 1024 ** 2
_USER_ROLE = Qt.ItemDataRole.UserRole


class FakeApp:
    """Doble de MainWindow: ejecuta run_task de forma SÍNCRONA (determinista, sin hilos)."""
    def __init__(self):
        self.admin = False

    def run_task(self, fn, on_done, track=True):  # misma firma que MainWindow.run_task
        try:
            result = fn(lambda *a, **k: None)  # el callback de log no hace nada
            on_done(True, result)
        except Exception as exc:  # noqa: BLE001
            on_done(False, f"{type(exc).__name__}: {exc}")


def _patch_sample(rows):
    """Sustituye el muestreo real por una muestra fija. Devuelve una función para restaurar."""
    original = _procmon.sample_processes

    def fake(cpu_count=None):
        return list(rows)
    _procmon.sample_processes = fake
    return lambda: setattr(_procmon, "sample_processes", original)


def _monitor():
    return gui_qt.ProcessMonitor(FakeApp())


def _rows():
    return [ProcRow(10, "chrome.exe", "u", 1.0, 100 * _MB, "running"),
            ProcRow(20, "python.exe", "u", 9.0, 200 * _MB, "running"),
            ProcRow(305, "svchost.exe", None, None, None, "running")]  # datos incompletos


# --- 1) enumeración con datos simulados --------------------------------------------------------
def test_enumeracion_con_datos_simulados():
    restore = _patch_sample(_rows())
    try:
        pm = _monitor()
        pm.start()                      # FakeApp ejecuta el muestreo de forma síncrona
        assert pm.table.rowCount() == 3
        pm.stop()
    finally:
        restore()


# --- 2) errores de permisos / datos incompletos ------------------------------------------------
def test_datos_incompletos_muestran_guion():
    restore = _patch_sample([ProcRow(5, "svc.exe", None, None, None, "running")])
    try:
        pm = _monitor()
        pm.start()
        assert pm.table.item(0, 2).text() == "—"   # usuario None → «—»
        assert pm.table.item(0, 3).text() == "—"   # cpu None → «—»
        assert pm.table.item(0, 4).text() == "—"   # memoria None → «—»
        pm.stop()
    finally:
        restore()


def test_error_de_muestreo_no_rompe_la_gui():
    original = _procmon.sample_processes

    def boom(cpu_count=None):
        raise RuntimeError("psutil no disponible")
    _procmon.sample_processes = boom
    try:
        pm = _monitor()
        pm.start()                      # run_task síncrono → on_done(False, …) → notice, sin excepción
        assert "No se pudieron muestrear" in pm.notice.text()
        pm.stop()
    finally:
        _procmon.sample_processes = original


# --- 3) filtrado y ordenación ------------------------------------------------------------------
def test_filtrado_sin_remuestrear():
    restore = _patch_sample(_rows())
    try:
        pm = _monitor()
        pm.start()
        pm.search.setText("python")     # filtra sobre la muestra, sin volver a consultar
        assert pm.table.rowCount() == 1
        assert pm.table.item(0, 0).data(_USER_ROLE) == 20
        pm.search.setText("")
        assert pm.table.rowCount() == 3
        pm.stop()
    finally:
        restore()


def test_orden_por_cpu_descendente_por_defecto():
    restore = _patch_sample(_rows())
    try:
        pm = _monitor()
        pm.start()                      # orden por defecto: cpu descendente
        assert pm.table.item(0, 0).data(_USER_ROLE) == 20   # python, 9.0 %
        # clic en la cabecera PID → ordena por PID ascendente
        pm._header_clicked(0)
        assert pm.table.item(0, 0).data(_USER_ROLE) == 10
        pm.stop()
    finally:
        restore()


# --- 4) inicio / detención / reanudación sin temporizadores duplicados -------------------------
def test_inicio_detencion_reanudacion_sin_timer_duplicado():
    restore = _patch_sample(_rows())
    try:
        pm = _monitor()
        pm.start()
        assert pm._running and pm.timer.isActive()
        primer_timer = pm.timer
        pm.stop()
        assert not pm._running and not pm.timer.isActive()
        pm.start()                      # reanudar
        assert pm._running and pm.timer.isActive()
        assert pm.timer is primer_timer  # el MISMO QTimer, no uno nuevo (sin duplicados)
        pm.stop()
    finally:
        restore()


def test_doble_start_no_duplica_muestreo():
    count = {"n": 0}
    original = _procmon.sample_processes

    def counted(cpu_count=None):
        count["n"] += 1
        return []
    _procmon.sample_processes = counted
    try:
        pm = _monitor()
        pm.start()                      # 1 muestreo
        pm.start()                      # ya en marcha: no debe muestrear de nuevo
        assert count["n"] == 1
        pm.stop()
    finally:
        _procmon.sample_processes = original


def test_guard_sampling_evita_solapamiento():
    count = {"n": 0}
    original = _procmon.sample_processes

    def counted(cpu_count=None):
        count["n"] += 1
        return []
    _procmon.sample_processes = counted
    try:
        pm = _monitor()
        pm._sampling = True
        pm._tick()                      # debe saltar por el guard de muestreo en curso
        assert count["n"] == 0
        pm._sampling = False
        pm._tick()
        assert count["n"] == 1
        pm.stop()
    finally:
        _procmon.sample_processes = original


# --- 5) el intervalo se respeta y se aplica en caliente ----------------------------------------
def test_intervalo_configurable_se_aplica():
    restore = _patch_sample(_rows())
    try:
        pm = _monitor()
        pm.interval.setCurrentIndex(0)  # 1 s
        pm.start()
        assert pm.timer.interval() == 1000
        pm.interval.setCurrentIndex(3)  # 5 s, en caliente
        assert pm.timer.interval() == 5000
        pm.stop()
    finally:
        restore()


# --- 6) cierre: el temporizador queda liberado -------------------------------------------------
def test_cierre_libera_el_temporizador():
    restore = _patch_sample(_rows())
    try:
        pm = _monitor()
        pm.start()
        assert pm.timer.isActive()
        pm.stop()
        assert not pm.timer.isActive()
        pm.stop()                       # parar dos veces es seguro
        assert not pm.timer.isActive()
    finally:
        restore()


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
