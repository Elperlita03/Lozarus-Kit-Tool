# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_rendimiento_disco.py. TODA la E/S va sobre árboles temporales propios de la prueba
(nunca sobre %TEMP%, las cachés reales ni el perfil de quien ejecuta): las raíces de cada categoría se
inyectan con `roots` y el perfil con `env`. Cubren:

  · lógica pura: formato de tamaños, nivel de uso de un volumen, validación de raíces peligrosas y de la
    ruta REAL que devuelve Windows tras abrir un archivo (uniones que desvían el borrado);
  · que el análisis no borra nada y cuenta por antigüedad;
  · que la limpieza respeta la antigüedad, no sigue enlaces, no toca lo que está fuera de la raíz, poda
    solo carpetas vacías y antiguas y nunca la raíz;
  · que las categorías de Administrador o con el navegador abierto no se tocan, ni las rutas rechazadas;
  · que la optimización de la unidad no ejecuta nada fuera de Windows ni sin Administrador.
"""

import ntpath
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos import _rendimiento_disco as rd  # noqa: E402

GB = 1024 ** 3
OLD = time.time() - 72 * 3600


def _file(path, size=1024, old=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"x" * size)
    if old:
        os.utime(path, (OLD, OLD))
    return path


def _sandbox():
    """Perfil de pega con Documentos y una carpeta de temporales con archivos antiguos y recientes."""
    base = tempfile.mkdtemp(prefix="lz_disco_")
    home = os.path.join(base, "home")
    temp = os.path.join(home, "AppData", "Local", "Temp")
    os.makedirs(os.path.join(home, "Documents"))
    _file(os.path.join(temp, "viejo.tmp"), 2048, old=True)
    _file(os.path.join(temp, "nuevo.tmp"), 512)
    _file(os.path.join(temp, "instalador", "paquete.cab"), 4096, old=True)
    os.utime(os.path.join(temp, "instalador"), (OLD, OLD))
    env = {"HOME": home, "USERPROFILE": home}
    return base, home, temp, env


def test_human_bytes_y_nivel_de_volumen():
    assert rd.human_bytes(None) == "—"
    assert rd.human_bytes(0) == "0 B"
    assert rd.human_bytes(2048) == "2 KB"
    assert rd.human_bytes(5 * 1024 ** 2) == "5.0 MB"
    assert rd.human_bytes(1.5 * GB) == "1.5 GB"
    assert rd.volume_level(50, 100 * GB, 200 * GB) == "ok"
    assert rd.volume_level(88, 24 * GB, 200 * GB) == "warn"
    assert rd.volume_level(96, 8 * GB, 200 * GB) == "critical"
    assert rd.volume_level(70, int(1.5 * GB), 200 * GB) == "critical"   # poco margen absoluto en un disco grande
    assert rd.volume_level(80, 100 * 1024 ** 2, GB // 2) == "ok"        # partición pequeña: solo cuenta el %


def test_check_root_rechaza_rutas_peligrosas():
    base, home, temp, env = _sandbox()
    try:
        assert rd.check_root(temp, env)[0] is True
        assert rd.check_root(os.path.join(home, ".cache", "thumbnails"), env)[0] is True
        for bad in ("relativa/ruta", os.path.abspath(os.sep), home, os.path.dirname(home),
                    os.path.join(home, "Documents", "Temp")):
            ok, why = rd.check_root(bad, env)
            assert ok is False and why, bad
        if hasattr(os, "symlink"):
            link = os.path.join(base, "Temp")
            try:
                os.symlink(os.path.join(home, "Documents"), link)
            except OSError:
                return  # sin permiso para crear enlaces (Windows sin modo desarrollador)
            ok, why = rd.check_root(link, env)
            assert ok is False and "personal" in why   # se juzga la ruta REAL, no el nombre del enlace
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_temp_debe_parecer_temporales():
    assert rd._expected("user_temp", os.path.join("C:", "Users", "x", "AppData", "Local", "Temp"))
    assert rd._expected("user_temp", os.path.join("C:", "Users", "x", "AppData", "Local", "Temp", "2"))
    assert not rd._expected("user_temp", os.path.join("C:", "Users", "x", "Proyectos"))
    assert rd._expected("chrome", os.path.join("C:", "cualquier", "ruta"))


def test_final_path_inside_detecta_uniones():
    root = ntpath.normcase(r"C:\Users\Bob\AppData\Local\Temp")
    assert rd.final_path_inside("\\\\?\\C:\\Users\\Bob\\AppData\\Local\\Temp\\x\\f.tmp", root)
    assert rd.final_path_inside(r"c:\users\bob\appdata\local\temp\f.tmp", root)
    assert not rd.final_path_inside("\\\\?\\C:\\Windows\\System32\\drivers\\x.sys", root)   # desviado
    assert not rd.final_path_inside("\\\\?\\C:\\Users\\Bob\\AppData\\Local\\Temp2\\f.tmp", root)
    assert not rd.final_path_inside("\\\\?\\D:\\Temp\\f.tmp", root)
    assert not rd.final_path_inside("", root)
    unc = ntpath.normcase(r"\\srv\share\temp")
    assert rd.final_path_inside("\\\\?\\UNC\\srv\\share\\temp\\a\\b.tmp", unc)


def test_analisis_no_borra_y_cuenta_por_antiguedad():
    base, _home, temp, env = _sandbox()
    try:
        res = rd.scan_targets(["user_temp"], age_h=24, roots={"user_temp": [temp]}, env=env, admin=False,
                              running=[])
        row = res["targets"][0]
        assert row["status"] == "ok" and row["files"] == 3
        assert row["eligible_files"] == 2 and row["eligible_bytes"] == 2048 + 4096
        assert row["recent_files"] == 1
        assert res["eligible_bytes"] == 2048 + 4096
        for name in ("viejo.tmp", "nuevo.tmp", os.path.join("instalador", "paquete.cab")):
            assert os.path.exists(os.path.join(temp, name)), name   # el análisis no toca nada
        res = rd.scan_targets(["user_temp"], age_h=24, roots={"user_temp": [temp]}, env=env, admin=False,
                              running=[], deadline_s=0)
        assert res["targets"][0]["partial"] is True
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_limpieza_respeta_antiguedad_enlaces_y_raiz():
    base, _home, temp, env = _sandbox()
    try:
        outside = os.path.join(base, "fuera")
        victim = _file(os.path.join(outside, "importante.doc"), 300, old=True)
        linked = False
        if hasattr(os, "symlink"):
            try:
                os.symlink(outside, os.path.join(temp, "enlace_carpeta"))
                os.symlink(victim, os.path.join(temp, "enlace_archivo.tmp"))
                linked = True
            except OSError:
                pass
        res = rd.clean_targets(["user_temp"], age_h=24, roots={"user_temp": [temp]}, env=env, admin=False,
                               running=[])
        row = res["targets"][0]
        assert row["status"] == "ok"
        assert row["deleted"] == 2 and row["freed"] == 2048 + 4096 and res["freed"] == row["freed"]
        assert not os.path.exists(os.path.join(temp, "viejo.tmp"))
        assert os.path.exists(os.path.join(temp, "nuevo.tmp"))          # reciente: se respeta
        assert not os.path.exists(os.path.join(temp, "instalador"))     # vacía y antigua: se poda
        assert os.path.isdir(temp)                                       # la raíz nunca se borra
        assert os.path.exists(victim)                                    # nada fuera de la raíz
        if linked:
            assert os.path.islink(os.path.join(temp, "enlace_carpeta"))
            assert os.path.islink(os.path.join(temp, "enlace_archivo.tmp"))
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_dry_run_no_borra():
    base, _home, temp, env = _sandbox()
    try:
        res = rd.clean_targets(["user_temp"], age_h=24, roots={"user_temp": [temp]}, env=env, admin=False,
                               running=[], dry_run=True)
        assert res["dry_run"] is True and res["deleted"] == 2 and res["freed"] == 2048 + 4096
        assert os.path.exists(os.path.join(temp, "viejo.tmp"))
        assert os.path.exists(os.path.join(temp, "instalador", "paquete.cab"))
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_patrones_y_sin_recursion():
    base = tempfile.mkdtemp(prefix="lz_disco_")
    try:
        _file(os.path.join(base, "thumbcache_256.db"))
        _file(os.path.join(base, "iconcache_32.db"))
        _file(os.path.join(base, "otro.db"))
        _file(os.path.join(base, "sub", "thumbcache_1024.db"))
        target = rd.Target("prueba", "user", "", "", patterns=("thumbcache_*.db", "iconcache_*.db"),
                           recursive=False)
        names = sorted(os.path.basename(p) for p, _st in rd._iter_files(base, target, time.monotonic() + 30))
        assert names == ["iconcache_32.db", "thumbcache_256.db"]
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_admin_y_navegador_abierto_no_se_tocan():
    base, _home, temp, env = _sandbox()
    try:
        cache = os.path.join(base, "chrome", "Default", "Cache")
        _file(os.path.join(cache, "f_000001"), 1000)
        res = rd.clean_targets(["system_temp", "chrome"], age_h=24, env=env, admin=False,
                               roots={"system_temp": [temp], "chrome": [cache]}, running=["chrome.exe"])
        by_key = {r["key"]: r for r in res["targets"]}
        assert by_key["system_temp"]["status"] == "admin" and by_key["system_temp"]["deleted"] == 0
        assert by_key["chrome"]["status"] == "in_use" and "chrome" in by_key["chrome"]["note"]
        assert os.path.exists(os.path.join(temp, "viejo.tmp"))
        assert os.path.exists(os.path.join(cache, "f_000001"))
        assert set(res["skipped"]) == {"system_temp", "chrome"}
        # Con el navegador cerrado, su caché se limpia sea cual sea la antigüedad (age_h = 0).
        res = rd.clean_targets(["chrome"], age_h=168, env=env, admin=False, roots={"chrome": [cache]}, running=[])
        assert res["targets"][0]["deleted"] == 1 and not os.path.exists(os.path.join(cache, "f_000001"))
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_ruta_rechazada_no_se_toca():
    base, home, _temp, env = _sandbox()
    try:
        doc = _file(os.path.join(home, "Documents", "tesis.docx"), 100, old=True)
        res = rd.clean_targets(["inet_cache"], age_h=24, env=env, admin=True, running=[],
                               roots={"inet_cache": [os.path.join(home, "Documents")]})
        row = res["targets"][0]
        assert row["status"] == "unsafe" and row["deleted"] == 0 and "seguridad" in row["note"].lower()
        assert os.path.exists(doc)
        scan = rd.scan_targets(["user_temp"], env=env, admin=False, running=[], roots={"user_temp": [home]})
        assert scan["targets"][0]["status"] == "unsafe" and scan["eligible_bytes"] == 0
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_consumidores_de_espacio():
    base = tempfile.mkdtemp(prefix="lz_espacio_")
    try:
        _file(os.path.join(base, "Videos", "peli.mkv"), 50_000)
        _file(os.path.join(base, "Videos", "corto.mp4"), 20_000)
        _file(os.path.join(base, "Documents", "a.txt"), 10)
        _file(os.path.join(base, "Downloads", "setup.exe"), 30_000)
        res = rd.space_consumers(base, top=2, folders=(("Vídeos", "Videos"), ("Documentos", "Documents"),
                                                       ("Descargas", "Downloads"), ("No existe", "Nada")))
        assert [f["label"] for f in res["folders"]] == ["Vídeos", "Descargas", "Documentos"]
        assert res["folders"][0]["bytes"] == 70_000 and res["total"] == 100_010
        assert [f["name"] for f in res["largest"]] == ["peli.mkv", "setup.exe"]
        assert res["partial"] is False
        assert rd.space_consumers(base, deadline_s=0, folders=(("Vídeos", "Videos"),))["partial"] is True
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_volumenes_y_discos():
    vols = rd.analyze_volumes()
    assert isinstance(vols, list) and sum(1 for v in vols if v["system"]) <= 1
    for v in vols:
        assert v["level"] in ("ok", "warn", "critical") and 0 <= v["percent"] <= 100
    disks = [{"letters": ["C"], "media": "SSD", "label": "SANO", "level": "ok", "model": "NVMe"}]
    out = rd.attach_disks([{"letter": "C"}, {"letter": "D"}, {"letter": ""}], disks)
    assert out[0]["media"] == "SSD" and out[0]["health"] == "SANO" and "media" not in out[1]


def test_optimizar_unidad_no_ejecuta_sin_windows_ni_admin():
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return {"rc": 0, "output": "Optimization: 100% complete.\nThe operation completed successfully.",
                "cancelled": False, "timed_out": False, "seconds": 1.0}

    orig = rd.IS_WINDOWS
    try:
        rd.IS_WINDOWS = False
        res = rd.optimize_volume(admin=True, runner=runner)
        assert res["ok"] is False and "Windows" in res["message"] and calls == []
        rd.IS_WINDOWS = True
        res = rd.optimize_volume("C:", admin=False, runner=runner)
        assert res["ok"] is False and "Administrador" in res["message"] and calls == []
        res = rd.optimize_volume("C: & del *", admin=True, runner=runner)   # nada que no sea «X:»
        assert res["ok"] is False and calls == []
        res = rd.optimize_volume("d:", admin=True, runner=runner)
        assert res["ok"] is True and calls[-1][1:] == ["D:", "/O", "/U"] and res["command"] == "defrag D: /O /U"
        res = rd.optimize_volume("C:", admin=True, runner=lambda argv, **k: {"rc": 1, "output": "", "cancelled": True,
                                                                             "timed_out": False, "seconds": 2.0})
        assert res["ok"] is False and res["cancelled"] is True and "cancelada" in res["message"].lower()
    finally:
        rd.IS_WINDOWS = orig


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
