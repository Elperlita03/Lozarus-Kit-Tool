# -*- coding: utf-8 -*-
"""
Pruebas de modulos/_privacidad.py. E/S real SIEMPRE sobre directorios/ficheros temporales propios de
la prueba; nunca sobre el %TEMP% real del usuario ni sobre su portapapeles:

  · shred_file: tritura un fichero de prueba y comprueba que desaparece; caso de archivo inexistente.
  · looks_sensitive: heurística pura (frase semilla, dirección cripto, clave, tarjeta, texto normal).
  · clean_temp: sobre una carpeta temporal de pega; comprueba el recuento y que un fichero abierto se
    OMITE (no se fuerza) en Windows.
  · read_clipboard_text: solo se comprueba que no lanza y devuelve None o str (lectura inocua).

No se llama a clear_clipboard() para no vaciar el portapapeles real de quien ejecuta las pruebas, ni
a clean_temp() sin argumento (que actuaría sobre el %TEMP% real).
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modulos._privacidad import (clean_temp, looks_sensitive, read_clipboard_text,  # noqa: E402
                                 shred_file)


def test_shred_file_sobrescribe_y_borra():
    tmp = tempfile.mkdtemp(prefix="shred_")
    try:
        fp = os.path.join(tmp, "secreto.txt")
        with open(fp, "wb") as fh:
            fh.write(b"datos confidenciales" * 100)
        size = os.path.getsize(fp)
        res = shred_file(fp, passes=2)
        assert res["ok"] is True
        assert res["bytes"] == size and res["passes"] == 2
        assert res["renombrado"] is True     # se renombró antes de borrar (limpia la MFT)
        assert not os.path.exists(fp)        # el fichero ya no está
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_shred_file_vacio():
    tmp = tempfile.mkdtemp(prefix="shred_")
    try:
        fp = os.path.join(tmp, "vacio.bin")
        open(fp, "wb").close()
        res = shred_file(fp)
        assert res["ok"] is True and res["bytes"] == 0 and not os.path.exists(fp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_shred_file_inexistente_no_lanza():
    res = shred_file(os.path.join(tempfile.gettempdir(), "no_existe_lozarus_zzz.bin"))
    assert res["ok"] is False and res["error"]


def test_looks_sensitive_detecta():
    seed = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    assert looks_sensitive(seed)[0] is True
    assert "semilla" in looks_sensitive(seed)[1].lower()
    assert looks_sensitive("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")[0] is True          # BTC
    assert looks_sensitive("0x52908400098527886E0F7030069857D2E4169EE7")[0] is True  # ETH
    assert looks_sensitive("a" * 64)[0] is True                                      # hex de 64
    assert looks_sensitive("4111 1111 1111 1111")[0] is True                         # tarjeta
    assert looks_sensitive("sk-ABCDEFGHIJKLMNOPQRSTUVWX")[0] is True                 # token API


def test_looks_sensitive_texto_normal_y_vacio():
    assert looks_sensitive("Hola, ¿quedamos mañana para revisar el informe del proyecto?")[0] is False
    assert looks_sensitive("")[0] is False
    assert looks_sensitive(None)[0] is False


def test_clean_temp_cuenta_y_omite_bloqueados():
    tmp = tempfile.mkdtemp(prefix="temp_")
    fh = None
    try:
        for i in range(3):
            with open(os.path.join(tmp, f"f{i}.tmp"), "wb") as f:
                f.write(b"x" * 1024)
        os.makedirs(os.path.join(tmp, "sub"), exist_ok=True)
        with open(os.path.join(tmp, "sub", "s.tmp"), "wb") as f:
            f.write(b"y" * 512)
        # un fichero abierto y sin cerrar: en Windows no se puede borrar → debe omitirse
        bloqueado = os.path.join(tmp, "bloqueado.tmp")
        fh = open(bloqueado, "wb")
        fh.write(b"z" * 256)
        fh.flush()

        res = clean_temp(base=tmp)
        assert res["ok"] is True and res["dir"] == tmp
        assert res["eliminados"] >= 4        # los 3 + el de la subcarpeta
        assert res["bytes"] >= 3 * 1024 + 512
        if sys.platform == "win32":
            assert res["omitidos"] >= 1 and os.path.exists(bloqueado)  # el abierto sobrevivió
    finally:
        if fh is not None:
            fh.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_clean_temp_carpeta_inexistente():
    res = clean_temp(base=os.path.join(tempfile.gettempdir(), "no_existe_lozarus_dir_zzz"))
    assert res["ok"] is False and res["error"]


def test_read_clipboard_no_lanza():
    val = read_clipboard_text()  # lectura inocua: None o str
    assert val is None or isinstance(val, str)


def test_prototipos_portapapeles_son_de_64_bits():
    # Regresión del segfault: sin restype, GetClipboardData devolvía el HANDLE truncado a int de 32
    # bits y GlobalLock desreferenciaba basura. Comprobación determinista: NO toca el portapapeles.
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    from modulos._privacidad import _clipboard_api
    _c, u, k = _clipboard_api()
    assert u.GetClipboardData.restype is wintypes.HANDLE
    assert k.GlobalLock.restype is wintypes.LPVOID
    assert ctypes.sizeof(u.GetClipboardData.restype) == ctypes.sizeof(ctypes.c_void_p)
    assert u is not ctypes.windll.user32  # WinDLL privado: no altera los prototipos compartidos


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
