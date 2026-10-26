# -*- coding: utf-8 -*-
"""
Plantilla de plugin. Este fichero empieza por "_", así que el cargador lo ignora.

Para crear un módulo nuevo:
  1. Copia este fichero como NN_nombre.py (NN fija el orden de ejecución, p. ej. 10_usb.py).
  2. Cambia key, title y description. `key` es lo que se escribe en -m y debe ser única.
  3. Escribe tus comprobaciones como métodos y devuélvelas en checks().
  4. Comprueba que se detecta:  python auditor.py --listar

Reglas del proyecto:
  · Solo lectura: consulta el sistema, nunca lo modifiques.
  · Informa con self.add(SEVERIDAD, título, detalle, recomendación).
  · Si falta un permiso o una herramienta, lanza CheckSkipped("motivo"): el
    núcleo lo convierte en [SKIP] y la auditoría continúa. Cualquier otra
    excepción también se captura, pero un mensaje claro ayuda al usuario.
  · Si una comprobación emite varios hallazgos, pasa key="..." a self.add()
    para que el modo --diff los reconozca entre ejecuciones; para valores que
    crecen (intentos, eventos...), pasa también metric=número.
"""

from __future__ import annotations

from ._base import IS_WINDOWS, PASS, WARNING, AuditModule, CheckSkipped
from ._utilidades import reg_get


class EjemploModule(AuditModule):
    key = "ejemplo"
    title = "EJEMPLO"
    description = "Plantilla: comprueba si la protección de AutoPlay está activa"

    def checks(self):
        # Devuelve solo las comprobaciones aplicables al SO actual; una lista vacía
        # hace que el módulo se marque como "no compatible con este sistema operativo".
        return [self.check_autoplay] if IS_WINDOWS else []

    def check_autoplay(self):
        """Reproducción automática (AutoPlay)"""  # 1ª línea del docstring = etiqueta del [SKIP]
        value = reg_get(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
                        "DisableAutoplay")
        if value is None:
            raise CheckSkipped("No se encontró la configuración de AutoPlay")
        if value == 1:
            self.add(PASS, "AutoPlay desactivado para este usuario")
        else:
            self.add(WARNING, "AutoPlay activado para este usuario",
                     "Al conectar un USB o un disco, Windows ofrece abrir su contenido automáticamente.",
                     "Desactívalo en Configuración > Bluetooth y dispositivos > Reproducción automática.")
