# -*- coding: utf-8 -*-
"""
Notificaciones nativas del sistema para el Modo Centinela de Lozarus Kit Tool.

  · notify(): lanza una notificación de escritorio con plyer desde un hilo propio, de
    modo que la interfaz nunca espera a Windows (plyer mantiene vivo el aviso con un
    time.sleep durante 'timeout' segundos).
  · Sentinel: registro anti-spam en memoria. Cada proceso, identificado por PID e
    instante de creación (un PID reutilizado por otro programa cuenta como nuevo), se
    notifica una sola vez, y solo vuelve a avisar si su alerta sube de WARNING a
    CRITICAL. El registro se limpia cuando el proceso termina.

Solo lectura: este módulo no modifica nada del sistema, únicamente muestra avisos.
Dependencia opcional:  pip install plyer   (sin ella el centinela queda desactivado)
Prueba rápida desde la carpeta del proyecto:  python -m modulos._alertas
"""

from __future__ import annotations

import os
import threading
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ._base import CRITICAL, INFO, WARNING, Severity

try:
    from plyer import notification  # pip install plyer
    HAS_PLYER = True
except ImportError:
    notification = None
    HAS_PLYER = False

APP_NAME = "Lozarus Kit Tool"
LEVEL_LABELS = {CRITICAL: "🔴 CRITICAL", WARNING: "🟡 WARNING", INFO: "🔵 INFO"}
ICON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "lozarus.ico")
TITLE_MAX, MESSAGE_MAX = 63, 255  # límites de Windows para el título y el texto del aviso


def notify(severity: Severity, message: str, timeout: int = 8) -> bool:
    """
    Muestra "Lozarus Security | <nivel>" con el mensaje indicado. Vuelve al instante: el
    envío se hace en un hilo 'daemon'. Devuelve False si plyer no está disponible.
    """
    if not HAS_PLYER:
        return False
    title = f"Lozarus Security | {LEVEL_LABELS.get(severity, severity.value)}"[:TITLE_MAX]
    text = message if len(message) <= MESSAGE_MAX else message[:MESSAGE_MAX - 1] + "…"
    icon = ICON if os.path.exists(ICON) else ""

    def send() -> None:
        try:
            notification.notify(title=title, message=text, app_name=APP_NAME, app_icon=icon, timeout=timeout)
        except Exception:
            pass  # un fallo al notificar nunca debe afectar a la auditoría ni a la interfaz

    threading.Thread(target=send, daemon=True, name="notificacion").start()
    return True


def describe_threats(alerts: List) -> Tuple[Severity, str]:
    """Texto del aviso para una o varias amenazas nuevas (las detectadas en la misma muestra
    se agrupan en un solo aviso para no llenar la pantalla)."""
    worst = CRITICAL if any(a.severity is CRITICAL for a in alerts) else WARNING
    if len(alerts) == 1:
        a = alerts[0]
        return worst, f"Proceso sospechoso detectado: {a.name} (PID: {a.pid})\nMotivo: {a.reasons[0]}"
    # Windows muestra unas 4 líneas: cabecera corta y una línea por proceso (el motivo de cada
    # uno está en el Monitor en Vivo; el aviso individual sí lo incluye)
    head = f"{len(alerts)} procesos sospechosos detectados:"
    lines = [f"• {a.name} (PID: {a.pid})" for a in alerts[:3]]
    if len(alerts) > 3:
        lines[-1] = f"• … y {len(alerts) - 2} más en el Monitor en Vivo"
    return worst, head + "\n" + "\n".join(lines)


class Sentinel:
    """Anti-spam del Modo Centinela: deja pasar solo las amenazas nuevas."""

    RANK = {WARNING: 1, CRITICAL: 2}

    def __init__(self):
        self.notified: Dict[Tuple[int, float], Severity] = {}  # (pid, creación) -> nivel ya avisado

    def new_threats(self, alerts: Iterable, running_pids: Optional[Set[int]] = None) -> List:
        """Devuelve las alertas que aún no se han notificado y las registra. Debe llamarse con
        cada muestra, esté el aviso activado o no: así, al activar el Modo Centinela no salta
        de golpe todo lo que ya estaba en la tabla."""
        fresh = []
        for alert in alerts:
            key = (alert.pid, getattr(alert, "created", 0))
            before = self.notified.get(key)
            if before is None or self.RANK.get(alert.severity, 0) > self.RANK.get(before, 0):
                fresh.append(alert)
                self.notified[key] = alert.severity
        if running_pids is not None:  # olvida los procesos que ya han terminado
            self.notified = {k: v for k, v in self.notified.items() if k[0] in running_pids}
        return fresh


if __name__ == "__main__":  # python -m modulos._alertas  -> aviso de prueba
    if notify(CRITICAL, "Proceso sospechoso detectado: prueba.exe (PID: 4012)\n"
                        "Motivo: alerta de prueba de Lozarus Kit Tool", timeout=6):
        print("Notificación de prueba enviada: debería aparecer en la esquina inferior derecha.")
        threading.Event().wait(7)  # mantiene vivo el proceso mientras se muestra el aviso
    else:
        print("plyer no está instalado:  pip install plyer")
