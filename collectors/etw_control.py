# -*- coding: utf-8 -*-
"""
Control del colector ETW desde la interfaz: requisitos, arranque/parada y estado vivo.

El colector (`etw_collector.EtwCollector`) publica eventos normalizados en el bus de la GUI, que la
Caja Negra persiste. ETW de kernel exige Administrador y la biblioteca pywintrace; si falta algo,
`readiness()` dice exactamente qué y cómo resolverlo, y no se intenta nada. `start()`/`stop()`
pueden tardar (abrir/cerrar la sesión ETW): la GUI los llama desde un hilo de fondo.

IMPORTANTE: una sesión ETW sobrevive al proceso que la creó si no se detiene. La GUI llama a
`stop()` en su cierre ordenado; este controlador nunca deja una sesión propia abierta a sabiendas.
"""

import importlib.util
from typing import Any, Callable, Dict, Optional, Tuple

from collectors.etw_collector import EtwCollector


def pywintrace_available() -> bool:
    """¿Está pywintrace (módulo `etw`) en ESTE entorno de Python? Sin importarlo (solo lo busca)."""
    return importlib.util.find_spec("etw") is not None


def readiness(is_admin: bool, has_pywintrace: bool, has_bus: bool) -> Tuple[bool, str]:
    """(se_puede_iniciar, guía). Pura: el orden de los avisos va de lo más a lo menos bloqueante."""
    if not has_bus:
        return False, "El núcleo de eventos no está activo en esta sesión: el colector no tendría destino."
    if not has_pywintrace:
        return False, ("pywintrace no está instalado en este entorno de Python. Instálalo con "
                       "«py -m pip install pywintrace==0.2.0» o ejecuta Lozarus con el entorno de "
                       "spikes/etw/.venv.")
    if not is_admin:
        return False, ("La telemetría ETW de kernel requiere Administrador: usa «Relanzar como "
                       "Administrador (UAC)».")
    return True, "Listo: el colector puede iniciarse (proveedor Kernel-Process)."


class EtwController:
    """Envuelve un EtwCollector conectado al bus. `session_factory` permite inyectar un doble."""

    def __init__(self, bus: Any, provider: str = "kernel-process",
                 session_factory: Optional[Callable[..., Any]] = None):
        self._bus = bus
        self._provider = provider
        self._factory = session_factory
        self._collector: Optional[EtwCollector] = None
        self._last: Dict[str, Any] = {"received": 0, "published": 0, "dropped": 0, "errors": 0}
        self.last_error: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._collector is not None and self._collector.metrics().started

    def start(self) -> Dict[str, Any]:
        """Abre la sesión ETW (bloqueante: llamar desde un hilo). Nunca lanza; el fallo queda en
        `last_error` (permisos, pywintrace ausente, sesión rechazada…)."""
        if self.running:
            return self.status()
        kwargs = {"session_factory": self._factory} if self._factory is not None else {}
        collector = EtwCollector(self._bus, self._provider, **kwargs)
        collector.start()
        m = collector.metrics()
        if m.started:
            self._collector, self.last_error = collector, None
        else:
            self._collector, self.last_error = None, m.init_error or "no se pudo iniciar la sesión ETW"
        return self.status()

    def stop(self) -> Dict[str, Any]:
        """Cierra la sesión propia (idempotente). Conserva las últimas métricas para mostrarlas."""
        collector = self._collector
        if collector is not None:
            collector.stop()
            m = collector.metrics()
            self._last = {"received": m.events_received, "published": m.events_published,
                          "dropped": m.bus_dropped, "errors": m.consumer_errors}
            self._collector = None
        return self.status()

    def status(self) -> Dict[str, Any]:
        """Estado vivo: running, contadores (de la sesión actual o de la última) y error."""
        collector = self._collector
        if collector is None:
            return {"running": False, "error": self.last_error, **self._last}
        m = collector.metrics()
        return {"running": m.started, "error": m.init_error, "received": m.events_received,
                "published": m.events_published, "dropped": m.bus_dropped,
                "errors": m.consumer_errors, "session": m.session_name}
