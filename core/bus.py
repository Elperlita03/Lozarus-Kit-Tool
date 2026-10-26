# -*- coding: utf-8 -*-
"""
Bus de eventos de Lozarus: conecta los colectores (productores) con los motores de detección
(consumidores) a través de una **cola acotada**, en un hilo de despacho propio y **sin ninguna
dependencia de Qt/PySide6**. Un adaptador a la GUI (que marshalea al hilo de la interfaz) vendrá
en otra capa; el bus no sabe nada de widgets.

Garantías REALES (documentadas, no prometidas de más):
  - **Orden:** FIFO dentro del bus; los eventos se entregan en el orden en que se encolaron. El bus
    NO reordena por tiempo de evento (eso es tarea de la correlación, con tolerancia).
  - **Entrega:** **como máximo una vez** por evento encolado. Ante cola llena se DESCARTA según la
    política y se cuenta en `dropped`. No hay entrega «exactamente una vez» (no existe tal mecanismo).
  - **Duplicados:** el bus no introduce duplicados.
  - **Pérdidas:** los descartes INTERNOS del bus (`dropped`) se contabilizan aparte de las pérdidas
    de la FUENTE (p. ej. EventsLost de ETW, en `SensorHealth`). Son contadores distintos.
  - **Sin bloqueos indefinidos:** la política BLOCK usa un timeout finito; el despacho hace `get`
    con timeout; `stop()` siempre termina el hilo.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional

from .errors import BusError
from .events import Event

Subscriber = Callable[[Event], None]


class OverflowPolicy(str, Enum):
    """Qué hacer cuando la cola está llena al publicar."""
    DROP_NEWEST = "drop_newest"   # descarta el evento entrante (por defecto)
    DROP_OLDEST = "drop_oldest"   # descarta el más antiguo y encola el nuevo
    BLOCK = "block"               # espera hasta `block_timeout` y, si no cabe, descarta


@dataclass
class BusMetrics:
    """Instantánea de métricas del bus. `dropped` son descartes INTERNOS (no de la fuente)."""
    published: int = 0            # intentos de publicación
    enqueued: int = 0            # encolados con éxito
    delivered: int = 0           # eventos despachados a los suscriptores
    dropped: int = 0             # descartados por cola llena (política de overflow)
    subscriber_errors: int = 0   # excepciones lanzadas por callbacks de suscriptores
    max_depth: int = 0           # profundidad máxima observada de la cola
    current_depth: int = 0       # profundidad actual (aproximada)


class EventBus:
    """
    Bus desacoplado con cola acotada y un hilo de despacho. Implementa el Protocol `EventSink`
    (`publish`). Los suscriptores se ejecutan en el hilo de despacho: deben ser rápidos y NO ser
    widgets de Qt (para la GUI, usar un adaptador que marshalee al hilo de la interfaz).
    """

    def __init__(self, maxsize: int = 1024, policy: OverflowPolicy = OverflowPolicy.DROP_NEWEST,
                 block_timeout: float = 0.1, name: str = "bus"):
        if maxsize <= 0:
            raise BusError("maxsize debe ser > 0 (la cola debe estar acotada)")
        self.name = name
        self._policy = policy
        self._block_timeout = max(0.0, float(block_timeout))  # finito: nunca espera indefinidamente
        self._q: "queue.Queue[Event]" = queue.Queue(maxsize=maxsize)
        self._subscribers: List[Subscriber] = []
        self._lock = threading.Lock()         # protege métricas y el drop+put de DROP_OLDEST
        self._sub_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._drain_on_stop = True
        # métricas
        self._published = self._enqueued = self._delivered = 0
        self._dropped = self._sub_errors = self._max_depth = 0

    # --- Suscripción -------------------------------------------------------------------------
    def subscribe(self, callback: Subscriber) -> None:
        """Registra un consumidor. Se invoca en el hilo de despacho; debe ser no bloqueante."""
        with self._sub_lock:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Subscriber) -> None:
        with self._sub_lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    # --- Publicación (EventSink) -------------------------------------------------------------
    def publish(self, event: Event) -> bool:
        """
        Encola un evento según la política de overflow. Devuelve True si se encoló, False si se
        descartó. Thread-safe y sin bloqueos indefinidos. Puede llamarse antes de `start()`
        (los eventos quedan en la cola hasta que arranca el despacho).
        """
        with self._lock:
            self._published += 1

        enqueued = False
        if self._policy is OverflowPolicy.BLOCK:
            try:
                self._q.put(event, timeout=self._block_timeout)
                enqueued = True
            except queue.Full:
                enqueued = False
        elif self._policy is OverflowPolicy.DROP_OLDEST:
            with self._lock:  # drop del más antiguo + put, atómico frente a otros publicadores
                if self._q.full():
                    try:
                        self._q.get_nowait()
                        self._dropped += 1
                    except queue.Empty:
                        pass
                try:
                    self._q.put_nowait(event)
                    enqueued = True
                except queue.Full:
                    enqueued = False
        else:  # DROP_NEWEST
            try:
                self._q.put_nowait(event)
                enqueued = True
            except queue.Full:
                enqueued = False

        with self._lock:
            if enqueued:
                self._enqueued += 1
                depth = self._q.qsize()
                if depth > self._max_depth:
                    self._max_depth = depth
            else:
                if self._policy is not OverflowPolicy.DROP_OLDEST:  # DROP_OLDEST ya contó su descarte
                    self._dropped += 1
        return enqueued

    # --- Ciclo de vida -----------------------------------------------------------------------
    def start(self) -> None:
        """Arranca el hilo de despacho (idempotente)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=f"eventbus-{self.name}", daemon=True)
        self._thread.start()

    def stop(self, drain: bool = True, timeout: float = 2.0) -> None:
        """Detiene el despacho. Si `drain`, procesa lo que quede en la cola antes de salir. Idempotente."""
        self._drain_on_stop = drain
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        self._thread = None

    def flush(self, timeout: float = 2.0) -> bool:
        """Espera (hasta `timeout`) a que la cola se vacíe. Útil para pruebas deterministas."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._q.empty():
                return True
            time.sleep(0.005)
        return self._q.empty()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            self._dispatch(event)
        if self._drain_on_stop:  # vaciar lo pendiente al cerrar
            while True:
                try:
                    event = self._q.get_nowait()
                except queue.Empty:
                    break
                self._dispatch(event)

    def _dispatch(self, event: Event) -> None:
        with self._sub_lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:  # un suscriptor que falla NUNCA tumba el bus
                with self._lock:
                    self._sub_errors += 1
        with self._lock:
            self._delivered += 1

    # --- Métricas ----------------------------------------------------------------------------
    def metrics(self) -> BusMetrics:
        with self._lock:
            return BusMetrics(
                published=self._published, enqueued=self._enqueued, delivered=self._delivered,
                dropped=self._dropped, subscriber_errors=self._sub_errors,
                max_depth=self._max_depth, current_depth=self._q.qsize(),
            )
