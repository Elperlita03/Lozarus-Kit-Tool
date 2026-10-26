# -*- coding: utf-8 -*-
"""
Caja Negra: consumidor del EventBus que PERSISTE cada evento en un diario JSONL append-only.

Diseño (coherente con core/bus.py, cuyos suscriptores corren en el hilo de despacho y deben ser
RÁPIDOS y no bloqueantes):

  bus → `_on_event` (encola, no bloquea) → cola interna → hilo escritor → disco (JSONL)

El suscriptor solo encola (operación rápida); un hilo escritor propio hace la E/S, de modo que ni el
bus ni la GUI se bloquean por el disco. Rota el fichero por tamaño. Las métricas distinguen eventos
recibidos, escritos, descartados por cola llena y errores de escritura (desconocido nunca es 0 falso).

No termina procesos, no modifica el sistema: solo observa y guarda.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from typing import Any, Dict, Optional


class CajaNegra:
    """Persiste en JSONL los eventos publicados en un EventBus. Pensada para solo lectura/registro."""

    def __init__(self, directory: str, filename: str = "eventos.jsonl",
                 max_bytes: int = 5 * 1024 * 1024, maxsize: int = 10000):
        self._dir = directory
        self._path = os.path.join(directory, filename)
        self._max_bytes = max_bytes
        self._queue: "queue.Queue[Any]" = queue.Queue(maxsize=maxsize)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._fh = None
        # Métricas (enteros, lectura atómica en CPython). Se cuentan por separado.
        self.received = 0        # eventos entregados por el bus a este consumidor
        self.written = 0         # eventos escritos en disco
        self.dropped = 0         # descartados porque la cola interna estaba llena
        self.write_errors = 0    # fallos de escritura/rotación
        self.rotations = 0

    @property
    def path(self) -> str:
        return self._path

    # --- Suscripción al bus -------------------------------------------------------------------
    def attach(self, bus) -> None:
        """Se registra como consumidor del bus. `bus` debe exponer subscribe(callback)."""
        bus.subscribe(self._on_event)

    def _on_event(self, event) -> None:
        """Se ejecuta en el hilo de despacho del bus: SOLO encola (rápido, no bloqueante)."""
        self.received += 1
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1  # la Caja Negra no sigue el ritmo: se cuenta, no se bloquea el bus

    # --- Ciclo de vida del escritor -----------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        os.makedirs(self._dir, exist_ok=True)
        self._stop.clear()
        self._thread = threading.Thread(target=self._writer, name="caja-negra", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Pide la parada y espera a que el escritor vacíe la cola y cierre el fichero. Idempotente."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # --- Escritor (hilo propio) ---------------------------------------------------------------
    def _writer(self) -> None:
        try:
            self._fh = open(self._path, "a", encoding="utf-8")
        except OSError:
            self.write_errors += 1
            return
        try:
            # Sigue hasta que se pida parar Y la cola esté vacía (no pierde lo pendiente).
            while not self._stop.is_set() or not self._queue.empty():
                try:
                    event = self._queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                self._write_one(event)
        finally:
            try:
                if self._fh is not None:
                    self._fh.close()
            except OSError:
                pass
            self._fh = None

    def _write_one(self, event) -> None:
        try:
            if not hasattr(event, "to_json"):
                # Para no contaminar el JSONL con líneas no-JSON, un objeto no serializable se cuenta
                # como error y NO se escribe (el diario sigue siendo un JSONL válido).
                raise TypeError("evento sin to_json")
            self._fh.write(event.to_json() + "\n")
            self._fh.flush()
            self.written += 1
            self._rotate_if_needed()
        except Exception:  # noqa: BLE001  (un evento mal formado o un fallo de E/S no debe matar el hilo)
            self.write_errors += 1

    def _rotate_if_needed(self) -> None:
        try:
            if self._fh is not None and self._fh.tell() >= self._max_bytes:
                self._fh.close()
                stamp = time.strftime("%Y%m%d_%H%M%S")
                os.replace(self._path, os.path.join(self._dir, f"eventos_{stamp}.jsonl"))
                self.rotations += 1
                self._fh = open(self._path, "a", encoding="utf-8")
        except OSError:
            self.write_errors += 1

    # --- Lectura de estado (para la GUI) ------------------------------------------------------
    def count(self) -> int:
        """Nº de eventos escritos en disco (lo que muestra el panel de salud)."""
        return self.written

    def metrics(self) -> Dict[str, Any]:
        return {"received": self.received, "written": self.written, "dropped": self.dropped,
                "write_errors": self.write_errors, "rotations": self.rotations, "path": self._path}
