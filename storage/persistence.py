# -*- coding: utf-8 -*-
"""
Motor de persistencia táctica: guarda y restaura el estado de las defensas y la configuración del
usuario en un JSON local (`Lozarus_Forensics/tactical_config.json`).

Objetivo: que si el usuario deja el Honeypot activado (o la Auto-Reconstrucción), al cerrar y volver
a abrir `gui_qt.py` todo se restaure exactamente en ese estado.

Solo biblioteca estándar. Escritura ATÓMICA (fichero temporal + os.replace) para no corromper el
JSON si el proceso muere a mitad. Tolerante: un fichero ausente o ilegible se trata como «sin
configuración», nunca lanza al cargar.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, Mapping


class TacticalConfig:
    """Diccionario persistente de configuración. Hilo-seguro para guardar."""

    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        self._data: Dict[str, Any] = {}
        self.load()

    @property
    def path(self) -> str:
        return self._path

    def load(self) -> Dict[str, Any]:
        """Carga el JSON. Si no existe o está corrupto, deja la configuración vacía (sin lanzar)."""
        try:
            with open(self._path, encoding="utf-8") as fh:
                data = json.load(fh)
            self._data = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            self._data = {}
        return dict(self._data)

    def save(self) -> bool:
        """Escribe el JSON de forma atómica. Devuelve True si se guardó; False ante un error de E/S."""
        with self._lock:
            try:
                directory = os.path.dirname(self._path) or "."
                os.makedirs(directory, exist_ok=True)
                tmp = self._path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(self._data, fh, ensure_ascii=False, indent=2)
                os.replace(tmp, self._path)  # atómico: o el fichero viejo o el nuevo, nunca a medias
                return True
            except OSError:
                return False

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any, save: bool = True) -> None:
        self._data[key] = value
        if save:
            self.save()

    def update(self, mapping: Mapping[str, Any], save: bool = True) -> None:
        self._data.update(mapping)
        if save:
            self.save()

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._data)
