# -*- coding: utf-8 -*-
"""
Jerarquía de errores del núcleo de Lozarus. Todo el núcleo lanza subclases de `LozarusError`,
nunca excepciones genéricas sin contexto, para que las capas superiores puedan distinguir el
origen del fallo (validación de datos, serialización, colector o bus) y reaccionar en consecuencia.
"""

from __future__ import annotations


class LozarusError(Exception):
    """Raíz de todos los errores del núcleo de Lozarus."""


class ValidationError(LozarusError):
    """Un modelo recibió datos inválidos (p. ej. una marca temporal naive o un PID negativo)."""


class SerializationError(LozarusError):
    """Fallo al serializar a dict/JSON o al reconstruir un modelo desde ellos."""


class SchemaVersionError(SerializationError):
    """El esquema del dato no es compatible con la versión que entiende este núcleo."""


class CollectorError(LozarusError):
    """Fallo en un colector (inicialización, captura, estado o liberación de recursos)."""


class BusError(LozarusError):
    """Fallo del bus de eventos (publicación, despacho o cierre)."""
