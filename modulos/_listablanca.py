# -*- coding: utf-8 -*-
"""
Lista blanca de procesos de confianza (Monitor en Vivo de Lozarus).

El usuario marca como «de confianza» procesos legítimos de su flujo de trabajo (por ejemplo
herramientas de desarrollo que abren red o se inyectan) para que dejen de generar alertas
repetitivas. Se compara por NOMBRE de ejecutable, en minúsculas y sin ruta, porque el PID cambia en
cada arranque. La lista se guarda en `tactical_config.json` (clave `trusted_processes`) y sobrevive
a los reinicios.

Funciones PURAS sobre una lista: la persistencia la hace la GUI con TacticalConfig. Marcar un proceso
como de confianza NO cambia nada del sistema: solo silencia su alerta en la interfaz de Lozarus.
"""

import os
from typing import Iterable, List, Tuple

CONFIG_KEY = "trusted_processes"


def normalize(name: str) -> str:
    """Nombre de ejecutable comparable: solo el nombre del fichero, en minúsculas y sin espacios."""
    if not name:
        return ""
    return os.path.basename(str(name)).strip().lower()


def is_trusted(name: str, trusted: Iterable[str]) -> bool:
    """¿Está el proceso en la lista blanca? Compara por nombre normalizado. Pura."""
    target = normalize(name)
    if not target:
        return False
    return target in {normalize(t) for t in trusted}


def add_trusted(name: str, trusted: Iterable[str]) -> Tuple[List[str], bool]:
    """
    Devuelve (lista_nueva_ordenada_sin_duplicados, cambió). `cambió` es False si ya estaba. Pura:
    no toca disco; quien llama persiste el resultado.
    """
    actual = {normalize(t) for t in trusted if normalize(t)}
    target = normalize(name)
    if not target:
        return sorted(actual), False
    if target in actual:
        return sorted(actual), False
    actual.add(target)
    return sorted(actual), True


def remove_trusted(name: str, trusted: Iterable[str]) -> Tuple[List[str], bool]:
    """Devuelve (lista_nueva, cambió). `cambió` es False si no estaba. Pura."""
    actual = {normalize(t) for t in trusted if normalize(t)}
    target = normalize(name)
    if target not in actual:
        return sorted(actual), False
    actual.discard(target)
    return sorted(actual), True
