"""
modulos/_puntuacion.py · LOZARUS KIT TOOL

Puntuación de Seguridad del Sistema (0-100). Función PURA: combina lo que se sabe del equipo en la
sesión (diagnóstico completo, puertos en escucha y ajustes del Arsenal) con pesos fijos; los
componentes sin datos no cuentan y su peso se reparte entre los demás. Nunca inventa un valor.
"""

from __future__ import annotations

from typing import Optional, Tuple

# Peso de cada componente cuando hay datos de todos.
WEIGHTS = {"audit": 0.55, "ports": 0.20, "arsenal": 0.25}
LABELS = {"audit": "Diagnóstico completo", "ports": "Puertos expuestos", "arsenal": "Endurecimiento (Arsenal)"}
# Penalización por puerto de riesgo expuesto y SIN mitigar.
PORT_PENALTY = {"critical": 20, "warning": 8}
GRADES = ((90, "A", "BLINDADO"), (75, "B", "ROBUSTO"), (60, "C", "MEJORABLE"), (40, "D", "EXPUESTO"),
          (0, "E", "CRÍTICO"))


def grade(score: int) -> Tuple[str, str]:
    """(letra, etiqueta) de una puntuación."""
    return next((letter, label) for floor, letter, label in GRADES if score >= floor)


def security_score(audit: Optional[int] = None, ports: Optional[Tuple[int, int]] = None,
                   arsenal: Optional[Tuple[int, int]] = None) -> Optional[dict]:
    """
    audit   = puntuación del último diagnóstico (ya con los hallazgos mitigados como superados).
    ports   = (críticos, avisos) expuestos y pendientes, o None si no se auditaron.
    arsenal = (ajustes aplicados, total), o None si aún no se leyó el registro.
    Devuelve {score, letter, label, parts}, o None si aún no se midió el equipo (ni diagnóstico ni puertos).
    """
    parts = {}
    if audit is not None:
        parts["audit"] = max(0, min(100, int(audit)))
    if ports is not None:
        crit, warn = ports
        parts["ports"] = max(0, 100 - PORT_PENALTY["critical"] * crit - PORT_PENALTY["warning"] * warn)
    if arsenal is not None and arsenal[1]:
        parts["arsenal"] = round(100 * arsenal[0] / arsenal[1])
    if "audit" not in parts and "ports" not in parts:
        return None  # sin medir el equipo, el Arsenal solo no basta para dar una nota (sería engañosa)
    weight = sum(WEIGHTS[k] for k in parts)
    score = round(sum(WEIGHTS[k] * v for k, v in parts.items()) / weight)
    letter, label = grade(score)
    return {"score": score, "letter": letter, "label": label, "parts": parts}


def next_step(result: Optional[dict], pending_risks: int, arsenal: Optional[Tuple[int, int]]) -> str:
    """Siguiente acción con más impacto sobre la nota (texto para la interfaz y el informe)."""
    parts = (result or {}).get("parts", {})
    if "audit" not in parts:
        return "Lanza el Diagnóstico Completo en Escaneo de Vectores para una nota precisa."
    if pending_risks:
        return f"Mitiga {pending_risks} riesgo(s) pendiente(s) en Escaneo de Vectores."
    if arsenal is not None and arsenal[0] < arsenal[1]:
        return f"Aplica los perfiles del Arsenal: quedan {arsenal[1] - arsenal[0]} ajuste(s) por endurecer."
    if "ports" not in parts:
        return "Audita los puertos en escucha para completar la nota."
    return "Equipo en su mejor estado conocido. Repite el diagnóstico tras cada cambio importante."
