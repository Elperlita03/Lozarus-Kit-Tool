"""
ui/informe.py · LOZARUS KIT TOOL

Puente entre las páginas y los módulos puros de puntuación e informe: lee el estado VIVO de la
sesión (Escaneo de Vectores, Arsenal, Almacenamiento y Salud del Sistema), calcula la Puntuación de
Seguridad, toma las métricas de rendimiento del momento y exporta el informe ejecutivo HTML.
"""

from __future__ import annotations

import datetime as dt
import getpass
import os
import platform
import socket
from typing import Optional

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFileDialog

from modulos import _arsenal as arsenal
from modulos import _salud_sistema as health
from modulos._base import CRITICAL, WARNING
from modulos._forense import FORENSICS_DIR
from modulos._informe import CLASSIFICATION, DOC_VERSION, render_html, report_reference
from modulos._puntuacion import next_step, security_score
from modulos._rendimiento_disco import analyze_volumes

from ui.theme import APP_NAME
from ui.widgets import _emit_event
from ui.chrome import Toast

REPORTS_DIR = os.path.join(FORENSICS_DIR, "Informes")


def security_inputs(app) -> dict:
    """Entradas de la puntuación: None en lo que aún no se ha medido en la sesión."""
    pages = getattr(app, "pages", {})
    audit, ars = pages.get("auditoria"), pages.get("arsenal")
    last = getattr(audit, "last_result", None)
    rows = getattr(audit, "_port_rows", None)
    ports = None
    if rows is not None:
        live = [r for r in rows if r["exposed"] and not r.get("mitigated")]
        ports = (sum(1 for r in live if r["severity"] is CRITICAL), sum(1 for r in live if r["severity"] is WARNING))
    snap = getattr(ars, "_snap", None)
    counts = audit._counts() if audit is not None and hasattr(audit, "_counts") else {}
    return {"audit": last[0] if last else None, "ports": ports,
            "arsenal": (sum(snap["applied"].values()), len(arsenal.TWEAKS)) if snap else None,
            "pending": counts.get("critical", 0) + counts.get("warning", 0)}


def compute_security(app) -> tuple:
    """(resultado de security_score o None, siguiente paso recomendado, entradas)."""
    inputs = security_inputs(app)
    result = security_score(inputs["audit"], inputs["ports"], inputs["arsenal"])
    return result, next_step(result, inputs["pending"], inputs["arsenal"]), inputs


def collect_report(app) -> dict:
    pages = getattr(app, "pages", {})
    audit, ars = pages.get("auditoria"), pages.get("arsenal")
    result, step, inputs = compute_security(app)
    fixed = getattr(audit, "_fixed", {})
    titles = getattr(app, "module_titles", {})
    findings = [{"severity": f.severity.value, "module": titles.get(f.module, f.module), "title": f.title,
                 "detail": f.detail, "recommendation": f.recommendation, "mitigated": fixed.get(id(f))}
                for f in getattr(audit, "findings", [])]
    rows = getattr(audit, "_port_rows", None)
    ports = None if rows is None else [
        {"severity": r["severity"].value, "proto": r["proto"], "ip": r["ip"], "port": r["port"],
         "service": r["service"], "process": r["process"], "pid": r["pid"], "exposed": r["exposed"],
         "mitigated": r.get("mitigated")} for r in rows]
    snap = getattr(ars, "_snap", None)
    tweaks = None if not snap else [
        {"title": t.title, "card": t.card, "applied": bool(snap["applied"].get(t.key)),
         "values": [arsenal.describe(v) for v in t.values], "backed_up": t.key in snap["backed_up"]}
        for t in arsenal.TWEAKS]
    now, host = dt.datetime.now(), socket.gethostname()
    return {"app": APP_NAME, "host": host, "user": getpass.getuser(),
            "os": f"{platform.system()} {platform.release()} ({platform.version()})",
            "admin": bool(getattr(app, "admin", False)), "generated": now.strftime("%d/%m/%Y %H:%M"),
            "security": result, "next_step": step, "audit_score": inputs["audit"],
            "findings": findings, "ports": ports, "arsenal": tweaks,
            "doc": {"reference": report_reference(host, now), "classification": CLASSIFICATION,
                    "version": DOC_VERSION, "issued": now.strftime("%d/%m/%Y %H:%M"),
                    "scope": "Seguridad, rendimiento y salud del sistema operativo"},
            "performance": health.system_performance(), "storage": storage_report(app),
            "health": health_report(app)}


def storage_report(app) -> dict:
    """Almacenamiento de la sesión (página Almacenamiento); sin ella, los volúmenes leídos al momento."""
    page = getattr(app, "pages", {}).get("almacenamiento")
    if page is not None and hasattr(page, "report_data"):
        return page.report_data()
    return {"volumes": analyze_volumes(), "scan": None, "recovered": 0, "recovered_by": [], "runs": 0,
            "optimized": None, "space": None}


def health_report(app) -> dict:
    """Salud del sistema (página Salud); sin ella, el historial de integridad guardado en el equipo."""
    page = getattr(app, "pages", {}).get("salud")
    if page is not None and hasattr(page, "report_data"):
        return page.report_data()
    state = health.load_state()
    integ = health.integrity_status(state)
    verdict = health.health_verdict(None, integ)
    return {"verdict": {"level": verdict["level"], "label": verdict["label"], "reasons": verdict["reasons"]},
            "integrity": integ, "signals": None, "history": state.get("history", [])[:8]}


def export_report(app) -> Optional[str]:
    """Pide destino, escribe el informe HTML, lo registra en la Caja Negra y lo abre en el navegador."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    name = f"Informe_Ejecutivo_Lozarus_{socket.gethostname()}_{dt.datetime.now():%Y%m%d_%H%M}.html"
    path, _ = QFileDialog.getSaveFileName(app, "Exportar informe ejecutivo de auditoría",
                                          os.path.join(REPORTS_DIR, name), "Informe HTML (*.html)")
    if not path:
        return None
    data = collect_report(app)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(data))
    except OSError as exc:
        Toast.notify(app, "x", "Informe", f"No se pudo guardar: {exc}", "fa5s.file-export")
        return None
    sec = data["security"]
    _emit_event(app, source="informe", event_type="report.exported",
                payload={"path": path, "reference": data["doc"]["reference"], "score": sec["score"] if sec else None,
                         "findings": len(data["findings"]), "ports": len(data["ports"] or []),
                         "health": (data["health"].get("verdict") or {}).get("label"),
                         "recovered_bytes": data["storage"].get("recovered", 0)})
    app.console.log("*", f"Informe ejecutivo exportado ({data['doc']['reference']}): {path}")
    Toast.notify(app, "*", "Informe exportado", f"{data['doc']['reference']} · {os.path.basename(path)}",
                 "fa5s.file-export")
    QDesktopServices.openUrl(QUrl.fromLocalFile(path))
    return path
