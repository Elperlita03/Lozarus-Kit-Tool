"""
modulos/_informe.py · LOZARUS KIT TOOL

Informe de auditoría en HTML autocontenido (sin recursos externos) con la estética «Black & White
Aura»: puntuación, riesgos pendientes, vectores mitigados, optimizaciones del Arsenal y puertos.
Función PURA: recibe un dict con los datos de la sesión y devuelve el HTML. Todo texto que procede
del sistema (procesos, rutas, títulos) se escapa.
"""

from __future__ import annotations

from html import escape
from typing import Iterable, List, Optional

from ._puntuacion import LABELS

SEV_COLOR = {"CRITICAL": "#F87171", "WARNING": "#F5B544", "INFO": "#E5E5E5", "PASS": "#4ADE80", "SKIP": "#8A8A8A"}
OK, WARN, DANGER, MUTED = "#4ADE80", "#F5B544", "#F87171", "#8A8A8A"
CARD_NAMES = {"privacy": "Privacidad", "network": "Red y USB", "ux": "UX y limpieza"}

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#000;color:#fff;font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif;
 background-image:radial-gradient(1200px 600px at 50% -200px,rgba(255,255,255,.07),transparent 70%)}
main{max-width:1080px;margin:0 auto;padding:48px 24px 64px}
.eyebrow{color:#8A8A8A;letter-spacing:.22em;font-size:11px;text-transform:uppercase;margin:0 0 6px}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:15px;letter-spacing:.14em;text-transform:uppercase;color:#BDBDBD;margin:0 0 14px}
.card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.14);
 border-top-color:rgba(255,255,255,.38);border-radius:14px;padding:22px 24px;margin:18px 0;
 box-shadow:0 0 28px rgba(255,255,255,.07)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px 24px;margin-top:18px}
.meta div span{display:block;color:#8A8A8A;font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.hero{display:flex;gap:32px;align-items:center;flex-wrap:wrap}
.ring{--v:0;--c:#fff;width:168px;height:168px;border-radius:50%;flex:none;display:grid;place-items:center;
 background:conic-gradient(var(--c) calc(var(--v)*1%),rgba(255,255,255,.08) 0);
 box-shadow:0 0 40px rgba(255,255,255,.10)}
.ring>div{width:136px;height:136px;border-radius:50%;background:#050505;display:grid;place-items:center;
 text-align:center}
.ring b{font-size:46px;line-height:1}.ring small{color:#8A8A8A;display:block}
.grade{font-size:22px;font-weight:700;letter-spacing:.12em}
.bars{flex:1;min-width:260px}
.bar{margin:10px 0}.bar label{display:flex;justify-content:space-between;color:#BDBDBD;font-size:12px}
.bar i{display:block;height:6px;border-radius:3px;background:rgba(255,255,255,.08);margin-top:5px;overflow:hidden}
.bar i em{display:block;height:100%;border-radius:3px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
.kpi{border:1px solid rgba(255,255,255,.12);border-radius:12px;padding:14px 16px;background:rgba(255,255,255,.02)}
.kpi b{font-size:28px;display:block}.kpi span{color:#8A8A8A;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:#8A8A8A;font-weight:600;font-size:11px;letter-spacing:.1em;text-transform:uppercase;
 border-bottom:1px solid rgba(255,255,255,.14);padding:8px 10px}
td{padding:9px 10px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}
code{font:12px/1.4 Consolas,"Cascadia Mono",monospace;color:#D4D4D4;word-break:break-all}
.pill{display:inline-block;border-radius:9px;padding:1px 9px;font-size:11px;font-weight:700;letter-spacing:.08em;
 border:1px solid currentColor;white-space:nowrap}
.muted{color:#8A8A8A}.next{margin-top:14px;color:#BDBDBD}
footer{color:#555;font-size:12px;text-align:center;margin-top:36px}
@media print{body{background:#000;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


def _pill(text: str, color: str) -> str:
    return f'<span class="pill" style="color:{color}">{escape(text)}</span>'


def _score_color(score: Optional[int]) -> str:
    return MUTED if score is None else OK if score >= 85 else WARN if score >= 60 else DANGER


def _table(headers: Iterable[str], rows: List[str], empty: str) -> str:
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _section(title: str, body: str) -> str:
    return f'<section class="card"><h2>{escape(title)}</h2>{body}</section>'


def render_html(data: dict) -> str:
    """HTML completo del informe. `data` lo arma ui/informe.collect_report()."""
    sec = data.get("security")
    findings = data.get("findings") or []
    ports = data.get("ports")
    arsenal = data.get("arsenal")

    # --- Puntuación ---------------------------------------------------------------------------
    if sec:
        bars = "".join(
            f'<div class="bar"><label><span>{escape(LABELS[k])}</span><span>{v}/100</span></label>'
            f'<i><em style="width:{v}%;background:{_score_color(v)}"></em></i></div>'
            for k, v in sec["parts"].items())
        missing = [LABELS[k] for k in LABELS if k not in sec["parts"]]
        if missing:
            bars += f'<p class="muted">Sin datos en esta sesión: {escape(", ".join(missing))}.</p>'
        hero = (f'<div class="hero"><div class="ring" style="--v:{sec["score"]};--c:{_score_color(sec["score"])}">'
                f'<div><div><b>{sec["score"]}</b><small>/ 100</small></div></div></div>'
                f'<div class="bars"><div class="grade" style="color:{_score_color(sec["score"])}">'
                f'{escape(sec["letter"])} · {escape(sec["label"])}</div>{bars}'
                f'<p class="next">➜ {escape(data.get("next_step", ""))}</p></div></div>')
    else:
        hero = '<p class="muted">Sin datos suficientes: ejecuta el diagnóstico completo antes de exportar.</p>'

    # --- KPIs ---------------------------------------------------------------------------------
    pending = [f for f in findings if f["severity"] in ("CRITICAL", "WARNING") and not f["mitigated"]]
    fixed = [f for f in findings if f["mitigated"]]
    ports_fixed = [p for p in ports or [] if p["mitigated"]]
    exposed = [p for p in ports or [] if p["exposed"] and not p["mitigated"]]
    applied = sum(1 for t in arsenal or [] if t["applied"])
    kpis = [(len([f for f in pending if f["severity"] == "CRITICAL"]), "Críticos pendientes", DANGER),
            (len([f for f in pending if f["severity"] == "WARNING"]), "Avisos pendientes", WARN),
            (len(fixed) + len(ports_fixed), "Vectores mitigados en la sesión", OK),
            ("—" if ports is None else len(exposed), "Puertos expuestos", WARN if exposed else OK),
            ("—" if arsenal is None else f"{applied}/{len(arsenal)}", "Ajustes del Arsenal aplicados", OK)]
    kpi_html = '<div class="kpis">' + "".join(
        f'<div class="kpi"><b style="color:{color}">{escape(str(v))}</b><span>{escape(t)}</span></div>'
        for v, t, color in kpis) + "</div>"

    # --- Tablas -------------------------------------------------------------------------------
    mitigated_rows = [
        f'<tr><td>{_pill("PUERTO", MUTED)}</td><td><code>{escape(p["proto"])} {escape(str(p["port"]))}</code> '
        f'{escape(p["service"])} · {escape(p["process"])}</td><td>{escape(p["mitigated"])}</td></tr>'
        for p in ports_fixed] + [
        f'<tr><td>{_pill(f["severity"], SEV_COLOR[f["severity"]])}</td><td>{escape(f["title"])}'
        f'<br><span class="muted">{escape(f["module"])}</span></td><td>{escape(f["mitigated"])}</td></tr>'
        for f in fixed]
    pending_rows = [
        f'<tr><td>{_pill(f["severity"], SEV_COLOR[f["severity"]])}</td><td>{escape(f["title"])}'
        f'<br><span class="muted">{escape(f["module"])}</span></td><td>{escape(f["recommendation"] or "—")}</td></tr>'
        for f in pending]
    arsenal_rows = [
        f'<tr><td>{escape(t["title"])}<br><span class="muted">{escape(CARD_NAMES.get(t["card"], t["card"]))}'
        f'</span></td><td>{_pill("✔ APLICADO", OK) if t["applied"] else _pill("POR DEFECTO", MUTED)}</td>'
        f'<td>{"<br>".join(f"<code>{escape(v)}</code>" for v in t["values"])}</td></tr>'
        for t in arsenal or []]
    port_rows = [
        f'<tr><td>{_pill("MITIGADO", OK) if p["mitigated"] else _pill(p["severity"], SEV_COLOR[p["severity"]])}</td>'
        f'<td><code>{escape(p["proto"])}</code></td><td><code>{escape(p["ip"])}:{escape(str(p["port"]))}</code></td>'
        f'<td>{escape(p["service"])}</td><td>{escape(p["process"])} '
        f'<span class="muted">PID {escape(str(p["pid"]) if p["pid"] is not None else "—")}</span></td></tr>'
        for p in ports or []]

    audit = data.get("audit_score")
    meta = [("Equipo", data["host"]), ("Sistema operativo", data["os"]), ("Usuario", data["user"]),
            ("Privilegios", "Administrador" if data["admin"] else "Usuario estándar"),
            ("Generado", data["generated"]),
            ("Último diagnóstico", f"{audit}/100" if audit is not None else "no ejecutado en la sesión")]
    meta_html = '<div class="meta">' + "".join(
        f"<div><span>{escape(k)}</span>{escape(str(v))}</div>" for k, v in meta) + "</div>"

    body = "".join([
        f'<header><p class="eyebrow">{escape(data["app"])} · Informe de auditoría técnica</p>'
        f'<h1>Informe de seguridad del sistema</h1>{meta_html}</header>',
        _section("Puntuación de seguridad", hero),
        _section("Resumen", kpi_html),
        _section("Vectores mitigados en la sesión",
                 _table(("Tipo", "Vector", "Mitigación aplicada"), mitigated_rows,
                        "Ningún vector mitigado todavía en esta sesión.")),
        _section("Riesgos pendientes",
                 _table(("Nivel", "Hallazgo", "Recomendación"), pending_rows,
                        "Sin riesgos CRITICAL / WARNING pendientes." if findings
                        else "No se ejecutó el diagnóstico completo en esta sesión.")),
        _section("Optimizaciones del Arsenal",
                 _table(("Ajuste", "Estado", "Registro"), arsenal_rows,
                        "El estado del Arsenal no se pudo leer (solo Windows).")),
        _section("Puertos en escucha",
                 _table(("Estado", "Proto", "Dirección", "Servicio", "Proceso"), port_rows,
                        "No se auditaron los puertos en esta sesión." if ports is None
                        else "Ningún puerto en escucha.")),
        f'<footer>{escape(data["app"])} · informe generado localmente; ningún dato sale del equipo.</footer>',
    ])
    return (f'<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Informe de seguridad · {escape(data["host"])}</title><style>{CSS}</style></head>'
            f"<body><main>{body}</main></body></html>")
