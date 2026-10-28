"""
modulos/_informe.py · LOZARUS KIT TOOL

Informe EJECUTIVO de auditoría técnica en HTML autocontenido (sin recursos externos), listo para revisar
en pantalla con la estética «Black & White Aura» o para imprimir / guardar como PDF y entregar en una
revisión técnica:

  · Cabecera corporativa: marca, clasificación, referencia única del documento, ficha del equipo
    auditado y, al imprimir, encabezado y pie repetidos en cada página (con numeración en Chromium).
  · Resumen ejecutivo redactado a partir de los datos de la sesión (sin inventar nada: lo que no se
    midió no aparece como correcto).
  · Puntuación de seguridad, rendimiento del sistema (CPU, memoria, arranque y unidades), salud del
    sistema operativo (integridad SFC/DISM y estabilidad), resumen visual de optimizaciones, vectores
    mitigados, riesgos pendientes, Arsenal, puertos y control del documento (revisión y aprobación).
  · Al imprimir cambia a un tema claro (fondo blanco, colores semánticos legibles) y evita partir las
    tarjetas pequeñas entre páginas.

Función PURA: recibe un dict con los datos de la sesión y devuelve el HTML. Todo texto que procede del
sistema (procesos, rutas, títulos, nombres de equipo) se escapa.
"""

from __future__ import annotations

import datetime as dt
import re
from html import escape
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ._puntuacion import LABELS
from ._rendimiento_disco import human_bytes
from ._salud_sistema import format_duration

# Colores semánticos como variables CSS: el tema de impresión los redefine (legibles sobre blanco).
OK, WARN, DANGER, MUTED, INFO = "var(--ok)", "var(--warn)", "var(--crit)", "var(--muted)", "var(--info)"
SEV_COLOR = {"CRITICAL": DANGER, "WARNING": WARN, "INFO": INFO, "PASS": OK, "SKIP": MUTED}
LEVEL_COLOR = {"ok": OK, "warn": WARN, "critical": DANGER, "unknown": MUTED}
CARD_NAMES = {"privacy": "Privacidad", "network": "Red y USB", "ux": "UX y limpieza"}
CLASSIFICATION = "CONFIDENCIAL · USO INTERNO"
DOC_VERSION = "1.0"

LOGO = ('<svg viewBox="0 0 48 48" width="42" height="42" aria-hidden="true">'
        '<path d="M24 3 6 10v12c0 11.5 7.7 20.7 18 23 10.3-2.3 18-11.5 18-23V10L24 3z" fill="none" '
        'stroke="currentColor" stroke-width="2.4" stroke-linejoin="round"/>'
        '<path d="M19 14v18h11" fill="none" stroke="currentColor" stroke-width="3.6" stroke-linecap="round" '
        'stroke-linejoin="round"/></svg>')

CSS = """
:root{--bg:#000;--panel:#050505;--line:rgba(255,255,255,.14);--rim:rgba(255,255,255,.38);--fg:#fff;--fg2:#BDBDBD;
 --muted:#8A8A8A;--faint:#555;--track:rgba(255,255,255,.08);--ok:#4ADE80;--warn:#F5B544;--crit:#F87171;--info:#E5E5E5;
 --glow:rgba(255,255,255,.07)}
*{box-sizing:border-box}
html{color-scheme:dark}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif;
 background-image:radial-gradient(1200px 600px at 50% -200px,rgba(255,255,255,.07),transparent 70%)}
.sheet{width:100%;border-collapse:collapse}
.sheet>thead>tr>td,.sheet>tfoot>tr>td,.sheet>tbody>tr>td{padding:0;border:0}
.runhead,.runfoot{display:none}
main{max-width:1080px;margin:0 auto;padding:36px 24px 64px;counter-reset:sec}
.toolbar{display:flex;justify-content:flex-end;margin-bottom:14px}
.toolbar button{font:inherit;font-size:12px;font-weight:600;letter-spacing:.06em;color:var(--fg);background:transparent;
 border:1px solid rgba(255,255,255,.45);border-radius:9px;padding:7px 14px;cursor:pointer}
.toolbar button:hover{background:rgba(255,255,255,.08)}
.brandbar{display:flex;justify-content:space-between;align-items:center;gap:16px;padding-bottom:18px;
 border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;color:var(--fg)}
.brand b{display:block;font-size:20px;letter-spacing:.32em;font-weight:800;line-height:1.1}
.brand span{display:block;font-size:10px;letter-spacing:.3em;color:var(--muted);font-weight:700}
.classif{font-size:11px;font-weight:700;letter-spacing:.16em;color:var(--warn);border:1px solid currentColor;
 border-radius:8px;padding:4px 10px;white-space:nowrap}
.titleblock{margin:26px 0 6px}
.eyebrow{color:var(--muted);letter-spacing:.22em;font-size:11px;text-transform:uppercase;margin:0 0 6px}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.01em;line-height:1.2}
.subtitle{color:var(--fg2);margin:0}
.docmeta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px 24px;margin:20px 0 4px;
 padding:16px 18px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.02)}
.docmeta div span{display:block;color:var(--muted);font-size:10.5px;letter-spacing:.12em;text-transform:uppercase}
.docmeta div b{font-weight:600;overflow-wrap:anywhere}
h2{font-size:15px;letter-spacing:.14em;text-transform:uppercase;color:var(--fg2);margin:0 0 14px;break-after:avoid}
h2::before{counter-increment:sec;content:counter(sec,decimal-leading-zero) "\\2003";color:var(--muted)}
h3{font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:22px 0 10px;break-after:avoid}
.card{background:rgba(255,255,255,.03);border:1px solid var(--line);border-top-color:var(--rim);border-radius:14px;
 padding:22px 24px;margin:18px 0;box-shadow:0 0 28px var(--glow)}
.summary p{margin:0 0 10px;color:var(--fg2)}.summary p b{color:var(--fg)}
.hero{display:flex;gap:32px;align-items:center;flex-wrap:wrap}
.ring{--v:0;--c:#fff;width:168px;height:168px;border-radius:50%;flex:none;display:grid;place-items:center;
 background:conic-gradient(var(--c) calc(var(--v)*1%),var(--track) 0);box-shadow:0 0 40px var(--glow)}
.ring>div{width:136px;height:136px;border-radius:50%;background:var(--panel);display:grid;place-items:center;
 text-align:center}
.ring b{font-size:46px;line-height:1}.ring small{color:var(--muted);display:block}
.grade{font-size:22px;font-weight:700;letter-spacing:.12em}
.bars{flex:1;min-width:260px}
.bar{margin:10px 0}.bar label{display:flex;justify-content:space-between;color:var(--fg2);font-size:12px}
.bar i{display:block;height:6px;border-radius:3px;background:var(--track);margin-top:5px;overflow:hidden}
.bar i em{display:block;height:100%;border-radius:3px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}
.kpi{border:1px solid var(--line);border-radius:12px;padding:14px 16px;background:rgba(255,255,255,.02)}
.kpi b{font-size:26px;display:block;line-height:1.2;overflow-wrap:anywhere}.kpi span{color:var(--muted);font-size:12px}
.kpi small{display:block;color:var(--fg2);font-size:11.5px;margin-top:2px}
.kpi .mini{display:block;height:5px;border-radius:3px;background:var(--track);margin-top:8px;overflow:hidden}
.kpi .mini em{display:block;height:100%;border-radius:3px}
.chart{display:grid;gap:10px;margin-top:6px}
.chart .row{display:grid;grid-template-columns:minmax(150px,250px) minmax(0,1fr) minmax(110px,auto);gap:14px;
 align-items:center;font-size:13px}
.chart .lbl{color:var(--fg2);overflow-wrap:anywhere}
.chart .track{height:10px;border-radius:5px;background:var(--track);overflow:hidden}
.chart .fill{display:block;height:100%;border-radius:5px;background:var(--c,var(--fg))}
.chart .val{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.reasons{list-style:none;margin:12px 0 0;padding:0}
.reasons li{padding:4px 0 4px 20px;position:relative;color:var(--fg2)}
.reasons li::before{content:"";position:absolute;left:3px;top:12px;width:8px;height:8px;border-radius:50%;
 background:var(--c)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:4px 24px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:11px;letter-spacing:.1em;text-transform:uppercase;
 border-bottom:1px solid var(--line);padding:8px 10px}
td{padding:9px 10px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}
tr{break-inside:avoid}
code{font:12px/1.4 Consolas,"Cascadia Mono",monospace;color:var(--fg2);word-break:break-all}
.pill{display:inline-block;border-radius:9px;padding:1px 9px;font-size:11px;font-weight:700;letter-spacing:.08em;
 border:1px solid currentColor;white-space:nowrap}
.muted{color:var(--muted)}.next{margin-top:14px;color:var(--fg2)}
.signoff td{height:46px}.signoff td:first-child{width:22%;color:var(--fg2)}
.disclaimer{font-size:12px;color:var(--muted);margin:14px 0 0}
footer{color:var(--faint);font-size:12px;text-align:center;margin-top:36px}
@page{size:A4;margin:14mm 12mm 15mm;
 @bottom-right{content:"Página " counter(page) " de " counter(pages);font:9px "Segoe UI",sans-serif;color:#666}}
@media print{
 :root{--bg:#fff;--panel:#fff;--line:#CFCFCF;--rim:#CFCFCF;--fg:#111;--fg2:#333;--muted:#666;--faint:#999;
  --track:#E5E5E5;--ok:#15803D;--warn:#B45309;--crit:#B91C1C;--info:#334155;--glow:transparent}
 html{color-scheme:light}
 body{background:#fff;background-image:none;font-size:11.5px;-webkit-print-color-adjust:exact;print-color-adjust:exact}
 main{max-width:none;padding:0}
 .toolbar,footer{display:none}
 .runhead{display:table-header-group}.runfoot{display:table-footer-group}
 .runhead td>div,.runfoot td>div{display:flex;justify-content:space-between;gap:12px;font-size:8.5px;color:#666;
  letter-spacing:.06em}
 .runhead td>div{border-bottom:1px solid #CFCFCF;padding-bottom:4px;margin-bottom:12px}
 .runfoot td>div{border-top:1px solid #CFCFCF;padding-top:4px;margin-top:12px}
 .card{box-shadow:none;margin:12px 0;padding:14px 16px;background:#fff}
 .card.keep,.kpi,.docmeta{break-inside:avoid}
 td{border-bottom-color:#E5E5E5}
 .ring{box-shadow:none}
 .toolbar button{display:none}
 h1{font-size:24px}
}
@media (max-width:640px){.chart .row{grid-template-columns:minmax(0,1fr)}.chart .val{text-align:left}}
"""


# =============================================================================================
# Utilidades puras
# =============================================================================================
def _pill(text: str, color: str) -> str:
    return f'<span class="pill" style="color:{color}">{escape(text)}</span>'


def _score_color(score: Optional[int]) -> str:
    return MUTED if score is None else OK if score >= 85 else WARN if score >= 60 else DANGER


def _table(headers: Iterable[str], rows: List[str], empty: str) -> str:
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _section(title: str, body: str, keep: bool = False) -> str:
    return f'<section class="card{" keep" if keep else ""}"><h2>{escape(title)}</h2>{body}</section>'


def _kpi(value: Any, label: str, color: Optional[str] = None, note: str = "", fill: Optional[float] = None) -> str:
    style = f' style="color:{color}"' if color else ""
    mini = (f'<span class="mini"><em style="width:{max(0.0, min(100.0, fill)):.1f}%;background:{color or OK}"></em>'
            "</span>" if fill is not None else "")
    small = f"<small>{escape(note)}</small>" if note else ""
    return f'<div class="kpi"><b{style}>{escape(str(value))}</b><span>{escape(label)}</span>{small}{mini}</div>'


def _chart(rows: Sequence[Tuple[str, float, str, str]], empty: str) -> str:
    """Barras horizontales: (etiqueta, porcentaje 0-100, valor mostrado, color)."""
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    return '<div class="chart">' + "".join(
        f'<div class="row"><span class="lbl">{escape(label)}</span><span class="track">'
        f'<span class="fill" style="width:{max(0.0, min(100.0, pct)):.1f}%;--c:{color}"></span></span>'
        f'<span class="val">{escape(value)}</span></div>' for label, pct, value, color in rows) + "</div>"


def _reasons(reasons: Sequence[Sequence[str]]) -> str:
    if not reasons:
        return ""
    return '<ul class="reasons">' + "".join(
        f'<li style="--c:{LEVEL_COLOR.get(level, MUTED)}">{escape(text)}</li>' for level, text in reasons) + "</ul>"


def _when(value: Any) -> str:
    try:
        return dt.datetime.fromisoformat(str(value)).strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError):
        return "—"


def report_reference(host: str, when: dt.datetime) -> str:
    """Referencia única y legible del documento: LZ-AUD-AAAAMMDD-HHMM-EQUIPO. Pura."""
    tag = re.sub(r"[^A-Z0-9]", "", (host or "").upper())[:12] or "EQUIPO"
    return f"LZ-AUD-{when:%Y%m%d-%H%M}-{tag}"


# =============================================================================================
# Resumen ejecutivo
# =============================================================================================
def executive_summary(data: Dict[str, Any]) -> List[str]:
    """Párrafos del resumen ejecutivo (HTML con las cifras en negrita). Solo afirma lo que se midió."""
    paras: List[str] = []
    host = escape(str(data.get("host", "")))
    sec = data.get("security")
    if sec:
        paras.append(f"El equipo <b>{host}</b> obtiene una puntuación de seguridad de <b>{sec['score']}/100</b> "
                     f"(<b>{escape(sec['letter'])} · {escape(sec['label'])}</b>).")
    else:
        paras.append(f"El equipo <b>{host}</b> aún no tiene una puntuación de seguridad: falta el diagnóstico completo "
                     "o la auditoría de puertos en la sesión.")
    findings = data.get("findings") or []
    if findings:
        crit = sum(1 for f in findings if f["severity"] == "CRITICAL" and not f["mitigated"])
        warn = sum(1 for f in findings if f["severity"] == "WARNING" and not f["mitigated"])
        fixed = sum(1 for f in findings if f["mitigated"]) + sum(1 for p in data.get("ports") or [] if p.get("mitigated"))
        risk = (f"Quedan <b>{crit}</b> riesgo(s) crítico(s) y <b>{warn}</b> aviso(s) pendientes" if crit or warn
                else "No quedan riesgos críticos ni avisos pendientes")
        paras.append(risk + (f"; durante la sesión se mitigaron <b>{fixed}</b> vector(es)." if fixed else "."))
    health = data.get("health") or {}
    verdict = health.get("verdict")
    if verdict:
        worst = next((t for lvl, t in verdict.get("reasons", []) if lvl in ("warn", "critical")), "")
        paras.append(f"Salud del sistema operativo: <b>{escape(verdict['label'])}</b>"
                     + (f" — {escape(worst)}." if worst else "."))
    storage = data.get("storage") or {}
    system = next((v for v in storage.get("volumes") or [] if v.get("system")), None)
    if system:
        line = (f"El disco del sistema ({escape(str(system['mount']))}) está al <b>{system['percent']:.0f} %</b> con "
                f"<b>{escape(human_bytes(system['free']))}</b> libres")
        recovered = storage.get("recovered") or 0
        if recovered:
            line += f"; en la sesión se recuperaron <b>{escape(human_bytes(recovered))}</b>"
        scan = storage.get("scan")
        if scan and scan.get("eligible_bytes"):
            line += f" y quedan <b>{escape(human_bytes(scan['eligible_bytes']))}</b> liberables de forma segura"
        paras.append(line + ".")
    perf = data.get("performance") or {}
    parts = []
    if perf.get("cpu_percent") is not None:
        parts.append(f"CPU al <b>{perf['cpu_percent']:.0f} %</b>")
    if perf.get("ram_percent") is not None:
        parts.append(f"memoria al <b>{perf['ram_percent']:.0f} %</b>")
    if perf.get("uptime_s") is not None:
        parts.append(f"encendido desde hace <b>{escape(format_duration(perf['uptime_s']))}</b>")
    if parts:
        paras.append("En el momento del informe: " + ", ".join(parts) + ".")
    if data.get("next_step"):
        paras.append(f"Siguiente paso recomendado: <b>{escape(data['next_step'])}</b>")
    return paras


# =============================================================================================
# Secciones
# =============================================================================================
def _header(data: Dict[str, Any], doc: Dict[str, Any]) -> str:
    audit = data.get("audit_score")
    meta = [("Referencia", doc["reference"]), ("Fecha de emisión", doc["issued"]),
            ("Equipo auditado", data["host"]), ("Sistema operativo", data["os"]), ("Usuario", data["user"]),
            ("Privilegios", "Administrador" if data["admin"] else "Usuario estándar"),
            ("Último diagnóstico", f"{audit}/100" if audit is not None else "no ejecutado en la sesión"),
            ("Versión del documento", doc["version"])]
    meta_html = '<div class="docmeta">' + "".join(
        f"<div><span>{escape(k)}</span><b>{escape(str(v))}</b></div>" for k, v in meta) + "</div>"
    return (f'<div class="toolbar"><button type="button" onclick="window.print()">Imprimir / Guardar como PDF'
            f'</button></div>'
            f'<header><div class="brandbar"><div class="brand">{LOGO}<div><b>LOZARUS</b><span>KIT TOOL</span></div>'
            f'</div><div class="classif">{escape(doc["classification"])}</div></div>'
            f'<div class="titleblock"><p class="eyebrow">{escape(data["app"])} · Informe ejecutivo de auditoría '
            f'técnica</p><h1>Seguridad, rendimiento y salud del sistema</h1>'
            f'<p class="subtitle">{escape(doc["scope"])}</p></div>{meta_html}</header>')


def _score_section(data: Dict[str, Any]) -> str:
    sec = data.get("security")
    if not sec:
        return '<p class="muted">Sin datos suficientes: ejecuta el diagnóstico completo antes de exportar.</p>'
    bars = "".join(
        f'<div class="bar"><label><span>{escape(LABELS[k])}</span><span>{v}/100</span></label>'
        f'<i><em style="width:{v}%;background:{_score_color(v)}"></em></i></div>'
        for k, v in sec["parts"].items())
    missing = [LABELS[k] for k in LABELS if k not in sec["parts"]]
    if missing:
        bars += f'<p class="muted">Sin datos en esta sesión: {escape(", ".join(missing))}.</p>'
    return (f'<div class="hero"><div class="ring" style="--v:{sec["score"]};--c:{_score_color(sec["score"])}">'
            f'<div><div><b>{sec["score"]}</b><small>/ 100</small></div></div></div>'
            f'<div class="bars"><div class="grade" style="color:{_score_color(sec["score"])}">'
            f'{escape(sec["letter"])} · {escape(sec["label"])}</div>{bars}'
            f'<p class="next">➜ {escape(data.get("next_step", ""))}</p></div></div>')


def _summary_kpis(data: Dict[str, Any]) -> str:
    findings = data.get("findings") or []
    ports, arsenal = data.get("ports"), data.get("arsenal")
    pending = [f for f in findings if f["severity"] in ("CRITICAL", "WARNING") and not f["mitigated"]]
    fixed = [f for f in findings if f["mitigated"]]
    ports_fixed = [p for p in ports or [] if p["mitigated"]]
    exposed = [p for p in ports or [] if p["exposed"] and not p["mitigated"]]
    applied = sum(1 for t in arsenal or [] if t["applied"])
    return '<div class="kpis">' + "".join([
        _kpi(len([f for f in pending if f["severity"] == "CRITICAL"]), "Críticos pendientes", DANGER),
        _kpi(len([f for f in pending if f["severity"] == "WARNING"]), "Avisos pendientes", WARN),
        _kpi(len(fixed) + len(ports_fixed), "Vectores mitigados en la sesión", OK),
        _kpi("—" if ports is None else len(exposed), "Puertos expuestos", WARN if exposed else OK),
        _kpi("—" if arsenal is None else f"{applied}/{len(arsenal)}", "Ajustes del Arsenal aplicados", OK),
    ]) + "</div>"


def _performance_section(data: Dict[str, Any]) -> str:
    perf = data.get("performance") or {}
    storage = data.get("storage") or {}

    def pct(value):
        return "—" if value is None else f"{value:.0f} %"

    def level(value):
        return None if value is None else (DANGER if value >= 90 else WARN if value >= 75 else OK)

    cores = " · ".join(x for x in (f"{perf['cpu_physical']} núcleos" if perf.get("cpu_physical") else "",
                                   f"{perf['cpu_logical']} hilos" if perf.get("cpu_logical") else "",
                                   f"{perf['cpu_mhz']} MHz" if perf.get("cpu_mhz") else "") if x)
    ram_note = (f"{human_bytes(perf['ram_used'])} de {human_bytes(perf['ram_total'])}"
                if perf.get("ram_total") else "")
    kpis = '<div class="kpis">' + "".join([
        _kpi(pct(perf.get("cpu_percent")), "Uso de CPU", level(perf.get("cpu_percent")), cores,
             perf.get("cpu_percent")),
        _kpi(pct(perf.get("ram_percent")), "Uso de memoria", level(perf.get("ram_percent")), ram_note,
             perf.get("ram_percent")),
        _kpi(pct(perf.get("swap_percent")), "Archivo de paginación", level(perf.get("swap_percent"))),
        _kpi(format_duration(perf.get("uptime_s")), "Tiempo encendido", None,
             f"desde {_when(perf.get('boot_time'))}" if perf.get("boot_time") else ""),
        _kpi("—" if perf.get("processes") is None else perf["processes"], "Procesos en ejecución"),
    ]) + "</div>"
    cpu = f'<p class="muted">Procesador: {escape(str(perf.get("cpu_model") or "—"))}</p>' if perf else ""
    rows = []
    for v in storage.get("volumes") or []:
        label = f"{v['mount']}{' (sistema)' if v.get('system') else ''} · {v.get('fstype') or '—'}"
        media = v.get("media") if v.get("media") not in (None, "—") else ""
        if media:
            label += f" · {media}"
        rows.append((label, float(v["percent"]), f"{v['percent']:.0f} % · {human_bytes(v['free'])} libres",
                     LEVEL_COLOR.get(v.get("level"), MUTED)))
    if not perf and not rows:
        return '<p class="muted">Sin métricas de rendimiento en esta sesión.</p>'
    return kpis + cpu + "<h3>Ocupación de las unidades</h3>" + _chart(rows, "No se pudieron leer las unidades.")


def _health_section(data: Dict[str, Any]) -> str:
    health = data.get("health")
    if not health:
        return '<p class="muted">El diagnóstico de salud del sistema no está disponible en esta sesión.</p>'
    verdict = health.get("verdict") or {"level": "unknown", "label": "SIN VERIFICAR", "reasons": []}
    head = (f'<p>Estado global: {_pill(verdict["label"], LEVEL_COLOR.get(verdict["level"], MUTED))}</p>'
            + _reasons(verdict.get("reasons") or []))
    integ = health.get("integrity") or {}
    rows = []
    for name, result in (("Archivos protegidos (SFC)", integ.get("files")),
                         ("Almacén de componentes (DISM)", integ.get("store"))):
        if result:
            rows.append(f'<tr><td>{escape(name)}</td><td>{_pill(result.get("label", "—"), LEVEL_COLOR.get(result.get("level"), MUTED))}'
                        f'</td><td>{escape(_when(result.get("when")))}</td><td>{escape(result.get("message") or "")}'
                        f'<br><code>{escape(result.get("command") or "")}</code></td></tr>')
        else:
            rows.append(f'<tr><td>{escape(name)}</td><td>{_pill("SIN VERIFICAR", MUTED)}</td><td>—</td>'
                        '<td class="muted">Sin resultados en este equipo.</td></tr>')
    integrity = _table(("Comprobación", "Resultado", "Fecha", "Detalle"), rows, "")
    signals = health.get("signals")
    if signals:
        days = signals.get("window_days", 7)

        def count(value):
            return "no disponible" if value is None else str(value)

        pending = signals.get("pending_reboot")
        srows = [("Reinicio pendiente", "no se puede leer" if pending is None else (", ".join(pending) or "no")),
                 ("Tiempo encendido", format_duration(signals.get("uptime_s"))),
                 (f"Apagados inesperados ({days} días)", count(signals.get("unexpected_shutdowns"))),
                 (f"Pantallazos azules ({days} días)", count(signals.get("bugchecks")))]
        for disk in signals.get("disks") or []:
            srows.append((f"Disco «{disk.get('model', '')}»", f"{disk.get('media', '—')} · {disk.get('label', '—').lower()}"))
        stability = _table(("Señal", "Valor"), [f"<tr><td>{escape(k)}</td><td>{escape(v)}</td></tr>" for k, v in srows], "")
    else:
        stability = '<p class="muted">Las señales de estabilidad no se leyeron en esta sesión.</p>'
    return (head + '<div class="cols"><div><h3>Integridad de los archivos del sistema</h3>' + integrity
            + '</div><div><h3>Estabilidad del equipo</h3>' + stability + "</div></div>")


def _optimizations_section(data: Dict[str, Any]) -> str:
    storage = data.get("storage") or {}
    findings, ports, arsenal = data.get("findings") or [], data.get("ports"), data.get("arsenal")
    health = data.get("health") or {}
    recovered = storage.get("recovered") or 0
    scan = storage.get("scan") or {}
    applied = sum(1 for t in arsenal or [] if t["applied"])
    mitigated = sum(1 for f in findings if f["mitigated"]) + sum(1 for p in ports or [] if p.get("mitigated"))
    files = (health.get("integrity") or {}).get("files")
    optimized = storage.get("optimized")
    kpis = '<div class="kpis">' + "".join([
        _kpi(human_bytes(recovered), "Espacio recuperado en la sesión", OK if recovered else None,
             f"{storage.get('runs', 0)} limpieza(s) segura(s)"),
        _kpi(human_bytes(scan["eligible_bytes"]) if scan else "—", "Liberable ahora (seguro)",
             WARN if scan and scan.get("eligible_bytes", 0) >= 1024 ** 3 else None,
             f"análisis {_when(scan.get('when'))}" if scan else "sin analizar"),
        _kpi("—" if arsenal is None else f"{applied}/{len(arsenal)}", "Endurecimiento aplicado", OK, "",
             None if not arsenal else 100.0 * applied / len(arsenal)),
        _kpi(mitigated, "Vectores mitigados", OK if mitigated else None),
        _kpi(files["label"] if files else "SIN VERIFICAR", "Integridad (SFC)",
             LEVEL_COLOR.get(files["level"], MUTED) if files else MUTED, _when(files["when"]) if files else ""),
        _kpi(("SÍ" if optimized.get("ok") else "NO") if optimized else "—", "Unidad optimizada (TRIM/defrag)",
             (OK if optimized.get("ok") else WARN) if optimized else None,
             _when(optimized.get("when")) if optimized else "no ejecutada"),
    ]) + "</div>"
    by = storage.get("recovered_by") or []
    top = max((x["bytes"] for x in by), default=0) or 1
    recovered_rows = [(x["title"], 100.0 * x["bytes"] / top, f"{human_bytes(x['bytes'])} · {x['files']} archivos", OK)
                      for x in by]
    pending = sorted((t for t in scan.get("targets") or [] if t.get("eligible_bytes")),
                     key=lambda t: -t["eligible_bytes"])
    top_p = max((t["eligible_bytes"] for t in pending), default=0) or 1
    pending_rows = [(t["title"] + ("" if t["status"] == "ok" else " (requiere acción)"),
                     100.0 * t["eligible_bytes"] / top_p, human_bytes(t["eligible_bytes"]),
                     WARN if t["status"] == "ok" else MUTED) for t in pending[:8]]
    return (kpis + "<h3>Espacio recuperado por categoría</h3>"
            + _chart(recovered_rows, "Ninguna limpieza en esta sesión.")
            + "<h3>Espacio liberable por categoría</h3>"
            + _chart(pending_rows, "Sin espacio liberable en el último análisis." if scan else
                     "El almacenamiento no se analizó en esta sesión."))


def _document_control(data: Dict[str, Any], doc: Dict[str, Any]) -> str:
    rows = [("Elaborado por", f"{data['app']} (generación automática) · usuario {data['user']}", doc["issued"]),
            ("Revisado por", "", ""), ("Aprobado por", "", "")]
    table = _table(("Rol", "Nombre", "Firma", "Fecha"),
                   [f"<tr><td>{escape(role)}</td><td>{escape(name)}</td><td></td><td>{escape(when)}</td></tr>"
                    for role, name, when in rows], "")
    return (table.replace("<table>", '<table class="signoff">', 1)
            + f'<p class="disclaimer">Documento {escape(doc["reference"])} · {escape(doc["classification"].lower())}. '
            "Se genera localmente a partir de comprobaciones de solo lectura y de las acciones registradas en la Caja "
            "Negra durante la sesión; ningún dato sale del equipo. Lo que no se midió en la sesión figura como «sin "
            "datos» o «sin verificar»: nunca se presenta como correcto.</p>")


def _tables(data: Dict[str, Any]) -> List[str]:
    """Secciones de detalle: vectores mitigados, riesgos pendientes, Arsenal y puertos."""
    findings = data.get("findings") or []
    ports, arsenal = data.get("ports"), data.get("arsenal")
    pending = [f for f in findings if f["severity"] in ("CRITICAL", "WARNING") and not f["mitigated"]]
    fixed = [f for f in findings if f["mitigated"]]
    ports_fixed = [p for p in ports or [] if p["mitigated"]]
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
    return [
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
    ]


# =============================================================================================
# Documento
# =============================================================================================
def render_html(data: dict) -> str:
    """HTML completo del informe. `data` lo arma ui/informe.collect_report(); las claves nuevas (doc,
    performance, storage, health) son opcionales: sin ellas, sus secciones lo indican sin inventar datos."""
    doc = {"reference": report_reference(data.get("host", ""), dt.datetime.now()), "classification": CLASSIFICATION,
           "version": DOC_VERSION, "issued": data.get("generated", ""),
           "scope": "Seguridad, rendimiento y salud del sistema operativo"}
    doc.update(data.get("doc") or {})
    summary = "".join(f"<p>{p}</p>" for p in executive_summary(data))
    body = "".join([
        _header(data, doc),
        _section("Resumen ejecutivo", f'<div class="summary">{summary}</div>{_summary_kpis(data)}', keep=True),
        _section("Puntuación de seguridad", _score_section(data), keep=True),
        _section("Rendimiento del sistema", _performance_section(data), keep=True),
        _section("Salud del sistema operativo", _health_section(data)),
        _section("Resumen visual de optimizaciones", _optimizations_section(data)),
        *_tables(data),
        _section("Control del documento", _document_control(data, doc), keep=True),
        f'<footer>{escape(data["app"])} · informe generado localmente; ningún dato sale del equipo.</footer>',
    ])
    run_head = (f'<div><span>{escape(data["app"])} · Informe ejecutivo de auditoría técnica</span>'
                f'<span>{escape(doc["reference"])} · {escape(doc["classification"])}</span></div>')
    run_foot = (f'<div><span>{escape(data["host"])} · emitido {escape(doc["issued"])}</span>'
                "<span>Documento generado localmente · ningún dato sale del equipo</span></div>")
    return (f'<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Informe ejecutivo · {escape(data["host"])} · {escape(doc["reference"])}</title>'
            f"<style>{CSS}</style></head><body>"
            f'<table class="sheet"><thead class="runhead"><tr><td>{run_head}</td></tr></thead>'
            f'<tfoot class="runfoot"><tr><td>{run_foot}</td></tr></tfoot>'
            f"<tbody><tr><td><main>{body}</main></td></tr></tbody></table></body></html>")
