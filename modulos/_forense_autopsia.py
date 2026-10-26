# -*- coding: utf-8 -*-
"""
Laboratorio forense de Lozarus (todo LOCAL, solo lectura, sin ejecutar nada):

  · Visor de la Caja Negra: lee el `eventos.jsonl` real (un JSON por línea), tolera líneas corruptas,
    filtra por categoría y por texto, y exporta una copia de las evidencias.
  · Mesa de autopsias ESTÁTICA: analiza un archivo SIN ejecutarlo — hashes (MD5/SHA-256), tamaño,
    entropía de Shannon (0–8; aviso si supera 7,2 por posible empaquetado/cifrado), cabeceras básicas
    si es un PE (MZ) y extracción de indicadores (IPs, URLs, rutas de registro y APIs sospechosas).

Funciones aisladas de Qt para poder probarlas sin interfaz. No abre, no lanza y no modifica archivos.
"""

import datetime as dt
import hashlib
import json
import math
import os
import re
import struct
from collections import Counter

ENTROPY_WARN = 7.2                       # por encima: posible packer/cifrado
MAX_SCAN = 24 * 1024 * 1024              # bytes leídos para entropía/strings/PE (los hashes usan todo)


# =============================================================================================
# Visor de la Caja Negra (eventos.jsonl)
# =============================================================================================
# Prefijo de `source` -> categoría legible para el filtro del visor.
_CATEGORIAS = (("honeypot", "honeypot"), ("monitor", "monitor"), ("red", "network"),
               ("fantasma", "privacy"), ("forensics", "forensics"), ("forense", "forensics"))


def event_category(ev):
    """Categoría de un evento a partir del prefijo de su `source`. Pura."""
    src = str(ev.get("source", "")).lower()
    for prefijo, cat in _CATEGORIAS:
        if src.startswith(prefijo):
            return cat
    return "otros"


def read_events(path, source=None, text=None, limit=2000):
    """
    Lee `eventos.jsonl` (un JSON por línea). Devuelve una lista de dicts, los MÁS RECIENTES primero.
    Las líneas corruptas se saltan (no rompen el visor). `source`: categoría a filtrar (ver
    event_category); `text`: subcadena que debe aparecer en la línea; `limit`: tope de filas.
    """
    eventos = []
    if not path or not os.path.isfile(path):
        return eventos
    text_low = text.lower() if text else None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for linea in fh:
            linea = linea.strip()
            if not linea:
                continue
            if text_low and text_low not in linea.lower():
                continue
            try:
                ev = json.loads(linea)
            except (ValueError, TypeError):
                continue
            if not isinstance(ev, dict):
                continue
            if source and event_category(ev) != source:
                continue
            eventos.append(ev)
    eventos.reverse()
    return eventos[:limit] if limit else eventos


def event_row(ev):
    """(hora, categoría, fuente, tipo, resumen) para una fila de la tabla del visor. Pura."""
    prov = ev.get("provenance") or {}
    cuando = prov.get("received_utc") or ev.get("timestamp_utc") or ""
    if cuando and "T" in cuando:
        cuando = cuando.split("+")[0].replace("T", " ")[:19]
    payload = ev.get("payload") or {}
    resumen = ", ".join(f"{k}={v}" for k, v in list(payload.items())[:6])
    return (cuando, event_category(ev), str(ev.get("source", "")),
            str(ev.get("event_type", "") or ""), resumen)


def export_report(events, path):
    """Guarda una copia de los eventos. `.json` → lista indentada; cualquier otra extensión → JSONL.
    Devuelve el número de eventos escritos."""
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(list(events), fh, ensure_ascii=False, indent=2)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return len(events)


# =============================================================================================
# Mesa de autopsias estática (analizador de archivos / PE)
# =============================================================================================
def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon en bits/byte (0–8). Pura."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def classify_entropy(entropy):
    """(etiqueta, aviso) a partir de la entropía. aviso=True si supera ENTROPY_WARN (7,2). Pura."""
    if entropy > ENTROPY_WARN:
        return "alta (posible empaquetado/cifrado)", True
    if entropy >= 6.0:
        return "media", False
    return "baja/normal", False


_MACHINES = {0x14C: "Intel x86 (386+)", 0x8664: "x64 (AMD64)", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2",
             0xAA64: "ARM64", 0x200: "Intel Itanium (IA64)", 0x1C2: "ARM Thumb"}
_SUBSYSTEMS = {1: "Native", 2: "GUI de Windows", 3: "Consola (CUI)", 5: "OS/2", 7: "POSIX",
               9: "Windows CE", 10: "EFI", 16: "Boot"}
_MAGIC = {0x10B: "PE32", 0x20B: "PE32+", 0x107: "ROM"}


def parse_pe_headers(data: bytes):
    """
    Cabeceras PE básicas a partir de los bytes del fichero (que empiezan por 'MZ'). Devuelve un dict
    o None si no es un PE válido. No ejecuta nada; solo lee estructuras con comprobación de límites.
    """
    try:
        if data[:2] != b"MZ" or len(data) < 0x40:
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew <= 0 or e_lfanew + 24 > len(data):
            return None
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        machine, n_sec, timestamp, _psym, _nsym, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
        pe = {
            "machine": machine, "machine_name": _MACHINES.get(machine, f"0x{machine:04x}"),
            "sections": n_sec, "timestamp": timestamp, "timestamp_utc": _ts_utc(timestamp),
            "characteristics": chars, "is_dll": bool(chars & 0x2000), "is_exe": bool(chars & 0x0002),
            "magic": None, "magic_name": "?", "subsystem": None, "subsystem_name": "?",
            "opt_header_size": opt_size,
        }
        opt = coff + 20
        if opt + 2 <= len(data):
            magic = struct.unpack_from("<H", data, opt)[0]
            pe["magic"], pe["magic_name"] = magic, _MAGIC.get(magic, f"0x{magic:04x}")
        if opt + 70 <= len(data):   # Subsystem está en el offset 68 del optional header (PE32 y PE32+)
            subsys = struct.unpack_from("<H", data, opt + 68)[0]
            pe["subsystem"], pe["subsystem_name"] = subsys, _SUBSYSTEMS.get(subsys, f"0x{subsys:04x}")
        return pe
    except (struct.error, IndexError, ValueError):
        return None


def _ts_utc(ts):
    try:
        if 0 < int(ts) < 4102444800:   # entre 1970 y ~2100: timestamp plausible
            return dt.datetime.fromtimestamp(int(ts), dt.timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        pass
    return None


# APIs / cadenas cuya presencia en un binario es, cuando menos, digna de mirar con lupa.
_APIS_SOSPECHOSAS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "SetWindowsHookEx", "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "WinExec",
    "ShellExecute", "CreateProcess", "URLDownloadToFile", "InternetOpen", "InternetReadFile",
    "AdjustTokenPrivileges", "OpenProcess", "CreateService", "RegSetValue", "CryptEncrypt",
    "FromBase64String", "Invoke-Expression", "IEX", "DownloadString", "powershell",
    "cmd.exe", "rundll32", "regsvr32", "schtasks", "bcdedit", "vssadmin", "wscript", "mshta",
]
_RX_URL = re.compile(r"(?:https?|ftp)://[^\s\"'<>|]{4,200}", re.I)
_RX_REG = re.compile(r"(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"'<>|]{3,200}", re.I)
_RX_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _strings_ascii(data, minlen=4):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "replace"))
    return out


def _strings_utf16(data, minlen=4):
    out, cur, i, n = [], bytearray(), 0, len(data)
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if 32 <= lo < 127 and hi == 0:
            cur.append(lo)
            i += 2
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
            i += 1
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "replace"))
    return out


def _valid_ip(s):
    partes = s.split(".")
    return len(partes) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in partes)


def _dedup(seq, cap=60):
    vistos, out = set(), []
    for x in seq:
        if x not in vistos:
            vistos.add(x)
            out.append(x)
            if len(out) >= cap:
                break
    return out


def extract_indicators(data: bytes):
    """
    Extrae indicadores de los bytes (ASCII + UTF-16LE): IPs, URLs, rutas de registro y APIs
    sospechosas. Pura; no ejecuta nada. Devuelve {ips, urls, registry, apis}.
    """
    strings = _strings_ascii(data) + _strings_utf16(data)
    blob = "\n".join(strings)
    blob_low = blob.lower()
    ips = [s for s in _RX_IP.findall(blob) if _valid_ip(s) and s != "0.0.0.0"]
    urls = _RX_URL.findall(blob)
    registry = _RX_REG.findall(blob)
    apis = [api for api in _APIS_SOSPECHOSAS if api.lower() in blob_low]
    return {"ips": _dedup(ips), "urls": _dedup(urls),
            "registry": _dedup(registry), "apis": _dedup(apis)}


def analyze_file(path):
    """
    Autopsia ESTÁTICA de un archivo (no se ejecuta). Devuelve un dict con: ok, path, name, size, md5,
    sha256, entropy, entropy_warn, is_pe, pe (o None), indicators, error. Nunca lanza.
    """
    res = {"ok": False, "path": path, "name": os.path.basename(path), "size": 0, "md5": "",
           "sha256": "", "entropy": 0.0, "entropy_warn": False, "is_pe": False, "pe": None,
           "indicators": {}, "error": ""}
    try:
        if not os.path.isfile(path):
            res["error"] = "No es un archivo regular o no existe."
            return res
        res["size"] = os.path.getsize(path)
        md5, sha = hashlib.md5(), hashlib.sha256()
        head = bytearray()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                md5.update(chunk)
                sha.update(chunk)
                if len(head) < MAX_SCAN:
                    head.extend(chunk[:MAX_SCAN - len(head)])
        head = bytes(head)
        res["md5"] = md5.hexdigest()
        res["sha256"] = sha.hexdigest()
        res["entropy"] = round(shannon_entropy(head), 3)
        res["entropy_warn"] = res["entropy"] > ENTROPY_WARN
        res["is_pe"] = head[:2] == b"MZ"
        if res["is_pe"]:
            res["pe"] = parse_pe_headers(head)
        res["indicators"] = extract_indicators(head)
        res["ok"] = True
    except Exception as exc:  # noqa: BLE001
        res["error"] = f"{type(exc).__name__}: {exc}"
    return res
