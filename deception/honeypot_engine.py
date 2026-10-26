# -*- coding: utf-8 -*-
"""
Motor de Honeypot autónomo (SIN privilegios de Administrador).

Despliega dos tipos de trampas en una carpeta señuelo controlada y las vigila con un hilo de baja
latencia que, para cada cebo, comprueba su EXISTENCIA y su INTEGRIDAD (SHA-256 + tamaño):

  · Canarios de integridad/ransomware: ficheros cebo (.docx/.xlsx/.pdf simulados) con contenido de
    relleno de entropía conocida.
  · Honeypot de credenciales/InfoStealers: ficheros de alto valor (passwords_export.csv,
    seed_phrase_backup.txt, .env_production) con tokens FALSOS generados dinámicamente.

Cuando se detecta MODIFICACIÓN o ELIMINACIÓN de un cebo, el motor:
  1. Intenta identificar (mejor esfuerzo, con psutil) un proceso del usuario con el directorio abierto.
  2. Emite un Event crítico al EventBus (que la Caja Negra persiste en eventos.jsonl).
  3. Si la Auto-Reconstrucción está activa, regenera el cebo al instante.

LÍMITES HONESTOS (modo usuario, sin driver ni auditoría SACL):
  · Se detecta de forma fiable CREACIÓN, MODIFICACIÓN y BORRADO (por hash/tamaño/existencia).
  · NO se puede detectar la simple LECTURA de un fichero sin modificarlo: eso exige auditoría del SO
    (SACL, Administrador) o un driver. No se finge esa capacidad.
  · La atribución del proceso es TENTATIVA: sin privilegios, `open_files()` de procesos ajenos suele
    dar AccessDenied; se marca «no atribuible» en ese caso, nunca se inventa un culpable.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import secrets
import threading
import time
from typing import Any, Callable, Dict, List, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False

# Estados de un cebo
INTACTO, MODIFICADO, ELIMINADO = "Intacto", "Modificado", "Eliminado"

# Tipos de trampa
CANARIO, CREDENCIAL = "Canario", "Credencial"

_DECOY_MARK = "LOZARUS DECOY — fichero señuelo inofensivo. No contiene datos reales."


def _fake_token(nbytes: int = 24) -> str:
    return secrets.token_hex(nbytes)


# Generadores de contenido (bytes). Los canarios llevan relleno pseudoaleatorio (entropía); las
# credenciales, tokens FALSOS dinámicos. Todo marcado claramente como señuelo de Lozarus.
def _canario(nombre: str) -> Callable[[], bytes]:
    def gen() -> bytes:
        relleno = secrets.token_bytes(4096)  # entropía conocida solo tras escribir (baseline = hash)
        cabecera = (f"{_DECOY_MARK}\nDocumento: {nombre}\n"
                    f"Generado: {dt.datetime.now().isoformat(timespec='seconds')}\n\n").encode("utf-8")
        return cabecera + relleno
    return gen


def _passwords_csv() -> bytes:
    filas = ["sitio,usuario,contraseña"]
    for sitio in ("banco-online", "correo-corporativo", "vpn-empresa", "cripto-exchange"):
        filas.append(f"{sitio}.example,admin,{_fake_token(16)}")
    return (f"# {_DECOY_MARK}\n" + "\n".join(filas) + "\n").encode("utf-8")


def _seed_phrase() -> bytes:
    palabras = [secrets.token_hex(3) for _ in range(12)]  # 12 «palabras» FALSAS
    return (f"{_DECOY_MARK}\nBIP39 (señuelo, sin validez): " + " ".join(palabras) + "\n").encode("utf-8")


def _env_production() -> bytes:
    lineas = [f"# {_DECOY_MARK}",
              f"DATABASE_URL=postgres://decoy:{_fake_token(12)}@db.example:5432/prod",
              f"AWS_SECRET_ACCESS_KEY={_fake_token(20)}",
              f"STRIPE_SECRET_KEY=sk_live_{_fake_token(16)}",
              f"JWT_SECRET={_fake_token(24)}"]
    return ("\n".join(lineas) + "\n").encode("utf-8")


# (nombre de fichero, tipo, generador de contenido)
TRAP_SPECS = [
    ("Finanzas_Q4_2026.docx", CANARIO, _canario("Finanzas_Q4_2026")),
    ("Nomina_Confidencial.xlsx", CANARIO, _canario("Nomina_Confidencial")),
    ("Contrato_Fusion.pdf", CANARIO, _canario("Contrato_Fusion")),
    ("passwords_export.csv", CREDENCIAL, _passwords_csv),
    ("seed_phrase_backup.txt", CREDENCIAL, _seed_phrase),
    (".env_production", CREDENCIAL, _env_production),
]


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class HoneypotEngine:
    """
    Gestiona la red de trampas señuelo. `bus` (opcional) recibe los Events; `event_factory` permite
    inyectar el constructor de Event en pruebas (por defecto usa core.events.Event).
    Todo es observación + registro: no termina procesos ni cambia prioridades.
    """

    def __init__(self, decoy_dir: str, bus=None, event_factory: Optional[Callable[..., Any]] = None,
                 auto_rebuild: bool = False, interval: float = 1.0):
        self.decoy_dir = decoy_dir
        self.bus = bus
        self.auto_rebuild = auto_rebuild
        self.interval = max(0.2, float(interval))
        self._event_factory = event_factory
        self._lock = threading.Lock()
        self._scan_lock = threading.Lock()   # serializa scan_once (evita incidentes duplicados)
        self._traps: Dict[str, Dict[str, Any]] = {}   # path -> {name, tipo, hash, size, state}
        self._incidents: List[Dict[str, Any]] = []
        self._active = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # --- despliegue / retirada ----------------------------------------------------------------
    def deploy(self) -> Dict[str, Any]:
        """Crea la carpeta y los cebos, calcula su línea base (hash/tamaño) y activa la red."""
        os.makedirs(self.decoy_dir, exist_ok=True)
        with self._lock:
            self._traps.clear()
            for name, tipo, gen in TRAP_SPECS:
                path = os.path.join(self.decoy_dir, name)
                self._write(path, gen)
                self._traps[path] = {"name": name, "tipo": tipo, "hash": _sha256(path),
                                     "size": self._size(path), "state": INTACTO, "gen": gen}
            self._active = True
        return {"desplegadas": len(self._traps), "dir": self.decoy_dir}

    def retract(self) -> Dict[str, Any]:
        """Retira los cebos (borra los ficheros) y desactiva la red."""
        with self._lock:
            removed = 0
            for path in list(self._traps):
                try:
                    os.remove(path)
                    removed += 1
                except OSError:
                    pass
            self._traps.clear()
            self._active = False
        return {"retiradas": removed}

    @staticmethod
    def _write(path: str, gen: Callable[[], bytes]) -> None:
        with open(path, "wb") as fh:
            fh.write(gen())

    @staticmethod
    def _size(path: str) -> Optional[int]:
        try:
            return os.path.getsize(path)
        except OSError:
            return None

    def add_custom_trap(self, name: str, tipo: str = CANARIO) -> str:
        """Añade una trampa personalizada al nombre dado (sin ruta). Devuelve la ruta creada.
        Si el honeypot no está desplegado aún, crea igualmente el fichero pero sin vigilarlo."""
        safe = os.path.basename(name).strip() or "trampa_personalizada.txt"
        path = os.path.join(self.decoy_dir, safe)
        os.makedirs(self.decoy_dir, exist_ok=True)
        gen = _canario(safe)
        self._write(path, gen)
        with self._lock:
            self._traps[path] = {"name": safe, "tipo": tipo, "hash": _sha256(path),
                                 "size": self._size(path), "state": INTACTO, "gen": gen}
        return path

    # --- vigilancia ---------------------------------------------------------------------------
    def start(self) -> None:
        """Arranca el hilo vigilante (idempotente). Requiere haber desplegado antes."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._watch, name="honeypot", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _watch(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception:  # noqa: BLE001  (el vigilante nunca debe morir por un fallo puntual)
                pass
            self._stop.wait(self.interval)

    def scan_once(self) -> List[Dict[str, Any]]:
        """
        Comprueba cada cebo una vez. Detecta modificación (hash/tamaño) y borrado (existencia).
        Registra incidentes, emite Events y, si procede, reconstruye. Devuelve el estado de los cebos.

        Serializado con `_scan_lock`: dos escaneos nunca corren a la vez, así una misma alteración no
        genera incidentes duplicados (p. ej. si el vigilante y una llamada externa coinciden).
        """
        with self._scan_lock:
            nuevos: List[Dict[str, Any]] = []
            with self._lock:
                trampas = [(p, dict(t)) for p, t in self._traps.items()]
            for path, info in trampas:
                if not os.path.exists(path):
                    if info["state"] != ELIMINADO:
                        nuevos.append(self._incident(path, info, ELIMINADO))
                else:
                    actual = _sha256(path)
                    if actual is not None and actual != info["hash"] and info["state"] != MODIFICADO:
                        nuevos.append(self._incident(path, info, MODIFICADO))
            for inc in nuevos:
                self._emit(inc)
                if self.auto_rebuild:
                    self._rebuild(inc["path"])
            return self.trap_list()

    def _incident(self, path: str, info: Dict[str, Any], change: str) -> Dict[str, Any]:
        suspect = self._identify_suspect()
        incident = {
            "ts": dt.datetime.now().strftime("%H:%M:%S"),
            "iso": dt.datetime.now().isoformat(timespec="seconds"),
            "trap": info["name"], "tipo": info["tipo"], "change": change, "path": path,
            "hash_before": info["hash"], "suspect": suspect, "recorded": False,
        }
        with self._lock:
            if path in self._traps:
                self._traps[path]["state"] = change
            self._incidents.append(incident)
        return incident

    def _identify_suspect(self) -> str:
        """Mejor esfuerzo: proceso del usuario con la carpeta señuelo abierta. Honesto si no se puede."""
        if not HAS_PSUTIL:
            return "no atribuible (psutil no disponible)"
        target = os.path.normcase(self.decoy_dir)
        deadline = time.time() + 0.8  # presupuesto de tiempo: no bloquear el vigilante
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                if time.time() > deadline:
                    break
                try:
                    for f in proc.open_files():
                        if os.path.normcase(f.path).startswith(target):
                            return f"{proc.info.get('name') or '?'} (PID {proc.info.get('pid')})"
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.Error, OSError):
                    continue
        except Exception:  # noqa: BLE001
            pass
        return "no atribuible sin privilegios"

    def _emit(self, incident: Dict[str, Any]) -> None:
        """Publica un Event crítico en el bus (para la Caja Negra). Marca el incidente como grabado."""
        if self.bus is None:
            return
        factory = self._event_factory or self._default_factory()
        if factory is None:
            return
        try:
            event = factory(
                source="honeypot", event_type="honeypot.triggered",
                payload={"trap": incident["trap"], "tipo": incident["tipo"],
                         "change": incident["change"], "path": incident["path"],
                         "severity": "CRITICAL", "suspect": incident["suspect"],
                         "hash_before": incident["hash_before"]})
            if self.bus.publish(event):
                with self._lock:
                    incident["recorded"] = True
        except Exception:  # noqa: BLE001  (un fallo del bus no debe romper el vigilante)
            pass

    @staticmethod
    def _default_factory():
        try:
            from core.events import Event, ObservationQuality

            def make(**kw):
                return Event.create(observation=ObservationQuality.COMPLETE, **kw)
            return make
        except Exception:  # noqa: BLE001
            return None

    def _rebuild(self, path: str) -> None:
        """Regenera un cebo borrado o modificado y restablece su línea base (estado Intacto)."""
        with self._lock:
            info = self._traps.get(path)
            if info is None:
                return
            gen = info["gen"]
        try:
            os.makedirs(self.decoy_dir, exist_ok=True)
            self._write(path, gen)
            new_hash, new_size = _sha256(path), self._size(path)
            with self._lock:
                if path in self._traps:
                    self._traps[path].update({"hash": new_hash, "size": new_size, "state": INTACTO})
        except OSError:
            pass

    # --- estado para la GUI -------------------------------------------------------------------
    def trap_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [{"name": t["name"], "tipo": t["tipo"], "path": p,
                     "hash": (t["hash"] or "")[:12], "state": t["state"]}
                    for p, t in self._traps.items()]

    def status(self) -> Dict[str, Any]:
        with self._lock:
            traps = list(self._traps.values())
            comprometidos = [t for t in traps if t["state"] != INTACTO]
            return {"active": self._active, "auto_rebuild": self.auto_rebuild,
                    "total": len(traps), "integridad": not comprometidos,
                    "comprometidos": len(comprometidos),
                    "incidentes": len(self._incidents), "dir": self.decoy_dir}

    def new_incidents(self, since: int) -> List[Dict[str, Any]]:
        """Incidentes a partir del índice `since` (para la consola de alertas de la GUI)."""
        with self._lock:
            return list(self._incidents[since:])

    def incident_count(self) -> int:
        with self._lock:
            return len(self._incidents)

    @property
    def active(self) -> bool:
        return self._active
