"""
modulos/_mitigacion.py · LOZARUS KIT TOOL

Motor de MITIGACIÓN del Escaneo de Vectores. Cada hallazgo con remediación conocida se traduce en un
Remedio: una lista ordenada de pasos atómicos sobre ESTE equipo (valor del registro, comando de
netsh/sc/net/schtasks, directiva de seguridad con secedit, ajuste del Arsenal o cmdlet de PowerShell).

Garantías:
  · Transacción: los pasos se aplican en orden y, si uno falla, se deshacen los ya aplicados.
  · Verificación: los valores del registro y las directivas se releen tras escribirlos.
  · Auditoría: cada paso guarda el «antes» y el «después» (event_payload → Caja Negra).
  · Reversión: undo_remedy() restaura los valores previos. Los pasos que no admiten deshacer (p. ej.
    encender el firewall: Lozarus nunca lo apaga) lo declaran y la interfaz no ofrece «Deshacer».

Sin Qt y con el sistema detrás de un backend: las pruebas usan un doble en memoria.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ._base import ADMIN_NAME, CRITICAL, SKIP, WARNING
from ._inicio import RUN_KEYS

REG_SZ, REG_DWORD = 1, 4

UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
PS_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
DEVICEGUARD_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
HVCI_KEY = DEVICEGUARD_KEY + r"\Scenarios\HypervisorEnforcedCodeIntegrity"
LANMAN_KEY = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
TS_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP_KEY = TS_KEY + r"\WinStations\RDP-Tcp"
TS_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
WDIGEST_KEY = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
AUTORUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
WU_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
LSA_PPL_NO_UEFI_BUILD = 22621  # Windows 11 22H2: RunAsPPL = 2 activa la protección SIN bloqueo UEFI

# Mecanismo de cada paso: lo que la interfaz muestra en la columna «Acción directa».
MECHANISMS = {"WINREG": "Registro (winreg)", "NETSH": "Firewall (netsh)", "DIRECTIVA": "Directiva de seguridad",
              "CUENTA": "Cuenta local (net user)", "SERVICIO": "Servicio (sc.exe)", "DEFENDER": "Microsoft Defender",
              "TAREA": "Tarea programada (schtasks)", "DISM": "Característica de Windows (DISM)"}
FIREWALL_PROFILES = {"Domain": ("Dominio", "domainprofile"), "Private": ("Privado", "privateprofile"),
                     "Public": ("Público", "publicprofile")}
SYSTEM_TOOLS = ("netsh", "sc", "net", "schtasks", "secedit", "ipconfig", "arp")


class StepError(Exception):
    """Un paso no se pudo aplicar, verificar o deshacer."""


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:240] if lines else ""


def _sys32(exe: str) -> str:
    """Herramientas del sistema por ruta absoluta (evita el secuestro por PATH)."""
    if exe.lower() not in SYSTEM_TOOLS:
        return exe
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", exe + ".exe")
    return path if os.path.isfile(path) else exe


def parse_inf(text: str) -> Dict[str, str]:
    """Pares «Clave = valor» de un INF exportado por secedit (función pura)."""
    return dict(re.findall(r"^\s*(\w+)\s*=\s*(.*?)\s*$", text or "", re.M))


def build_inf(settings: Dict[str, Any]) -> str:
    """Plantilla de seguridad mínima con solo las directivas de [System Access] indicadas."""
    lines = "".join(f"{key} = {value}\n" for key, value in settings.items())
    return ("[Unicode]\nUnicode=yes\n[System Access]\n" + lines +
            '[Version]\nsignature="$CHICAGO$"\nRevision=1\n')


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return value


# =================================================================================================
# Backend real (Windows). Las pruebas sustituyen esta clase por un doble en memoria.
# =================================================================================================
class WindowsBackend:
    def reg_read(self, hive: str, subkey: str, name: str) -> Tuple[bool, Any, Optional[int]]:
        from ._arsenal import read_value  # winreg: solo Windows
        return read_value(hive, subkey, name)

    def reg_write(self, hive: str, subkey: str, name: str, data: Any, kind: Optional[int]) -> None:
        from ._arsenal import write_value
        write_value(hive, subkey, name, data, kind)

    def reg_delete(self, hive: str, subkey: str, name: str) -> None:
        from ._arsenal import delete_value
        delete_value(hive, subkey, name)

    def run(self, argv: Sequence[str], timeout: int = 120) -> Tuple[int, str]:
        from ._utilidades import run_cmd
        rc, out, err = run_cmd([_sys32(argv[0])] + list(argv[1:]), timeout=timeout)
        return rc, (out + "\n" + err).strip()

    def powershell(self, script: str, timeout: int = 300) -> Tuple[int, str]:
        from ._utilidades import powershell_raw
        rc, out, err = powershell_raw(script, timeout=timeout)
        return rc, (out + "\n" + err).strip()

    def secedit_read(self) -> Dict[str, str]:
        """Directivas de [System Access] actuales (secedit /export: requiere Administrador)."""
        workdir = tempfile.mkdtemp(prefix="lozarus_sec_")
        cfg = os.path.join(workdir, "export.inf")
        try:
            rc, out = self.run(["secedit", "/export", "/cfg", cfg, "/areas", "SECURITYPOLICY", "/quiet"], 90)
            if not os.path.isfile(cfg):
                raise StepError(_last_line(out) or f"secedit /export devolvió el código {rc}")
            with open(cfg, encoding="utf-16") as fh:
                return parse_inf(fh.read())
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def secedit_write(self, settings: Dict[str, Any]) -> Tuple[int, str]:
        """Aplica SOLO las directivas indicadas (base de datos temporal: el resto no se toca)."""
        workdir = tempfile.mkdtemp(prefix="lozarus_sec_")
        inf, db = os.path.join(workdir, "lozarus.inf"), os.path.join(workdir, "lozarus.sdb")
        try:
            with open(inf, "w", encoding="utf-16") as fh:
                fh.write(build_inf(settings))
            return self.run(["secedit", "/configure", "/db", db, "/cfg", inf, "/areas", "SECURITYPOLICY",
                             "/quiet"], 120)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def arsenal_apply(self, key: str) -> dict:
        from . import _arsenal
        return _arsenal.apply(_arsenal.BY_KEY[key])

    def arsenal_revert(self, key: str) -> dict:
        from . import _arsenal
        return _arsenal.revert(_arsenal.BY_KEY[key])

    def arsenal_is_applied(self, key: str) -> bool:
        from . import _arsenal
        return _arsenal.is_applied(_arsenal.BY_KEY[key])

    def windows_build(self) -> int:
        try:
            from ._utilidades import windows_build
            return int(windows_build())
        except Exception:  # noqa: BLE001
            return 0


BACKEND = WindowsBackend()


def probe(be, hive: str, subkey: str, name: str) -> Tuple[bool, Any]:
    """Lectura tolerante para DECIDIR el remedio (fuera de Windows o sin acceso: «no existe»)."""
    try:
        exists, data, _kind = be.reg_read(hive, subkey, name)
        return bool(exists), data
    except Exception:  # noqa: BLE001
        return False, None


# =================================================================================================
# Pasos atómicos
# =================================================================================================
@dataclass
class RegSet:
    """Escribe un valor (DWORD o REG_SZ), lo relee para verificarlo y guarda el original."""
    hive: str
    subkey: str
    name: str
    data: Any
    kind: int = REG_DWORD
    undoable: bool = True
    mechanism: str = "WINREG"

    @property
    def path(self) -> str:
        return f"{self.hive}\\{self.subkey}\\{self.name or '(predeterminado)'}"

    @property
    def admin(self) -> bool:
        return self.hive == "HKLM"

    def describe(self) -> str:
        return f"{self.path} = {self.data} ({'DWORD' if self.kind == REG_DWORD else 'REG_SZ'})"

    def apply(self, be) -> dict:
        exists, before, kind = be.reg_read(self.hive, self.subkey, self.name)
        rec = {"what": self.describe(), "before": {"exists": exists, "data": before, "type": kind},
               "after": self.data}
        be.reg_write(self.hive, self.subkey, self.name, self.data, self.kind)
        ok, now, _kind = be.reg_read(self.hive, self.subkey, self.name)
        if not ok or now != self.data:
            self.undo(be, rec)
            raise StepError(f"{self.path}: el valor no quedó escrito (se leyó {now!r})")
        return rec

    def undo(self, be, rec: dict) -> None:
        before = rec["before"]
        if before["exists"]:
            be.reg_write(self.hive, self.subkey, self.name, before["data"], before["type"])
        else:
            be.reg_delete(self.hive, self.subkey, self.name)

    def undo_describe(self, rec: dict) -> str:
        before = rec["before"]
        return (f"{self.path} = {before['data']!r} (valor original)" if before["exists"]
                else f"{self.path} → se elimina (no existía)")


@dataclass
class RegDelete:
    """Elimina un valor (entrada de arranque) con copia previa para poder restaurarlo."""
    hive: str
    subkey: str
    name: str
    undoable: bool = True
    mechanism: str = "WINREG"

    @property
    def path(self) -> str:
        return f"{self.hive}\\{self.subkey}\\{self.name}"

    @property
    def admin(self) -> bool:
        return self.hive == "HKLM"

    def describe(self) -> str:
        return f"{self.path} → eliminar el valor (copia previa en la Caja Negra)"

    def apply(self, be) -> dict:
        exists, before, kind = be.reg_read(self.hive, self.subkey, self.name)
        rec = {"what": self.describe(), "before": {"exists": exists, "data": before, "type": kind}, "after": None}
        if not exists:
            return rec  # ya no existe: el objetivo de la mitigación ya se cumple
        be.reg_delete(self.hive, self.subkey, self.name)
        if be.reg_read(self.hive, self.subkey, self.name)[0]:
            raise StepError(f"{self.path}: el valor sigue existiendo tras borrarlo")
        return rec

    def undo(self, be, rec: dict) -> None:
        before = rec["before"]
        if before["exists"]:
            be.reg_write(self.hive, self.subkey, self.name, before["data"], before["type"])

    def undo_describe(self, rec: dict) -> str:
        before = rec["before"]
        return f"{self.path} = {before['data']!r} (se restaura)" if before["exists"] else f"{self.path} (no existía)"


@dataclass
class Command:
    """Comando del sistema sin shell (netsh, sc, net, schtasks). Éxito = código de salida 0."""
    argv: Tuple[str, ...]
    undo_argv: Optional[Tuple[str, ...]] = None
    mechanism: str = "NETSH"
    timeout: int = 120
    admin: bool = True

    @property
    def undoable(self) -> bool:
        return self.undo_argv is not None

    def describe(self) -> str:
        return subprocess.list2cmdline(self.argv)

    def _run(self, be, argv: Sequence[str]) -> str:
        rc, out = be.run(list(argv), self.timeout)
        if rc != 0:
            raise StepError(f"«{subprocess.list2cmdline(argv)}» terminó con código {rc}: {_last_line(out)}")
        return _last_line(out)

    def apply(self, be) -> dict:
        return {"what": self.describe(), "output": self._run(be, self.argv)}

    def undo(self, be, rec: dict) -> None:
        if self.undo_argv is None:
            raise StepError(f"«{self.describe()}» no admite deshacer")
        self._run(be, self.undo_argv)

    def undo_describe(self, rec: dict) -> str:
        return subprocess.list2cmdline(self.undo_argv) if self.undo_argv else f"{self.describe()} (sin deshacer)"


@dataclass
class PowerShell:
    """Cmdlet de PowerShell (Defender, características de Windows). Error terminante = fallo."""
    script: str
    undo_script: Optional[str] = None
    mechanism: str = "DEFENDER"
    timeout: int = 300
    admin: bool = True

    @property
    def undoable(self) -> bool:
        return self.undo_script is not None

    def describe(self) -> str:
        return self.script

    def _run(self, be, script: str) -> str:
        rc, out = be.powershell(script, self.timeout)
        if rc != 0:
            raise StepError(f"PowerShell terminó con código {rc}: {_last_line(out)}")
        return _last_line(out)

    def apply(self, be) -> dict:
        return {"what": self.describe(), "output": self._run(be, self.script)}

    def undo(self, be, rec: dict) -> None:
        if self.undo_script is None:
            raise StepError("este paso no admite deshacer")
        self._run(be, self.undo_script)

    def undo_describe(self, rec: dict) -> str:
        return self.undo_script or f"{self.script} (sin deshacer)"


@dataclass
class SecPolicy:
    """Directiva de [System Access] con secedit; se relee para verificarla."""
    setting: str
    value: int
    undoable: bool = True
    mechanism: str = "DIRECTIVA"
    admin: bool = True

    def describe(self) -> str:
        return f"secedit /configure · [System Access] {self.setting} = {self.value}"

    def _set(self, be, value) -> None:
        rc, out = be.secedit_write({self.setting: value})
        now = be.secedit_read().get(self.setting)
        if str(now) != str(value):
            raise StepError(f"secedit no aplicó {self.setting} = {value} (código {rc}: {_last_line(out)})")

    def apply(self, be) -> dict:
        before = be.secedit_read().get(self.setting)
        self._set(be, self.value)
        return {"what": self.describe(), "before": before, "after": self.value}

    def undo(self, be, rec: dict) -> None:
        if rec.get("before") is None:
            raise StepError(f"{self.setting} no estaba definida: no hay valor previo que restaurar")
        self._set(be, rec["before"])

    def undo_describe(self, rec: dict) -> str:
        return f"secedit /configure · [System Access] {self.setting} = {rec.get('before')} (valor original)"


@dataclass
class AccountPolicy:
    """Política de cuentas con `net accounts`; el valor previo y la verificación salen de secedit."""
    flag: str        # minpwlen | lockoutthreshold
    value: int
    setting: str     # clave equivalente en secedit: MinimumPasswordLength | LockoutBadCount
    undoable: bool = True
    mechanism: str = "DIRECTIVA"
    admin: bool = True

    def describe(self) -> str:
        return f"net accounts /{self.flag}:{self.value}"

    def _set(self, be, value) -> None:
        rc, out = be.run(["net", "accounts", f"/{self.flag}:{value}"], 60)
        if rc != 0:
            raise StepError(f"net accounts /{self.flag}:{value} terminó con código {rc}: {_last_line(out)}")
        now = be.secedit_read().get(self.setting)
        if str(now) != str(value):
            raise StepError(f"{self.setting} sigue valiendo {now!r} tras net accounts")

    def apply(self, be) -> dict:
        before = be.secedit_read().get(self.setting)
        self._set(be, self.value)
        return {"what": self.describe(), "before": before, "after": self.value}

    def undo(self, be, rec: dict) -> None:
        if rec.get("before") is None:
            raise StepError(f"{self.setting}: valor previo desconocido")
        self._set(be, rec["before"])

    def undo_describe(self, rec: dict) -> str:
        return f"net accounts /{self.flag}:{rec.get('before')} (valor original)"


@dataclass
class ArsenalTweak:
    """Delegación en el Arsenal: el original queda en rollback_state.json y su badge pasa a APLICADO."""
    tweak: str
    undoable: bool = True
    mechanism: str = "WINREG"

    @property
    def admin(self) -> bool:
        from . import _arsenal
        return _arsenal.BY_KEY[self.tweak].admin

    def describe(self) -> str:
        from . import _arsenal
        values = "; ".join(_arsenal.describe(v) for v in _arsenal.BY_KEY[self.tweak].values)
        return f"{values}  · Arsenal (rollback_state.json)"

    def apply(self, be) -> dict:
        info = be.arsenal_apply(self.tweak)
        if not be.arsenal_is_applied(self.tweak):
            be.arsenal_revert(self.tweak)
            raise StepError(f"el ajuste «{self.tweak}» del Arsenal no quedó aplicado")
        return {"what": self.describe(), "arsenal": info}

    def undo(self, be, rec: dict) -> None:
        be.arsenal_revert(self.tweak)

    def undo_describe(self, rec: dict) -> str:
        return f"Arsenal · revertir «{self.tweak}» desde rollback_state.json"


# =================================================================================================
# Remedio = pasos + inteligencia defensiva
# =================================================================================================
@dataclass
class Remedy:
    key: str                 # agrupa acciones idénticas: en lote se ejecutan una sola vez
    label: str               # texto del botón
    icon: str
    protects: str            # qué protege (inteligencia defensiva)
    impact: str              # qué cambia en el equipo al aplicarlo
    steps: List[Any]
    reboot: bool = False
    batch: bool = True       # False: solo de forma individual (puede cortar servicios en uso)

    @property
    def mechanism(self) -> str:
        return self.steps[0].mechanism if self.steps else "WINREG"

    @property
    def mechanisms(self) -> List[str]:
        return list(dict.fromkeys(s.mechanism for s in self.steps))

    @property
    def admin(self) -> bool:
        return any(getattr(s, "admin", True) for s in self.steps)

    @property
    def undoable(self) -> bool:
        return bool(self.steps) and all(s.undoable for s in self.steps)

    def targets(self) -> List[str]:
        return [s.describe() for s in self.steps]


def apply_remedy(remedy: Remedy, be=None) -> dict:
    """Aplica los pasos en orden; si uno falla, deshace los anteriores (transacción). Nunca lanza."""
    be = be or BACKEND
    records: List[dict] = []
    try:
        for step in remedy.steps:
            records.append(step.apply(be))
    except Exception as exc:  # noqa: BLE001  (se informa y se revierte; nunca a medias)
        undo_errors = []
        for step, rec in reversed(list(zip(remedy.steps, records))):
            try:
                step.undo(be, rec)
            except Exception as undo_exc:  # noqa: BLE001
                undo_errors.append(f"{step.describe()}: {undo_exc}")
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "records": records,
                "rolled_back": bool(records) and not undo_errors, "undo_errors": undo_errors}
    return {"ok": True, "records": records}


def undo_remedy(remedy: Remedy, records: List[dict], be=None) -> dict:
    """Restaura los valores previos en orden inverso. Nunca lanza: devuelve {ok, errors}."""
    be = be or BACKEND
    errors = []
    for step, rec in reversed(list(zip(remedy.steps, records))):
        try:
            step.undo(be, rec)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{step.describe()}: {exc}")
    return {"ok": not errors, "errors": errors}


def undo_preview(remedy: Remedy, records: List[dict]) -> List[str]:
    """Lo EXACTO que hará undo_remedy() (para la confirmación), en el mismo orden inverso."""
    return [step.undo_describe(rec) for step, rec in reversed(list(zip(remedy.steps, records)))]


def event_payload(remedy: Remedy, result: dict) -> dict:
    """Resumen JSON-serializable para la Caja Negra: qué se hizo, con qué mecanismo y antes/después."""
    return {"remedy": remedy.key, "action": remedy.label, "mechanism": remedy.mechanism,
            "targets": remedy.targets(), "reboot": remedy.reboot, "ok": bool(result.get("ok")),
            "error": result.get("error", ""), "rolled_back": result.get("rolled_back", False),
            "steps": _jsonable(result.get("records", []))}


# =================================================================================================
# Catálogo: hallazgo -> remedio
# =================================================================================================
DEFENSE_RUN = ("Las claves Run/RunOnce lanzan programas en cada inicio de sesión: es la técnica de persistencia "
               "más usada por el malware (MITRE T1547.001).")
DEFENSE_HVCI = ("La integridad de memoria (HVCI) usa el hipervisor para que en el núcleo solo se ejecute código "
                "firmado y verificado: bloquea rootkits y controladores vulnerables o sin firma (BYOVD).")
DEFENSE_FIREWALL = ("El Firewall de Windows descarta las conexiones entrantes no solicitadas. Sin él, cualquier "
                    "servicio en escucha queda expuesto a gusanos, fuerza bruta y movimiento lateral.")


def needs_elevation(finding) -> bool:
    """SKIP por falta de privilegios: la acción es relanzar Lozarus como Administrador."""
    return finding.severity is SKIP and (ADMIN_NAME in finding.detail or "denegado" in finding.detail.lower())


def _reg(key, label, icon, protects, impact, steps, **kw) -> Remedy:
    return Remedy(key, label, icon, protects, impact, list(steps), **kw)


def _uac(title: str) -> Optional[Remedy]:
    if "desactivado" in title:
        return _reg("uac:lua", "Activar UAC", "fa5s.user-shield",
                    "UAC separa los privilegios del administrador: sin él, todo programa que ejecutes, incluido "
                    "el malware, corre con control total del sistema.",
                    "Requiere reiniciar. Volverá a aparecer el aviso de elevación al instalar o cambiar la "
                    "configuración del sistema.", [RegSet("HKLM", UAC_KEY, "EnableLUA", 1)], reboot=True)
    if "sin preguntar" in title:
        return _reg("uac:consent", "Exigir consentimiento de UAC", "fa5s.user-shield",
                    "Con ConsentPromptBehaviorAdmin = 0 un proceso se eleva a administrador sin preguntar: el "
                    "malware obtiene privilegios en silencio.",
                    "Windows pedirá consentimiento en el escritorio seguro antes de cada elevación (nivel "
                    "predeterminado).", [RegSet("HKLM", UAC_KEY, "ConsentPromptBehaviorAdmin", 5)])
    if "escritorio seguro" in title:
        return _reg("uac:secure", "Activar escritorio seguro de UAC", "fa5s.user-shield",
                    "El escritorio seguro aísla el aviso de UAC: ningún otro proceso puede leerlo, falsificarlo "
                    "ni pulsar «Sí» por ti.", "El aviso de elevación atenuará la pantalla (comportamiento "
                    "predeterminado de Windows).", [RegSet("HKLM", UAC_KEY, "PromptOnSecureDesktop", 1)])
    return None


def _hvci(be) -> Remedy:
    steps: List[Any] = [RegSet("HKLM", DEVICEGUARD_KEY, "EnableVirtualizationBasedSecurity", 1)]
    if not probe(be, "HKLM", DEVICEGUARD_KEY, "RequirePlatformSecurityFeatures")[0]:
        # Solo si no existe: un 3 (Secure Boot + protección DMA) nunca se rebaja a 1.
        steps.append(RegSet("HKLM", DEVICEGUARD_KEY, "RequirePlatformSecurityFeatures", 1))
    steps.append(RegSet("HKLM", HVCI_KEY, "Enabled", 1))
    return _reg("hvci", "Activar integridad de memoria (HVCI)", "fa5s.microchip", DEFENSE_HVCI,
                "Requiere reiniciar. Los controladores incompatibles dejarán de cargarse: revísalos antes en "
                "Seguridad de Windows. Solo se aplica de forma individual.", steps, reboot=True, batch=False)


def _smbv1(title: str) -> Remedy:
    steps: List[Any] = []
    if "servidor" in title:
        steps.append(ArsenalTweak("smb1"))
    if "cliente" in title:
        steps.append(PowerShell("Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart "
                                "-ErrorAction Stop | Out-Null",
                                "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart "
                                "-ErrorAction Stop | Out-Null", mechanism="DISM", timeout=900))
    if not steps:
        steps.append(ArsenalTweak("smb1"))
    return _reg("smb1", "Desactivar SMBv1", "fa5s.server",
                "SMBv1 no cifra ni firma y arrastra los fallos que explotaron WannaCry y NotPetya (EternalBlue).",
                "Efectivo tras reiniciar. NAS y equipos muy antiguos que solo hablan SMBv1 dejarán de ser "
                "accesibles.", steps, reboot=True)


def _rdp(finding, be) -> Remedy:
    if finding.severity is CRITICAL:  # habilitado SIN NLA
        steps = [RegSet("HKLM", RDP_TCP_KEY, "UserAuthentication", 1)]
        if probe(be, "HKLM", TS_POLICY_KEY, "UserAuthentication")[0]:
            steps.append(RegSet("HKLM", TS_POLICY_KEY, "UserAuthentication", 1))
        return _reg("rdp:nla", "Exigir NLA en Escritorio remoto", "fa5s.desktop",
                    "Con NLA el usuario se autentica ANTES de crear la sesión: sin ella, la pantalla de inicio "
                    "queda expuesta a fuerza bruta y a fallos previos a la autenticación (BlueKeep).",
                    "Los clientes de Escritorio remoto sin soporte de NLA (muy antiguos) no podrán conectar.",
                    steps)
    steps = [RegSet("HKLM", TS_KEY, "fDenyTSConnections", 1)]
    if probe(be, "HKLM", TS_POLICY_KEY, "fDenyTSConnections")[0]:
        steps.append(RegSet("HKLM", TS_POLICY_KEY, "fDenyTSConnections", 1))
    return _reg("rdp:off", "Desactivar Escritorio remoto", "fa5s.desktop",
                "Un Escritorio remoto abierto es el primer objetivo de la fuerza bruta y del ransomware operado "
                "por humanos.", "Las sesiones de Escritorio remoto activas se cortarán: si administras este "
                "equipo en remoto, no lo apliques. Solo se aplica de forma individual.", steps, batch=False)


def _firewall(finding) -> Optional[Remedy]:
    profile = finding.key.partition(":")[2]
    label, netsh_profile = FIREWALL_PROFILES.get(profile, (profile, ""))
    if not netsh_profile:
        return None
    title = finding.title.lower()
    if "desactivado" in title and "terceros" not in finding.detail.lower():
        return _reg(f"firewall:on:{profile}", f"Activar firewall · perfil {label}", "fa5s.shield-alt",
                    DEFENSE_FIREWALL, f"El perfil {label} volverá a filtrar las conexiones entrantes no solicitadas; "
                    "las reglas de permitir existentes se mantienen.",
                    [Command(("netsh", "advfirewall", "set", netsh_profile, "state", "on"))])
    if "permite todo" in title:
        return _reg(f"firewall:block:{profile}", f"Bloquear entrada por defecto · {label}", "fa5s.shield-alt",
                    "Con la acción de entrada «Permitir» el firewall está encendido pero no filtra: todo servicio "
                    "en escucha queda accesible desde la red.", "Solo se aceptarán las conexiones entrantes con "
                    "una regla explícita (comportamiento predeterminado de Windows). La salida no cambia.",
                    [PowerShell(f"Set-NetFirewallProfile -Profile {profile} -DefaultInboundAction Block "
                                "-ErrorAction Stop", mechanism="NETSH")])
    return None


def _accounts(finding) -> Optional[Remedy]:
    title = finding.title
    if "invitado" in title.lower():
        match = re.search(r"\(([^()]+)\)\s*$", title)
        if not match:
            return None
        name = match.group(1)
        return _reg(f"cuenta:guest:{name}", "Deshabilitar cuenta Invitado", "fa5s.user-slash",
                    "La cuenta Invitado permite iniciar sesión sin credenciales personales y es un punto de "
                    "entrada conocido.", "Nadie podrá iniciar sesión como Invitado. Reversible con «Deshacer».",
                    [Command(("net", "user", name, "/active:no"), ("net", "user", name, "/active:yes"),
                             mechanism="CUENTA")])
    return None


def _security_policy(title: str) -> Optional[Remedy]:
    if "cifrado reversible" in title:
        return _reg("secpol:cleartext", "Desactivar cifrado reversible", "fa5s.key",
                    "El cifrado reversible equivale a guardar las contraseñas en claro: quien acceda a la base SAM "
                    "las recupera.", "Las contraseñas se guardarán con hash a partir del próximo cambio de cada "
                    "usuario.", [SecPolicy("ClearTextPassword", 0)])
    if "complejidad" in title:
        return _reg("secpol:complexity", "Exigir complejidad de contraseña", "fa5s.key",
                    "Sin requisitos de complejidad se aceptan contraseñas triviales, las primeras que prueba un "
                    "ataque de diccionario.", "Solo afecta a los próximos cambios de contraseña.",
                    [SecPolicy("PasswordComplexity", 1)])
    if "anónima" in title:
        return _reg("secpol:anon", "Bloquear traducción anónima SID/nombre", "fa5s.user-lock",
                    "La traducción anónima SID/nombre permite enumerar las cuentas del equipo sin autenticarse.",
                    "Ningún efecto para los usuarios autenticados.", [SecPolicy("LSAAnonymousNameLookup", 0)])
    return None


def _password_policy(title: str) -> Optional[Remedy]:
    if "longitud mínima" in title:
        return _reg("secpol:minlen", "Exigir 14 caracteres mínimos", "fa5s.key",
                    "Las contraseñas cortas (o vacías) caen en segundos por fuerza bruta.",
                    "Las próximas contraseñas deberán tener al menos 14 caracteres; las actuales siguen valiendo "
                    "hasta que se cambien.", [AccountPolicy("minpwlen", 14, "MinimumPasswordLength")])
    if "bloqueo" in title:
        return _reg("secpol:lockout", "Bloquear tras 10 intentos fallidos", "fa5s.user-lock",
                    "Sin umbral de bloqueo se pueden probar contraseñas sin límite contra las cuentas locales.",
                    "Una cuenta se bloqueará tras 10 intentos fallidos (duración según la directiva actual).",
                    [AccountPolicy("lockoutthreshold", 10, "LockoutBadCount")])
    return None


def _run_entry(finding) -> Optional[Remedy]:
    origin, _, name = finding.key[len("persist:run:"):].partition(":")
    hive, subkey = next(((h, k) for label, h, k in RUN_KEYS if label == origin), (None, None))
    if hive is None or not name:
        return None
    return _reg(finding.key, "Eliminar entrada de arranque", "fa5s.trash-alt", DEFENSE_RUN,
                "El programa dejará de arrancar con la sesión; el ejecutable NO se borra. El valor original se "
                "guarda antes y se puede restaurar con «Deshacer».", [RegDelete(hive, subkey, name)])


def _task(finding) -> Optional[Remedy]:
    name = finding.key[len("persist:task:"):]
    if not name:
        return None
    return _reg(finding.key, "Deshabilitar tarea programada", "fa5s.calendar-times",
                "Las tareas que lanzan binarios sin firma desde carpetas de usuario son una vía de persistencia "
                "habitual del malware (MITRE T1053.005).", "La tarea queda deshabilitada, no se borra: "
                "reactivable con «Deshacer» o desde el Programador de tareas.",
                [Command(("schtasks", "/Change", "/TN", name, "/Disable"), ("schtasks", "/Change", "/TN", name,
                                                                            "/Enable"), mechanism="TAREA")])


WU_SERVICE = _reg("wuauserv", "Reactivar Windows Update", "fa5s.sync-alt",
                  "Sin Windows Update el equipo deja de recibir parches de seguridad y acumula vulnerabilidades "
                  "públicas.", "El servicio vuelve a inicio Manual (predeterminado): Windows lo arranca cuando "
                  "busca actualizaciones.", [Command(("sc", "config", "wuauserv", "start=", "demand"),
                                                     ("sc", "config", "wuauserv", "start=", "disabled"),
                                                     mechanism="SERVICIO")])
DEFENDER_RTP = _reg("defender:rtp", "Reactivar protección en tiempo real", "fa5s.shield-virus",
                    "La protección en tiempo real analiza cada archivo al abrirlo o descargarlo; apagarla es lo "
                    "primero que hace el malware.", "Reactiva Microsoft Defender en tiempo real. Si una directiva o "
                    "Tamper Protection lo impiden, se informará del fallo.",
                    [PowerShell("Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop")])


def remedy_for(finding, be=None) -> Optional[Remedy]:
    """Remedio real para un hallazgo WARNING/CRITICAL, o None si solo cabe seguir la recomendación."""
    if finding.severity not in (CRITICAL, WARNING):
        return None
    be = be or BACKEND
    check, key, title = finding.check, finding.key, finding.title.lower()
    if check == "check_uac":
        return _uac(title)
    if check == "check_powershell_logging":
        return _reg("pslog", "Activar registro de PowerShell", "fa5s.terminal",
                    "El registro de bloques de script (evento 4104) guarda el código PowerShell que se ejecuta, "
                    "aunque llegue ofuscado o solo exista en memoria: evidencia clave frente al malware sin "
                    "fichero.", "Cada bloque de script queda en Microsoft-Windows-PowerShell/Operational. Coste de "
                    "disco mínimo.", [RegSet("HKLM", PS_KEY, "EnableScriptBlockLogging", 1)])
    if key in ("hardening:hvci", "persist:drivers:unsigned"):
        return _hvci(be)
    if check == "check_smbv1":
        return _smbv1(title)
    if check == "check_smb_signing":
        return _reg("smb:signing", "Exigir firma SMB", "fa5s.file-signature",
                    "La firma SMB obligatoria impide retransmitir contra este equipo autenticaciones NTLM "
                    "capturadas en la red (NTLM relay).", "Clientes SMB muy antiguos sin firma no podrán conectar a "
                    "las carpetas compartidas. Efectivo al reiniciar el servicio Servidor.",
                    [RegSet("HKLM", LANMAN_KEY, "RequireSecuritySignature", 1)], reboot=True)
    if check == "check_rdp":
        return _rdp(finding, be)
    if check == "check_llmnr":
        return _reg("llmnr", "Desactivar LLMNR", "fa5s.broadcast-tower",
                    "LLMNR permite que cualquier equipo de la LAN responda por nombres inexistentes y capture "
                    "hashes NTLM (Responder).", "Los nombres se resolverán solo por DNS; sin efecto en redes con "
                    "DNS bien configurado.", [ArsenalTweak("llmnr")])
    if check == "check_wdigest":
        return _reg("wdigest", "Desactivar WDigest en claro", "fa5s.key",
                    "Con UseLogonCredential = 1 la contraseña de cada sesión queda en claro en la memoria de "
                    "LSASS, al alcance de Mimikatz.", "Ninguno en sistemas modernos; las sesiones abiertas conservan "
                    "la credencial hasta cerrar sesión.", [RegSet("HKLM", WDIGEST_KEY, "UseLogonCredential", 0)])
    if check == "check_lsa_protection":
        modern = be.windows_build() >= LSA_PPL_NO_UEFI_BUILD
        note = ("" if modern else " En Windows 10 con UEFI el valor queda fijado en el firmware: revertirlo exige "
                                  "la herramienta de exclusión de Microsoft.")
        return _reg("lsa:ppl", "Proteger LSASS (RunAsPPL)", "fa5s.lock",
                    "LSASS como proceso protegido (PPL) impide que las herramientas de volcado de credenciales "
                    "lean su memoria.", "Requiere reiniciar. Los complementos de LSA sin firma (lectores de "
                    "tarjetas o software de seguridad antiguo) dejarán de cargarse." + note,
                    [RegSet("HKLM", LSA_KEY, "RunAsPPL", 2 if modern else 1, undoable=modern)], reboot=True)
    if check == "check_ntlm":
        return _reg("ntlm", "Enviar solo NTLMv2", "fa5s.key",
                    "LM y NTLMv1 se rompen en minutos: con una respuesta capturada en la red se obtiene la "
                    "contraseña.", "Equipos y NAS muy antiguos que solo admiten NTLMv1 no podrán autenticarse.",
                    [RegSet("HKLM", LSA_KEY, "LmCompatibilityLevel", 5)])
    if check == "check_autorun":
        steps = ([RegSet("HKLM", AUTORUN_KEY, "NoDriveTypeAutoRun", 255)]
                 if probe(be, "HKLM", AUTORUN_KEY, "NoDriveTypeAutoRun")[0] else [ArsenalTweak("autorun")])
        return _reg("autorun", "Bloquear AutoRun en todas las unidades", "fa5s.compact-disc",
                    "AutoRun ejecuta el contenido de discos y USB al conectarlos: la vía clásica de propagación de "
                    "gusanos por memorias extraíbles.", "Al conectar un USB no se ejecutará nada automáticamente; "
                    "ábrelo tú desde el Explorador.", steps)
    if (check == "check_updates" and "deshabilitado" in title) or key == "telemetria:wuauserv":
        return WU_SERVICE
    if check == "check_updates" and "directiva" in title:
        return _reg("wu:policy", "Reactivar actualizaciones automáticas", "fa5s.sync-alt",
                    "La directiva NoAutoUpdate impide que Windows descargue e instale parches por sí mismo.",
                    "Windows volverá a buscar e instalar actualizaciones automáticamente.",
                    [RegSet("HKLM", WU_POLICY_KEY, "NoAutoUpdate", 0)])
    if key == "telemetria:rtp" or (check == "check_defender" and "no hay protección" in title):
        return DEFENDER_RTP
    if check == "check_defender" and "firmas" in title:
        return _reg("defender:signatures", "Actualizar firmas de Defender", "fa5s.shield-virus",
                    "Unas firmas de más de una semana no detectan las familias de malware recientes.",
                    "Descarga las últimas definiciones de Microsoft Defender (necesita internet).",
                    [PowerShell("Update-MpSignature -ErrorAction Stop", timeout=600)])
    if check == "check_windows_firewall" and key.startswith("firewall:"):
        return _firewall(finding)
    if check == "check_local_accounts":
        return _accounts(finding)
    if check == "check_security_policy":
        return _security_policy(title)
    if check == "check_password_policy":
        return _password_policy(title)
    if key.startswith("persist:run:"):
        return _run_entry(finding)
    if key.startswith("persist:task:"):
        return _task(finding)
    return None


def port_block_remedy(proto: str, port: int) -> Remedy:
    """Regla de entrada REAL en el Firewall de Windows para un puerto (deshacer = borrar la regla)."""
    rule = f"Lozarus - Bloqueo {proto} {port}"
    return _reg(f"port:{proto}:{port}", "Bloquear puerto en el firewall", "fa5s.ban",
                "Un puerto expuesto es una puerta abierta: cualquier equipo de la red puede conectarse, probar "
                "contraseñas o explotar una vulnerabilidad del proceso que lo atiende.",
                f"Se rechazarán las conexiones entrantes a {proto} {port}; el servicio sigue funcionando para este "
                "equipo. «Deshacer» elimina la regla.",
                [Command(("netsh", "advfirewall", "firewall", "add", "rule", f"name={rule}", "dir=in",
                          "action=block", f"protocol={proto}", f"localport={port}"),
                         ("netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"))])


__all__ = ["Remedy", "StepError", "RegSet", "RegDelete", "Command", "PowerShell", "SecPolicy", "AccountPolicy",
           "ArsenalTweak", "MECHANISMS", "remedy_for", "port_block_remedy", "needs_elevation", "apply_remedy",
           "undo_remedy", "undo_preview", "event_payload", "parse_inf", "build_inf", "WindowsBackend", "BACKEND"]
