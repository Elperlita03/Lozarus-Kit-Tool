# -*- coding: utf-8 -*-
"""
Catálogo de capacidades de Lozarus: los 41 módulos de la arquitectura + la infraestructura que SÍ
está implementada y probada.

**Procedencia de los estados.** No son estimaciones: salen de leer el repositorio el 2026-10-20 y de
`docs/00_AUDITORIA_ARQUITECTURA.md` §2. Reglas que se han aplicado:

  · `impl_tested`  → hay código Y pruebas automáticas que pasan.
  · `impl_partial` → hay código real funcionando, con alcance incompleto y SIN pruebas automáticas.
  · `proto_tested` → validado en `spikes/` con pruebas; no es producción.
  · `designed`     → hay diseño/contrato documentado, no hay código.
  · `needs_valid`  → no se sabe si es viable; requiere prototipo que lo decida.
  · `redesign`     → la idea original se descartó o se acotó (docs/00 §3).

**Resultado honesto:** ninguno de los 41 módulos está `impl_tested`. Lo único con pruebas es la
infraestructura (`core/`, `collectors/`). No se inventan porcentajes de avance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

AREAS: Tuple[str, ...] = (
    "Núcleo y telemetría",
    "Forense y evidencia",
    "Endurecimiento",
    "Defensa y contención",
    "Engaño defensivo",
    "Memoria y bajo nivel",
    "Perímetro y hardware",
    "Recuperación",
    "Plataforma",
)

AREA_ICONS: Dict[str, str] = {
    "Núcleo y telemetría": "fa5s.wave-square",
    "Forense y evidencia": "fa5s.fingerprint",
    "Endurecimiento": "fa5s.shield-alt",
    "Defensa y contención": "fa5s.hand-paper",
    "Engaño defensivo": "fa5s.eye",
    "Memoria y bajo nivel": "fa5s.microchip",
    "Perímetro y hardware": "fa5s.network-wired",
    "Recuperación": "fa5s.life-ring",
    "Plataforma": "fa5s.cubes",
}


@dataclass(frozen=True)
class Capability:
    num: int                       # 0 = infraestructura (no forma parte de los 41)
    name: str
    area: str
    status: str                    # clave de theme.STATUS
    objective: str                 # para qué sirve, en una línea
    description: str               # explicación comprensible para no expertos
    deps: Tuple[str, ...] = ()
    tests: str = "No hay pruebas automáticas."
    limits: str = ""
    next_step: str = ""
    backing: str = ""              # archivo real que lo respalda, si existe
    priority: int = 3              # prioridad de docs/00 §2 (1 = base de confianza)
    privileges: str = "usuario"

    @property
    def label(self) -> str:
        return self.name if self.num == 0 else f"{self.num:02d} · {self.name}"


# =============================================================================================
# Infraestructura realmente implementada (NO forma parte de los 41 módulos)
# =============================================================================================
CORE: List[Capability] = [
    Capability(
        0, "core/events.py — Modelo de evento", "Núcleo y telemetría", "impl_tested",
        "Define qué es un evento para todo el sistema.",
        "El idioma común de Lozarus. Cualquier sensor, venga de donde venga, traduce lo que observa "
        "a este formato (`lozarus.event.v1`), para que el resto del producto no dependa de la fuente. "
        "Guarda la hora original, qué reloj la produjo y si se puede convertir a UTC con fiabilidad.",
        deps=("solo biblioteca estándar",), tests="12 pruebas automáticas, pasan sin privilegios.",
        limits="No convierte marcas de reloj ambiguas: las marca como desconocidas en lugar de adivinar.",
        next_step="Sin cambios previstos; es la base estable.",
        backing="core/events.py", priority=1),
    Capability(
        0, "core/contracts.py — Contratos y salud", "Núcleo y telemetría", "impl_tested",
        "Define cómo se comporta un sensor y cómo informa de su salud.",
        "Fija qué tiene que cumplir cualquier colector y cómo declara si está vivo, cuántos eventos ha "
        "visto y cuántos ha perdido. Distingue tres cosas que suelen confundirse: pérdida desconocida, "
        "cero confirmado y pérdida detectada.",
        deps=("core/events.py",), tests="9 pruebas automáticas (4 de pérdidas + 5 de contrato).",
        limits="Es un contrato: no observa nada por sí mismo.",
        next_step="Lo consumirá OBSIDIAN para calcular cobertura.",
        backing="core/contracts.py", priority=1),
    Capability(
        0, "core/bus.py — Bus de eventos", "Núcleo y telemetría", "impl_tested",
        "Transporta eventos de los sensores a quien los consume, sin acoplarlos.",
        "Una cola con tamaño máximo que separa a quien produce eventos de quien los procesa. Si el "
        "consumidor no da abasto, descarta de forma controlada y lo CUENTA, en vez de bloquear el "
        "sensor o mentir. Garantiza orden de llegada y entrega como mucho una vez.",
        deps=("core/events.py",), tests="8 pruebas automáticas, incluidas las de saturación.",
        limits="Entrega «como mucho una vez»: ante saturación se descarta, no se reintenta.",
        next_step="Conectarlo con la Caja Negra y OBSIDIAN (Fase 3B).",
        backing="core/bus.py", priority=1),
    Capability(
        0, "collectors/etw_collector.py — Colector ETW", "Núcleo y telemetría", "impl_tested",
        "Recibe eventos del propio Windows (ETW) y los normaliza.",
        "El primer sensor de producción. Abre su PROPIA sesión de trazas de Windows con un nombre "
        "único, recibe eventos del proveedor de procesos y los traduce al modelo común. Nunca toca "
        "sesiones de Windows ni de otras aplicaciones.",
        deps=("core/", "pywintrace (solo en ejecución real)"),
        tests="13 pruebas automáticas que corren SIN Administrador (sesión falsa inyectada).",
        limits="NO está integrado en ninguna interfaz. En ejecución real exige Administrador o "
               "«Performance Log Users». La pérdida de ETW solo se conoce al parar la sesión.",
        next_step="Conectarlo al bus en vivo desde una interfaz, de forma explícita y separada.",
        backing="collectors/etw_collector.py", priority=1, privileges="Administrador"),
    Capability(
        0, "spikes/etw — Prototipo ETW", "Núcleo y telemetría", "proto_tested",
        "Prototipo que demostró que consumir ETW desde Python era viable.",
        "El experimento aislado previo al colector de producción. Sirvió para comprobar que se podían "
        "recibir eventos reales de Windows sin escribir un driver. Se conserva como referencia "
        "reproducible y no se toca.",
        deps=("pywintrace==0.2.0",), tests="8 pruebas de normalización + 1 de integración real.",
        limits="No es producción. Su captura real fue una ráfaga corta, no una prueba de capacidad.",
        next_step="Congelado: se mantiene como referencia.",
        backing="spikes/etw/", priority=1, privileges="Administrador"),
    Capability(
        0, "Lozarus Rescue (WinPE)", "Recuperación", "needs_valid",
        "Entorno arrancable para analizar y reparar un Windows apagado.",
        "Un USB que arranca su propio mini-Windows para examinar el disco del equipo averiado sin "
        "ejecutar su sistema. Diseñado por completo, pero la pieza clave sigue sin verificar: nadie ha "
        "comprobado que PySide6 funcione dentro de WinPE.",
        deps=("Windows ADK + WinPE add-on", "WinPE-WMI", "WinPE-SecureStartup"),
        tests="Ninguna todavía: no se ha construido el medio.",
        limits="Un Windows apagado no tiene RAM ni procesos: solo se analizan ficheros. Sin la clave "
               "de BitLocker, los datos son irrecuperables por diseño.",
        next_step="Fase P0: construir el USB mínimo y resolver la decisión D1 (¿Qt en WinPE?).",
        backing="docs/05_PRODUCTO_SENTINEL_RESCUE.md", priority=2, privileges="SYSTEM (en WinPE)"),
]


# =============================================================================================
# Los 41 módulos de la arquitectura
# =============================================================================================
def _m(num, name, area, status, objective, description, **kw) -> Capability:
    return Capability(num, name, area, status, objective, description, **kw)


MODULES: List[Capability] = [
    _m(1, "Medidores CPU/RAM", "Plataforma", "impl_partial",
       "Mostrar el consumo real del equipo.",
       "Los indicadores circulares de procesador y memoria que ves en el panel. Leen datos reales del "
       "equipo mediante psutil y se refrescan solos.",
       deps=("psutil", "PySide6"), backing="gui_qt.py (Gauge)",
       tests="Sin pruebas automáticas: es código de interfaz.",
       limits="Mide el equipo donde corre Lozarus, no un sistema remoto ni uno apagado.",
       next_step="Reutilizarlo en el Cuartel general definitivo.", priority=1),
    _m(2, "Bento Cards", "Plataforma", "impl_partial",
       "Organizar la información en tarjetas legibles.",
       "El sistema de tarjetas que agrupa cada bloque de información. Es la base visual sobre la que "
       "se monta el resto de paneles.",
       deps=("PySide6",), backing="gui_qt.py (BentoCard)",
       tests="Sin pruebas automáticas: es código de interfaz.",
       limits="Hoy vive dentro de la GUI de producción; esta beta reimplementa su propia versión.",
       next_step="Unificar un único sistema de tarjetas al aprobar el diseño.", priority=1),
    _m(3, "Protocolo Cero — captura de evidencia", "Forense y evidencia", "impl_partial",
       "Congelar una foto del estado del equipo antes de tocar nada.",
       "Antes de responder a un incidente conviene guardar cómo estaba todo: procesos, conexiones y "
       "ficheros sospechosos, con su huella digital (hash) para demostrar que no se han alterado.",
       deps=("psutil",), backing="modulos/_forense.py (system_snapshot, forensic_report)",
       tests="Sin pruebas automáticas.",
       limits="Captura lo observable desde el modo usuario; no incluye memoria ni procesos protegidos.",
       next_step="Formalizar manifiesto y cadena de custodia en un paquete `evidence/` compartido.",
       priority=1),
    _m(4, "Motor de Persistencia — configuración cifrada", "Plataforma", "designed",
       "Guardar la configuración de Lozarus protegida.",
       "Almacenar ajustes y secretos cifrados con DPAPI, de forma que queden atados a este usuario y "
       "este equipo.",
       deps=("pywin32 (CryptProtectData)",),
       limits="DPAPI protege frente a otros usuarios, NO frente al propio usuario que lo cifró.",
       next_step="Implementar junto con el paquete `storage/`.", priority=1),
    _m(5, "Guillotina de Contexto — perfiles", "Endurecimiento", "designed",
       "Cambiar de golpe entre perfiles de seguridad.",
       "Conmutar un conjunto de ajustes (por ejemplo «viaje» o «casa») guardando siempre el estado "
       "anterior para poder volver atrás.",
       deps=("servicio privilegiado",), privileges="Administrador",
       limits="No debe tocar servicios críticos: un perfil mal diseñado puede dejar el equipo inservible.",
       next_step="Definir la lista blanca de ajustes reversibles.", priority=3),
    _m(6, "Caja Negra — búfer de telemetría", "Núcleo y telemetría", "designed",
       "Guardar los últimos eventos para poder mirar atrás tras un incidente.",
       "Como la caja negra de un avión: mantiene una ventana reciente de todo lo observado, de modo "
       "que cuando salta una alerta se pueda reconstruir qué pasó justo antes.",
       deps=("core/bus.py",),
       limits="La ventana está limitada por memoria y disco: los huecos deben marcarse, no ocultarse.",
       next_step="Fase 3B: suscribirla al bus y persistir en disco (append-only).", priority=2),
    _m(7, "Eclipse Engine — motor de respuesta", "Defensa y contención", "designed",
       "Orquestar las respuestas a un incidente.",
       "El cerebro que decide qué hacer ante una detección y en qué orden, siempre pudiendo simular "
       "antes de actuar y revertir después.",
       deps=("servicio privilegiado", "core/"), privileges="Administrador (vía servicio)",
       limits="Las acciones peligrosas deben delegarse y poder simularse; nunca automáticas por defecto.",
       next_step="Definir el contrato plan/validate/apply/verify/rollback.", priority=4),
    _m(8, "Matriz de desinfección y endurecimiento", "Endurecimiento", "impl_partial",
       "Revisar y corregir la configuración de seguridad de Windows.",
       "Comprueba 16 puntos de configuración (UAC, Defender, actualizaciones, BitLocker, Arranque "
       "seguro, SMBv1, RDP, LSASS...) y propone correcciones reversibles.",
       deps=("PowerShell", "Registro de Windows"), backing="modulos/05_hardening.py + _tacticas.py",
       tests="Sin pruebas automáticas.", privileges="usuario/Administrador",
       limits="Algunas comprobaciones requieren Administrador; sin él se marcan como omitidas, no como correctas.",
       next_step="Añadir restauración de un clic con estado previo guardado.", priority=2),
    _m(9, "Debloat Trampa — señuelos de servicios", "Endurecimiento", "redesign",
       "Reducir software innecesario de Windows.",
       "La idea original (sustituir servicios reales por falsos) se descartó: rompe dependencias y es "
       "indistinguible de malware. Se sustituye por desactivación reversible guardando el estado previo.",
       deps=("servicio privilegiado",), privileges="Administrador",
       limits="Descartado en su forma original (docs/00 §3.1).",
       next_step="Implementar solo la variante reversible + vigilar qué reactiva lo desactivado.",
       priority=4),
    _m(10, "Reparación del sistema", "Recuperación", "impl_partial",
       "Reparar Windows cuando algo se ha corrompido.",
       "Envoltorio de las herramientas oficiales de reparación de Windows. Hoy solo existe el "
       "restablecimiento completo (Protocolo Omega), que es la opción más drástica.",
       deps=("sfc", "DISM", "systemreset"), backing="modulos/_tacticas.py (factory_reset)",
       tests="Sin pruebas automáticas.", privileges="Administrador",
       limits="El restablecimiento es IRREVERSIBLE. Faltan las reparaciones intermedias (sfc, DISM).",
       next_step="Añadir sfc/DISM/BCD antes de ofrecer nunca el restablecimiento.", priority=3),
    _m(11, "Congelador de Persistencia", "Forense y evidencia", "impl_partial",
       "Detectar qué programas se ejecutan solos al arrancar.",
       "Revisa las cuatro vías clásicas por las que algo se asegura de arrancar con Windows: claves "
       "Run, Winlogon, tareas programadas y controladores.",
       deps=("Registro de Windows", "schtasks"), backing="modulos/11_persistencia.py",
       tests="Sin pruebas automáticas.",
       limits="Es una foto, no una línea base: todavía no compara con un estado anterior.",
       next_step="Guardar línea base y mostrar diferencias entre capturas.", priority=2),
    _m(12, "Blindaje de Sombras (VSS)", "Forense y evidencia", "designed",
       "Vigilar los puntos de restauración de Windows.",
       "El ransomware borra las instantáneas del sistema antes de cifrar. Esto detecta ese borrado.",
       deps=("ETW", "Registro de eventos"), privileges="Administrador",
       limits="Se puede DETECTAR el borrado, no IMPEDIRLO frente a un administrador.",
       next_step="Regla de detección sobre el colector ETW.", priority=3),
    _m(13, "Cortafuegos de Intención Humana", "Perímetro y hardware", "needs_valid",
       "Distinguir el tráfico que el usuario provocó del que no.",
       "Intenta correlacionar si una conexión de salida coincide con actividad real del usuario. Si "
       "algo se conecta mientras nadie toca el equipo, es sospechoso.",
       deps=("telemetría de red", "señales de sesión"),
       limits="Muchísimos falsos positivos. Solo debería avisar, jamás bloquear automáticamente.",
       next_step="Medir la tasa de falsos positivos antes de plantearse implementarlo.", priority=4),
    _m(14, "Honeypots de credenciales sintéticas", "Engaño defensivo", "needs_valid",
       "Poner credenciales falsas como cebo.",
       "Credenciales que no sirven para nada real: si alguien las usa, es que ha estado husmeando.",
       deps=("telemetría de autenticación",), privileges="Administrador",
       limits="En un equipo suelto, detectar su USO es muy limitado. **Nunca credenciales reales.**",
       next_step="Acotar a escenarios donde el uso sea observable.", priority=4),
    _m(15, "Archivos señuelo (canary files)", "Engaño defensivo", "impl_partial",
       "Colocar archivos cebo que avisan si alguien los toca.",
       "Ficheros de aspecto jugoso pero sin valor real. Si algo los abre o los cifra, salta el aviso: "
       "es una de las formas más fiables y menos invasivas de detectar ransomware.",
       deps=("auditoría SACL",), backing="modulos/_defensa_local.py (deploy_canaries, scan_canaries)",
       tests="Sin pruebas automáticas.", privileges="usuario/Administrador",
       limits="Solo detecta y avisa; no bloquea nada.",
       next_step="Conectar la detección al bus de eventos.", priority=2),
    _m(16, "Detección de exfiltración", "Perímetro y hardware", "needs_valid",
       "Notar cuándo se están sacando datos del equipo.",
       "Vigila volúmenes de subida anómalos hacia destinos poco habituales.",
       deps=("telemetría de red",), privileges="Administrador",
       limits="Heurístico. El cifrado de las conexiones impide ver el contenido.",
       next_step="Definir la línea base de tráfico normal.", priority=4),
    _m(17, "Shell señuelo", "Engaño defensivo", "redesign",
       "Entretener a un intruso con una consola falsa.",
       "Técnica de engaño activo. Se descartó en el equipo real: añade superficie de ataque y aporta "
       "poco valor defensivo. Solo tendría sentido en un laboratorio aislado.",
       limits="Excluido fuera de un laboratorio autorizado (docs/00 §3.2).",
       next_step="Mantener solo dentro del Mirror Lab, si llega a hacerse.", priority=5),
    _m(18, "Tarpitting", "Engaño defensivo", "redesign",
       "Ralentizar deliberadamente a un atacante.",
       "Igual que el anterior: engaño activo, solo admisible en entorno controlado y autorizado.",
       privileges="Administrador",
       limits="Puede atrapar tráfico legítimo. Excluido del equipo productivo.",
       next_step="Solo laboratorio.", priority=5),
    _m(19, "Red de Espejismos", "Engaño defensivo", "redesign",
       "Simular una red entera falsa.",
       "Requiere virtualización y es claramente de laboratorio. Descartado para el producto base.",
       deps=("virtualización",), privileges="Administrador",
       limits="Alcance de laboratorio; coste alto, valor defensivo bajo en un host suelto.",
       next_step="Solo laboratorio.", priority=5),
    _m(20, "Protección de cámara y micrófono", "Perímetro y hardware", "designed",
       "Saber qué aplicaciones usan la cámara o el micrófono.",
       "Windows anota qué aplicación ha usado cada periférico sensible. Esto lo lee y permite cortar "
       "el acceso desde los ajustes de privacidad del sistema.",
       deps=("Registro de Windows (Consent Store)",),
       limits="«Proteger» aquí significa conmutar los ajustes del propio Windows, no interceptar nada.",
       next_step="Lectura del historial de uso + accesos directos a los ajustes.", priority=3),
    _m(21, "Phantom Map — disco contra memoria", "Memoria y bajo nivel", "needs_valid",
       "Detectar programas cuyo contenido en memoria no coincide con el del disco.",
       "Cuando algo se inyecta en un proceso legítimo, lo que se ejecuta en memoria deja de parecerse "
       "al fichero original. Esto compara ambos.",
       deps=("APIs de memoria de Windows",), privileges="Administrador",
       limits="FALLA contra procesos protegidos (PPL, Credential Guard). Produce indicios, nunca pruebas. "
              "Debe listar qué procesos NO pudo inspeccionar.",
       next_step="Prototipo que mida cobertura real y falsos positivos.", priority=4),
    _m(22, "Cámara de Asfixia — límites por proceso", "Defensa y contención", "designed",
       "Ahogar un proceso sospechoso sin matarlo.",
       "Limitar cuánta CPU y memoria puede consumir un proceso, para contenerlo mientras se investiga "
       "en lugar de cerrarlo y perder la evidencia.",
       deps=("Job Objects",), privileges="Administrador",
       limits="Asignar un proceso ajeno a un Job Object tiene restricciones técnicas.",
       next_step="Adaptador `windows/jobobjects.py`.", priority=3),
    _m(23, "Detección de process hollowing", "Memoria y bajo nivel", "needs_valid",
       "Detectar procesos vaciados y sustituidos por código malicioso.",
       "Una técnica clásica: arrancar un programa legítimo y reemplazar su contenido antes de que "
       "empiece. Se detecta por indicios, no con certeza.",
       privileges="Administrador",
       limits="Sin el proveedor protegido de Windows no hay prueba, solo heurística.",
       next_step="Medir falsos positivos junto al módulo 21.", priority=4),
    _m(24, "Time-Dilation — limitar CPU", "Defensa y contención", "designed",
       "Frenar un proceso para ganar tiempo.",
       "Reduce la CPU disponible de un proceso sospechoso mientras se decide qué hacer.",
       deps=("Job Objects",), privileges="Administrador",
       limits="Nunca debe aplicarse a procesos críticos del sistema.",
       next_step="Mismo adaptador que el módulo 22.", priority=4),
    _m(25, "Integridad de módulos cargados", "Memoria y bajo nivel", "impl_partial",
       "Detectar bibliotecas extrañas dentro de procesos del sistema.",
       "Revisa procesos que suelen usarse como anfitriones (svchost, explorer, lsass...) buscando "
       "módulos cargados que no deberían estar ahí.",
       deps=("psutil", "APIs de Windows"), backing="modulos/13_inyecciones.py (check_injected_modules)",
       tests="Sin pruebas automáticas.", privileges="usuario/Administrador",
       limits="Muchos procesos del sistema solo son legibles como Administrador; los no accesibles se "
              "cuentan como tales en vez de darse por limpios.",
       next_step="Elevar a regla de detección sobre el bus.", priority=4),
    _m(26, "Telemetría de excepciones y bajo nivel", "Núcleo y telemetría", "needs_valid",
       "Ver fallos y comportamientos anómalos a bajo nivel.",
       "La telemetría más profunda del sistema operativo, la que de verdad delata los ataques finos.",
       deps=("ETW de kernel",), privileges="Administrador",
       limits="Lo verdaderamente profundo exige el proveedor Threat-Intelligence, reservado a "
              "antivirus firmados por Microsoft. **Límite duro del proyecto.**",
       next_step="Documentar qué subconjunto SÍ es accesible sin driver.", priority=4),
    _m(27, "Escudo Anti-BYOVD", "Endurecimiento", "designed",
       "Detectar controladores vulnerables usados como puerta trasera.",
       "Hay controladores legítimos pero con fallos que los atacantes instalan a propósito. Esto "
       "inventaría los controladores cargados y los compara con una lista de conocidos peligrosos.",
       deps=("WMI", "lista de bloqueo versionada"), privileges="Administrador",
       limits="Lozarus puede AUDITAR; IMPEDIR que se carguen es cosa de WDAC/HVCI, no de Python.",
       next_step="Provisionar la lista de bloqueo versionada y arrancar en modo auditoría.", priority=2),
    _m(28, "Protección de LSASS", "Endurecimiento", "impl_partial",
       "Proteger el proceso que guarda las contraseñas de Windows.",
       "Comprueba si LSASS corre como proceso protegido (RunAsPPL), que es lo que impide que "
       "herramientas tipo Mimikatz extraigan credenciales de su memoria.",
       deps=("Registro de Windows",), backing="modulos/05_hardening.py (RunAsPPL, UseLogonCredential)",
       tests="Sin pruebas automáticas.",
       limits="Verifica y recomienda. DETECTAR accesos a LSASS exige el proveedor protegido: no es posible.",
       next_step="Añadir comprobación de Credential Guard (VBS/HVCI).", priority=2),
    _m(29, "Inventario y control de USB/HID", "Perímetro y hardware", "impl_partial",
       "Controlar qué se conecta por USB.",
       "Inventaría los dispositivos conectados y permite cortar el almacenamiento USB, útil cuando se "
       "sospecha de exfiltración por memoria extraíble.",
       deps=("Registro de Windows", "WMI"), backing="modulos/_contencion.py (killswitch USB)",
       tests="Sin pruebas automáticas.", privileges="Administrador",
       limits="Bloquea almacenamiento; no distingue un teclado legítimo de uno malicioso.",
       next_step="Inventario histórico de dispositivos vistos.", priority=2),
    _m(30, "Patrones de interacción (biometría)", "Plataforma", "redesign",
       "Reconocer al usuario por cómo teclea.",
       "**Excluido por defecto.** Perfilar la cadencia de tecleo es biometría conductual: invasivo, "
       "sesgado y fácilmente confundible con un keylogger.",
       limits="Excluido del producto base (docs/00 §3.5).",
       next_step="Si se necesita «actividad de sesión», usar señales no biométricas (bloqueo, inactividad).",
       priority=5),
    _m(31, "Radar Wi-Fi (Evil Twin)", "Perímetro y hardware", "needs_valid",
       "Detectar redes Wi-Fi que suplantan a la tuya.",
       "Busca puntos de acceso que imitan tu red para interceptar el tráfico.",
       deps=("Npcap", "adaptador en modo monitor"), privileges="Administrador",
       limits="El modo monitor es raro en Windows: depende del hardware concreto.",
       next_step="Comprobar primero si el adaptador del equipo lo admite.", priority=5),
    _m(32, "Contención de conexiones", "Defensa y contención", "impl_partial",
       "Cortar la red de forma controlada y reversible.",
       "Aísla el equipo con reglas de cortafuegos, guardando el estado previo para poder levantarlo "
       "después. Es la base de la «Cuarentena Absoluta».",
       deps=("netsh advfirewall",), backing="modulos/_contencion.py (apply/lift_quarantine)",
       tests="Sin pruebas automáticas.", privileges="Administrador",
       limits="Granularidad por regla, no por flujo individual.",
       next_step="Evaluar WFP nativo para control por flujo.", priority=3),
    _m(33, "Hardware Sub-GHz / NFC", "Perímetro y hardware", "needs_valid",
       "Vigilar señales de radio y NFC.",
       "Queda fuera del núcleo de una herramienta de software; dependería de hardware específico.",
       deps=("hardware externo",),
       limits="Fuera del alcance de un EDR de software. Módulo opcional.",
       next_step="Aplazado indefinidamente.", priority=5),
    _m(34, "Mirror Lab — laboratorio desechable", "Forense y evidencia", "impl_partial",
       "Abrir algo sospechoso en una caja aislada.",
       "Lanza un fichero dudoso dentro de Windows Sandbox, un entorno desechable que se destruye al "
       "cerrarse, para ver qué hace sin arriesgar el equipo.",
       deps=("Windows Sandbox",), backing="modulos/_tacticas.py (launch_in_sandbox, sandbox_available)",
       tests="Sin pruebas automáticas.",
       limits="Requiere que Windows Sandbox esté disponible (no está en todas las ediciones).",
       next_step="Capturar y comparar el antes/después de la ejecución.", priority=4),
    _m(35, "Mesa de Autopsias — análisis estático de PE", "Forense y evidencia", "designed",
       "Examinar un ejecutable sin llegar a ejecutarlo.",
       "Abre el fichero como quien lee una radiografía: cabeceras, secciones, qué funciones importa, "
       "si está firmado, su huella digital. Todo sin que el programa llegue a correr.",
       deps=("pefile (ya instalado)",),
       limits="El análisis estático no ve lo que un programa hace solo al ejecutarse.",
       next_step="Es el mejor candidato del paquete compartido: sirve igual en Sentinel y en Rescue.",
       priority=2),
    _m(36, "Identidad seudónima", "Plataforma", "redesign",
       "Gestionar identidades de prueba.",
       "Se divide en dos: gestionar etiquetas de activos de laboratorio es útil; **falsificar "
       "identificadores de hardware queda excluido** por no ser defensivo.",
       limits="La parte de falsificación de HW-ID está excluida (docs/00 §3.6).",
       next_step="Conservar solo el inventario de activos de laboratorio.", priority=4),
    _m(37, "Saneamiento de datos (NIST 800-88)", "Recuperación", "designed",
       "Borrar datos de forma que no se puedan recuperar.",
       "Sobrescritura de ficheros y del espacio libre, además de limpieza del portapapeles.",
       privileges="usuario/Administrador",
       limits="En discos SSD la sobrescritura por software NO garantiza el borrado: hace falta el "
              "comando de sanitización del propio disco. La interfaz debe decirlo.",
       next_step="Detectar el tipo de medio y declarar la garantía real.", priority=3),
    _m(38, "Autodefensa de Lozarus", "Plataforma", "designed",
       "Dificultar que alguien manipule la propia herramienta.",
       "Protecciones del proceso, canal de control restringido y verificación de los propios binarios.",
       deps=("Named Pipes + ACL",), privileges="Administrador",
       limits="**Mejor esfuerzo, nunca garantía.** No se puede resistir a un administrador decidido ni "
              "alcanzar protección PPL sin firma antimalware de Microsoft.",
       next_step="Implementar junto al servicio privilegiado.", priority=2),
    _m(39, "OBSIDIAN — integridad de la telemetría", "Núcleo y telemetría", "designed",
       "Vigilar que la vigilancia funciona.",
       "El módulo que impide que el producto mienta. Mide qué sensores están vivos, cuántos eventos se "
       "han perdido y qué ventanas de tiempo quedaron sin observar. Si hay un hueco, lo dice: nunca "
       "declara «limpio» sobre lo que no pudo ver.",
       deps=("core/contracts.py", "core/bus.py"),
       tests="Sus contratos (SensorHealth, LossState) YA están implementados y probados en core/.",
       limits="Mide la cobertura de los sensores propios, no la del sistema entero.",
       next_step="Fase 3B: implementarlo sobre el bus. **Prioridad máxima del proyecto.**", priority=1),
    _m(40, "IRONCLAD — confianza de arranque", "Endurecimiento", "designed",
       "Comprobar que el equipo arranca con las defensas puestas.",
       "Verifica Arranque seguro, seguridad basada en virtualización y el inventario de controladores "
       "firmados: la cadena de confianza desde el encendido.",
       deps=("WMI (Win32_DeviceGuard)", "registro de Code Integrity"), privileges="Administrador",
       limits="Desde modo usuario es un grafo observacional, no una verificación a prueba de manipulación.",
       next_step="Empezar por la lectura de estado de Secure Boot/VBS/HVCI.", priority=2),
    _m(41, "CHRONOS — cronología forense", "Forense y evidencia", "designed",
       "Reconstruir qué pasó y en qué orden.",
       "Une las huellas que deja NTFS (diario de cambios, tabla maestra de ficheros), Prefetch, "
       "Amcache y los registros de eventos para armar una línea de tiempo del incidente.",
       deps=("DeviceIoControl", "SeBackupPrivilege"), privileges="Administrador",
       limits="Debe detectar lagunas y reinicios del diario. **No atribuir** un cambio a un proceso "
              "solo por cercanía temporal: distinguir observación, inferencia y conclusión.",
       next_step="Arrancar en solo lectura; es el desarrollo forense más valioso.", priority=2),
]


# =============================================================================================
# Resúmenes
# =============================================================================================
def counts_by_status(items: List[Capability]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for cap in items:
        out[cap.status] = out.get(cap.status, 0) + 1
    return out


def by_area(items: List[Capability]) -> Dict[str, List[Capability]]:
    out: Dict[str, List[Capability]] = {a: [] for a in AREAS}
    for cap in items:
        out.setdefault(cap.area, []).append(cap)
    return {k: v for k, v in out.items() if v}


ALL: List[Capability] = CORE + MODULES
