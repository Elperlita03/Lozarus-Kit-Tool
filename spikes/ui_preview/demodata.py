# -*- coding: utf-8 -*-
"""
Datos de DEMOSTRACIÓN de la beta.

**Todo lo que hay en este archivo es inventado para poder enseñar la interfaz.** Ningún dato procede
de una observación real del equipo. Las vistas que lo usan están obligadas a mostrar `DemoBadge`.

Lo único real que enseña la beta son las métricas de CPU/RAM del propio equipo (vía psutil, en
`runtime.py`) y los estados del catálogo (verificados contra el repositorio, en `catalog.py`).
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from theme import C

# ---------------------------------------------------------------------------------------------
# Procesos (simulados)
# ---------------------------------------------------------------------------------------------
# (nombre, pid, padre, cpu%, ram MB, firma, veredicto)
PROCESSES: List[Tuple[str, int, str, float, int, str, str]] = [
    ("explorer.exe", 4820, "winlogon.exe", 1.2, 182, "Microsoft Windows", "normal"),
    ("chrome.exe", 9112, "explorer.exe", 7.4, 940, "Google LLC", "normal"),
    ("svchost.exe", 1304, "services.exe", 0.4, 38, "Microsoft Windows", "normal"),
    ("powershell.exe", 7744, "explorer.exe", 2.1, 96, "Microsoft Windows", "atencion"),
    ("svch0st.exe", 8812, "powershell.exe", 18.9, 211, "sin firma", "sospechoso"),
    ("rundll32.exe", 8866, "svch0st.exe", 4.5, 44, "Microsoft Windows", "atencion"),
    ("notepad.exe", 6020, "explorer.exe", 0.1, 22, "Microsoft Windows", "normal"),
]

VERDICT_COLORS: Dict[str, str] = {
    "normal": C["ok"],
    "atencion": C["warn"],
    "sospechoso": C["crit"],
}
VERDICT_LABELS: Dict[str, str] = {
    "normal": "Normal",
    "atencion": "Revisar",
    "sospechoso": "Sospechoso",
}
VERDICT_ICONS: Dict[str, str] = {
    "normal": "fa5s.check",
    "atencion": "fa5s.exclamation",
    "sospechoso": "fa5s.skull-crossbones",
}

# ---------------------------------------------------------------------------------------------
# Conexiones (simuladas)
# ---------------------------------------------------------------------------------------------
# (proceso, local, remoto, estado, país, veredicto)
CONNECTIONS: List[Tuple[str, str, str, str, str, str]] = [
    ("chrome.exe", "192.168.1.42:51324", "142.250.184.3:443", "ESTABLECIDA", "ES", "normal"),
    ("svch0st.exe", "192.168.1.42:51890", "193.27.14.88:8443", "ESTABLECIDA", "—", "sospechoso"),
    ("explorer.exe", "192.168.1.42:51201", "20.42.65.92:443", "ESTABLECIDA", "IE", "normal"),
    ("svchost.exe", "0.0.0.0:135", "—", "ESCUCHANDO", "—", "atencion"),
    ("powershell.exe", "192.168.1.42:51993", "193.27.14.88:8443", "CIERRE_ESPERA", "—", "atencion"),
]

# ---------------------------------------------------------------------------------------------
# Archivos sospechosos (simulados)
# ---------------------------------------------------------------------------------------------
# (ruta, tamaño, firma, entropía, veredicto)
FILES: List[Tuple[str, str, str, str, str]] = [
    (r"C:\Users\...\AppData\Roaming\svch0st.exe", "211 KB", "sin firma", "7,91 (alta)", "sospechoso"),
    (r"C:\Users\...\AppData\Local\Temp\upd_7742.dll", "88 KB", "sin firma", "7,44 (alta)", "sospechoso"),
    (r"C:\ProgramData\winhelper\cfg.dat", "4 KB", "n/a", "3,10 (baja)", "atencion"),
    (r"C:\Windows\System32\notepad.exe", "360 KB", "Microsoft Windows", "6,02 (normal)", "normal"),
]

# ---------------------------------------------------------------------------------------------
# Persistencia (simulada)
# ---------------------------------------------------------------------------------------------
# (vía, nombre, valor, veredicto)
PERSISTENCE: List[Tuple[str, str, str, str]] = [
    ("Registro · Run (HKCU)", "WinUpdateHelper", r"%APPDATA%\svch0st.exe /s", "sospechoso"),
    ("Tarea programada", "MicrosoftEdgeUpdateX", r"rundll32.exe upd_7742.dll,Start", "sospechoso"),
    ("Registro · Run (HKLM)", "SecurityHealth", r"%WINDIR%\system32\SecurityHealthSystray.exe", "normal"),
    ("Winlogon · Shell", "Shell", "explorer.exe", "normal"),
    ("Servicio", "Spooler", r"%WINDIR%\System32\spoolsv.exe", "normal"),
]

# ---------------------------------------------------------------------------------------------
# Incidentes y cronología (simulados)
# ---------------------------------------------------------------------------------------------
# (hora, título, detalle, color)
TIMELINE: List[Tuple[str, str, str, str]] = [
    ("14:02:11", "Proceso creado desde PowerShell",
     "powershell.exe (7744) creó svch0st.exe (8812) en %APPDATA%. El nombre imita a svchost.exe.",
     C["crit"]),
    ("14:02:14", "Persistencia escrita",
     "Nueva clave Run en HKCU apuntando al ejecutable recién creado.", C["crit"]),
    ("14:02:31", "Conexión saliente a destino desconocido",
     "svch0st.exe abrió una conexión TLS a 193.27.14.88:8443, sin resolución DNS previa.", C["warn"]),
    ("14:03:02", "Archivo señuelo abierto",
     "Se accedió a un canary file del escritorio. Los señuelos no tienen valor real.", C["warn"]),
    ("14:03:40", "Hueco de observabilidad",
     "12 s sin eventos del sensor ETW. No se puede afirmar qué ocurrió en esa ventana.", C["muted"]),
    ("14:04:05", "Módulo no reconocido en proceso del sistema",
     "upd_7742.dll cargado dentro de un proceso anfitrión habitual.", C["crit"]),
]

# (identificador, título, severidad, estado, resumen)
INCIDENTS: List[Tuple[str, str, str, str, str]] = [
    ("INC-0042", "Cadena de persistencia desde PowerShell", "critica", "abierto",
     "Un script creó un ejecutable con nombre imitado, lo registró para arrancar con Windows y "
     "abrió una conexión saliente."),
    ("INC-0041", "Señuelo accedido", "media", "en revisión",
     "Un archivo cebo del escritorio fue abierto. Puede ser exploración manual o automática."),
    ("INC-0039", "Hueco de telemetría", "informativa", "cerrado",
     "El sensor estuvo 12 s sin publicar. La ventana queda marcada como no observada."),
]

SEVERITY_COLORS: Dict[str, str] = {
    "critica": C["crit"], "media": C["warn"], "informativa": C["muted"], "baja": C["ok"],
}
SEVERITY_LABELS: Dict[str, str] = {
    "critica": "Crítica", "media": "Media", "informativa": "Informativa", "baja": "Baja",
}

# ---------------------------------------------------------------------------------------------
# Contención propuesta (simulada) — impacto y reversibilidad SIEMPRE explícitos
# ---------------------------------------------------------------------------------------------
# (acción, impacto, reversible, explicación)
CONTAINMENT: List[Tuple[str, str, bool, str]] = [
    ("Aislar el equipo de la red", "Alto", True,
     "Corta todas las conexiones salvo las imprescindibles. Pierdes Internet hasta levantarlo."),
    ("Congelar el proceso sospechoso", "Medio", True,
     "Lo deja suspendido sin cerrarlo, para no perder la evidencia que tiene en memoria."),
    ("Limitar su CPU y memoria", "Bajo", True,
     "Lo ahoga para que no avance mientras investigas."),
    ("Poner en cuarentena el ejecutable", "Medio", True,
     "Copia la evidencia, la verifica por hash y mueve el archivo a un almacén controlado."),
    ("Desactivar la tarea programada", "Bajo", True,
     "Evita que vuelva a ejecutarse al arrancar. Se guarda el estado previo."),
    ("Restablecer Windows", "Muy alto", False,
     "IRREVERSIBLE. Solo como último recurso y después de preservar toda la evidencia."),
]

# ---------------------------------------------------------------------------------------------
# Señuelos (simulados) — nunca credenciales reales
# ---------------------------------------------------------------------------------------------
# (tipo, nombre, ubicación, estado, activaciones)
DECOYS: List[Tuple[str, str, str, str, int]] = [
    ("Archivo señuelo", "Contraseñas_backup.xlsx", "Escritorio", "activo", 1),
    ("Archivo señuelo", "nominas_2026.docx", "Documentos", "activo", 0),
    ("Archivo señuelo", "claves_wifi.txt", "Descargas", "activo", 0),
    ("Carpeta señuelo", "Copias_de_seguridad\\", "C:\\", "activo", 0),
    ("Credencial sintética", "svc_backup (sin validez real)", "Almacén local", "propuesto", 0),
]

# ---------------------------------------------------------------------------------------------
# Cuarentena (simulada)
# ---------------------------------------------------------------------------------------------
# (archivo, origen, hash, fecha, estado)
QUARANTINE: List[Tuple[str, str, str, str, str]] = [
    ("svch0st.exe", r"%APPDATA%\svch0st.exe", "a3f1…9c47", "2026-10-20 14:05", "aislado"),
    ("upd_7742.dll", r"%TEMP%\upd_7742.dll", "7b20…11de", "2026-10-20 14:06", "aislado"),
]

# ---------------------------------------------------------------------------------------------
# Análisis estático de PE (simulado)
# ---------------------------------------------------------------------------------------------
PE_SAMPLE: Dict[str, str] = {
    "Archivo": "svch0st.exe",
    "Tamaño": "211 KB",
    "SHA-256": "a3f1c0de…9c47 (truncado para la demostración)",
    "Arquitectura": "x86-64",
    "Compilado": "2026-10-18 03:11 UTC (declarado en la cabecera)",
    "Firma digital": "Ninguna",
    "Secciones": ".text .rdata .data .reloc (1 con entropía 7,91)",
    "Importaciones llamativas": "VirtualAllocEx · WriteProcessMemory · CreateRemoteThread",
    "Empaquetado": "Probable (entropía alta y pocas importaciones visibles)",
}

PE_NOTE = ("El análisis estático describe el archivo tal como está en disco. No demuestra lo que hace "
           "al ejecutarse: las importaciones llamativas son un indicio, no una condena.")

# ---------------------------------------------------------------------------------------------
# Salud de sensores (simulada, excepto donde se indique)
# ---------------------------------------------------------------------------------------------
# (sensor, estado, eventos, pérdida fuente, descartes bus, nota)
SENSORS: List[Tuple[str, str, str, str, str, str]] = [
    ("ETW · Kernel-Process", "detenido", "—", "—", "—",
     "El colector existe y está probado, pero no se conecta desde esta beta."),
    ("Registro de eventos", "no implementado", "—", "—", "—", "Colector previsto, sin código aún."),
    ("Procesos (psutil)", "no implementado", "—", "—", "—", "Colector previsto, sin código aún."),
    ("Red", "no implementado", "—", "—", "—", "Colector previsto, sin código aún."),
    ("Dispositivos USB", "no implementado", "—", "—", "—", "Colector previsto, sin código aún."),
    ("Sistema de archivos", "no implementado", "—", "—", "—", "Colector previsto, sin código aún."),
]

# Serie para el gráfico de eventos del modo demostración
EVENT_RATE_DEMO: List[float] = [
    4, 7, 6, 9, 14, 11, 8, 12, 19, 26, 31, 24, 18, 15, 12, 9, 11, 13, 10, 8,
    7, 9, 22, 41, 38, 29, 17, 12, 10, 8, 6, 9, 11, 14, 12, 9, 7, 6, 8, 10,
]

# ---------------------------------------------------------------------------------------------
# Rescue — flujo previsto (no ejecutable)
# ---------------------------------------------------------------------------------------------
# (paso, título, descripción)
RESCUE_FLOW: List[Tuple[str, str, str]] = [
    ("R0", "Arranque y autoverificación",
     "El USB arranca su propio entorno y Lozarus comprueba el hash de su propio contenido."),
    ("R1", "Inventario de discos",
     "Localiza discos, particiones e instalaciones de Windows. Marca las unidades cifradas."),
    ("R2", "Desbloqueo de BitLocker",
     "Si hay cifrado, guía al usuario con SU clave legítima. Sin clave, se detiene y lo explica."),
    ("R3", "Montaje en solo lectura",
     "El disco investigado se monta sin permitir escritura. Escribir exige un paso aparte."),
    ("R4", "Triaje offline",
     "Persistencia, artefactos de ejecución y análisis de archivos, sin ejecutar el Windows dañado."),
    ("R5", "Preservación de evidencia",
     "Copia con hash verificado al destino elegido, nunca al disco investigado."),
    ("R6", "Cuarentena",
     "Solo después de preservar: copia, mueve y deja un manifiesto para poder restaurar."),
    ("R7", "Reparación",
     "Primero rescatar archivos, después reparar arranque y sistema. Lo irreversible, al final."),
    ("R8", "Informe",
     "Exporta el informe del incidente y el registro completo de operaciones."),
]

RESCUE_LIMITS: List[str] = [
    "Un Windows apagado no tiene RAM ni procesos: Rescue analiza ARCHIVOS, no un sistema en marcha.",
    "hiberfil.sys y pagefile.sys son restos en disco, no la memoria del momento del incidente.",
    "Sin la clave de BitLocker, los datos son irrecuperables por diseño del cifrado.",
    "El USB todavía NO está construido: falta validar que PySide6 funcione dentro de WinPE.",
    "FAT32 limita los archivos a 4 GB, por eso el medio necesita una segunda partición NTFS.",
]
