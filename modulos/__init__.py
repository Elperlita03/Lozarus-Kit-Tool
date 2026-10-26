# -*- coding: utf-8 -*-
"""
Paquete de plugins del auditor de seguridad.

auditor.py importa automáticamente cada fichero .py de esta carpeta que no
empiece por "_" y ejecuta las subclases de AuditModule que define, por orden
de nombre de fichero (de ahí los prefijos 01_, 02_...).

    _base.py         clase base AuditModule, severidades y hallazgos
    _utilidades.py   utilidades de solo lectura (comandos, PowerShell, registro...)
    _plantilla.py    plantilla comentada para crear un plugin nuevo

Para añadir una capacidad: copia _plantilla.py como NN_nombre.py y rellénala.
Para desactivar un plugin sin borrarlo: renómbralo con "_" delante.
"""
