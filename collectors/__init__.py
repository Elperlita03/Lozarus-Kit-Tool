# -*- coding: utf-8 -*-
"""
Colectores (sensores) de Lozarus. Cada colector observa UNA fuente y publica eventos normalizados
en el bus (`EventSink`). Dependen solo de `core/` (y de los adaptadores de `windows/` cuando existan);
nunca importan la GUI ni ejecutan respuestas.
"""
