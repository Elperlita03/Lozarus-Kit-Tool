"""
ui · LOZARUS KIT TOOL — interfaz PySide6 separada por piezas

  _compat        dependencias opcionales (qtawesome, Caja Negra/EventBus, persistencia + Honeypot)
  theme          paleta, hoja de estilo QSS, iconos del menú y estilos de estado
  widgets        fábricas y widgets reutilizables (tablas, tarjetas, Page, Worker, gráficos)
  dialogs        diálogos de confirmación, protocolo de reset y terminal en vivo
  chrome         marco de la ventana: barra de título, consola, avisos, alertas y redimensionado
  kit            piezas de Sistema y Perímetro: estado de cabecera, baldosas, inspector y acciones seguras
  page_*         una página del menú lateral por archivo (page_ghost: herramientas del Modo Fantasma)

Dependencias en un solo sentido: _compat -> theme -> widgets -> dialogs/chrome -> kit -> page_* -> gui_qt.
gui_qt.py solo monta la ventana principal (MainWindow) y el menú lateral.
"""
