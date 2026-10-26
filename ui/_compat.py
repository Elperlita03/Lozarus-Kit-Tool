"""
ui/_compat.py · LOZARUS KIT TOOL

Dependencias OPCIONALES de la interfaz, resueltas en un único sitio. Si alguna falta, la GUI
arranca igual y desactiva la función correspondiente (las banderas HAS_* lo indican).
"""

try:
    import qtawesome as qta  # iconos vectoriales (Font Awesome); opcional
    HAS_QTA = True
except ImportError:
    qta, HAS_QTA = None, False

try:  # Núcleo de eventos + Caja Negra (opcionales: si faltan, la GUI sigue sin ellos)
    from core.bus import EventBus
    from core.events import Event, ObservationQuality
    from forensics.blackbox import CajaNegra
    HAS_BLACKBOX = True
except Exception:  # noqa: BLE001
    EventBus = Event = ObservationQuality = CajaNegra = None
    HAS_BLACKBOX = False

try:  # Persistencia táctica + motor de Honeypot autónomo (opcionales)
    from storage.persistence import TacticalConfig
    from deception.honeypot_engine import HoneypotEngine
    HAS_HONEYPOT = True
except Exception:  # noqa: BLE001
    TacticalConfig = HoneypotEngine = None
    HAS_HONEYPOT = False
