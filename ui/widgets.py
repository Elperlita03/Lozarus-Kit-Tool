"""
ui/widgets.py · LOZARUS KIT TOOL

Piezas reutilizables de la interfaz: iconos, tablas y tarjetas, la página base (Page),
el hilo de trabajo (Worker), gráficos del Centro de Comando y utilidades compartidas.
"""

from __future__ import annotations

import math
import random
import socket
import time
from collections import deque
from contextlib import contextmanager
from functools import lru_cache
from typing import Any, Callable, Iterator, Optional, Sequence, Tuple

from PySide6.QtCore import (Property, QEasingCurve, QEvent, QLineF, QPoint, QPointF, QPropertyAnimation, QRect,
                            QRectF, QSize, QThread, QTimer, Qt, Signal)
from PySide6.QtGui import (QBrush, QColor, QFont, QIcon, QImage, QPainter, QPainterPath, QPen, QPixmap,
                           QPolygonF, QRadialGradient)
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QGraphicsDropShadowEffect, QGraphicsScene,
                               QHBoxLayout, QLabel, QPushButton, QScrollArea, QTableWidget, QVBoxLayout,
                               QWidget)

from ui._compat import HAS_QTA, Event, ObservationQuality, qta
from ui.theme import COLORS, GLASS


def icon(name: str, color: Optional[str] = None, disabled_color: Optional[str] = None,
         animation: Any = None) -> QIcon:
    """
    Icono vectorial qtawesome. En estado deshabilitado se pinta con el mismo gris que el texto
    deshabilitado (antes qtawesome usaba un gris claro y el icono «brillaba» en botones inactivos).
    """
    if not HAS_QTA or not name:
        return QIcon()
    opts = {"color": color or COLORS["accent"], "color_disabled": disabled_color or COLORS["disabled"]}
    if animation is not None:
        opts["animation"] = animation
    try:
        return qta.icon(name, **opts)
    except Exception:  # noqa: BLE001  (icono inexistente en esta versión de qtawesome)
        return QIcon()


def with_icon(button, name: str, color: Optional[str] = None, size: int = 16):
    """Pone un icono vectorial a un botón (y devuelve el botón, para encadenar)."""
    button.setIcon(icon(name, color))
    button.setIconSize(QSize(size, size))
    return button


# ---------------------------------------------------------------------------
# «AURA REAL»: resplandor blanco uniforme (QGraphicsDropShadowEffect con desplazamiento 0)
# ---------------------------------------------------------------------------
# No es una animación, pero un QGraphicsDropShadowEffect aplicado EN VIVO re-desenfoca el widget
# en cada repintado suyo o de un hijo (medido: ×10 el coste de cada actualización y ×3 el de cada
# paso de scroll). Por eso:
#   · Tarjetas (#Card, #Bento, #Chip): el efecto genera UNA vez un sprite del halo y AuraHost (el
#     cuerpo de cada página) lo pinta en 9 piezas alrededor de ellas: actualizar o desplazar el
#     contenido solo copia píxeles.
#   · Botones de acción y paneles flotantes (Toast, alertas): efecto en vivo; son pequeños.
AURA_BLUR = 28
AURA_ALPHA = 0.30                                   # blanco al 30 %: presencia real sobre el negro
AURA_PAD = 2 * AURA_BLUR                            # hasta dónde llega el halo fuera del widget
AURA_RADIUS = {"Card": 14, "Bento": 14, "Chip": 12}  # tarjetas con aura -> radio de esquina (QSS)
AURA_BUTTONS = {"", "Primary", "Danger", "Warn"}    # botones de acción (no los de utilidad)


def _aura_effect(parent=None) -> QGraphicsDropShadowEffect:
    effect = QGraphicsDropShadowEffect(parent)
    effect.setBlurRadius(AURA_BLUR)
    effect.setColor(QColor(255, 255, 255, round(255 * AURA_ALPHA)))
    effect.setOffset(0, 0)
    return effect


def apply_aura(widget: QWidget) -> QGraphicsDropShadowEffect:
    """Aura EN VIVO (botones, paneles flotantes): resplandor blanco uniforme hacia fuera."""
    effect = _aura_effect(widget)
    widget.setGraphicsEffect(effect)
    return effect


def apply_button_auras(root: QWidget) -> None:
    """Pone el aura a los botones de acción que cuelgan de `root` (una vez por botón)."""
    for button in root.findChildren(QPushButton):
        if button.objectName() in AURA_BUTTONS and button.graphicsEffect() is None:
            apply_aura(button)


@lru_cache(maxsize=4)
def _aura_sprite(radius: int) -> QPixmap:
    """
    Halo de una tarjeta de esquina `radius`, generado UNA vez con QGraphicsDropShadowEffect sobre un
    rectángulo redondeado blanco; el interior se vacía para que solo quede el resplandor exterior.
    """
    core = 2 * (radius + 2) + 2                     # 2 px centrales: la parte que se estira
    size = core + 2 * AURA_PAD
    shape = QPainterPath()
    shape.addRoundedRect(QRectF(AURA_PAD, AURA_PAD, core, core), radius, radius)
    scene = QGraphicsScene(0, 0, size, size)
    item = scene.addPath(shape, QPen(Qt.PenStyle.NoPen), QBrush(QColor("#FFFFFF")))
    item.setGraphicsEffect(_aura_effect())
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    scene.render(p, QRectF(0, 0, size, size), QRectF(0, 0, size, size))
    p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
    p.fillPath(shape, QColor(0, 0, 0))
    p.end()
    return QPixmap.fromImage(img)


def _paint_aura(p: QPainter, rect: QRect, radius: int, clip: QRect) -> None:
    """Pinta el halo alrededor de `rect` en 9 piezas (esquinas fijas, bordes estirados). Solo dibuja
    las piezas que tocan `clip`: al actualizarse un medidor no se recompone el halo entero."""
    sprite = _aura_sprite(radius)
    s, c = sprite.width(), AURA_PAD + radius + 2    # c: lado de cada esquina del sprite
    out = rect.adjusted(-AURA_PAD, -AURA_PAD, AURA_PAD, AURA_PAD)
    x, y, w, h = out.x(), out.y(), out.width(), out.height()
    if w < 2 * c or h < 2 * c:
        return
    for dst, src in (((x, y, c, c), (0, 0, c, c)), ((x + w - c, y, c, c), (s - c, 0, c, c)),
                     ((x, y + h - c, c, c), (0, s - c, c, c)), ((x + w - c, y + h - c, c, c), (s - c, s - c, c, c)),
                     ((x + c, y, w - 2 * c, c), (c, 0, 2, c)), ((x + c, y + h - c, w - 2 * c, c), (c, s - c, 2, c)),
                     ((x, y + c, c, h - 2 * c), (0, c, c, 2)), ((x + w - c, y + c, c, h - 2 * c), (s - c, c, c, 2))):
        target = QRect(*dst)
        if clip.intersects(target):  # clip: QRect o QRegion
            p.drawPixmap(target, sprite, QRect(*src))


# Luz ambiental: un foco tenue y estático en la parte superior central de cada página.
AMBIENT_ALPHA = 16                                  # blanco 16/255 en el centro -> transparente


def _paint_ambient(p: QPainter, width: int, clip: QRect) -> None:
    """Degradado radial fijo (sin animación) centrado arriba; solo rellena la parte que toca `clip`."""
    radius = max(420.0, width * 0.45)
    area = QRect(int(width / 2 - radius), 0, int(2 * radius), int(radius)).intersected(clip)
    if area.isEmpty():
        return
    glow = QRadialGradient(QPointF(width / 2, 0), radius)
    glow.setColorAt(0.0, QColor(255, 255, 255, AMBIENT_ALPHA))
    glow.setColorAt(1.0, QColor(0, 0, 0, 0))
    p.fillRect(area, QBrush(glow))


# ---------------------------------------------------------------------------
# FONDO ANIMADO «COSMOS»: partículas de luz que derivan despacio por detrás de las tarjetas
# ---------------------------------------------------------------------------
# Coste acotado: 48 partículas a 30 FPS, SOLO mientras la página se ve (el temporizador se para al
# ocultarla o minimizar). Cada fotograma invalida únicamente el recuadro diminuto de las partículas
# que CAMBIAN de aspecto (otro píxel o otro nivel de brillo): a esta velocidad casi todas avanzan
# menos de medio píxel por fotograma, así que Qt solo repinta lo que de verdad se ve distinto.
PARTICLE_COUNT = 48
PARTICLE_FPS = 30
PARTICLE_SPEED = (4.0, 12.0)                # px/s: deriva lenta
PARTICLE_LEVELS = 20                        # niveles de brillo del parpadeo (cuantizado)
PARTICLE_BLOCKERS_EVERY = PARTICLE_FPS      # fotogramas entre recálculos de las zonas con aura en vivo
PARTICLE_RADII = (0.8, 1.2, 1.7, 2.4)       # núcleo de cada luz (px); 4 tamaños → 4 sprites en caché
PARTICLE_HALO = 3.5                          # el halo de cada luz mide 3,5 veces su núcleo


class _Particle:
    # x, y, phase: estado continuo · px, py, level: lo pintado (píxel entero y nivel de brillo)
    __slots__ = ("x", "y", "vx", "vy", "r", "alpha", "phase", "twinkle", "px", "py", "level")

    def look(self) -> tuple:
        level = round(self.alpha * (0.65 + 0.35 * math.sin(self.phase)) * PARTICLE_LEVELS)
        return int(self.x), int(self.y), level


@lru_cache(maxsize=len(PARTICLE_RADII))
def _particle_sprite(r: float) -> QPixmap:
    """Luz blanca suave (núcleo + halo) pre-renderizada UNA vez por tamaño."""
    halo = r * PARTICLE_HALO
    size = int(math.ceil(2 * halo)) + 2
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    grad = QRadialGradient(QPointF(size / 2, size / 2), halo)
    grad.setColorAt(0.0, QColor(255, 255, 255, 255))
    grad.setColorAt(r / halo, QColor(255, 255, 255, 190))
    grad.setColorAt(1.0, QColor(255, 255, 255, 0))
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(grad))
    p.drawEllipse(QPointF(size / 2, size / 2), halo, halo)
    p.end()
    return QPixmap.fromImage(img)


# Rayos y grietas cósmicas: cada pocos fotogramas un arco eléctrico une dos luces cercanas o una
# grieta rasga el fondo. Viven menos de un segundo y se invalidan por SEGMENTOS (recuadros de unos
# pocos px), nunca por su caja envolvente: un rayo en diagonal no obliga a repintar media página.
BOLT_EVERY = (10, 36)               # fotogramas entre un rayo/grieta y el siguiente (aleatorio)
BOLT_MAX = 3                        # simultáneos como mucho
BOLT_LEVELS = 8                     # niveles de brillo del desvanecido (cuantizado)
BOLT_PAD = 4                        # margen del recuadro de cada segmento (trazo del halo + antialias)
BOLT_WHITE, BOLT_SILVER = "#FFFFFF", "#BDBDBD"
ARC_CHANCE = 0.6                    # probabilidad de arco (si no hay pareja de luces: grieta)
ARC_REACH = (24.0, 150.0)           # px: distancia entre las dos luces que puede unir un arco
ARC_LIFE = 0.35                     # s
ARC_DEPTH = 3                       # subdivisiones del zigzag: 2**3 = 8 segmentos
CRACK_LIFE = 0.9                    # s
CRACK_GROW = 0.25                   # s que tarda en abrirse entera
CRACK_STEPS = (5, 9)                # segmentos del tronco
CRACK_STEP_LEN = (9.0, 18.0)        # px por segmento


class _Bolt:
    # segs: [(orden, QLineF, QRect)] por orden · shown, level: lo pintado (segmentos abiertos y brillo)
    __slots__ = ("kind", "segs", "depth", "life", "age", "shown", "level")


def _bolt_seg(order: int, a: QPointF, b: QPointF) -> tuple:
    box = QRectF(a, b).normalized().adjusted(-BOLT_PAD, -BOLT_PAD, BOLT_PAD, BOLT_PAD).toAlignedRect()
    return order, QLineF(a, b), box


def _arc_points(a: QPointF, b: QPointF, rng: random.Random) -> list:
    """Zigzag eléctrico entre `a` y `b` por desplazamiento del punto medio."""
    pts, jitter = [a, b], QLineF(a, b).length() * 0.18
    for _ in range(ARC_DEPTH):
        nxt = [pts[0]]
        for p, q in zip(pts, pts[1:]):
            dx, dy = q.x() - p.x(), q.y() - p.y()
            length = math.hypot(dx, dy) or 1.0
            off = rng.uniform(-jitter, jitter)
            nxt += [QPointF((p.x() + q.x()) / 2 - dy / length * off, (p.y() + q.y()) / 2 + dx / length * off), q]
        pts, jitter = nxt, jitter / 2
    return pts


@lru_cache(maxsize=2)
def _bolt_pens(kind: str) -> tuple:
    """(halo, núcleo): arco de núcleo blanco con halo plata; grieta de núcleo plata con halo blanco."""
    glow_color, core_color, core_w = ((BOLT_SILVER, BOLT_WHITE, 1.2) if kind == "arc"
                                      else (BOLT_WHITE, BOLT_SILVER, 1.0))
    pens = []
    for color, alpha, width in ((glow_color, 70 if kind == "arc" else 40, 3.0), (core_color, 255, core_w)):
        c = QColor(color)
        c.setAlpha(alpha)
        pen = QPen(c, width)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        pens.append(pen)
    return tuple(pens)


class AuraHost(QWidget):
    """
    Cuerpo de una página: pinta la luz ambiental, las partículas del fondo animado con sus rayos y
    grietas cósmicas, y el aura de sus tarjetas DIRECTAS desde el sprite en caché. Si una tarjeta
    se mueve, cambia de tamaño o se oculta, repinta el cuerpo (el halo sobresale del widget).
    """

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._particles: list = []
        self._rng = random.Random()
        self._last_t: Optional[float] = None
        self._blockers: list = []     # zonas con aura EN VIVO (botones): ahí las luces se apagan
        self._frame = 0
        self._bolts: list = []        # rayos y grietas vivos
        self._next_bolt = self._rng.randint(*BOLT_EVERY)
        self._timer = QTimer(self)
        self._timer.setInterval(1000 // PARTICLE_FPS)
        self._timer.timeout.connect(self._step)

    # --- motor de animación: solo corre con la página a la vista ------------------------------
    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._last_t = None
        self._timer.start()

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self._timer.stop()

    def _spawn(self, area: QRect) -> _Particle:
        rng, pt = self._rng, _Particle()
        pt.x = rng.uniform(area.left(), area.right())
        pt.y = rng.uniform(area.top(), area.bottom())
        angle = rng.uniform(-math.pi * 0.85, -math.pi * 0.15)   # deriva ligera hacia arriba
        speed = rng.uniform(*PARTICLE_SPEED)
        pt.vx, pt.vy = math.cos(angle) * speed, math.sin(angle) * speed
        pt.r = rng.choice(PARTICLE_RADII)
        pt.alpha = rng.uniform(0.25, 0.8)
        pt.phase = rng.uniform(0, 2 * math.pi)
        pt.twinkle = rng.uniform(0.4, 1.4)                       # rad/s del parpadeo
        pt.px, pt.py, pt.level = pt.look()
        return pt

    def _live_effect_zones(self) -> list:
        """
        Zonas de los widgets con aura EN VIVO (botones de acción). Una luz que pasara por detrás
        obligaría a re-desenfocar el botón en cada fotograma, así que ahí las partículas se apagan.
        """
        zones = []
        for w in self.findChildren(QWidget):
            effect = w.graphicsEffect()
            if effect is not None and effect.isEnabled() and w.isVisible():
                zones.append(QRect(w.mapTo(self, QPoint(0, 0)), w.size())
                             .adjusted(-AURA_PAD, -AURA_PAD, AURA_PAD, AURA_PAD))
        return zones

    def _dirty(self, x0: float, y0: float, x1: float, y1: float, r: float) -> None:
        pad = r * PARTICLE_HALO + 2
        self.update(QRect(int(min(x0, x1) - pad), int(min(y0, y1) - pad),
                          int(abs(x1 - x0) + 2 * pad) + 1, int(abs(y1 - y0) + 2 * pad) + 1))

    def _step(self) -> None:
        area = self.visibleRegion().boundingRect()
        if area.isEmpty():
            return
        now = time.monotonic()
        dt = 0.0 if self._last_t is None else min(now - self._last_t, 0.1)  # tope: sin saltos tras una pausa
        self._last_t = now
        while len(self._particles) < PARTICLE_COUNT:
            pt = self._spawn(area)
            self._particles.append(pt)
            self._dirty(pt.x, pt.y, pt.x, pt.y, pt.r)
        if self._frame % PARTICLE_BLOCKERS_EVERY == 0:
            self._blockers = self._live_effect_zones()
        self._frame += 1
        left, top = area.left(), area.top()
        width, height = max(1, area.width()), max(1, area.height())
        for pt in self._particles:
            pt.x += pt.vx * dt
            pt.y += pt.vy * dt
            pt.phase += pt.twinkle * dt
            wrapped = not area.contains(int(pt.x), int(pt.y))
            if wrapped:  # sale por un borde (o el scroll la dejó fuera): reaparece por el opuesto
                pt.x = left + (pt.x - left) % width
                pt.y = top + (pt.y - top) % height
            look = pt.look()
            if look[2] > 0 and self._blockers:
                spot = QRect(look[0] - 4, look[1] - 4, 9, 9)
                if any(zone.intersects(spot) for zone in self._blockers):
                    look = (look[0], look[1], 0)  # detrás de un botón con aura en vivo: apagada
            if look == (pt.px, pt.py, pt.level):
                continue  # mismo píxel y mismo brillo: nada que repintar
            x0, y0, was_lit = pt.px, pt.py, pt.level > 0
            pt.px, pt.py, pt.level = look
            if not was_lit and look[2] == 0:
                continue  # apagada antes y ahora: no hay nada que borrar ni que pintar
            if wrapped:
                self._dirty(x0, y0, x0, y0, pt.r)
                self._dirty(pt.px, pt.py, pt.px, pt.py, pt.r)
            else:
                self._dirty(x0, y0, pt.px, pt.py, pt.r)
        self._step_bolts(area, dt)

    # --- rayos y grietas cósmicas ------------------------------------------------------------
    def _new_bolt(self, kind: str, segs: list, life: float) -> Optional[_Bolt]:
        if not segs or any(zone.intersects(box) for _, _, box in segs for zone in self._blockers):
            return None  # rozaría un botón con aura en vivo: lo obligaría a re-desenfocarse
        bolt = _Bolt()
        bolt.kind, bolt.segs, bolt.life = kind, sorted(segs, key=lambda seg: seg[0]), life
        bolt.depth = bolt.segs[-1][0] + 1
        bolt.age, bolt.shown, bolt.level = 0.0, 0, 0
        return bolt

    def _spawn_arc(self) -> Optional[_Bolt]:
        """Arco entre una luz encendida y su vecina encendida más cercana (dentro de ARC_REACH)."""
        lit = [pt for pt in self._particles if pt.level > 0]
        if len(lit) < 2:
            return None
        rng, near, far = self._rng, *ARC_REACH
        a = rng.choice(lit)
        best, best_d = None, far
        for pt in lit:
            d = math.hypot(pt.px - a.px, pt.py - a.py)
            if near <= d < best_d:
                best, best_d = pt, d
        if best is None:
            return None
        pts = _arc_points(QPointF(a.px + 0.5, a.py + 0.5), QPointF(best.px + 0.5, best.py + 0.5), rng)
        segs = [_bolt_seg(0, p, q) for p, q in zip(pts, pts[1:])]
        if rng.random() < 0.5:  # zarcillo: una horquilla corta desde un vértice intermedio
            root = pts[rng.randrange(2, len(pts) - 2)]
            angle = rng.uniform(0, 2 * math.pi)
            for _ in range(2):
                step = rng.uniform(5.0, 10.0)
                tip = QPointF(root.x() + math.cos(angle) * step, root.y() + math.sin(angle) * step)
                segs.append(_bolt_seg(0, root, tip))
                root, angle = tip, angle + rng.uniform(-0.7, 0.7)
        return self._new_bolt("arc", segs, ARC_LIFE)

    def _spawn_crack(self, area: QRect) -> Optional[_Bolt]:
        """Grieta: tronco quebrado con alguna rama; se abre segmento a segmento (orden = paso)."""
        rng, segs = self._rng, []
        pos = QPointF(rng.uniform(area.left(), area.right()), rng.uniform(area.top(), area.bottom()))
        heading = rng.uniform(0, 2 * math.pi)
        for i in range(rng.randint(*CRACK_STEPS)):
            heading += rng.uniform(-0.6, 0.6)
            step = rng.uniform(*CRACK_STEP_LEN)
            nxt = QPointF(pos.x() + math.cos(heading) * step, pos.y() + math.sin(heading) * step)
            segs.append(_bolt_seg(i, pos, nxt))
            pos = nxt
            if i and rng.random() < 0.3:  # rama: sale del nudo y se abre a la vez que el tronco
                bpos, bhead = pos, heading + rng.choice((-1, 1)) * rng.uniform(0.6, 1.1)
                for j in range(1, rng.randint(2, 3) + 1):
                    blen = rng.uniform(*CRACK_STEP_LEN) * 0.6
                    bnext = QPointF(bpos.x() + math.cos(bhead) * blen, bpos.y() + math.sin(bhead) * blen)
                    segs.append(_bolt_seg(i + j, bpos, bnext))
                    bpos, bhead = bnext, bhead + rng.uniform(-0.5, 0.5)
        return self._new_bolt("crack", segs, CRACK_LIFE)

    def _bolt_look(self, bolt: _Bolt) -> tuple:
        """(segmentos abiertos, nivel de brillo) que tocaría pintar ahora."""
        if bolt.age >= bolt.life:
            return bolt.shown, 0
        if bolt.kind == "arc":  # parpadeo eléctrico mientras se apaga
            fade = (1 - bolt.age / bolt.life) * self._rng.uniform(0.55, 1.0)
            return len(bolt.segs), round(fade * BOLT_LEVELS)
        open_steps = math.ceil(bolt.age / CRACK_GROW * bolt.depth)
        shown = sum(1 for order, _, _ in bolt.segs if order < open_steps)
        fade = min(1.0, 2 * (1 - bolt.age / bolt.life))  # plena la primera mitad, luego se apaga
        return shown, round(fade * BOLT_LEVELS)

    def _step_bolts(self, area: QRect, dt: float) -> None:
        if self._frame >= self._next_bolt:
            self._next_bolt = self._frame + self._rng.randint(*BOLT_EVERY)
            if len(self._bolts) < BOLT_MAX:
                bolt = self._spawn_arc() if self._rng.random() < ARC_CHANCE else None
                bolt = bolt or self._spawn_crack(area)
                if bolt is not None:
                    self._bolts.append(bolt)
        alive = []
        for bolt in self._bolts:
            bolt.age += dt
            shown, level = self._bolt_look(bolt)
            if (shown, level) != (bolt.shown, bolt.level):
                # mismo brillo: solo los segmentos recién abiertos; otro brillo: todos los abiertos
                first = bolt.shown if level == bolt.level else 0
                for _, _, box in bolt.segs[first:max(shown, bolt.shown)]:
                    self.update(box)
                bolt.shown, bolt.level = shown, level
            if bolt.level > 0 or bolt.age < bolt.life:
                alive.append(bolt)  # apagada y vencida: su último borrado ya está invalidado
        self._bolts = alive

    def childEvent(self, event) -> None:
        super().childEvent(event)
        child = event.child()
        if event.added() and isinstance(child, QWidget) and child.objectName() in AURA_RADIUS:
            child.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:
        if event.type() in (QEvent.Type.Move, QEvent.Type.Resize, QEvent.Type.Show, QEvent.Type.Hide):
            self.update()
        return False

    def paintEvent(self, event) -> None:
        region = event.region()  # región EXACTA (las partículas la dejan en muchos recuadros pequeños)
        p = QPainter(self)
        _paint_ambient(p, self.width(), region.boundingRect())  # 1) atmósfera
        for pt in self._particles:                                # 2) partículas del fondo
            sprite = _particle_sprite(pt.r)
            side = sprite.width()
            x, y = pt.px - side // 2, pt.py - side // 2           # lo mismo que _step invalidó
            if pt.level > 0 and region.intersects(QRect(x, y, side, side)):
                p.setOpacity(pt.level / PARTICLE_LEVELS)          # parpadeo suave (cuantizado)
                p.drawPixmap(x, y, sprite)
        if self._bolts:                                           # 3) rayos y grietas
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            for bolt in self._bolts:
                lines = [line for _, line, box in bolt.segs[:bolt.shown] if region.intersects(box)]
                if bolt.level > 0 and lines:
                    p.setOpacity(bolt.level / BOLT_LEVELS)
                    for pen in _bolt_pens(bolt.kind):             # halo y, encima, el núcleo
                        p.setPen(pen)
                        p.drawLines(lines)
            p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        p.setOpacity(1.0)
        for child in self.children():                             # 4) halos de las tarjetas
            radius = AURA_RADIUS.get(child.objectName()) if isinstance(child, QWidget) else None
            if radius and child.isVisible():
                rect = child.geometry()
                if region.intersects(rect.adjusted(-AURA_PAD, -AURA_PAD, AURA_PAD, AURA_PAD)):
                    _paint_aura(p, rect, radius, region)
        p.end()


def _hold_aura(widget: QWidget, hold: bool) -> None:
    """
    Apaga (hold=True) o devuelve el aura del widget y de sus contenedores. El spinner de set_busy
    repinta el botón cada 30 ms; con el aura activa, Qt re-desenfocaría la tarjeta entera 33 veces
    por segundo. Lleva la cuenta por efecto: dos botones ocupados en la misma tarjeta no se pisan.
    """
    w = widget
    while w is not None:
        effect = w.graphicsEffect()
        if isinstance(effect, QGraphicsDropShadowEffect):
            holds = max(0, int(effect.property("lz_holds") or 0) + (1 if hold else -1))
            effect.setProperty("lz_holds", holds)
            effect.setEnabled(holds == 0)
        w = w.parentWidget()


def set_busy(button: QPushButton, busy: bool, text: Optional[str] = None) -> None:
    """
    Estado «ocupado» de un botón mientras su tarea corre en segundo plano: lo deshabilita (evita el
    doble clic), muestra un texto de progreso y un spinner animado en color de acento. Al terminar
    restaura su texto e icono originales. Un único `Spin` por botón, reutilizado: qtawesome crea un
    QTimer hijo por animación, así que crear uno nuevo en cada clic acumularía temporizadores.
    """
    button.setProperty("busy", busy)  # estilo propio en el QSS (texto en acento mientras trabaja)
    button.style().unpolish(button)
    button.style().polish(button)
    if bool(button.property("lz_aura_held")) != busy:  # el aura se pausa mientras gira el spinner
        button.setProperty("lz_aura_held", busy)
        _hold_aura(button, busy)
    if busy:
        if getattr(button, "_lz_idle", None) is None:   # guarda el estado de reposo una sola vez
            button._lz_idle = (button.text(), button.icon())
        button.setEnabled(False)
        if text:
            button.setText(text)
        if HAS_QTA:
            spin = getattr(button, "_lz_spin", None)
            if spin is None:
                spin = qta.Spin(button, interval=30, step=10)
                button._lz_spin = spin
            else:
                spin.start()
            button.setIcon(icon("fa5s.circle-notch", COLORS["accent"], COLORS["accent"], spin))
        return
    spin = getattr(button, "_lz_spin", None)
    if spin is not None:
        spin.stop()
    idle = getattr(button, "_lz_idle", None)
    if idle is not None:
        button.setText(idle[0])
        button.setIcon(idle[1])
        button._lz_idle = None
    button.setEnabled(True)


@contextmanager
def frozen(widget: QWidget) -> Iterator[None]:
    """Suspende el repintado durante un relleno masivo (p. ej. cientos de celdas) y repinta UNA vez."""
    widget.setUpdatesEnabled(False)
    try:
        yield
    finally:
        widget.setUpdatesEnabled(True)


class LzTable(QTableWidget):
    """
    QTableWidget con ESTADO VACÍO: sin filas, pinta un icono y un mensaje centrados en lugar de un
    recuadro negro vacío, para que se entienda qué mostrará la tabla y cómo llenarla.
    """

    def __init__(self, rows: int, cols: int):
        super().__init__(rows, cols)
        self._empty_text = ""
        self._empty_icon = "fa5s.inbox"

    def set_empty_text(self, text: str, icon_name: str = "fa5s.inbox") -> None:
        self._empty_text, self._empty_icon = text, icon_name
        self.viewport().update()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self.rowCount() or not self._empty_text:
            return
        p = QPainter(self.viewport())
        try:
            area = self.viewport().rect().adjusted(32, 0, -32, 0)
            if HAS_QTA:
                pix = icon(self._empty_icon, COLORS["faint"]).pixmap(30, 30)
                p.drawPixmap(area.center().x() - 15, area.center().y() - 40, pix)
            p.setPen(QColor(COLORS["muted"]))
            font = p.font()
            font.setPointSize(10)
            p.setFont(font)
            p.drawText(area.adjusted(0, 4, 0, 40), int(Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap),
                       self._empty_text)
        finally:
            p.end()


def make_table(headers: Sequence[str], widths: Optional[Sequence[int]] = None,
               empty: str = "", empty_icon: str = "fa5s.inbox") -> QTableWidget:
    """
    Tabla de solo lectura con el aspecto común de Lozarus: filas de alto fijo, cabecera alineada a
    la izquierda, sin rejilla, selección de fila única y texto recortado con «…» en vez de saltos.
    `empty`: mensaje que se muestra centrado mientras la tabla no tiene filas.
    """
    t = LzTable(0, len(headers))
    if empty:
        t.set_empty_text(empty, empty_icon)
    t.setHorizontalHeaderLabels(list(headers))
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(30)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.setWordWrap(False)
    t.setTextElideMode(Qt.TextElideMode.ElideRight)
    hh = t.horizontalHeader()
    hh.setStretchLastSection(True)
    hh.setHighlightSections(False)
    hh.setMinimumSectionSize(48)
    hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    for i, w in enumerate(widths or ()):
        t.setColumnWidth(i, w)
    return t


def make_card(title: str, desc: str = "") -> Tuple[QFrame, QVBoxLayout]:
    """Tarjeta estándar (márgenes y espaciado únicos) con título y descripción opcional."""
    box = QFrame()
    box.setObjectName("Card")
    lay = QVBoxLayout(box)
    lay.setContentsMargins(18, 16, 18, 16)
    lay.setSpacing(10)
    head = QLabel(title)
    head.setObjectName("CardTitle")
    lay.addWidget(head)
    if desc:
        sub = QLabel(desc)
        sub.setObjectName("CardText")
        sub.setWordWrap(True)
        lay.addWidget(sub)
    return box, lay


# Hilos que seguían vivos al cerrar la ventana (ver MainWindow._wait_workers y main()).
_ORPHAN_WORKERS: list = []


class Worker(QThread):
    """
    Clase base para ejecutar trabajo en segundo plano (diagnósticos, scripts de PowerShell) sin
    congelar la interfaz. Recibe una función `fn(emit)` donde `emit(kind, text)` publica líneas en
    la consola. Las señales de Qt se entregan al hilo de la UI de forma segura (conexión en cola),
    así que nunca se tocan widgets desde aquí.
    """
    log = Signal(str, str)       # (kind, text) -> consola de telemetría
    done = Signal(bool, object)  # (ok, resultado-o-mensaje-de-error)

    def __init__(self, fn: Callable[[Callable[[str, str], None]], Any]):
        super().__init__()
        self._fn = fn

    def run(self) -> None:
        try:
            result = self._fn(self.log.emit)
            self.done.emit(True, result)
        except Exception as exc:
            self.done.emit(False, f"{type(exc).__name__}: {exc}")


class Page(QWidget):
    """
    Sección con cabecera FIJA (título + subtítulo) y un cuerpo con scroll vertical. `self.root` es el
    layout de ese cuerpo: las páginas añaden ahí sus tarjetas sin ocuparse del scroll. Sin él, el
    QStackedWidget heredaba el mínimo de la página más alta (≈1430×1630 px) e ignoraba el tamaño de
    la ventana, que se salía de una pantalla 1080p.
    """

    def __init__(self, title: str, subtitle: str, icon_name: Optional[str] = None):
        super().__init__()
        self.setObjectName("Content")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 26, 10, 16)  # + 20 px del cuerpo: hueco para el aura de las tarjetas
        outer.setSpacing(16)
        header = QHBoxLayout()
        header.setContentsMargins(20, 0, 20, 0)
        header.setSpacing(14)
        if icon_name:
            ic = QLabel()
            ic.setPixmap(icon(icon_name, COLORS["accent"]).pixmap(30, 30))
            ic.setAlignment(Qt.AlignmentFlag.AlignTop)
            header.addWidget(ic)
        titlecol = QVBoxLayout()
        titlecol.setSpacing(2)
        head = QLabel(title)
        head.setObjectName("PageTitle")
        sub = QLabel(subtitle)
        sub.setObjectName("PageSub")
        sub.setWordWrap(True)
        titlecol.addWidget(head)
        titlecol.addWidget(sub)
        header.addLayout(titlecol, 1)
        outer.addLayout(header)

        scroll = QScrollArea()
        scroll.setObjectName("Content")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = AuraHost()  # pinta el aura de las tarjetas de la página
        body.setObjectName("Content")
        self.root = QVBoxLayout(body)
        self.root.setContentsMargins(20, 12, 24, 22)
        self.root.setSpacing(16)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        # Las páginas montan sus botones DESPUÉS de este __init__: su aura se aplica al volver al
        # bucle de eventos, cuando ya existen todos.
        QTimer.singleShot(0, self, lambda: apply_button_auras(self))


class Gauge(QWidget):
    """Medidor circular dibujado con QPainter: pista gris, arco de color y porcentaje en el centro."""

    def __init__(self, color=COLORS["accent"], size=132, thickness=11):
        super().__init__()
        self.setFixedSize(size, size)
        self._value = 0.0
        self._color = color
        self._thickness = thickness

    def set_value(self, value) -> None:
        self._value = max(0.0, min(100.0, float(value)))
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        m = self._thickness / 2 + 4
        rect = QRectF(m, m, self.width() - 2 * m, self.height() - 2 * m)
        track = QPen(QColor(COLORS["panel_alt"]))
        track.setWidthF(self._thickness)
        track.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(track)
        p.drawArc(rect, 0, 360 * 16)
        if self._value > 0:
            arc = QPen(QColor(self._color))
            arc.setWidthF(self._thickness)
            arc.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(arc)
            p.drawArc(rect, 90 * 16, -int(360 * 16 * self._value / 100))
        p.setPen(QColor(COLORS["text"]))
        font = QFont(self.font())  # tipografía de la aplicación (theme.base_font), no una fija
        font.setPointSize(21)
        font.setWeight(QFont.Weight.Bold)
        p.setFont(font)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{self._value:.0f}%")


class BentoCard(QFrame):
    """
    Tarjeta grande clicable (bento) con icono, título, descripción y estado; borde animado al hover.
    `status_fn()` devuelve (activo, texto) o (activo, texto, valor): `valor` es una métrica que se
    muestra grande bajo el título, y `activo` puede ser un color para el punto (p. ej. COLORS["warn"]).
    """

    def __init__(self, icon_name, title, desc, status_fn, on_click):
        super().__init__()
        self.setObjectName("Bento")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(154)
        self._on_click = on_click
        self._status_fn = status_fn
        self._border = QColor(COLORS["border"])
        self._anim = QPropertyAnimation(self, b"border", self)
        self._anim.setDuration(170)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(8)
        top = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon(icon_name, COLORS["accent"]).pixmap(26, 26))
        top.addWidget(ic)
        top.addStretch(1)
        self.dot = QLabel("●")
        self.dot.setStyleSheet(f"color:{COLORS['faint']}; font-size:11px;")
        top.addWidget(self.dot)
        lay.addLayout(top)
        t = QLabel(title)
        t.setObjectName("CardTitle")
        t.setWordWrap(True)  # sin esto, 4 títulos largos por fila forzaban scroll horizontal
        d = QLabel(desc)
        d.setObjectName("CardText")
        d.setWordWrap(True)
        self.value = QLabel("")
        self.value.setObjectName("ChipVal")
        self.value.setVisible(False)  # solo las tarjetas con métrica lo muestran
        lay.addWidget(t)
        lay.addWidget(self.value)
        lay.addWidget(d)
        lay.addStretch(1)
        self.status = QLabel("")
        self.status.setObjectName("Tiny")
        lay.addWidget(self.status)
        self._last: Optional[tuple] = None
        self._apply()
        self.refresh()  # aura: la pinta AuraHost alrededor de #Bento (sprite en caché, sin re-desenfocar)

    def refresh(self) -> None:
        state = self._status_fn()
        if state == self._last:
            return  # sin cambios: no re-aplicar estilos (cada setStyleSheet fuerza un re-polish)
        self._last = state
        active, text = state[0], state[1]
        color = active if isinstance(active, str) else COLORS["ok"] if active else COLORS["faint"]
        self.dot.setStyleSheet(f"color:{color}; font-size:11px;")
        self.status.setText(text)
        if len(state) > 2:
            self.value.setText(state[2])
            self.value.setVisible(True)

    def _get_border(self):
        return self._border

    def _set_border(self, color):
        self._border = color
        self._apply()

    border = Property(QColor, _get_border, _set_border)

    def _apply(self):
        c = self._border
        rim = max(0.38, c.red() / 255)  # rim light: el borde superior nunca queda por debajo de 0.38
        self.setStyleSheet(f"#Bento {{ background:{GLASS['card']}; border:1px solid "
                           f"rgb({c.red()},{c.green()},{c.blue()}); border-top:1px solid "
                           f"rgba(255,255,255,{rim:.2f}); border-radius:14px; }}")

    def _to(self, color):
        self._anim.stop()
        self._anim.setStartValue(self._border)
        self._anim.setEndValue(QColor(color))
        self._anim.start()

    def enterEvent(self, event):
        self._to(QColor(COLORS["accent"]))
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._to(QColor(COLORS["border"]))
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._on_click()
        super().mousePressEvent(event)


class PulseGraph(QWidget):
    """
    Pulso en vivo (QPainter): curvas de los últimos 60 s de CPU %, Memoria % y tráfico de red. CPU y
    RAM van en escala fija 0-100; la red se autoescala a su máximo reciente (se muestra su KB/s). Es
    ligero: guarda tres deques de 60 puntos y repinta en cada tic de 1 s.
    """
    SERIES = [("CPU", COLORS["accent"]), ("RAM", COLORS["accent_2"]), ("RED", COLORS["ok"])]

    def __init__(self):
        super().__init__()
        self.setMinimumSize(210, 96)
        self._cpu = deque(maxlen=60)
        self._ram = deque(maxlen=60)
        self._net = deque(maxlen=60)
        self._net_kbs = 0.0

    def push(self, cpu: float, ram: float, net_kbs: float) -> None:
        self._cpu.append(max(0.0, min(100.0, cpu)))
        self._ram.append(max(0.0, min(100.0, ram)))
        self._net.append(max(0.0, net_kbs))
        self._net_kbs = net_kbs
        self.update()

    def _poly(self, data, w, h, pad, vmax):
        n = len(data)
        if n < 2:
            return None
        step = (w - 2 * pad) / (self._cpu.maxlen - 1)
        x0 = w - pad - (n - 1) * step
        pts = []
        for i, v in enumerate(data):
            y = h - pad - (v / vmax if vmax else 0) * (h - 2 * pad)
            pts.append(QPointF(x0 + i * step, y))
        return QPolygonF(pts)

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h, pad = self.width(), self.height(), 8
        p.setPen(QPen(QColor(COLORS["panel_alt"]), 1))
        for frac in (0.0, 0.5, 1.0):   # rejilla horizontal tenue
            y = pad + frac * (h - 2 * pad)
            p.drawLine(int(pad), int(y), int(w - pad), int(y))
        net_max = max(list(self._net) or [1.0]) or 1.0
        for data, (_lbl, color), vmax in ((self._cpu, self.SERIES[0], 100.0),
                                          (self._ram, self.SERIES[1], 100.0),
                                          (self._net, self.SERIES[2], net_max)):
            poly = self._poly(data, w, h, pad, vmax)
            if poly is None:
                continue
            pen = QPen(QColor(color))
            pen.setWidthF(1.6)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPolyline(poly)
        p.end()

    def net_label(self) -> str:
        v = self._net_kbs
        return f"{v/1024:.1f} MB/s" if v >= 1024 else f"{v:.0f} KB/s"


class HealthBadge(QFrame):
    """Puntuación de salud global del sistema (0-100): número grande + etiqueta, con color semántico."""

    def __init__(self):
        super().__init__()
        self.setObjectName("Card")
        self.setFixedWidth(118)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(13, 10, 13, 10)
        lay.setSpacing(2)
        cap = QLabel("SALUD")
        cap.setObjectName("ChipCap")
        self.value = QLabel("—")
        self.value.setStyleSheet(f"color:{COLORS['text']}; font-size:28px; font-weight:bold;")
        self.label = QLabel("")
        self.label.setObjectName("Tiny")
        lay.addWidget(cap)
        lay.addWidget(self.value)
        lay.addWidget(self.label)

    def set_score(self, score: Optional[int], etiqueta: str) -> None:
        if score is None:
            self.value.setText("—")
            self.label.setText("calculando…")
            return
        color = COLORS["ok"] if score >= 85 else COLORS["warn"] if score >= 60 else COLORS["danger"]
        self.value.setText(str(score))
        self.value.setStyleSheet(f"color:{color}; font-size:30px; font-weight:bold;")
        self.label.setText(etiqueta)


def format_bytes(value: int) -> str:
    return f"{value / 1024 ** 3:.1f} GB" if value >= 1024 ** 3 else f"{value / 1024 ** 2:.0f} MB"


def repolish(widget) -> None:
    """Reaplica el QSS tras cambiar el objectName de un widget en caliente."""
    widget.setStyleSheet("")
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def stat_chip(caption: str):
    """Tarjeta compacta: rótulo arriba y valor grande debajo. Devuelve (tarjeta, label-del-valor)."""
    chip = QFrame()
    chip.setObjectName("Chip")
    chip.setMinimumHeight(66)   # evita que el rótulo superior quede recortado por arriba
    lay = QVBoxLayout(chip)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(3)
    cap = QLabel(caption)
    cap.setObjectName("ChipCap")
    val = QLabel("—")
    val.setObjectName("ChipVal")
    lay.addWidget(cap)
    lay.addWidget(val)
    return chip, val


def _emit_event(app, *, source, event_type, payload, observation=None, **extra):
    """
    Publica un Event en el bus de la GUI (que la Caja Negra persiste en eventos.jsonl). No bloquea y
    NUNCA lanza: si el bus/núcleo no está disponible devuelve False sin romper la función que llama.
    """
    bus = getattr(app, "bus", None)
    if bus is None or Event is None:
        return False
    try:
        obs = observation or (ObservationQuality.PARTIAL if ObservationQuality else None)
        bus.publish(Event.create(source=source, host=socket.gethostname(), observation=obs,
                                 event_type=event_type, payload=payload, **extra))
        return True
    except Exception as exc:  # noqa: BLE001
        try:
            app.console.log("x", f"Caja Negra: no se registró el evento: {exc}")
        except Exception:  # noqa: BLE001
            pass
        return False
