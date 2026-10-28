"""
ui/kit.py · LOZARUS KIT TOOL

Piezas comunes de las páginas de SISTEMA Y PERÍMETRO (Escaneo de Vectores, Endurecimiento de Red y
Perímetro, Optimización de Red y Procesos, Arsenal & Modo Fantasma):
  · HeaderStatus  indicador de estado global en tiempo real + privilegios (cabecera fija de la página).
  · Tile          baldosa Bento: icono, título, píldora de estado, descripción y fila de acciones.
  · Inspector     tarjeta de doble columna: inteligencia defensiva | acción directa.
  · SafeActions   privilegios con salto a UAC → confirmación con lo exacto → segundo plano con spinner →
                  cierre trazable (destello del botón, aviso flotante y evento en la Caja Negra).
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional, Sequence, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ui.theme import COLORS, badge_qss
from ui.widgets import _emit_event, flash_aura, icon, set_busy, with_icon
from ui.dialogs import ConfirmDialog
from ui.chrome import Toast

KIND_COLOR = {"*": COLORS["ok"], "!": COLORS["warn"], "x": COLORS["danger"]}


def set_pill(label: QLabel, text: str, color: str, size: int = 10) -> None:
    """Píldora semántica (texto + color); solo re-estiliza si cambia: cada setStyleSheet re-pule el widget."""
    state = (text, color, size)
    if getattr(label, "_lz_pill", None) != state:
        label._lz_pill = state
        label.setText(text)
        label.setStyleSheet(badge_qss(color, size))
    label.setVisible(bool(text))


def action_button(text: str, icon_name: str, kind: str = "Ghost", slot: Optional[Callable] = None,
                  size: int = 14) -> QPushButton:
    """Botón con el lenguaje de la casa: icono qtawesome del color de su variante y cursor de mano."""
    btn = QPushButton(text)
    btn.setObjectName(kind)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    color = {"Danger": COLORS["danger"], "Warn": COLORS["danger"], "Ghost": COLORS["muted"],
             "Mini": COLORS["muted"], "Toggle": COLORS["muted"]}.get(kind)
    with_icon(btn, icon_name, color, size)
    if slot is not None:
        btn.clicked.connect(slot)
    return btn


class HeaderStatus(QWidget):
    """Dos píldoras apiladas a la derecha de la cabecera: estado global y privilegios del proceso."""

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 2, 0, 0)
        lay.setSpacing(6)
        self.state = QLabel()
        self.priv = QLabel()
        for pill in (self.state, self.priv):
            pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(pill, 0, Qt.AlignmentFlag.AlignRight)
        lay.addStretch(1)

    def set_state(self, text: str, color: str, tip: str = "") -> None:
        set_pill(self.state, f"●  {text}", color)
        if self.state.toolTip() != tip:
            self.state.setToolTip(tip)

    def set_admin(self, admin: bool) -> None:
        set_pill(self.priv, "ADMINISTRADOR" if admin else "USUARIO ESTÁNDAR",
                 COLORS["ok"] if admin else COLORS["muted"])
        self.priv.setToolTip("Lozarus se ejecuta elevado: las acciones del sistema se aplican directamente." if admin
                             else "Las acciones que modifican Windows ofrecerán relanzar Lozarus con UAC.")


class Tile(QFrame):
    """
    Baldosa Bento. `level="card"`: tarjeta de primer nivel (#Card: aura y rim light del cuerpo de la
    página). `level="tile"`: baldosa hundida dentro de una tarjeta (#Tile, con su propio rim light).
    `body` admite contenido extra; `footer` es la fila inferior (nota a la izquierda, acciones a la derecha).
    """

    def __init__(self, icon_name: str, title: str, desc: str = "", level: str = "tile"):
        super().__init__()
        card = level == "card"
        self.setObjectName("Card" if card else "Tile")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(*((18, 16, 18, 16) if card else (14, 12, 14, 12)))
        lay.setSpacing(8 if card else 6)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.icon_label = QLabel()
        self.icon_label.setPixmap(icon(icon_name, COLORS["accent"]).pixmap(20 if card else 16, 20 if card else 16))
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.title = QLabel(title)
        self.title.setObjectName("CardTitle" if card else "TileTitle")
        self.title.setWordWrap(True)
        self.pill = QLabel()
        self.pill.setVisible(False)
        top.addWidget(self.icon_label)
        top.addWidget(self.title, 1)
        top.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignTop)
        lay.addLayout(top)
        self.desc = QLabel(desc)
        self.desc.setObjectName("CardText")
        self.desc.setWordWrap(True)
        self.desc.setVisible(bool(desc))
        lay.addWidget(self.desc)
        self.body = QVBoxLayout()
        self.body.setSpacing(6)
        lay.addLayout(self.body)
        lay.addStretch(1)
        self._card = card
        self.footer = QHBoxLayout()
        self.footer.setSpacing(8)
        self.note = QLabel()
        self.note.setObjectName("Tiny")
        self.note.setWordWrap(True)
        self.note.setVisible(not card)  # en la baldosa compacta la nota (aunque vacía) separa los botones
        if card:  # tarjeta: la nota en su propia línea y los botones debajo, alineados a la izquierda
            lay.addWidget(self.note)
            self.footer.addStretch(1)
        else:     # baldosa compacta: nota a la izquierda y botones a la derecha en la misma fila
            self.footer.addWidget(self.note, 1)
        lay.addLayout(self.footer)

    def set_pill(self, text: str, color: str) -> None:
        set_pill(self.pill, text, color)

    def set_note(self, text: str, tip: str = "") -> None:
        if self.note.text() != text:
            self.note.setText(text)
        self.note.setToolTip(tip)
        self.note.setVisible(bool(text) or not self._card)

    def add_action(self, button: QPushButton) -> QPushButton:
        if self._card:
            self.footer.insertWidget(self.footer.count() - 1, button)
        else:
            self.footer.addWidget(button)
        return button


class Inspector(QFrame):
    """
    Tarjeta inferior de dos columnas (oculta hasta seleccionar una fila). Izquierda: inteligencia
    defensiva (estado, contexto, título y hasta FIELDS campos). Derecha: acción directa (mecanismo,
    botones y nota). Los campos se reutilizan: mostrar otro elemento no recrea widgets.
    """
    FIELDS = 4

    def __init__(self, left_caption: str, right_caption: str):
        super().__init__()
        self.setObjectName("Card")
        row = QHBoxLayout(self)
        row.setContentsMargins(20, 16, 20, 16)
        row.setSpacing(20)
        left = QVBoxLayout()
        left.setSpacing(6)
        cap = QLabel(left_caption)
        cap.setObjectName("ChipCap")
        head = QHBoxLayout()
        head.setSpacing(10)
        self.state = QLabel()
        self.context = QLabel()
        self.context.setObjectName("Tiny")
        head.addWidget(self.state)
        head.addWidget(self.context, 1)
        self.title = QLabel()
        self.title.setObjectName("CardTitle")
        self.title.setWordWrap(True)
        self.title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        left.addWidget(cap)
        left.addLayout(head)
        left.addWidget(self.title)
        self._fields: List[Tuple[QLabel, QLabel]] = []
        for _ in range(self.FIELDS):
            fcap, fval = QLabel(), QLabel()
            fcap.setObjectName("FieldCap")
            fval.setObjectName("FieldVal")
            fval.setWordWrap(True)
            fval.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            fcap.setContentsMargins(0, 6, 0, 0)
            left.addWidget(fcap)
            left.addWidget(fval)
            self._fields.append((fcap, fval))
        left.addStretch(1)
        sep = QFrame()
        sep.setObjectName("VSep")
        sep.setFixedWidth(1)
        right = QVBoxLayout()
        right.setSpacing(10)
        rcap = QLabel(right_caption)
        rcap.setObjectName("ChipCap")
        self.mechanism = QLabel()
        self.actions = QVBoxLayout()
        self.actions.setSpacing(8)
        self.note = QLabel()
        self.note.setObjectName("Tiny")
        self.note.setWordWrap(True)
        right.addWidget(rcap)
        right.addWidget(self.mechanism, 0, Qt.AlignmentFlag.AlignLeft)
        right.addLayout(self.actions)
        right.addWidget(self.note)
        right.addStretch(1)
        row.addLayout(left, 3)
        row.addWidget(sep)
        row.addLayout(right, 2)
        self.setVisible(False)

    def show_item(self, state: str, color: str, context: str, title: str,
                  fields: Sequence[Tuple[str, str, bool]], mechanism: str = "", note: str = "") -> None:
        """fields = [(rótulo, texto, monoespaciado)]: los vacíos se ocultan."""
        set_pill(self.state, state, color)
        self.context.setText(context)
        self.title.setText(title)
        shown = [f for f in fields if f[1]][:self.FIELDS]
        for i, (fcap, fval) in enumerate(self._fields):
            if i < len(shown):
                caption, text, mono = shown[i]
                fcap.setText(caption.upper())
                fval.setText(text)
                if fval.objectName() != ("FieldMono" if mono else "FieldVal"):
                    fval.setObjectName("FieldMono" if mono else "FieldVal")
                    fval.style().unpolish(fval)
                    fval.style().polish(fval)
            fcap.setVisible(i < len(shown))
            fval.setVisible(i < len(shown))
        set_pill(self.mechanism, mechanism, COLORS["accent"])
        self.note.setText(note)
        self.note.setVisible(bool(note))
        self.setVisible(True)


class SafeActions:
    """
    Mixin de las páginas que modifican el sistema (requiere self.app = MainWindow). Cada acción sigue el
    mismo orden obligatorio: privilegios → confirmación con lo exacto → segundo plano con spinner →
    resultado trazable. `_busy_changed()` es el gancho para repintar el indicador de estado global.
    """
    _lz_running = 0

    @property
    def running(self) -> int:
        return self._lz_running

    def admin_ok(self, action: str, why: str = "") -> bool:
        """True con privilegios; sin ellos ofrece relanzar elevado (UAC) y devuelve False."""
        if getattr(self.app, "admin", False):
            return True
        self.app.console.log("!", f"{action}: requiere Administrador")
        if ConfirmDialog.ask(self.app, "Se requiere Administrador",
                             f"«{action}» modifica la configuración de Windows y exige privilegios de "
                             "Administrador." + (f"\n\n{why}" if why else "") +
                             "\n\n¿Relanzar Lozarus elevado (UAC)? Esta ventana se cerrará si la elevación "
                             "tiene éxito.", confirm_text="Relanzar como Administrador"):
            self.app.relaunch_as_admin()
        return False

    def confirm_exact(self, title: str, intro: str, lines: Sequence[str], *, footer: str = "",
                      confirm_text: str = "Aplicar", danger: bool = True, limit: int = 10) -> bool:
        """Confirmación obligatoria que muestra los comandos o rutas EXACTOS que se van a ejecutar."""
        lines = list(lines)
        body = intro
        if lines:
            more = f"\n   … y {len(lines) - limit} más" if len(lines) > limit else ""
            body += "\n\nSe ejecutará exactamente:\n" + "\n".join(f"   {ln}" for ln in lines[:limit]) + more
        if footer:
            body += f"\n\n{footer}"
        return ConfirmDialog.ask(self.app, title, body + "\n\n¿Continuar?", confirm_text=confirm_text, danger=danger)

    def run_action(self, button: Optional[QPushButton], busy_text: str, fn: Callable[[Callable], Any],
                   on_done: Callable[[bool, Any], None]) -> None:
        """app.run_task con spinner en el botón; el indicador global cuenta las acciones en curso."""
        if button is not None:
            set_busy(button, True, busy_text)
        self._lz_running += 1
        self._busy_changed()

        def done(ok: bool, payload: Any) -> None:
            self._lz_running = max(0, self._lz_running - 1)
            if button is not None:
                set_busy(button, False)
            self._busy_changed()
            on_done(ok, payload)

        self.app.run_task(fn, done)

    def finish(self, button: Optional[QPushButton], kind: str, title: str, text: str, icon_name: str, *,
               source: str, event_type: str, payload: dict) -> None:
        """Cierre trazable: consola, destello del botón, evento en la Caja Negra y aviso flotante."""
        self.app.console.log(kind if kind in KIND_COLOR else "~", f"{title}: {text}")
        if button is not None:
            flash_aura(button, KIND_COLOR.get(kind, COLORS["accent"]))
        _emit_event(self.app, source=source, event_type=event_type, payload=payload)
        Toast.notify(self.app, kind, title, text, icon_name)

    def _busy_changed(self) -> None:
        """Gancho: la página repinta su estado global (EN CURSO · n)."""
