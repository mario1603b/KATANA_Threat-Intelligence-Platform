###Version Nueva



"""
KATANA v0.8  ·  Threat Intelligence Platform
Sophos Firewall Log Analyzer
─────────────────────────────────────────────
Stack:
  UI       → PyQt6
  Gráficos → pyqtgraph  (nativo Qt, sin backend Agg)
  PDF      → reportlab   (UTF-8 nativo, tablas reales)
  Datos    → pandas
  Mapas    → plotly  (browser)
  DB       → sqlite3  (stdlib, whitelist + historial persistentes)
"""

import sys, os, re, time, json, traceback, webbrowser, warnings, sqlite3
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import numpy as np
import requests
import pandas as pd

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QFileDialog, QMessageBox, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLineEdit, QComboBox,
    QFrame, QHeaderView, QProgressBar, QSplitter, QCheckBox,
    QGroupBox, QAbstractItemView, QSpinBox,
    QDialog, QDialogButtonBox, QTableWidget, QTableWidgetItem,
    QSizePolicy, QMenu
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QCursor, QBrush, QAction, QPainter, QFont

import pyqtgraph as pg

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ─────────────────────────────────────────────────────────────────────────────
#  BASE DE DATOS  (whitelist + historial persistentes vía sqlite3)
# ─────────────────────────────────────────────────────────────────────────────
DB_PATH = Path.home() / ".katana_0.8.db"

def _init_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY
        )""")
    con.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT,
            filename TEXT,
            n_ips    INTEGER,
            n_events INTEGER,
            n_ctrs   INTEGER
        )""")
    con.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip      TEXT PRIMARY KEY,
            country TEXT,
            lat     REAL,
            lon     REAL,
            ts      INTEGER DEFAULT (strftime('%s','now'))
        )""")
    con.commit()
    return con

_DB = _init_db()

def db_whitelist_load():
    return {r[0] for r in _DB.execute("SELECT ip FROM whitelist")}

def db_whitelist_save(ips: set):
    _DB.execute("DELETE FROM whitelist")
    _DB.executemany("INSERT INTO whitelist VALUES (?)", [(ip,) for ip in ips])
    _DB.commit()

def db_history_add(ts, filename, n_ips, n_events, n_ctrs):
    _DB.execute("INSERT INTO history (ts,filename,n_ips,n_events,n_ctrs) VALUES (?,?,?,?,?)",
                (ts, filename, n_ips, n_events, n_ctrs))
    _DB.commit()

def db_history_load():
    return _DB.execute(
        "SELECT ts,filename,n_ips,n_events,n_ctrs FROM history ORDER BY id DESC LIMIT 200"
    ).fetchall()

def db_history_clear():
    _DB.execute("DELETE FROM history"); _DB.commit()

# ── Geo cache  ────────────────────────────────────────────────────────────────
# TTL: 30 días (IPs raramente cambian de país antes de eso)
_GEO_TTL = 30 * 86400

def db_geo_load(ips: list) -> dict:
    """Devuelve {ip: (country, lat, lon)} para las IPs que están en caché y no han expirado."""
    if not ips:
        return {}
    now = int(time.time())
    placeholders = ",".join("?" * len(ips))
    rows = _DB.execute(
        f"SELECT ip,country,lat,lon,ts FROM geo_cache WHERE ip IN ({placeholders})",
        ips
    ).fetchall()
    return {r[0]: (r[1], r[2], r[3])
            for r in rows if (now - r[4]) < _GEO_TTL}

def db_geo_save(results: dict):
    """Guarda {ip: (country, lat, lon)} en caché. Thread-safe con lock."""
    now = int(time.time())
    con = sqlite3.connect(DB_PATH)   # conexión propia para el thread worker
    con.executemany(
        "INSERT OR REPLACE INTO geo_cache (ip,country,lat,lon,ts) VALUES (?,?,?,?,?)",
        [(ip, v[0], v[1], v[2], now) for ip, v in results.items()]
    )
    con.commit(); con.close()

# ─────────────────────────────────────────────────────────────────────────────
#  TEMA  (macOS-style dark / warm light)
# ─────────────────────────────────────────────────────────────────────────────
MONO = "'JetBrains Mono','IBM Plex Mono','Consolas','Courier New',monospace"
SANS = "'Poppins','Segoe UI','Helvetica Neue',sans-serif"

THEMES = {
    "dark": {
        "BG":       "#1C1C1E", "SURFACE":  "#2C2C2E", "SURFACE2": "#3A3A3C",
        "BORDER":   "#3A3A3C", "BORDER2":  "#48484A",
        "INK":      "#F2F2F7", "INK2":     "#AEAEB2", "INK_DIM":  "#636366",
        "ACCENT":   "#0A84FF", "ACCENT_D": "#0060CC",
        "DANGER":   "#FF453A", "SUCCESS":  "#30D158", "WARN":     "#FF9F0A",
        "S_CRIT":   "#FF453A", "S_HIGH":   "#FF9F0A",
        "S_MED":    "#0A84FF", "S_LOW":    "#30D158",
        "CON_BG":   "#161618", "CON_FG":   "#7AE47A",
    },
    "light": {
        "BG":       "#F0EFEB", "SURFACE":  "#FAFAF8", "SURFACE2": "#EEECEA",
        "BORDER":   "#D8D6D0", "BORDER2":  "#C2C0BA",
        "INK":      "#1C1C1E", "INK2":     "#4A4A50", "INK_DIM":  "#8E8E93",
        "ACCENT":   "#007AFF", "ACCENT_D": "#005EC4",
        "DANGER":   "#C0392B", "SUCCESS":  "#1A7A42", "WARN":     "#C06010",
        "S_CRIT":   "#C0392B", "S_HIGH":   "#C06010",
        "S_MED":    "#007AFF", "S_LOW":    "#1A7A42",
        "CON_BG":   "#1C1C1E", "CON_FG":   "#5EDB5E",
    },
}

_T    = THEMES["dark"]
ACCENT = _T["ACCENT"]
WARN   = _T["WARN"]
SEV_COLOR = {}

def T(k): return _T[k]

def _update_globals():
    global _T, ACCENT, WARN, SEV_COLOR
    ACCENT = _T["ACCENT"]; WARN = _T["WARN"]
    SEV_COLOR = {
        "CRITICAL": _T["S_CRIT"], "HIGH": _T["S_HIGH"],
        "MEDIUM":   _T["S_MED"],  "LOW":  _T["S_LOW"],
    }

_update_globals()


def _build_qss() -> str:
    t = _T
    return f"""
/* ── Base ── */
* {{ font-family:{SANS}; font-size:12px; color:{t['INK']}; outline:none; }}
QMainWindow,QDialog {{ background:{t['BG']}; }}
QWidget {{ background:transparent; color:{t['INK']}; }}

/* ── Estructuras ── */
#sidebar  {{ background:{t['SURFACE']}; border-right:1px solid {t['BORDER']}; }}
#topbar   {{ background:{t['SURFACE']}; border-bottom:1px solid {t['BORDER']}; }}
#card     {{ background:{t['SURFACE']}; border:1px solid {t['BORDER']}; border-radius:6px; }}

/* ── Botones base ── */
QPushButton {{
    background:{t['SURFACE2']}; color:{t['INK2']};
    border:1px solid {t['BORDER2']}; border-radius:5px;
    padding:6px 14px; font-size:11px; font-weight:500;
}}
QPushButton:hover   {{ background:{t['BORDER2']}; color:{t['INK']}; }}
QPushButton:pressed {{ background:{t['BORDER']}; }}
QPushButton:disabled {{ color:{t['INK_DIM']}; border-color:{t['BORDER']}; background:{t['SURFACE']}; }}

/* Primary — máximo énfasis */
QPushButton#primary {{
    background:{t['ACCENT']}; color:white; border:none;
    font-weight:700; font-size:12px; letter-spacing:0.3px;
}}
QPushButton#primary:hover    {{ background:{t['ACCENT_D']}; }}
QPushButton#primary:disabled {{ background:{t['BORDER2']}; color:{t['INK_DIM']}; }}

/* Ghost */
QPushButton#ghost {{
    background:transparent; border:none;
    color:{t['INK_DIM']}; padding:4px 8px; font-size:11px; font-weight:400;
}}
QPushButton#ghost:hover {{ color:{t['ACCENT']}; background:{t['ACCENT']}18; }}

/* Danger */
QPushButton#danger {{
    background:{t['DANGER']}12; color:{t['DANGER']};
    border:1px solid {t['DANGER']}44; border-radius:5px;
    font-weight:600; font-size:11px;
}}
QPushButton#danger:hover    {{ background:{t['DANGER']}22; border-color:{t['DANGER']}; }}
QPushButton#danger:disabled {{ color:{t['INK_DIM']}; border-color:{t['BORDER']}; background:transparent; }}

/* Success */
QPushButton#success {{
    background:{t['SUCCESS']}12; color:{t['SUCCESS']};
    border:1px solid {t['SUCCESS']}44; border-radius:5px;
    font-weight:600; font-size:11px;
}}
QPushButton#success:hover    {{ background:{t['SUCCESS']}22; border-color:{t['SUCCESS']}; }}
QPushButton#success:disabled {{ color:{t['INK_DIM']}; border-color:{t['BORDER']}; background:transparent; }}

/* Theme toggle */
QPushButton#theme_btn {{
    background:{t['SURFACE2']}; border:1px solid {t['BORDER2']};
    color:{t['INK2']}; padding:3px 10px; border-radius:10px;
    font-size:10px; font-weight:500;
}}
QPushButton#theme_btn:hover {{ color:{t['INK']}; background:{t['BORDER2']}; }}

/* ── Tabs ── */
QTabWidget::pane {{
    background:{t['SURFACE']}; border:1px solid {t['BORDER']};
    border-top:none; border-radius:0 0 6px 6px;
}}
QTabBar {{ background:{t['BG']}; }}
QTabBar::tab {{
    background:transparent; color:{t['INK_DIM']};
    padding:8px 20px; border:none;
    border-bottom:2px solid transparent;
    font-size:11px; font-weight:500;
}}
QTabBar::tab:selected {{
    color:{t['INK']}; border-bottom:2px solid {t['ACCENT']};
    font-weight:700;
}}
QTabBar::tab:hover:!selected {{
    color:{t['INK2']}; border-bottom:2px solid {t['BORDER2']};
}}

/* ── Árbol IP y tablas — datos mono, peso suave ── */
QTreeWidget,QTableWidget {{
    background:{t['SURFACE']}; color:{t['INK2']};
    border:none; alternate-background-color:{t['BG']};
    gridline-color:{t['BORDER']};
    font-family:{MONO}; font-size:11px; font-weight:400;
    selection-background-color:{t['ACCENT']}28; selection-color:{t['INK']};
}}
QTreeWidget::item,QTableWidget::item {{
    padding:5px 10px; border-bottom:1px solid {t['BORDER']};
    color:{t['INK2']};
}}
QTreeWidget::item:selected,QTableWidget::item:selected {{
    background:{t['ACCENT']}28; color:{t['INK']};
    border-left:2px solid {t['ACCENT']}; font-weight:500;
}}
QTreeWidget::item:hover:!selected,QTableWidget::item:hover:!selected {{
    background:{t['SURFACE2']};
}}
QHeaderView {{ background:{t['BG']}; }}
QHeaderView::section {{
    background:{t['BG']}; color:{t['INK_DIM']};
    border:none; border-bottom:1px solid {t['BORDER2']};
    border-right:1px solid {t['BORDER']};
    padding:6px 10px; font-size:9px; font-weight:700;
    letter-spacing:1px;
}}

/* ── Inputs ── */
QLineEdit {{
    background:{t['BG']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; border-radius:5px;
    padding:6px 10px; font-weight:400;
    selection-background-color:{t['ACCENT']}44;
}}
QLineEdit:focus   {{ border-color:{t['ACCENT']}; background:{t['SURFACE']}; }}
QLineEdit:disabled {{ color:{t['INK_DIM']}; }}

QComboBox {{
    background:{t['BG']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; border-radius:5px;
    padding:5px 10px; min-width:100px; font-weight:400;
}}
QComboBox:focus {{ border-color:{t['ACCENT']}; }}
QComboBox::drop-down {{ border:none; width:18px; }}
QComboBox QAbstractItemView {{
    background:{t['SURFACE']}; color:{t['INK']};
    border:1px solid {t['BORDER2']};
    selection-background-color:{t['ACCENT']}28; selection-color:{t['INK']};
    font-weight:400;
}}

QTextEdit {{
    background:{t['SURFACE']}; color:{t['INK']};
    border:1px solid {t['BORDER']}; border-radius:5px;
    padding:6px; font-weight:400;
}}
QTextEdit#console {{
    background:{t['CON_BG']}; color:{t['CON_FG']};
    border:none; border-radius:5px;
    font-family:{MONO}; font-size:11px; padding:10px;
}}

/* ── Checkboxes ── */
QCheckBox {{ color:{t['INK2']}; spacing:6px; font-size:11px; font-weight:400; }}
QCheckBox::indicator {{
    width:14px; height:14px; background:{t['BG']};
    border:1.5px solid {t['BORDER2']}; border-radius:3px;
}}
QCheckBox::indicator:checked {{ background:{t['ACCENT']}; border-color:{t['ACCENT']}; }}

/* ── Progress ── */
QProgressBar {{
    background:{t['BORDER']}; border:none; border-radius:1px;
    height:2px; color:transparent;
}}
QProgressBar::chunk {{ background:{t['ACCENT']}; border-radius:1px; }}

/* ── Scrollbars ── */
QScrollBar:vertical {{ background:transparent; width:6px; border:none; }}
QScrollBar::handle:vertical {{ background:{t['BORDER2']}; border-radius:3px; min-height:24px; }}
QScrollBar::handle:vertical:hover {{ background:{t['INK_DIM']}; }}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{ background:transparent; height:6px; border:none; }}
QScrollBar::handle:horizontal {{ background:{t['BORDER2']}; border-radius:3px; }}
QScrollBar::handle:horizontal:hover {{ background:{t['INK_DIM']}; }}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {{ width:0; }}

QFrame[frameShape="4"],QFrame[frameShape="5"] {{
    color:{t['BORDER']}; background:{t['BORDER']}; max-height:1px; border:none;
}}

/* ── SpinBox ── */
QSpinBox {{
    background:{t['BG']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; border-radius:5px;
    padding:5px 8px; font-weight:400;
}}
QSpinBox:focus {{ border-color:{t['ACCENT']}; }}
QSpinBox::up-button,QSpinBox::down-button {{ width:0; }}

/* ── GroupBox ── */
QGroupBox {{
    color:{t['INK_DIM']}; border:1px solid {t['BORDER']};
    border-radius:6px; margin-top:14px; padding-top:12px;
    font-size:10px; font-weight:700; letter-spacing:0.8px;
    background:{t['SURFACE']};
}}
QGroupBox::title {{
    subcontrol-origin:margin; left:12px; padding:0 6px;
    color:{t['INK_DIM']}; background:{t['SURFACE']};
}}

/* ── Menús — bold, bien diferenciados ── */
QMenu {{
    background:{t['SURFACE']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; padding:4px; border-radius:8px;
}}
QMenu::item {{
    padding:7px 20px; font-size:12px; font-weight:600;
    border-radius:4px; color:{t['INK']};
}}
QMenu::item:selected {{
    background:{t['ACCENT']}28; color:{t['INK']};
    font-weight:700;
}}
QMenu::separator {{ height:1px; background:{t['BORDER']}; margin:4px 8px; }}

/* ── Mensajes ── */
QMessageBox {{ background:{t['SURFACE']}; }}
QMessageBox QLabel {{ color:{t['INK']}; font-size:12px; font-weight:500; background:transparent; }}
QMessageBox QPushButton {{ min-width:80px; font-weight:600; }}

QLabel#lbl_dim {{ color:{t['INK_DIM']}; font-weight:400; }}
QToolTip {{
    background:{t['SURFACE2']}; color:{t['INK']};
    border:1px solid {t['BORDER2']}; padding:4px 8px;
    border-radius:4px; font-size:11px; font-weight:500;
}}
"""


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS UI
# ─────────────────────────────────────────────────────────────────────────────
def sep(vertical=False):
    f = QFrame()
    f.setFrameShape(QFrame.Shape.VLine if vertical else QFrame.Shape.HLine)
    f.setFixedWidth(1) if vertical else f.setFixedHeight(1)
    return f

def lbl(text, size=12, color=None, bold=False, mono=False, dim=False):
    l = QLabel(text)
    family = MONO if mono else SANS
    weight = "600" if bold else "400"
    style  = f"font-family:{family};font-size:{size}px;font-weight:{weight};background:transparent;"
    if color:
        style += f"color:{color};"
        l.setStyleSheet(style)
    elif dim:
        l.setObjectName("lbl_dim")
        l.setStyleSheet(style)
    else:
        l.setStyleSheet(style)
    return l

def spacer(h=None, v=None):
    w = QWidget()
    if h: w.setFixedWidth(h)
    if v: w.setFixedHeight(v)
    w.setSizePolicy(
        QSizePolicy.Policy.Expanding if not h else QSizePolicy.Policy.Fixed,
        QSizePolicy.Policy.Expanding if not v else QSizePolicy.Policy.Fixed,
    )
    return w


# ─────────────────────────────────────────────────────────────────────────────
#  PYQTGRAPH HELPERS  — crea PlotWidgets con tema activo
# ─────────────────────────────────────────────────────────────────────────────
def _pg_bar(x_labels, values, color_first=None, title="") -> pg.PlotWidget:
    """Gráfico de barras horizontal usando pyqtgraph."""
    surf = _T["SURFACE"]; ink2 = _T["INK2"]; brd  = _T["BORDER"]
    acc  = color_first or _T["ACCENT"]; brd2 = _T["BORDER2"]

    pw = pg.PlotWidget()
    pw.setBackground(surf)
    pw.showGrid(x=True, y=False, alpha=0.15)
    pw.getAxis('bottom').setPen(pg.mkPen(brd))
    pw.getAxis('left').setPen(pg.mkPen(brd))
    pw.getAxis('left').setTextPen(pg.mkPen(ink2))
    pw.getAxis('bottom').setTextPen(pg.mkPen(ink2))
    if title:
        pw.setTitle(title, color=ink2, size="10pt")

    n = len(values)
    colors = [acc] + [brd2] * (n - 1)
    for i, (v, c) in enumerate(zip(values, colors)):
        bar = pg.BarGraphItem(x=[i], height=[v], width=0.6,
                              brush=pg.mkBrush(c), pen=pg.mkPen(None))
        pw.addItem(bar)

    ticks = [(i, str(x_labels[i])[:16]) for i in range(n)]
    pw.getAxis('bottom').setTicks([ticks])
    pw.getAxis('bottom').setStyle(tickTextOffset=4)
    pw.setMouseEnabled(x=False, y=False)
    pw.getViewBox().setDefaultPadding(0.05)
    return pw


def _pg_hbar(labels, values, color_first=None) -> pg.PlotWidget:
    """Gráfico de barras vertical (para usuarios)."""
    surf = _T["SURFACE"]; ink2 = _T["INK2"]; brd  = _T["BORDER"]
    wrn  = color_first or _T["WARN"]; brd2 = _T["BORDER2"]

    pw = pg.PlotWidget()
    pw.setBackground(surf)
    pw.showGrid(x=True, y=False, alpha=0.15)
    pw.getAxis('bottom').setPen(pg.mkPen(brd))
    pw.getAxis('left').setPen(pg.mkPen(brd))
    pw.getAxis('left').setTextPen(pg.mkPen(ink2))
    pw.getAxis('bottom').setTextPen(pg.mkPen(ink2))

    n = len(values)
    colors = [wrn] + [brd2] * (n - 1)
    for i, (v, c) in enumerate(zip(values, colors)):
        bar = pg.BarGraphItem(x=[i], height=[v], width=0.6,
                              brush=pg.mkBrush(c), pen=pg.mkPen(None))
        pw.addItem(bar)

    ticks = [(i, str(labels[i])[:18]) for i in range(n)]
    pw.getAxis('bottom').setTicks([ticks])
    pw.setMouseEnabled(x=False, y=False)
    return pw


def _pg_line(x_vals, y_vals) -> pg.PlotWidget:
    """Gráfico de línea para timeline."""
    surf = _T["SURFACE"]; ink2 = _T["INK2"]; brd = _T["BORDER"]
    acc  = _T["ACCENT"]; dng  = _T["DANGER"]

    pw = pg.PlotWidget()
    pw.setBackground(surf)
    pw.showGrid(x=False, y=True, alpha=0.15)
    pw.getAxis('bottom').setPen(pg.mkPen(brd))
    pw.getAxis('left').setPen(pg.mkPen(brd))
    pw.getAxis('left').setTextPen(pg.mkPen(ink2))
    pw.getAxis('bottom').setTextPen(pg.mkPen(ink2))

    xs = list(range(len(y_vals)))
    # fill bajo la curva
    fill = pg.FillBetweenItem(
        pg.PlotDataItem(xs, y_vals, pen=pg.mkPen(acc, width=1.5)),
        pg.PlotDataItem(xs, [0] * len(xs), pen=pg.mkPen(None)),
        brush=pg.mkBrush(acc + "22")
    )
    pw.addItem(fill)
    pw.plot(xs, y_vals, pen=pg.mkPen(acc, width=1.5),
            symbol='o', symbolSize=5,
            symbolBrush=pg.mkBrush(dng), symbolPen=pg.mkPen(None))

    n = max(1, len(xs) // 10)
    ticks = [(xs[i], str(x_vals[i])[:12]) for i in range(0, len(xs), n)]
    pw.getAxis('bottom').setTicks([ticks])
    pw.setMouseEnabled(x=False, y=False)
    return pw

def _pg_donut(labels, values) -> pg.PlotWidget:
    """
    Gráfico de donut con sectores dibujados como anillos mediante QGraphicsEllipseItem.
    Texto en Poppins Bold.
    """
    from PyQt6.QtWidgets import QGraphicsEllipseItem
    from PyQt6.QtGui import QFont

    surf = _T["SURFACE"]
    pw = pg.PlotWidget()
    pw.setBackground(surf)
    pw.hideAxis('bottom')
    pw.hideAxis('left')
    pw.setAspectLocked(True)
    pw.setMouseEnabled(x=False, y=False)

    total = sum(values) or 1
    start_angle = 90  # Comenzar desde arriba (las 12 en punto)

    # Radios
    R_OUT = 1.0
    R_IN = 0.6

    for label, value in zip(labels, values):
        span = value / total * 360.0

        # Convertir a 1/16 de grado (Qt requiere esto)
        start_16 = int(start_angle * 16)
        span_16 = int(-span * 16)  # negativo para sentido horario

        # --- Sector exterior (el anillo de color) ---
        outer_ellipse = QGraphicsEllipseItem(-R_OUT, -R_OUT, 2*R_OUT, 2*R_OUT)
        outer_ellipse.setStartAngle(start_16)
        outer_ellipse.setSpanAngle(span_16)
        outer_ellipse.setPen(pg.mkPen(None))
        color = SEV_COLOR.get(label, _T["INK_DIM"])
        outer_ellipse.setBrush(pg.mkBrush(color))
        pw.addItem(outer_ellipse)

        # --- Sector interior (para recortar el centro y crear el agujero) ---
        inner_ellipse = QGraphicsEllipseItem(-R_IN, -R_IN, 2*R_IN, 2*R_IN)
        inner_ellipse.setStartAngle(start_16)
        inner_ellipse.setSpanAngle(span_16)
        inner_ellipse.setPen(pg.mkPen(None))
        inner_ellipse.setBrush(pg.mkBrush(surf))  # Mismo color que el fondo
        pw.addItem(inner_ellipse)

        # --- Texto: etiqueta y porcentaje ---
        # Calcular el ángulo medio del sector (en radianes)
        mid_angle_deg = start_angle - span / 2
        mid_angle_rad = np.radians(mid_angle_deg)

        # Posición a mitad del anillo (radio promedio)
        r_mid = (R_OUT + R_IN) / 2
        x = r_mid * np.cos(mid_angle_rad)
        y = r_mid * np.sin(mid_angle_rad)

        pct = f"{value/total*100:.0f}%"
        display_text = f"{label}\n{pct}"

        text_item = pg.TextItem(display_text, anchor=(0.5, 0.5), color=_T["INK2"])

        # Forzar Poppins Bold (o la sans-serif bold más cercana)
        font = QFont("Poppins, Segoe UI, Helvetica Neue, sans-serif", 8)
        font.setBold(True)
        text_item.setFont(font)

        text_item.setPos(x, y)
        pw.addItem(text_item)

        # Actualizar ángulo de inicio para el siguiente sector
        start_angle -= span

    return pw

# ─────────────────────────────────────────────────────────────────────────────
#  PDF  (reportlab — UTF-8 nativo, sin hackear latin-1)
# ─────────────────────────────────────────────────────────────────────────────
def _build_pdf(df: pd.DataFrame, df_mapa, path: str):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        raise RuntimeError(
            "reportlab no instalado.\nEjecuta:  pip install reportlab"
        )

    BLUE   = rl_colors.HexColor("#0A84FF")
    GRAY   = rl_colors.HexColor("#8E8E93")
    DARK   = rl_colors.HexColor("#1C1C1E")
    RED    = rl_colors.HexColor("#FF453A")
    ORANGE = rl_colors.HexColor("#FF9F0A")
    GREEN  = rl_colors.HexColor("#30D158")
    WHITE  = rl_colors.white
    LTGRAY = rl_colors.HexColor("#F0EFEB")

    sev_color = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": BLUE, "LOW": GREEN}

    doc  = SimpleDocTemplate(path, pagesize=A4,
                             leftMargin=2*cm, rightMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)
    ss   = getSampleStyleSheet()
    body = []

    h1 = ParagraphStyle("h1", parent=ss["Normal"], fontSize=22, textColor=BLUE,
                         alignment=TA_CENTER, fontName="Helvetica-Bold", spaceAfter=4)
    sub = ParagraphStyle("sub", parent=ss["Normal"], fontSize=9, textColor=GRAY,
                          alignment=TA_CENTER, spaceAfter=12)
    sec = ParagraphStyle("sec", parent=ss["Normal"], fontSize=12, textColor=DARK,
                          fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4)
    kv  = ParagraphStyle("kv", parent=ss["Normal"], fontSize=11,
                          textColor=DARK, spaceAfter=3)

    # ── Header ────────────────────────────────────────────────────────────
    body.append(Paragraph("KATANA v0.8 — Executive Forensic Report", h1))
    body.append(Paragraph(
        f"Generated {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}"
        f"  |  {len(df):,} events analyzed", sub))
    body.append(HRFlowable(width="100%", color=GRAY, thickness=0.5, spaceAfter=10))

    # ── 1. Summary ────────────────────────────────────────────────────────
    body.append(Paragraph("1.  INCIDENT SUMMARY", sec))
    crit = (df[df["Severidad"] == "CRITICAL"]["IP_Atacante"].nunique()
            if "Severidad" in df.columns else "N/A")
    for k, v in [("Total events",         f"{len(df):,}"),
                 ("Unique attacker IPs",   f"{df['IP_Atacante'].nunique():,}"),
                 ("Countries of origin",   f"{df['Pais'].nunique():,}"),
                 ("CRITICAL severity IPs", str(crit))]:
        body.append(Paragraph(f"<b>{k}:</b>  {v}", kv))
    body.append(Spacer(1, 10))

    # ── 2. Top countries ──────────────────────────────────────────────────
    body.append(Paragraph("2.  TOP 10 ATTACK ORIGINS", sec))
    total_ev = len(df)
    tdata = [["COUNTRY", "EVENTS", "% TOTAL"]]
    for c, n in df["Pais"].value_counts().head(10).items():
        tdata.append([str(c), f"{n:,}", f"{n/total_ev*100:.1f}%"])
    tbl = Table(tdata, colWidths=[9*cm, 4*cm, 4*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [LTGRAY, WHITE]),
        ("GRID",        (0,0), (-1,-1), 0.25, GRAY),
        ("ALIGN",       (1,0), (-1,-1), "CENTER"),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
    ]))
    body.append(tbl)
    body.append(Spacer(1, 10))

    # ── 3. Top IPs ────────────────────────────────────────────────────────
    body.append(Paragraph("3.  TOP 15 IPs FOR BLACKLISTING", sec))
    top = df.groupby(["IP_Atacante", "Pais"]).size().reset_index(name="N")
    if "Severidad" in df.columns:
        sm = (df[["IP_Atacante", "Severidad"]]
              .drop_duplicates()
              .set_index("IP_Atacante")["Severidad"])
        top["S"] = top["IP_Atacante"].map(sm).fillna("LOW")
    else:
        top["S"] = "LOW"
    top = top.sort_values("N", ascending=False).head(15)

    tdata2 = [["IP ADDRESS", "COUNTRY", "EVENTS", "SEVERITY"]]
    for _, r in top.iterrows():
        tdata2.append([str(r["IP_Atacante"]), str(r["Pais"])[:22],
                       str(r["N"]), str(r["S"])])
    tbl2 = Table(tdata2, colWidths=[5*cm, 6*cm, 3*cm, 3*cm])
    row_styles = [
        ("BACKGROUND",  (0,0), (-1,0), DARK),
        ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("GRID",        (0,0), (-1,-1), 0.25, GRAY),
        ("ALIGN",       (2,0), (-1,-1), "CENTER"),
        ("TOPPADDING",  (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
    ]
    for i, (_, r) in enumerate(top.iterrows(), 1):
        c = sev_color.get(str(r["S"]), GRAY)
        row_styles.append(("TEXTCOLOR", (3, i), (3, i), c))
        row_styles.append(("FONTNAME",  (3, i), (3, i), "Helvetica-Bold"))
    tbl2.setStyle(TableStyle(row_styles))
    body.append(tbl2)
    body.append(Spacer(1, 10))

    # ── 4. Users ──────────────────────────────────────────────────────────
    if "Usuario" in df.columns:
        uu = (df[~df["Usuario"].isin(["—", "-", "", "nan"])]
              ["Usuario"].value_counts().head(10))
        if not uu.empty:
            body.append(Paragraph("4.  TARGETED ACCOUNTS (BRUTE FORCE)", sec))
            tdata3 = [["USERNAME", "ATTEMPTS"]]
            for u, n in uu.items():
                tdata3.append([str(u), str(n)])
            tbl3 = Table(tdata3, colWidths=[12*cm, 5*cm])
            tbl3.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,0), ORANGE),
                ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
                ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 9),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [LTGRAY, WHITE]),
                ("GRID",        (0,0), (-1,-1), 0.25, GRAY),
                ("ALIGN",       (1,0), (-1,-1), "CENTER"),
                ("TOPPADDING",  (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ]))
            body.append(tbl3)

    doc.build(body)


# ─────────────────────────────────────────────────────────────────────────────
#  WORKERS
# ─────────────────────────────────────────────────────────────────────────────
class AnalysisWorker(QThread):
    progress = pyqtSignal(str)
    log      = pyqtSignal(str)
    finished = pyqtSignal(object, object, int, int)
    error    = pyqtSignal(str)

    def __init__(self, filepath: str, whitelist: list):
        super().__init__()
        self.filepath  = filepath
        self.whitelist = set(whitelist)

    def run(self):
        try:
            t0 = time.perf_counter()
            self.log.emit(f"Loading  {os.path.basename(self.filepath)}")

            # ── 1. Leer CSV ──────────────────────────────────────────────────
            # Intentar con sniffing automático; fallback a coma explícita
            try:
                df = pd.read_csv(self.filepath, sep=None, engine="python",
                                 low_memory=False)
            except Exception:
                df = pd.read_csv(self.filepath, sep=",", low_memory=False)

            self.log.emit(f"{len(df):,} rows  ·  {len(df.columns)} columns")
            df.columns = df.columns.str.strip()

            # ── 2. Extraer IP ────────────────────────────────────────────────
            ip_col = next((c for c in df.columns
                           if re.search(r"src|source|attacker|client|remote", c, re.I)), None)
            if ip_col:
                self.log.emit(f"IP column → '{ip_col}'")
                df["IP_Atacante"] = (df[ip_col].astype(str)
                                     .str.extract(r"\b((?:\d{1,3}\.){3}\d{1,3})\b"))
            else:
                # Construir _row solo cuando no hay columna dedicada, y con
                # str join vectorizado (más rápido que apply en filas grandes)
                self.log.emit("No IP column found — scanning all columns")
                df["_row"] = df.fillna("").astype(str).apply(" ".join, axis=1)
                df["IP_Atacante"] = df["_row"].str.extract(
                    r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

            df_ips = df.dropna(subset=["IP_Atacante"]).copy()

            # ── 3. Filtrar IPs privadas y whitelist ──────────────────────────
            priv = re.compile(
                r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0)")
            mask_pub = ~df_ips["IP_Atacante"].str.match(priv)
            df_ips = df_ips[mask_pub]
            if self.whitelist:
                df_ips = df_ips[~df_ips["IP_Atacante"].isin(self.whitelist)]
            if df_ips.empty:
                self.error.emit("No external attacker IPs found."); return

            # ── 4. Usuario  ──────────────────────────────────────────────────
            if "Username" in df_ips.columns:
                df_ips["Usuario"] = df_ips["Username"].astype(str)
            elif "_row" in df_ips.columns:
                df_ips["Usuario"] = df_ips["_row"].str.extract(
                    r"User\s+([^\s]+)\s+failed\s+to\s+login", flags=re.I)
            else:
                df_ips["Usuario"] = pd.NA
            df_ips["Usuario"] = (df_ips["Usuario"].fillna("—")
                                 .replace({"": "—", "nan": "—", "N/A": "—"}))

            # ── 5. Puerto  ───────────────────────────────────────────────────
            pc = next((c for c in df_ips.columns
                       if re.search(r"dst.?port|dport|dest.?port", c, re.I)), None)
            if pc:
                df_ips["Puerto"] = df_ips[pc].astype(str)
            elif "_row" in df_ips.columns:
                df_ips["Puerto"] = df_ips["_row"].str.extract(
                    r"(?:dst|dport)[\s:=]+(\d{1,5})", flags=re.I)
            else:
                df_ips["Puerto"] = "—"
            df_ips["Puerto"] = df_ips["Puerto"].fillna("—")

            # ── 6. Timestamp  ────────────────────────────────────────────────
            tc = next((c for c in df_ips.columns
                       if re.search(r"^(time|date|timestamp|fecha)$", c, re.I)), None)
            df_ips["Timestamp"] = (pd.to_datetime(df_ips[tc], errors="coerce")
                                   if tc else pd.NaT)

            # ── 7. Severidad vectorizada  ────────────────────────────────────
            # np.select es ~10x más rápido que map(lambda) fila a fila
            cnt    = df_ips["IP_Atacante"].value_counts()
            mx     = cnt.max() or 1
            ratios = df_ips["IP_Atacante"].map(cnt) / mx
            df_ips["Severidad"] = np.select(
                [ratios > 0.5, ratios > 0.25, ratios > 0.1],
                ["CRITICAL",   "HIGH",        "MEDIUM"],
                default="LOW"
            )

            # ── 8. Geolocalización con caché + paralelismo  ──────────────────
            ips_u = df_ips["IP_Atacante"].unique().tolist()
            total = len(ips_u)
            self.log.emit(f"Geolocating {total:,} unique IPs")

            # Cargar lo que ya está en caché
            cached  = db_geo_load(ips_u)
            missing = [ip for ip in ips_u if ip not in cached]

            if cached:
                self.log.emit(f"  {len(cached):,} IPs from cache — "
                              f"{len(missing):,} need lookup")

            geo_results: dict = dict(cached)   # {ip: (country, lat, lon)}

            if missing:
                # Dividir en batches de 45 (límite ip-api free tier)
                batches = [missing[i:i+45] for i in range(0, len(missing), 45)]
                done    = [0]

                def _fetch_batch(batch: list) -> dict:
                    """Hace la llamada a ip-api y devuelve {ip: (country,lat,lon)}."""
                    for attempt in range(3):
                        try:
                            r = requests.post(
                                "http://ip-api.com/batch",
                                json=[{"query": ip,
                                       "fields": "query,country,lat,lon,status"}
                                      for ip in batch],
                                timeout=15)
                            if r.status_code == 429:
                                time.sleep(65); continue
                            if r.status_code == 200:
                                result = {}
                                for d in r.json():
                                    ip = d.get("query", "")
                                    if d.get("status") == "success":
                                        result[ip] = (d["country"],
                                                      d.get("lat", 0.0),
                                                      d.get("lon", 0.0))
                                    else:
                                        result[ip] = ("Unknown", 0.0, 0.0)
                                db_geo_save(result)   # persistir en caché
                                return result
                        except Exception:
                            time.sleep(2)
                    return {ip: ("Error", 0.0, 0.0) for ip in batch}

                # ip-api free tier: ~45 req/min en batch → un thread + sleep entre batches
                # Con caché la mayoría de ejecuciones son mucho más rápidas
                # Usamos 2 workers: el rate limit es por IP cliente, no por conexión
                # pero mantenemos ≤1 req/s para ser conservadores
                n_workers = min(2, len(batches))
                completed = 0
                with ThreadPoolExecutor(max_workers=n_workers) as pool:
                    futures = {}
                    for idx, batch in enumerate(batches):
                        # Pequeña separación entre lanzamientos para no saturar
                        if idx > 0:
                            time.sleep(0.7)
                        futures[pool.submit(_fetch_batch, batch)] = batch

                    for fut in as_completed(futures):
                        batch_result = fut.result()
                        geo_results.update(batch_result)
                        completed += len(futures[fut])
                        self.progress.emit(
                            f"Geolocating  {min(completed, len(missing))}/{len(missing)}")

            # Mapear resultados al DataFrame
            df_ips["Pais"] = df_ips["IP_Atacante"].map(
                lambda ip: geo_results.get(ip, ("Unknown", 0.0, 0.0))[0])
            df_ips["Lat"]  = df_ips["IP_Atacante"].map(
                lambda ip: geo_results.get(ip, ("Unknown", 0.0, 0.0))[1])
            df_ips["Lon"]  = df_ips["IP_Atacante"].map(
                lambda ip: geo_results.get(ip, ("Unknown", 0.0, 0.0))[2])

            df_mapa = df_ips.groupby("Pais").size().reset_index(name="Total_Ataques")

            # ── 9. Exportar CSV  ─────────────────────────────────────────────
            cols = [c for c in ["Timestamp", "IP_Atacante", "Pais", "Puerto",
                                 "Usuario", "Severidad", "Lat", "Lon"]
                    if c in df_ips.columns]
            csv_path = Path.home() / "Resultado_KATANA.csv"
            df_ips[cols].to_csv(csv_path, index=False)

            elapsed = time.perf_counter() - t0
            self.log.emit(f"CSV saved  {csv_path}")
            self.log.emit(f"Analysis completed in {elapsed:.1f}s")
            self.finished.emit(df_ips, df_mapa, total, len(df_ips))

        except Exception as e:
            traceback.print_exc(); self.error.emit(str(e))


class AegisWorker(QThread):
    log      = pyqtSignal(str)
    finished = pyqtSignal(int, int)

    def __init__(self, fw_ip, fw_port, fw_user, fw_pass, ips, dry=False):
        super().__init__()
        self.fw_ip=fw_ip; self.fw_port=fw_port; self.fw_user=fw_user
        self.fw_pass=fw_pass; self.ips=ips; self.dry=dry

    def run(self):
        if self.dry:
            self.log.emit("DRY RUN — no requests sent")
            for ip in self.ips:
                self.log.emit(f"  sim  AEGIS_{ip.replace('.','_')}"); time.sleep(0.05)
            self.finished.emit(len(self.ips), len(self.ips)); return

        url = f"https://{self.fw_ip}:{self.fw_port}/webconsole/APIController"
        ok = 0; created = []; failed = 0
        for ip in self.ips:
            name = f"AEGIS_{ip.replace('.','_')}"
            xml  = (f"<Request><Login><Username>{self.fw_user}</Username>"
                    f"<Password>{self.fw_pass}</Password></Login>"
                    f"<Set><IPHost><n>{name}</n><IPFamily>IPv4</IPFamily>"
                    f"<HostType>IP</HostType><IPAddress>{ip}</IPAddress>"
                    f"</IPHost></Set></Request>")
            self.log.emit(f"  → {name}")
            try:
                res = requests.post(url, data={"reqxml": xml}, verify=False, timeout=5)
                txt = res.text
                if 'status="200"' in txt or "Configuration applied" in txt:
                    self.log.emit("     ok"); ok += 1; created.append(name)
                elif "already exists" in txt:
                    self.log.emit("     exists"); created.append(name)
                elif "Authentication Failure" in txt:
                    self.log.emit("     auth error — aborting"); break
                else:
                    self.log.emit("     unexpected response"); failed += 1
            except Exception as ex:
                self.log.emit(f"     error ({ex})"); failed += 1
            time.sleep(0.5)

        if failed:
            self.log.emit(f"  {failed} IPs failed")
        if created:
            self.log.emit("Updating group KATANA_BLACKLIST")
            hosts = "".join(f"<Host>{h}</Host>" for h in created)
            xml_g = (f"<Request><Login><Username>{self.fw_user}</Username>"
                     f"<Password>{self.fw_pass}</Password></Login>"
                     f"<Set><IPHostGroup><n>KATANA_BLACKLIST</n>"
                     f"<IPFamily>IPv4</IPFamily><HostList>{hosts}</HostList>"
                     f"</IPHostGroup></Set></Request>")
            try:
                r = requests.post(url, data={"reqxml": xml_g}, verify=False, timeout=10)
                self.log.emit("     ok" if "status=\"200\"" in r.text else "     group error")
            except Exception:
                self.log.emit("     group connection error")
        self.finished.emit(ok, len(self.ips))


# ─────────────────────────────────────────────────────────────────────────────
#  COMPONENTES
# ─────────────────────────────────────────────────────────────────────────────
class MetricTile(QWidget):
    def __init__(self, title: str, color_key: str = "ACCENT"):
        super().__init__()
        self._key = color_key
        self.setObjectName("card")
        lo = QVBoxLayout(self); lo.setContentsMargins(16,12,16,12); lo.setSpacing(4)
        self._val = lbl("—", size=26, color=T(color_key), bold=True, mono=True)
        lo.addWidget(self._val)
        lo.addWidget(lbl(title, size=10, dim=True))
        self.setMinimumWidth(100)

    def set(self, v):   self._val.setText(str(v))
    def recolor(self):
        self._val.setStyleSheet(
            f"font-size:26px;font-family:{MONO};font-weight:600;"
            f"color:{T(self._key)};background:transparent;")


class StatusDot(QWidget):
    def __init__(self, color: str, size: int = 7):
        super().__init__()
        self._c = color; self._s = size
        self.setFixedSize(size + 2, size + 2)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor(self._c)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(1, 1, self._s, self._s)


class FilterRow(QWidget):
    changed = pyqtSignal(str, str, str)

    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        lo = QHBoxLayout(self); lo.setContentsMargins(10,6,10,6); lo.setSpacing(8)
        lo.addWidget(lbl("Filter:", size=10, dim=True))
        self.ip      = QLineEdit(); self.ip.setPlaceholderText("IP or range")
        self.ip.setFixedWidth(150); self.ip.textChanged.connect(self._emit)
        self.country = QLineEdit(); self.country.setPlaceholderText("Country")
        self.country.setFixedWidth(110); self.country.textChanged.connect(self._emit)
        self.sev     = QComboBox()
        self.sev.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.sev.setFixedWidth(100); self.sev.currentTextChanged.connect(self._emit)
        clr = QPushButton("Clear"); clr.setObjectName("ghost")
        clr.setFixedWidth(50); clr.clicked.connect(self._clear)
        for w in [self.ip, self.country, self.sev, clr]: lo.addWidget(w)
        lo.addStretch()

    def _emit(self):
        self.changed.emit(self.ip.text(), self.country.text(), self.sev.currentText())

    def _clear(self):
        self.ip.clear(); self.country.clear(); self.sev.setCurrentIndex(0)


# ─────────────────────────────────────────────────────────────────────────────
#  DIÁLOGOS
# ─────────────────────────────────────────────────────────────────────────────
class ExportDialog(QDialog):
    def __init__(self, df, df_mapa, parent=None):
        super().__init__(parent)
        self.df = df; self.df_mapa = df_mapa
        self.setWindowTitle("Export Data"); self.setFixedWidth(440)
        lo = QVBoxLayout(self); lo.setContentsMargins(24,24,24,20); lo.setSpacing(14)

        # ── Título ────────────────────────────────────────────────────────────
        lo.addWidget(lbl("Export Report", size=15, bold=True))
        lo.addWidget(lbl(f"{df['IP_Atacante'].nunique():,} IPs  ·  "
                         f"{len(df):,} events  ·  "
                         f"{df['Pais'].nunique()} countries",
                         dim=True, size=11))
        lo.addWidget(sep())

        # ── Formatos disponibles ──────────────────────────────────────────────
        lo.addWidget(lbl("Output formats", size=10, bold=True))

        def _fmt_row(chk_widget, icon, label, desc, color):
            row = QWidget(); row.setObjectName("card")
            rl = QHBoxLayout(row); rl.setContentsMargins(12,10,12,10); rl.setSpacing(10)
            rl.addWidget(chk_widget)
            badge = QLabel(icon)
            badge.setFixedWidth(22)
            badge.setStyleSheet(f"font-size:15px; background:transparent; color:{color};")
            rl.addWidget(badge)
            col = QVBoxLayout(); col.setSpacing(1)
            col.addWidget(lbl(label, size=11, bold=True))
            col.addWidget(lbl(desc,  size=10, dim=True))
            rl.addLayout(col); rl.addStretch()
            return row

        self.chk_pdf  = QCheckBox(); self.chk_pdf.setChecked(True)
        self.chk_xlsx = QCheckBox()
        self.chk_json = QCheckBox()
        self.chk_ioc  = QCheckBox()

        lo.addWidget(_fmt_row(self.chk_pdf,  "📄", "PDF Report",
                              "Executive forensic summary — countries, IPs, severity",
                              T("ACCENT")))
        lo.addWidget(_fmt_row(self.chk_xlsx, "📊", "Excel  (.xlsx)",
                              "Full IP table with all columns — ideal for SOC analysts",
                              T("SUCCESS")))
        lo.addWidget(_fmt_row(self.chk_json, "{ }", "JSON  — SIEM / SOAR",
                              "Machine-readable IOC payload for ingestion pipelines",
                              T("WARN")))
        lo.addWidget(_fmt_row(self.chk_ioc,  "🛡", "IOC List  (.txt)",
                              "Plain IP list for firewall rules or threat intel feeds",
                              T("DANGER")))

        lo.addWidget(sep())

        # ── Filtro top N ──────────────────────────────────────────────────────
        row_n = QHBoxLayout(); row_n.setSpacing(6)
        self.chk_top = QCheckBox("Limit to top")
        self.spin    = QSpinBox(); self.spin.setRange(10, 9999); self.spin.setValue(100)
        self.spin.setFixedWidth(70)
        row_n.addWidget(self.chk_top); row_n.addWidget(self.spin)
        row_n.addWidget(lbl("IPs", dim=True)); row_n.addStretch()
        lo.addLayout(row_n); lo.addWidget(sep())

        # ── Botones ───────────────────────────────────────────────────────────
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setObjectName("primary")
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Export selected")
        btns.accepted.connect(self._run); btns.rejected.connect(self.reject)
        lo.addWidget(btns)

    def _run(self):
        if not any([self.chk_pdf.isChecked(), self.chk_xlsx.isChecked(),
                    self.chk_json.isChecked(), self.chk_ioc.isChecked()]):
            QMessageBox.warning(self, "Export", "Select at least one format.")
            return

        df = self.df
        if self.chk_top.isChecked():
            top_ips = df["IP_Atacante"].value_counts().head(self.spin.value()).index
            df = df[df["IP_Atacante"].isin(top_ips)]

        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = []

        if self.chk_pdf.isChecked():
            p = f"KATANA_Report_{ts}.pdf"
            try:
                _build_pdf(df, self.df_mapa, p); out.append(("PDF Report",   p, True))
            except Exception as e:
                out.append(("PDF Report", f"error: {e}", False))

        if self.chk_xlsx.isChecked():
            p = f"KATANA_IPs_{ts}.xlsx"
            try:
                df.drop(columns=["_row"], errors="ignore").to_excel(p, index=False)
                out.append(("Excel (.xlsx)", p, True))
            except Exception as e:
                out.append(("Excel (.xlsx)", f"error: {e}", False))

        if self.chk_json.isChecked():
            p = f"KATANA_SIEM_{ts}.json"
            try:
                grp_cols = [c for c in ["IP_Atacante","Pais","Severidad"] if c in df.columns]
                c = df.groupby(grp_cols).size().reset_index(name="events")
                payload = {"katana": "8.0", "ts": ts,
                           "total_ips":    int(df["IP_Atacante"].nunique()),
                           "total_events": int(len(df)),
                           "iocs":         c.to_dict("records")}
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
                out.append(("JSON SIEM", p, True))
            except Exception as e:
                out.append(("JSON SIEM", f"error: {e}", False))

        if self.chk_ioc.isChecked():
            p = f"KATANA_IOC_{ts}.txt"
            try:
                ips = df["IP_Atacante"].value_counts().index.tolist()
                with open(p, "w", encoding="utf-8") as f:
                    f.write(f"# KATANA IOC  {datetime.now()}\n# {len(ips)} IPs\n\n")
                    f.write("\n".join(ips))
                out.append(("IOC List (.txt)", p, True))
            except Exception as e:
                out.append(("IOC List (.txt)", f"error: {e}", False))

        lines = "\n".join(
            f"  {'✓' if ok else '✗'}  {name}  →  {path}"
            for name, path, ok in out
        )
        QMessageBox.information(self, "Export complete",
            f"Files created:\n\n{lines}")
        for _, path, ok in out:
            if ok and path.endswith(".pdf"):
                webbrowser.open(f"file://{os.path.abspath(path)}")
        self.accept()


class WhitelistDialog(QDialog):
    def __init__(self, whitelist: set, parent=None):
        super().__init__(parent)
        self._wl = whitelist
        self.setWindowTitle("IP Whitelist"); self.setMinimumSize(360, 380)
        lo = QVBoxLayout(self); lo.setContentsMargins(20,20,20,16); lo.setSpacing(10)
        lo.addWidget(lbl("IP Whitelist", size=14, bold=True))
        lo.addWidget(lbl("IPs excluded from analysis. One per line.", dim=True, size=11))
        lo.addWidget(sep())
        self.txt = QTextEdit()
        self.txt.setFont(QFont("Consolas", 11))
        self.txt.setPlaceholderText("192.168.1.1\n10.0.0.5")
        self.txt.setText("\n".join(sorted(whitelist)))
        lo.addWidget(self.txt, 1)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Save).setObjectName("primary")
        btns.accepted.connect(self._save); btns.rejected.connect(self.reject)
        lo.addWidget(btns)

    def _save(self):
        self._wl.clear()
        self._wl.update(
            {l.strip() for l in self.txt.toPlainText().splitlines() if l.strip()})
        db_whitelist_save(self._wl)
        self.accept()


# ─────────────────────────────────────────────────────────────────────────────
#  SPLASH SCREEN  —  Enterprise Edition
# ─────────────────────────────────────────────────────────────────────────────
class SplashScreen(QWidget):
    """Pantalla de carga premium con logo y barra de progreso."""
    done = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowFlags(
            Qt.WindowType.SplashScreen |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(460, 280)

        screen = QApplication.primaryScreen().geometry()
        self.move(
            (screen.width()  - self.width())  // 2,
            (screen.height() - self.height()) // 2,
        )

        root = QWidget(self)
        root.setFixedSize(460, 280)
        root.setStyleSheet(
            "background:#1C1C1E; border-radius:16px;"
            "border:1px solid #48484A;")
        lo = QVBoxLayout(root)
        lo.setContentsMargins(44, 40, 44, 36)
        lo.setSpacing(0)

        # ── Logo ────────────────────────────────────────────────────────────
        logo_row = QHBoxLayout(); logo_row.setSpacing(14)

        class _Logo(QWidget):
            def __init__(self):
                super().__init__(); self.setFixedSize(48, 48)
            def paintEvent(self, _):
                p = QPainter(self)
                p.setRenderHint(QPainter.RenderHint.Antialiasing)
                # Fondo gradiente dorado → azul (Enterprise)
                from PyQt6.QtGui import QLinearGradient
                grad = QLinearGradient(0, 0, 48, 48)
                grad.setColorAt(0, QColor("#0A84FF"))
                grad.setColorAt(1, QColor("#FF9F0A"))
                p.setBrush(QBrush(grad))
                p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(0, 0, 48, 48)
                f = QFont("Poppins", 21, QFont.Weight.Bold)
                p.setFont(f)
                p.setPen(QColor("white"))
                p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "K")

        logo_row.addWidget(_Logo())
        txt_col = QVBoxLayout(); txt_col.setSpacing(3)

        name_lbl = QLabel("KATANA")
        name_lbl.setStyleSheet(
            f"font-family:{SANS}; font-size:24px; font-weight:800;"
            f"color:#F2F2F7; background:transparent; letter-spacing:3px;")
        edition_lbl = QLabel("Enterprise  ·  Threat Intelligence Platform")
        edition_lbl.setStyleSheet(
            f"font-family:{SANS}; font-size:11px; font-weight:500;"
            f"color:#FF9F0A; background:transparent; letter-spacing:0.5px;")

        txt_col.addWidget(name_lbl); txt_col.addWidget(edition_lbl)
        logo_row.addLayout(txt_col); logo_row.addStretch()
        lo.addLayout(logo_row)
        lo.addSpacing(30)

        # ── Estado ──────────────────────────────────────────────────────────
        self._status = QLabel("Initializing…")
        self._status.setStyleSheet(
            f"font-family:{SANS}; font-size:11px; font-weight:500;"
            f"color:#AEAEB2; background:transparent;")
        lo.addWidget(self._status)
        lo.addSpacing(10)

        # ── Barra degradada ──────────────────────────────────────────────────
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setFixedHeight(4)
        self._bar.setTextVisible(False)
        self._bar.setStyleSheet("""
            QProgressBar {
                background:#3A3A3C; border:none; border-radius:2px;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0A84FF, stop:0.6 #FF9F0A, stop:1 #FF453A);
                border-radius:2px;
            }
        """)
        lo.addWidget(self._bar)
        lo.addSpacing(16)

        footer = QLabel("v0.8  ·  Sophos Firewall Log Analyzer  ·  Enterprise Edition")
        footer.setStyleSheet(
            f"font-family:{SANS}; font-size:9px; font-weight:400;"
            f"color:#48484A; background:transparent;")
        lo.addWidget(footer)

        # ── Animación ────────────────────────────────────────────────────────
        self._steps = [
            (12,  "Loading libraries…"),
            (28,  "Connecting to database…"),
            (45,  "Loading whitelist…"),
            (60,  "Applying enterprise theme…"),
            (78,  "Building interface…"),
            (90,  "Loading AEGIS engine…"),
            (100, "Ready."),
        ]
        self._step_idx = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)
        self._timer.start(210)

    def _advance(self):
        if self._step_idx >= len(self._steps):
            self._timer.stop()
            QTimer.singleShot(160, self.done.emit)
            return
        val, msg = self._steps[self._step_idx]
        self._bar.setValue(val)
        self._status.setText(msg)
        self._step_idx += 1


# ─────────────────────────────────────────────────────────────────────────────
#  VENTANA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
class KatanaApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KATANA  ·  Threat Intelligence Platform")
        self.setMinimumSize(1300, 800)
        self.df     = None
        self.df_map = None
        self._wl    = db_whitelist_load()
        self._aw    = None
        self._egw   = None
        self._dark  = True
        self.setStyleSheet(_build_qss())
        self._ui()

    # ──────────────────────────────────────────────────────── LAYOUT ──
    def _ui(self):
        root = QWidget(); self.setCentralWidget(root)
        rl = QVBoxLayout(root); rl.setContentsMargins(0,0,0,0); rl.setSpacing(0)
        rl.addWidget(self._build_topbar())

        body = QWidget(); bl = QHBoxLayout(body)
        bl.setContentsMargins(0,0,0,0); bl.setSpacing(0)
        bl.addWidget(self._build_sidebar())

        self._main_w = QWidget()
        self._main_w.setStyleSheet(f"background:{T('BG')};")
        ml = QHBoxLayout(self._main_w)
        ml.setContentsMargins(16,16,16,16); ml.setSpacing(12)
        self._spl = QSplitter(Qt.Orientation.Horizontal)
        self._spl.setStyleSheet(
            f"QSplitter::handle{{background:{T('BORDER')};width:1px;}}")
        self._spl.addWidget(self._build_ip_panel())
        self._spl.addWidget(self._build_tabs())
        self._spl.setSizes([290, 880])
        ml.addWidget(self._spl)
        bl.addWidget(self._main_w, 1)
        rl.addWidget(body, 1)

    # ──────────────────────────────────────────────────────── TOPBAR ──
    def _build_topbar(self):
        bar = QWidget(); bar.setObjectName("topbar"); bar.setFixedHeight(38)
        lo = QHBoxLayout(bar); lo.setContentsMargins(20,0,20,0); lo.setSpacing(16)
        lo.addWidget(StatusDot(T("SUCCESS")))
        lo.addWidget(lbl("KATANA", size=13, bold=True))
        lo.addWidget(lbl("v0.8", size=11, dim=True))
        lo.addWidget(sep(vertical=True)); lo.addWidget(spacer(h=4))
        self._tb_file = lbl("No log loaded", size=10, dim=True)
        lo.addWidget(self._tb_file)
        lo.addWidget(spacer())
        self._tb_time = lbl("", size=10, mono=True, dim=True)
        lo.addWidget(self._tb_time)
        self._btn_theme = QPushButton("●  Dark")
        self._btn_theme.setObjectName("theme_btn")
        self._btn_theme.setFixedSize(72, 24)
        self._btn_theme.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_theme.clicked.connect(self._toggle_theme)
        lo.addWidget(self._btn_theme)
        t = QTimer(self)
        t.timeout.connect(
            lambda: self._tb_time.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S")))
        t.start(1000)
        self._tb_time.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        return bar

    # ──────────────────────────────────────────────────────── SIDEBAR ──
    def _build_sidebar(self):
        sb = QWidget(); sb.setObjectName("sidebar"); sb.setFixedWidth(210)
        lo = QVBoxLayout(sb); lo.setContentsMargins(16,20,16,16); lo.setSpacing(0)

        lo.addWidget(lbl("Operations", size=10, dim=True)); lo.addSpacing(8)

        self.btn_load = QPushButton("Load CSV log")
        self.btn_load.setFixedHeight(36)
        self.btn_load.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_load.clicked.connect(self._load)
        lo.addWidget(self.btn_load)

        self._file_lbl = lbl("No file selected", size=10, dim=True)
        self._file_lbl.setWordWrap(True)
        lo.addSpacing(6); lo.addWidget(self._file_lbl)
        lo.addSpacing(10)

        self._pbar = QProgressBar()
        self._pbar.setFixedHeight(2); self._pbar.setRange(0,0)
        self._pbar.setVisible(False)
        lo.addWidget(self._pbar); lo.addSpacing(6)

        self.btn_run = QPushButton("Run analysis")
        self.btn_run.setObjectName("primary"); self.btn_run.setFixedHeight(38)
        self.btn_run.setEnabled(False)
        self.btn_run.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_run.clicked.connect(self._run)
        lo.addWidget(self.btn_run); lo.addSpacing(8)

        self.btn_export = QPushButton("Export data")
        self.btn_export.setObjectName("success"); self.btn_export.setFixedHeight(34)
        self.btn_export.setEnabled(False)
        self.btn_export.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_export.clicked.connect(self._export)
        lo.addWidget(self.btn_export)

        lo.addSpacing(20); lo.addWidget(sep()); lo.addSpacing(16)
        lo.addWidget(lbl("Configuration", size=10, dim=True)); lo.addSpacing(8)

        btn_wl = QPushButton("IP Whitelist")
        btn_wl.setFixedHeight(32)
        btn_wl.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_wl.clicked.connect(self._whitelist_dlg)
        lo.addWidget(btn_wl)

        lo.addSpacing(20); lo.addWidget(sep()); lo.addSpacing(16)
        lo.addWidget(lbl("Metrics", size=10, dim=True)); lo.addSpacing(8)

        self.m_ips    = MetricTile("Unique IPs",   "ACCENT")
        self.m_events = MetricTile("Total events", "DANGER")
        self.m_ctrs   = MetricTile("Countries",    "WARN")
        self.m_crit   = MetricTile("Critical IPs", "S_CRIT")
        for m in [self.m_ips, self.m_events, self.m_ctrs, self.m_crit]:
            lo.addWidget(m); lo.addSpacing(6)

        lo.addStretch()
        lo.addWidget(lbl("Sophos Firewall Log Analyzer", size=9, dim=True))
        return sb

    # ──────────────────────────────────────────────────────── IP PANEL ──
    def _build_ip_panel(self):
        panel = QWidget(); panel.setObjectName("card")
        lo = QVBoxLayout(panel); lo.setContentsMargins(0,0,0,0); lo.setSpacing(0)

        self._ip_hdr = QWidget(); self._ip_hdr.setFixedHeight(44)
        self._ip_hdr.setStyleSheet(
            f"background:{T('BG')};border-bottom:1px solid {T('BORDER')};")
        hl = QHBoxLayout(self._ip_hdr); hl.setContentsMargins(14,0,10,0)
        hl.addWidget(lbl("Detected IPs", size=11, bold=True))
        hl.addStretch()
        self._ip_count = lbl("0", size=11, mono=True, color=T("ACCENT"))
        hl.addWidget(self._ip_count)
        btn_ctx = QPushButton("···"); btn_ctx.setObjectName("ghost")
        btn_ctx.setFixedSize(28, 28)
        btn_ctx.clicked.connect(self._ip_menu)
        hl.addWidget(btn_ctx)
        lo.addWidget(self._ip_hdr)

        self._filter = FilterRow()
        self._filter.changed.connect(self._filter_table)
        lo.addWidget(self._filter); lo.addWidget(sep())

        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Sev", "Country", "IP", "Attempts"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(False)
        self.tree.setSortingEnabled(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._row_menu)
        hv = self.tree.header()
        hv.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hv.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hv.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hv.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.tree.setColumnWidth(0, 62)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(3, 68)
        lo.addWidget(self.tree, 1)
        return panel

    # ──────────────────────────────────────────────────────── TABS ──
    def _build_tabs(self):
        self.tabs = QTabWidget()
        tabs_def = [
            ("Dashboard",  self._build_tab_dashboard),
            ("Geography",  self._build_tab_geo),
            ("Timeline",   self._build_tab_timeline),
            ("Users",      self._build_tab_users),
            ("Patterns",   self._build_tab_patterns),
            ("Intel Map",  self._build_tab_intel),
            ("AEGIS",      self._build_tab_aegis),
            ("History",    self._build_tab_history),
        ]
        for name, builder in tabs_def:
            w = QWidget(); self.tabs.addTab(w, name); builder(w)
        return self.tabs

    # ── Dashboard ──────────────────────────────────────────────────────
    def _build_tab_dashboard(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(16)

        kpi_row = QHBoxLayout(); kpi_row.setSpacing(10)
        self._kpi = {}
        for k, title, ck in [("events",   "Events",         "DANGER"),
                               ("ips",      "Unique IPs",     "ACCENT"),
                               ("countries","Countries",      "WARN"),
                               ("critical", "Critical",       "S_CRIT"),
                               ("users",    "Users targeted", "INK2")]:
            tile = MetricTile(title, ck)
            self._kpi[k] = tile; kpi_row.addWidget(tile)
        lo.addLayout(kpi_row)

        charts = QHBoxLayout(); charts.setSpacing(12)
        self._dash_left  = self._chart_panel("Top countries")
        self._dash_right = self._chart_panel("Severity breakdown")
        charts.addWidget(self._dash_left, 1)
        charts.addWidget(self._dash_right, 1)
        lo.addLayout(charts, 1)

        self._dash_status = QLabel("Load a CSV log and run analysis to begin.")
        self._dash_status.setObjectName("card")
        self._dash_status.setStyleSheet("padding:8px 14px;font-size:11px;border-radius:3px;")
        lo.addWidget(self._dash_status)

    def _chart_panel(self, title: str) -> QWidget:
        w = QWidget(); w.setObjectName("card")
        lo = QVBoxLayout(w); lo.setContentsMargins(14,12,14,12); lo.setSpacing(8)
        lo.addWidget(lbl(title, size=11, bold=True))
        inner = QWidget()
        il = QVBoxLayout(inner); il.setContentsMargins(0,0,0,0)
        pl = lbl("No data", dim=True, size=11)
        pl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        il.addWidget(pl)
        lo.addWidget(inner, 1)
        w._inner = inner
        w._placeholder = pl
        return w

    def _replace_chart(self, panel, new_widget):
        """Reemplaza el contenido del panel por un nuevo widget pyqtgraph."""
        inner  = panel._inner
        layout = inner.layout()
        # Eliminar todo excepto el placeholder
        to_rm = []
        for i in range(layout.count()):
            it = layout.itemAt(i)
            w  = it.widget() if it else None
            if w and w is not panel._placeholder:
                to_rm.append(w)
        for w in to_rm:
            layout.removeWidget(w); w.deleteLater()
        panel._placeholder.setVisible(False)
        layout.addWidget(new_widget)

    # ── Geography ──────────────────────────────────────────────────────
    def _build_tab_geo(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20)
        lo.addWidget(lbl("Geographic Distribution", size=13, bold=True))
        lo.addWidget(lbl("Top 15 countries by attack volume", dim=True, size=11))
        lo.addSpacing(10)
        self._geo_inner = QWidget()
        gl = QVBoxLayout(self._geo_inner); gl.setContentsMargins(0,0,0,0)
        self._geo_ph = lbl("Run analysis to see geographic distribution.", dim=True, size=11)
        self._geo_ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gl.addWidget(self._geo_ph)
        lo.addWidget(self._geo_inner, 1)

    # ── Timeline ───────────────────────────────────────────────────────
    def _build_tab_timeline(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(12)
        row = QHBoxLayout()
        row.addWidget(lbl("Attack Timeline", size=13, bold=True)); row.addStretch()
        row.addWidget(lbl("Granularity:", size=10, dim=True))
        self._tl_combo = QComboBox()
        self._tl_combo.addItems(["Hourly", "Daily", "Weekly"])
        self._tl_combo.setFixedWidth(100)
        self._tl_combo.currentIndexChanged.connect(lambda _: self._draw_timeline())
        row.addWidget(self._tl_combo)
        lo.addLayout(row)
        self._tl_inner = QWidget()
        tl = QVBoxLayout(self._tl_inner); tl.setContentsMargins(0,0,0,0)
        self._tl_ph = lbl("No timestamp data in this log.", dim=True, size=11)
        self._tl_ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tl.addWidget(self._tl_ph)
        lo.addWidget(self._tl_inner, 1)

    # ── Users ──────────────────────────────────────────────────────────
    def _build_tab_users(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20)
        lo.addWidget(lbl("Targeted Accounts", size=13, bold=True))
        lo.addWidget(lbl("Brute-force username frequency", dim=True, size=11))
        lo.addSpacing(10)
        self._usr_inner = QWidget()
        ul = QVBoxLayout(self._usr_inner); ul.setContentsMargins(0,0,0,0)
        self._usr_ph = lbl("No user data in this log.", dim=True, size=11)
        self._usr_ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ul.addWidget(self._usr_ph)
        lo.addWidget(self._usr_inner, 1)

    # ── Patterns ───────────────────────────────────────────────────────
    def _build_tab_patterns(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(14)
        lo.addWidget(lbl("Attack Patterns", size=13, bold=True))
        lo.addWidget(lbl("Subnet clustering and port analysis", dim=True, size=11))
        lo.addSpacing(4)
        lo.addWidget(lbl("/24 Subnet Activity", size=11, bold=True))
        self._tree_sub = QTreeWidget()
        self._tree_sub.setColumnCount(3)
        self._tree_sub.setHeaderLabels(["Subnet /24", "Distinct IPs", "Total Events"])
        self._tree_sub.setRootIsDecorated(False)
        self._tree_sub.setAlternatingRowColors(True)
        hv = self._tree_sub.header()
        for i in range(3): hv.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        lo.addWidget(self._tree_sub, 1); lo.addWidget(sep())
        lo.addWidget(lbl("Target Port Distribution", size=11, bold=True))
        self._tree_ports = QTreeWidget()
        self._tree_ports.setColumnCount(2)
        self._tree_ports.setHeaderLabels(["Port", "Attempts"])
        self._tree_ports.setRootIsDecorated(False)
        self._tree_ports.setAlternatingRowColors(True)
        self._tree_ports.setMaximumHeight(150)
        hv2 = self._tree_ports.header()
        for i in range(2): hv2.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        lo.addWidget(self._tree_ports)

    # ── Intel Map ──────────────────────────────────────────────────────
    def _build_tab_intel(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(0,0,0,0)
        center = QWidget(); center.setMaximumWidth(460)
        cl = QVBoxLayout(center); cl.setContentsMargins(40,60,40,60); cl.setSpacing(12)
        cl.addWidget(lbl("Threat Map", size=22, bold=True))
        cl.addWidget(lbl("Interactive choropleth and 3D globe.\nOpens in browser.",
                         dim=True, size=12))
        cl.addSpacing(20)
        self._btn_map_2d = QPushButton("Open 2D Choropleth Map")
        self._btn_map_2d.setObjectName("primary"); self._btn_map_2d.setFixedHeight(40)
        self._btn_map_2d.setEnabled(False)
        self._btn_map_2d.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_map_2d.clicked.connect(self._map_2d)
        cl.addWidget(self._btn_map_2d)
        self._btn_map_3d = QPushButton("Open 3D Globe")
        self._btn_map_3d.setFixedHeight(36); self._btn_map_3d.setEnabled(False)
        self._btn_map_3d.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_map_3d.clicked.connect(self._map_3d)
        cl.addWidget(self._btn_map_3d)
        lo.addStretch(); lo.addWidget(center, 0, Qt.AlignmentFlag.AlignCenter); lo.addStretch()

    # ── AEGIS ──────────────────────────────────────────────────────────
    def _build_tab_aegis(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(24,20,24,20); lo.setSpacing(14)
        lo.addWidget(lbl("AEGIS  —  Active Defense Engine", size=14, bold=True))
        warn = QLabel("⚠  This engine makes live changes to your Sophos Firewall.")
        warn.setStyleSheet(f"color:{T('WARN')};font-size:11px;background:transparent;")
        lo.addWidget(warn); lo.addWidget(sep())

        cred = QGroupBox("SOPHOS API CREDENTIALS")
        gl = QHBoxLayout(cred); gl.setSpacing(20); gl.setContentsMargins(16,14,16,14)

        def field(ph, pw=False, w=140):
            e = QLineEdit(); e.setPlaceholderText(ph); e.setFixedWidth(w)
            if pw: e.setEchoMode(QLineEdit.EchoMode.Password)
            return e

        self.fw_ip   = field("192.168.1.1")
        self.fw_user = field("admin")
        self.fw_port = field("4444", w=80); self.fw_port.setText("4444")
        self.fw_pass = field("password", pw=True)

        for pairs in [
            [("Firewall IP", self.fw_ip),   ("Username", self.fw_user)],
            [("Port",        self.fw_port),  ("Password", self.fw_pass)],
        ]:
            col = QWidget(); cl2 = QVBoxLayout(col)
            cl2.setSpacing(8); cl2.setContentsMargins(0,0,0,0)
            for label, widget in pairs:
                r = QHBoxLayout(); r.setSpacing(8)
                lb = lbl(label, size=10, dim=True); lb.setFixedWidth(80)
                r.addWidget(lb); r.addWidget(widget); cl2.addLayout(r)
            gl.addWidget(col)
        gl.addStretch(); lo.addWidget(cred)

        ar = QHBoxLayout(); ar.setSpacing(12)
        ar.addWidget(lbl("Inject:", size=10, dim=True))
        self._combo_lim = QComboBox()
        self._combo_lim.addItems(["Top 10","Top 25","Top 50","Top 100","All IPs"])
        self._combo_lim.setFixedWidth(110)
        ar.addWidget(self._combo_lim)
        self._chk_dry = QCheckBox("Dry run (simulate only)")
        ar.addWidget(self._chk_dry); ar.addStretch()
        self._btn_aegis = QPushButton("Inject rules into firewall")
        self._btn_aegis.setObjectName("danger"); self._btn_aegis.setFixedHeight(36)
        self._btn_aegis.setEnabled(False)
        self._btn_aegis.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._btn_aegis.clicked.connect(self._aegis_run)
        ar.addWidget(self._btn_aegis); lo.addLayout(ar); lo.addWidget(sep())

        lo.addWidget(lbl("Console", size=10, dim=True))
        self._console = QTextEdit(); self._console.setObjectName("console")
        self._console.setReadOnly(True)
        self._console.setText("AEGIS standby — awaiting analysis\n")
        lo.addWidget(self._console, 1)

    # ── History ────────────────────────────────────────────────────────
    def _build_tab_history(self, tab):
        lo = QVBoxLayout(tab); lo.setContentsMargins(20,20,20,20); lo.setSpacing(12)
        lo.addWidget(lbl("Analysis History", size=13, bold=True))
        lo.addWidget(lbl("Persistent across sessions — stored in ~/.katana_v0.8.db",
                         dim=True, size=10))
        lo.addSpacing(4)

        self._hist_tbl = QTableWidget(0, 5)
        self._hist_tbl.setHorizontalHeaderLabels(
            ["Date / Time", "File", "IPs", "Events", "Countries"])
        self._hist_tbl.setAlternatingRowColors(True)
        self._hist_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._hist_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        hv = self._hist_tbl.horizontalHeader()
        hv.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self._hist_tbl.setColumnWidth(0, 160)
        hv.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for i in [2, 3, 4]:
            hv.setSectionResizeMode(i, QHeaderView.ResizeMode.Fixed)
            self._hist_tbl.setColumnWidth(i, 80)
        lo.addWidget(self._hist_tbl, 1)

        btn = QPushButton("Clear history"); btn.setFixedWidth(120)
        btn.clicked.connect(self._clear_history)
        lo.addWidget(btn)

        # Cargar historial de DB
        for row in db_history_load():
            self._hist_tbl_add_row(*row)

    # ────────────────────────────────────────────────────── TEMA ──
    def _toggle_theme(self):
        global _T
        self._dark = not self._dark
        _T = THEMES["dark"] if self._dark else THEMES["light"]
        _update_globals()
        self.setStyleSheet(_build_qss())
        self._btn_theme.setText("●  Dark" if self._dark else "○  Light")

        # Widgets con inline style
        self._main_w.setStyleSheet(f"background:{T('BG')};")
        self._spl.setStyleSheet(
            f"QSplitter::handle{{background:{T('BORDER')};width:1px;}}")
        self._ip_hdr.setStyleSheet(
            f"background:{T('BG')};border-bottom:1px solid {T('BORDER')};")
        self._ip_count.setStyleSheet(
            f"font-size:11px;font-family:{MONO};color:{T('ACCENT')};background:transparent;")

        for tile in [self.m_ips, self.m_events, self.m_ctrs, self.m_crit]:
            tile.recolor()
        for tile in self._kpi.values():
            tile.recolor()

        # Redibujar gráficos (pyqtgraph: se recrean con nuevo tema)
        if self.df is not None:
            self._draw_dashboard(self.df)
            self._draw_geo(self.df)
            self._draw_timeline()
            self._draw_users(self.df)
            self._draw_patterns(self.df)

    # ────────────────────────────────────────────────────── DRAW ──
    def _draw_table(self, df):
        self.tree.clear()
        cnt = df.groupby(["Pais", "IP_Atacante"]).size().reset_index(name="N")
        if "Severidad" in df.columns:
            sm = (df[["IP_Atacante", "Severidad"]]
                  .drop_duplicates()
                  .set_index("IP_Atacante")["Severidad"])
            cnt["S"] = cnt["IP_Atacante"].map(sm).fillna("LOW")
        else:
            cnt["S"] = "LOW"
        for _, r in cnt.sort_values("N", ascending=False).iterrows():
            c  = SEV_COLOR.get(r["S"], T("INK2"))
            it = QTreeWidgetItem([r["S"], str(r["Pais"]),
                                  str(r["IP_Atacante"]), str(r["N"])])
            it.setForeground(0, QBrush(QColor(c)))
            it.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
            it.setTextAlignment(3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.tree.addTopLevelItem(it)
        self._ip_count.setText(str(len(cnt)))

    def _draw_dashboard(self, df):
        # Countries bar
        top_p  = df["Pais"].value_counts().head(10)
        bar_w  = _pg_bar(top_p.index.tolist(), top_p.values.tolist())
        self._replace_chart(self._dash_left, bar_w)

        # Severity donut
        if "Severidad" in df.columns:
            sc = df.drop_duplicates("IP_Atacante")["Severidad"].value_counts()
        else:
            sc = pd.Series({"LOW": df["IP_Atacante"].nunique()})
        donut_w = _pg_donut(list(sc.index), list(sc.values))
        self._replace_chart(self._dash_right, donut_w)

    def _draw_geo(self, df):
        top_p = df["Pais"].value_counts().head(15)
        pw    = _pg_bar(top_p.index.tolist(), top_p.values.tolist(),
                        color_first=_T["ACCENT"])

        lo = self._geo_inner.layout()
        while lo.count():
            it = lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        self._geo_ph.setVisible(False)
        lo.addWidget(pw)

    def _draw_timeline(self):
        if self.df is None: return
        df = self.df
        if "Timestamp" not in df.columns or df["Timestamp"].isna().all():
            self._tl_ph.setVisible(True); return

        gran = self._tl_combo.currentText()
        df_t = df.dropna(subset=["Timestamp"]).copy()
        if gran == "Hourly":  df_t["B"] = df_t["Timestamp"].dt.floor("h")
        elif gran == "Daily": df_t["B"] = df_t["Timestamp"].dt.date
        else:                 df_t["B"] = df_t["Timestamp"].dt.to_period("W").dt.start_time

        serie = df_t.groupby("B").size()
        if serie.empty: self._tl_ph.setVisible(True); return

        pw = _pg_line([str(k) for k in serie.index], serie.values.tolist())
        lo = self._tl_inner.layout()
        while lo.count():
            it = lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        self._tl_ph.setVisible(False)
        lo.addWidget(pw)

    def _draw_users(self, df):
        if "Usuario" not in df.columns:
            self._usr_ph.setVisible(True); return
        top_u = (df[df["Usuario"] != "—"]["Usuario"]
                 .value_counts().head(12).sort_values())
        if top_u.empty:
            self._usr_ph.setVisible(True); return

        pw = _pg_hbar(top_u.index.tolist(), top_u.values.tolist())
        lo = self._usr_inner.layout()
        while lo.count():
            it = lo.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        self._usr_ph.setVisible(False)
        lo.addWidget(pw)

    def _draw_patterns(self, df):
        self._tree_sub.clear()
        df2 = df.copy()
        df2["Sub"] = df2["IP_Atacante"].str.extract(r"^(\d+\.\d+\.\d+)\.")
        sr = (df2.groupby("Sub")
              .agg(IPs=("IP_Atacante","nunique"), Total=("IP_Atacante","count"))
              .reset_index().sort_values("Total", ascending=False).head(20))
        for _, r in sr.iterrows():
            it = QTreeWidgetItem([f"{r['Sub']}.0/24", str(r["IPs"]), str(r["Total"])])
            it.setForeground(0, QBrush(QColor(ACCENT)))
            it.setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
            it.setTextAlignment(2, Qt.AlignmentFlag.AlignCenter)
            self._tree_sub.addTopLevelItem(it)

        self._tree_ports.clear()
        if "Puerto" in df.columns:
            for p, n in df[df["Puerto"] != "—"]["Puerto"].value_counts().head(15).items():
                it = QTreeWidgetItem([str(p), str(n)])
                it.setForeground(0, QBrush(QColor(WARN)))
                it.setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
                self._tree_ports.addTopLevelItem(it)

    # ────────────────────────────────────────────────────── LÓGICA ──
    def _load(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Open Sophos Log", "", "CSV files (*.csv);;All files (*.*)")
        if f:
            self._file = f
            name = os.path.basename(f)
            disp = name if len(name) <= 28 else name[:25] + "..."
            self._file_lbl.setText(disp)
            self._file_lbl.setStyleSheet(
                f"color:{T('ACCENT')};font-size:10px;background:transparent;")
            self._tb_file.setText(name)
            self._tb_file.setStyleSheet(
                f"color:{T('INK2')};font-size:10px;background:transparent;")
            self.btn_run.setEnabled(True)

    def _run(self):
        if not hasattr(self, "_file"): return
        self.btn_run.setEnabled(False); self.btn_run.setText("Analyzing…")
        self._btn_map_2d.setEnabled(False); self._btn_map_3d.setEnabled(False)
        self._btn_aegis.setEnabled(False);  self.btn_export.setEnabled(False)
        self._pbar.setVisible(True)
        self._console_write(f"Analysis started  {datetime.now().strftime('%H:%M:%S')}")
        self._aw = AnalysisWorker(self._file, list(self._wl))
        self._aw.progress.connect(self.btn_run.setText)
        self._aw.log.connect(self._console_write)
        self._aw.finished.connect(self._on_done)
        self._aw.error.connect(self._on_err)
        self._aw.start()

    def _on_done(self, df, df_map, n_ips, n_events):
        self.df     = df
        self.df_map = df_map

        crit = (df[df["Severidad"] == "CRITICAL"]["IP_Atacante"].nunique()
                if "Severidad" in df.columns else 0)
        usr  = (df[df["Usuario"] != "—"]["Usuario"].nunique()
                if "Usuario" in df.columns else 0)

        self.m_ips.set(n_ips); self.m_events.set(n_events)
        self.m_ctrs.set(df["Pais"].nunique()); self.m_crit.set(crit)
        for k, v in [("events",n_events), ("ips",n_ips),
                     ("countries",df["Pais"].nunique()),
                     ("critical",crit), ("users",usr)]:
            self._kpi[k].set(v)

        self._draw_table(df)
        self._draw_dashboard(df)
        self._draw_geo(df)
        self._draw_timeline()
        self._draw_users(df)
        self._draw_patterns(df)

        self._btn_map_2d.setEnabled(True); self._btn_map_3d.setEnabled(True)
        self._btn_aegis.setEnabled(True);  self.btn_export.setEnabled(True)
        self.btn_run.setEnabled(True);     self.btn_run.setText("Run analysis")
        self._pbar.setVisible(False)

        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        db_history_add(ts, os.path.basename(self._file),
                       n_ips, n_events, df["Pais"].nunique())
        self._hist_tbl_add_row(ts, os.path.basename(self._file),
                               n_ips, n_events, df["Pais"].nunique())

        self._dash_status.setText(
            f"Analysis complete  ·  {n_ips:,} unique IPs  ·  "
            f"{n_events:,} events  ·  {df['Pais'].nunique()} countries")
        self._console_write(f"Done  ·  {n_ips} IPs  ·  {n_events} events")

        QMessageBox.information(self, "KATANA",
            f"Analysis complete.\n\n"
            f"  {n_ips:,} unique attacker IPs\n"
            f"  {n_events:,} total events\n"
            f"  {df['Pais'].nunique()} countries of origin")

    def _on_err(self, msg):
        self.btn_run.setEnabled(True); self.btn_run.setText("Run analysis")
        self._pbar.setVisible(False)
        QMessageBox.critical(self, "Analysis Error", msg)

    # ────────────────────────────────────────────────────── MAPS ──
    def _map_2d(self):
        if self.df_map is None or (hasattr(self.df_map,"empty") and self.df_map.empty): return
        import plotly.express as px
        fig = px.choropleth(
            self.df_map, locations="Pais", locationmode="country names",
            color="Total_Ataques", hover_name="Pais",
            color_continuous_scale="Blues",
            title="KATANA v0.8  ·  Global Attack Distribution")
        fig.update_layout(
            paper_bgcolor="#1C1C1E", plot_bgcolor="#1C1C1E",
            font=dict(family="IBM Plex Sans,sans-serif", color="#F2F2F7"),
            geo=dict(showframe=False, showcoastlines=True,
                     coastlinecolor="#48484A", bgcolor="#2C2C2E",
                     projection_type="equirectangular"))
        p = os.path.abspath("katana_map.html")
        fig.write_html(p); webbrowser.open(f"file://{p}")

    def _map_3d(self):
        if self.df is None: return
        try:
            import plotly.express as px
            df = self.df.dropna(subset=["Lat","Lon"])
            df = df[df["Lat"] != 0.0]
            cnt = df.groupby(["IP_Atacante","Pais","Lat","Lon"]).size().reset_index(name="Events")
            fig = px.scatter_geo(
                cnt, lat="Lat", lon="Lon", color="Events",
                hover_name="IP_Atacante", size="Events", size_max=28,
                color_continuous_scale="Blues", projection="orthographic",
                title="KATANA v0.8  ·  3D Attack Globe")
            fig.update_layout(
                paper_bgcolor="#1C1C1E",
                font=dict(family="IBM Plex Sans,sans-serif", color="#F2F2F7"),
                geo=dict(bgcolor="#2C2C2E", showland=True, landcolor="#3A3A3C",
                         showocean=True, oceancolor="#1C1C1E",
                         showcoastlines=True, coastlinecolor="#48484A"))
            p = os.path.abspath("katana_globe.html")
            fig.write_html(p); webbrowser.open(f"file://{p}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ────────────────────────────────────────────────────── AEGIS ──
    def _aegis_run(self):
        if self.df is None: return
        fw_ip  = self.fw_ip.text().strip()
        fw_prt = self.fw_port.text().strip()
        fw_usr = self.fw_user.text().strip()
        fw_pw  = self.fw_pass.text().strip()
        dry    = self._chk_dry.isChecked()

        if not dry and not all([fw_ip, fw_prt, fw_usr, fw_pw]):
            QMessageBox.warning(self, "AEGIS", "Fill in all firewall credentials."); return

        sel = self._combo_lim.currentText()
        ips = (self.df["IP_Atacante"].value_counts().index.tolist() if sel == "All IPs"
               else self.df["IP_Atacante"].value_counts()
                        .head(int(sel.split()[1])).index.tolist())

        if not dry:
            r = QMessageBox.question(
                self, "Confirm AEGIS",
                f"Mode: LIVE  [{fw_ip}]\nIPs to inject: {len(ips)}\n\nProceed?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes: return

        self._btn_aegis.setEnabled(False); self._btn_aegis.setText("Running…")
        self._console_write(
            f"\nAEGIS → {'DRY RUN' if dry else 'LIVE  ['+fw_ip+']'}  · {len(ips)} targets")
        self._egw = AegisWorker(fw_ip, fw_prt, fw_usr, fw_pw, ips, dry=dry)
        self._egw.log.connect(self._console_write)
        self._egw.finished.connect(
            lambda ok, tot: (
                self._console_write(f"\nAEGIS complete · {ok}/{tot} IPs processed"),
                self._btn_aegis.setEnabled(True),
                self._btn_aegis.setText("Inject rules into firewall")
            ))
        self._egw.start()

    # ────────────────────────────────────────────────────── FILTER ──
    def _filter_table(self, ip_f, country_f, sev_f):
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            it   = root.child(i)
            show = True
            if ip_f      and ip_f.lower()      not in it.text(2).lower(): show = False
            if country_f and country_f.lower() not in it.text(1).lower(): show = False
            if sev_f != "All" and it.text(0) != sev_f:                    show = False
            it.setHidden(not show)

    # ────────────────────────────────────────────────────── MENUS ──
    def _ip_menu(self):
        m = QMenu(self)
        m.addAction("Copy all IPs to clipboard", self._copy_all_ips)
        m.addAction("Export visible IPs as IOC",  self._export_visible_ioc)
        m.addSeparator()
        m.addAction("Sort by attempts ↓",
                    lambda: self.tree.sortByColumn(3, Qt.SortOrder.DescendingOrder))
        m.exec(QCursor.pos())

    def _row_menu(self, pos):
        it = self.tree.itemAt(pos)
        if not it: return
        ip = it.text(2); m = QMenu(self)
        m.addAction(f"Copy  {ip}",
                    lambda: QApplication.clipboard().setText(ip))
        m.addAction("Add to whitelist",
                    lambda ip=ip: (
                        self._wl.add(ip),
                        db_whitelist_save(self._wl),
                        QMessageBox.information(
                            self, "Whitelist",
                            f"{ip} added to whitelist.\n\n"
                            f"Will be excluded from the next analysis run.\n"
                            f"Persisted to disk.")
                    ))
        m.addSeparator()
        m.addAction("VirusTotal  ↗",
                    lambda: webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}"))
        m.addAction("AbuseIPDB  ↗",
                    lambda: webbrowser.open(f"https://www.abuseipdb.com/check/{ip}"))
        m.addAction("Shodan  ↗",
                    lambda: webbrowser.open(f"https://www.shodan.io/host/{ip}"))
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _copy_all_ips(self):
        if self.df is None: return
        QApplication.clipboard().setText("\n".join(self.df["IP_Atacante"].unique()))

    def _export_visible_ioc(self):
        root = self.tree.invisibleRootItem()
        ips  = [root.child(i).text(2) for i in range(root.childCount())
                if not root.child(i).isHidden()]
        p = f"IOC_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"# KATANA IOC  {datetime.now()}\n"); f.write("\n".join(ips))
        QMessageBox.information(self, "Exported", f"{len(ips)} IPs → {p}")

    # ────────────────────────────────────────────────────── WHITELIST ──
    def _whitelist_dlg(self):
        WhitelistDialog(self._wl, self).exec()

    # ────────────────────────────────────────────────────── EXPORT ──
    def _export(self):
        if self.df is None: return
        ExportDialog(self.df, self.df_map, self).exec()

    # ────────────────────────────────────────────────────── HISTORY ──
    def _hist_tbl_add_row(self, ts, filename, n_ips, n_events, n_ctrs):
        r = self._hist_tbl.rowCount()
        self._hist_tbl.insertRow(0)   # más reciente arriba
        for c, v in enumerate([ts, filename, str(n_ips), str(n_events), str(n_ctrs)]):
            it = QTableWidgetItem(v)
            it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._hist_tbl.setItem(0, c, it)

    def _clear_history(self):
        db_history_clear()
        self._hist_tbl.setRowCount(0)

    # ────────────────────────────────────────────────────── CONSOLE ──
    def _console_write(self, text):
        self._console.append(text)
        sb = self._console.verticalScrollBar(); sb.setValue(sb.maximum())


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    splash = SplashScreen()
    splash.show()
    app.processEvents()

    _main_win = None

    def _launch():
        global _main_win
        splash.hide()
        _main_win = KatanaApp()
        _main_win.show()
        splash.deleteLater()

    splash.done.connect(_launch)
    sys.exit(app.exec())