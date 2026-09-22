"""
ui/styles.py

Hoja de estilos Qt para mantener la misma línea visual que RobotEye
(tema oscuro, acentos cian/verde de terminal).
"""

DARK_STYLESHEET = """
QWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 13px;
}

QMainWindow {
    background-color: #0d1117;
}

QLabel#TitleLabel {
    font-size: 20px;
    font-weight: bold;
    color: #39d0d8;
}

QLabel#SubtitleLabel {
    color: #6e7681;
    font-size: 12px;
}

QLineEdit, QSpinBox, QComboBox {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 6px 8px;
    color: #c9d1d9;
}

QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1px solid #39d0d8;
}

QPushButton {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 8px 16px;
    color: #c9d1d9;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #30363d;
    border: 1px solid #39d0d8;
}

QPushButton:disabled {
    color: #484f58;
}

QPushButton#ScanButton {
    background-color: #1f6feb;
    border: none;
    color: white;
}

QPushButton#ScanButton:hover {
    background-color: #388bfd;
}

QPushButton#CancelButton {
    background-color: #da3633;
    border: none;
    color: white;
}

QPushButton#CancelButton:hover {
    background-color: #f85149;
}

QCheckBox {
    spacing: 6px;
}

QProgressBar {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    text-align: center;
    color: #c9d1d9;
}

QProgressBar::chunk {
    background-color: #39d0d8;
    border-radius: 3px;
}

QPlainTextEdit#LogConsole {
    background-color: #010409;
    border: 1px solid #30363d;
    color: #58a6ff;
    font-family: "JetBrains Mono", "Consolas", monospace;
}

QTreeWidget {
    background-color: #161b22;
    border: 1px solid #30363d;
    alternate-background-color: #1c2128;
}

QTreeWidget::item {
    padding: 4px;
}

QHeaderView::section {
    background-color: #21262d;
    color: #c9d1d9;
    padding: 6px;
    border: none;
    border-bottom: 1px solid #30363d;
}

QTabWidget::pane {
    border: 1px solid #30363d;
    background-color: #0d1117;
}

QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    padding: 8px 16px;
    border: 1px solid #30363d;
    border-bottom: none;
}

QTabBar::tab:selected {
    background-color: #0d1117;
    color: #39d0d8;
    border-bottom: 2px solid #39d0d8;
}

QScrollBar:vertical {
    background: #0d1117;
    width: 10px;
}

QScrollBar::handle:vertical {
    background: #30363d;
    border-radius: 5px;
    min-height: 20px;
}
"""

SEVERITY_COLORS = {
    "CRITICO": "#f85149",
    "ALTO": "#ffa657",
    "MEDIO": "#e3b341",
    "BAJO": "#3fb950",
    "INFO": "#58a6ff",
}
