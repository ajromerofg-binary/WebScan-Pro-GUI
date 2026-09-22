"""
ui/main_window.py

Ventana principal de WebScan Pro GUI.
Tres zonas: configuración del escaneo, progreso en vivo con consola,
y resultados (árbol de hallazgos + informe HTML embebido).
"""

import os
import sys
import webbrowser

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QSpinBox, QPushButton, QCheckBox, QGroupBox,
    QProgressBar, QPlainTextEdit, QTreeWidget, QTreeWidgetItem,
    QTabWidget, QMessageBox, QGridLayout, QFileDialog, QSplitter,
)

from core.scanner import ScannerWorker, SCAN_MODULES, ScanResult
from ui.styles import SEVERITY_COLORS

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    HAS_WEBENGINE = True
except ImportError:
    HAS_WEBENGINE = False


class MainWindow(QMainWindow):
    def __init__(self, script_path: str):
        super().__init__()
        self.script_path = script_path
        self.worker: ScannerWorker | None = None
        self.last_result: ScanResult | None = None

        self.setWindowTitle("WebScan Pro — GUI")
        self.resize(1100, 750)

        self._build_ui()

    # ------------------------------------------------------------------
    # Construcción de la UI
    # ------------------------------------------------------------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        root.addLayout(self._build_header())
        root.addWidget(self._build_config_group())

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_progress_panel())
        splitter.addWidget(self._build_results_panel())
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, stretch=1)

    def _build_header(self) -> QVBoxLayout:
        layout = QVBoxLayout()
        title = QLabel("WEBSCAN PRO")
        title.setObjectName("TitleLabel")
        subtitle = QLabel("Escáner de vulnerabilidades web · OWASP Top 10 · Sr.Robot Labs")
        subtitle.setObjectName("SubtitleLabel")
        layout.addWidget(title)
        layout.addWidget(subtitle)
        return layout

    def _build_config_group(self) -> QGroupBox:
        group = QGroupBox("Configuración del escaneo")
        outer = QVBoxLayout(group)

        form = QFormLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://objetivo.com")
        form.addRow("URL objetivo:", self.url_input)

        row = QHBoxLayout()
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 120)
        self.timeout_input.setValue(12)
        self.timeout_input.setSuffix(" s")
        row.addWidget(QLabel("Timeout:"))
        row.addWidget(self.timeout_input)

        row.addSpacing(20)
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setPlaceholderText("(por defecto: ~/Desktop/WebScan_<timestamp>)")
        browse_btn = QPushButton("Elegir carpeta…")
        browse_btn.clicked.connect(self._choose_output_dir)
        row.addWidget(QLabel("Salida:"))
        row.addWidget(self.output_dir_input, stretch=1)
        row.addWidget(browse_btn)
        outer.addLayout(form)
        outer.addLayout(row)

        # Selector de módulos (checkboxes en vez de --only por CLI)
        modules_box = QGroupBox("Módulos a ejecutar")
        grid = QGridLayout(modules_box)
        self.module_checks: dict[str, QCheckBox] = {}
        for i, (key, title) in enumerate(SCAN_MODULES):
            if key == "fingerprint":
                label = "Fingerprinting"
            else:
                label = title.split("(")[0].strip().title()
            cb = QCheckBox(label)
            cb.setChecked(True)
            self.module_checks[key] = cb
            grid.addWidget(cb, i // 4, i % 4)
        outer.addWidget(modules_box)

        select_row = QHBoxLayout()
        all_btn = QPushButton("Marcar todos")
        all_btn.clicked.connect(lambda: self._set_all_modules(True))
        none_btn = QPushButton("Desmarcar todos")
        none_btn.clicked.connect(lambda: self._set_all_modules(False))
        select_row.addWidget(all_btn)
        select_row.addWidget(none_btn)
        select_row.addStretch()

        self.scan_btn = QPushButton("▶  Iniciar escaneo")
        self.scan_btn.setObjectName("ScanButton")
        self.scan_btn.clicked.connect(self._start_scan)
        self.cancel_btn = QPushButton("■  Cancelar")
        self.cancel_btn.setObjectName("CancelButton")
        self.cancel_btn.clicked.connect(self._cancel_scan)
        self.cancel_btn.setEnabled(False)
        select_row.addWidget(self.scan_btn)
        select_row.addWidget(self.cancel_btn)
        outer.addLayout(select_row)

        return group

    def _build_progress_panel(self) -> QGroupBox:
        group = QGroupBox("Progreso")
        layout = QVBoxLayout(group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.current_module_label = QLabel("Sin escaneo en curso")
        self.current_module_label.setObjectName("SubtitleLabel")

        self.live_counts_label = QLabel(self._format_counts({}))
        layout.addWidget(self.current_module_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.live_counts_label)

        self.log_console = QPlainTextEdit()
        self.log_console.setObjectName("LogConsole")
        self.log_console.setReadOnly(True)
        layout.addWidget(QLabel("Consola:"))
        layout.addWidget(self.log_console, stretch=1)

        return group

    def _build_results_panel(self) -> QGroupBox:
        group = QGroupBox("Resultados")
        layout = QVBoxLayout(group)

        self.tabs = QTabWidget()

        # Pestaña 1: árbol estructurado de hallazgos
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Severidad", "Hallazgo", "Categoría"])
        self.results_tree.setAlternatingRowColors(True)
        self.results_tree.itemClicked.connect(self._show_finding_detail)
        self.tabs.addTab(self.results_tree, "Hallazgos")

        self.detail_panel = QPlainTextEdit()
        self.detail_panel.setReadOnly(True)
        self.tabs.addTab(self.detail_panel, "Detalle")

        # Pestaña 2: informe HTML embebido (usa el que ya genera el script)
        self.html_view = None
        if HAS_WEBENGINE:
            try:
                self.html_view = QWebEngineView()
                self.tabs.addTab(self.html_view, "Informe HTML")
            except Exception as e:
                # No debería llegar aquí si main.py fijó --no-sandbox bajo
                # root, pero si WebEngine falla por cualquier otro motivo
                # (librerías del sistema ausentes, etc.) no queremos tirar
                # abajo toda la ventana por la pestaña de informe HTML.
                self.html_view = None
                placeholder = QLabel(
                    f"No se pudo inicializar el visor HTML embebido:\n{e}\n\n"
                    "Usa el botón 'Abrir HTML en navegador' como alternativa."
                )
                placeholder.setAlignment(Qt.AlignCenter)
                placeholder.setWordWrap(True)
                self.tabs.addTab(placeholder, "Informe HTML")
        else:
            placeholder = QLabel(
                "QtWebEngine no está instalado.\n"
                "Instala 'PySide6-WebEngine' para ver el informe HTML embebido,\n"
                "o usa el botón 'Abrir informes' para abrirlo en el navegador."
            )
            placeholder.setAlignment(Qt.AlignCenter)
            self.tabs.addTab(placeholder, "Informe HTML")

        layout.addWidget(self.tabs)

        actions = QHBoxLayout()
        self.open_reports_btn = QPushButton("Abrir carpeta de informes")
        self.open_reports_btn.setEnabled(False)
        self.open_reports_btn.clicked.connect(self._open_reports_folder)
        self.open_html_btn = QPushButton("Abrir HTML en navegador")
        self.open_html_btn.setEnabled(False)
        self.open_html_btn.clicked.connect(self._open_html_report)
        actions.addWidget(self.open_reports_btn)
        actions.addWidget(self.open_html_btn)
        actions.addStretch()
        layout.addLayout(actions)

        return group

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _set_all_modules(self, checked: bool):
        for cb in self.module_checks.values():
            cb.setChecked(checked)

    def _choose_output_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Elegir carpeta de salida")
        if path:
            self.output_dir_input.setText(path)

    def _format_counts(self, counts: dict) -> str:
        parts = []
        for sev in ["CRITICO", "ALTO", "MEDIO", "BAJO", "INFO"]:
            n = counts.get(sev, 0)
            color = SEVERITY_COLORS[sev]
            parts.append(f'<span style="color:{color}">● {sev}: {n}</span>')
        return "&nbsp;&nbsp;".join(parts)

    # ------------------------------------------------------------------
    # Lanzar / cancelar escaneo
    # ------------------------------------------------------------------
    def _selected_modules(self) -> list[str]:
        return [k for k, cb in self.module_checks.items() if cb.isChecked()]

    def _start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Falta URL", "Introduce una URL objetivo antes de escanear.")
            return

        selected = self._selected_modules()
        if not selected:
            QMessageBox.warning(self, "Sin módulos", "Selecciona al menos un módulo a ejecutar.")
            return

        # El motor acepta una lista de módulos separada por comas
        # (--only headers,sqli,xss); si están todos marcados no hace
        # falta pasar --only en absoluto (escaneo completo, incluye
        # fingerprinting, que no tiene checkbox propio).
        only_module = None
        if len(selected) != len(SCAN_MODULES):
            only_module = ",".join(selected)

        self.log_console.clear()
        self.results_tree.clear()
        self.detail_panel.clear()
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.open_reports_btn.setEnabled(False)
        self.open_html_btn.setEnabled(False)

        self.worker = ScannerWorker(
            script_path=self.script_path,
            target_url=url,
            timeout=self.timeout_input.value(),
            output_dir=self.output_dir_input.text().strip() or None,
            only_module=only_module,
        )
        self.worker.module_started.connect(self._on_module_started)
        self.worker.log_line.connect(self._on_log_line)
        self.worker.finding_seen.connect(self._on_finding_seen)
        self.worker.finished_scan.connect(self._on_scan_finished)
        self.worker.start()

    def _cancel_scan(self):
        if self.worker:
            self.worker.cancel()
        self.cancel_btn.setEnabled(False)

    # ------------------------------------------------------------------
    # Slots de progreso
    # ------------------------------------------------------------------
    def _on_module_started(self, idx: int, total: int, title: str):
        pct = int(((idx + 1) / total) * 90)  # deja margen para "generando informes"
        self.progress_bar.setValue(pct)
        self.current_module_label.setText(f"Ejecutando módulo {idx + 1}/{total}: {title}")

    def _on_log_line(self, line: str):
        self.log_console.appendPlainText(line)
        sb = self.log_console.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_finding_seen(self, severity: str, name: str):
        # feedback inmediato en la barra de progreso mientras corre
        self.current_module_label.setText(f"[{severity}] {name}")

    def _on_scan_finished(self, ok: bool, result: ScanResult | None, error: str):
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

        if not ok or result is None:
            self.progress_bar.setValue(0)
            self.current_module_label.setText("Escaneo fallido")
            QMessageBox.critical(self, "Error en el escaneo", error or "Error desconocido.")
            return

        self.progress_bar.setValue(100)
        self.current_module_label.setText(
            f"Completado — riesgo {result.risk_level} (score {result.risk_score})"
        )
        self.live_counts_label.setText(self._format_counts(result.counts))
        self.last_result = result

        self._populate_results_tree(result)
        self._load_html_report(result)

        self.open_reports_btn.setEnabled(bool(result.output_dir))
        self.open_html_btn.setEnabled(bool(result.output_dir))

    # ------------------------------------------------------------------
    # Resultados
    # ------------------------------------------------------------------
    def _populate_results_tree(self, result: ScanResult):
        self.results_tree.clear()
        order = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3, "INFO": 4}
        findings = sorted(result.findings, key=lambda f: order.get(f.severity, 5))
        for f in findings:
            item = QTreeWidgetItem([f.severity, f.name, f.category])
            color = SEVERITY_COLORS.get(f.severity)
            if color:
                from PySide6.QtGui import QColor
                item.setForeground(0, QColor(color))
            item.setData(0, Qt.UserRole, f)
            self.results_tree.addTopLevelItem(item)
        for i in range(3):
            self.results_tree.resizeColumnToContents(i)

    def _show_finding_detail(self, item: QTreeWidgetItem, _col: int):
        f = item.data(0, Qt.UserRole)
        if not f:
            return
        text = (
            f"ID: {f.id}\n"
            f"Severidad: {f.severity}\n"
            f"Categoría: {f.category}\n\n"
            f"Descripción:\n{f.description}\n\n"
            f"Evidencia:\n{f.evidence}\n\n"
            f"Recomendación:\n{f.recommendation}\n"
        )
        self.detail_panel.setPlainText(text)
        self.tabs.setCurrentWidget(self.detail_panel)

    def _load_html_report(self, result: ScanResult):
        if not self.html_view or not result.output_dir:
            return
        html_path = os.path.join(result.output_dir, "informe_completo.html")
        if os.path.exists(html_path):
            from PySide6.QtCore import QUrl
            self.html_view.load(QUrl.fromLocalFile(os.path.abspath(html_path)))

    def _open_reports_folder(self):
        if self.last_result and self.last_result.output_dir:
            path = self.last_result.output_dir
            if sys.platform.startswith("linux"):
                os.system(f'xdg-open "{path}"')
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.startfile(path)  # type: ignore[attr-defined]

    def _open_html_report(self):
        if self.last_result and self.last_result.output_dir:
            html_path = os.path.join(self.last_result.output_dir, "informe_completo.html")
            if os.path.exists(html_path):
                webbrowser.open(f"file://{os.path.abspath(html_path)}")
