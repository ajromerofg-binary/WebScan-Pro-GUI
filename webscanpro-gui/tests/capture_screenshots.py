#!/usr/bin/env python3
"""
tests/capture_screenshots.py

Genera capturas de pantalla REALES de la aplicación (no maquetas) para
los manuales: arranca la ventana en modo offscreen, ejecuta un escaneo
real contra el servidor de pruebas y guarda el estado resultante.
"""
import os
import sys
import time

os.environ["QT_QPA_PLATFORM"] = "offscreen"
if hasattr(os, "geteuid") and os.geteuid() == 0:
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer, QEventLoop

from ui.main_window import MainWindow

OUT_DIR = "/tmp/screenshots"
os.makedirs(OUT_DIR, exist_ok=True)


def save_shot(widget, name):
    pix = widget.grab()
    path = os.path.join(OUT_DIR, f"{name}.png")
    pix.save(path)
    print(f"Guardado: {path} ({pix.width()}x{pix.height()})")


def main():
    app = QApplication(sys.argv)
    win = MainWindow(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webscanpro.sh"))
    win.resize(1100, 750)
    win.show()

    # 1) Estado inicial: panel de configuración vacío
    win.url_input.setText("")
    app.processEvents()
    save_shot(win, "01_inicial")

    # 2) Configuración rellena, lista para escanear — limitamos a
    # headers + sqli (ya validados exhaustivamente) para una captura
    # rápida y determinista; no necesitamos los 12 módulos para
    # ilustrar el flujo de la interfaz.
    win.url_input.setText("http://127.0.0.1:8801/buscar?q=test")
    for key, cb in win.module_checks.items():
        cb.setChecked(key in ("headers", "sqli"))
    app.processEvents()
    save_shot(win, "02_configurado")

    # 3) Lanzar un escaneo REAL (headers + sqli) contra el servidor de
    # pruebas y esperar a que termine, para capturar resultados reales.
    loop = QEventLoop()
    win.worker_finished_ok = False

    def on_finished(ok, result, error):
        win.worker_finished_ok = ok
        loop.quit()

    win._start_scan()
    if win.worker:
        win.worker.finished_scan.connect(on_finished)
        QTimer.singleShot(120000, loop.quit)  # salvaguarda anti-colgado
        loop.exec()
        # Asegurar que el hilo ha terminado de verdad antes de seguir
        # (si no, Qt aborta el proceso al destruir un QThread en marcha).
        win.worker.wait(5000)

    app.processEvents()
    time.sleep(0.3)
    app.processEvents()
    save_shot(win, "03_resultados")

    # 4) Detalle de un hallazgo concreto
    if win.results_tree.topLevelItemCount() > 0:
        item = win.results_tree.topLevelItem(0)
        win.results_tree.setCurrentItem(item)
        win._show_finding_detail(item, 0)
        app.processEvents()
        save_shot(win, "04_detalle_hallazgo")

    print("Escaneo de la captura terminó OK:", win.worker_finished_ok)
    app.quit()


if __name__ == "__main__":
    main()
