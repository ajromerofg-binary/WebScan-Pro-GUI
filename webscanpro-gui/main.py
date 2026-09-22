#!/usr/bin/env python3
"""
WebScan Pro GUI — punto de entrada.

Aplicación de escritorio (PySide6) que envuelve el motor webscanpro.sh
sin reimplementar su lógica de detección: lo ejecuta como subproceso,
muestra progreso en vivo y presenta los hallazgos y el informe HTML
que el propio script genera.
"""

import os
import sys

# IMPORTANTE: debe fijarse ANTES de importar cualquier módulo de Qt/WebEngine.
# QtWebEngine (Chromium) hace un hard-exit nativo del proceso completo si se
# ejecuta como root sin --no-sandbox — no es una excepción de Python
# capturable, mata la app entera al construir la ventana. Herramientas de
# pentesting se ejecutan habitualmente como root (Kali, sudo), así que lo
# detectamos y lo forzamos automáticamente en ese caso.
if hasattr(os, "geteuid") and os.geteuid() == 0:
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox")

from PySide6.QtWidgets import QApplication, QMessageBox

from ui.main_window import MainWindow
from ui.styles import DARK_STYLESHEET


def find_script() -> str:
    """Localiza webscanpro.sh.

    Bajo PyInstaller (--onefile), los recursos empaquetados con
    --add-data se extraen en tiempo de ejecución a una carpeta temporal
    accesible vía sys._MEIPASS — buscar solo junto a __file__ (que
    apunta dentro del propio ejecutable comprimido) nunca lo encuentra.
    """
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidate = os.path.join(meipass, "webscanpro.sh")
            if os.path.exists(candidate):
                return candidate
        # Fallback: junto al propio ejecutable (por si se distribuye
        # sin --onefile, o el script se copió a mano junto al binario)
        candidate = os.path.join(os.path.dirname(sys.executable), "webscanpro.sh")
        if os.path.exists(candidate):
            return candidate

    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, "webscanpro.sh")
    if os.path.exists(candidate):
        return candidate
    # Fallback: buscar en el directorio de trabajo actual
    candidate = os.path.join(os.getcwd(), "webscanpro.sh")
    return candidate


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)
    app.setApplicationName("WebScan Pro GUI")

    script_path = find_script()
    if not os.path.exists(script_path):
        QMessageBox.critical(
            None, "webscanpro.sh no encontrado",
            f"No se ha encontrado el motor en:\n{script_path}\n\n"
            "Colócalo en el mismo directorio que main.py (o el binario)."
        )
        sys.exit(1)

    window = MainWindow(script_path)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
