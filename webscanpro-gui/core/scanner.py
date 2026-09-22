"""
core/scanner.py

Wrapper de ejecución para el motor webscanpro.sh.
No reimplementa la lógica de detección: lanza el script bash como
subproceso, parsea su stdout en tiempo real para reportar progreso
por módulo, y al finalizar localiza y carga el JSON de hallazgos
que el propio script serializa en /tmp/ws_findings_<timestamp>.json.
"""

import glob
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QThread, Signal


# Módulos en el orden en que el script los ejecuta (ver `main()` en
# webscanpro.sh). El texto de cada tupla es el título que imprime
# section() para ese módulo — se usa para detectar en qué punto del
# escaneo va la barra de progreso.
SCAN_MODULES = [
    ("headers", "SECURITY HEADERS"),
    ("sqli", "SQL INJECTION (SQLi)"),
    ("xss", "CROSS-SITE SCRIPTING (XSS)"),
    ("xxe", "XML EXTERNAL ENTITY (XXE)"),
    ("lfi", "LOCAL FILE INCLUSION (LFI)"),
    ("rfi", "REMOTE FILE INCLUSION (RFI)"),
    ("path", "PATH TRAVERSAL"),
    ("ssrf", "SERVER-SIDE REQUEST FORGERY (SSRF)"),
    ("ssti", "SERVER-SIDE TEMPLATE INJECTION (SSTI)"),
    ("cms", "DETECCIÓN DE CMS Y TECNOLOGÍAS"),
    ("files", "ARCHIVOS Y RUTAS SENSIBLES"),
    ("fingerprint", "FINGERPRINTING E INFORMACIÓN ADICIONAL"),
]

# Códigos ANSI (colores + control) que el script imprime para terminal.
# Códigos ANSI que el script imprime para terminal: no solo color/SGR
# (que terminan en 'm'), sino cualquier secuencia CSI — el motor llama
# a `clear` al iniciar, que emite control de cursor/borrado de pantalla
# (ESC[H, ESC[2J, ESC[3J, etc.), no solo color. Filtrar solo "...m"
# dejaba esas secuencias sin limpiar, apareciendo como texto corrupto
# en la consola de la GUI.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Línea de hallazgo: "  [CRÍTICO] Nombre del hallazgo" (tras limpiar ANSI)
_FINDING_RE = re.compile(r"\[(CR[ÍI]TICO|ALTO|MEDIO|BAJO|INFO)\]\s+(.+)")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


@dataclass
class Finding:
    id: str
    name: str
    severity: str
    category: str
    description: str
    evidence: str
    recommendation: str

    @classmethod
    def from_json(cls, d: dict) -> "Finding":
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            severity=d.get("severity", "INFO"),
            category=d.get("category", ""),
            description=d.get("description", ""),
            evidence=d.get("evidence", ""),
            recommendation=d.get("recommendation", ""),
        )


@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)  # severidad -> nº
    risk_score: int = 0
    risk_level: str = "BAJO"
    output_dir: str = ""
    raw_log: str = ""

    @property
    def total(self) -> int:
        return len(self.findings)


class ScannerWorker(QThread):
    """
    Ejecuta webscanpro.sh en un proceso hijo y emite señales de
    progreso mientras corre. No bloquea la UI: se lanza con .start()
    desde la ventana principal.
    """

    # (índice_módulo, total_módulos, nombre_módulo)
    module_started = Signal(int, int, str)
    # línea de log ya limpia de ANSI, para consola en vivo
    log_line = Signal(str)
    # hallazgo detectado en vivo (severidad, nombre)
    finding_seen = Signal(str, str)
    # escaneo terminado: (ok, ScanResult | None, mensaje_error)
    finished_scan = Signal(bool, object, str)

    def __init__(self, script_path: str, target_url: str, timeout: int = 12,
                 output_dir: str | None = None, only_module: str | None = None,
                 parent=None):
        super().__init__(parent)
        self.script_path = script_path
        self.target_url = target_url
        self.timeout = timeout
        self.output_dir = output_dir
        self.only_module = only_module
        self._proc = None
        self._cancelled = False

    def cancel(self):
        self._cancelled = True
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()

    def _clean_subprocess_env(self) -> dict:
        """Entorno para el subproceso bash/curl.

        Bajo PyInstaller (--onefile), el bootloader fija LD_LIBRARY_PATH
        (y en algunos casos LD_PRELOAD) para que Python/Qt encuentren
        sus propias librerías empaquetadas — pero cualquier subproceso
        lanzado (bash, y a su vez curl) HEREDA esa variable. Si curl
        termina resolviendo símbolos contra una libssl/libcrypto
        empaquetada para Qt en vez de la del sistema, puede fallar de
        forma silenciosa e inmediata (DNS/TLS rotos) aunque el mismo
        curl funcione perfectamente a mano en una terminal normal, sin
        el entorno de PyInstaller de por medio.

        PyInstaller exporta el valor ORIGINAL (previo a su propia
        modificación) en LD_LIBRARY_PATH_ORIG precisamente para que
        quien lance procesos externos pueda restaurarlo antes de
        ejecutar binarios que no deben usar las librerías empaquetadas.
        """
        env = os.environ.copy()
        if getattr(sys, "frozen", False):
            orig = env.get("LD_LIBRARY_PATH_ORIG")
            if orig is not None:
                env["LD_LIBRARY_PATH"] = orig
            else:
                env.pop("LD_LIBRARY_PATH", None)
        return env

    def run(self):
        start_time = time.time()
        cmd = ["bash", self.script_path, "-u", self.target_url, "-t", str(self.timeout)]
        if self.output_dir:
            cmd += ["-o", self.output_dir]
        if self.only_module:
            cmd += ["--only", self.only_module]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=self._clean_subprocess_env(),
            )
        except FileNotFoundError as e:
            self.finished_scan.emit(False, None, f"No se pudo lanzar el script: {e}")
            return
        except Exception as e:
            self.finished_scan.emit(False, None, f"Error al iniciar el escaneo: {e}")
            return

        if self.only_module:
            # only_module puede ser un único módulo o una lista separada
            # por comas ("headers,sqli,xss") — el motor acepta ambas.
            requested_keys = set(self.only_module.split(","))
            modules = [t for m, t in SCAN_MODULES if m in requested_keys]
        else:
            modules = [t for _, t in SCAN_MODULES]
        current_module_idx = -1
        raw_lines = []

        for raw_line in self._proc.stdout:
            if self._cancelled:
                break
            clean = strip_ansi(raw_line).rstrip("\n")
            raw_lines.append(clean)
            self.log_line.emit(clean)

            # ¿Cambio de módulo? (coincide con un título de section())
            for idx, title in enumerate(modules):
                if title in clean:
                    current_module_idx = idx
                    self.module_started.emit(idx, len(modules), title)
                    break

            # ¿Hallazgo detectado?
            m = _FINDING_RE.search(clean)
            if m:
                self.finding_seen.emit(m.group(1), m.group(2).strip())

        self._proc.wait()
        elapsed = time.time() - start_time

        if self._cancelled:
            self.finished_scan.emit(False, None, "Escaneo cancelado por el usuario.")
            return

        if self._proc.returncode != 0:
            self.finished_scan.emit(
                False, None,
                f"El script terminó con código {self._proc.returncode} tras {elapsed:.1f}s."
            )
            return

        result = self._load_result("\n".join(raw_lines))
        if result is None:
            self.finished_scan.emit(
                False, None,
                "El escaneo terminó pero no se pudo localizar el JSON de hallazgos."
            )
            return

        self.finished_scan.emit(True, result, "")

    def _load_result(self, raw_log: str) -> ScanResult | None:
        # Determinar la carpeta de salida PRIMERO: la necesitamos para
        # localizar la copia persistente del JSON (ver más abajo) antes
        # de recurrir al canal interno /tmp.
        out_dir = self.output_dir or ""
        if not out_dir:
            # El script imprime "Directorio de salida: <ruta>" en el log
            for line in raw_log.splitlines():
                if "Directorio de salida:" in line:
                    out_dir = line.split("Directorio de salida:")[-1].strip()
                    break

        # Fuente preferida: la copia persistente que el motor escribe en
        # la propia carpeta de salida (informe_hallazgos.json — con
        # json.dump() real, no el hand-rolled de /tmp). Es una ruta
        # exacta y conocida, sin la fragilidad de "buscar por glob en
        # /tmp y esperar que siga ahí" (el canal de /tmp puede fallar
        # por motivos ajenos al escaneo en sí: limpieza del sistema,
        # aislamiento de /tmp entre procesos, otro escaneo concurrente
        # pisando el más reciente, etc. — ninguno de los cuales indica
        # que el escaneo haya ido mal).
        raw_findings = None
        if out_dir:
            preferred_path = os.path.join(out_dir, "informe_hallazgos.json")
            if os.path.exists(preferred_path):
                try:
                    with open(preferred_path, "r", encoding="utf-8") as f:
                        raw_findings = json.load(f)
                except (json.JSONDecodeError, OSError):
                    raw_findings = None

        # Fallback: el canal interno /tmp (compatibilidad con motores
        # antiguos que no escriban todavía la copia persistente).
        if raw_findings is None:
            candidates = sorted(
                glob.glob("/tmp/ws_findings_*.json"),
                key=os.path.getmtime,
                reverse=True,
            )
            if not candidates:
                return None
            try:
                with open(candidates[0], "r", encoding="utf-8") as f:
                    raw_findings = json.load(f)
            except (json.JSONDecodeError, OSError):
                return None

        findings = [Finding.from_json(d) for d in raw_findings]
        counts = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "INFO": 0}
        for f_ in findings:
            counts[f_.severity] = counts.get(f_.severity, 0) + 1

        score = counts["CRITICO"] * 10 + counts["ALTO"] * 5 + counts["MEDIO"] * 3 + counts["BAJO"] * 1
        if score >= 20:
            level = "CRITICO"
        elif score >= 10:
            level = "ALTO"
        elif score >= 5:
            level = "MEDIO"
        else:
            level = "BAJO"

        return ScanResult(
            target=self.target_url,
            findings=findings,
            counts=counts,
            risk_score=score,
            risk_level=level,
            output_dir=out_dir,
            raw_log=raw_log,
        )
