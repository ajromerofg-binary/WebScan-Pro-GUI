#!/usr/bin/env python3
"""
docs/build_manual_tecnico.py
Genera el Manual Técnico de WebScan Pro GUI (PDF).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from reportlab.platypus import Paragraph, PageBreak, KeepTogether, NextPageTemplate, Spacer
from reportlab.lib.units import cm

from pdf_common import build_styles, make_doc, cover_page, screenshot, bullet_list, simple_table, code_block

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
OUT_PATH = "/mnt/user-data/outputs/WebScanPro_GUI_Manual_Tecnico.pdf"

styles = build_styles()
doc = make_doc(OUT_PATH, "Manual Técnico")
story = []

cover_page(
    story, styles,
    subtitle="Arquitectura, motor de detección y guía de mantenimiento",
    doc_label="MANUAL TÉCNICO",
    version="1.0",
    date_str="Septiembre 2026",
)
story.insert(0, NextPageTemplate("Body"))

# ═══════════════════════════════════════════════════════════════════
# ÍNDICE
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("Índice", styles["H1"]))
toc_entries = [
    "1. Arquitectura general",
    "2. Estructura del proyecto",
    "3. El motor: webscanpro.sh",
    "4. El wrapper: core/scanner.py",
    "5. La interfaz: ui/main_window.py",
    "6. Módulos de detección (detalle técnico)",
    "7. Formato de datos: JSON de hallazgos",
    "8. Metodología de testing y regresión",
    "9. Bugs corregidos durante el desarrollo",
    "10. Empaquetado y despliegue",
    "11. Limitaciones conocidas y roadmap",
]
for e in toc_entries:
    story.append(Paragraph(e, styles["TOCEntry"]))
story.append(PageBreak())

# ═══════════════════════════════════════════════════════════════════
# 1. ARQUITECTURA GENERAL
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("1. Arquitectura general", styles["H1"]))
story.append(Paragraph(
    "WebScan Pro GUI sigue el mismo patrón que RobotEye: una interfaz de escritorio en "
    "<b>PySide6</b> que envuelve un motor ya existente, sin reimplementar su lógica. El motor "
    "(<font face='Courier'>webscanpro.sh</font>) es un script Bash de ~2.190 líneas, autocontenido "
    "(solo depende de <font face='Courier'>curl</font> y <font face='Courier'>python3</font> para "
    "URL-encoding y generación de informes), que se ejecuta como subproceso.",
    styles["Body"],
))
story.append(Paragraph(
    "El flujo de datos es: <b>GUI → subprocess.Popen(bash webscanpro.sh ...) → stdout parseado "
    "en vivo para progreso → JSON de hallazgos en /tmp leído al finalizar → árbol de resultados "
    "+ informe HTML embebido</b>.",
    styles["Body"],
))
story.append(Paragraph(
    "Decisión de diseño clave: la GUI nunca reimplementa lógica de detección. Todo lo que sabe "
    "hacer el motor en CLI sigue funcionando igual desde ahí; la GUI es una capa de presentación "
    "y orquestación, no una reescritura.",
    styles["CalloutInfo"],
))

# ═══════════════════════════════════════════════════════════════════
# 2. ESTRUCTURA DEL PROYECTO
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("2. Estructura del proyecto", styles["H1"]))
story.append(code_block(
    "webscanpro-gui/\n"
    "+-- main.py                  # punto de entrada\n"
    "+-- webscanpro.sh             # motor original, sin modificar en su lógica\n"
    "+-- requirements.txt\n"
    "+-- core/\n"
    "|   `-- scanner.py           # QThread: subprocess + parseo + carga de resultados\n"
    "+-- ui/\n"
    "|   +-- main_window.py       # configuración, progreso, resultados\n"
    "|   `-- styles.py             # tema oscuro/cyberpunk\n"
    "+-- tests/\n"
    "|   +-- test_scanner.py       # tests unitarios del wrapper (pytest)\n"
    "|   +-- test_target_server.py # servidor HTTP de pruebas con vulns conocidas\n"
    "|   +-- run_regression.sh     # batería de regresión end-to-end\n"
    "|   `-- capture_screenshots.py\n"
    "`-- docs/                     # este manual y su generador",
    styles["CodeBlock"],
))

# ═══════════════════════════════════════════════════════════════════
# 3. EL MOTOR
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("3. El motor: webscanpro.sh", styles["H1"]))
story.append(Paragraph(
    "El motor ejecuta hasta 12 módulos de detección en secuencia fija cuando no se filtra "
    "ningún módulo concreto:",
    styles["Body"],
))
story.append(simple_table(
    ["Orden", "Módulo", "Función bash"],
    [
        ["1", "Security Headers", "scan_security_headers"],
        ["2", "SQL Injection", "scan_sqli"],
        ["3", "XSS", "scan_xss"],
        ["4", "XXE", "scan_xxe"],
        ["5", "LFI", "scan_lfi"],
        ["6", "RFI", "scan_rfi"],
        ["7", "Path Traversal", "scan_path_traversal"],
        ["8", "SSRF", "scan_ssrf"],
        ["9", "SSTI", "scan_ssti"],
        ["10", "CMS Detection", "scan_cms"],
        ["11", "Sensitive Files", "scan_sensitive_files"],
        ["12", "Fingerprinting", "scan_fingerprint"],
    ],
    styles, col_widths=[1.8 * cm, 5.2 * cm, 6.5 * cm],
))
story.append(Paragraph("Variables globales clave", styles["H2"]))
story.append(simple_table(
    ["Variable", "Contenido", "Uso"],
    [
        ["TARGET_URL", "URL objetivo completa tal cual la dio el usuario (con su propio path/query si lo tiene).", "Base para inyecciones de parámetros (SQLi, XSS, LFI, RFI, SSRF, Path Traversal, SSTI)."],
        ["ROOT_URL", "Esquema + host + puerto, SIN el path/query del objetivo.", "Base para rutas \"bien conocidas\" del sitio (robots.txt, .env, xmlrpc.php, directory listing, etc.)."],
        ["TARGET_HOST", "Solo el host, SIN puerto (recortado explícitamente).", "Únicamente informativo (banner). No usar para construir URLs — pierde el puerto."],
    ],
    styles, col_widths=[3 * cm, 6.5 * cm, 4 * cm],
))
story.append(Paragraph(
    "La distinción TARGET_URL / ROOT_URL es el resultado directo de un bug real encontrado "
    "durante el desarrollo (ver sección 9) — antes de esta separación, varios módulos "
    "concatenaban rutas bien conocidas sobre TARGET_URL, produciendo URLs corruptas cuando el "
    "objetivo ya tenía su propio path+query.",
    styles["CalloutDanger"],
))

story.append(Paragraph("Funciones auxiliares principales", styles["H2"]))
story.append(simple_table(
    ["Función", "Qué hace"],
    [
        ["hget(url, ...)", "Wrapper de curl -sk --max-time $TIMEOUT -A $UA -L --max-redirs 3, con footer ###CODE###%{http_code} para extraer el código de estado."],
        ["get_body(resp) / get_code(resp)", "Separan cuerpo y código HTTP del footer añadido por hget."],
        ["urlencode(string)", "Percent-encoding manual carácter a carácter. Necesario porque curl reciente rechaza URLs con espacios/comillas sin codificar ('URL rejected: Malformed input')."],
        ["add_test_param(base, pname, pval)", "Añade un parámetro de prueba usando '?' o '&' según si la URL base ya tiene query string — evita URLs con dos '?'."],
        ["add_finding(id, name, sev, cat, desc, evid, rec)", "Serializa un hallazgo como objeto JSON (escapado manual de comillas/backslashes vía sed) y lo acumula en el array de hallazgos."],
    ],
    styles, col_widths=[6 * cm, 7.5 * cm],
))

# ═══════════════════════════════════════════════════════════════════
# 4. WRAPPER
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("4. El wrapper: core/scanner.py", styles["H1"]))
story.append(Paragraph(
    "<b>ScannerWorker</b> (subclase de QThread) ejecuta el motor sin bloquear la UI:",
    styles["Body"],
))
story.append(code_block(
    "class ScannerWorker(QThread):\n"
    "    module_started = Signal(int, int, str)\n"
    "    log_line = Signal(str)\n"
    "    finding_seen = Signal(str, str)\n"
    "    finished_scan = Signal(bool, object, str)\n\n"
    "    def run(self):\n"
    "        cmd = [\"bash\", self.script_path, \"-u\", self.target_url, ...]\n"
    "        self._proc = subprocess.Popen(cmd, stdout=PIPE, stderr=STDOUT, text=True)\n"
    "        for raw_line in self._proc.stdout:\n"
    "            clean = strip_ansi(raw_line)\n"
    "            self.log_line.emit(clean)\n"
    "            # detecta cambios de módulo y hallazgos en vivo por regex\n"
    "        # al terminar: localiza y parsea el JSON de hallazgos",
    styles["CodeBlock"],
))
story.append(Paragraph("Cómo se obtienen los resultados", styles["H2"]))
story.append(Paragraph(
    "El motor bash serializa los hallazgos en <font face='Courier'>/tmp/ws_findings_"
    "&lt;timestamp&gt;.json</font> (ver sección 7) y no los borra al terminar. "
    "<font face='Courier'>ScannerWorker._load_result()</font> localiza el archivo más reciente "
    "con ese patrón (<font face='Courier'>glob + max(getmtime)</font>), lo parsea, y calcula el "
    "score de riesgo ponderado:",
    styles["Body"],
))
story.append(code_block(
    "score = CRÍTICOS×10 + ALTOS×5 + MEDIOS×3 + BAJOS×1\n"
    "nivel: BAJO (<5) / MEDIO (>=5) / ALTO (>=10) / CRÍTICO (>=20)",
    styles["CodeBlock"],
))
story.append(Paragraph(
    "Si el JSON está corrupto (el motor lo serializa manualmente con sed, no con una librería "
    "JSON real — un carácter no escapado en una evidencia HTTP podría romperlo) o no se "
    "encuentra, <font face='Courier'>_load_result()</font> devuelve <font face='Courier'>None</font> "
    "y la UI muestra un error claro en vez de crashear.",
    styles["CalloutInfo"],
))

# ═══════════════════════════════════════════════════════════════════
# 5. INTERFAZ
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("5. La interfaz: ui/main_window.py", styles["H1"]))
story.append(Paragraph(
    "MainWindow se divide en tres zonas (ver capturas en el Manual de Usuario): panel de "
    "configuración, panel de progreso (consola + barra), y panel de resultados (árbol + detalle "
    "+ HTML embebido vía QWebEngineView cuando está disponible).",
    styles["Body"],
))
story.append(Paragraph("Selección de módulos", styles["H2"]))
story.append(Paragraph(
    "Los checkboxes de módulos se traducen a <font face='Courier'>--only mod1,mod2,...</font> "
    "cuando no están todos marcados. El motor acepta una lista separada por comas (ver sección "
    "9 — antes solo aceptaba un único módulo, y la GUI ejecutaba solo el primero seleccionado "
    "con un aviso).",
    styles["Body"],
))
story.append(code_block(
    "only_module = \",\".join(selected) if len(selected) != len(SCAN_MODULES) else None",
    styles["CodeBlock"],
))
story.append(Paragraph("QtWebEngine y ejecución como root", styles["H2"]))
story.append(Paragraph(
    "QtWebEngine (basado en Chromium) hace un hard-exit nativo del proceso completo si se "
    "ejecuta como root sin <font face='Courier'>--no-sandbox</font> — no es una excepción de "
    "Python capturable. Como las herramientas de pentesting se ejecutan habitualmente como root "
    "(Kali, sudo), <font face='Courier'>main.py</font> detecta esto ANTES de importar cualquier "
    "módulo de Qt:",
    styles["Body"],
))
story.append(code_block(
    "if hasattr(os, \"geteuid\") and os.geteuid() == 0:\n"
    "    os.environ.setdefault(\"QTWEBENGINE_CHROMIUM_FLAGS\", \"--no-sandbox\")\n\n"
    "from PySide6.QtWidgets import QApplication  # import DESPUÉS del guard",
    styles["CodeBlock"],
))
story.append(Paragraph(
    "El orden importa: la variable de entorno debe fijarse antes de que se cargue el módulo de "
    "WebEngine, no después.",
    styles["CalloutDanger"],
))

# ═══════════════════════════════════════════════════════════════════
# 6. MÓDULOS DE DETECCIÓN — DETALLE SQLi
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("6. Módulos de detección — detalle: SQL Injection", styles["H1"]))
story.append(Paragraph(
    "El módulo de SQLi es el más elaborado del motor: cuatro técnicas independientes, cada una "
    "probada contra un servidor de pruebas controlado con verdaderos positivos y verdaderos "
    "negativos conocidos.",
    styles["Body"],
))
story.append(simple_table(
    ["ID", "Técnica", "Criterio de confirmación"],
    [
        ["SQLI01", "Error-based", "Patrón de error SQL (MySQL/PostgreSQL/MSSQL/Oracle/SQLite) reflejado en la respuesta tras inyectar comillas/operadores."],
        ["SQLI02", "Boolean-based blind", "Respuesta TRUE ('OR '1'='1) y FALSE ('OR '1'='2) difieren ≥5%, y el baseline coincide con una de las dos (≤3%). Se descarta si el baseline ya es inestable entre dos peticiones idénticas (contenido dinámico)."],
        ["SQLI03", "UNION-based", "ORDER BY N creciente hasta que aparece un error SQL — el punto de ruptura estima el nº de columnas."],
        ["SQLI04", "Time-based blind", "Retraso ≥2500ms respecto a un baseline SIN payload (no umbral absoluto), probado contra MySQL/MariaDB (SLEEP), MSSQL (WAITFOR DELAY) y PostgreSQL (pg_sleep)."],
    ],
    styles, col_widths=[1.8 * cm, 3.8 * cm, 7.9 * cm],
))
story.append(Paragraph(
    "Todos los payloads de las 4 técnicas pasan por <font face='Courier'>urlencode()</font> "
    "antes de construir la URL — necesario porque curl rechaza directamente URLs con espacios u "
    "otros caracteres sin codificar (ver sección 9).",
    styles["Body"],
))

# ═══════════════════════════════════════════════════════════════════
# 7. FORMATO JSON
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("7. Formato de datos: JSON de hallazgos", styles["H1"]))
story.append(Paragraph(
    "Cada hallazgo se serializa como un objeto con esta forma (ver <font face='Courier'>"
    "add_finding()</font> en el motor y <font face='Courier'>Finding.from_json()</font> en el "
    "wrapper):",
    styles["Body"],
))
story.append(code_block(
    '{\n'
    '  "id": "SQLI01",\n'
    '  "name": "SQL Injection detectado (Error-Based)",\n'
    '  "severity": "CRITICO",\n'
    '  "category": "SQL Injection",\n'
    '  "description": "...",\n'
    '  "evidence": "Parámetro: q | Payload: \' | ...",\n'
    '  "recommendation": "Usar consultas parametrizadas..."\n'
    '}',
    styles["CodeBlock"],
))
story.append(Paragraph(
    "El array completo se escribe primero en <font face='Courier'>/tmp/ws_findings_&lt;timestamp&gt;."
    "json</font> mediante escritura línea a línea con <font face='Courier'>echo</font>, no con "
    "una librería JSON — el escapado de comillas/backslashes en <font face='Courier'>add_finding"
    "()</font> se hace manualmente con <font face='Courier'>sed</font>. Es un canal interno "
    "volátil (GUI↔motor durante el propio escaneo), no pensado para persistir.",
    styles["CalloutInfo"],
))
story.append(Paragraph(
    "Además, <font face='Courier'>generate_reports()</font> vuelve a serializar ese mismo array "
    "—esta vez con <font face='Courier'>json.dump()</font> real de Python, no a mano— como "
    "<font face='Courier'>informe_hallazgos.json</font> en la carpeta de salida elegida por el "
    "usuario, junto a los otros tres informes (bug 11, ver sección 9). Si la lectura del JSON de "
    "/tmp falla (corrupto), se avisa explícitamente por stderr en vez de generar informes con "
    "\"0 hallazgos\" en silencio — una herramienta de seguridad no debe poder sugerir que un "
    "objetivo está limpio por un fallo de parseo.",
    styles["Body"],
))

# ═══════════════════════════════════════════════════════════════════
# 8. METODOLOGÍA DE TESTING
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("8. Metodología de testing y regresión", styles["H1"]))
story.append(Paragraph(
    "Todo el trabajo de fiabilidad se apoyó en pruebas reales contra objetivos controlados, no "
    "solo en revisión de código.",
    styles["Body"],
))
story.append(Paragraph("tests/test_target_server.py", styles["H2"]))
story.append(Paragraph(
    "Servidor HTTP mínimo (sin dependencias, <font face='Courier'>http.server</font>) con tres "
    "perfiles seleccionables por argumento:",
    styles["Body"],
))
story.append(simple_table(
    ["Perfil", "Comportamiento"],
    [
        ["secure", "Cabeceras de seguridad correctas, endpoints parametrizados sin vulnerabilidades reales."],
        ["insecure", "Sin cabeceras de seguridad; /buscar (SQLi error-based real), /perfil (XSS reflejado real), /login (SQLi boolean-blind real, sin errores visibles), /reporte (SQLi UNION-based real, 3 columnas simuladas), /.env y /admin expuestos."],
        ["slow_safe", "Servidor deliberadamente lento (3.5s) en CUALQUIER petición, sin SQL de por medio — existe específicamente para detectar falsos positivos del check de timing."],
    ],
    styles, col_widths=[2.5 * cm, 10.9 * cm],
))
story.append(Paragraph(
    "Importante: implementa <font face='Courier'>do_HEAD</font> explícitamente (Python's "
    "BaseHTTPRequestHandler no lo hace por defecto, devolvería 501) porque el módulo de "
    "Security Headers usa <font face='Courier'>curl -I</font> — sin esto, cualquier prueba de "
    "cabeceras fallaría por un problema del arnés, no del motor.",
    styles["Body"],
))
story.append(Paragraph("tests/run_regression.sh", styles["H2"]))
story.append(Paragraph(
    "Batería de 10 casos, cada uno con expectativa explícita (VULN/SAFE/HEADERS_*): levanta los "
    "tres perfiles en paralelo, ejecuta el motor contra cada endpoint conocido, y compara el "
    "recuento de hallazgos contra lo esperado.",
    styles["Body"],
))
story.append(Paragraph("tests/test_scanner.py", styles["H2"]))
story.append(Paragraph(
    "10 tests unitarios (pytest) para el wrapper Python: parseo ANSI, carga de JSON válido y "
    "corrupto, cálculo de score, selección del JSON más reciente cuando hay varios en /tmp, "
    "unicidad de claves/títulos de módulo.",
    styles["Body"],
))

# ═══════════════════════════════════════════════════════════════════
# 9. BUGS CORREGIDOS
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("9. Bugs corregidos durante el desarrollo", styles["H1"]))
story.append(Paragraph(
    "Registro técnico de cada bug real encontrado mediante pruebas (no revisión estática), su "
    "causa raíz y el fix aplicado.",
    styles["Body"],
))

bugs = [
    ("① Crash total al ejecutar como root",
     "Componente: main.py / QtWebEngine.",
     "QtWebEngine hace exit() nativo si detecta root sin --no-sandbox. No es un Exception de Python — un try/except alrededor de QWebEngineView() no lo captura.",
     "os.geteuid() == 0 → forzar QTWEBENGINE_CHROMIUM_FLAGS=--no-sandbox antes de importar Qt."),
    ("② Falso positivo en SQLi ciego por tiempo",
     "Componente: webscanpro.sh, scan_sqli (blind timing).",
     "Umbral absoluto (>2800ms) sin baseline. Cualquier objetivo lento por motivos no maliciosos (latencia, backend cargado, WAF) disparaba SQLI02.",
     "Medición diferencial: baseline SIN payload primero, marcar solo si delta ≥2500ms."),
    ("③ Payloads con espacios rechazados por curl",
     "Componente: webscanpro.sh, múltiples módulos.",
     "curl reciente rechaza URLs con espacios/comillas sin encodear ('URL rejected: Malformed input'), devolviendo respuesta vacía en silencio. Afectaba a payloads OR-based ya presentes en el script original.",
     "urlencode() aplicado a todos los payloads de inyección antes de construir la URL."),
    ("④ Boolean-based con asimetría fija",
     "Componente: webscanpro.sh, scan_sqli (boolean-based, código nuevo).",
     "Asumía TRUE≈baseline y FALSE≠baseline. En un login vulnerable típico es al revés: el comportamiento normal YA es 'falso'.",
     "Aceptar la firma en cualquiera de las dos direcciones (TRUE≈base O FALSE≈base, más la diferencia TRUE/FALSE)."),
    ("⑤ Rutas bien conocidas ancladas a TARGET_URL en vez de a la raíz",
     "Componente: webscanpro.sh — XXE, SSTI (path), CMS Detection, Path Traversal, Sensitive Files, Fingerprinting.",
     "TARGET_URL puede incluir su propio path+query. Concatenar '/.env' directamente producía 'http://host/buscar?q=test/.env', interpretado como el PARÁMETRO q, no como una ruta. TARGET_HOST tampoco sirve como base porque pierde el puerto (cut -d: -f1).",
     "Nueva variable ROOT_URL (esquema+host+puerto, derivada de TARGET_URL sin perder el puerto), usada como base en todos los módulos de rutas 'bien conocidas'."),
    ("⑥ Doble '?' al añadir parámetros de prueba sintéticos",
     "Componente: webscanpro.sh — LFI, RFI, Path Traversal (por parámetro), SSRF.",
     "\"${TARGET_URL}?${param}=${payload}\" sin comprobar si TARGET_URL ya tenía query string. Con dos '?', el servidor trataba todo como el valor del primer parámetro — el payload (p.ej. una URL con 'google' o la IP de metadata cloud) quedaba reflejado literalmente, y heurísticas de detección débiles lo confirmaban sin que hubiera fetch remoto real.",
     "Helper add_test_param() que usa '&' en vez de '?' cuando la URL base ya tiene query string."),
    ("⑦ SSTI: resultado esperado que es subcadena del propio payload",
     "Componente: webscanpro.sh, scan_ssti (probe Twig RCE).",
     "El probe esperaba 'registerUndefined' — subcadena literal de su propio payload 'registerUndefinedFilterCallback'. Cualquier página que refleje el input SIN evaluarlo ya contenía esa subcadena.",
     "Exigir que el payload literal completo YA NO esté en la respuesta (evidencia de evaluación real), además de que aparezca el resultado esperado."),
    ("⑧ Consola con secuencias ANSI de control sin limpiar",
     "Componente: core/scanner.py, strip_ansi().",
     "El regex solo eliminaba secuencias SGR/color (terminadas en 'm'). El motor llama a `clear` al iniciar, que emite control de cursor/borrado de pantalla (ESC[H, ESC[2J, ESC[3J) — no color — apareciendo como texto corrupto en la consola de la GUI.",
     "Regex generalizado a cualquier secuencia CSI: r\"\\x1b\\[[0-9;]*[a-zA-Z]\" (cualquier letra final, no solo 'm')."),
    ("⑨ Banner con código de escape sin interpretar",
     "Componente: webscanpro.sh, función banner().",
     "Una línea del banner usaba `echo` normal (sin -e) pero incluía ${NC} al final. Como NC se define con comillas simples ('\\\\033[0m'), sin -e el backslash se imprime literalmente en vez de interpretarse como ESC — se veía \"\\\\033[0m\" como texto plano tras el logo.",
     "Cambiado a `echo -e` en esa línea, consistente con el resto del banner."),
    ("⑩ curl falla en silencio dentro del binario compilado",
     "Componente: core/scanner.py, ScannerWorker.run() — solo afecta al binario PyInstaller, no al modo desarrollo.",
     "PyInstaller (--onefile) fija LD_LIBRARY_PATH apuntando a su carpeta temporal de extracción para que Python/Qt encuentren sus librerías empaquetadas. Los subprocesos lanzados (bash, y a su vez curl) HEREDAN esa variable — si curl resuelve símbolos contra una libssl/libcrypto empaquetada para Qt en vez de la del sistema, puede fallar de forma inmediata y silenciosa (reportado como 'No se puede conectar' incluso con red funcional), aunque el mismo curl funcione perfecto a mano en una terminal normal.",
     "Nuevo _clean_subprocess_env(): si sys.frozen, restaura LD_LIBRARY_PATH desde LD_LIBRARY_PATH_ORIG (convención de PyInstaller para este caso exacto) antes de lanzar bash. No se ha podido reproducir el fallo de forma determinista en el entorno de desarrollo para confirmarlo al 100% — es la causa más probable dado el patrón de síntomas, pero queda pendiente de confirmación en campo (ver sección 11)."),
    ("11. El JSON de hallazgos nunca llegaba a la carpeta de salida",
     "Componente: webscanpro.sh, generate_reports().",
     "FINDINGS_JSON solo se escribía en /tmp/ws_findings_<timestamp>.json — un canal interno volátil (se pierde al reiniciar, se sobrescribe con el siguiente escaneo) del que el usuario no tenía forma de saber que existía. Los tres informes (.txt/.txt/.html) sí se guardaban en OUTPUT_DIR, pero el JSON —el artefacto más reutilizable para automatización— nunca. Además, si la lectura de ese JSON fallaba (corrupto por el escapado manual del bug conocido en add_finding), el generador de informes lo tragaba en silencio con 'findings = []', produciendo un informe de '0 hallazgos' sin avisar — engañoso en una herramienta de seguridad.",
     "generate_reports() ahora también escribe informe_hallazgos.json en OUTPUT_DIR con json.dump() real de Python (no a mano). Un fallo de lectura del JSON de /tmp se reporta explícitamente por stderr en vez de degradar en silencio a 'sin hallazgos'."),
]
for title, comp, cause, fix in bugs:
    story.append(KeepTogether([
        Paragraph(title, styles["H3"]),
        Paragraph(f"<b>{comp}</b>", styles["Body"]),
        Paragraph(f"<b>Causa:</b> {cause}", styles["Body"]),
        Paragraph(f"<b>Fix:</b> {fix}", styles["Body"]),
    ]))

story.append(Paragraph(
    "Todos los bugs se descubrieron ejecutando el motor contra objetivos reales controlados "
    "(tests/test_target_server.py), no por lectura de código — varios (③, ⑤, ⑥) probablemente "
    "existían ya en el script original y nunca se habían notado porque, en los casos de prueba "
    "habituales, un payload anterior en la misma lista ya disparaba el hallazgo antes de llegar "
    "al payload afectado.",
    styles["CalloutDanger"],
))

# ═══════════════════════════════════════════════════════════════════
# 10. EMPAQUETADO
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("10. Empaquetado y despliegue", styles["H1"]))
story.append(code_block(
    "python3 -m venv venv\n"
    "source venv/bin/activate\n"
    "pip install -r requirements.txt\n"
    "pip install PySide6-WebEngine   # opcional, para el informe HTML embebido\n\n"
    "pip install pyinstaller\n"
    "pyinstaller --onefile --windowed \\\n"
    "  --add-data \"webscanpro.sh:.\" \\\n"
    "  --name webscanpro-gui \\\n"
    "  main.py",
    styles["CodeBlock"],
))
story.append(Paragraph(
    "El binario resultante queda en <font face='Courier'>dist/webscanpro-gui</font> (~218MB). "
    "Con PyInstaller, los recursos empaquetados (<font face='Courier'>--add-data</font>) se "
    "extraen en tiempo de ejecución a una carpeta temporal accesible vía "
    "<font face='Courier'>sys._MEIPASS</font>. <font face='Courier'>find_script()</font> en "
    "main.py ya contempla esto (detecta <font face='Courier'>sys.frozen</font> y busca ahí) — "
    "verificado extrayendo el binario compilado y comparando el <font face='Courier'>"
    "webscanpro.sh</font> resultante byte a byte contra el original.",
    styles["Body"],
))

# ═══════════════════════════════════════════════════════════════════
# 11. LIMITACIONES Y ROADMAP
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("11. Limitaciones conocidas y roadmap", styles["H1"]))
story.append(simple_table(
    ["Área", "Limitación actual", "Mejora natural"],
    [
        ["Empaquetado", "Requiere libxcb-cursor0 instalado en el sistema destino para el plugin de plataforma X11 — PyInstaller no puede embeber esta dependencia del sistema.", "Documentar en el instalador o detectar su ausencia con un mensaje de error más claro que el fallo nativo de Qt."],
        ["Serialización JSON", "El canal interno /tmp sigue escribiéndose a mano con sed (usado solo para pasar datos entre el motor bash y el generador de informes). La copia persistente en OUTPUT_DIR (informe_hallazgos.json, bug 11) ya usa json.dump() real.", "Eliminar el paso intermedio por /tmp: que el propio bash escriba directamente en formato robusto, o delegar toda la serialización al bloque Python embebido desde el principio."],
        ["Concurrencia", "Un escaneo a la vez; no hay cola ni escaneos en paralelo.", "Cola de escaneos con múltiples ScannerWorker si se necesita en el futuro."],
        ["SSTI heurística de tecnologías", "Basada en cabeceras del servidor; señal débil (INFO/MEDIO, ya etiquetada como 'revisar manualmente').", "Correlacionar con más de una señal (cookies, rutas típicas del framework) antes de sugerir un motor concreto."],
        ["Cobertura de pruebas", "El arnés de test cubre SQLi (4 técnicas), Headers, Sensitive Files, RFI/SSRF (regresión del bug ⑥) y SSTI (regresión del bug ⑦) con verdaderos positivos/negativos. XSS, XXE, LFI, Path Traversal, CMS y Fingerprinting solo tienen smoke tests (no crashean) tras el fix de ROOT_URL, sin battery de verdadero/falso positivo dedicada.", "Extender test_target_server.py con endpoints vulnerables/seguros conocidos para cada módulo restante."],
        ["Fix ⑩ (LD_LIBRARY_PATH)", "Aplicado y con fundamento técnico sólido (convención documentada de PyInstaller), pero NO reproducido de forma determinista en desarrollo — no se ha podido confirmar al 100% que sea la causa exacta de los fallos de conectividad reportados en campo sobre el binario compilado.", "Confirmar en el sistema donde falló originalmente (comparar LD_DEBUG=libs con y sin el fix). Si el fallo persiste, buscar otra causa (versión de curl/glibc específica del sistema, certificados, etc.)."],
        ["Soporte Windows", "run_windows.bat monta el entorno Python/PySide6, pero el motor sigue siendo un script Bash — requiere Git for Windows o WSL instalados aparte para que curl/bash estén disponibles. Sin compilar (.exe) todavía; PyInstaller no hace cross-compilación desde Linux.", "Compilar un .exe nativo desde una máquina Windows real. Evaluar si merece la pena portar el motor a Python puro para eliminar la dependencia de Bash en Windows."],
    ],
    styles, col_widths=[2.8 * cm, 6 * cm, 4.6 * cm],
))

doc.build(story)
print(f"Generado: {OUT_PATH}")
