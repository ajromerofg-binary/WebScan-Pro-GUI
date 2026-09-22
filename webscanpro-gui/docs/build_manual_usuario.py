#!/usr/bin/env python3
"""
docs/build_manual_usuario.py
Genera el Manual de Usuario de WebScan Pro GUI (PDF).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from reportlab.platypus import Spacer, Paragraph, PageBreak, HRFlowable, KeepTogether, NextPageTemplate
from reportlab.lib.units import cm

from pdf_common import (
    build_styles, make_doc, cover_page, screenshot, bullet_list, simple_table, code_block, CYAN,
)

ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
OUT_PATH = "/mnt/user-data/outputs/WebScanPro_GUI_Manual_Usuario.pdf"

styles = build_styles()
doc = make_doc(OUT_PATH, "Manual de Usuario")
story = []

# ═══════════════════════════════════════════════════════════════════
# PORTADA
# ═══════════════════════════════════════════════════════════════════
cover_page(
    story, styles,
    subtitle="Escáner de vulnerabilidades web · OWASP Top 10",
    doc_label="MANUAL DE USUARIO",
    version="1.0",
    date_str="Septiembre 2026",
)
story.insert(0, NextPageTemplate("Body"))

# ═══════════════════════════════════════════════════════════════════
# ÍNDICE
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("Índice", styles["H1"]))
toc_entries = [
    "1. Qué es WebScan Pro GUI",
    "2. Antes de empezar: uso legal y ético",
    "3. Instalación",
    "4. Primer vistazo a la interfaz",
    "5. Cómo hacer tu primer escaneo",
    "6. Entender los resultados",
    "7. Los informes generados",
    "8. Preguntas frecuentes y solución de problemas",
    "9. Glosario de términos",
]
for e in toc_entries:
    story.append(Paragraph(e, styles["TOCEntry"]))
story.append(PageBreak())

# ═══════════════════════════════════════════════════════════════════
# 1. QUÉ ES
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("1. Qué es WebScan Pro GUI", styles["H1"]))
story.append(Paragraph(
    "WebScan Pro GUI es una aplicación de escritorio que revisa una página web y te dice, "
    "de forma ordenada, qué puntos débiles de seguridad tiene. Piensa en ello como una "
    "revisión técnica de un coche, pero para una web: no la conduce ni la modifica, simplemente "
    "la inspecciona y te entrega un informe de lo que encuentra.",
    styles["Body"],
))
story.append(Paragraph(
    "Por debajo, la aplicación envuelve un motor de análisis (WebScan Pro) que ya existía como "
    "herramienta de línea de comandos. Esta versión con interfaz gráfica no cambia lo que ese "
    "motor sabe hacer — simplemente lo hace mucho más fácil de usar: rellenas un formulario, "
    "pulsas un botón, y ves el progreso y los resultados en pantalla en vez de leer texto en "
    "una terminal.",
    styles["Body"],
))
story.append(Paragraph("¿Qué tipo de problemas detecta?", styles["H2"]))
story.append(Paragraph(
    "La herramienta cubre las categorías más habituales del <b>OWASP Top 10</b>, que es la lista "
    "de referencia mundial de los fallos de seguridad web más comunes y peligrosos. En términos "
    "sencillos, comprueba cosas como:",
    styles["Body"],
))
story.append(bullet_list([
    "Si la web permite que alguien <b>manipule su base de datos</b> escribiendo texto especial en un formulario o en la URL (inyección SQL).",
    "Si la web permite <b>inyectar código que se ejecuta en el navegador de otra persona</b> que visite la página (XSS).",
    "Si hay <b>archivos que no deberían ser públicos</b> pero se pueden descargar sin permiso (copias de seguridad, configuración, credenciales).",
    "Si el servidor tiene <b>protecciones básicas de seguridad</b> activadas o no (las llamadas \"cabeceras de seguridad\").",
    "Si se puede engañar al servidor para que <b>acceda a sitios internos</b> a los que no debería llegar (SSRF), o para que <b>lea archivos del propio servidor</b> (Path Traversal, LFI).",
], styles))
story.append(Paragraph(
    "No necesitas entender los detalles técnicos de cada categoría para usar la aplicación — "
    "el informe explica cada hallazgo en un lenguaje razonablemente claro, con severidad, "
    "evidencia y una recomendación de cómo solucionarlo. La sección 9 de este manual incluye "
    "un glosario si quieres profundizar.",
    styles["Body"],
))

# ═══════════════════════════════════════════════════════════════════
# 2. USO LEGAL Y ÉTICO
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("2. Antes de empezar: uso legal y ético", styles["H1"]))
story.append(Paragraph(
    "<b>Usa esta herramienta únicamente sobre sitios web de tu propiedad, o para los que tengas "
    "autorización explícita y por escrito para realizar pruebas de seguridad.</b>",
    styles["CalloutDanger"],
))
story.append(Paragraph(
    "Escanear una web sin permiso —aunque sea \"solo para mirar\"— puede ser ilegal en la "
    "mayoría de países, incluso si no llegas a explotar nada de lo que encuentres. Piensa en "
    "esta herramienta como el equivalente a probar si la puerta de la casa de alguien está "
    "cerrada: hacerlo sin permiso es un problema, aunque no llegues a entrar.",
    styles["Body"],
))
story.append(Paragraph(
    "Esta herramienta realiza pruebas <b>pasivas y semi-activas</b>: no explota vulnerabilidades "
    "ni elimina/modifica datos, pero sí envía peticiones especialmente diseñadas al servidor "
    "objetivo, algunas de las cuales pueden generar carga o comportamientos inesperados. No es "
    "un sustituto de una auditoría manual completa por parte de un profesional.",
    styles["CalloutInfo"],
))

# ═══════════════════════════════════════════════════════════════════
# 3. INSTALACIÓN
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("3. Instalación", styles["H1"]))
story.append(Paragraph(
    "Hay dos formas de instalar y ejecutar la aplicación, según tu perfil.",
    styles["Body"],
))
story.append(Paragraph("Opción A — Si te han dado un ejecutable ya compilado", styles["H2"]))
story.append(bullet_list([
    "Descarga el archivo ejecutable (por ejemplo <b>webscanpro-gui</b>).",
    "Dale permisos de ejecución si tu sistema lo requiere (en Linux/macOS: clic derecho → Propiedades → Permisos, o en terminal: <font face='Courier'>chmod +x webscanpro-gui</font>).",
    "Haz doble clic sobre el archivo, o ejecútalo desde la terminal.",
], styles))
story.append(Paragraph("Opción B — Si tienes el código fuente (perfil técnico)", styles["H2"]))
story.append(Paragraph("Necesitas Python 3.10 o superior instalado. Desde una terminal, dentro de la carpeta del proyecto:", styles["Body"]))
story.append(code_block(
    "python3 -m venv venv\n"
    "source venv/bin/activate\n"
    "pip install -r requirements.txt\n"
    "python3 main.py",
    styles["CodeBlock"],
))
story.append(Paragraph(
    "Requisitos del sistema: el equipo necesita tener instalados <font face='Courier'>curl</font> "
    "y <font face='Courier'>python3</font> (el motor de análisis los usa internamente), además de "
    "Python y las dependencias del archivo requirements.txt para la interfaz gráfica.",
    styles["CalloutInfo"],
))
story.append(Paragraph("Opción C — Windows", styles["H2"]))
story.append(Paragraph(
    "Se incluye un script <font face='Courier'>run_windows.bat</font> que prepara el entorno y "
    "lanza la aplicación automáticamente (crea el entorno virtual, instala dependencias, arranca "
    "el programa). Haz doble clic sobre él, o ejecútalo desde una consola.",
    styles["Body"],
))
story.append(Paragraph(
    "<b>Importante:</b> el motor de análisis es un script Bash que depende de <font face='Courier'>"
    "curl</font>. Windows no trae ninguno de los dos por defecto. Antes de lanzar un escaneo, "
    "instala una de estas dos opciones:",
    styles["CalloutDanger"],
))
story.append(bullet_list([
    "<b>Git for Windows</b> (recomendado, más ligero): descárgalo de git-scm.com/download/win — instala bash y curl automáticamente.",
    "<b>WSL</b> (Subsistema de Windows para Linux): abre una consola como administrador y ejecuta <font face='Courier'>wsl --install</font>.",
], styles))
story.append(Paragraph(
    "Sin uno de los dos instalados, la interfaz se abre con normalidad, pero cualquier escaneo "
    "fallará al no encontrar \"bash\". El propio <font face='Courier'>run_windows.bat</font> te "
    "avisa si detecta que faltan.",
    styles["Body"],
))

# ═══════════════════════════════════════════════════════════════════
# 4. PRIMER VISTAZO
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("4. Primer vistazo a la interfaz", styles["H1"]))
story.append(Paragraph(
    "Al abrir la aplicación verás tres zonas principales, de arriba a abajo y de izquierda a "
    "derecha:",
    styles["Body"],
))
story.append(screenshot(
    os.path.join(ASSETS, "01_inicial.png"),
    "Pantalla inicial: configuración del escaneo, progreso y resultados (vacíos hasta el primer escaneo).",
    styles,
))
story.append(bullet_list([
    "<b>Configuración del escaneo</b> (arriba): aquí escribes qué web quieres analizar y ajustas las opciones.",
    "<b>Progreso</b> (abajo a la izquierda): mientras el escaneo corre, verás una barra de progreso, un resumen de hallazgos por gravedad, y una consola con el detalle técnico en vivo.",
    "<b>Resultados</b> (abajo a la derecha): al terminar, aquí aparece la lista de hallazgos, organizados por severidad, con una pestaña de detalle y otra con el informe visual completo.",
], styles))

# ═══════════════════════════════════════════════════════════════════
# 5. PRIMER ESCANEO
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("5. Cómo hacer tu primer escaneo", styles["H1"]))

story.append(Paragraph("Paso 1 — Introduce la URL objetivo", styles["H2"]))
story.append(Paragraph(
    "Escribe la dirección completa de la web que vas a analizar (incluyendo <font face='Courier'>"
    "http://</font> o <font face='Courier'>https://</font>), por ejemplo: "
    "<font face='Courier'>https://mi-sitio-de-pruebas.com</font>. Recuerda: solo sobre sitios "
    "propios o con autorización.",
    styles["Body"],
))

story.append(Paragraph("Paso 2 — Ajusta las opciones (opcional)", styles["H2"]))
story.append(bullet_list([
    "<b>Timeout:</b> cuántos segundos espera la herramienta la respuesta de cada petición antes de darla por perdida. El valor por defecto (12s) funciona bien en la mayoría de casos; súbelo si el sitio es lento.",
    "<b>Salida:</b> la carpeta donde se guardarán los informes generados. Si la dejas en blanco, se crea automáticamente una carpeta con fecha y hora en tu Escritorio.",
    "<b>Módulos a ejecutar:</b> por defecto están todos marcados (análisis completo). Puedes desmarcar los que no te interesen — por ejemplo, si solo quieres revisar las cabeceras de seguridad, desmarca todo excepto \"Security Headers\".",
], styles))

story.append(screenshot(
    os.path.join(ASSETS, "02_configurado.png"),
    "Configuración lista: URL objetivo introducida y módulos seleccionados (en este ejemplo, solo Security Headers y SQL Injection).",
    styles,
))

story.append(Paragraph("Paso 3 — Inicia el escaneo", styles["H2"]))
story.append(Paragraph(
    "Pulsa el botón <b>Iniciar escaneo</b>. Verás la consola de la izquierda llenarse con el "
    "detalle técnico en vivo, y la barra de progreso avanzar módulo a módulo. Puedes pulsar "
    "<b>Cancelar</b> en cualquier momento si necesitas detenerlo.",
    styles["Body"],
))
story.append(Paragraph(
    "El tiempo total depende de cuántos módulos hayas seleccionado y de lo rápido que responda "
    "el sitio objetivo. Un escaneo completo (los 12 módulos) puede tardar desde menos de un "
    "minuto hasta varios minutos.",
    styles["CalloutInfo"],
))

# ═══════════════════════════════════════════════════════════════════
# 6. ENTENDER RESULTADOS
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("6. Entender los resultados", styles["H1"]))
story.append(Paragraph(
    "Cuando el escaneo termina, la pestaña <b>Hallazgos</b> muestra una tabla con todo lo "
    "encontrado, ordenado por gravedad. Haz clic en cualquier fila para ver el detalle completo "
    "en la pestaña <b>Detalle</b>.",
    styles["Body"],
))
story.append(screenshot(
    os.path.join(ASSETS, "04_detalle_hallazgo.png"),
    "Detalle de un hallazgo: qué es, qué evidencia se encontró, y cómo solucionarlo.",
    styles,
))
story.append(Paragraph("Niveles de severidad", styles["H2"]))
story.append(simple_table(
    ["Severidad", "Qué significa", "Urgencia"],
    [
        ["CRÍTICO", "El fallo permite un compromiso serio: robo de datos, acceso no autorizado, control del servidor.", "Corregir de inmediato"],
        ["ALTO", "Riesgo significativo, aunque con más condiciones para explotarse que un CRÍTICO.", "Corregir pronto"],
        ["MEDIO", "Debilidad real, pero de impacto limitado o que requiere otro fallo adicional para ser peligrosa.", "Planificar corrección"],
        ["BAJO", "Información expuesta o configuración mejorable, sin explotación directa evidente.", "Corregir cuando sea posible"],
        ["INFO", "Dato informativo (p.ej. tecnología detectada), no es un fallo en sí mismo.", "Sin acción obligatoria"],
    ],
    styles, col_widths=[2.3 * cm, 9.7 * cm, 3.7 * cm],
))
story.append(Paragraph(
    "Cada hallazgo indica también un <b>score de riesgo global</b> del escaneo completo, "
    "calculado ponderando cuántos hallazgos hay de cada severidad. Es una forma rápida de "
    "hacerte una idea del estado general sin tener que leer cada línea.",
    styles["Body"],
))
story.append(Paragraph(
    "Un hallazgo detectado no siempre significa que el problema sea explotable sin más — algunos "
    "módulos (como la detección heurística de tecnologías) marcan indicios que conviene revisar "
    "manualmente, no confirmaciones absolutas. El propio informe lo indica cuando es así.",
    styles["CalloutInfo"],
))

# ═══════════════════════════════════════════════════════════════════
# 7. INFORMES
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("7. Los informes generados", styles["H1"]))
story.append(Paragraph(
    "Al terminar cada escaneo, la herramienta guarda automáticamente cuatro archivos en la "
    "carpeta de salida:",
    styles["Body"],
))
story.append(simple_table(
    ["Archivo", "Para quién es", "Qué contiene"],
    [
        ["informe_ejecutivo.txt", "Dirección / management", "Resumen sin tecnicismos: nivel de riesgo, conteo de hallazgos, recomendaciones principales."],
        ["informe_tecnico_IT.txt", "Equipo técnico / IT", "Detalle completo de cada hallazgo: evidencia exacta, parámetro afectado, pasos de remediación."],
        ["informe_completo.html", "Cualquiera (interactivo)", "Informe visual navegable en el propio navegador, con filtros por severidad y checklist de remediación."],
        ["informe_hallazgos.json", "Perfil técnico / automatización", "Los mismos hallazgos en formato JSON estructurado, para integrarlo con otras herramientas o scripts propios."],
    ],
    styles, col_widths=[4.5 * cm, 4 * cm, 7.2 * cm],
))
story.append(Paragraph(
    "Desde la pestaña <b>Informe HTML</b> de la aplicación puedes ver este último directamente "
    "embebido, sin salir del programa. Los botones <b>Abrir carpeta de informes</b> y "
    "<b>Abrir HTML en navegador</b>, debajo de los resultados, te llevan directamente a los "
    "archivos.",
    styles["Body"],
))

# ═══════════════════════════════════════════════════════════════════
# 8. FAQ / TROUBLESHOOTING
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("8. Preguntas frecuentes y solución de problemas", styles["H1"]))

faq = [
    ("La aplicación no arranca / se cierra sola al abrirla",
     "Si ejecutas la aplicación como administrador/root (frecuente en distribuciones orientadas "
     "a seguridad como Kali Linux), asegúrate de tener la última versión — esto se corrigió "
     "específicamente para ese escenario. Si el problema persiste, ejecútala desde una terminal "
     "para ver el mensaje de error exacto."),
    ("\"No se puede conectar\" al iniciar el escaneo",
     "Comprueba que la URL está bien escrita (incluyendo http:// o https://), que el sitio está "
     "accesible desde tu conexión, y que no hay un firewall bloqueando la salida."),
    ("El escaneo tarda mucho",
     "Es normal si has seleccionado muchos módulos, algunos de los cuales prueban decenas de "
     "combinaciones de parámetros. Puedes reducir el timeout o desmarcar los módulos que no "
     "necesites."),
    ("No veo la pestaña de Informe HTML / aparece un aviso",
     "Esa pestaña necesita un componente adicional (QtWebEngine) que puede no estar instalado en "
     "tu sistema. Puedes seguir usando el resto de la aplicación con normalidad, y abrir el "
     "informe HTML directamente en tu navegador con el botón correspondiente."),
    ("¿Puedo escanear varias webs a la vez?",
     "No en esta versión — la aplicación está pensada para un escaneo a la vez. Puedes lanzar "
     "escaneos sucesivos cambiando la URL objetivo."),
]
for q, a in faq:
    story.append(KeepTogether([
        Paragraph(q, styles["H3"]),
        Paragraph(a, styles["Body"]),
    ]))

# ═══════════════════════════════════════════════════════════════════
# 9. GLOSARIO
# ═══════════════════════════════════════════════════════════════════
story.append(Paragraph("9. Glosario de términos", styles["H1"]))
glosario = [
    ("SQL Injection (SQLi)", "Cuando una web usa el texto que escribes en un formulario para construir directamente una orden a su base de datos. Si no se hace con cuidado, alguien puede escribir texto especial para leer, cambiar o borrar datos que no debería."),
    ("XSS (Cross-Site Scripting)", "Cuando una web muestra tal cual, sin filtrar, un texto que le ha dado un usuario — permitiendo que ese texto incluya código que se ejecuta en el navegador de otra persona que visite la página."),
    ("SSRF (Server-Side Request Forgery)", "Cuando se puede engañar al servidor para que haga peticiones a direcciones que no debería alcanzar, como servicios internos de la propia infraestructura."),
    ("LFI / RFI (Local / Remote File Inclusion)", "Cuando una web permite incluir o leer archivos —del propio servidor (LFI) o de fuera (RFI)— a través de un parámetro mal validado."),
    ("Path Traversal", "Un ataque que usa secuencias como \"../\" para salir de la carpeta donde debería quedarse la web y leer archivos del sistema."),
    ("SSTI (Server-Side Template Injection)", "Cuando el motor que genera las páginas de la web evalúa código dentro del texto que le llega del usuario, en vez de tratarlo como texto plano."),
    ("Cabeceras de seguridad", "Instrucciones que el servidor envía al navegador para activar protecciones (por ejemplo, impedir que la página se abra dentro de otra, o forzar conexión cifrada)."),
    ("Falso positivo", "Un hallazgo que el escáner marca como problema pero que, tras revisión manual, resulta no serlo realmente."),
    ("OWASP Top 10", "El listado de referencia mundial (mantenido por la organización OWASP) de las categorías de vulnerabilidad web más críticas y frecuentes."),
]
for term, definition in glosario:
    story.append(KeepTogether([
        Paragraph(f"<b>{term}</b>", styles["Body"]),
        Paragraph(definition, styles["Body"]),
    ]))

doc.build(story)
print(f"Generado: {OUT_PATH}")
