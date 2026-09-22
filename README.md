[README.md](https://github.com/user-attachments/files/32514613/README.md)
# WebScan Pro — GUI

Aplicación de escritorio (PySide6) para el motor **WebScan Pro**
(`webscanpro.sh`), siguiendo el mismo patrón que RobotEye: interfaz
gráfica + binario compilado, bajo Sr.Robot Labs.

## Filosofía

**El motor no se toca.** Toda la lógica de detección (11 módulos:
headers, SQLi, XSS, XXE, LFI, RFI, path traversal, SSRF, SSTI, CMS,
archivos sensibles) sigue viviendo en `webscanpro.sh`, tal cual. La
GUI:

1. Lanza el script como subproceso (`bash webscanpro.sh -u <url> ...`).
2. Parsea su stdout en vivo (quitando los códigos ANSI de color) para
   mostrar progreso por módulo y hallazgos según van apareciendo.
3. Al terminar, localiza el JSON de hallazgos que el propio script ya
   serializa en `/tmp/ws_findings_<timestamp>.json` y lo carga en un
   árbol navegable con detalle por hallazgo. El motor guarda además
   una copia persistente de ese mismo JSON (`informe_hallazgos.json`,
   con serialización real de Python) en la carpeta de salida elegida,
   junto a los demás informes — el de `/tmp` es volátil y solo sirve
   como canal interno GUI↔motor durante el propio escaneo.
4. Embebe el `informe_completo.html` que genera el script (si
   `PySide6-WebEngine` está disponible) en una pestaña, o permite
   abrirlo en el navegador del sistema.

## Estructura

```
webscanpro-gui/
├── main.py                # punto de entrada
├── webscanpro.sh           # motor original, sin modificar
├── requirements.txt
├── core/
│   └── scanner.py          # QThread: subprocess + parseo de progreso + carga de resultados
└── ui/
    ├── main_window.py      # configuración, progreso, resultados
    └── styles.py            # tema oscuro/cyberpunk (coherente con RobotEye)
```

## Pruebas realizadas y bugs corregidos

Antes de darlo por bueno se hicieron pruebas reales (no solo revisión de
código): arranque de la GUI en modo offscreen, tests unitarios del
wrapper Python, y el motor bash lanzado contra servidores de prueba
controlados con vulnerabilidades conocidas y comportamiento seguro
conocido (`tests/test_target_server.py`, `tests/run_regression.sh`).

**Bugs encontrados y corregidos:**

1. **Crash total al ejecutar como root** (`main.py`): `QtWebEngine`
   (Chromium) hace un hard-exit nativo del proceso si detecta root sin
   `--no-sandbox` — no es una excepción de Python capturable, mataba
   la ventana antes de mostrarse. Relevante porque herramientas de
   pentesting se ejecutan habitualmente como root (Kali, sudo). Fix:
   detección automática de `os.geteuid() == 0` y `--no-sandbox`
   forzado antes de tocar Qt.

2. **Falso positivo en SQLi ciego por tiempo** (`webscanpro.sh`): el
   check original comparaba contra un umbral absoluto (2.8s), así que
   cualquier objetivo simplemente lento (latencia, backend cargado,
   WAF con delay) se marcaba como SQLi. Fix: medición diferencial
   contra una petición baseline sin payload — solo se marca si el
   retraso es atribuible al payload, no al servidor.

3. **Payloads con espacios rechazados por curl** (`webscanpro.sh`,
   afectaba también al script original): curl moderno rechaza
   directamente URLs con espacios/comillas sin codificar (`URL
   rejected: Malformed input`), devolviendo respuesta vacía en
   silencio — sin error visible. Los payloads OR-based del error-based
   original ("' OR '1'='1", "' OR 1=1--") nunca llegaban a probarse de
   verdad salvo que el payload anterior (solo comilla) ya disparase el
   hallazgo. Fix: `urlencode()` aplicado a todos los payloads de
   inyección en las 4 técnicas.

4. **Lógica boolean-based con asimetría fija** (bug propio, detectado
   en las mismas pruebas): asumía que la condición TRUE siempre se
   parece al baseline y FALSE difiere. En un login vulnerable real es
   frecuentemente al revés (el comportamiento normal ya es "falso").
   Fix: se acepta la firma en cualquiera de las dos direcciones.

5. **Rutas "bien conocidas" ancladas a la URL completa, no a la raíz
   del sitio** (`webscanpro.sh`, afectaba a XXE, SSTI, CMS Detection,
   Path Traversal, Sensitive Files y Fingerprinting): si el objetivo ya
   tenía su propio path+query (el caso normal — casi nadie escanea una
   raíz "pelada"), estos módulos concatenaban la ruta de prueba
   directamente sobre la URL completa: `http://host/buscar?q=test` +
   `/.env` → `http://host/buscar?q=test/.env`, que el servidor
   interpreta como el parámetro `q=test/.env`, no como la ruta `/.env`.
   Esto generaba decenas de falsos positivos (`.git`, `wp-config.php`,
   `backup.zip`, `phpMyAdmin`, etc.) en cualquier escaneo que no fuera
   contra la raíz exacta del dominio. Fix: nueva variable `ROOT_URL`
   (esquema+host+puerto, calculada sin perder el puerto — otro fallo
   que arrastraba `TARGET_HOST`), usada como base en todos estos
   módulos en vez de `TARGET_URL`.

6. **Doble `?` al añadir parámetros de prueba sintéticos**
   (`webscanpro.sh`, afectaba a LFI, RFI, Path Traversal por parámetro
   y SSRF): estos módulos prueban parámetros que la URL puede no
   tener (`file=`, `url=`, `path=`...) concatenando ciegamente
   `"${TARGET_URL}?${param}=${payload}"`. Si `TARGET_URL` ya tenía
   query string, el resultado tenía DOS signos `?`, y el servidor
   trataba todo como el valor del primer parámetro — reflejando el
   payload (p. ej. una URL con "google" o "169.254.169.254") de vuelta
   en la respuesta sin haberlo cargado de verdad. Con heurísticas de
   detección débiles, ese reflejo bastaba para confirmar RFI/SSRF sin
   que existiera vulnerabilidad real. Fix: helper `add_test_param()`
   que usa `&` en vez de `?` cuando ya hay query string previa.

7. **SSTI: "resultado esperado" que es subcadena de su propio
   payload** (bug de diseño en el motor, no solo de URL): el probe de
   Twig (`{{_self.env.registerUndefinedFilterCallback}}`) esperaba
   encontrar `registerUndefined` en la respuesta — pero esa cadena ya
   está contenida en el payload mismo. Cualquier página que refleje el
   input sin evaluarlo (sin motor de plantillas real de por medio)
   "confirmaba" SSTI solo por hacer eco del texto. Fix: se exige que
   el payload literal ya NO esté en la respuesta (evidencia de que se
   evaluó, no que se reflejó) además de que aparezca el resultado
   esperado — es el criterio estándar para distinguir evaluación real
   de mero reflejo.

**Motor de SQLi ampliado** — antes solo error-based + timing con
umbral absoluto; ahora 4 técnicas, cada una con verdadero positivo y
verdadero negativo verificados contra servidores de prueba:

| Técnica | ID | Qué detecta |
|---|---|---|
| Error-based | SQLI01 | Errores de motor SQL reflejados en la respuesta |
| Boolean-based blind | SQLI02 | Diferencia de contenido entre condición TRUE/FALSE sin errores visibles; descarta el check si la página ya es inestable entre dos peticiones idénticas (evita falsos positivos en contenido dinámico) |
| UNION-based | SQLI03 | Nº de columnas de la consulta vía `ORDER BY` creciente, hasta el punto de ruptura |
| Time-based blind | SQLI04 | Retraso atribuible al payload (diferencial contra baseline), cubriendo MySQL/MariaDB (`SLEEP`), MSSQL (`WAITFOR DELAY`) y PostgreSQL (`pg_sleep`) |

Para reproducir las pruebas: levantar los tres perfiles de
`tests/test_target_server.py` (`secure`, `insecure`, `slow_safe`) en
puertos distintos y ejecutar `tests/run_regression.sh`.

## Instalación

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Opcional pero recomendado, para el informe HTML embebido:
pip install PySide6-WebEngine
```

## Ejecución

```bash
python3 main.py
```

`webscanpro.sh` debe estar en el mismo directorio que `main.py` (ya
incluido en este proyecto). Requiere `curl` y `python3` en el sistema,
igual que el script original.

## Uso

1. Introduce la URL objetivo.
2. Ajusta timeout y, opcionalmente, carpeta de salida.
3. Selecciona los módulos a ejecutar (por defecto, todos).
4. Pulsa **Iniciar escaneo**. La consola de la izquierda muestra el
   log en vivo; la barra de progreso avanza módulo a módulo.
5. Al terminar, pestaña **Hallazgos**: árbol ordenado por severidad,
   clic en cada uno para ver el detalle (evidencia, recomendación).
   Pestaña **Informe HTML**: el mismo informe interactivo que genera
   el script, embebido.
6. Botones inferiores para abrir la carpeta de informes o el HTML en
   el navegador del sistema.

### Selección de varios módulos

El motor acepta `--only <mod1>,<mod2>,...` (lista separada por comas),
así que la GUI puede desmarcar cualquier combinación de módulos y
ejecutarlos todos en una sola pasada — ya no está limitada a un único
módulo por escaneo.

## Empaquetado (mismo patrón que RobotEye)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed \
  --add-data "webscanpro.sh:." \
  --name webscanpro-gui \
  main.py
```

El binario resultante queda en `dist/webscanpro-gui` (~218MB, incluye
Python + PySide6 + QtWebEngine/Chromium completo). `find_script()` en
`main.py` ya contempla `sys._MEIPASS` cuando `sys.frozen` está activo
— verificado extrayendo el binario compilado y comparando el
`webscanpro.sh` resultante byte a byte contra el original.

**Dependencia de sistema para el binario compilado:** el plugin de
plataforma X11 de Qt6 requiere `libxcb-cursor0` en el sistema donde se
ejecuta (no se puede embeber vía PyInstaller). Si el binario no
arranca con un error de plugin `xcb`, instalar:

```bash
# Debian/Ubuntu/Kali
sudo apt install libxcb-cursor0
```

## Aviso de uso

Igual que el script original: uso exclusivo en sistemas con
autorización explícita por escrito. Herramienta de pruebas pasivas y
semi-activas — complementar con análisis manual.
