#!/bin/bash
cd /home/claude/webscanpro-gui

declare -A tests=(
  ["error-based_VULN"]="http://127.0.0.1:8801/buscar?q=test|VULN"
  ["error-based_SAFE"]="http://127.0.0.1:8802/buscar?q=test|SAFE"
  ["boolean_VULN"]="http://127.0.0.1:8801/login?user=test|VULN"
  ["boolean_SAFE"]="http://127.0.0.1:8802/login?user=test|SAFE"
  ["union_VULN"]="http://127.0.0.1:8801/reporte?id=1|VULN"
  ["union_SAFE"]="http://127.0.0.1:8802/reporte?id=1|SAFE"
  ["timing_falso_positivo"]="http://127.0.0.1:8803/|SAFE"
  ["dinamico_legitimo"]="http://127.0.0.1:8801/dinamico?user=test|SAFE"
  ["headers_SECURE"]="http://127.0.0.1:8802/|HEADERS_SAFE"
  ["headers_INSECURE"]="http://127.0.0.1:8801/|HEADERS_VULN"
)

all_ok=1
for name in "${!tests[@]}"; do
  entry="${tests[$name]}"
  url="${entry%%|*}"
  expect="${entry#*|}"

  if [[ "$expect" == HEADERS_* ]]; then
    only="headers"
  else
    only="sqli"
  fi

  out=$(bash webscanpro.sh -u "$url" --only "$only" -o "/tmp/final_${name}" 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g')
  count=$(echo "$out" | grep -c "^\s*\[CRÍTICO\]\|^\s*\[ALTO\]\|^\s*\[MEDIO\]\|^\s*\[BAJO\]")

  case "$expect" in
    VULN)
      if [[ $count -gt 0 ]]; then echo "OK    [$name] -> detectado ($count hallazgos)"; else echo "FALLO [$name] -> NO detectado (debia detectarse)"; all_ok=0; fi
      ;;
    SAFE)
      if [[ $count -eq 0 ]]; then echo "OK    [$name] -> limpio (0 hallazgos)"; else echo "FALLO [$name] -> FALSO POSITIVO ($count hallazgos)"; all_ok=0; fi
      ;;
    HEADERS_SAFE)
      # solo debe quedar la divulgacion de version del server (1 hallazgo BAJO)
      if [[ $count -le 1 ]]; then echo "OK    [$name] -> $count hallazgo(s) (solo version del server esperada)"; else echo "FALLO [$name] -> $count hallazgos (esperabamos <=1)"; all_ok=0; fi
      ;;
    HEADERS_VULN)
      if [[ $count -ge 6 ]]; then echo "OK    [$name] -> $count hallazgos (cabeceras ausentes detectadas)"; else echo "FALLO [$name] -> solo $count hallazgos (esperabamos >=6)"; all_ok=0; fi
      ;;
  esac
done

echo ""
if [[ $all_ok -eq 1 ]]; then
  echo "==================================="
  echo "TODOS LOS TESTS DE REGRESION: OK"
  echo "==================================="
else
  echo "==================================="
  echo "HAY TESTS FALLANDO -- revisar arriba"
  echo "==================================="
fi
