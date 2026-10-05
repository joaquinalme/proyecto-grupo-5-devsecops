# proyecto-grupo-5-devsecops

**Evaluación 02 — Ética, Gobernanza (ISO/IEC 27034) y Seguridad Aplicada (OWASP Top 10)**

- **Caso asignado:** Grupo 5 — Logística: TrackLog API (Sistema de Seguimiento de Envíos y Flota)
- **Equipo:** Joaquín Almendares, Kevin Apablaza, Nicolás Flores
- **Profesor:** Dragustin Andrés Fernández Queipul
- **Modalidad:** Grupal (3 integrantes) · **Plazo:** 1 semana · **Puntaje:** 100 pts (exigencia 60%)

---

## 1. Resumen ejecutivo

Este repositorio documenta el trabajo de un equipo de ingeniería de seguridad (DevSecOps) contratado para auditar y blindar **TrackLog API**, una plataforma de logística con vulnerabilidades críticas introducidas deliberadamente para fines académicos.

El proceso siguió cuatro fases:

1. **Gobernanza** — manifiesto ético y marco normativo (ISO/IEC 27034) que definen la responsabilidad del equipo y los controles exigidos.
2. **Auditoría de código inseguro** — se desplegó la API original (`src/vulnerable/`) y se explotaron las 10 vulnerabilidades del OWASP Top 10, con evidencia real capturada vía `curl` (el binario real, tanto en `auditoria.sh` como en `auditoria.ps1`) (`auditoria/fase1/`).
3. **Refactorización y mitigación** — se reescribió la API (`src/seguro/`) aplicando *Zero Trust Input*, listas blancas, expresiones regulares y los 10 controles defensivos correspondientes.
4. **Re-auditoría de cierre** — se repitieron los mismos ataques contra la versión segura, confirmando códigos de respuesta defensivos controlados (`auditoria/fase2/`).

**Resultado:** las 10 vulnerabilidades fueron explotadas exitosamente en la Fase 1 (evidencia con HTTP 200 y datos filtrados) y quedaron mitigadas en la Fase 2 (HTTP 400/401/403/409, sin fuga de información).

## 2. Cómo se evalúa este proyecto (mapeo a la pauta)

Para facilitar la revisión, cada criterio de la pauta de evaluación tiene su evidencia en una ubicación específica del repositorio:

| # | Criterio (ponderación) | Dónde está la evidencia |
|---|---|---|
| 1 | Ética y Responsabilidad Social (**10%**) | [`gobierno-seguridad/01-manifiesto-etico.md`](gobierno-seguridad/01-manifiesto-etico.md) |
| 2 | Gobernanza ISO/IEC 27034 — ONF y ASC (**15%**) | [`gobierno-seguridad/02-ONF-marco-normativo.md`](gobierno-seguridad/02-ONF-marco-normativo.md) y [`gobierno-seguridad/03-ASC-perfil-controles.md`](gobierno-seguridad/03-ASC-perfil-controles.md) |
| 3 | Auditoría e Identificación de Fallos — Fase 1 Insegura (**20%**) | API vulnerable en [`src/vulnerable/`](src/vulnerable/) + evidencia cruda en [`auditoria/fase1/evidencia/`](auditoria/fase1/evidencia/) (10 archivos `.txt`, uno por riesgo OWASP) |
| 4 | Mitigación Integral del OWASP Top 10 (**30%**) | API refactorizada en [`src/seguro/`](src/seguro/) + re-pruebas en [`auditoria/fase2/evidencia/`](auditoria/fase2/evidencia/) (códigos 400/401/403/409 en los 10 riesgos) |
| 5 | Validación Robusta y Regex / *Zero Trust Input* (**15%**) | Implementado en `src/seguro/server.js`: `BARCODE_REGEX` (A03), validación de `username` (A02), `Number.isInteger` en IDs (A01/A04), lista blanca `ALLOWED_MAP_HOSTS` (A10) |
| 6 | Trazabilidad y Repositorio GitHub / *Docs-as-Code* (**10%**) | Estructura de carpetas de este repositorio + este mismo `README.md` + historial de commits en GitHub (ver sección 9 — **pendiente de subir**) |

> El detalle control-por-control (qué exige la norma y cómo se implementó) está en [`gobierno-seguridad/03-ASC-perfil-controles.md`](gobierno-seguridad/03-ASC-perfil-controles.md).

## 3. Estructura del repositorio — qué es cada cosa

```
proyecto-grupo-5-devsecops/
├── README.md                          <- este archivo: punto de entrada para el profesor
│
├── gobierno-seguridad/                <- Fase de Análisis Ético y Normativo (Sesiones 2.1-2.2)
│   ├── 01-manifiesto-etico.md         <- responsabilidad del desarrollador ante pérdida de datos
│   ├── 02-ONF-marco-normativo.md      <- Marco Normativo Organizacional (ISO/IEC 27034)
│   └── 03-ASC-perfil-controles.md     <- perfil de controles de seguridad de la aplicación (ASC)
│
├── src/
│   ├── vulnerable/                    <- Fase 1: API con las 10 fallas OWASP a propósito
│   │   ├── server.js                  <- endpoints, cada uno con un comentario [A0x] marcando la falla
│   │   ├── db.js                      <- base de datos SQLite en memoria (node:sqlite, sin instalar nada)
│   │   ├── xxe-lite.js                <- parser XML propio que SÍ resuelve entidades externas (XXE)
│   │   ├── package.json               <- dependencias (sin binarios nativos, ver sección 4)
│   │   └── README.md                  <- mapa vulnerabilidad -> endpoint, instrucciones propias
│   │
│   └── seguro/                        <- Fase 3: API refactorizada, los mismos endpoints pero blindados
│       ├── server.js                  <- cada endpoint con comentario [A0x] explicando la mitigación
│       ├── db.js                      <- igual que arriba, pero contraseñas con hash+salt (scrypt)
│       ├── xxe-lite.js                <- mismo parser, aquí usado con entidades externas DESHABILITADAS
│       ├── package.json               <- dependencias
│       ├── README.md                  <- mapa vulnerabilidad -> mitigación, usuarios de prueba
│       └── logs/                      <- access.log y security.log (se generan solos al correr la API)
│
└── auditoria/                         <- Scripts y evidencia de pentesting (Fases 1 y 2)
    ├── auditoria.sh                   <- script de pruebas con curl (Mac/Linux/WSL/Git Bash)
    ├── auditoria.ps1                  <- mismo script, en PowerShell, invocando curl.exe real (Windows nativo)
    ├── fase1/evidencia/*.txt          <- 10 archivos: respuesta cruda de cada ataque contra la API vulnerable
    └── fase2/evidencia/*.txt          <- 11 archivos: respuesta cruda de cada re-prueba contra la API segura
```

**Qué NO está versionado (ver `.gitignore`):** `node_modules/` de cada API (se regenera con `npm install`), los `logs/*.log` de `src/seguro/` (se regeneran solos al correr la API) y archivos `.env`.

## 4. Requisitos previos

| Requisito | Versión | Notas |
|---|---|---|
| **Node.js** | **≥ 22.5.0** (se probó con 24.21.0) | Trae incluido el módulo `node:sqlite`; no se necesita instalar ninguna base de datos ni compilador. Verifica con `node --version`. |
| **npm** | el que viene con Node.js | Se usa solo para instalar `express`, `body-parser`, etc. (todas son librerías en JavaScript puro, **ninguna requiere compilación nativa**). |
| **curl** | el que venga con el sistema | Lo exige el enunciado para las pruebas de penetración (punto 1.1.1.b). `auditoria.sh` y `auditoria.ps1` invocan el binario real de `curl` (no un alias ni una librería HTTP). En Windows 10/11 viene preinstalado como `curl.exe`; en Mac/Linux normalmente también viene preinstalado. Verifica con `curl --version` (Mac/Linux) o `curl.exe --version` (Windows). |
| **Visual Studio / Build Tools** | **no se necesita** | Versiones anteriores de este proyecto usaban `better-sqlite3` y `libxmljs2` (dependencias nativas) y requerían compilador en Windows. Eso se eliminó — ver sección 6. |

No hace falta instalar ninguna base de datos externa (SQLite corre en memoria, embebida en el proceso de Node) ni ningún parser XML externo.

## 5. Roles del equipo

| Integrante | Rol asumido (ISO/IEC 27034) |
|---|---|
| Kevin Apablaza | Arquitecto de seguridad — diseño de controles ASC y refactorización |
| Joaquín Almendares | Auditor / pentester — ejecución de `auditoria.ps1`/`auditoria.sh` y documentación de hallazgos |
| Nicolás Flores | Responsable de gobernanza y cumplimiento — manifiesto ético, ONF/ASC, README |

## 6. Cómo reproducir la auditoría completa

La API (Node.js) corre igual en **Windows, Mac o Linux**. Lo único que cambia entre sistemas operativos es el **script de auditoría**: hay una versión en Bash (`auditoria.sh`, para Mac/Linux/WSL/Git Bash) y una versión en PowerShell (`auditoria.ps1`, para Windows nativo). Ambas hacen exactamente lo mismo.

### 6.1 Fase 1 — Explotar la API vulnerable

**Mac / Linux / WSL / Git Bash:**
```bash
cd src/vulnerable
npm install
npm start &            # queda escuchando en http://localhost:4000

cd ../../auditoria
BASE_URL=http://localhost:4000 ./auditoria.sh vulnerable
# Evidencia generada en auditoria/fase1/evidencia/*.txt
```

**Windows (PowerShell):**
```powershell
cd src\vulnerable
npm install
Start-Process npm -ArgumentList "start"   # abre la API en otra ventana, http://localhost:4000

cd ..\..\auditoria
.\auditoria.ps1 -Mode vulnerable -BaseUrl http://localhost:4000
# Evidencia generada en auditoria\fase1\evidencia\*.txt
```

### 6.2 Fase 3 — Levantar la API segura y re-auditar

**Mac / Linux / WSL / Git Bash:**
```bash
cd src/seguro
npm install
npm start &            # queda escuchando en http://localhost:4001

cd ../../auditoria
BASE_URL=http://localhost:4001 ./auditoria.sh seguro
# Evidencia generada en auditoria/fase2/evidencia/*.txt
```

**Windows (PowerShell):**
```powershell
cd src\seguro
npm install
Start-Process npm -ArgumentList "start"   # http://localhost:4001

cd ..\..\auditoria
.\auditoria.ps1 -Mode seguro -BaseUrl http://localhost:4001
# Evidencia generada en auditoria\fase2\evidencia\*.txt
```

> Usuario de prueba para login: `cfuentes` / `camion2024` (ver más usuarios en `src/seguro/README.md`).

### 6.3 Notas de compatibilidad por sistema operativo

- El proyecto **no usa dependencias nativas** (se eliminaron `better-sqlite3` y `libxmljs2`): la base de datos usa `node:sqlite` (incluido en Node.js ≥ 22.5) y el parseo XML usa `xxe-lite.js`, un módulo propio sin binarios que compilar. Esto evita por completo los errores de `node-gyp`/Visual Studio al correr `npm install` en Windows, incluyendo el problema conocido de Visual Studio 2026 (versión "18"), que `node-gyp` todavía no reconoce.
- Si en Windows el comando `.\auditoria.ps1` (o `npm install`) se bloquea con un mensaje de "la ejecución de scripts está deshabilitada en este sistema", es la política de ejecución de PowerShell. Se soluciona corriendo, **una sola vez por sesión de terminal**:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  ```
  (responde `S`/`Sí` cuando pregunte). No afecta el resto del sistema ni requiere ser administrador.
- Si en cambio el error dice que el archivo **"no está firmado digitalmente"** (distinto al anterior: ese mensaje aparece aunque la política ya esté en `RemoteSigned`), es porque Windows marca como "descargado de Internet" cualquier archivo que venga de un `.zip` descargado o copiado desde otro equipo (lo bloquea con el atributo *Mark of the Web*). Se soluciona quitando esa marca a los scripts, una sola vez, desde la carpeta `auditoria/`:
  ```powershell
  Unblock-File .\auditoria.ps1
  ```
  Verifícalo con `Get-ExecutionPolicy -List` (debe mostrar `CurrentUser: RemoteSigned`) y vuelve a correr el script normalmente.
- Al arrancar cualquiera de las dos APIs puede aparecer `ExperimentalWarning: SQLite is an experimental feature`. Es solo informativo (viene de Node.js), no es un error y no afecta la demo.
- El payload de XXE en `auditoria.sh` lee `/etc/hostname` (ruta Linux/Mac); el de `auditoria.ps1` lee `C:\Windows\win.ini` (ruta Windows). Si corres la API vulnerable en un sistema operativo distinto al que corre el script, ajusta esa ruta dentro del script a un archivo que exista en la máquina donde corre la API.
- **Sobre "máquina auditora separada" (enunciado 1.1.1.b):** en esta entrega la API y el script de auditoría corren en el mismo equipo, en dos procesos/terminales distintos (uno sirviendo la API, otro ejecutando `curl` contra ella por HTTP), que es la interpretación estándar para este tipo de ejercicio. Si se quiere una separación física real, basta con apuntar `-BaseUrl`/`BASE_URL` a la IP de la máquina que corre la API dentro de la red local (por ejemplo `http://192.168.1.XX:4000`) y ejecutar el script desde otro equipo de la misma red.

## 7. Resumen de vulnerabilidades y mitigaciones

| # OWASP | Vulnerabilidad (Fase 1) | Evidencia | Mitigación (Fase 3) | Evidencia |
|---|---|---|---|---|
| A01 | Ubicación GPS de cualquier conductor sin control de acceso | `fase1/evidencia/A01_control_acceso.txt` → **200 OK**, filtra coordenadas | Verificación de ownership + rol | `fase2/evidencia/A01_control_acceso.txt` → **403** |
| A02 | Login exitoso con credenciales enviadas en texto plano por header | `A02_credenciales_texto_plano.txt` → **200 OK**, token emitido, credenciales viajaron en claro | Solo se aceptan por body JSON, hash scrypt, HTTPS exigido en prod | `A02_credenciales_texto_plano.txt` → **400** |
| A03 | Inyección SQL en búsqueda de paquetes | `A03_inyeccion_sql.txt` → **200 OK**, fuga de toda la tabla | Prepared statement + regex de formato | `A03_inyeccion_sql.txt` → **400** |
| A04 | Condición de carrera en asignación de paquetes | `A04_condicion_carrera.txt` → ambas solicitudes responden "ok" (se pisan) | `UPDATE` atómico condicional | `A04_condicion_carrera.txt` → primera **200**, segunda **409** |
| A05 | Panel `/admin` expuesto sin autenticación | `A05_panel_admin_expuesto.txt` → **200 OK**, filtra contraseñas | Auth + rol admin explícito | `A05_panel_admin_expuesto.txt` → **401**, `A05b...` (token válido pero rol driver) → **403** |
| A06 | Dependencia `xml2js@0.4.19` vulnerable, versión expuesta sin autenticación | `A06_componentes_vulnerables.txt` → **200 OK** | Dependencia eliminada del código activo; endpoint protegido | `A06_componentes_vulnerables.txt` → **401** |
| A07 | Autenticación falsificable (`X-Driver-Auth: true`) | `A07_autenticacion_falsificada.txt` → **200 OK** | JWT firmado y verificado en servidor | `A07_autenticacion_falsificada.txt` → **401** |
| A08 | XXE — lectura de un archivo del servidor vía entidad externa (p.ej. `/etc/hostname` o `C:\Windows\win.ini`) | `A08_xxe_lectura_archivo.txt` → **200 OK**, contenido del archivo filtrado en la respuesta | Entidades externas deshabilitadas + rechazo explícito de `<!DOCTYPE>`/`<!ENTITY>` | `A08_xxe_lectura_archivo.txt` → **400**, ningún archivo leído |
| A09 | Ningún registro de eventos ni ataques | `A09_falta_logging.txt` → confirma ausencia de carpeta `logs/` | Logging con `morgan` (`access.log`) + log de eventos de seguridad (`security.log`) | `A09_logging_habilitado.txt` → logs reales, incluyendo intentos bloqueados |
| A10 | SSRF hacia recurso interno con clave secreta | `A10_ssrf_recurso_interno.txt` → **200 OK**, `fleet_master_key` filtrada | Lista blanca de dominios + resolución DNS y bloqueo de IP privadas/locales | `A10_ssrf_recurso_interno.txt` → **400** |

Detalle normativo completo de cada control en [`gobierno-seguridad/03-ASC-perfil-controles.md`](gobierno-seguridad/03-ASC-perfil-controles.md).

## 8. Advertencia de uso

El código en `src/vulnerable/` contiene fallas de seguridad **intencionales** con fines exclusivamente educativos (Evaluación 02, DevSecOps). No debe desplegarse en un entorno de producción ni expuesto a redes públicas.

