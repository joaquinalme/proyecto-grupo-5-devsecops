# ASC — Application Security Control Profile (Perfil de Controles de Seguridad)
## Basado en ISO/IEC 27034 — Aplicado a TrackLog API

**Proyecto:** TrackLog API — Sistema de Seguimiento de Envíos y Flota
**Equipo:** Grupo 5 — Logística
**ONF de referencia:** `02-ONF-marco-normativo.md`

---

## 1. ¿Qué es el ASC?

El **ASC (Application Security Control)** es, según ISO/IEC 27034, el conjunto específico de controles de seguridad que se seleccionan del ONF y se aplican a una aplicación concreta, según su nivel de riesgo (ASR — Application Security Risk). Mientras el ONF es el catálogo general de la organización, el ASC es el "traje a medida" para TrackLog API.

## 2. Nivel de riesgo de la aplicación (ASR)

Según lo definido en el ONF, TrackLog API se clasifica como **ASR Nivel Alto**, dado que:

- Expone datos de geolocalización en tiempo real (impacto a la privacidad y seguridad física de personas).
- Gestiona credenciales de acceso de transportistas.
- Está expuesta públicamente en internet.
- Procesa archivos externos (XML) e integra servicios de terceros (mapas).

## 3. Perfil de controles seleccionados (ASC)

| # | Control (OWASP) | Requerimiento de Seguridad (ASR) | Control Técnico Exigido | Evidencia Esperada |
|---|---|---|---|---|
| 1 | **A01 — Control de acceso roto** | Ninguna coordenada GPS debe ser accesible sin validar que el solicitante tiene permiso sobre ese conductor | Verificación de autorización (ownership check) en `/api/driver/location`; control de acceso a nivel de objeto (no solo de endpoint) | Prueba `curl` sin token / con token de otro usuario → 403 Forbidden |
| 2 | **A02 — Fallas criptográficas** | Las credenciales de transportistas no deben viajar en texto plano | Forzar HTTPS/TLS en todas las rutas; prohibir el envío de credenciales por cabeceras sin cifrar | Captura de tráfico o prueba `curl` mostrando rechazo de HTTP plano / cabeceras sin TLS |
| 3 | **A03 — Inyección** | Las consultas de búsqueda de paquetes por código de barra no deben permitir inyección SQL | Uso de *prepared statements* / consultas parametrizadas; validación de formato del código de barra (regex) | `curl` con payload `' OR '1'='1` → respuesta controlada (400), no error de BD expuesto |
| 4 | **A04 — Diseño inseguro** | No deben poder asignarse dos conductores al mismo paquete simultáneamente | Control de concurrencia (bloqueo optimista o transacciones atómicas) en la asignación de paquetes | Prueba de doble asignación concurrente → solo una tiene éxito, la otra recibe 409 Conflict |
| 5 | **A05 — Configuración de seguridad incorrecta** | El panel `/admin` no debe depender de ocultación de ruta | Autenticación y autorización explícitas (roles) para acceder a `/admin`, independiente de si la ruta es conocida | `curl` directo a `/admin` sin credenciales → 401/403, no 200 |
| 6 | **A06 — Componentes vulnerables y desactualizados** | Las librerías de geolocalización no deben tener vulnerabilidades conocidas de desbordamiento de búfer | Actualización de dependencias; uso de `npm audit` / SCA; fijar versiones seguras en `package.json` | Reporte de `npm audit` sin vulnerabilidades críticas/altas |
| 7 | **A07 — Fallas de identificación y autenticación** | La autenticación no puede depender de una cabecera estática falsificable (`X-Driver-Auth: true`) | Autenticación basada en tokens firmados (JWT) con expiración y verificación de firma en servidor | `curl` con `X-Driver-Auth: true` falso → 401 Unauthorized |
| 8 | **A08 — Fallas de integridad de software y datos** | Los manifiestos XML no deben ser vulnerables a XXE | Deshabilitar resolución de entidades externas en el parser XML (`disallow-doctype-decl`, `resolveEntities=false`) | `curl` enviando XML con `<!ENTITY>` → rechazo controlado, sin lectura de archivos del sistema |
| 9 | **A09 — Fallas de registro y monitoreo** | Todos los eventos de ruta y acceso deben quedar registrados | Logging estructurado (sin datos sensibles en claro) de accesos, errores y cambios de estado | Archivo de log mostrando registro de intentos de acceso/ataque durante la auditoría |
| 10 | **A10 — Server-Side Request Forgery (SSRF)** | La integración con mapas de terceros no debe permitir URLs de redirección arbitrarias definidas por el usuario | Lista blanca estricta de dominios permitidos para llamadas salientes; validación de URL contra whitelist | `curl` enviando una URL interna (`http://localhost:...` o `http://169.254.169.254/...`) → rechazo (400), no hay llamada saliente |

## 4. Principios transversales exigidos por el ASC

Estos principios aplican a **todos** los controles anteriores, y son evaluados de forma transversal en la Fase de Refactorización:

- **Zero Trust Input:** ninguna entrada (body, headers, query params, archivos) se procesa sin validación explícita.
- **Listas blancas (whitelisting):** preferidas siempre sobre listas negras (blacklisting), tanto para formatos de entrada como para dominios externos permitidos.
- **Expresiones regulares (Regex) validadas en backend:** toda validación de formato (códigos de barra, IDs, URLs) se realiza en el servidor, nunca solo en el cliente.
- **Manejo seguro de excepciones:** ningún endpoint debe devolver *stack traces* ni mensajes de error que revelen detalles internos de implementación (versión de framework, rutas de archivos, queries SQL).
- **Códigos de respuesta defensivos:** el sistema refactorizado debe responder con códigos HTTP correctos y controlados (400, 401, 403, 409) en lugar de errores 500 no controlados.

## 5. Trazabilidad ASC ↔ Evidencia

Cada control de este ASC debe quedar demostrado en dos momentos, conforme a la estructura del repositorio:

- **`auditoria/fase1/`** → evidencia de que la vulnerabilidad existe en `src/vulnerable/` (explotación exitosa).
- **`auditoria/fase2/`** → evidencia de que el control fue implementado en `src/seguro/` (explotación bloqueada con código de respuesta defensivo).

---

*Documento elaborado en el marco de la Evaluación 02 — Gobernanza ISO/IEC 27034. Este ASC es la base normativa para el diseño de la refactorización de la Fase 3.*
