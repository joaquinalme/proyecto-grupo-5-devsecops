# TrackLog API — Versión Segura (Fase 3)

Refactorización completa de la API, mitigando las 10 vulnerabilidades de `src/vulnerable/` según el perfil de controles (`gobierno-seguridad/03-ASC-perfil-controles.md`).

## Instalación y ejecución

Requiere **Node.js 22.5 o superior** (usa `node:sqlite`, incluido en Node.js; no hay dependencias nativas que compilar, así que no se necesita Visual Studio ni build tools).

```bash
npm install
npm start
# API disponible en http://localhost:4001
```

## Archivos de esta carpeta

| Archivo | Contenido |
|---|---|
| `server.js` | La API Express refactorizada. Cada endpoint tiene un comentario `[A0x]` explicando la mitigación aplicada. |
| `db.js` | Misma base de datos en memoria (`node:sqlite`), pero las contraseñas se guardan con hash + salt (`scrypt`), nunca en texto plano. |
| `xxe-lite.js` | Mismo parser XML propio que en `src/vulnerable/`, aquí llamado con `noent:false, dtdload:false` (no resuelve entidades externas); además `server.js` rechaza cualquier `<!DOCTYPE>`/`<!ENTITY>` antes de llegar al parser. |
| `package.json` | Dependencias. Ya no incluye `xml2js` ni ninguna librería nativa. |
| `logs/` | Se crea sola al arrancar la API (`access.log` y `security.log`); no se sube a git. |

## Usuarios de prueba

| Usuario | Password | Rol |
|---|---|---|
| cfuentes | camion2024 | driver (id=1) |
| msoto | flota#2024 | driver (id=2) |
| jpino | ruta_norte | driver (id=3) |
| admin | AdminSeguro#2024 | admin |

## Mitigaciones implementadas

| OWASP | Mitigación |
|---|---|
| A01 | `requireAuth` + verificación de *ownership* (un conductor solo ve su propia ubicación; admin ve todas) → **403** si no corresponde |
| A02 | Credenciales solo por body JSON (rechaza headers), contraseñas con `scrypt` + salt, HTTPS exigido en producción |
| A03 | Consulta parametrizada + regex de formato de código de barra → **400** ante payload malformado |
| A04 | `UPDATE ... WHERE assigned_driver_id IS NULL` atómico → la segunda asignación concurrente recibe **409 Conflict** |
| A05 | `/admin` exige `requireAuth` + `requireRole('admin')` → **401/403** |
| A06 | Se elimina `xml2js@0.4.19`; dependencias fijadas a versiones mantenidas; endpoint de versión protegido |
| A07 | Autenticación JWT firmada y verificada en servidor; el header estático ya no otorga acceso → **401** |
| A08 | `xxe-lite.js` propio con `noent:false`, `dtdload:false` + rechazo explícito de `<!DOCTYPE>`/`<!ENTITY>` → **400**, sin lectura de archivos |
| A09 | Logging con `morgan` a `logs/access.log` + `logs/security.log` para eventos de seguridad (sin credenciales en claro) |
| A10 | Lista blanca de dominios permitidos + resolución DNS y bloqueo de rangos de IP privados/locales → **400** ante SSRF |

Ver `../../auditoria/fase2/` para la evidencia de las re-pruebas ejecutadas contra esta versión.
