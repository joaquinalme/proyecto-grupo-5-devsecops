# TrackLog API — Versión Vulnerable (Fase 1)

API Node.js/Express con **10 vulnerabilidades deliberadas**, una por cada categoría del OWASP Top 10, correspondientes al caso asignado al Grupo 5 (Logística).


## Instalación y ejecución

Requiere **Node.js 22.5 o superior** (usa `node:sqlite`, incluido en Node.js; no hay dependencias nativas que compilar, así que no se necesita Visual Studio ni build tools).

```bash
npm install
npm start
# API disponible en http://localhost:4000
```

## Archivos de esta carpeta

| Archivo | Contenido |
|---|---|
| `server.js` | La API Express. Cada endpoint tiene un comentario `[A0x]` indicando qué vulnerabilidad OWASP demuestra. |
| `db.js` | Base de datos SQLite en memoria (`node:sqlite`, incluido en Node.js) con datos de ejemplo (conductores y paquetes). Las contraseñas están en texto plano a propósito (A02). |
| `xxe-lite.js` | Parser XML propio, sin dependencias nativas, usado por el endpoint `/api/manifest/upload`. Aquí se llama con `noent:true, dtdload:true`, por lo que SÍ resuelve entidades externas (XXE). |
| `package.json` | Dependencias del proyecto. Nota: `xml2js@0.4.19` está fijada deliberadamente como "componente desactualizado" para la demo de A06. |

## Mapa de vulnerabilidades → endpoint

| OWASP | Vulnerabilidad | Endpoint |
|---|---|---|
| A01 | Control de acceso roto | `GET /api/driver/location/:id` |
| A02 | Fallas criptográficas | `POST /api/driver/login` (credenciales por header, texto plano) |
| A03 | Inyección SQL | `GET /api/package/search?barcode=` |
| A04 | Diseño inseguro (race condition) | `POST /api/package/assign` |
| A05 | Configuración de seguridad incorrecta | `GET /admin` |
| A06 | Componentes vulnerables | `xml2js@0.4.19` fijada en `package.json`; expuesta en `GET /api/version` |
| A07 | Autenticación rota (header falsificable) | Middleware `fakeAuth` (`X-Driver-Auth: true`) |
| A08 | XXE | `POST /api/manifest/upload` (usa `xxe-lite.js` propio con `noent:true`) |
| A09 | Falta de logging | Ausencia total de middleware de registro |
| A10 | SSRF | `POST /api/maps/geocode` (+ endpoint interno simulado `/internal/fleet-secrets`) |

Ver `../../gobierno-seguridad/03-ASC-perfil-controles.md` para el detalle de cada control esperado, y `../../auditoria/fase1/` para la evidencia de explotación de cada falla.
