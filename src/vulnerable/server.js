/**
 * TrackLog API - VERSION VULNERABLE (Fase 1 - Auditoría de Código Inseguro)
 * -------------------------------------------------------------------------
 * Uso exclusivamente académico (Evaluación 02 - DevSecOps).
 * Esta API contiene 10 vulnerabilidades DELIBERADAS, una por cada
 * categoría del OWASP Top 10, según el caso asignado (Grupo 5 - Logística).
 *
 * NO DESPLEGAR EN PRODUCCIÓN NI EXPONER A INTERNET PÚBLICO.
 */

const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');
const xml2js = require('xml2js');
const libxml = require('./xxe-lite');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(bodyParser.json());
// Body parser de texto para aceptar XML crudo en /api/manifest/upload
app.use(bodyParser.text({ type: ['application/xml', 'text/xml'] }));

// ---------------------------------------------------------------------------
// [A09] Fallas de registro y monitoreo
// ---------------------------------------------------------------------------
// A PROPÓSITO: no existe ningún middleware de logging. Ningún acceso,
// error o intento de ataque queda registrado en ningún archivo ni consola
// estructurada. "Por rendimiento" se deshabilitó por completo.
// (No agregar morgan, winston, ni console.log de auditoría aquí).

// ---------------------------------------------------------------------------
// [A07] Fallas de identificación y autenticación
// ---------------------------------------------------------------------------
// Middleware de autenticación basado en una cabecera estática falsificable.
// Cualquiera que envíe "X-Driver-Auth: true" se considera autenticado,
// sin firma, sin token, sin expiración.
function fakeAuth(req, res, next) {
  if (req.headers['x-driver-auth'] === 'true') {
    req.user = { authenticated: true, role: 'driver' };
    return next();
  }
  return res.status(401).json({ error: 'No autenticado' });
}

// ---------------------------------------------------------------------------
// [A01] Control de acceso roto
// ---------------------------------------------------------------------------
// Endpoint expone las coordenadas GPS de CUALQUIER conductor por id,
// sin validar que el solicitante tenga permiso sobre ese conductor.
// No requiere ni siquiera el fakeAuth de arriba.
app.get('/api/driver/location/:id', (req, res) => {
  const driver = db.prepare('SELECT id, name, lat, lng FROM drivers WHERE id = ?').get(req.params.id);
  if (!driver) return res.status(404).json({ error: 'Conductor no encontrado' });
  // Se devuelve la ubicación exacta sin ningún control de autorización.
  res.json({ driver });
});

// ---------------------------------------------------------------------------
// [A02] Fallas criptográficas
// ---------------------------------------------------------------------------
// Login que recibe usuario/contraseña por cabeceras HTTP, en texto plano,
// sin exigir TLS, y compara contra contraseñas almacenadas sin hash.
app.post('/api/driver/login', (req, res) => {
  const username = req.headers['x-username'];
  const password = req.headers['x-password']; // <-- credenciales en texto plano por cabecera
  const driver = db.prepare('SELECT * FROM drivers WHERE username = ? AND password = ?').get(username, password);
  if (!driver) return res.status(401).json({ error: 'Credenciales inválidas' });
  // "Token" trivial, sin firma, sin expiración.
  res.json({ ok: true, token: 'static-token-' + driver.id, driver: { id: driver.id, name: driver.name } });
});

// ---------------------------------------------------------------------------
// [A03] Inyección SQL
// ---------------------------------------------------------------------------
// Búsqueda de paquetes por código de barra concatenando el input
// directamente en la consulta SQL (sin parametrizar, sin validar formato).
app.get('/api/package/search', (req, res) => {
  const barcode = req.query.barcode || '';
  const query = `SELECT * FROM packages WHERE barcode = '${barcode}'`; // <-- inyección SQL
  try {
    const rows = db.prepare(query).all();
    res.json({ query_executed: query, results: rows });
  } catch (err) {
    // [A09/A06 agravante] Se expone el stack trace y detalle interno del error.
    res.status(500).json({ error: err.message, stack: err.stack, query });
  }
});

// ---------------------------------------------------------------------------
// [A04] Diseño inseguro (condición de carrera)
// ---------------------------------------------------------------------------
// Asignación de paquete a un conductor SIN control de concurrencia:
// se lee el estado, se espera (simulando trabajo), y luego se escribe,
// permitiendo que dos conductores "ganen" la misma asignación si llegan
// solicitudes simultáneas.
app.post('/api/package/assign', (req, res) => {
  const { package_id, driver_id } = req.body;
  const pkg = db.prepare('SELECT * FROM packages WHERE id = ?').get(package_id);
  if (!pkg) return res.status(404).json({ error: 'Paquete no encontrado' });

  // Ventana de carrera deliberada: entre la lectura y la escritura
  // no hay bloqueo ni transacción atómica.
  setTimeout(() => {
    db.prepare('UPDATE packages SET assigned_driver_id = ?, status = ? WHERE id = ?')
      .run(driver_id, 'en_ruta', package_id);
    res.json({ ok: true, package_id, assigned_driver_id: driver_id });
  }, 150);
});

// ---------------------------------------------------------------------------
// [A05] Configuración de seguridad incorrecta
// ---------------------------------------------------------------------------
// Panel de administración "protegido" únicamente porque la ruta no está
// documentada (security through obscurity). No hay autenticación real.
app.get('/admin', (req, res) => {
  const drivers = db.prepare('SELECT * FROM drivers').all();
  const packages = db.prepare('SELECT * FROM packages').all();
  res.json({ panel: 'admin-tracklog', drivers, packages });
});

// ---------------------------------------------------------------------------
// [A06] Componentes vulnerables y desactualizados
// ---------------------------------------------------------------------------
// Ver package.json: se fija deliberadamente xml2js@0.4.19, versión antigua
// con soporte de entidades externas habilitado por defecto (ver A08 abajo).
app.get('/api/version', (req, res) => {
  // Además, se expone información interna de versiones (ayuda a un atacante).
  res.json({
    api: '1.0.0-vulnerable',
    dependencies: require('./package.json').dependencies
  });
});

// ---------------------------------------------------------------------------
// [A08] Fallas de integridad de software y datos (XXE)
// ---------------------------------------------------------------------------
// Procesa manifiestos XML de carga SIN deshabilitar la resolución de
// entidades externas, permitiendo ataques XXE (lectura de archivos locales,
// SSRF interno, denegación de servicio).
app.post('/api/manifest/upload', fakeAuth, (req, res) => {
  const xml = req.body;
  try {
    // xxe-lite.js con noent:true EXPANDE entidades externas definidas en el
    // DOCTYPE (XXE clásico): un atacante puede leer archivos locales del
    // servidor (/etc/passwd, C:\Windows\win.ini, credenciales, etc.) incrustando
    // el contenido en la respuesta JSON.
    const doc = libxml.parseXml(xml, {
      noent: true,      // sustituye entidades (incluye SYSTEM/external)
      dtdload: true,    // carga DTD externas
      noblanks: false
    });
    res.json({ ok: true, manifest: doc.root().toString() });
  } catch (err) {
    // [A09 agravante] Se expone el stack trace y detalle interno del error.
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ---------------------------------------------------------------------------
// [A10] Server-Side Request Forgery (SSRF)
// ---------------------------------------------------------------------------
// Integración con "servicios de mapas de terceros": el servidor hace una
// petición HTTP saliente a la URL que el usuario especifique, sin validar
// contra ninguna lista blanca de dominios permitidos.
app.post('/api/maps/geocode', (req, res) => {
  const targetUrl = req.body.url;
  if (!targetUrl) return res.status(400).json({ error: 'url requerida' });

  http.get(targetUrl, (upstreamRes) => {
    let data = '';
    upstreamRes.on('data', (chunk) => { data += chunk; });
    upstreamRes.on('end', () => {
      res.json({ ok: true, fetched_url: targetUrl, upstream_status: upstreamRes.statusCode, body: data });
    });
  }).on('error', (err) => {
    res.status(500).json({ error: err.message, fetched_url: targetUrl });
  });
});

// ---------------------------------------------------------------------------
// Endpoint "interno" simulado para demostrar el impacto real del SSRF
// (equivalente a un recurso interno que nunca debería ser alcanzable
// desde fuera: p. ej. un endpoint de administración de flota interno).
// ---------------------------------------------------------------------------
app.get('/internal/fleet-secrets', (req, res) => {
  res.json({
    warning: 'Este endpoint simula un recurso interno NO expuesto públicamente.',
    fleet_master_key: 'INTERNAL-KEY-TRACKLOG-2024-XYZ',
    note: 'Alcanzado vía SSRF a través de /api/maps/geocode'
  });
});

app.listen(PORT, () => {
  console.log(`[VULNERABLE] TrackLog API escuchando en http://localhost:${PORT}`);
  console.log('Modo académico - Evaluación 02 DevSecOps - Grupo 5 Logística');
});
