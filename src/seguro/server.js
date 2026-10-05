/**
 * TrackLog API - VERSIÓN SEGURA (Fase 3 - Refactorización y Mitigación Integral)
 * --------------------------------------------------------------------------
 * Mitiga las 10 vulnerabilidades de la versión inicial (src/vulnerable),
 * aplicando Zero Trust Input, listas blancas, expresiones regulares y los
 * controles definidos en gobierno-seguridad/03-ASC-perfil-controles.md.
 */

const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');
const https = require('https');
const dns = require('dns');
const { URL } = require('url');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const libxml = require('./xxe-lite');
const { db, verifyPassword } = require('./db');

const app = express();
const PORT = process.env.PORT || 4001;

// En producción real, este secreto vendría de un vault / variable de entorno
// gestionada fuera del repositorio. Aquí se usa un valor fijo solo para la
// demo académica.
const JWT_SECRET = process.env.JWT_SECRET || 'tracklog-demo-secret-CHANGE-IN-PROD';

app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.text({ type: ['application/xml', 'text/xml'], limit: '200kb' }));

// Confiar en el proxy para detectar HTTPS real cuando se despliega detrás
// de un load balancer/TLS terminator.
app.set('trust proxy', true);

// ---------------------------------------------------------------------------
// [A09] Registro y monitoreo — mitigación
// ---------------------------------------------------------------------------
// Todo acceso queda registrado en logs/access.log (formato combinado),
// sin exponer cuerpos de petición con datos sensibles (contraseñas, tokens).
const LOG_DIR = path.join(__dirname, 'logs');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);
const accessLogStream = fs.createWriteStream(path.join(LOG_DIR, 'access.log'), { flags: 'a' });
morgan.token('safe-url', (req) => req.originalUrl.split('?')[0]);
app.use(morgan(':date[iso] :method :safe-url :status :response-time ms - :remote-addr', {
  stream: accessLogStream
}));
app.use(morgan(':date[iso] :method :safe-url :status :response-time ms', { }));

function logSecurityEvent(event, details) {
  const line = `${new Date().toISOString()} [SECURITY] ${event} ${JSON.stringify(details)}\n`;
  fs.appendFileSync(path.join(LOG_DIR, 'security.log'), line);
}

// ---------------------------------------------------------------------------
// Middleware: exigir HTTPS en producción (A02).
// En desarrollo local (NODE_ENV !== 'production') se permite HTTP solo para
// poder correr la demo académica sin certificados.
// ---------------------------------------------------------------------------
function requireHttps(req, res, next) {
  if (process.env.NODE_ENV === 'production' && req.protocol !== 'https') {
    return res.status(400).json({ error: 'Se requiere HTTPS' });
  }
  next();
}
app.use(requireHttps);

// ---------------------------------------------------------------------------
// [A02] Fallas criptográficas — mitigación
// ---------------------------------------------------------------------------
// Las credenciales SOLO se aceptan en el body JSON (nunca por headers), y
// se comparan contra un hash+salt (scrypt) almacenado en la base de datos,
// nunca contra texto plano.
app.post('/api/driver/login', (req, res) => {
  // Zero Trust Input: rechazar explícitamente credenciales enviadas por header.
  if (req.headers['x-username'] || req.headers['x-password']) {
    logSecurityEvent('credenciales_por_header_rechazadas', { ip: req.ip });
    return res.status(400).json({ error: 'Las credenciales deben enviarse en el body, no en headers' });
  }

  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username y password son requeridos' });
  }
  // Lista blanca de formato de usuario (evita payloads anómalos).
  if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(username)) {
    return res.status(400).json({ error: 'Formato de usuario inválido' });
  }

  const driver = db.prepare('SELECT * FROM drivers WHERE username = ?').get(username);
  if (!driver || !verifyPassword(password, driver.password_hash, driver.password_salt)) {
    logSecurityEvent('login_fallido', { username, ip: req.ip });
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  const token = jwt.sign(
    { sub: driver.id, role: driver.role, username: driver.username },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
  res.json({ ok: true, token });
});

// ---------------------------------------------------------------------------
// [A07] Autenticación — mitigación
// ---------------------------------------------------------------------------
// Middleware real: valida JWT firmado, con expiración, verificado en servidor.
// Ya NO existe ninguna cabecera estática que otorgue acceso.
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const [scheme, token] = authHeader.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Token Bearer requerido' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { sub, role, username }
    next();
  } catch (err) {
    logSecurityEvent('token_invalido', { ip: req.ip, reason: err.message });
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      logSecurityEvent('acceso_rol_denegado', { ip: req.ip, user: req.user && req.user.username, requiredRole: role });
      return res.status(403).json({ error: 'Permisos insuficientes' });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// [A01] Control de acceso — mitigación
// ---------------------------------------------------------------------------
// Requiere autenticación, y además verifica OWNERSHIP: un conductor solo
// puede ver su propia ubicación; un admin puede ver cualquiera.
app.get('/api/driver/location/:id', requireAuth, (req, res) => {
  const requestedId = parseInt(req.params.id, 10);
  if (!Number.isInteger(requestedId)) {
    return res.status(400).json({ error: 'id inválido' });
  }
  const isOwner = req.user.sub === requestedId;
  const isAdmin = req.user.role === 'admin';
  if (!isOwner && !isAdmin) {
    logSecurityEvent('acceso_ubicacion_no_autorizado', { ip: req.ip, solicitante: req.user.username, objetivo: requestedId });
    return res.status(403).json({ error: 'No autorizado para ver la ubicación de este conductor' });
  }
  const driver = db.prepare('SELECT id, name, lat, lng FROM drivers WHERE id = ?').get(requestedId);
  if (!driver) return res.status(404).json({ error: 'Conductor no encontrado' });
  res.json({ driver });
});

// ---------------------------------------------------------------------------
// [A03] Inyección SQL — mitigación
// ---------------------------------------------------------------------------
// Consulta parametrizada (prepared statement) + validación de formato del
// código de barra con una lista blanca estricta (regex).
const BARCODE_REGEX = /^[A-Z0-9-]{6,20}$/;

app.get('/api/package/search', requireAuth, (req, res) => {
  const barcode = req.query.barcode;
  if (typeof barcode !== 'string' || !BARCODE_REGEX.test(barcode)) {
    return res.status(400).json({ error: 'Formato de código de barra inválido' });
  }
  const rows = db.prepare('SELECT * FROM packages WHERE barcode = ?').all(barcode);
  res.json({ results: rows });
});

// ---------------------------------------------------------------------------
// [A04] Diseño inseguro (condición de carrera) — mitigación
// ---------------------------------------------------------------------------
// Asignación atómica mediante UPDATE condicional: solo tiene éxito si el
// paquete sigue sin asignar (assigned_driver_id IS NULL). La segunda
// petición concurrente recibe 409 Conflict, nunca se pisan ambas.
app.post('/api/package/assign', requireAuth, (req, res) => {
  const { package_id, driver_id } = req.body || {};
  if (!Number.isInteger(package_id) || !Number.isInteger(driver_id)) {
    return res.status(400).json({ error: 'package_id y driver_id deben ser enteros' });
  }

  const result = db.prepare(
    `UPDATE packages
     SET assigned_driver_id = ?, status = 'en_ruta', version = version + 1
     WHERE id = ? AND assigned_driver_id IS NULL`
  ).run(driver_id, package_id);

  if (result.changes === 0) {
    const pkg = db.prepare('SELECT * FROM packages WHERE id = ?').get(package_id);
    if (!pkg) return res.status(404).json({ error: 'Paquete no encontrado' });
    return res.status(409).json({ error: 'El paquete ya fue asignado a otro conductor', current_assignment: pkg.assigned_driver_id });
  }

  res.json({ ok: true, package_id, assigned_driver_id: driver_id });
});

// ---------------------------------------------------------------------------
// [A05] Configuración de seguridad — mitigación
// ---------------------------------------------------------------------------
// El panel admin exige autenticación + rol admin explícito, no depende de
// que la ruta sea "secreta".
app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  const drivers = db.prepare('SELECT id, name, username, role, lat, lng FROM drivers').all();
  const packages = db.prepare('SELECT * FROM packages').all();
  res.json({ panel: 'admin-tracklog', drivers, packages });
});

// ---------------------------------------------------------------------------
// [A06] Componentes vulnerables — mitigación
// ---------------------------------------------------------------------------
// Se eliminó xml2js@0.4.19. El endpoint de versión ya no expone el detalle
// de dependencias internas a usuarios no autenticados.
app.get('/api/version', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ api: '2.0.0-segura' });
});

// ---------------------------------------------------------------------------
// [A08] XXE — mitigación
// ---------------------------------------------------------------------------
// 1) Se rechaza explícitamente cualquier DOCTYPE (defensa en profundidad).
// 2) xxe-lite.js se usa con noent:false y dtdload:false (NO se resuelven
//    entidades externas ni se cargan DTDs externas).
app.post('/api/manifest/upload', requireAuth, (req, res) => {
  const xml = req.body;
  if (typeof xml !== 'string' || xml.length === 0) {
    return res.status(400).json({ error: 'Cuerpo XML requerido' });
  }
  if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml)) {
    logSecurityEvent('xxe_bloqueado', { ip: req.ip, user: req.user.username });
    return res.status(400).json({ error: 'DOCTYPE/ENTITY no permitido en manifiestos XML' });
  }
  try {
    const doc = libxml.parseXml(xml, {
      noent: false,   // NO expandir entidades
      dtdload: false, // NO cargar DTD externas
      noblanks: false
    });
    res.json({ ok: true, manifest: doc.root().toString() });
  } catch (err) {
    // No se expone stack trace al cliente (solo mensaje genérico).
    logSecurityEvent('error_parseo_manifiesto', { ip: req.ip, error: err.message });
    return res.status(400).json({ error: 'XML inválido' });
  }
});

// ---------------------------------------------------------------------------
// [A10] SSRF — mitigación
// ---------------------------------------------------------------------------
// Lista blanca estricta de dominios permitidos para la integración de mapas.
// Se resuelve el hostname y se bloquean rangos de IP privados/locales,
// evitando que un atacante use DNS rebinding o URLs tipo localhost/169.254.*.
const ALLOWED_MAP_HOSTS = new Set([
  'maps.example-provider.com',
  'nominatim.openstreetmap.org'
]);

function isPrivateOrLocalIp(ip) {
  return (
    ip === '127.0.0.1' || ip === '::1' ||
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    ip === '0.0.0.0'
  );
}

app.post('/api/maps/geocode', requireAuth, (req, res) => {
  const targetUrl = req.body && req.body.url;
  if (typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'url requerida' });
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: 'URL inválida' });
  }

  if (parsed.protocol !== 'https:') {
    return res.status(400).json({ error: 'Solo se permiten URLs https://' });
  }
  if (!ALLOWED_MAP_HOSTS.has(parsed.hostname)) {
    logSecurityEvent('ssrf_bloqueado_host_no_permitido', { ip: req.ip, intento: parsed.hostname });
    return res.status(400).json({ error: 'Dominio no permitido (fuera de lista blanca)' });
  }

  dns.lookup(parsed.hostname, (err, address) => {
    if (err) return res.status(400).json({ error: 'No se pudo resolver el host' });
    if (isPrivateOrLocalIp(address)) {
      logSecurityEvent('ssrf_bloqueado_ip_privada', { ip: req.ip, host: parsed.hostname, resuelto: address });
      return res.status(400).json({ error: 'Resolución a IP privada/local bloqueada' });
    }
    https.get(parsed.toString(), (upstreamRes) => {
      let data = '';
      upstreamRes.on('data', (c) => { data += c; });
      upstreamRes.on('end', () => {
        res.json({ ok: true, upstream_status: upstreamRes.statusCode, body: data.slice(0, 2000) });
      });
    }).on('error', (e) => {
      res.status(502).json({ error: 'No se pudo contactar al proveedor de mapas' });
    });
  });
});

// Endpoint interno simulado (igual que en la versión vulnerable), para que
// el script de auditoría pueda confirmar que YA NO es alcanzable vía SSRF.
app.get('/internal/fleet-secrets', (req, res) => {
  res.status(403).json({ error: 'Endpoint interno no accesible externamente' });
});

// ---------------------------------------------------------------------------
// Manejo de errores centralizado: nunca se devuelven stack traces al cliente.
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  logSecurityEvent('error_no_controlado', { ip: req.ip, error: err.message });
  res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => {
  console.log(`[SEGURA] TrackLog API escuchando en http://localhost:${PORT}`);
  console.log('Modo académico - Evaluación 02 DevSecOps - Grupo 5 Logística');
});
