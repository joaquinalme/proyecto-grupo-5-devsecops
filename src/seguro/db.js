// db.js - Base de datos de demostración para TrackLog API (versión SEGURA)
// [A02] Las contraseñas se almacenan con hash + salt (scrypt), nunca en texto plano.
// Usa node:sqlite (módulo nativo incluido en Node.js >= 22.5, sin
// dependencias externas ni compilación). API equivalente a better-sqlite3.

const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');

const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE drivers (
    id INTEGER PRIMARY KEY,
    name TEXT,
    username TEXT UNIQUE,
    password_hash TEXT,
    password_salt TEXT,
    role TEXT DEFAULT 'driver',
    lat REAL,
    lng REAL
  );

  CREATE TABLE packages (
    id INTEGER PRIMARY KEY,
    barcode TEXT,
    description TEXT,
    assigned_driver_id INTEGER,
    status TEXT DEFAULT 'pendiente',
    version INTEGER DEFAULT 0
  );
`);

function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPassword(plain, hash, salt) {
  const check = crypto.scryptSync(plain, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(hash, 'hex'));
}

const insertDriver = db.prepare(
  'INSERT INTO drivers (id, name, username, password_hash, password_salt, role, lat, lng) VALUES (?,?,?,?,?,?,?,?)'
);

const seedDrivers = [
  { id: 1, name: 'Carlos Fuentes', username: 'cfuentes', password: 'camion2024', role: 'driver', lat: -33.4489, lng: -70.6693 },
  { id: 2, name: 'Marcela Soto', username: 'msoto', password: 'flota#2024', role: 'driver', lat: -33.0472, lng: -71.6127 },
  { id: 3, name: 'Jorge Pino', username: 'jpino', password: 'ruta_norte', role: 'driver', lat: -36.8201, lng: -73.0444 },
  { id: 99, name: 'Admin TrackLog', username: 'admin', password: 'AdminSeguro#2024', role: 'admin', lat: 0, lng: 0 }
];

for (const d of seedDrivers) {
  const { hash, salt } = hashPassword(d.password);
  insertDriver.run(d.id, d.name, d.username, hash, salt, d.role, d.lat, d.lng);
}

const insertPackage = db.prepare(
  'INSERT INTO packages (id, barcode, description, assigned_driver_id, status, version) VALUES (?,?,?,?,?,0)'
);
insertPackage.run(1, 'PKG-0001-CL', 'Repuestos industriales', null, 'pendiente');
insertPackage.run(2, 'PKG-0002-CL', 'Equipos médicos', null, 'pendiente');
insertPackage.run(3, 'PKG-0003-CL', 'Electrónica de consumo', 1, 'en_ruta');

module.exports = { db, verifyPassword };
