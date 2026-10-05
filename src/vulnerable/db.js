// db.js - Base de datos de demostración para TrackLog API (version vulnerable)
// Usa node:sqlite (módulo nativo incluido en Node.js >= 22.5, sin
// dependencias externas ni compilación) en memoria con datos de ejemplo.
// API equivalente a better-sqlite3 para los fines de esta demo.

const { DatabaseSync } = require('node:sqlite');

const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE drivers (
    id INTEGER PRIMARY KEY,
    name TEXT,
    username TEXT,
    password TEXT,
    lat REAL,
    lng REAL
  );

  CREATE TABLE packages (
    id INTEGER PRIMARY KEY,
    barcode TEXT,
    description TEXT,
    assigned_driver_id INTEGER,
    status TEXT DEFAULT 'pendiente'
  );
`);

// Datos de ejemplo (A02: contraseñas en texto plano a propósito, simulando mal manejo de credenciales)
const insertDriver = db.prepare('INSERT INTO drivers (id, name, username, password, lat, lng) VALUES (?,?,?,?,?,?)');
insertDriver.run(1, 'Carlos Fuentes', 'cfuentes', 'camion2024', -33.4489, -70.6693);
insertDriver.run(2, 'Marcela Soto', 'msoto', 'flota#2024', -33.0472, -71.6127);
insertDriver.run(3, 'Jorge Pino', 'jpino', 'ruta_norte', -36.8201, -73.0444);

const insertPackage = db.prepare('INSERT INTO packages (id, barcode, description, assigned_driver_id, status) VALUES (?,?,?,?,?)');
insertPackage.run(1, 'PKG-0001-CL', 'Repuestos industriales', null, 'pendiente');
insertPackage.run(2, 'PKG-0002-CL', 'Equipos médicos', null, 'pendiente');
insertPackage.run(3, 'PKG-0003-CL', 'Electrónica de consumo', 1, 'en_ruta');

module.exports = db;
