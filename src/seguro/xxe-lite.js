// xxe-lite.js — mini parser XML educativo que reemplaza a libxmljs2 en esta
// demo académica, SIN dependencias nativas (cero compilación, funciona en
// cualquier Windows/Mac/Linux solo con Node.js).
//
// [A08 - MITIGADO] server.js llama a este módulo con noent:false y
// dtdload:false, y además rechaza cualquier XML con <!DOCTYPE>/<!ENTITY>
// ANTES de llegar aquí. Este módulo nunca lee archivos en la versión segura.
//
// Implementa únicamente lo que la API necesita: detectar un DOCTYPE con
// entidades externas (<!ENTITY name SYSTEM "...">) y, según las opciones
// recibidas, resolverlas (noent/dtdload = true) o no. La forma de uso
// replica la API mínima de libxmljs2 que usa server.js:
//
//   const doc = parseXml(xml, { noent: true, dtdload: true });
//   doc.root().toString();
//
// [A08] En modo vulnerable (noent:true, dtdload:true) este módulo SÍ lee
// archivos del sistema cuando el XML declara una entidad SYSTEM, replicando
// fielmente el comportamiento inseguro de un parser XML con resolución de
// entidades externas habilitada (XXE clásico).

'use strict';

const fs = require('fs');
const { fileURLToPath } = require('url');

const DOCTYPE_RE = /<!DOCTYPE\s+[^\[>]+(\[([\s\S]*?)\])?\s*>/i;
const ENTITY_RE = /<!ENTITY\s+(\S+)\s+SYSTEM\s+"([^"]+)"\s*>/gi;
const XML_DECL_RE = /^\s*<\?xml[^>]*\?>\s*/i;

function resolveSystemUri(uri) {
  // file:///C:/Windows/win.ini (Windows) o file:///etc/hostname (POSIX).
  if (/^file:\/\//i.test(uri)) {
    return fileURLToPath(uri);
  }
  // Sin esquema explícito: se trata como ruta de archivo tal cual.
  return uri;
}

function parseXml(xmlString, opts = {}) {
  const { noent = false, dtdload = false } = opts;

  if (typeof xmlString !== 'string' || xmlString.indexOf('<') === -1) {
    throw new Error('Document is empty or not well-formed XML');
  }

  let body = xmlString;
  const doctypeMatch = DOCTYPE_RE.exec(xmlString);
  const entities = {};

  if (doctypeMatch) {
    const internalSubset = doctypeMatch[2] || '';
    if (dtdload) {
      let m;
      ENTITY_RE.lastIndex = 0;
      while ((m = ENTITY_RE.exec(internalSubset)) !== null) {
        const [, name, systemId] = m;
        try {
          const filePath = resolveSystemUri(systemId);
          // noent:true EXPANDE entidades externas -> lee el archivo del
          // servidor indicado en el DOCTYPE (XXE).
          entities[name] = fs.readFileSync(filePath, 'utf8');
        } catch (err) {
          throw new Error(`failed to load external entity "${systemId}": ${err.message}`);
        }
      }
    }
    // El DOCTYPE nunca forma parte del elemento raíz devuelto (igual que
    // doc.root().toString() en libxmljs2, que solo serializa el root).
    body = xmlString.slice(0, doctypeMatch.index) + xmlString.slice(doctypeMatch.index + doctypeMatch[0].length);
  }

  body = body.replace(XML_DECL_RE, '').trim();

  if (noent) {
    for (const [name, value] of Object.entries(entities)) {
      body = body.split(`&${name};`).join(value);
    }
  }

  if (body.indexOf('<') === -1) {
    throw new Error('Document is empty or not well-formed XML');
  }

  return {
    root() {
      return { toString: () => body };
    }
  };
}

module.exports = { parseXml };
