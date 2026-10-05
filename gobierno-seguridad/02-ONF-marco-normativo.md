
# ONF — Marco Normativo Organizacional (Organizational Normative Framework)
## Basado en ISO/IEC 27034 — Aplicado a TrackLog API

**Proyecto:** TrackLog API — Sistema de Seguimiento de Envíos y Flota
**Equipo:** Grupo 5 — Logística

---

## 1. ¿Qué es el ONF?

La norma ISO/IEC 27034 (Seguridad de Aplicaciones) define el **Marco Normativo Organizacional (ONF)** como el repositorio central de todos los procesos, buenas prácticas, roles y estándares de seguridad que una organización aplica al ciclo de vida de sus aplicaciones. El ONF es el "libro de reglas" al que toda aplicación de la organización debe ajustarse.

En este proyecto, el equipo Grupo 5 asume el rol de "organización" consultora de seguridad, y define el ONF aplicable al desarrollo y mantenimiento de TrackLog API.

## 2. Componentes del ONF

### 2.1 Procesos de negocio aplicables

| Proceso | Descripción | Riesgo asociado en TrackLog API |
|---|---|---|
| Gestión de identidad y acceso | Autenticación y autorización de conductores, operadores y administradores | A01, A05, A07 |
| Transmisión de datos sensibles | Envío de credenciales, ubicación GPS y manifiestos de carga | A02, A08 |
| Persistencia de datos | Almacenamiento y consulta de paquetes, rutas y usuarios | A03, A04 |
| Gestión de componentes de terceros | Librerías de geolocalización y servicios de mapas externos | A06, A10 |
| Auditoría y trazabilidad | Registro de eventos del sistema | A09 |

### 2.2 Roles y responsabilidades (según ISO/IEC 27034)

| Rol | Responsabilidad en el proyecto |
|---|---|
| **Comité de Seguridad de Aplicaciones (ASC owner)** | El equipo completo, en conjunto, define y aprueba el perfil de controles (ASC) aplicable a TrackLog API |
| **Arquitecto de seguridad** | Responsable de definir cómo se aplican Zero Trust Input, cifrado y control de acceso en el rediseño |
| **Desarrollador / auditor** | Responsable de implementar los controles y de ejecutar las pruebas de penetración con `curl` |
| **Responsable de cumplimiento normativo** | Verifica que el ONF y el ASC se mantengan alineados con OWASP Top 10 e ISO/IEC 27034 |

> Nota: en un equipo de 3 integrantes, estos roles pueden repartirse o rotarse, pero deben quedar explícitamente asignados en el README del repositorio.

### 2.3 Niveles de confianza de la aplicación

Según ISO/IEC 27034, cada aplicación se clasifica según su exposición y criticidad. Para TrackLog API:

- **Clasificación:** Aplicación de **alto riesgo / alta criticidad**.
- **Justificación:**
  - Maneja datos de geolocalización en tiempo real (datos personales sensibles).
  - Gestiona credenciales de transportistas.
  - Tiene exposición a internet (API pública consumida por apps móviles de conductores y clientes).
  - Interactúa con servicios de terceros (mapas) y procesa archivos externos (XML de manifiestos).

Esta clasificación determina que el **perfil de controles (ASC)** exigido debe ser el más estricto posible dentro del catálogo del ONF (ver documento `03-ASC-perfil-controles.md`).

### 2.4 Catálogo de controles de seguridad (referencia al Top 10 OWASP)

El ONF de TrackLog API adopta como catálogo base el **OWASP Top 10**, mapeado a los dominios de ISO/IEC 27034:

| Dominio ISO/IEC 27034 | Control OWASP asociado |
|---|---|
| Control de acceso | A01 (Broken Access Control), A07 (Identification and Authentication Failures) |
| Criptografía y protección de datos en tránsito/reposo | A02 (Cryptographic Failures) |
| Validación de entradas | A03 (Injection) |
| Lógica de negocio e integridad | A04 (Insecure Design) |
| Configuración segura | A05 (Security Misconfiguration) |
| Gestión de componentes y dependencias | A06 (Vulnerable and Outdated Components) |
| Procesamiento seguro de datos externos | A08 (Software and Data Integrity Failures / XXE) |
| Monitoreo y registro | A09 (Security Logging and Monitoring Failures) |
| Seguridad en integraciones externas | A10 (Server-Side Request Forgery) |

### 2.5 Ciclo de vida de seguridad aplicado (ASLC — Application Security Life Cycle)

1. **Especificación de requerimientos de seguridad** → este documento (ONF) y el ASC.
2. **Diseño seguro** → Fase de refactorización (Zero Trust Input, listas blancas, regex).
3. **Implementación** → `src/seguro/`.
4. **Verificación** → `auditoria/fase1/` (código vulnerable) y `auditoria/fase2/` (código refactorizado).
5. **Liberación y mantenimiento** → README ejecutivo + historial de commits en GitHub.

## 3. Alcance y vigencia

Este ONF aplica exclusivamente al proyecto TrackLog API desarrollado en el contexto de la Evaluación 02. Debe ser revisado y actualizado cada vez que:

- Se incorpore un nuevo componente de terceros.
- Se detecte una nueva vulnerabilidad no contemplada en el OWASP Top 10 vigente.
- Cambie el nivel de exposición de la aplicación (ej. de uso interno a uso público).

---

*Documento elaborado en el marco de la Evaluación 02 — Gobernanza ISO/IEC 27034.*
