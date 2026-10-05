# Manifiesto Ético — Responsabilidad del Desarrollador ante la Pérdida de Datos de Usuarios

**Proyecto:** TrackLog API — Sistema de Seguimiento de Envíos y Flota
**Equipo:** Grupo 5 — Logística
**Integrantes:** Almendares, Apablaza, Flores
**Fecha:** 05-10-2026

---

## 1. Propósito

Este manifiesto establece el compromiso ético del equipo de desarrollo e ingeniería de seguridad (DevSecOps) responsable de auditar, refactorizar y blindar la plataforma **TrackLog API**. Su objetivo es dejar constancia explícita de que la seguridad de los datos de conductores, clientes y operaciones logísticas no es un requisito opcional ni postergable, sino una obligación profesional, legal y moral del equipo de desarrollo.

## 2. Contexto del problema

El sistema TrackLog API, en su versión inicial, fue desarrollado priorizando la velocidad de entrega por sobre la seguridad. Esto se tradujo en vulnerabilidades críticas que, de ser explotadas en un entorno real, podrían:

- Exponer la **ubicación en tiempo real de conductores** (A01), poniendo en riesgo su seguridad física y su privacidad.
- Filtrar **credenciales de transportistas** transmitidas sin cifrado (A02), facilitando el robo de identidad y accesos no autorizados.
- Permitir la **manipulación de bases de datos** mediante inyección SQL (A03), comprometiendo la integridad de rutas, paquetes y usuarios.
- Habilitar accesos administrativos no controlados (A05) y autenticaciones falsificables (A07).
- Exponer a la organización a ataques de denegación de servicio, fuga de información interna (XXE, A08) y redirecciones maliciosas (SSRF, A10).
- Impedir la trazabilidad de incidentes por la ausencia de registro de eventos (A09).

Cada una de estas fallas representa no solo un riesgo técnico, sino una amenaza directa a personas reales: conductores cuya ubicación puede ser rastreada por terceros malintencionados, clientes cuyos envíos pueden ser interceptados o manipulados, y transportistas cuyas credenciales pueden ser robadas y usadas en su contra.

## 3. Principios éticos que asume el equipo

1. **Responsabilidad ante todo.** El desarrollador que escribe o despliega código con vulnerabilidades conocidas, o que omite controles básicos de seguridad por presión de tiempo o costos, es responsable de las consecuencias de esa decisión. La seguridad no es responsabilidad exclusiva de "un tercero" (el área de seguridad, el cliente, el usuario final): es parte inherente del rol de quien construye el software.

2. **Privacidad y minimización de datos.** Los datos de geolocalización de conductores y la información personal de clientes se tratan bajo el principio de necesidad: solo se expone lo estrictamente necesario, a quien tiene autorización para verlo, y nunca sin cifrado en tránsito.

3. **Transparencia ante el fallo.** Si el equipo detecta una vulnerabilidad —propia o heredada del desarrollo original— se documenta y reporta, no se oculta ni se minimiza. El manejo inseguro de excepciones (stack traces expuestos) es, en sí mismo, una falta ética porque revela información interna a un atacante.

4. **Responsabilidad civil y penal del ingeniero de software.** El equipo reconoce que, dependiendo de la legislación aplicable (p. ej. normativa de protección de datos personales), negligencia grave en el tratamiento de datos de usuarios puede derivar en responsabilidad civil (indemnización por daños) y, en casos graves, responsabilidad penal para quienes tomaron la decisión de omitir controles de seguridad conocidos. "No lo sabía" no es una defensa válida cuando la vulnerabilidad corresponde a una categoría documentada y pública como el OWASP Top 10.

5. **Seguridad por diseño, no como parche.** El equipo se compromete a que la refactorización no sea un maquillaje superficial (ej. ocultar errores en el frontend) sino una corrección estructural en el backend, aplicando *Zero Trust Input*: ninguna entrada del usuario se considera confiable por defecto.

6. **Rendición de cuentas documentada.** Todo el proceso de auditoría, hallazgos y corrección queda versionado en el repositorio (Docs-as-Code), de manera que exista trazabilidad verificable de qué se encontró, cuándo, y cómo se corrigió.

## 4. Compromiso del equipo

Nosotros, como equipo responsable del proyecto TrackLog API, declaramos que:

- Actuaremos con la diligencia debida de un profesional de la ingeniería de software y la seguridad informática.
- No consideraremos "entregado" ni "listo para producción" ningún sistema que no haya pasado por un proceso de auditoría y mitigación de riesgos documentado.
- Priorizaremos la protección de las personas (conductores, clientes, operadores) por sobre la velocidad de entrega cuando ambas entren en conflicto.
- Asumimos que la confianza de los usuarios en la plataforma se construye con hechos verificables (pruebas, evidencia, controles implementados), no con promesas.

---

*Documento elaborado en el marco de la Evaluación 02 — Ética, Gobernanza (ISO/IEC 27034) y Seguridad Aplicada (OWASP Top 10).*
