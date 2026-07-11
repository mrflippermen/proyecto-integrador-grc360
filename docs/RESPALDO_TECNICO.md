# Documento de Respaldo Técnico

**Proyecto:** CyberRisk 360 — Sistema de Gestión de Riesgos Cibernéticos
**Asignatura:** Seguridad Informática (ITIZ3301) · Proyecto Integrador

---

## 1. Resumen del sistema

CyberRisk 360 es una aplicación web que **automatiza la metodología GRC-360** de
gestión de riesgos cibernéticos, alineada con ISO/IEC 27001, 27002:2022 y 27005.
Permite recorrer las seis fases del ciclo de riesgo —valoración de activos,
identificación de riesgos, tratamiento, cálculo de riesgo residual, comunicación
y monitoreo— e incorpora **inteligencia de amenazas real** (CVSS, EPSS, CISA KEV)
y un panel de **cumplimiento** frente a ISO 27001 y NIST CSF 2.0.

---

## 2. Diagrama de arquitectura del sistema

El sistema usa una arquitectura de **dos capas desacopladas** (frontend / API):

```
┌──────────────────────────────────────────────────────────────────────┐
│                            NAVEGADOR (usuario)                          │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │ HTML + islas interactivas (Chart.js)
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│          FRONTEND  ·  Astro (SSR) + SCSS + TypeScript  ·  :4321         │
│  Páginas .astro (dashboard, riesgos, intel, cumplimiento, auditoría)   │
│  src/lib/api.ts  →  cliente HTTP tipado                                 │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │  HTTP / JSON  (fetch)
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│              BACKEND  ·  Flask (API REST JSON)  ·  :5000                │
│  Blueprints: api, dashboard, assets, risks, treatments, intel,         │
│              compliance, admin, auth                                    │
│  Lógica GRC-360: CVSS 3.1 · riesgo residual · VPR · CES · SLA          │
└───────────────┬──────────────────────────────┬───────────────────────┘
                │ SQLAlchemy (ORM)              │ requests (HTTPS)
                ▼                               ▼
        ┌───────────────┐            ┌──────────────────────────────┐
        │  SQLite (BD)  │            │  Inteligencia de amenazas:    │
        │  activos,     │            │   · NVD  (CVSS)               │
        │  riesgos,     │            │   · EPSS (FIRST.org)          │
        │  controles... │            │   · CISA KEV                  │
        └───────────────┘            └──────────────────────────────┘
```

> La misma lógica de Flask sirve además una **interfaz Jinja2** propia
> (renderizada en servidor) como alternativa, de modo que el sistema es usable
> tanto desde el frontend Astro como directamente desde Flask.

---

## 3. Explicación del desarrollo y herramientas utilizadas

### 3.1 Backend (API y lógica de negocio)

| Herramienta | Uso |
|-------------|-----|
| **Python 3 / Flask 3** | Framework web; patrón *application factory* + *blueprints* (un módulo por fase). |
| **SQLAlchemy + SQLite** | ORM y base de datos embebida, portable y sin servidor. |
| **Flask-Login / Werkzeug** | Autenticación con roles y *hash* de contraseñas (PBKDF2). |
| **requests** | Consultas HTTPS a las APIs de inteligencia de amenazas. |

Módulos de lógica destacados:
- `app/cvss.py` — implementación de la fórmula oficial **CVSS v3.1** (validada
  contra los vectores de referencia de FIRST.org).
- `app/threat_intel.py` — servicio que consulta **NVD, EPSS y CISA KEV** con
  *timeouts*, caché y degradación elegante.
- `app/models.py` — modelos y toda la matemática de la metodología: riesgo
  inherente (P×I), **riesgo residual** (combinación multiplicativa de controles
  implementados), **VPR**, **Cyber Exposure Score** y **SLA** de remediación.

### 3.2 Frontend (capa visual)

| Herramienta | Uso |
|-------------|-----|
| **Astro 4 (SSR, adaptador Node)** | Renderiza cada página en el servidor obteniendo los datos de la API. |
| **SCSS** | Sistema de diseño (tokens, mixins, bucles) — "Consola de Operaciones de Riesgo". |
| **TypeScript** | Cliente de API tipado (`api.ts`), islas de gráficos y lógica de formularios. |
| **Chart.js** | Gráficos interactivos (tendencia de exposición, distribución de riesgo). |

### 3.3 Decisiones de diseño relevantes

- **Riesgo residual solo por controles implementados:** un control propuesto no
  reduce el riesgo hasta estar implementado o verificado (realismo metodológico).
- **VPR transparente:** `CVSS + hasta +2 por EPSS`, con piso de 9.0 si la
  vulnerabilidad está en CISA KEV — enfoque documentado e inspirado en Tenable.
- **Reducción máxima del 90 %:** el riesgo residual nunca llega a cero.
- **Gráficos con un solo eje:** las series de escalas distintas (CES vs. número de
  críticos) se indexan a una base común (0–100), siguiendo buenas prácticas de
  visualización de datos.

---

## 4. Capturas de pantalla del funcionamiento

Las capturas se encuentran en `docs/capturas/`:

| # | Archivo | Módulo |
|---|---------|--------|
| 1 | `01-panel-monitoreo.png` | Panel de monitoreo (Fase 6): KPIs, Cyber Exposure Score, matriz 5×5, tendencia y distribución. |
| 2 | `02-inteligencia-amenazas.png` | Inteligencia de amenazas: CVSS, EPSS, CISA KEV y VPR con enriquecimiento vía API en vivo. |
| 3 | `03-cumplimiento.png` | Cumplimiento: cobertura ISO 27002:2022 y NIST CSF 2.0. |
| 4 | `04-detalle-riesgo.png` | Detalle de riesgo: inherente → tratamiento → residual, SLA e inteligencia. |
| 5 | `05-registro-riesgos.png` | Registro de riesgos con búsqueda y filtros. |
| 6 | `06-login.png` | Autenticación (interfaz Flask). |

---

## 5. Conclusiones

1. **Se automatizó íntegramente la metodología propuesta.** Las seis fases de
   GRC-360 quedaron operativas: desde la valoración CIA de activos hasta el
   monitoreo continuo, con recálculo automático del riesgo residual al aplicar
   controles ISO/IEC 27002:2022.

2. **El sistema alcanza estándares internacionales.** Integra CVSS v3.1 (FIRST.org),
   EPSS, el catálogo CISA KEV, ISO/IEC 27001/27002/27005 y NIST CSF 2.0,
   ofreciendo métricas comparables con herramientas comerciales de gestión de
   exposición (Cyber Exposure Score, VPR, SLA de remediación).

3. **La arquitectura desacoplada (Astro + API Flask) es profesional y escalable.**
   Separar la presentación (Astro/SCSS/TypeScript) de la lógica (Flask/SQLAlchemy)
   permite evolucionar cada capa de forma independiente y reutilizar la API desde
   otros clientes (móvil, integraciones).

4. **La inteligencia de amenazas convierte al sistema en una herramienta viva.**
   Enriquecer una vulnerabilidad con datos reales de explotación (EPSS/KEV)
   transforma la priorización estática en una priorización basada en la amenaza
   real del momento.

---

## 6. Recomendaciones

1. **Seguridad de la API:** en producción, proteger los endpoints `/api/*` con
   autenticación (sesión o JWT) y restringir CORS al origen del frontend.
2. **Persistencia robusta:** migrar de SQLite a PostgreSQL para entornos
   multiusuario con alta concurrencia.
3. **Automatizar las instantáneas:** ejecutar la captura de `RiskSnapshot` de
   forma programada (tarea cron) para alimentar la tendencia histórica con datos
   reales en lugar de simulados.
4. **Enriquecimiento por lotes y caché persistente:** programar la actualización
   periódica de CVSS/EPSS/KEV y almacenar el catálogo KEV completo para operar sin
   conexión.
5. **Flujo de aprobación del riesgo aceptado:** añadir un paso de aprobación
   formal (con firma del responsable) cuando un riesgo que excede el apetito se
   marque como "Aceptado".
6. **Pruebas automatizadas y CI:** incorporar pruebas unitarias de la lógica de
   riesgo y una canalización de integración continua.
