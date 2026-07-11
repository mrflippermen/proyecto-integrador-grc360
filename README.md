# CyberRisk 360 — Sistema de Gestión de Riesgos Cibernéticos

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3-000000?logo=flask)
![Astro](https://img.shields.io/badge/Astro-4-BC52EE?logo=astro)
![ISO 27001](https://img.shields.io/badge/ISO-27001-00529B)
![License](https://img.shields.io/badge/license-MIT-green)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)

> **ITIZ3301 · Seguridad Informática — Proyecto Integrador**
> Aplicación web que automatiza la metodología propia **GRC-360** de gestión de
> riesgos cibernéticos, alineada con **ISO/IEC 27001, ISO/IEC 27002:2022 e
> ISO/IEC 27005**.

CyberRisk 360 permite a una organización recorrer, en un solo flujo, todo el
ciclo de gestión de riesgos: desde la valoración de sus activos de información
hasta el monitoreo continuo del riesgo residual, apoyándose en un catálogo de
controles ISO/IEC 27002:2022.

## 🔗 Enlaces en vivo (sin instalar nada)

- **Aplicación:** https://mrflippermen.github.io/proyecto-integrador-grc360/
- **Presentación ejecutiva (web):** https://mrflippermen.github.io/proyecto-integrador-grc360/presentacion/
- **Presentación en PowerPoint:** [`presentacion/CyberRisk360-Presentacion.pptx`](presentacion/CyberRisk360-Presentacion.pptx) (14 slides, editable)

Aplicación cliente de una sola página (autónoma, con carga de Excel/CSV,
inteligencia de amenazas y todos los módulos GRC-360). Se abre directamente en el
navegador — ideal para revisión. El código fuente completo (backend Flask + API +
frontend Astro) se documenta más abajo.

---

## 1. Módulos (metodología GRC-360)

| Fase | Módulo | Descripción |
|------|--------|-------------|
| 1 | **Valoración de activos** | Registro y clasificación de activos; valoración CIA (Confidencialidad, Integridad, Disponibilidad) en escala 1–5. |
| 2 | **Identificación de riesgos** | Amenazas, vulnerabilidades y controles existentes; análisis Probabilidad × Impacto. |
| 3 | **Tratamiento del riesgo** | Estrategias (Mitigar / Transferir / Aceptar / Evitar) y controles ISO/IEC 27002:2022, con responsables. |
| 4 | **Cálculo de riesgo residual** | Recalculo automático tras la implementación de controles. |
| 5 | **Comunicación y consulta** | Observaciones, recomendaciones y generación de informes ejecutivos. |
| 6 | **Monitoreo y supervisión** | Panel con KPIs, matriz de riesgo 5×5 y seguimiento de controles. |

---

## 2. Tecnologías

Arquitectura de **dos capas desacopladas** (frontend Astro + API Flask):

**Backend / API (`/` raíz del proyecto)**
- **Python 3 · Flask 3** — API REST JSON + interfaz Jinja2 (application factory + blueprints).
- **SQLAlchemy · SQLite** — ORM y base de datos embebida, portable, sin servidor.
- **Flask-Login / Werkzeug** — autenticación con roles y *hash* PBKDF2.
- **requests** — inteligencia de amenazas (NVD, EPSS, CISA KEV).
- Lógica: **CVSS v3.1** (FIRST.org), riesgo residual, **VPR**, **Cyber Exposure Score**, **SLA**.

**Frontend (`astro-frontend/`)**
- **Astro 4 (SSR)** — renderiza en servidor consumiendo la API.
- **SCSS** — sistema de diseño (tokens + mixins).
- **TypeScript** — cliente de API tipado, islas de gráficos y formularios.
- **Chart.js** — gráficos interactivos.

**Estándares:** ISO/IEC 27001 · 27002:2022 · 27005 · ISO 31000 · NIST CSF 2.0 · CVSS v3.1 · MITRE ATT&CK.

---

## 3. Instalación y ejecución

Requisitos: **Python 3.10+**.

```bash
# 1. Situarse en la carpeta del proyecto
cd proyecto-integrador-grc360

# 2. Crear y activar un entorno virtual
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Cargar datos de demostración (caso "FinTech Andina S.A.")
python seed.py

# 5. Iniciar el backend / API (deja esta terminal abierta)
python run.py
```

- **API + interfaz Flask:** http://127.0.0.1:5000

### Frontend Astro (opcional, capa visual con SCSS + TypeScript)

En **otra terminal**, con el backend Flask ya corriendo:

```bash
cd astro-frontend
npm install        # solo la primera vez
npm run dev        # servidor de desarrollo
```

- **Frontend Astro:** http://127.0.0.1:4321

> El frontend Astro consume la API Flask (`http://127.0.0.1:5000/api`). Si su API
> corre en otra dirección, cree `astro-frontend/.env` con
> `PUBLIC_API_URL=http://mi-host:5000/api`.
>
> También puede usar directamente la **interfaz Flask** en :5000 sin Astro.

### Cuentas de demostración

| Rol | Correo | Contraseña |
|-----|--------|-----------|
| Administrador | `admin@cyberrisk360.com` | `Admin123` |
| Analista | `analista@cyberrisk360.com` | `Analista123` |

> El script `seed.py` reinicia la base de datos y carga un caso de estudio
> completo (6 activos, 10 riesgos, 14 tratamientos y 31 controles ISO).

---

## 4. Estructura del proyecto

```
proyecto-integrador-grc360/
├── run.py                  # Punto de entrada
├── config.py               # Configuración (BD, sesiones)
├── seed.py                 # Datos de demostración + catálogo ISO 27002:2022
├── requirements.txt
├── app/
│   ├── __init__.py         # Application factory
│   ├── extensions.py       # Instancias de db y login_manager
│   ├── models.py           # Modelos + lógica de la metodología GRC-360
│   ├── blueprints/         # Un módulo por fase
│   │   ├── auth.py         # Autenticación
│   │   ├── dashboard.py    # Fase 6 — Monitoreo
│   │   ├── assets.py       # Fase 1 — Activos
│   │   ├── risks.py        # Fase 2 — Riesgos + catálogos
│   │   ├── treatments.py   # Fases 3 y 4 — Tratamiento y residual
│   │   ├── communication.py# Fase 5 — Comunicación
│   │   └── reports.py       # Informes ejecutivos
│   ├── templates/          # Vistas Jinja2 (interfaz Flask)
│   ├── cvss.py             # Cálculo CVSS v3.1
│   ├── threat_intel.py     # NVD · EPSS · CISA KEV
│   └── static/             # CSS + Chart.js
├── astro-frontend/         # Frontend Astro + SCSS + TypeScript
│   ├── src/lib/api.ts      # Cliente de API tipado
│   ├── src/styles/         # Sistema de diseño SCSS (tokens + global)
│   ├── src/layouts/        # Layout + Sidebar
│   ├── src/components/     # ChartCanvas (isla Chart.js)
│   └── src/pages/          # Páginas .astro (dashboard, riesgos, intel, ...)
└── docs/                   # Manual, respaldo técnico, análisis ético y capturas
```

---

## 5. Documentación

- `docs/METODOLOGIA_GRC360.md` — descripción formal de la metodología.
- `docs/MANUAL_USUARIO.md` — manual de usuario (máx. 5 páginas).
- `docs/RESPALDO_TECNICO.md` — arquitectura, herramientas, capturas, conclusiones y recomendaciones.
- `docs/ANALISIS_ETICO.md` — análisis del dilema ético y de responsabilidad profesional (RC4).
- `docs/capturas/` — capturas de pantalla del funcionamiento del sistema.

---

## 6. Seguridad implementada

- Contraseñas almacenadas con *hash* PBKDF2 (nunca en texto plano).
- Control de acceso: todas las rutas de gestión requieren sesión iniciada.
- Cookies de sesión `HttpOnly` y `SameSite=Lax`.
- Validación de datos de entrada en servidor (rangos 1–5, unicidad de códigos, longitudes mínimas).
