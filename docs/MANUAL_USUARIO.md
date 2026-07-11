# Manual de Usuario — CyberRisk 360

**Sistema de Gestión de Riesgos Cibernéticos · Metodología GRC-360**
Guía rápida (máx. 5 páginas).

---

## 1. Acceso al sistema

1. Abra el navegador en la dirección del frontend: **http://localhost:4321**
   (o la interfaz Flask en **http://localhost:5000**).
2. En la interfaz Flask, inicie sesión con una cuenta de demostración:

   | Rol | Correo | Contraseña |
   |-----|--------|-----------|
   | Administrador | `admin@cyberrisk360.com` | `Admin123` |
   | Analista | `analista@cyberrisk360.com` | `Analista123` |

La barra lateral izquierda organiza el sistema según las **seis fases de la
metodología GRC-360**, numeradas del 1 al 6.

---

## 2. Fase 1 — Valoración de activos

**Menú: “Valoración de activos”.**

1. Pulse **“Nuevo activo”**.
2. Complete el **código** (ej. `ACT-007`), **nombre**, **tipo** y **propietario**.
3. Valore el activo en las tres dimensiones de seguridad (escala 1–5):
   - **Confidencialidad:** impacto si la información se divulga.
   - **Integridad:** impacto si la información se altera.
   - **Disponibilidad:** impacto si el activo deja de estar disponible.
4. Guarde. El **valor del activo** se calcula automáticamente como la dimensión
   más alta.

---

## 3. Fase 2 — Identificación de riesgos

**Menú: “Identificación de riesgos”.**

1. Pulse **“Nuevo riesgo”**.
2. Asigne un **código** (ej. `R-013`) y seleccione:
   - el **activo** afectado,
   - la **amenaza** (del catálogo, con su técnica MITRE ATT&CK),
   - la **vulnerabilidad** que la amenaza explota.
3. Valore la **probabilidad** y el **impacto** (1–5). El sistema calcula el
   **riesgo inherente = Probabilidad × Impacto** y lo clasifica en Bajo, Medio,
   Alto o Crítico.
4. Use la **barra de búsqueda y el filtro por nivel** para localizar riesgos en
   la lista.

> **Catálogos:** en el menú “Catálogos” puede agregar nuevas amenazas y
> vulnerabilidades reutilizables.

---

## 4. Fase 3 — Tratamiento del riesgo

**Desde la ficha de un riesgo, pulse “Añadir tratamiento”.**

1. Elija la **estrategia de respuesta**: *Mitigar*, *Transferir*, *Aceptar* o
   *Evitar*.
2. (Opcional) Seleccione un **control ISO/IEC 27002:2022** de referencia.
3. Indique el **control propuesto**, el **responsable** y la **fecha objetivo**.
4. Estime la **eficacia** del control (0–90 %).
5. Actualice el **estado** del control conforme avanza:
   *Propuesto → En Implementación → Implementado → Verificado.*

> **Importante:** solo los controles **Implementado** o **Verificado** reducen el
> riesgo residual.

---

## 5. Fase 4 — Riesgo residual

El **riesgo residual** se calcula y muestra automáticamente en la ficha de cada
riesgo, junto al riesgo inherente y al **porcentaje de reducción** logrado. No
requiere acción manual: cada vez que registra o actualiza un tratamiento, el
sistema lo recalcula.

---

## 6. Fase 5 — Comunicación y consulta

**Menú: “Comunicación y consulta”.**

1. Seleccione el **tipo** (*Observación* o *Recomendación*).
2. Asócielo a un riesgo (opcional) y escriba el **contenido**.
3. Registre. Las comunicaciones aparecen en el panel y en el informe ejecutivo.

**Reportes:** en el menú “Reportes” → **“Informe ejecutivo”** genera un documento
consolidado para la dirección. Púlselo y use **Ctrl/Cmd + P** para exportarlo a
PDF.

---

## 7. Fase 6 — Monitoreo y supervisión

**Menú: “Panel de monitoreo”** (pantalla de inicio). Muestra:

- **KPIs:** activos, riesgos, controles y reducción de riesgo global.
- **Cyber Exposure Score (0–1000):** exposición agregada de la organización.
- **Alertas de gobierno:** riesgos que exceden el **apetito de riesgo** y **SLA de
  remediación vencidos**.
- **Matriz de riesgo 5×5** y **distribución inherente vs. residual**.
- **Tendencia de exposición** (últimas 13 semanas).

---

## 8. Módulos avanzados

### 8.1 Inteligencia de amenazas

**Menú: “Inteligencia de amenazas”.** Para enriquecer una vulnerabilidad:

1. Escriba un identificador **CVE** (ej. `CVE-2021-44228`) en la fila
   correspondiente.
2. Pulse el botón **↻**. El sistema consulta **NVD, EPSS y CISA KEV** en vivo y
   completa el CVSS, la probabilidad de explotación, el estado KEV y el **VPR**
   (prioridad de remediación).

### 8.2 Cumplimiento

**Menú: “Cumplimiento”.** Muestra la cobertura de controles frente a
**ISO/IEC 27002:2022** (por tema) y a **NIST CSF 2.0** (por función: Gobernar,
Identificar, Proteger, Detectar, Responder, Recuperar).

### 8.3 Auditoría y configuración

- **Auditoría:** bitácora cronológica de todas las acciones (trazabilidad). Desde
  aquí puede **exportar el registro de riesgos a CSV**.
- **Configuración:** definir el nombre de la organización y el **apetito de
  riesgo** (umbral de riesgo residual tolerado).

---

## 9. Consejos de uso

- Los campos obligatorios están marcados con un asterisco rojo (*).
- El sistema valida los datos de entrada (rangos 1–5, códigos únicos, longitudes
  mínimas) y muestra mensajes claros en caso de error.
- Haga clic en cualquier fila de riesgo para abrir su ficha detallada.
