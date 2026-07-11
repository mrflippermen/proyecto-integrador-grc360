# Guía de Usuario — CyberRisk 360

**Sistema de Gestión de Riesgos Cibernéticos · Metodología GRC-360**

Esta guía explica cómo usar CyberRisk 360 como **cliente**: no necesita instalar
ni programar nada. Solo abrir el enlace y usarlo.

---

## 1. Cómo abrir la aplicación

Tiene **dos formas** de acceder, sin instalar nada:

**A) Por enlace (recomendado).** Abra en cualquier navegador moderno (Chrome,
Edge, Firefox, Safari):

> ### 👉 https://mrflippermen.github.io/proyecto-integrador-grc360/

La aplicación carga sola, con un caso de ejemplo ya preparado.

**B) Por archivo.** También puede abrir el archivo `cyberrisk360-demo.html`
haciendo **doble clic**. Funciona sin conexión a internet: todo corre dentro de
su navegador.

> **Sus datos son privados.** La información que ingrese o cargue se guarda solo
> en su propio navegador (no se envía a ningún servidor). Puede volver al ejemplo
> original con **“Restablecer demo”** en el menú.

---

## 2. La pantalla principal

Al abrir, verá el **Panel de monitoreo**. A la izquierda está el **menú**,
organizado según las seis fases de la metodología GRC-360:

1. Valoración de activos
2. Identificación de riesgos
3. Tratamiento (ISO 27002)
4. Riesgo residual
5. Comunicación y consulta
6. Monitoreo y supervisión

Más abajo encontrará **Inteligencia de amenazas**, **Cumplimiento**, e
**Importar Excel/CSV**.

En un teléfono, pulse el botón **☰ Menú** para abrir la navegación.

---

## 3. Cargar sus propios datos desde Excel

Esta es la forma más rápida de llenar el sistema con su información.

1. En el menú, entre a **“Importar Excel/CSV”**.
2. Elija si va a cargar **activos** o **riesgos**.
3. Pulse **“Descargar plantilla (.xlsx)”**. Se descarga un archivo de Excel con
   las columnas correctas y una fila de ejemplo.
4. Abra la plantilla en Excel, **borre la fila de ejemplo** y escriba sus datos.
5. Guarde el archivo y **arrástrelo a la zona de carga** (o haga clic para
   seleccionarlo).
6. Revise la **vista previa**: las filas correctas aparecen como “OK” y las que
   tienen errores se marcan en rojo con el motivo.
7. Pulse **“Importar N filas”**. ¡Listo! Sus datos ya están en el sistema.

**Columnas de la plantilla de activos:**
`codigo, nombre, tipo, propietario, confidencialidad, integridad, disponibilidad, descripcion`
(confidencialidad, integridad y disponibilidad van de 1 a 5).

**Columnas de la plantilla de riesgos:**
`codigo, activo_codigo, amenaza, vulnerabilidad, probabilidad, impacto, estado, descripcion`
(probabilidad e impacto van de 1 a 5; `activo_codigo` debe existir como activo).

> Si una amenaza o vulnerabilidad no existe todavía, el sistema la **crea
> automáticamente** al importar el riesgo.

---

## 4. Registrar datos manualmente

### Activos (Fase 1)
1. Entre a **“Valoración de activos”** → **“+ Nuevo activo”**.
2. Complete código, nombre, tipo y propietario.
3. Valore el activo en las tres dimensiones (escala 1–5):
   - **Confidencialidad:** impacto si la información se divulga.
   - **Integridad:** impacto si la información se altera.
   - **Disponibilidad:** impacto si el activo deja de estar disponible.
4. Guarde. El **valor del activo** se calcula solo (la dimensión más alta).

### Riesgos (Fase 2)
1. Entre a **“Identificación de riesgos”** → **“+ Nuevo riesgo”**.
2. Elija el **activo**, la **amenaza** y la **vulnerabilidad**.
3. Valore **probabilidad** e **impacto** (1–5). El sistema calcula el
   **riesgo inherente = Probabilidad × Impacto**.
4. Guarde. Use la **barra de búsqueda** y el **filtro por nivel** para encontrar
   riesgos en la lista. Haga clic en cualquier riesgo para ver su ficha completa.

### Tratamiento (Fase 3) y riesgo residual (Fase 4)
1. Abra un riesgo y pulse **“+ Añadir”** en “Plan de tratamiento”.
2. Elija la estrategia (**Mitigar, Transferir, Aceptar, Evitar**), un control
   **ISO/IEC 27002:2022**, el responsable y la **eficacia** (0–90 %).
3. Marque el **estado** del control. **Importante:** solo los controles
   *Implementado* o *Verificado* reducen el riesgo.
4. El **riesgo residual** se recalcula automáticamente y se muestra junto al
   inherente, con el porcentaje de reducción.

---

## 5. Inteligencia de amenazas

En **“Inteligencia de amenazas”** puede enriquecer una vulnerabilidad:

1. Escriba un identificador **CVE** (por ejemplo `CVE-2021-44228`).
2. Pulse el botón **↻**.
3. El sistema completa el **CVSS** (severidad técnica), el **EPSS**
   (probabilidad de explotación), si está en **CISA KEV** (explotación activa) y
   calcula el **VPR** (prioridad de remediación).

> En la versión de demostración por enlace, esto usa un catálogo local de CVE
> conocidos (Log4Shell, EternalBlue, BlueKeep, Zerologon, etc.). La versión
> completa consulta las bases NVD, EPSS y CISA en vivo.

---

## 6. Cumplimiento

En **“Cumplimiento”** verá qué tan alineado está su programa con
**ISO/IEC 27002:2022** (cobertura por tema) y con **NIST Cybersecurity Framework
2.0** (Gobernar, Identificar, Proteger, Detectar, Responder, Recuperar). Sirve
para detectar en qué áreas hay que reforzar controles.

---

## 7. Panel de monitoreo (Fase 6)

Es la pantalla de inicio. De un vistazo muestra:

- **Indicadores clave:** activos, riesgos, controles y reducción de riesgo.
- **Cyber Exposure Score (0–1000):** la exposición total de la organización.
- **Alertas:** riesgos que superan el **apetito de riesgo** y **SLA vencidos**.
- **Matriz de riesgo 5×5** y **distribución inherente vs. residual**.
- **Tendencia** del riesgo en el tiempo y **riesgos prioritarios**.

---

## 8. Preguntas frecuentes

**¿Necesito instalar algo?** No. Solo abrir el enlace o el archivo.

**¿Se pierden mis datos si cierro?** No. Se guardan en su navegador. Si usa otro
navegador o el modo incógnito, empezará de nuevo desde el ejemplo.

**¿Cómo vuelvo al ejemplo original?** Menú → **“Restablecer demo”**.

**¿Qué archivos de Excel acepta?** `.xlsx`, `.xls` y `.csv`.

**¿Puedo usarlo en el celular?** Sí. Use el botón **☰ Menú** para navegar.
