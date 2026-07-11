# Análisis del Dilema Ético y de Responsabilidad Profesional

**Proyecto:** CyberRisk 360 — Sistema de Gestión de Riesgos Cibernéticos
**Asignatura:** Seguridad Informática (ITIZ3301) · Proyecto Integrador
**Resultado de aprendizaje:** RC4 — Reconoce responsabilidades éticas y
profesionales y emite juicios informados, considerando el impacto de las
soluciones de ingeniería en contextos globales, económicos, ambientales y
sociales.

> Este documento cumple los tres criterios de la rúbrica ADN_FICA_RC4:
> (1) análisis de un dilema ético, (2) evaluación del impacto de las soluciones
> y (3) planteamiento de conclusiones con juicios profesionales y éticos.

---

## 1. Contexto: el rol del ingeniero en ciberseguridad y software

El ingeniero en ciberseguridad y software ocupa hoy una posición de **confianza
crítica** en la sociedad. Diseña y opera los sistemas que custodian datos
personales, transacciones financieras, historiales médicos e infraestructura.
Cuando ese profesional construye una herramienta que **automatiza decisiones de
riesgo** —como CyberRisk 360, que decide qué riesgos son "críticos", qué
controles priorizar y qué exposición es "tolerable"— asume una responsabilidad
que trasciende lo técnico: sus criterios se convierten en las reglas con las que
una organización protege (o desatiende) a las personas que dependen de ella.

Este proyecto no es neutral. Un sistema que calcula un "riesgo residual" y lo
pinta de verde está, implícitamente, **autorizando a la organización a dejar de
actuar**. Ahí nace el dilema.

---

## 2. Análisis del dilema ético

### 2.1 El dilema central: la falsa certeza de la automatización

**Dilema:** *¿Hasta qué punto es ético que un sistema automatizado de gestión de
riesgos traduzca decisiones profundamente humanas —cuánto riesgo aceptar sobre
los datos de un cliente— en un número con apariencia de objetividad?*

CyberRisk 360 convierte juicios cualitativos (probabilidad, impacto, eficacia de
un control) en puntajes precisos (un residual de "6", una reducción del "70 %").
Esa precisión es **retórica, no científica**: detrás de cada número hay una
estimación humana cargada de sesgos, incentivos y desconocimiento. El dilema
ético surge cuando la organización trata esos números como verdades y deja de
cuestionarlos:

- Un gerente puede **aceptar** un riesgo crítico sobre datos de clientes solo
  porque el sistema muestra "reducción del 82 %", sin entender que ese 82 % es
  una eficacia *estimada* y no *verificada*.
- El propio diseño del software puede inducir a la complacencia: un tablero lleno
  de indicadores en verde comunica "estamos seguros", cuando en realidad puede
  significar "hemos decidido no mirar más de cerca".

Este es un dilema clásico de **responsabilidad profesional** recogido en el
Código de Ética de la ACM/IEEE: *"evitar el daño"* y *"ser honesto sobre las
capacidades y limitaciones del software"*. Un ingeniero que entrega una
herramienta de riesgo sin comunicar sus límites falta a ese principio.

### 2.2 Dilemas derivados

**a) Protección de datos vs. utilidad del sistema.**
Para gestionar el riesgo, la herramienta concentra en una sola base de datos el
inventario completo de activos, vulnerabilidades y controles de la organización.
Ese repositorio es, paradójicamente, **uno de los activos más peligrosos que
existen**: un mapa exacto de dónde golpear. ¿Es responsable centralizar tanta
información sensible? El dilema se resuelve con controles (autenticación,
cifrado, mínimo privilegio, bitácora de auditoría), pero nunca desaparece: la
herramienta que reduce el riesgo también crea uno nuevo.

**b) Inteligencia de amenazas y doble uso.**
CyberRisk 360 integra CVSS, EPSS y el catálogo CISA KEV para priorizar
vulnerabilidades explotadas activamente. Esa misma inteligencia que ayuda a un
defensor a **parchear primero lo más peligroso** es la que un atacante usaría
para **atacar primero lo más rentable**. El profesional tiene la responsabilidad
de usar información de doble uso con una finalidad legítima y defensiva, y de no
exponerla a quien pueda darle un uso ofensivo.

**c) Rendición de cuentas cuando el sistema se equivoca.**
Si la herramienta clasifica como "bajo" un riesgo que luego causa una brecha,
¿de quién es la culpa? ¿Del algoritmo, del analista que ingresó los datos, del
gerente que aceptó el riesgo, o del ingeniero que diseñó la fórmula? La
automatización **difumina la responsabilidad**, y un diseño ético debe
contrarrestar esa difuminación: por eso CyberRisk 360 registra en una **bitácora
de auditoría** quién hizo cada cosa, y muestra que el residual "nunca es cero".

---

## 3. Evaluación del impacto de las soluciones

Las decisiones de diseño de CyberRisk 360 tienen impactos concretos en cuatro
contextos. Se evalúan tanto los efectos positivos buscados como los riesgos que
introducen.

### 3.1 Impacto social

- **Positivo:** al obligar a valorar los activos por *confidencialidad,
  integridad y disponibilidad* y a priorizar por amenaza real (KEV/EPSS), la
  herramienta ayuda a que las organizaciones protejan primero los datos que más
  afectan a las personas (datos financieros y personales de clientes). Democratiza
  una práctica —la gestión de riesgos ISO 27005— que antes solo estaba al alcance
  de grandes empresas con consultores costosos.
- **Riesgo:** la "seguridad de tablero". Si la dirección confunde *tener un panel
  en verde* con *estar protegida*, el impacto social es negativo: personas reales
  quedan expuestas mientras la organización cree lo contrario. **Mitigación
  incorporada:** el sistema muestra explícitamente el riesgo residual, los SLA
  vencidos y los riesgos que exceden el apetito, evitando una narrativa
  falsamente tranquilizadora.

### 3.2 Impacto económico

- **Positivo:** priorizar con VPR y SLA permite **asignar un presupuesto de
  seguridad siempre limitado** a los controles de mayor retorno (los que reducen
  la exposición sobre los activos más valiosos). Para una PYME, esto es la
  diferencia entre gastar bien o malgastar. El cálculo de riesgo residual y de
  reducción global (%) traduce la seguridad a un lenguaje que la gerencia
  financiera entiende.
- **Riesgo:** una mala estimación de eficacia puede llevar a **inversiones
  equivocadas** (comprar el control que el sistema "premia" en vez del que
  realmente protege) o a **falsa economía** (aceptar riesgos caros por ahorrar en
  controles). El costo de una brecha —multas por protección de datos, pérdida de
  clientes, remediación— supera con creces el de los controles omitidos.

### 3.3 Impacto ambiental

- **Positivo:** el sistema fue diseñado con **sobriedad computacional**: una base
  de datos SQLite ligera, sin dependencias pesadas ni servicios en la nube
  permanentemente encendidos, y un frontend estático. Menor consumo de cómputo
  significa menor huella de carbono. Además, al evitar incidentes, evita el
  enorme gasto energético asociado a la respuesta a brechas (análisis forense,
  restauración masiva, centros de datos de respaldo).
- **Riesgo:** la integración con inteligencia de amenazas realiza consultas a
  servicios externos (NVD, EPSS, CISA). Un diseño irresponsable que consultara
  masivamente y sin caché generaría tráfico y cómputo innecesarios. **Mitigación
  incorporada:** las consultas son bajo demanda, con caché del catálogo KEV y
  *timeouts*, minimizando el consumo de red.

### 3.4 Impacto global y de contexto

En un contexto **global**, las amenazas no tienen fronteras: una vulnerabilidad
como Log4Shell (CVE-2021-44228) afectó simultáneamente a organizaciones de todos
los países. Al apoyarse en marcos internacionales (**ISO/IEC 27001/27002/27005,
NIST CSF 2.0, CVSS de FIRST.org**), CyberRisk 360 habla el mismo idioma de
riesgo que el resto del mundo, permitiendo que una empresa latinoamericana se
compare y coopere con estándares internacionales. El impacto global positivo es
la **interoperabilidad de la defensa**; el riesgo es la **dependencia de fuentes
extranjeras** (¿qué pasa si NVD deja de estar disponible?), que se mitiga
cacheando datos y permitiendo el funcionamiento sin conexión.

---

## 4. Conclusiones — juicios profesionales y éticos

1. **La automatización de la gestión de riesgos es éticamente legítima solo si es
   honesta sobre sus límites.** El juicio profesional que sostiene este proyecto
   es que un buen sistema de riesgos no busca *eliminar* el criterio humano, sino
   *informarlo*. Por eso CyberRisk 360 nunca declara un riesgo en cero, distingue
   controles *propuestos* de *implementados* (solo estos reducen el residual) y
   expone abiertamente lo que aún está mal (SLA vencidos, apetito excedido). Un
   ingeniero responsable entrega herramientas que **invitan a mirar, no a dejar
   de mirar**.

2. **La responsabilidad profesional no se automatiza.** La conclusión ética
   central es que ninguna fórmula exime al analista, al gerente ni al ingeniero
   de responder por sus decisiones. La bitácora de auditoría y la segregación de
   roles del sistema materializan este principio: la trazabilidad es la forma
   técnica de la rendición de cuentas.

3. **Proteger datos es un acto de respeto por las personas, no un requisito de
   cumplimiento.** El impacto más profundo de una buena gestión de riesgos es
   social: detrás de cada "activo" (una base de datos de clientes) hay personas
   cuya privacidad y patrimonio dependen de decisiones que suelen ser invisibles
   para ellas. El profesional de ciberseguridad es, en la práctica, un
   **fiduciario de esa confianza**.

4. **El conocimiento de doble uso obliga a una postura ética explícita.** Integrar
   inteligencia de amenazas ofensiva (qué se explota, con qué probabilidad) con
   una finalidad exclusivamente defensiva es coherente con la ética profesional
   siempre que se resguarde esa información y se use para proteger. El mismo
   conocimiento que hace competente a un ingeniero lo hace peligroso si abandona
   sus principios; la diferencia no está en la técnica, sino en la ética que la
   gobierna.

5. **Juicio final.** CyberRisk 360 demuestra que es posible construir tecnología
   de seguridad que sea a la vez potente y responsable: potente porque prioriza
   con estándares internacionales e inteligencia real; responsable porque está
   diseñada para no engañar a quien la usa. La lección profesional que deja el
   proyecto es que **en ingeniería de seguridad, la decisión de diseño más
   importante casi nunca es técnica: es ética.**

---

### Referencias de marco ético y técnico

- ACM/IEEE-CS *Software Engineering Code of Ethics and Professional Practice*.
- ISO/IEC 27005:2022 — *Gestión de riesgos de seguridad de la información*.
- ISO 31000:2018 — *Gestión del riesgo* (apetito y tolerancia al riesgo).
- Reglamentos de protección de datos personales (referencia GDPR / LOPDP Ecuador).
- FIRST.org — *CVSS v3.1* y *EPSS*; CISA — *Known Exploited Vulnerabilities Catalog*.
