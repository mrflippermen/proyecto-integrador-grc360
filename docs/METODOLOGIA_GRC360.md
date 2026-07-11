# Metodología GRC-360 de Gestión de Riesgos Cibernéticos

**Proyecto:** CyberRisk 360 · ITIZ3301 — Seguridad Informática
**Marcos de referencia:** ISO/IEC 27001 · ISO/IEC 27002:2022 · ISO/IEC 27005 · NIST SP 800-30

---

## 1. Propósito

GRC-360 (*Governance, Risk & Compliance 360°*) es una metodología cíclica,
propuesta por el grupo, para identificar, analizar, tratar y monitorear los
riesgos de seguridad de la información en un entorno organizacional. Toma como
base el proceso de gestión de riesgos de la ISO/IEC 27005 y lo operacionaliza en
seis fases automatizables, empleando el catálogo de controles de la
ISO/IEC 27002:2022 como referencia de tratamiento.

El objetivo es que una PYME o un área de TI pueda pasar de una gestión de riesgos
"en hojas de cálculo" a un proceso **repetible, trazable y medible**.

---

## 2. Escalas cualitativas

Todas las variables se valoran en una escala entera **1–5** para mantener
consistencia en el cálculo:

| Valor | Etiqueta | Interpretación |
|:---:|----------|----------------|
| 1 | Muy Bajo | Impacto/probabilidad insignificante |
| 2 | Bajo | Menor |
| 3 | Medio | Moderado |
| 4 | Alto | Grave |
| 5 | Muy Alto | Crítico / catastrófico |

---

## 3. Fase 1 — Valoración de activos

Cada activo de información se registra y se clasifica por tipo (Información,
Software, Hardware, Servicio, Personal, Instalación) y se valora en las tres
dimensiones de seguridad:

- **Confidencialidad (C):** impacto si la información es divulgada.
- **Integridad (I):** impacto si la información es alterada.
- **Disponibilidad (D):** impacto si el activo deja de estar disponible.

**Valor del activo** = `max(C, I, D)` — criterio conservador: un activo es tan
crítico como su dimensión más sensible.

---

## 4. Fase 2 — Identificación y análisis de riesgos

Un **riesgo** se modela como la tripleta:

```
Riesgo = Activo  +  Amenaza  +  Vulnerabilidad
```

es decir, una amenaza que explota una vulnerabilidad sobre un activo. Se
documentan además los **controles existentes**. El riesgo se valora con:

```
Riesgo inherente = Probabilidad (1–5)  ×  Impacto (1–5)   →   rango 1–25
```

El **riesgo inherente** representa la exposición *antes* de aplicar nuevos
controles. La clasificación por niveles se realiza sobre una matriz 5×5:

| Puntaje | Nivel | Color |
|:---:|:---:|:---:|
| 1 – 4 | **Bajo** | 🟢 Verde |
| 5 – 9 | **Medio** | 🟡 Amarillo |
| 10 – 14 | **Alto** | 🟠 Naranja |
| 15 – 25 | **Crítico** | 🔴 Rojo |

---

## 5. Fase 3 — Tratamiento del riesgo

Para cada riesgo se selecciona una **estrategia de respuesta**:

| Estrategia | Descripción |
|-----------|-------------|
| **Mitigar** | Aplicar controles que reducen probabilidad y/o impacto. |
| **Transferir** | Trasladar el riesgo a un tercero (seguro, proveedor de nube). |
| **Aceptar** | Asumir el riesgo cuando su nivel es tolerable o el costo del control supera el beneficio. |
| **Evitar** | Eliminar la fuente del riesgo (retirar el activo o proceso). |

Cada tratamiento se asocia opcionalmente a un **control ISO/IEC 27002:2022**
(93 controles agrupados en 4 temas: Organizacional, Personas, Físico y
Tecnológico), un **responsable**, una **fecha objetivo** y una **eficacia
estimada (0–90 %)**.

---

## 6. Fase 4 — Cálculo del riesgo residual

El **riesgo residual** es la exposición que permanece *después* de implementar
los controles. Sólo los controles con estado **Implementado** o **Verificado**
reducen el riesgo (un control únicamente propuesto todavía no protege al activo).

Las eficacias se combinan de forma **multiplicativa** para modelar
*rendimientos decrecientes* (dos controles del 50 % no eliminan el riesgo, sino
que dejan `0,5 × 0,5 = 0,25` de exposición):

```
Eficacia total = 1 − Π (1 − eficaciaᵢ)          (limitada a 0,90 máx.)
Riesgo residual = round( Riesgo inherente × (1 − Eficacia total) )   (mínimo 1)
```

Casos especiales:
- **Aceptar** → riesgo residual = riesgo inherente.
- **Evitar** (implementado) → riesgo residual = 1 (mínimo).

> Se limita la reducción máxima a 90 %: **nunca existe riesgo cero**, un
> principio fundamental de la gestión realista de riesgos.

---

## 7. Fase 5 — Comunicación y consulta

Se registran **observaciones** y **recomendaciones** dirigidas a las partes
interesadas, asociadas o no a un riesgo específico. El sistema genera un
**informe ejecutivo** exportable a PDF con la postura de riesgo, el registro
completo, el plan de tratamiento y las recomendaciones.

---

## 8. Fase 6 — Monitoreo y supervisión

Un panel consolidado presenta en tiempo real:

- **KPIs:** activos valorados, riesgos identificados, controles aplicados y
  reducción de riesgo global (inherente → residual).
- **Matriz de riesgo 5×5** con la distribución de riesgos por Probabilidad ×
  Impacto.
- **Comparación inherente vs. residual** por nivel.
- **Riesgos prioritarios** (residual ≥ Alto) que requieren atención inmediata.
- **Estado de los controles** (Propuesto → En Implementación → Implementado →
  Verificado).

El ciclo es **iterativo**: los hallazgos del monitoreo alimentan nuevas
valoraciones, cerrando el bucle de mejora continua (coherente con el ciclo PDCA
de la ISO/IEC 27001).

---

## 9. Diagrama del flujo

```
 ┌──────────────┐   ┌────────────────┐   ┌───────────────┐
 │ 1. Valoración│──▶│ 2. Identificar │──▶│ 3. Tratamiento│
 │   de activos │   │    y analizar  │   │  (ISO 27002)  │
 └──────────────┘   └────────────────┘   └───────┬───────┘
        ▲                                         │
        │                                         ▼
 ┌──────┴───────┐   ┌────────────────┐   ┌───────────────┐
 │ 6. Monitoreo │◀──│ 5. Comunicación│◀──│ 4. Riesgo     │
 │ y supervisión│   │   y consulta   │   │    residual   │
 └──────────────┘   └────────────────┘   └───────────────┘
        └──────────── mejora continua (PDCA) ◀────────────┘
```
