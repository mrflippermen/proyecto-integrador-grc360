"""
Blueprint del panel de monitoreo (FASE 6 — Monitoreo y supervisión).

Consolida indicadores clave (KPI), la matriz de riesgo 5x5 y el seguimiento
de controles para las partes interesadas.
"""
from flask import Blueprint, render_template
from flask_login import login_required

from ..models import (
    Asset, Risk, Treatment, Control, Observation, Setting, RiskSnapshot,
    nivel_desde_puntaje, cyber_exposure_score, ces_nivel,
)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    riesgos = Risk.query.all()
    activos = Asset.query.all()
    setting = Setting.get()

    # --- Cyber Exposure Score (estilo Tenable Lumin, 0–1000) ---
    ces = cyber_exposure_score(riesgos)
    ces_lvl = ces_nivel(ces)

    # --- Riesgos que exceden el apetito de riesgo (residual > umbral) ---
    sobre_apetito = [r for r in riesgos if r.puntaje_residual > setting.apetito_riesgo]

    # --- SLA de remediación vencidos ---
    sla_vencidos = [r for r in riesgos if r.sla_vencido]

    # --- Serie histórica para la tendencia (últimas 13 instantáneas) ---
    snaps = RiskSnapshot.query.order_by(RiskSnapshot.fecha).all()
    historial = {
        "fechas": [s.fecha.strftime("%d/%m") for s in snaps],
        "ces": [s.ces for s in snaps],
        "criticos": [s.n_criticos for s in snaps],
    }

    # --- KPIs principales ---
    total_riesgos = len(riesgos)
    total_activos = len(activos)
    total_controles = Treatment.query.count()

    # Distribución de riesgo inherente vs residual por nivel.
    niveles = ["Bajo", "Medio", "Alto", "Crítico"]
    dist_inherente = {n: 0 for n in niveles}
    dist_residual = {n: 0 for n in niveles}
    for r in riesgos:
        dist_inherente[r.nivel_inherente[0]] += 1
        dist_residual[r.nivel_residual[0]] += 1

    # Riesgos críticos/altos residuales que requieren atención prioritaria.
    criticos = sorted(
        [r for r in riesgos if r.puntaje_residual >= 10],
        key=lambda r: r.puntaje_residual,
        reverse=True,
    )

    # Matriz de calor 5x5 (probabilidad x impacto) con conteo de riesgos.
    matriz = [[0] * 5 for _ in range(5)]
    for r in riesgos:
        # fila = impacto (5 arriba .. 1 abajo), columna = probabilidad (1..5)
        matriz[5 - r.impacto][r.probabilidad - 1] += 1

    # Reducción de riesgo global lograda por el tratamiento.
    suma_inh = sum(r.puntaje_inherente for r in riesgos) or 1
    suma_res = sum(r.puntaje_residual for r in riesgos)
    reduccion_global = round((suma_inh - suma_res) / suma_inh * 100)

    # Estado de los controles.
    controles = Treatment.query.all()
    estados_control = {}
    for c in controles:
        estados_control[c.estado] = estados_control.get(c.estado, 0) + 1

    return render_template(
        "dashboard.html",
        total_riesgos=total_riesgos,
        total_activos=total_activos,
        total_controles=total_controles,
        dist_inherente=dist_inherente,
        dist_residual=dist_residual,
        criticos=criticos,
        matriz=matriz,
        reduccion_global=reduccion_global,
        estados_control=estados_control,
        observaciones=Observation.query.order_by(Observation.creado_en.desc()).limit(5).all(),
        nivel_desde_puntaje=nivel_desde_puntaje,
        ces=ces, ces_lvl=ces_lvl,
        setting=setting,
        sobre_apetito=sobre_apetito,
        sla_vencidos=sla_vencidos,
        historial=historial,
    )
