"""
Blueprint de reportes (apoya FASE 5 — Comunicación y consulta).

Genera un informe consolidado para partes interesadas, imprimible/exportable
a PDF desde el navegador (Ctrl+P). Incluye resumen ejecutivo, registro de
riesgos y plan de tratamiento.
"""
from datetime import datetime

from flask import Blueprint, render_template
from flask_login import login_required, current_user

from ..models import Asset, Risk, Treatment, Observation

reports_bp = Blueprint("reports", __name__, url_prefix="/reportes")


@reports_bp.route("/")
@login_required
def index():
    return render_template("reports/index.html")


@reports_bp.route("/ejecutivo")
@login_required
def ejecutivo():
    riesgos = Risk.query.all()
    riesgos.sort(key=lambda r: r.puntaje_residual, reverse=True)

    suma_inh = sum(r.puntaje_inherente for r in riesgos) or 1
    suma_res = sum(r.puntaje_residual for r in riesgos)
    reduccion_global = round((suma_inh - suma_res) / suma_inh * 100)

    criticos = [r for r in riesgos if r.puntaje_residual >= 10]

    return render_template(
        "reports/ejecutivo.html",
        riesgos=riesgos,
        activos=Asset.query.order_by(Asset.codigo).all(),
        observaciones=Observation.query.order_by(Observation.creado_en.desc()).all(),
        reduccion_global=reduccion_global,
        criticos=criticos,
        total_controles=Treatment.query.count(),
        generado_por=current_user.nombre,
        fecha=datetime.now().strftime("%d/%m/%Y %H:%M"),
    )
