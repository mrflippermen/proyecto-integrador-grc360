"""
Blueprint de comunicación y consulta (FASE 5).

Registro de observaciones y recomendaciones dirigidas a las partes
interesadas, asociadas o no a un riesgo concreto.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from ..extensions import db
from ..models import Observation, Risk

comm_bp = Blueprint("communication", __name__, url_prefix="/comunicacion")


@comm_bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        contenido = request.form.get("contenido", "").strip()
        tipo = request.form.get("tipo", "Recomendación")
        risk_id = request.form.get("risk_id") or None

        if len(contenido) < 5:
            flash("La observación debe tener al menos 5 caracteres.", "danger")
        else:
            obs = Observation(
                risk_id=int(risk_id) if risk_id else None,
                autor=current_user.nombre,
                tipo=tipo,
                contenido=contenido,
            )
            db.session.add(obs)
            db.session.commit()
            flash("Observación registrada correctamente.", "success")
        return redirect(url_for("communication.index"))

    observaciones = Observation.query.order_by(Observation.creado_en.desc()).all()
    return render_template(
        "communication/index.html",
        observaciones=observaciones,
        riesgos=Risk.query.order_by(Risk.codigo).all(),
    )


@comm_bp.route("/<int:obs_id>/eliminar", methods=["POST"])
@login_required
def eliminar(obs_id):
    obs = db.session.get(Observation, obs_id)
    if obs:
        db.session.delete(obs)
        db.session.commit()
        flash("Observación eliminada.", "info")
    return redirect(url_for("communication.index"))
