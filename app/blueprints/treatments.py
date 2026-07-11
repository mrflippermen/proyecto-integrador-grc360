"""
Blueprint de tratamiento (FASE 3 y 4 — Tratamiento del riesgo y riesgo residual).

Registra la estrategia de respuesta (Mitigar/Transferir/Aceptar/Evitar), el
control ISO/IEC 27002:2022 asociado, el responsable y la eficacia estimada;
el riesgo residual se recalcula automáticamente en el modelo Risk.
"""
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from ..extensions import db
from ..models import (
    Risk, Control, Treatment, AuditLog, ESTRATEGIAS_TRATAMIENTO, ESTADOS_CONTROL
)

treatments_bp = Blueprint("treatments", __name__, url_prefix="/tratamiento")


@treatments_bp.route("/riesgo/<int:risk_id>/nuevo", methods=["GET", "POST"])
@login_required
def nuevo(risk_id):
    riesgo = db.session.get(Risk, risk_id)
    if not riesgo:
        flash("Riesgo no encontrado.", "warning")
        return redirect(url_for("risks.listar"))

    controles = Control.query.order_by(Control.codigo_iso).all()

    if request.method == "POST":
        errores = []
        estrategia = request.form.get("estrategia", "Mitigar")
        if estrategia not in ESTRATEGIAS_TRATAMIENTO:
            errores.append("Estrategia de tratamiento inválida.")

        try:
            eficacia = int(request.form.get("eficacia", 0))
            if not 0 <= eficacia <= 90:
                raise ValueError
        except ValueError:
            errores.append("La eficacia debe ser un entero entre 0 y 90 (%).")
            eficacia = 0

        if errores:
            for e in errores:
                flash(e, "danger")
            return render_template(
                "treatments/form.html", riesgo=riesgo, controles=controles,
                estrategias=ESTRATEGIAS_TRATAMIENTO, estados=ESTADOS_CONTROL,
                tratamiento=request.form,
            )

        control_id = request.form.get("control_id") or None
        fecha_obj = request.form.get("fecha_objetivo") or None

        t = Treatment(
            risk_id=riesgo.id,
            control_id=int(control_id) if control_id else None,
            estrategia=estrategia,
            descripcion=request.form.get("descripcion", "").strip(),
            responsable=request.form.get("responsable", "").strip(),
            eficacia=eficacia if estrategia == "Mitigar" else (eficacia if estrategia == "Transferir" else 0),
            estado=request.form.get("estado", "Propuesto"),
        )
        if fecha_obj:
            try:
                t.fecha_objetivo = datetime.strptime(fecha_obj, "%Y-%m-%d").date()
            except ValueError:
                pass
        db.session.add(t)

        # Actualiza el estado del riesgo según la estrategia.
        if estrategia == "Aceptar":
            riesgo.estado = "Aceptado"
        elif riesgo.estado == "Identificado":
            riesgo.estado = "En Tratamiento"
        db.session.commit()
        AuditLog.registrar(current_user.nombre, "CREAR", "Tratamiento",
                           f"{riesgo.codigo} · {estrategia} · eficacia {t.eficacia}%")
        flash("Tratamiento registrado. El riesgo residual fue recalculado.", "success")
        return redirect(url_for("risks.detalle", risk_id=riesgo.id))

    return render_template(
        "treatments/form.html", riesgo=riesgo, controles=controles,
        estrategias=ESTRATEGIAS_TRATAMIENTO, estados=ESTADOS_CONTROL, tratamiento=None,
    )


@treatments_bp.route("/<int:treatment_id>/estado", methods=["POST"])
@login_required
def cambiar_estado(treatment_id):
    """Actualiza el estado de implementación de un control (monitoreo)."""
    t = db.session.get(Treatment, treatment_id)
    if t:
        nuevo_estado = request.form.get("estado")
        if nuevo_estado in ESTADOS_CONTROL:
            t.estado = nuevo_estado
            # Si todos los controles del riesgo están verificados -> Controlado.
            if all(x.estado in ("Implementado", "Verificado") for x in t.riesgo.tratamientos):
                if t.riesgo.estado not in ("Aceptado", "Cerrado"):
                    t.riesgo.estado = "Controlado"
            db.session.commit()
            flash("Estado del control actualizado.", "success")
        return redirect(url_for("risks.detalle", risk_id=t.risk_id))
    return redirect(url_for("risks.listar"))


@treatments_bp.route("/<int:treatment_id>/eliminar", methods=["POST"])
@login_required
def eliminar(treatment_id):
    t = db.session.get(Treatment, treatment_id)
    risk_id = t.risk_id if t else None
    if t:
        db.session.delete(t)
        db.session.commit()
        flash("Tratamiento eliminado. El riesgo residual fue recalculado.", "info")
    return redirect(url_for("risks.detalle", risk_id=risk_id))


@treatments_bp.route("/controles")
@login_required
def controles():
    """Catálogo de controles ISO/IEC 27002:2022."""
    lista = Control.query.order_by(Control.codigo_iso).all()
    # Agrupa por tema para presentación.
    por_tema = {}
    for c in lista:
        por_tema.setdefault(c.tema, []).append(c)
    return render_template("treatments/controles.html", por_tema=por_tema, total=len(lista))
