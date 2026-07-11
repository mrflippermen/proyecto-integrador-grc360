"""
Blueprint de riesgos (FASE 2 — Identificación y análisis de riesgos).

Un riesgo relaciona un Activo con una Amenaza y una Vulnerabilidad, y se
valora con Probabilidad x Impacto (escala 1..5). Incluye la gestión de los
catálogos de amenazas y vulnerabilidades.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from ..extensions import db
from ..models import Asset, Threat, Vulnerability, Risk, AuditLog, ESTADOS_RIESGO

risks_bp = Blueprint("risks", __name__, url_prefix="/riesgos")


def _validar_1_5(valor, campo, errores):
    try:
        v = int(valor)
        if not 1 <= v <= 5:
            raise ValueError
        return v
    except (TypeError, ValueError):
        errores.append(f"{campo} debe ser un entero entre 1 y 5.")
        return None


@risks_bp.route("/")
@login_required
def listar():
    riesgos = Risk.query.order_by(Risk.codigo).all()
    # Orden por criticidad residual para priorizar visualmente.
    riesgos.sort(key=lambda r: r.puntaje_residual, reverse=True)
    return render_template("risks/list.html", riesgos=riesgos)


@risks_bp.route("/<int:risk_id>")
@login_required
def detalle(risk_id):
    riesgo = db.session.get(Risk, risk_id)
    if not riesgo:
        flash("Riesgo no encontrado.", "warning")
        return redirect(url_for("risks.listar"))
    return render_template("risks/detail.html", riesgo=riesgo)


@risks_bp.route("/nuevo", methods=["GET", "POST"])
@risks_bp.route("/<int:risk_id>/editar", methods=["GET", "POST"])
@login_required
def editar(risk_id=None):
    riesgo = db.session.get(Risk, risk_id) if risk_id else None
    activos = Asset.query.order_by(Asset.nombre).all()
    amenazas = Threat.query.order_by(Threat.nombre).all()
    vulnerabilidades = Vulnerability.query.order_by(Vulnerability.nombre).all()

    if request.method == "POST":
        errores = []
        codigo = request.form.get("codigo", "").strip().upper()
        asset_id = request.form.get("asset_id")
        threat_id = request.form.get("threat_id")
        vuln_id = request.form.get("vulnerability_id")

        if not codigo:
            errores.append("El código del riesgo es obligatorio.")
        if not (asset_id and threat_id and vuln_id):
            errores.append("Debe seleccionar activo, amenaza y vulnerabilidad.")

        existente = Risk.query.filter_by(codigo=codigo).first()
        if existente and (riesgo is None or existente.id != riesgo.id):
            errores.append(f"Ya existe un riesgo con el código {codigo}.")

        prob = _validar_1_5(request.form.get("probabilidad"), "Probabilidad", errores)
        imp = _validar_1_5(request.form.get("impacto"), "Impacto", errores)

        if errores:
            for e in errores:
                flash(e, "danger")
            return render_template(
                "risks/form.html", riesgo=riesgo or request.form, activos=activos,
                amenazas=amenazas, vulnerabilidades=vulnerabilidades,
                estados=ESTADOS_RIESGO, es_nuevo=riesgo is None,
            )

        es_creacion = riesgo is None
        if riesgo is None:
            riesgo = Risk()
            db.session.add(riesgo)

        riesgo.codigo = codigo
        riesgo.asset_id = int(asset_id)
        riesgo.threat_id = int(threat_id)
        riesgo.vulnerability_id = int(vuln_id)
        riesgo.descripcion = request.form.get("descripcion", "").strip()
        riesgo.controles_existentes = request.form.get("controles_existentes", "").strip()
        riesgo.probabilidad = prob
        riesgo.impacto = imp
        riesgo.estado = request.form.get("estado", "Identificado")
        db.session.commit()
        AuditLog.registrar(current_user.nombre, "CREAR" if es_creacion else "EDITAR",
                           "Riesgo", f"{riesgo.codigo} · P{riesgo.probabilidad}×I{riesgo.impacto}")
        flash("Riesgo guardado correctamente.", "success")
        return redirect(url_for("risks.detalle", risk_id=riesgo.id))

    return render_template(
        "risks/form.html", riesgo=riesgo, activos=activos, amenazas=amenazas,
        vulnerabilidades=vulnerabilidades, estados=ESTADOS_RIESGO, es_nuevo=riesgo is None,
    )


@risks_bp.route("/<int:risk_id>/eliminar", methods=["POST"])
@login_required
def eliminar(risk_id):
    riesgo = db.session.get(Risk, risk_id)
    if riesgo:
        codigo = riesgo.codigo
        db.session.delete(riesgo)
        db.session.commit()
        AuditLog.registrar(current_user.nombre, "ELIMINAR", "Riesgo", codigo)
        flash("Riesgo eliminado.", "info")
    return redirect(url_for("risks.listar"))


# ---------------------------------------------------------------------------
# Catálogos de amenazas y vulnerabilidades
# ---------------------------------------------------------------------------

@risks_bp.route("/catalogos", methods=["GET", "POST"])
@login_required
def catalogos():
    if request.method == "POST":
        tipo = request.form.get("tipo")
        nombre = request.form.get("nombre", "").strip()
        categoria = request.form.get("categoria", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        if len(nombre) < 3:
            flash("El nombre debe tener al menos 3 caracteres.", "danger")
        elif tipo == "amenaza":
            db.session.add(Threat(nombre=nombre, categoria=categoria, descripcion=descripcion))
            db.session.commit()
            flash("Amenaza agregada al catálogo.", "success")
        elif tipo == "vulnerabilidad":
            db.session.add(Vulnerability(nombre=nombre, categoria=categoria, descripcion=descripcion))
            db.session.commit()
            flash("Vulnerabilidad agregada al catálogo.", "success")
        return redirect(url_for("risks.catalogos"))

    return render_template(
        "risks/catalogos.html",
        amenazas=Threat.query.order_by(Threat.nombre).all(),
        vulnerabilidades=Vulnerability.query.order_by(Vulnerability.nombre).all(),
    )
