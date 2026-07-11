"""
Blueprint de activos (FASE 1 — Valoración de activos).

CRUD de activos de información con valoración CIA (Confidencialidad,
Integridad, Disponibilidad) en escala 1..5.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from ..extensions import db
from ..models import Asset, AuditLog

assets_bp = Blueprint("assets", __name__, url_prefix="/activos")

TIPOS = ["Información", "Software", "Hardware", "Servicio", "Personal", "Instalación"]


def _validar_cia(valor, campo, errores):
    try:
        v = int(valor)
        if not 1 <= v <= 5:
            raise ValueError
        return v
    except (TypeError, ValueError):
        errores.append(f"El valor de {campo} debe ser un entero entre 1 y 5.")
        return None


@assets_bp.route("/")
@login_required
def listar():
    activos = Asset.query.order_by(Asset.codigo).all()
    return render_template("assets/list.html", activos=activos)


@assets_bp.route("/nuevo", methods=["GET", "POST"])
@assets_bp.route("/<int:asset_id>/editar", methods=["GET", "POST"])
@login_required
def editar(asset_id=None):
    activo = db.session.get(Asset, asset_id) if asset_id else None

    if request.method == "POST":
        errores = []
        codigo = request.form.get("codigo", "").strip().upper()
        nombre = request.form.get("nombre", "").strip()

        if not codigo:
            errores.append("El código del activo es obligatorio.")
        if len(nombre) < 3:
            errores.append("El nombre debe tener al menos 3 caracteres.")

        # Unicidad del código.
        existente = Asset.query.filter_by(codigo=codigo).first()
        if existente and (activo is None or existente.id != activo.id):
            errores.append(f"Ya existe un activo con el código {codigo}.")

        c = _validar_cia(request.form.get("confidencialidad"), "Confidencialidad", errores)
        i = _validar_cia(request.form.get("integridad"), "Integridad", errores)
        d = _validar_cia(request.form.get("disponibilidad"), "Disponibilidad", errores)

        if errores:
            for e in errores:
                flash(e, "danger")
            return render_template("assets/form.html", activo=activo or request.form, tipos=TIPOS, es_nuevo=activo is None)

        es_creacion = activo is None
        if activo is None:
            activo = Asset()
            db.session.add(activo)

        activo.codigo = codigo
        activo.nombre = nombre
        activo.descripcion = request.form.get("descripcion", "").strip()
        activo.tipo = request.form.get("tipo", "Información")
        activo.propietario = request.form.get("propietario", "").strip()
        activo.confidencialidad = c
        activo.integridad = i
        activo.disponibilidad = d
        db.session.commit()
        AuditLog.registrar(current_user.nombre, "CREAR" if es_creacion else "EDITAR",
                           "Activo", f"{activo.codigo} · {activo.nombre}")
        flash("Activo guardado correctamente.", "success")
        return redirect(url_for("assets.listar"))

    return render_template("assets/form.html", activo=activo, tipos=TIPOS, es_nuevo=activo is None)


@assets_bp.route("/<int:asset_id>/eliminar", methods=["POST"])
@login_required
def eliminar(asset_id):
    activo = db.session.get(Asset, asset_id)
    if activo:
        if activo.riesgos:
            flash("No se puede eliminar: el activo tiene riesgos asociados.", "warning")
            return redirect(url_for("assets.listar"))
        codigo = activo.codigo
        db.session.delete(activo)
        db.session.commit()
        AuditLog.registrar(current_user.nombre, "ELIMINAR", "Activo", codigo)
        flash("Activo eliminado.", "info")
    return redirect(url_for("assets.listar"))
