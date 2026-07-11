"""
Blueprint de administración: configuración, auditoría y exportación de datos.
"""
import csv
import io

from flask import Blueprint, render_template, redirect, url_for, request, flash, Response
from flask_login import login_required, current_user

from ..extensions import db
from ..models import Setting, AuditLog, Risk

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/configuracion", methods=["GET", "POST"])
@login_required
def configuracion():
    s = Setting.get()
    if request.method == "POST":
        s.organizacion = request.form.get("organizacion", "").strip() or s.organizacion
        try:
            apetito = int(request.form.get("apetito_riesgo"))
            if 1 <= apetito <= 25:
                s.apetito_riesgo = apetito
            else:
                raise ValueError
        except (TypeError, ValueError):
            flash("El apetito de riesgo debe ser un entero entre 1 y 25.", "danger")
            return render_template("admin/configuracion.html", s=s)
        db.session.commit()
        AuditLog.registrar(current_user.nombre, "EDITAR", "Configuración",
                           f"Apetito de riesgo = {s.apetito_riesgo}")
        flash("Configuración actualizada.", "success")
        return redirect(url_for("admin.configuracion"))
    return render_template("admin/configuracion.html", s=s)


@admin_bp.route("/auditoria")
@login_required
def auditoria():
    logs = AuditLog.query.order_by(AuditLog.creado_en.desc()).limit(200).all()
    return render_template("admin/auditoria.html", logs=logs)


@admin_bp.route("/exportar/riesgos.csv")
@login_required
def exportar_riesgos():
    """Exporta el registro de riesgos a CSV (portabilidad de datos)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "Codigo", "Activo", "Amenaza", "Vulnerabilidad", "CVE", "CVSS", "VPR",
        "Probabilidad", "Impacto", "Riesgo_Inherente", "Nivel_Inherente",
        "Riesgo_Residual", "Nivel_Residual", "Reduccion_%", "Estado",
        "SLA_dias", "SLA_vencido",
    ])
    for r in Risk.query.order_by(Risk.codigo).all():
        writer.writerow([
            r.codigo, r.activo.nombre, r.amenaza.nombre, r.vulnerabilidad.nombre,
            r.vulnerabilidad.cve_id or "", r.vulnerabilidad.cvss_score or "",
            r.vulnerabilidad.vpr if r.vulnerabilidad.vpr is not None else "",
            r.probabilidad, r.impacto, r.puntaje_inherente, r.nivel_inherente[0],
            r.puntaje_residual, r.nivel_residual[0], r.reduccion_pct, r.estado,
            r.sla_dias, "SI" if r.sla_vencido else "NO",
        ])
    AuditLog.registrar(current_user.nombre, "EXPORTAR", "Riesgos", "Exportación CSV del registro de riesgos")
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=registro_riesgos.csv"},
    )
