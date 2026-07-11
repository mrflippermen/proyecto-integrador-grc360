"""
Blueprint de Inteligencia de Amenazas (Cyber Threat Intelligence).

Enriquece las vulnerabilidades con datos reales de NVD (CVSS), EPSS
(probabilidad de explotación) y CISA KEV (explotación activa), y calcula un VPR
(Vulnerability Priority Rating) al estilo Tenable. Da soporte al control
ISO/IEC 27002:2022 5.7 "Inteligencia de amenazas".
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from ..extensions import db
from ..models import Vulnerability, AuditLog
from .. import threat_intel

intel_bp = Blueprint("intel", __name__, url_prefix="/intel")


@intel_bp.route("/")
@login_required
def index():
    vulns = Vulnerability.query.all()
    # Ordena por VPR descendente (las que no tienen intel van al final).
    vulns.sort(key=lambda v: (v.vpr if v.vpr is not None else -1), reverse=True)

    enriquecidas = [v for v in vulns if v.cvss_score is not None]
    kev_count = sum(1 for v in vulns if v.kev)
    criticas = sum(1 for v in enriquecidas if (v.vpr or 0) >= 9)
    epss_alto = sum(1 for v in enriquecidas if (v.epss_score or 0) >= 0.5)

    return render_template(
        "intel/index.html", vulns=vulns, enriquecidas=enriquecidas,
        kev_count=kev_count, criticas=criticas, epss_alto=epss_alto,
    )


@intel_bp.route("/vuln/<int:vuln_id>/enriquecer", methods=["POST"])
@login_required
def enriquecer(vuln_id):
    v = db.session.get(Vulnerability, vuln_id)
    if not v:
        flash("Vulnerabilidad no encontrada.", "warning")
        return redirect(url_for("intel.index"))

    cve_id = (request.form.get("cve_id") or v.cve_id or "").strip().upper()
    if not threat_intel.cve_valido(cve_id):
        flash("Ingrese un identificador CVE válido (formato CVE-AAAA-NNNN).", "danger")
        return redirect(url_for("intel.index"))

    res = threat_intel.enriquecer(cve_id)
    v.cve_id = cve_id
    if res["cvss_score"] is not None:
        v.cvss_score = res["cvss_score"]
        v.cvss_vector = res["cvss_vector"]
    if res["descripcion"]:
        v.descripcion = res["descripcion"][:2000]
    if res["epss_score"] is not None:
        v.epss_score = res["epss_score"]
        v.epss_percentile = res["epss_percentile"]
    v.kev = res["kev"]
    v.kev_fecha = res["kev_fecha"]
    v.intel_fecha = res.get("fecha")
    db.session.commit()

    AuditLog.registrar(current_user.nombre, "ENRIQUECER", "Vulnerabilidad",
                       f"{cve_id} · fuentes: {', '.join(res['fuentes']) or 'ninguna'}")

    if res["ok"]:
        detalle = f"CVSS {v.cvss_score or '—'} · EPSS {v.epss_pct or '—'}% · " \
                  f"{'KEV ✔' if v.kev else 'no-KEV'} · fuentes: {', '.join(res['fuentes'])}"
        flash(f"{cve_id} enriquecido. {detalle}", "success")
    else:
        flash(f"No se pudo obtener inteligencia para {cve_id}. "
              f"{' '.join(res['errores'])}", "warning")
    return redirect(url_for("intel.index"))
