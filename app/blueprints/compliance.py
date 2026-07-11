"""
Blueprint de Cumplimiento (Compliance).

Mide la cobertura del programa de seguridad frente a marcos internacionales:
  - ISO/IEC 27002:2022 : % de controles del catálogo efectivamente aplicados.
  - NIST CSF 2.0        : distribución de los controles aplicados por función
                          (Govern, Identify, Protect, Detect, Respond, Recover).
"""
from flask import Blueprint, render_template
from flask_login import login_required

from ..models import Control, Treatment

compliance_bp = Blueprint("compliance", __name__, url_prefix="/cumplimiento")

# Orden y descripción de las funciones NIST CSF 2.0.
NIST_FUNCIONES = [
    ("Govern", "Gobernar", "Estrategia, políticas y supervisión del riesgo."),
    ("Identify", "Identificar", "Conocer activos, riesgos y contexto."),
    ("Protect", "Proteger", "Salvaguardas para limitar el impacto."),
    ("Detect", "Detectar", "Identificar eventos y anomalías."),
    ("Respond", "Responder", "Acciones ante un incidente detectado."),
    ("Recover", "Recuperar", "Restaurar capacidades tras un incidente."),
]


@compliance_bp.route("/")
@login_required
def index():
    controles = Control.query.all()
    total_catalogo = len(controles)

    # Controles efectivamente aplicados (con al menos un tratamiento asociado).
    aplicados_ids = {t.control_id for t in Treatment.query.all() if t.control_id}
    aplicados = [c for c in controles if c.id in aplicados_ids]
    cobertura_iso = round(len(aplicados) / total_catalogo * 100) if total_catalogo else 0

    # Distribución por tema ISO.
    temas = {}
    for c in controles:
        t = temas.setdefault(c.tema, {"total": 0, "aplicados": 0})
        t["total"] += 1
        if c.id in aplicados_ids:
            t["aplicados"] += 1

    # Distribución por función NIST CSF 2.0.
    nist = {}
    for clave, nombre, desc in NIST_FUNCIONES:
        catalogo = [c for c in controles if c.nist_csf == clave]
        aplic = [c for c in catalogo if c.id in aplicados_ids]
        nist[clave] = {
            "nombre": nombre, "desc": desc,
            "catalogo": len(catalogo), "aplicados": len(aplic),
            "pct": round(len(aplic) / len(catalogo) * 100) if catalogo else 0,
        }

    return render_template(
        "compliance/index.html",
        total_catalogo=total_catalogo, aplicados=aplicados,
        cobertura_iso=cobertura_iso, temas=temas,
        nist=nist, nist_orden=NIST_FUNCIONES,
    )
