"""
API REST (JSON) de CyberRisk 360.

Expone toda la lógica de la metodología GRC-360 —valoración de activos, análisis
de riesgo, tratamiento, riesgo residual, inteligencia de amenazas y cumplimiento—
como servicios JSON para ser consumidos por el frontend Astro (SCSS + TypeScript).

Nota académica: para simplificar la demostración local, los endpoints de lectura
son abiertos. En producción se protegerían con autenticación (sesión/JWT) y CORS
restringido al origen del frontend.
"""
from flask import Blueprint, jsonify, request

from ..extensions import db
from ..models import (
    Asset, Threat, Vulnerability, Risk, Control, Treatment, Observation,
    Setting, AuditLog, RiskSnapshot,
    cyber_exposure_score, ces_nivel, nivel_desde_puntaje,
    ESTRATEGIAS_TRATAMIENTO, ESTADOS_RIESGO, ESTADOS_CONTROL,
)
from ..blueprints.compliance import NIST_FUNCIONES
from .. import threat_intel

api_bp = Blueprint("api", __name__, url_prefix="/api")


# --- CORS abierto para el frontend Astro (dev en :4321) ---
@api_bp.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@api_bp.route("/<path:_any>", methods=["OPTIONS"])
@api_bp.route("/", methods=["OPTIONS"])
def preflight(_any=None):
    return ("", 204)


# ---------------------------------------------------------------------------
# Serializadores
# ---------------------------------------------------------------------------

def nivel_dict(niv):
    return {"nombre": niv[0], "clase": niv[1], "color": niv[2]}


def asset_dict(a):
    return {
        "id": a.id, "codigo": a.codigo, "nombre": a.nombre, "descripcion": a.descripcion,
        "tipo": a.tipo, "propietario": a.propietario,
        "confidencialidad": a.confidencialidad, "integridad": a.integridad,
        "disponibilidad": a.disponibilidad, "valor": a.valor, "valor_texto": a.valor_texto,
        "n_riesgos": len(a.riesgos),
    }


def vuln_dict(v):
    return {
        "id": v.id, "nombre": v.nombre, "categoria": v.categoria, "descripcion": v.descripcion,
        "cve_id": v.cve_id, "cvss_score": v.cvss_score, "cvss_vector": v.cvss_vector,
        "cvss_severidad": v.cvss_severidad, "epss_pct": v.epss_pct, "epss_percentile": v.epss_percentile,
        "kev": v.kev, "kev_fecha": v.kev_fecha, "vpr": v.vpr, "vpr_nivel": v.vpr_nivel,
        "intel_fecha": v.intel_fecha.isoformat() if v.intel_fecha else None,
    }


def threat_dict(t):
    return {"id": t.id, "nombre": t.nombre, "categoria": t.categoria, "descripcion": t.descripcion,
            "attack_id": t.attack_id, "attack_tactica": t.attack_tactica}


def treatment_dict(t):
    return {
        "id": t.id, "estrategia": t.estrategia, "descripcion": t.descripcion,
        "responsable": t.responsable, "eficacia": t.eficacia, "estado": t.estado,
        "fecha_objetivo": t.fecha_objetivo.isoformat() if t.fecha_objetivo else None,
        "control": {"codigo_iso": t.control.codigo_iso, "nombre": t.control.nombre,
                    "tema": t.control.tema, "nist_csf": t.control.nist_csf} if t.control else None,
    }


def risk_dict(r, full=False):
    d = {
        "id": r.id, "codigo": r.codigo, "descripcion": r.descripcion, "estado": r.estado,
        "activo": {"id": r.activo.id, "codigo": r.activo.codigo, "nombre": r.activo.nombre,
                   "valor": r.activo.valor},
        "amenaza": threat_dict(r.amenaza),
        "vulnerabilidad": vuln_dict(r.vulnerabilidad),
        "probabilidad": r.probabilidad, "impacto": r.impacto,
        "puntaje_inherente": r.puntaje_inherente, "nivel_inherente": nivel_dict(r.nivel_inherente),
        "puntaje_residual": r.puntaje_residual, "nivel_residual": nivel_dict(r.nivel_residual),
        "reduccion_pct": r.reduccion_pct, "eficacia_total": round(r.eficacia_total * 100),
        "sla_dias": r.sla_dias, "sla_restante": r.sla_restante, "sla_vencido": r.sla_vencido,
    }
    if full:
        d["controles_existentes"] = r.controles_existentes
        d["tratamientos"] = [treatment_dict(t) for t in r.tratamientos]
        d["observaciones"] = [obs_dict(o) for o in r.observaciones]
    return d


def obs_dict(o):
    return {"id": o.id, "tipo": o.tipo, "autor": o.autor, "contenido": o.contenido,
            "risk_id": o.risk_id, "risk_codigo": o.riesgo.codigo if o.riesgo else None,
            "creado_en": o.creado_en.isoformat()}


# ---------------------------------------------------------------------------
# Overview (dashboard)
# ---------------------------------------------------------------------------

@api_bp.route("/overview")
def overview():
    riesgos = Risk.query.all()
    setting = Setting.get()
    niveles = ["Bajo", "Medio", "Alto", "Crítico"]

    dist_inh = {n: 0 for n in niveles}
    dist_res = {n: 0 for n in niveles}
    matriz = [[0] * 5 for _ in range(5)]
    for r in riesgos:
        dist_inh[r.nivel_inherente[0]] += 1
        dist_res[r.nivel_residual[0]] += 1
        matriz[5 - r.impacto][r.probabilidad - 1] += 1

    suma_inh = sum(r.puntaje_inherente for r in riesgos) or 1
    suma_res = sum(r.puntaje_residual for r in riesgos)
    reduccion = round((suma_inh - suma_res) / suma_inh * 100)

    estados_control = {}
    for t in Treatment.query.all():
        estados_control[t.estado] = estados_control.get(t.estado, 0) + 1

    ces = cyber_exposure_score(riesgos)
    snaps = RiskSnapshot.query.order_by(RiskSnapshot.fecha).all()

    criticos = sorted([r for r in riesgos if r.puntaje_residual >= 10],
                      key=lambda r: r.puntaje_residual, reverse=True)

    return jsonify({
        "organizacion": setting.organizacion,
        "apetito_riesgo": setting.apetito_riesgo,
        "kpis": {
            "activos": Asset.query.count(),
            "riesgos": len(riesgos),
            "controles": Treatment.query.count(),
            "reduccion": reduccion,
        },
        "ces": {"score": ces, "nivel": ces_nivel(ces)[0], "clase": ces_nivel(ces)[1]},
        "matriz": matriz,
        "dist_inherente": dist_inh,
        "dist_residual": dist_res,
        "estados_control": estados_control,
        "sobre_apetito": [risk_dict(r) for r in riesgos if r.puntaje_residual > setting.apetito_riesgo],
        "sla_vencidos": [risk_dict(r) for r in riesgos if r.sla_vencido],
        "criticos": [risk_dict(r) for r in criticos],
        "historial": {
            "fechas": [s.fecha.strftime("%d/%m") for s in snaps],
            "ces": [s.ces for s in snaps],
            "criticos": [s.n_criticos for s in snaps],
        },
        "observaciones": [obs_dict(o) for o in
                          Observation.query.order_by(Observation.creado_en.desc()).limit(5).all()],
    })


# ---------------------------------------------------------------------------
# Activos
# ---------------------------------------------------------------------------

@api_bp.route("/assets")
def assets():
    return jsonify([asset_dict(a) for a in Asset.query.order_by(Asset.codigo).all()])


@api_bp.route("/assets", methods=["POST"])
def create_asset():
    d = request.get_json(force=True)
    errores = []
    codigo = (d.get("codigo") or "").strip().upper()
    nombre = (d.get("nombre") or "").strip()
    if not codigo:
        errores.append("El código es obligatorio.")
    if len(nombre) < 3:
        errores.append("El nombre debe tener al menos 3 caracteres.")
    if Asset.query.filter_by(codigo=codigo).first():
        errores.append(f"Ya existe un activo con el código {codigo}.")
    for k in ("confidencialidad", "integridad", "disponibilidad"):
        try:
            if not 1 <= int(d.get(k)) <= 5:
                raise ValueError
        except (TypeError, ValueError):
            errores.append(f"{k} debe ser un entero entre 1 y 5.")
    if errores:
        return jsonify({"ok": False, "errores": errores}), 400
    a = Asset(codigo=codigo, nombre=nombre, descripcion=(d.get("descripcion") or "").strip(),
              tipo=d.get("tipo") or "Información", propietario=(d.get("propietario") or "").strip(),
              confidencialidad=int(d["confidencialidad"]), integridad=int(d["integridad"]),
              disponibilidad=int(d["disponibilidad"]))
    db.session.add(a)
    db.session.commit()
    AuditLog.registrar(d.get("usuario", "API"), "CREAR", "Activo", f"{a.codigo} · {a.nombre}")
    return jsonify({"ok": True, "asset": asset_dict(a)}), 201


# ---------------------------------------------------------------------------
# Riesgos
# ---------------------------------------------------------------------------

@api_bp.route("/risks")
def risks():
    rs = sorted(Risk.query.all(), key=lambda r: r.puntaje_residual, reverse=True)
    return jsonify([risk_dict(r) for r in rs])


@api_bp.route("/risks/<int:rid>")
def risk_detail(rid):
    r = db.session.get(Risk, rid)
    if not r:
        return jsonify({"error": "no encontrado"}), 404
    return jsonify(risk_dict(r, full=True))


@api_bp.route("/risks", methods=["POST"])
def create_risk():
    d = request.get_json(force=True)
    errores = []
    codigo = (d.get("codigo") or "").strip().upper()
    if not codigo:
        errores.append("El código es obligatorio.")
    if Risk.query.filter_by(codigo=codigo).first():
        errores.append(f"Ya existe un riesgo con el código {codigo}.")
    if not (d.get("asset_id") and d.get("threat_id") and d.get("vulnerability_id")):
        errores.append("Debe seleccionar activo, amenaza y vulnerabilidad.")
    for k in ("probabilidad", "impacto"):
        try:
            if not 1 <= int(d.get(k)) <= 5:
                raise ValueError
        except (TypeError, ValueError):
            errores.append(f"{k} debe ser un entero entre 1 y 5.")
    if errores:
        return jsonify({"ok": False, "errores": errores}), 400
    r = Risk(codigo=codigo, asset_id=int(d["asset_id"]), threat_id=int(d["threat_id"]),
             vulnerability_id=int(d["vulnerability_id"]), probabilidad=int(d["probabilidad"]),
             impacto=int(d["impacto"]), descripcion=(d.get("descripcion") or "").strip(),
             controles_existentes=(d.get("controles_existentes") or "").strip(),
             estado=d.get("estado") or "Identificado")
    db.session.add(r)
    db.session.commit()
    AuditLog.registrar(d.get("usuario", "API"), "CREAR", "Riesgo", f"{r.codigo}")
    return jsonify({"ok": True, "risk": risk_dict(r, full=True)}), 201


# ---------------------------------------------------------------------------
# Inteligencia de amenazas
# ---------------------------------------------------------------------------

@api_bp.route("/intel")
def intel():
    vulns = sorted(Vulnerability.query.all(),
                   key=lambda v: (v.vpr if v.vpr is not None else -1), reverse=True)
    enr = [v for v in vulns if v.cvss_score is not None]
    return jsonify({
        "kpis": {
            "enriquecidas": len(enr), "total": len(vulns),
            "kev": sum(1 for v in vulns if v.kev),
            "vpr_critico": sum(1 for v in enr if (v.vpr or 0) >= 9),
            "epss_alto": sum(1 for v in enr if (v.epss_score or 0) >= 0.5),
        },
        "vulnerabilidades": [vuln_dict(v) for v in vulns],
    })


@api_bp.route("/intel/<int:vid>/enrich", methods=["POST"])
def enrich(vid):
    v = db.session.get(Vulnerability, vid)
    if not v:
        return jsonify({"ok": False, "error": "no encontrado"}), 404
    d = request.get_json(force=True)
    cve = (d.get("cve_id") or v.cve_id or "").strip().upper()
    if not threat_intel.cve_valido(cve):
        return jsonify({"ok": False, "error": "CVE inválido (formato CVE-AAAA-NNNN)."}), 400
    res = threat_intel.enriquecer(cve)
    v.cve_id = cve
    if res["cvss_score"] is not None:
        v.cvss_score, v.cvss_vector = res["cvss_score"], res["cvss_vector"]
    if res["descripcion"]:
        v.descripcion = res["descripcion"][:2000]
    if res["epss_score"] is not None:
        v.epss_score, v.epss_percentile = res["epss_score"], res["epss_percentile"]
    v.kev, v.kev_fecha, v.intel_fecha = res["kev"], res["kev_fecha"], res.get("fecha")
    db.session.commit()
    AuditLog.registrar(d.get("usuario", "API"), "ENRIQUECER", "Vulnerabilidad",
                       f"{cve} · fuentes: {', '.join(res['fuentes']) or 'ninguna'}")
    return jsonify({"ok": res["ok"], "fuentes": res["fuentes"], "errores": res["errores"],
                    "vulnerabilidad": vuln_dict(v)})


# ---------------------------------------------------------------------------
# Cumplimiento
# ---------------------------------------------------------------------------

@api_bp.route("/compliance")
def compliance():
    controles = Control.query.all()
    total = len(controles)
    aplicados_ids = {t.control_id for t in Treatment.query.all() if t.control_id}
    aplicados = [c for c in controles if c.id in aplicados_ids]

    temas = {}
    for c in controles:
        t = temas.setdefault(c.tema, {"total": 0, "aplicados": 0})
        t["total"] += 1
        if c.id in aplicados_ids:
            t["aplicados"] += 1

    nist = []
    for clave, nombre, desc in NIST_FUNCIONES:
        cat = [c for c in controles if c.nist_csf == clave]
        ap = [c for c in cat if c.id in aplicados_ids]
        nist.append({"clave": clave, "nombre": nombre, "desc": desc,
                     "catalogo": len(cat), "aplicados": len(ap),
                     "pct": round(len(ap) / len(cat) * 100) if cat else 0})

    return jsonify({
        "cobertura_iso": round(len(aplicados) / total * 100) if total else 0,
        "total_catalogo": total, "aplicados": len(aplicados),
        "temas": temas, "nist": nist,
    })


# ---------------------------------------------------------------------------
# Catálogos, auditoría, configuración
# ---------------------------------------------------------------------------

@api_bp.route("/catalogs")
def catalogs():
    return jsonify({
        "activos": [asset_dict(a) for a in Asset.query.order_by(Asset.codigo).all()],
        "amenazas": [threat_dict(t) for t in Threat.query.order_by(Threat.nombre).all()],
        "vulnerabilidades": [vuln_dict(v) for v in Vulnerability.query.order_by(Vulnerability.nombre).all()],
        "estados_riesgo": ESTADOS_RIESGO,
        "estrategias": ESTRATEGIAS_TRATAMIENTO,
        "estados_control": ESTADOS_CONTROL,
    })


@api_bp.route("/audit")
def audit():
    logs = AuditLog.query.order_by(AuditLog.creado_en.desc()).limit(200).all()
    return jsonify([{"usuario": l.usuario, "accion": l.accion, "entidad": l.entidad,
                     "detalle": l.detalle, "creado_en": l.creado_en.isoformat()} for l in logs])


@api_bp.route("/observations", methods=["POST"])
def create_obs():
    d = request.get_json(force=True)
    contenido = (d.get("contenido") or "").strip()
    if len(contenido) < 5:
        return jsonify({"ok": False, "error": "La observación debe tener al menos 5 caracteres."}), 400
    o = Observation(risk_id=int(d["risk_id"]) if d.get("risk_id") else None,
                    autor=d.get("autor", "API"), tipo=d.get("tipo", "Recomendación"),
                    contenido=contenido)
    db.session.add(o)
    db.session.commit()
    return jsonify({"ok": True, "observacion": obs_dict(o)}), 201


@api_bp.route("/settings", methods=["GET", "POST"])
def settings():
    s = Setting.get()
    if request.method == "POST":
        d = request.get_json(force=True)
        s.organizacion = (d.get("organizacion") or s.organizacion).strip()
        try:
            ap = int(d.get("apetito_riesgo"))
            if 1 <= ap <= 25:
                s.apetito_riesgo = ap
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Apetito inválido (1–25)."}), 400
        db.session.commit()
        AuditLog.registrar(d.get("usuario", "API"), "EDITAR", "Configuración",
                           f"Apetito = {s.apetito_riesgo}")
    return jsonify({"organizacion": s.organizacion, "apetito_riesgo": s.apetito_riesgo})
