"""
Servicio de Inteligencia de Amenazas (Cyber Threat Intelligence).

Enriquece una vulnerabilidad a partir de su identificador CVE consultando tres
fuentes públicas y gratuitas (sin API key), las mismas que emplean las
plataformas comerciales de gestión de exposición:

  1. NVD (NIST)        -> CVSS v3.1 base score + descripción oficial del CVE.
     https://services.nvd.nist.gov/rest/json/cves/2.0
  2. EPSS (FIRST.org)  -> probabilidad de explotación en los próximos 30 días.
     https://api.first.org/data/v1/epss
  3. CISA KEV          -> ¿la vulnerabilidad está siendo explotada activamente?
     https://www.cisa.gov/.../known_exploited_vulnerabilities.json

Todas las llamadas usan timeout y degradación elegante: si una fuente no
responde, se devuelve la información parcial y se registra el error, de modo que
la aplicación nunca se bloquea por falta de conectividad.
"""
import re
import time
from datetime import datetime

try:
    import requests
except ImportError:  # la app funciona aunque requests no esté instalado
    requests = None

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

TIMEOUT = 10
_HEADERS = {"User-Agent": "CyberRisk360/1.0 (proyecto academico ITIZ3301)"}

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Caché en memoria del catálogo CISA KEV (evita descargarlo en cada consulta).
_kev_cache = {"cargado": 0, "cves": None}
_KEV_TTL = 3600  # 1 hora


def cve_valido(cve_id):
    return bool(cve_id and CVE_REGEX.match(cve_id.strip()))


def _cargar_kev():
    """Descarga (y cachea) el catálogo CISA KEV como dict {CVE: fecha}."""
    ahora = time.time()
    if _kev_cache["cves"] is not None and (ahora - _kev_cache["cargado"]) < _KEV_TTL:
        return _kev_cache["cves"]
    if requests is None:
        return {}
    try:
        r = requests.get(KEV_URL, timeout=TIMEOUT, headers=_HEADERS)
        r.raise_for_status()
        data = r.json()
        cves = {v["cveID"].upper(): v.get("dateAdded", "") for v in data.get("vulnerabilities", [])}
        _kev_cache.update({"cargado": ahora, "cves": cves})
        return cves
    except Exception:
        return _kev_cache["cves"] or {}


def _consultar_nvd(cve_id):
    """Devuelve (cvss_score, cvss_vector, descripcion) desde la NVD."""
    if requests is None:
        return None, None, None
    try:
        r = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=TIMEOUT, headers=_HEADERS)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return None, None, None
        cve = vulns[0]["cve"]
        # Descripción en inglés.
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
        # Métrica CVSS 3.1 (o 3.0 como respaldo).
        metrics = cve.get("metrics", {})
        m = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
        if m:
            data = m[0]["cvssData"]
            return data.get("baseScore"), data.get("vectorString"), desc
        return None, None, desc
    except Exception:
        return None, None, None


def _consultar_epss(cve_id):
    """Devuelve (epss_score, percentil) desde FIRST.org EPSS."""
    if requests is None:
        return None, None
    try:
        r = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=TIMEOUT, headers=_HEADERS)
        r.raise_for_status()
        data = r.json().get("data", [])
        if data:
            return float(data[0]["epss"]), float(data[0]["percentile"])
        return None, None
    except Exception:
        return None, None


def enriquecer(cve_id):
    """Consulta las tres fuentes y devuelve un dict consolidado de inteligencia.

    Estructura de retorno:
        {
          ok, cve_id, cvss_score, cvss_vector, descripcion,
          epss_score, epss_percentile, kev, kev_fecha, fuentes, errores
        }
    """
    cve_id = (cve_id or "").strip().upper()
    resultado = {
        "ok": False, "cve_id": cve_id, "cvss_score": None, "cvss_vector": None,
        "descripcion": None, "epss_score": None, "epss_percentile": None,
        "kev": False, "kev_fecha": None, "fuentes": [], "errores": [],
    }

    if not cve_valido(cve_id):
        resultado["errores"].append("Identificador CVE inválido (formato CVE-AAAA-NNNN).")
        return resultado
    if requests is None:
        resultado["errores"].append("La librería 'requests' no está instalada.")
        return resultado

    # 1) NVD (CVSS + descripción)
    score, vector, desc = _consultar_nvd(cve_id)
    if score is not None or desc:
        resultado.update({"cvss_score": score, "cvss_vector": vector, "descripcion": desc})
        resultado["fuentes"].append("NVD")
    else:
        resultado["errores"].append("NVD: sin datos o sin conexión.")

    # 2) EPSS (probabilidad de explotación)
    epss, pct = _consultar_epss(cve_id)
    if epss is not None:
        resultado.update({"epss_score": epss, "epss_percentile": pct})
        resultado["fuentes"].append("EPSS")
    else:
        resultado["errores"].append("EPSS: sin datos o sin conexión.")

    # 3) CISA KEV (explotación activa)
    kev = _cargar_kev()
    if kev:
        resultado["fuentes"].append("CISA KEV")
        if cve_id in kev:
            resultado.update({"kev": True, "kev_fecha": kev[cve_id]})
    else:
        resultado["errores"].append("CISA KEV: catálogo no disponible.")

    resultado["ok"] = bool(resultado["fuentes"])
    resultado["fecha"] = datetime.utcnow()
    return resultado
