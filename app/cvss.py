"""
Cálculo de CVSS v3.1 (Common Vulnerability Scoring System).

Implementa la especificación oficial de FIRST.org para el **Base Score**, el
mismo estándar internacional que utilizan Tenable Nessus, Qualys y la NVD para
puntuar vulnerabilidades técnicas.

Referencia: https://www.first.org/cvss/v3.1/specification-document
"""
import math

# Pesos de las métricas base (según la especificación 3.1).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}   # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                           # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}              # Privileges Req. (Scope Unchanged)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}              # Privileges Req. (Scope Changed)
_UI = {"N": 0.85, "R": 0.62}                           # User Interaction
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}               # Impacto C / I / A

METRICAS = {
    "AV": {"label": "Vector de ataque", "opts": [("N", "Red"), ("A", "Adyacente"), ("L", "Local"), ("P", "Físico")]},
    "AC": {"label": "Complejidad", "opts": [("L", "Baja"), ("H", "Alta")]},
    "PR": {"label": "Privilegios", "opts": [("N", "Ninguno"), ("L", "Bajos"), ("H", "Altos")]},
    "UI": {"label": "Interacción usuario", "opts": [("N", "Ninguna"), ("R", "Requerida")]},
    "S": {"label": "Alcance (Scope)", "opts": [("U", "Sin cambio"), ("C", "Cambiado")]},
    "C": {"label": "Confidencialidad", "opts": [("N", "Ninguno"), ("L", "Bajo"), ("H", "Alto")]},
    "I": {"label": "Integridad", "opts": [("N", "Ninguno"), ("L", "Bajo"), ("H", "Alto")]},
    "A": {"label": "Disponibilidad", "opts": [("N", "Ninguno"), ("L", "Bajo"), ("H", "Alto")]},
}


def _roundup(x):
    """Redondeo hacia arriba a 1 decimal, según el algoritmo oficial 3.1."""
    entero = round(x * 100000)
    if entero % 10000 == 0:
        return entero / 100000.0
    return (math.floor(entero / 10000) + 1) / 10.0


def calcular_base_score(av, ac, pr, ui, s, c, i, a):
    """Devuelve el CVSS v3.1 Base Score (0.0–10.0) a partir de las 8 métricas."""
    iss = 1 - ((1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))

    if s == "U":
        impacto = 6.42 * iss
        pr_val = _PR_U[pr]
    else:
        impacto = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        pr_val = _PR_C[pr]

    explotabilidad = 8.22 * _AV[av] * _AC[ac] * pr_val * _UI[ui]

    if impacto <= 0:
        return 0.0
    if s == "U":
        return _roundup(min(impacto + explotabilidad, 10))
    return _roundup(min(1.08 * (impacto + explotabilidad), 10))


def severidad(score):
    """Traduce un Base Score a la escala cualitativa cualitativa oficial."""
    if score == 0:
        return "Ninguna"
    if score < 4.0:
        return "Baja"
    if score < 7.0:
        return "Media"
    if score < 9.0:
        return "Alta"
    return "Crítica"


def vector_string(av, ac, pr, ui, s, c, i, a):
    """Construye el vector CVSS 3.1 canónico."""
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def parse_vector(vector):
    """Extrae las métricas de un vector CVSS 3.1; devuelve dict o None."""
    if not vector:
        return None
    partes = {}
    for token in vector.replace("CVSS:3.1/", "").split("/"):
        if ":" in token:
            k, v = token.split(":", 1)
            partes[k] = v
    requeridas = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    if all(k in partes for k in requeridas):
        return partes
    return None


def score_desde_vector(vector):
    """Base Score a partir de un vector; None si el vector es inválido."""
    p = parse_vector(vector)
    if not p:
        return None
    try:
        return calcular_base_score(p["AV"], p["AC"], p["PR"], p["UI"], p["S"], p["C"], p["I"], p["A"])
    except (KeyError, ValueError):
        return None


def cvss_a_impacto(score):
    """Mapea un CVSS 0–10 a la escala de impacto 1–5 de la metodología GRC-360."""
    if score is None:
        return None
    if score < 2.0:
        return 1
    if score < 4.0:
        return 2
    if score < 7.0:
        return 3
    if score < 9.0:
        return 4
    return 5
