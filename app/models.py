"""
Modelos de datos de CyberRisk 360.

Implementa la metodología propia GRC-360, alineada con ISO/IEC 27005 e
ISO/IEC 27002:2022, en seis fases:

  1. Valoración de activos          -> Asset (C, I, D)
  2. Identificación de riesgos      -> Threat, Vulnerability, Risk
  3. Tratamiento del riesgo         -> Control, Treatment
  4. Cálculo de riesgo residual     -> Treatment.residual_*
  5. Comunicación y consulta        -> Observation
  6. Monitoreo y supervisión        -> estados + panel (dashboard)

Todas las escalas cualitativas se manejan en un rango entero 1..5 para
mantener consistencia en el cálculo Probabilidad x Impacto.
"""
from datetime import datetime, date

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db, login_manager
from . import cvss


# ---------------------------------------------------------------------------
# Escalas y utilidades de la metodología GRC-360
# ---------------------------------------------------------------------------

ESCALA_CUALITATIVA = {
    1: "Muy Bajo",
    2: "Bajo",
    3: "Medio",
    4: "Alto",
    5: "Muy Alto",
}

ESTRATEGIAS_TRATAMIENTO = ["Mitigar", "Transferir", "Aceptar", "Evitar"]

ESTADOS_RIESGO = ["Identificado", "En Tratamiento", "Controlado", "Aceptado", "Cerrado"]

ESTADOS_CONTROL = ["Propuesto", "En Implementación", "Implementado", "Verificado"]


def nivel_desde_puntaje(puntaje):
    """Traduce un puntaje de riesgo 1..25 a un nivel cualitativo y color.

    Rangos definidos por el grupo para la matriz 5x5:
        1-4   -> Bajo       (verde)
        5-9   -> Medio      (amarillo)
        10-14 -> Alto       (naranja)
        15-25 -> Crítico    (rojo)
    """
    if puntaje <= 4:
        return "Bajo", "success", "#2e9e5b"
    if puntaje <= 9:
        return "Medio", "warning", "#e0a800"
    if puntaje <= 14:
        return "Alto", "orange", "#e8590c"
    return "Crítico", "danger", "#c92a2a"


# ---------------------------------------------------------------------------
# Usuarios y autenticación
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # Rol: administrador, analista o auditor (segregación de funciones).
    rol = db.Column(db.String(30), nullable=False, default="analista")
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def es_admin(self):
        return self.rol == "administrador"

    def __repr__(self):
        return f"<User {self.email} ({self.rol})>"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# FASE 1 — Valoración de activos
# ---------------------------------------------------------------------------

class Asset(db.Model):
    """Activo de información valorado según criterios CIA (1..5)."""

    __tablename__ = "activos"

    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(20), unique=True, nullable=False)
    nombre = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text)
    # Categoría del activo: Información, Software, Hardware, Servicio, Personal, Instalación.
    tipo = db.Column(db.String(40), nullable=False, default="Información")
    propietario = db.Column(db.String(120))  # responsable / dueño del activo

    # Valoración CIA en escala 1..5.
    confidencialidad = db.Column(db.Integer, nullable=False, default=3)
    integridad = db.Column(db.Integer, nullable=False, default=3)
    disponibilidad = db.Column(db.Integer, nullable=False, default=3)

    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    riesgos = db.relationship("Risk", backref="activo", cascade="all, delete-orphan")

    @property
    def valor(self):
        """Valor del activo = máximo de las tres dimensiones CIA.

        Se usa el máximo (criterio conservador): un activo es tan crítico
        como su dimensión más sensible.
        """
        return max(self.confidencialidad, self.integridad, self.disponibilidad)

    @property
    def valor_texto(self):
        return ESCALA_CUALITATIVA.get(self.valor, "N/D")

    def __repr__(self):
        return f"<Asset {self.codigo} - {self.nombre}>"


# ---------------------------------------------------------------------------
# FASE 2 — Identificación de riesgos (amenazas, vulnerabilidades, riesgo)
# ---------------------------------------------------------------------------

class Threat(db.Model):
    """Catálogo de amenazas (alineado a ISO/IEC 27005 Anexo)."""

    __tablename__ = "amenazas"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)
    categoria = db.Column(db.String(60))  # p.ej. Malware, Error humano, Físico
    descripcion = db.Column(db.Text)
    # Mapeo a MITRE ATT&CK (marco de tácticas y técnicas de adversarios).
    attack_id = db.Column(db.String(15))     # p.ej. T1486
    attack_tactica = db.Column(db.String(60))  # p.ej. Impact, Initial Access

    def __repr__(self):
        return f"<Threat {self.nombre}>"


class Vulnerability(db.Model):
    """Vulnerabilidad explotable, enriquecible con inteligencia de amenazas.

    Puede vincularse a un CVE real y enriquecerse automáticamente con:
      - CVSS v3.1 (NVD)      -> severidad técnica
      - EPSS (FIRST.org)     -> probabilidad de explotación a 30 días
      - CISA KEV             -> ¿explotada activamente en el mundo real?
    De estos indicadores se deriva un VPR (prioridad) al estilo Tenable.
    """

    __tablename__ = "vulnerabilidades"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)
    categoria = db.Column(db.String(60))
    descripcion = db.Column(db.Text)

    # --- Inteligencia de amenazas ---
    cve_id = db.Column(db.String(20))                 # p.ej. CVE-2021-44228
    cvss_vector = db.Column(db.String(60))            # vector CVSS 3.1
    cvss_score = db.Column(db.Float)                  # 0.0–10.0
    epss_score = db.Column(db.Float)                  # 0.0–1.0 (probabilidad)
    epss_percentile = db.Column(db.Float)             # 0.0–1.0 (percentil)
    kev = db.Column(db.Boolean, default=False)        # en catálogo CISA KEV
    kev_fecha = db.Column(db.String(20))              # fecha de adición a KEV
    intel_fecha = db.Column(db.DateTime)              # último enriquecimiento

    @property
    def cvss_severidad(self):
        return cvss.severidad(self.cvss_score) if self.cvss_score is not None else None

    @property
    def epss_pct(self):
        """EPSS como porcentaje legible (0–100)."""
        return round(self.epss_score * 100, 1) if self.epss_score is not None else None

    @property
    def vpr(self):
        """Vulnerability Priority Rating (0–10), al estilo Tenable.

        Combina la severidad técnica (CVSS) con la amenaza real:
          - Base: CVSS score (0–10).
          - EPSS: la probabilidad de explotación desplaza la prioridad hasta +2.
          - KEV: si está siendo explotada activamente, se eleva a un piso de 9.0.
        Es una aproximación transparente y documentada (Tenable VPR es propietario).
        """
        if self.cvss_score is None:
            return None
        base = self.cvss_score
        epss = self.epss_score or 0
        vpr = base + 2.0 * epss                       # la amenaza activa sube prioridad
        if self.kev:
            vpr = max(vpr, 9.0)                        # explotada => casi máxima prioridad
        return round(min(10.0, vpr), 1)

    @property
    def vpr_nivel(self):
        v = self.vpr
        if v is None:
            return None
        if v < 4.0:
            return "Baja"
        if v < 7.0:
            return "Media"
        if v < 9.0:
            return "Alta"
        return "Crítica"

    def __repr__(self):
        return f"<Vulnerability {self.nombre}>"


class Risk(db.Model):
    """Riesgo = Activo + Amenaza + Vulnerabilidad, valorado por P x I."""

    __tablename__ = "riesgos"

    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(20), unique=True, nullable=False)

    asset_id = db.Column(db.Integer, db.ForeignKey("activos.id"), nullable=False)
    threat_id = db.Column(db.Integer, db.ForeignKey("amenazas.id"), nullable=False)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilidades.id"), nullable=False)

    amenaza = db.relationship("Threat")
    vulnerabilidad = db.relationship("Vulnerability")

    descripcion = db.Column(db.Text)
    controles_existentes = db.Column(db.Text)  # controles ya implementados

    # Valoración del riesgo inherente (antes de nuevos controles).
    probabilidad = db.Column(db.Integer, nullable=False, default=3)  # 1..5
    impacto = db.Column(db.Integer, nullable=False, default=3)       # 1..5

    estado = db.Column(db.String(30), default="Identificado")
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    tratamientos = db.relationship(
        "Treatment", backref="riesgo", cascade="all, delete-orphan"
    )
    observaciones = db.relationship(
        "Observation", backref="riesgo", cascade="all, delete-orphan"
    )

    # ---- Cálculo del riesgo inherente ----
    @property
    def puntaje_inherente(self):
        return self.probabilidad * self.impacto

    @property
    def nivel_inherente(self):
        return nivel_desde_puntaje(self.puntaje_inherente)

    # ---- Cálculo del riesgo residual (Fase 4) ----
    @property
    def eficacia_total(self):
        """Eficacia acumulada de los controles IMPLEMENTADOS (0..0.9).

        Sólo los controles con estado 'Implementado' o 'Verificado' reducen el
        riesgo residual: un control únicamente propuesto o en implementación aún
        no protege al activo. Las eficacias se combinan de forma multiplicativa
        (rendimientos decrecientes) para evitar que el riesgo residual sea cero.
        """
        factor = 1.0
        for t in self.tratamientos:
            if t.estrategia in ("Aceptar", "Evitar"):
                continue
            if t.estado not in ("Implementado", "Verificado"):
                continue
            factor *= (1 - (t.eficacia or 0) / 100.0)
        # Se limita a 0.9 de reducción máxima: nunca hay riesgo cero.
        return min(0.9, 1 - factor)

    @property
    def puntaje_residual(self):
        """Riesgo residual = riesgo inherente x (1 - eficacia de controles).

        Si la estrategia es 'Aceptar' el riesgo residual = inherente.
        Si es 'Evitar' (implementado) el riesgo se reduce al mínimo: el
        activo/proceso se retira.
        """
        evitado = any(
            t.estrategia == "Evitar" and t.estado in ("Implementado", "Verificado")
            for t in self.tratamientos
        )
        if evitado:
            return 1
        residual = round(self.puntaje_inherente * (1 - self.eficacia_total))
        return max(1, residual)

    @property
    def nivel_residual(self):
        return nivel_desde_puntaje(self.puntaje_residual)

    @property
    def reduccion_pct(self):
        if self.puntaje_inherente == 0:
            return 0
        return round(
            (self.puntaje_inherente - self.puntaje_residual)
            / self.puntaje_inherente * 100
        )

    # ---- SLA de remediación (según el nivel de riesgo inherente) ----
    # Ventana de tratamiento recomendada por nivel, práctica común en
    # herramientas de gestión de exposición (p.ej. Tenable, Qualys).
    SLA_DIAS = {"Crítico": 15, "Alto": 30, "Medio": 60, "Bajo": 90}

    @property
    def sla_dias(self):
        return self.SLA_DIAS.get(self.nivel_inherente[0], 90)

    @property
    def dias_transcurridos(self):
        if not self.creado_en:
            return 0
        return (datetime.utcnow() - self.creado_en).days

    @property
    def sla_vencido(self):
        """True si el riesgo no está controlado/aceptado dentro de su SLA."""
        if self.estado in ("Controlado", "Aceptado", "Cerrado"):
            return False
        return self.dias_transcurridos > self.sla_dias

    @property
    def sla_restante(self):
        """Días restantes de SLA (negativo si está vencido)."""
        return self.sla_dias - self.dias_transcurridos

    def __repr__(self):
        return f"<Risk {self.codigo}>"


# ---------------------------------------------------------------------------
# FASE 3 — Tratamiento del riesgo (controles ISO/IEC 27002:2022)
# ---------------------------------------------------------------------------

class Control(db.Model):
    """Catálogo de controles de referencia ISO/IEC 27002:2022."""

    __tablename__ = "controles"

    id = db.Column(db.Integer, primary_key=True)
    codigo_iso = db.Column(db.String(15), nullable=False)  # p.ej. "8.7"
    nombre = db.Column(db.String(200), nullable=False)
    # Tema ISO 27002:2022: Organizacional, Personas, Físico, Tecnológico.
    tema = db.Column(db.String(30))
    # Función NIST CSF 2.0: Govern, Identify, Protect, Detect, Respond, Recover.
    nist_csf = db.Column(db.String(15))

    def __repr__(self):
        return f"<Control {self.codigo_iso} - {self.nombre}>"


class Treatment(db.Model):
    """Decisión de tratamiento aplicada a un riesgo concreto."""

    __tablename__ = "tratamientos"

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey("riesgos.id"), nullable=False)
    control_id = db.Column(db.Integer, db.ForeignKey("controles.id"), nullable=True)
    control = db.relationship("Control")

    estrategia = db.Column(db.String(20), nullable=False, default="Mitigar")
    descripcion = db.Column(db.Text)  # control propuesto / plan de acción
    responsable = db.Column(db.String(120))
    fecha_objetivo = db.Column(db.Date)

    # Eficacia estimada del control (0..90 %) usada para el riesgo residual.
    eficacia = db.Column(db.Integer, default=50)
    estado = db.Column(db.String(30), default="Propuesto")
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Treatment {self.estrategia} riesgo={self.risk_id}>"


# ---------------------------------------------------------------------------
# FASE 5 — Comunicación y consulta
# ---------------------------------------------------------------------------

class Observation(db.Model):
    """Observaciones / recomendaciones para las partes interesadas."""

    __tablename__ = "observaciones"

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey("riesgos.id"), nullable=True)
    autor = db.Column(db.String(120))
    tipo = db.Column(db.String(30), default="Recomendación")  # Observación / Recomendación
    contenido = db.Column(db.Text, nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Observation {self.tipo} riesgo={self.risk_id}>"


# ---------------------------------------------------------------------------
# Configuración organizacional — apetito de riesgo (ISO 31000 / 27005)
# ---------------------------------------------------------------------------

class Setting(db.Model):
    """Parámetros globales. Tabla de una sola fila (id=1)."""

    __tablename__ = "configuracion"

    id = db.Column(db.Integer, primary_key=True)
    organizacion = db.Column(db.String(150), default="FinTech Andina S.A.")
    # Apetito de riesgo: puntaje residual máximo tolerado por la organización.
    # Todo riesgo residual por encima de este umbral requiere escalamiento.
    apetito_riesgo = db.Column(db.Integer, default=9)

    @staticmethod
    def get():
        s = db.session.get(Setting, 1)
        if not s:
            s = Setting(id=1)
            db.session.add(s)
            db.session.commit()
        return s


# ---------------------------------------------------------------------------
# Bitácora de auditoría (ISO/IEC 27002:2022 — 8.15 Registro de eventos)
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    """Registro inmutable de acciones para trazabilidad y rendición de cuentas."""

    __tablename__ = "auditoria"

    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(120))
    accion = db.Column(db.String(20))       # CREAR, EDITAR, ELIMINAR, ENRIQUECER
    entidad = db.Column(db.String(40))      # Activo, Riesgo, Tratamiento, ...
    detalle = db.Column(db.String(255))
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def registrar(usuario, accion, entidad, detalle=""):
        db.session.add(AuditLog(usuario=usuario, accion=accion, entidad=entidad, detalle=detalle[:255]))
        db.session.commit()


# ---------------------------------------------------------------------------
# Instantáneas históricas — tendencia de la postura de riesgo en el tiempo
# ---------------------------------------------------------------------------

class RiskSnapshot(db.Model):
    """Fotografía periódica de la postura de riesgo para graficar la tendencia."""

    __tablename__ = "instantaneas"

    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.Date, nullable=False)
    ces = db.Column(db.Integer)                 # Cyber Exposure Score 0–1000
    riesgo_residual_total = db.Column(db.Integer)
    n_criticos = db.Column(db.Integer)          # riesgos residuales Alto/Crítico
    n_controles = db.Column(db.Integer)         # controles implementados

    @staticmethod
    def capturar(riesgos):
        """Crea una instantánea del estado actual (se puede llamar periódicamente)."""
        implementados = sum(
            1 for r in riesgos for t in r.tratamientos
            if t.estado in ("Implementado", "Verificado")
        )
        snap = RiskSnapshot(
            fecha=date.today(),
            ces=cyber_exposure_score(riesgos),
            riesgo_residual_total=sum(r.puntaje_residual for r in riesgos),
            n_criticos=sum(1 for r in riesgos if r.puntaje_residual >= 10),
            n_controles=implementados,
        )
        db.session.add(snap)
        db.session.commit()
        return snap


# ---------------------------------------------------------------------------
# Métricas agregadas de exposición organizacional (estilo Tenable Lumin)
# ---------------------------------------------------------------------------

def cyber_exposure_score(riesgos):
    """Cyber Exposure Score (CES) 0–1000, ponderado por el valor del activo.

    Agrega el riesgo residual de todos los riesgos, dando más peso a los que
    afectan activos más críticos. 0 = sin exposición · 1000 = exposición máxima.
    Inspirado en el Cyber Exposure Score de Tenable Lumin (escala 0–1000).
    """
    if not riesgos:
        return 0
    num = 0.0
    den = 0.0
    for r in riesgos:
        peso = r.activo.valor if r.activo else 3       # 1–5
        num += r.puntaje_residual * peso               # residual 1–25 × peso
        den += 25 * peso                               # máximo posible
    return round(num / den * 1000) if den else 0


def ces_nivel(score):
    """Nivel cualitativo del Cyber Exposure Score."""
    if score < 200:
        return "Bajo", "success"
    if score < 450:
        return "Medio", "warning"
    if score < 700:
        return "Alto", "orange"
    return "Crítico", "danger"
