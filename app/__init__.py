"""
Application factory de CyberRisk 360.

Crea la aplicación Flask, registra extensiones y blueprints, e inyecta
utilidades comunes en las plantillas.
"""
import os
from flask import Flask, redirect, url_for

from config import Config
from .extensions import db, login_manager
from . import models


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Inicialización de extensiones.
    db.init_app(app)
    login_manager.init_app(app)

    # Registro de blueprints (un módulo por fase de la metodología).
    from .blueprints.auth import auth_bp
    from .blueprints.dashboard import dashboard_bp
    from .blueprints.assets import assets_bp
    from .blueprints.risks import risks_bp
    from .blueprints.treatments import treatments_bp
    from .blueprints.communication import comm_bp
    from .blueprints.reports import reports_bp
    from .blueprints.intel import intel_bp
    from .blueprints.compliance import compliance_bp
    from .blueprints.admin import admin_bp
    from .blueprints.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(risks_bp)
    app.register_blueprint(treatments_bp)
    app.register_blueprint(comm_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(intel_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    # Health check para Render (no requiere autenticación).
    @app.route("/health")
    def health():
        return {"status": "ok", "app": "CyberRisk 360"}

    # Redirigir raíz al login.
    @app.route("/")
    def root():
        return redirect(url_for("auth.login"))

    # Utilidades disponibles en todas las plantillas Jinja.
    from .models import ESCALA_CUALITATIVA, nivel_desde_puntaje

    @app.context_processor
    def inject_helpers():
        return {
            "escala": ESCALA_CUALITATIVA,
            "nivel_desde_puntaje": nivel_desde_puntaje,
        }

    # Crea las tablas si no existen.
    with app.app_context():
        db.create_all()

    return app
