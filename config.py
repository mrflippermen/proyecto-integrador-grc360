"""
Configuración central de CyberRisk 360.
Sistema de Gestión de Riesgos Cibernéticos - ITIZ3301 Proyecto Integrador.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Configuración base de la aplicación."""

    # Clave para firmar sesiones y protección CSRF. En producción se debe
    # cargar desde una variable de entorno y nunca dejarse fija en el código.
    SECRET_KEY = os.environ.get("SECRET_KEY", "cyberrisk-360-clave-dev-cambiar-en-produccion")

    # Base de datos SQLite: portable, sin servidor externo, ideal para la
    # entrega académica. Se puede migrar a PostgreSQL cambiando esta URI.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "cyberrisk360.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Endurecimiento de cookies de sesión (buenas prácticas de seguridad).
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
