"""
Extensiones de Flask instanciadas de forma independiente para evitar
importaciones circulares (patrón application factory).
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Debe iniciar sesión para acceder a este módulo."
login_manager.login_message_category = "warning"
