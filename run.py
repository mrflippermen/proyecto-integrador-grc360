"""
Punto de entrada de CyberRisk 360.

Uso:
    python run.py            -> inicia el servidor de desarrollo en :5000
    gunicorn wsgi:app        -> inicia el servidor de producción
"""
import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=debug)
