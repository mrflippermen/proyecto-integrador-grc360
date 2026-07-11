"""Blueprint de autenticación: login, logout y registro de usuarios."""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user

from ..extensions import db
from ..models import User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f"Bienvenido/a, {user.nombre}.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.index"))
        flash("Credenciales incorrectas. Verifique su correo y contraseña.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/registro", methods=["GET", "POST"])
def registro():
    """Registro de nuevos analistas (validación de datos de entrada)."""
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Validaciones de entrada.
        errores = []
        if len(nombre) < 3:
            errores.append("El nombre debe tener al menos 3 caracteres.")
        if "@" not in email or "." not in email:
            errores.append("El correo electrónico no es válido.")
        if len(password) < 6:
            errores.append("La contraseña debe tener al menos 6 caracteres.")
        if User.query.filter_by(email=email).first():
            errores.append("Ya existe una cuenta con ese correo.")

        if errores:
            for e in errores:
                flash(e, "danger")
            return render_template("registro.html", nombre=nombre, email=email)

        user = User(nombre=nombre, email=email, rol="analista")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Cuenta creada. Ya puede iniciar sesión.", "success")
        return redirect(url_for("auth.login"))

    return render_template("registro.html")
