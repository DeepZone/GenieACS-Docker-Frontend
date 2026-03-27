import os
from datetime import datetime, UTC

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:////data/app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

os.makedirs("/data", exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="viewer")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)


class AppConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    acs_api_url = db.Column(db.String(500), nullable=False, default="http://genieacs:7557")
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


@app.before_request
def ensure_setup_complete():
    if request.endpoint in {"static"}:
        return None

    user_count = User.query.count()
    setup_allowed_endpoints = {"initial_setup", "login", "logout"}

    if user_count == 0 and request.endpoint not in setup_allowed_endpoints:
        return redirect(url_for("initial_setup"))

    if user_count > 0 and request.endpoint == "initial_setup":
        return redirect(url_for("login"))

    return None


@app.route("/")
def root():
    if User.query.count() == 0:
        return redirect(url_for("initial_setup"))
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/setup", methods=["GET", "POST"])
def initial_setup():
    if User.query.count() > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        acs_api_url = request.form.get("acs_api_url", "").strip()

        if not username or not password or not acs_api_url:
            flash("Bitte alle Felder ausfüllen.", "danger")
            return render_template("setup.html")

        admin = User(username=username, role="admin")
        admin.set_password(password)

        config = AppConfig(acs_api_url=acs_api_url, updated_at=datetime.now(UTC))

        db.session.add(admin)
        db.session.add(config)
        db.session.commit()

        flash("Admin-Benutzer wurde angelegt. Bitte einloggen.", "success")
        return redirect(url_for("login"))

    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Ungültige Zugangsdaten.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Du wurdest ausgeloggt.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    config = AppConfig.query.first()
    return render_template("dashboard.html", config=config)


def admin_required():
    if not current_user.is_authenticated or current_user.role != "admin":
        flash("Keine Berechtigung.", "warning")
        return False
    return True


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if not admin_required():
        return redirect(url_for("dashboard"))

    config = AppConfig.query.first()
    if config is None:
        config = AppConfig(acs_api_url="http://genieacs:7557")
        db.session.add(config)
        db.session.commit()

    if request.method == "POST":
        acs_api_url = request.form.get("acs_api_url", "").strip()
        if not acs_api_url:
            flash("ACS-API-URL darf nicht leer sein.", "danger")
            return render_template("settings.html", config=config)

        config.acs_api_url = acs_api_url
        config.updated_at = datetime.now(UTC)
        db.session.commit()
        flash("Einstellungen gespeichert.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", config=config)


@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    if not admin_required():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")

        if role not in {"admin", "editor", "viewer"}:
            flash("Ungültige Rolle.", "danger")
            return redirect(url_for("users"))

        if not username or not password:
            flash("Benutzername und Passwort sind erforderlich.", "danger")
            return redirect(url_for("users"))

        if User.query.filter_by(username=username).first():
            flash("Benutzername existiert bereits.", "danger")
            return redirect(url_for("users"))

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Benutzer erstellt.", "success")
        return redirect(url_for("users"))

    all_users = User.query.order_by(User.username.asc()).all()
    return render_template("users.html", users=all_users)


@app.post("/users/<int:user_id>/delete")
@login_required
def delete_user(user_id: int):
    if not admin_required():
        return redirect(url_for("dashboard"))

    user = db.session.get(User, user_id)
    if user is None:
        flash("Benutzer nicht gefunden.", "warning")
        return redirect(url_for("users"))

    if user.id == current_user.id:
        flash("Du kannst deinen eigenen Benutzer nicht löschen.", "danger")
        return redirect(url_for("users"))

    db.session.delete(user)
    db.session.commit()
    flash("Benutzer gelöscht.", "info")
    return redirect(url_for("users"))


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
