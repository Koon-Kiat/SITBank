from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, url_for
from sqlalchemy import text

from app.extensions import db


main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))
    return render_template("index.html")


@main_bp.get("/health/live")
def health_live():
    return jsonify({"status": "ok"})


@main_bp.get("/health/ready")
def health_ready():
    try:
        db.session.execute(text("SELECT 1"))
        current_app.extensions["redis"].ping()
    except Exception:
        db.session.rollback()
        return jsonify({"status": "unavailable"}), 503
    return jsonify({"status": "ready"})
