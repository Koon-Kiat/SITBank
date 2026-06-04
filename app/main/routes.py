from __future__ import annotations

from flask import Blueprint, g, redirect, render_template, url_for


main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.dashboard"))
    return render_template("index.html")
