from __future__ import annotations

from flask import Blueprint


banking_bp = Blueprint("banking", __name__, url_prefix="/banking")
