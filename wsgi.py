import os
import sys

from app import create_app
from app.security.production_guard import enforce_production_startup_guard


def _is_flask_cli_process() -> bool:
    """Keep migrations and one-off Flask commands outside the WSGI-only guard."""

    executable = os.path.normcase(os.path.abspath(sys.argv[0]))
    executable_name = os.path.basename(executable)
    normalized_executable = executable.replace("\\", "/")
    return executable_name in {"flask", "flask.exe"} or "/flask/" in normalized_executable


def create_runtime_wsgi_app():
    app = create_app(app_mode="customer")
    if not _is_flask_cli_process():
        enforce_production_startup_guard(app, app_mode="customer")
    return app


app = create_runtime_wsgi_app()
