from __future__ import annotations

import os

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix


def create_app(config_name: str | None = None) -> Flask:
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__)

    # Determine config class from environment or argument
    if not config_name:
        config_name = os.getenv("APP_ENV", "production")

    if config_name == "testing":
        from config import TestingConfig
        app.config.from_object(TestingConfig)
    else:
        from config import Config
        app.config.from_object(Config)

    # Apply proxy fix if configured to trust upstream proxy headers
    if app.config.get("TRUSTED_PROXY_COUNT", 0) > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=app.config["TRUSTED_PROXY_COUNT"],
            x_proto=app.config["TRUSTED_PROXY_COUNT"],
            x_host=0,
            x_prefix=0,
        )

    # Initialize Flask extensions
    from .extensions import db, migrate, csrf, limiter, talisman
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)
    talisman.init_app(app)

    # Initialize custom server-side session management
    from .security.sessions import init_app as init_session
    init_session(app)

    # Register blueprints based on the application component
    if app.config["SITBANK_COMPONENT"] == "admin":
        from .routes import admin_bp
        app.register_blueprint(admin_bp)
    else:
        from .auth.routes import auth_bp
        from .web.routes import web_bp
        from .banking.routes import banking_bp
        from .main.routes import main_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(web_bp)
        app.register_blueprint(banking_bp)
        app.register_blueprint(main_bp)

    return app
