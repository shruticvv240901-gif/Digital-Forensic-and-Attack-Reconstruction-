"""
Flask Application Factory.
Initializes the web application, registers blueprints, and sets up configurations.
"""

from flask import Flask, render_template
from config import Config
import logging


def create_app(config_class=Config) -> Flask:
    """Creates and configures an instance of the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configure logging format
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    )

    # Register application blueprints
    from app.routes.main import main_bp
    from app.routes.api import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    # Custom Error Handlers
    @app.errorhandler(404)
    def page_not_found(error):
        return render_template("404.html", error=error), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template(
            "404.html",
            error="Internal Server Error: Something unexpected occurred.",
        ), 500

    return app
