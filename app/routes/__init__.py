"""
Routes package for web pages and JSON API endpoints.
"""

from app.routes.main import main_bp
from app.routes.api import api_bp

__all__ = ["main_bp", "api_bp"]
