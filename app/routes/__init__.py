"""
Flask Routes
============
Blueprint-based routing for web interface and API endpoints.
"""

from flask import Blueprint

# Main Blueprint (Web Interface)
main_bp = Blueprint('main', __name__)

# API Blueprint (JSON Endpoints)
api_bp = Blueprint('api', __name__)

# Import routes to register them with blueprints
from . import web_routes
from . import api_routes

__all__ = ['main_bp', 'api_bp']
