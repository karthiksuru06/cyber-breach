"""
Cyber Guard AI v3.0 - Application Factory
==========================================
Flask application factory using clean architecture principles.
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Initialize extensions
db = SQLAlchemy()


def create_app(config_name='development'):
    """
    Application Factory Pattern

    Args:
        config_name: Configuration profile (development, production, testing)

    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    # Load configuration
    app.config.from_object(f'app.config.{config_name.capitalize()}Config')

    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize extensions with app
    db.init_app(app)

    # Initialize LoginManager
    from flask_login import LoginManager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    
    from app.models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from app.routes import main_bp, api_bp
    from app.auth import auth_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Initialize AI engines
    from app.ai_engine import init_models
    with app.app_context():
        init_models(app)

    # Load local threat intelligence CSV (optional - graceful degradation if missing)
    from app.utils.threat_intel import load_threat_csv
    csv_path = os.path.join(app.root_path, '..', 'data', 'malicious_dataset.csv')
    try:
        threat_count = load_threat_csv(csv_path)
        if threat_count > 0:
            app.logger.info(f"Loaded {threat_count} threat signatures")
        else:
            app.logger.warning("No threat intelligence dataset loaded - using neural models only")
    except Exception as e:
        app.logger.warning(f"Could not load threat intelligence: {e}. Neural models will handle detection.")

    # Create database tables
    with app.app_context():
        db.create_all()

    return app
