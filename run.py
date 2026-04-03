"""
Cyber Guard AI v3.0 - Application Entry Point
==============================================
Clean Architecture Implementation
"""

import os
from app import create_app

# Define models directory path (relative to this file)
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')

# Create application instance using factory pattern
app = create_app('development')  # Options: 'development', 'production', 'testing'
app.config['MODELS_FOLDER'] = MODELS_DIR

if __name__ == '__main__':
    # Development server
    app.run(
        host='0.0.0.0',  # Accessible from network
        port=5000,
        debug=True,       # Enable debugger and auto-reload
        use_reloader=True
    )

# Production deployment:
# gunicorn -w 4 -b 0.0.0.0:5000 run:app
