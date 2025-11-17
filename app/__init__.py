# app/__init__.py

from flask import Flask
from flask_mongoengine import MongoEngine # Use MongoEngine for MongoDB
from .config import Config

# 1. Initialize MongoEngine *outside* the function
mongo = MongoEngine()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # 2. Initialize MongoEngine with the Flask app
    mongo.init_app(app)

    # 3. CRUCIAL FIX: Import and register blueprints *here* # This prevents the circular import of models/db during initialization.
    with app.app_context():
        # Import models so they are registered with MongoEngine/Flask
        from app import models 
        
        # Import and register your routes
        from app.routes import bp as main_bp
        app.register_blueprint(main_bp)

    return app
