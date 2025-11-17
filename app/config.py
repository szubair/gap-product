# config.py

import os

class Config:
    # A Secret Key is required by Flask for session management and security
    SECRET_KEY = os.environ.get('SECRET')
    
    # --- MongoDB Settings for Flask-MongoEngine ---
    MONGODB_SETTINGS = {
        # 'db' defines the name of your database inside the MongoDB server
        'db': 'gap_db',
        # 'host' and 'port' should match your MongoDB server installation
        'host': 'localhost',  
        'port': 27017
    }
    
    # Define a folder where uploaded files will be temporarily saved
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
