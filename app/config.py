# config.py

import os

class Config:
    # A Secret Key is required by Flask for session management and security
    # 6d95ca25fe14a3615b1287f6201531b8666d3f232d1a86f213239d07e0fab152
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
    
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
