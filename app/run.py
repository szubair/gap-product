# run.py

from app import create_app

# The create_app function is defined in app/__init__.py
app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
