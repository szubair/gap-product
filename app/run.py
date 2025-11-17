# run.py

from app import create_app

# The create_app function is defined in app/__init__.py
app = create_app()

if __name__ == '__main__':
    # Flask runs on http://127.0.0.1:5000/ by default
    app.run(debug=True)
