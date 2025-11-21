# app/routes.py

from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
from app.db_processor import upload_asset_list, upload_vulnerability_scan # Import the core logic
from app.db_processor import get_asset_list_for_display, get_unknown_hosts_for_display


bp = Blueprint('main', __name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'xls', 'xlsx'}

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/assets')
def view_assets():
    asset_data = get_asset_list_for_display()

    return render_template('asset_list.html', assets=asset_data)

@bp.route('/unknown-hosts')
def view_unknown_hosts():
    unknown_data = get_unknown_hosts_for_display()

    return render_template('unknown_hosts.html', unknown_assets=unknown_data)

@bp.route('/upload_asset_list', methods=['GET', 'POST'])
def upload_assets():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        
        if file.filename == '' or not allowed_file(file.filename):
            flash('No selected file or unsupported file type (must be CSV or Excel)', 'warning')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            try:
                # --- CORE LOGIC: Process the Asset List ---
                result_message = upload_asset_list(file_path)
                flash(f'Asset Upload Successful: {result_message}', 'success')
                return redirect(url_for('main.index'))
            except Exception as e:
                flash(f'Error processing asset file: {e}', 'danger')
                return redirect(request.url)
            finally:
                # Clean up uploaded file to prevent disk space issues
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except OSError as e:
                        print(f"Warning: Could not delete uploaded file {file_path}: {e}")

    # GET request renders the upload form
    return render_template('upload_form.html', upload_type='Asset List')


@bp.route('/upload_scan_report', methods=['GET', 'POST'])
def upload_scans():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        
        if file.filename == '' or not allowed_file(file.filename):
            flash('No selected file or unsupported file type (must be CSV or Excel)', 'warning')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            try:
                # --- CORE LOGIC: Process the Vulnerability Scan ---
                result_message = upload_vulnerability_scan(file_path)
                flash(f'Scan Upload Successful: {result_message}', 'success')
                return redirect(url_for('main.index'))
            except Exception as e:
                flash(f'Error processing scan file: {e}', 'danger')
                return redirect(request.url)
            finally:
                # Clean up uploaded file to prevent disk space issues
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except OSError as e:
                        print(f"Warning: Could not delete uploaded file {file_path}: {e}")

    return render_template('upload_form.html', upload_type='Vulnerability Scan Report')
