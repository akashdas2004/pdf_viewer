from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
import uuid
import zipfile
import shutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'static/pdfs'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size for batch uploads

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['email'], user['is_admin'])
    return None

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables"""
    try:
        conn = get_db_connection()
        
        # Users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Folders table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')
        
        # PDFs table (updated with folder_id)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                folder_id INTEGER,
                uploaded_by INTEGER,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploaded_by) REFERENCES users (id),
                FOREIGN KEY (folder_id) REFERENCES folders (id)
            )
        ''')
        
        # User PDF access table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_pdf_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                pdf_id INTEGER,
                can_download BOOLEAN DEFAULT FALSE,
                assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (pdf_id) REFERENCES pdfs (id),
                UNIQUE(user_id, pdf_id)
            )
        ''')
        
        # User folder access table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_folder_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                folder_id INTEGER,
                can_download BOOLEAN DEFAULT FALSE,
                assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (folder_id) REFERENCES folders (id),
                UNIQUE(user_id, folder_id)
            )
        ''')
        
        # Create default admin user if it doesn't exist
        admin_exists = conn.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin_exists:
            admin_password = generate_password_hash('admin123')
            conn.execute(
                'INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
                ('admin', 'admin@example.com', admin_password, True)
            )
            print("Created default admin user: admin/admin123")
        
        # Create sample users if they don't exist
        sample_users = [
            ('john_doe', 'john@example.com', 'password123'),
            ('jane_smith', 'jane@example.com', 'password123'),
            ('bob_wilson', 'bob@example.com', 'password123'),
        ]
        
        for username, email, password in sample_users:
            user_exists = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if not user_exists:
                password_hash = generate_password_hash(password)
                conn.execute(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                    (username, email, password_hash)
                )
                print(f"Created sample user: {username}/password123")
        
        # Create default folder if it doesn't exist
        default_folder = conn.execute('SELECT id FROM folders WHERE name = ?', ('General',)).fetchone()
        if not default_folder:
            admin_id = conn.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
            if admin_id:
                conn.execute(
                    'INSERT INTO folders (name, description, created_by) VALUES (?, ?, ?)',
                    ('General', 'Default folder for uncategorized PDFs', admin_id['id'])
                )
                print("Created default 'General' folder")
        
        conn.commit()
        conn.close()
        print("Database initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        # Try to create database file if it doesn't exist
        try:
            open('database.db', 'a').close()
            print("Created database file, retrying initialization...")
            init_db()  # Retry once
        except Exception as retry_error:
            print(f"Failed to create database: {retry_error}")

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['email'], user['is_admin'])
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users WHERE is_admin = FALSE').fetchall()
    
    # Get folders with PDF counts
    folders = conn.execute('''
        SELECT f.*, u.username as created_by_name,
               COUNT(p.id) as pdf_count
        FROM folders f 
        LEFT JOIN users u ON f.created_by = u.id
        LEFT JOIN pdfs p ON f.id = p.folder_id
        GROUP BY f.id
        ORDER BY f.created_at DESC
    ''').fetchall()
    
    # Get PDFs with folder information
    pdfs = conn.execute('''
        SELECT p.*, u.username as uploaded_by_name, f.name as folder_name
        FROM pdfs p 
        LEFT JOIN users u ON p.uploaded_by = u.id
        LEFT JOIN folders f ON p.folder_id = f.id
        ORDER BY p.upload_date DESC
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', users=users, pdfs=pdfs, folders=folders)

@app.route('/admin/access-management')
@login_required
def access_management():
    if not current_user.is_admin:
        abort(403)
    
    conn = get_db_connection()
    
    # Get all users (except admins)
    users = conn.execute('SELECT * FROM users WHERE is_admin = FALSE').fetchall()
    
    # Get all folders
    folders = conn.execute('SELECT * FROM folders').fetchall()
    
    # Get folder access data
    folder_access = conn.execute('''
        SELECT ufa.*, u.username, f.name as folder_name
        FROM user_folder_access ufa
        JOIN users u ON ufa.user_id = u.id
        JOIN folders f ON ufa.folder_id = f.id
        ORDER BY u.username, f.name
    ''').fetchall()
    
    # Get PDF access data
    pdf_access = conn.execute('''
        SELECT upa.*, u.username, p.original_filename, f.name as folder_name
        FROM user_pdf_access upa
        JOIN users u ON upa.user_id = u.id
        JOIN pdfs p ON upa.pdf_id = p.id
        LEFT JOIN folders f ON p.folder_id = f.id
        ORDER BY u.username, f.name, p.original_filename
    ''').fetchall()
    
    # Get user access summary
    user_access_summary = {}
    for user in users:
        # Count folders and PDFs the user has access to
        folder_count = conn.execute('''
            SELECT COUNT(*) as count FROM user_folder_access
            WHERE user_id = ?
        ''', (user['id'],)).fetchone()['count']
        
        pdf_count = conn.execute('''
            SELECT COUNT(*) as count FROM user_pdf_access
            WHERE user_id = ?
        ''', (user['id'],)).fetchone()['count']
        
        user_access_summary[user['id']] = {
            'folder_count': folder_count,
            'pdf_count': pdf_count
        }
    
    conn.close()
    
    return render_template('access_management.html', 
                          users=users, 
                          folders=folders, 
                          folder_access=folder_access, 
                          pdf_access=pdf_access,
                          user_access_summary=user_access_summary)

@app.route('/admin/user-access/<int:user_id>')
@login_required
def user_access_detail(user_id):
    if not current_user.is_admin:
        abort(403)
    
    conn = get_db_connection()
    
    # Get user info
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        flash('User not found')
        return redirect(url_for('access_management'))
    
    # Get folder access for this user
    folder_access = conn.execute('''
        SELECT ufa.*, f.name as folder_name, f.description
        FROM user_folder_access ufa
        JOIN folders f ON ufa.folder_id = f.id
        WHERE ufa.user_id = ?
        ORDER BY f.name
    ''', (user_id,)).fetchall()
    
    # Get PDF access for this user
    pdf_access = conn.execute('''
        SELECT upa.*, p.original_filename, f.name as folder_name
        FROM user_pdf_access upa
        JOIN pdfs p ON upa.pdf_id = p.id
        LEFT JOIN folders f ON p.folder_id = f.id
        WHERE upa.user_id = ?
        ORDER BY f.name, p.original_filename
    ''', (user_id,)).fetchall()
    
    # Get folders user doesn't have access to
    available_folders = conn.execute('''
        SELECT f.* FROM folders f
        WHERE f.id NOT IN (
            SELECT folder_id FROM user_folder_access
            WHERE user_id = ?
        )
        ORDER BY f.name
    ''', (user_id,)).fetchall()
    
    # Get PDFs user doesn't have access to
    available_pdfs = conn.execute('''
        SELECT p.*, f.name as folder_name FROM pdfs p
        LEFT JOIN folders f ON p.folder_id = f.id
        WHERE p.id NOT IN (
            SELECT pdf_id FROM user_pdf_access
            WHERE user_id = ?
        )
        ORDER BY f.name, p.original_filename
    ''', (user_id,)).fetchall()
    
    conn.close()
    
    return render_template('user_access_detail.html', 
                          user=user, 
                          folder_access=folder_access, 
                          pdf_access=pdf_access,
                          available_folders=available_folders,
                          available_pdfs=available_pdfs)

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        abort(403)
    
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    
    if not username or not email or not password:
        flash('All fields are required')
        return redirect(url_for('admin_dashboard'))
    
    password_hash = generate_password_hash(password)
    
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()
        flash('User added successfully')
    except sqlite3.IntegrityError:
        flash('Username or email already exists')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_folder', methods=['POST'])
@login_required
def add_folder():
    if not current_user.is_admin:
        abort(403)
    
    name = request.form['folder_name']
    description = request.form.get('folder_description', '')
    
    if not name:
        flash('Folder name is required')
        return redirect(url_for('admin_dashboard'))
    
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO folders (name, description, created_by) VALUES (?, ?, ?)',
            (name, description, current_user.id)
        )
        conn.commit()
        conn.close()
        flash('Folder created successfully')
    except sqlite3.IntegrityError:
        flash('Folder name already exists')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/upload_pdf', methods=['POST'])
@login_required
def upload_pdf():
    if not current_user.is_admin:
        abort(403)
    
    folder_id = request.form.get('folder_id')
    if not folder_id:
        flash('Please select a folder')
        return redirect(url_for('admin_dashboard'))
    
    if 'pdf_file' not in request.files:
        flash('No file selected')
        return redirect(url_for('admin_dashboard'))
    
    file = request.files['pdf_file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('admin_dashboard'))
    
    if file and file.filename.lower().endswith('.pdf'):
        # Generate unique filename
        unique_filename = str(uuid.uuid4()) + '.pdf'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Save to database
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO pdfs (filename, original_filename, file_path, folder_id, uploaded_by) VALUES (?, ?, ?, ?, ?)',
            (unique_filename, file.filename, file_path, folder_id, current_user.id)
        )
        conn.commit()
        conn.close()
        
        flash('PDF uploaded successfully')
    else:
        flash('Please upload a valid PDF file')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/batch_upload', methods=['POST'])
@login_required
def batch_upload():
    if not current_user.is_admin:
        abort(403)
    
    folder_id = request.form.get('batch_folder_id')
    if not folder_id:
        flash('Please select a folder for batch upload')
        return redirect(url_for('admin_dashboard'))
    
    if 'batch_files' not in request.files:
        flash('No files selected')
        return redirect(url_for('admin_dashboard'))
    
    files = request.files.getlist('batch_files')
    if not files or all(f.filename == '' for f in files):
        flash('No files selected')
        return redirect(url_for('admin_dashboard'))
    
    uploaded_count = 0
    failed_files = []
    
    conn = get_db_connection()
    
    for file in files:
        if file and file.filename != '':
            if file.filename.lower().endswith('.pdf'):
                try:
                    # Generate unique filename
                    unique_filename = str(uuid.uuid4()) + '.pdf'
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(file_path)
                    
                    # Save to database
                    conn.execute(
                        'INSERT INTO pdfs (filename, original_filename, file_path, folder_id, uploaded_by) VALUES (?, ?, ?, ?, ?)',
                        (unique_filename, file.filename, file_path, folder_id, current_user.id)
                    )
                    uploaded_count += 1
                except Exception as e:
                    failed_files.append(file.filename)
                    print(f"Error uploading {file.filename}: {e}")
            else:
                failed_files.append(f"{file.filename} (not a PDF)")
    
    conn.commit()
    conn.close()
    
    if uploaded_count > 0:
        flash(f'Successfully uploaded {uploaded_count} PDF(s)')
    
    if failed_files:
        flash(f'Failed to upload: {", ".join(failed_files)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/assign_pdf', methods=['POST'])
@login_required
def assign_pdf():
    if not current_user.is_admin:
        abort(403)
    
    user_id = request.form['user_id']
    pdf_id = request.form['pdf_id']
    can_download = 'can_download' in request.form
    
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT OR REPLACE INTO user_pdf_access (user_id, pdf_id, can_download) VALUES (?, ?, ?)',
            (user_id, pdf_id, can_download)
        )
        conn.commit()
        conn.close()
        flash('PDF assigned successfully')
    except Exception as e:
        flash('Error assigning PDF')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/assign_folder', methods=['POST'])
@login_required
def assign_folder():
    if not current_user.is_admin:
        abort(403)
    
    user_id = request.form['folder_user_id']
    folder_id = request.form['folder_assign_id']
    can_download = 'folder_can_download' in request.form
    
    try:
        conn = get_db_connection()
        
        # Assign folder access
        conn.execute(
            'INSERT OR REPLACE INTO user_folder_access (user_id, folder_id, can_download) VALUES (?, ?, ?)',
            (user_id, folder_id, can_download)
        )
        
        # Also assign all PDFs in the folder
        pdfs_in_folder = conn.execute(
            'SELECT id FROM pdfs WHERE folder_id = ?', (folder_id,)
        ).fetchall()
        
        for pdf in pdfs_in_folder:
            conn.execute(
                'INSERT OR REPLACE INTO user_pdf_access (user_id, pdf_id, can_download) VALUES (?, ?, ?)',
                (user_id, pdf['id'], can_download)
            )
        
        conn.commit()
        conn.close()
        flash('Folder and all its PDFs assigned successfully')
    except Exception as e:
        flash('Error assigning folder')
        print(f"Error in assign_folder: {e}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/revoke_folder_access', methods=['POST'])
@login_required
def revoke_folder_access():
    if not current_user.is_admin:
        abort(403)
    
    user_id = request.form['user_id']
    folder_id = request.form['folder_id']
    
    try:
        conn = get_db_connection()
        
        # Remove folder access
        conn.execute(
            'DELETE FROM user_folder_access WHERE user_id = ? AND folder_id = ?',
            (user_id, folder_id)
        )
        
        # Remove access to all PDFs in the folder
        pdfs_in_folder = conn.execute(
            'SELECT id FROM pdfs WHERE folder_id = ?', (folder_id,)
        ).fetchall()
        
        for pdf in pdfs_in_folder:
            conn.execute(
                'DELETE FROM user_pdf_access WHERE user_id = ? AND pdf_id = ?',
                (user_id, pdf['id'])
            )
        
        conn.commit()
        conn.close()
        flash('Access to folder and its PDFs revoked successfully')
    except Exception as e:
        flash('Error revoking folder access')
        print(f"Error in revoke_folder_access: {e}")
    
    # Redirect back to the user access detail page if coming from there
    if request.referrer and 'user-access' in request.referrer:
        return redirect(request.referrer)
    return redirect(url_for('access_management'))

@app.route('/admin/revoke_pdf_access', methods=['POST'])
@login_required
def revoke_pdf_access():
    if not current_user.is_admin:
        abort(403)
    
    user_id = request.form['user_id']
    pdf_id = request.form['pdf_id']
    
    try:
        conn = get_db_connection()
        conn.execute(
            'DELETE FROM user_pdf_access WHERE user_id = ? AND pdf_id = ?',
            (user_id, pdf_id)
        )
        conn.commit()
        conn.close()
        flash('PDF access revoked successfully')
    except Exception as e:
        flash('Error revoking PDF access')
    
    # Redirect back to the user access detail page if coming from there
    if request.referrer and 'user-access' in request.referrer:
        return redirect(request.referrer)
    return redirect(url_for('access_management'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    conn = get_db_connection()
    
    # Get user's assigned folders
    user_folders = conn.execute('''
        SELECT f.*, ufa.can_download, ufa.assigned_date,
               COUNT(p.id) as pdf_count
        FROM folders f
        JOIN user_folder_access ufa ON f.id = ufa.folder_id
        LEFT JOIN pdfs p ON f.id = p.folder_id
        WHERE ufa.user_id = ?
        GROUP BY f.id
        ORDER BY f.name
    ''', (current_user.id,)).fetchall()
    
    # Get user's assigned PDFs with folder information
    user_pdfs = conn.execute('''
        SELECT p.*, upa.can_download, upa.assigned_date, f.name as folder_name
        FROM pdfs p
        JOIN user_pdf_access upa ON p.id = upa.pdf_id
        LEFT JOIN folders f ON p.folder_id = f.id
        WHERE upa.user_id = ?
        ORDER BY f.name, p.original_filename
    ''', (current_user.id,)).fetchall()
    
    conn.close()
    
    return render_template('user_dashboard.html', pdfs=user_pdfs, folders=user_folders)

@app.route('/folder/<int:folder_id>')
@login_required
def view_folder(folder_id):
    conn = get_db_connection()
    
    # Check if user has access to this folder
    if not current_user.is_admin:
        folder_access = conn.execute('''
            SELECT * FROM user_folder_access 
            WHERE user_id = ? AND folder_id = ?
        ''', (current_user.id, folder_id)).fetchone()
        
        if not folder_access:
            conn.close()
            flash('You do not have access to this folder')
            return redirect(url_for('user_dashboard'))
    
    # Get folder information
    folder = conn.execute('SELECT * FROM folders WHERE id = ?', (folder_id,)).fetchone()
    if not folder:
        conn.close()
        flash('Folder not found')
        return redirect(url_for('user_dashboard'))
    
    # Get PDFs in this folder
    if current_user.is_admin:
        folder_pdfs = conn.execute('''
            SELECT p.*, u.username as uploaded_by_name
            FROM pdfs p
            LEFT JOIN users u ON p.uploaded_by = u.id
            WHERE p.folder_id = ?
            ORDER BY p.original_filename
        ''', (folder_id,)).fetchall()
        can_download = True
    else:
        folder_pdfs = conn.execute('''
            SELECT p.*, upa.can_download, u.username as uploaded_by_name
            FROM pdfs p
            JOIN user_pdf_access upa ON p.id = upa.pdf_id
            LEFT JOIN users u ON p.uploaded_by = u.id
            WHERE p.folder_id = ? AND upa.user_id = ?
            ORDER BY p.original_filename
        ''', (folder_id, current_user.id)).fetchall()
        
        # Get folder download permission
        folder_access = conn.execute('''
            SELECT can_download FROM user_folder_access 
            WHERE user_id = ? AND folder_id = ?
        ''', (current_user.id, folder_id)).fetchone()
        can_download = folder_access['can_download'] if folder_access else False
    
    conn.close()
    
    return render_template('folder_view.html', folder=folder, pdfs=folder_pdfs, can_download=can_download)

@app.route('/view_pdf/<int:pdf_id>')
@login_required
def view_pdf(pdf_id):
    # Check if user has access to this PDF
    conn = get_db_connection()
    
    try:
        if current_user.is_admin:
            # Admin can view any PDF
            pdf = conn.execute('SELECT * FROM pdfs WHERE id = ?', (pdf_id,)).fetchone()
            can_download = True
        else:
            # Regular users need assignment
            access = conn.execute('''
                SELECT p.*, upa.can_download
                FROM pdfs p
                JOIN user_pdf_access upa ON p.id = upa.pdf_id
                WHERE p.id = ? AND upa.user_id = ?
            ''', (pdf_id, current_user.id)).fetchone()
            
            if not access:
                conn.close()
                flash('You do not have access to this PDF')
                return redirect(url_for('user_dashboard'))
            
            pdf = access
            can_download = access['can_download']
        
        conn.close()
        
        if not pdf:
            flash('PDF not found')
            if current_user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        
        # Check if file exists
        if not os.path.exists(pdf['file_path']):
            flash('PDF file not found on server')
            if current_user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        
        return render_template('pdf_viewer.html', pdf=pdf, can_download=can_download)
        
    except Exception as e:
        conn.close()
        print(f"Error in view_pdf: {e}")
        flash('Error accessing PDF')
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

@app.route('/serve_pdf/<int:pdf_id>')
@login_required
def serve_pdf(pdf_id):
    # Check if user has access to this PDF
    conn = get_db_connection()
    
    try:
        if current_user.is_admin:
            # Admin can access any PDF
            pdf = conn.execute('SELECT * FROM pdfs WHERE id = ?', (pdf_id,)).fetchone()
        else:
            # Regular users need assignment
            access = conn.execute('''
                SELECT p.*
                FROM pdfs p
                JOIN user_pdf_access upa ON p.id = upa.pdf_id
                WHERE p.id = ? AND upa.user_id = ?
            ''', (pdf_id, current_user.id)).fetchone()
            
            if not access:
                conn.close()
                abort(403)
            pdf = access
        
        conn.close()
        
        if not pdf:
            abort(404)
        
        # Check if file exists
        if not os.path.exists(pdf['file_path']):
            print(f"File not found: {pdf['file_path']}")
            abort(404)
        
        return send_file(pdf['file_path'], as_attachment=False, mimetype='application/pdf')
        
    except Exception as e:
        conn.close()
        print(f"Error in serve_pdf: {e}")
        abort(500)

@app.route('/download_pdf/<int:pdf_id>')
@login_required
def download_pdf(pdf_id):
    # Check if user has download permission
    conn = get_db_connection()
    
    try:
        if current_user.is_admin:
            # Admin can download any PDF
            pdf = conn.execute('SELECT * FROM pdfs WHERE id = ?', (pdf_id,)).fetchone()
            can_download = True
        else:
            # Regular users need download permission
            access = conn.execute('''
                SELECT p.*, upa.can_download
                FROM pdfs p
                JOIN user_pdf_access upa ON p.id = upa.pdf_id
                WHERE p.id = ? AND upa.user_id = ? AND upa.can_download = TRUE
            ''', (pdf_id, current_user.id)).fetchone()
            
            if not access:
                conn.close()
                flash('You do not have download permission for this PDF')
                return redirect(url_for('user_dashboard'))
            
            pdf = access
            can_download = access['can_download']
        
        conn.close()
        
        if not pdf or not can_download:
            flash('Download not allowed')
            if current_user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        
        # Check if file exists
        if not os.path.exists(pdf['file_path']):
            flash('PDF file not found on server')
            if current_user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        
        return send_file(pdf['file_path'], as_attachment=True, download_name=pdf['original_filename'])
        
    except Exception as e:
        conn.close()
        print(f"Error in download_pdf: {e}")
        flash('Error downloading PDF')
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

@app.route('/download_folder/<int:folder_id>')
@login_required
def download_folder(folder_id):
    conn = get_db_connection()
    
    try:
        # Check if user has access to this folder
        if not current_user.is_admin:
            folder_access = conn.execute('''
                SELECT can_download FROM user_folder_access 
                WHERE user_id = ? AND folder_id = ? AND can_download = TRUE
            ''', (current_user.id, folder_id)).fetchone()
            
            if not folder_access:
                conn.close()
                flash('You do not have download permission for this folder')
                return redirect(url_for('user_dashboard'))
        
        # Get folder information
        folder = conn.execute('SELECT * FROM folders WHERE id = ?', (folder_id,)).fetchone()
        if not folder:
            conn.close()
            flash('Folder not found')
            return redirect(url_for('user_dashboard'))
        
        # Get PDFs in this folder that user has access to
        if current_user.is_admin:
            folder_pdfs = conn.execute('''
                SELECT * FROM pdfs WHERE folder_id = ?
            ''', (folder_id,)).fetchall()
        else:
            folder_pdfs = conn.execute('''
                SELECT p.* FROM pdfs p
                JOIN user_pdf_access upa ON p.id = upa.pdf_id
                WHERE p.folder_id = ? AND upa.user_id = ? AND upa.can_download = TRUE
            ''', (folder_id, current_user.id)).fetchall()
        
        conn.close()
        
        if not folder_pdfs:
            flash('No downloadable PDFs found in this folder')
            return redirect(url_for('user_dashboard'))
        
        # Create a temporary zip file
        import tempfile
        temp_dir = tempfile.mkdtemp()
        zip_filename = f"{folder['name']}_pdfs.zip"
        zip_path = os.path.join(temp_dir, zip_filename)
        
        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            for pdf in folder_pdfs:
                if os.path.exists(pdf['file_path']):
                    zip_file.write(pdf['file_path'], pdf['original_filename'])
        
        return send_file(zip_path, as_attachment=True, download_name=zip_filename)
        
    except Exception as e:
        conn.close()
        print(f"Error in download_folder: {e}")
        flash('Error downloading folder')
        return redirect(url_for('user_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    try:
        conn = get_db_connection()
        
        # Check if user exists and is not an admin
        user = conn.execute('SELECT * FROM users WHERE id = ? AND is_admin = FALSE', (user_id,)).fetchone()
        if not user:
            flash('User not found or cannot delete admin users')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        # Delete user's PDF access records first (foreign key constraint)
        conn.execute('DELETE FROM user_pdf_access WHERE user_id = ?', (user_id,))
        
        # Delete user's folder access records
        conn.execute('DELETE FROM user_folder_access WHERE user_id = ?', (user_id,))
        
        # Delete the user
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        conn.commit()
        conn.close()
        flash(f'User "{user["username"]}" deleted successfully')
    except Exception as e:
        flash('Error deleting user')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_pdf/<int:pdf_id>', methods=['POST'])
@login_required
def delete_pdf(pdf_id):
    if not current_user.is_admin:
        abort(403)
    
    try:
        conn = get_db_connection()
        
        # Get PDF info before deletion
        pdf = conn.execute('SELECT * FROM pdfs WHERE id = ?', (pdf_id,)).fetchone()
        if not pdf:
            flash('PDF not found')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        # Delete user access records first (foreign key constraint)
        conn.execute('DELETE FROM user_pdf_access WHERE pdf_id = ?', (pdf_id,))
        
        # Delete PDF record from database
        conn.execute('DELETE FROM pdfs WHERE id = ?', (pdf_id,))
        
        conn.commit()
        conn.close()
        
        # Delete physical file
        try:
            if os.path.exists(pdf['file_path']):
                os.remove(pdf['file_path'])
        except Exception as file_error:
            print(f"Warning: Could not delete file {pdf['file_path']}: {file_error}")
        
        flash(f'PDF "{pdf["original_filename"]}" deleted successfully')
    except Exception as e:
        flash('Error deleting PDF')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    if not current_user.is_admin:
        abort(403)
    
    try:
        conn = get_db_connection()
        
        # Get folder info before deletion
        folder = conn.execute('SELECT * FROM folders WHERE id = ?', (folder_id,)).fetchone()
        if not folder:
            flash('Folder not found')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        # Get all PDFs in this folder
        pdfs_in_folder = conn.execute('SELECT * FROM pdfs WHERE folder_id = ?', (folder_id,)).fetchall()
        
        # Delete all PDFs in the folder
        for pdf in pdfs_in_folder:
            # Delete user access records
            conn.execute('DELETE FROM user_pdf_access WHERE pdf_id = ?', (pdf['id'],))
            # Delete PDF record
            conn.execute('DELETE FROM pdfs WHERE id = ?', (pdf['id'],))
            # Delete physical file
            try:
                if os.path.exists(pdf['file_path']):
                    os.remove(pdf['file_path'])
            except Exception as file_error:
                print(f"Warning: Could not delete file {pdf['file_path']}: {file_error}")
        
        # Delete folder access records
        conn.execute('DELETE FROM user_folder_access WHERE folder_id = ?', (folder_id,))
        
        # Delete the folder
        conn.execute('DELETE FROM folders WHERE id = ?', (folder_id,))
        
        conn.commit()
        conn.close()
        
        flash(f'Folder "{folder["name"]}" and all its contents deleted successfully')
    except Exception as e:
        flash('Error deleting folder')
        print(f"Error in delete_folder: {e}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_admin', methods=['POST'])
@login_required
def add_admin():
    if not current_user.is_admin:
        abort(403)
    
    username = request.form['admin_username']
    email = request.form['admin_email']
    password = request.form['admin_password']
    
    if not username or not email or not password:
        flash('All fields are required for admin creation')
        return redirect(url_for('admin_dashboard'))
    
    password_hash = generate_password_hash(password)
    
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
            (username, email, password_hash, True)
        )
        conn.commit()
        conn.close()
        flash(f'Admin user "{username}" created successfully')
    except sqlite3.IntegrityError:
        flash('Username or email already exists')
    
    return redirect(url_for('admin_dashboard'))

# Initialize database on startup (for all environments)
init_db()

if __name__ == '__main__':
    app.run(debug=True)
