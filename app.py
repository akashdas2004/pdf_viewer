from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'static/pdfs'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

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
        
        # PDFs table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                uploaded_by INTEGER,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploaded_by) REFERENCES users (id)
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
    pdfs = conn.execute('''
        SELECT p.*, u.username as uploaded_by_name 
        FROM pdfs p 
        LEFT JOIN users u ON p.uploaded_by = u.id
    ''').fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', users=users, pdfs=pdfs)

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

@app.route('/admin/upload_pdf', methods=['POST'])
@login_required
def upload_pdf():
    if not current_user.is_admin:
        abort(403)
    
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
            'INSERT INTO pdfs (filename, original_filename, file_path, uploaded_by) VALUES (?, ?, ?, ?)',
            (unique_filename, file.filename, file_path, current_user.id)
        )
        conn.commit()
        conn.close()
        
        flash('PDF uploaded successfully')
    else:
        flash('Please upload a valid PDF file')
    
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

@app.route('/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    user_pdfs = conn.execute('''
        SELECT p.*, upa.can_download, upa.assigned_date
        FROM pdfs p
        JOIN user_pdf_access upa ON p.id = upa.pdf_id
        WHERE upa.user_id = ?
        ORDER BY upa.assigned_date DESC
    ''', (current_user.id,)).fetchall()
    conn.close()
    
    return render_template('user_dashboard.html', pdfs=user_pdfs)

@app.route('/view_pdf/<int:pdf_id>')
@login_required
def view_pdf(pdf_id):
    # Check if user has access to this PDF
    conn = get_db_connection()
    
    try:
        if current_user.is_admin:
            pdf = conn.execute('SELECT * FROM pdfs WHERE id = ?', (pdf_id,)).fetchone()
            can_download = True
        else:
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
            return redirect(url_for('user_dashboard'))
        
        # Check if file exists
        if not os.path.exists(pdf['file_path']):
            flash('PDF file not found on server')
            return redirect(url_for('user_dashboard'))
        
        return render_template('pdf_viewer.html', pdf=pdf, can_download=can_download)
        
    except Exception as e:
        conn.close()
        print(f"Error in view_pdf: {e}")
        flash('Error accessing PDF')
        return redirect(url_for('user_dashboard'))

@app.route('/serve_pdf/<int:pdf_id>')
@login_required
def serve_pdf(pdf_id):
    # Check if user has access to this PDF
    conn = get_db_connection()
    
    try:
        if current_user.is_admin:
            pdf = conn.execute('SELECT * FROM pdfs WHERE id = ?', (pdf_id,)).fetchone()
        else:
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
            pdf = conn.execute('SELECT * FROM pdfs WHERE id = ?', (pdf_id,)).fetchone()
            can_download = True
        else:
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
            return redirect(url_for('user_dashboard'))
        
        # Check if file exists
        if not os.path.exists(pdf['file_path']):
            flash('PDF file not found on server')
            return redirect(url_for('user_dashboard'))
        
        return send_file(pdf['file_path'], as_attachment=True, download_name=pdf['original_filename'])
        
    except Exception as e:
        conn.close()
        print(f"Error in download_pdf: {e}")
        flash('Error downloading PDF')
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

# Debug route to check PDF assignments
@app.route('/debug/assignments')
@login_required
def debug_assignments():
    if not current_user.is_admin:
        abort(403)
    
    conn = get_db_connection()
    assignments = conn.execute('''
        SELECT u.username, p.original_filename, upa.can_download, upa.assigned_date
        FROM user_pdf_access upa
        JOIN users u ON upa.user_id = u.id
        JOIN pdfs p ON upa.pdf_id = p.id
        ORDER BY upa.assigned_date DESC
    ''').fetchall()
    conn.close()
    
    result = "<h2>PDF Assignments Debug</h2><table border='1'><tr><th>User</th><th>PDF</th><th>Can Download</th><th>Assigned Date</th></tr>"
    for assignment in assignments:
        result += f"<tr><td>{assignment['username']}</td><td>{assignment['original_filename']}</td><td>{assignment['can_download']}</td><td>{assignment['assigned_date']}</td></tr>"
    result += "</table>"
    
    return result

# Initialize database on startup (for all environments)
init_db()

if __name__ == '__main__':
    app.run(debug=True)
