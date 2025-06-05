"""
Database initialization script for the PDF Management System.
Run this script to set up the database with sample data.
"""

import sqlite3
from werkzeug.security import generate_password_hash
import os

def init_database():
    """Initialize the database with tables and sample data"""
    
    # Create database connection
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    print("Creating database tables...")
    
    # Users table
    cursor.execute('''
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
    cursor.execute('''
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
    cursor.execute('''
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
    
    print("Tables created successfully!")
    
    # Create sample users
    print("Creating sample users...")
    
    # Admin user
    admin_password = generate_password_hash('admin123')
    cursor.execute(
        'INSERT OR IGNORE INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
        ('admin', 'admin@example.com', admin_password, True)
    )
    
    # Sample regular users
    users_data = [
        ('john_doe', 'john@example.com', 'password123'),
        ('jane_smith', 'jane@example.com', 'password123'),
        ('bob_wilson', 'bob@example.com', 'password123'),
    ]
    
    for username, email, password in users_data:
        password_hash = generate_password_hash(password)
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
    
    # Commit changes
    conn.commit()
    
    # Display created users
    cursor.execute('SELECT username, email, is_admin FROM users')
    users = cursor.fetchall()
    
    print(f"\nCreated {len(users)} users:")
    for user in users:
        role = "Admin" if user[2] else "User"
        print(f"  - {user[0]} ({user[1]}) - {role}")
    
    # Create upload directory
    upload_dir = 'static/pdfs'
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
        print(f"\nCreated upload directory: {upload_dir}")
    
    conn.close()
    print("\nDatabase initialization completed!")
    print("\nYou can now run the Flask application with: python app.py")
    print("\nLogin credentials:")
    print("  Admin: username='admin', password='admin123'")
    print("  Users: username='john_doe', password='password123' (and similar for other users)")

if __name__ == "__main__":
    init_database()
