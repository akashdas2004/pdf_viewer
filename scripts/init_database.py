#!/usr/bin/env python3
"""
Enhanced Database Initialization Script for the PDF Management System.
This script sets up the database with tables and sample data.

Features:
- Robust error handling
- Logging system
- Command-line arguments for customization
- Database backup before modifications
- Transaction management
- Progress indicators
- Data validation
- Option to reset/recreate the database
"""

import sqlite3
import os
import sys
import argparse
import logging
import time
import shutil
import json
from datetime import datetime
from werkzeug.security import generate_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('database_init.log')
    ]
)
logger = logging.getLogger('db_init')

# Default configuration
DEFAULT_CONFIG = {
    'database_path': 'database.db',
    'backup_dir': 'backups',
    'admin_username': 'admin',
    'admin_email': 'admin@example.com',
    'admin_password': 'admin123',
    'create_sample_users': True,
    'create_sample_folders': True,
    'upload_dir': 'static/pdfs'
}

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Initialize the PDF Management System database.')
    parser.add_argument('--config', help='Path to configuration JSON file')
    parser.add_argument('--database', help='Path to database file')
    parser.add_argument('--reset', action='store_true', help='Reset the database (delete existing)')
    parser.add_argument('--no-sample-data', action='store_true', help='Do not create sample users and folders')
    parser.add_argument('--admin-username', help='Admin username')
    parser.add_argument('--admin-email', help='Admin email')
    parser.add_argument('--admin-password', help='Admin password')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    return parser.parse_args()

def load_config(args):
    """Load configuration from file and/or command line arguments."""
    config = DEFAULT_CONFIG.copy()
    
    # Load from config file if provided
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
    
    # Override with command line arguments
    if args.database:
        config['database_path'] = args.database
    if args.admin_username:
        config['admin_username'] = args.admin_username
    if args.admin_email:
        config['admin_email'] = args.admin_email
    if args.admin_password:
        config['admin_password'] = args.admin_password
    if args.no_sample_data:
        config['create_sample_users'] = False
        config['create_sample_folders'] = False
    
    return config

def backup_database(db_path, backup_dir):
    """Create a backup of the database if it exists."""
    if not os.path.exists(db_path):
        logger.info("No existing database to backup.")
        return
    
    # Create backup directory if it doesn't exist
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        logger.info(f"Created backup directory: {backup_dir}")
    
    # Create backup with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(backup_dir, f"database_{timestamp}.db")
    
    try:
        shutil.copy2(db_path, backup_path)
        logger.info(f"Database backed up to {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return None

def get_db_connection(db_path):
    """Create a database connection with proper settings."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def create_tables(conn):
    """Create all required database tables."""
    logger.info("Creating database tables...")
    
    try:
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
        logger.info("✓ Users table created")
        
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
        logger.info("✓ Folders table created")
        
        # PDFs table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                folder_id INTEGER,
                uploaded_by INTEGER,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_size INTEGER,
                FOREIGN KEY (uploaded_by) REFERENCES users (id),
                FOREIGN KEY (folder_id) REFERENCES folders (id)
            )
        ''')
        logger.info("✓ PDFs table created")
        
        # User PDF access table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_pdf_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                pdf_id INTEGER,
                can_download BOOLEAN DEFAULT FALSE,
                assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                assigned_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (pdf_id) REFERENCES pdfs (id),
                FOREIGN KEY (assigned_by) REFERENCES users (id),
                UNIQUE(user_id, pdf_id)
            )
        ''')
        logger.info("✓ User PDF access table created")
        
        # User folder access table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_folder_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                folder_id INTEGER,
                can_download BOOLEAN DEFAULT FALSE,
                assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                assigned_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (folder_id) REFERENCES folders (id),
                FOREIGN KEY (assigned_by) REFERENCES users (id),
                UNIQUE(user_id, folder_id)
            )
        ''')
        logger.info("✓ User folder access table created")
        
        # Access logs table (new)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                resource_type TEXT NOT NULL,
                resource_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        logger.info("✓ Access logs table created")
        
        return True
    except sqlite3.Error as e:
        logger.error(f"Error creating tables: {e}")
        return False

def create_admin_user(conn, username, email, password):
    """Create the admin user if it doesn't exist."""
    logger.info(f"Setting up admin user: {username}")
    
    try:
        # Check if admin already exists
        admin_exists = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        
        if not admin_exists:
            password_hash = generate_password_hash(password)
            conn.execute(
                'INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, True)
            )
            logger.info(f"✓ Admin user '{username}' created successfully")
        else:
            logger.info(f"✓ Admin user '{username}' already exists")
        
        return True
    except sqlite3.Error as e:
        logger.error(f"Error creating admin user: {e}")
        return False

def create_sample_users(conn):
    """Create sample regular users."""
    logger.info("Creating sample users...")
    
    sample_users = [
        ('john_doe', 'john@example.com', 'password123'),
        ('jane_smith', 'jane@example.com', 'password123'),
        ('bob_wilson', 'bob@example.com', 'password123'),
    ]
    
    created_count = 0
    for username, email, password in sample_users:
        try:
            # Check if user already exists
            user_exists = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            
            if not user_exists:
                password_hash = generate_password_hash(password)
                conn.execute(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                    (username, email, password_hash)
                )
                created_count += 1
                logger.info(f"✓ Sample user '{username}' created")
            else:
                logger.info(f"✓ Sample user '{username}' already exists")
                
        except sqlite3.Error as e:
            logger.error(f"Error creating sample user {username}: {e}")
    
    logger.info(f"Created {created_count} new sample users")
    return created_count > 0

def create_sample_folders(conn, admin_id):
    """Create sample folders."""
    logger.info("Creating sample folders...")
    
    default_folders = [
        ('General', 'Default folder for uncategorized PDFs'),
        ('Documents', 'Important documents and forms'),
        ('Reports', 'Monthly and annual reports'),
        ('Training', 'Training materials and guides'),
    ]
    
    created_count = 0
    for folder_name, folder_description in default_folders:
        try:
            # Check if folder already exists
            folder_exists = conn.execute('SELECT id FROM folders WHERE name = ?', (folder_name,)).fetchone()
            
            if not folder_exists:
                conn.execute(
                    'INSERT INTO folders (name, description, created_by) VALUES (?, ?, ?)',
                    (folder_name, folder_description, admin_id)
                )
                created_count += 1
                logger.info(f"✓ Sample folder '{folder_name}' created")
            else:
                logger.info(f"✓ Sample folder '{folder_name}' already exists")
                
        except sqlite3.Error as e:
            logger.error(f"Error creating folder {folder_name}: {e}")
    
    logger.info(f"Created {created_count} new folders")
    return created_count > 0

def ensure_upload_directory(upload_dir):
    """Ensure the upload directory exists."""
    if not os.path.exists(upload_dir):
        try:
            os.makedirs(upload_dir)
            logger.info(f"✓ Created upload directory: {upload_dir}")
        except Exception as e:
            logger.error(f"Error creating upload directory: {e}")
            return False
    else:
        logger.info(f"✓ Upload directory already exists: {upload_dir}")
    
    return True

def init_database(config, reset=False):
    """Initialize the database with required tables and sample data."""
    db_path = config['database_path']
    
    # Handle reset option
    if reset and os.path.exists(db_path):
        backup_path = backup_database(db_path, config['backup_dir'])
        if backup_path:
            try:
                os.remove(db_path)
                logger.info(f"Existing database deleted (backup created at {backup_path})")
            except Exception as e:
                logger.error(f"Failed to delete existing database: {e}")
                return False
    
    # Create a backup if database exists and we're not resetting
    elif os.path.exists(db_path):
        backup_database(db_path, config['backup_dir'])
    
    # Connect to database
    try:
        conn = get_db_connection(db_path)
    except sqlite3.Error as e:
        logger.error(f"Failed to connect to database: {e}")
        return False
    
    # Use a transaction for all operations
    try:
        conn.execute("BEGIN TRANSACTION")
        
        # Create tables
        if not create_tables(conn):
            conn.execute("ROLLBACK")
            conn.close()
            return False
        
        # Create admin user
        if not create_admin_user(conn, config['admin_username'], config['admin_email'], config['admin_password']):
            conn.execute("ROLLBACK")
            conn.close()
            return False
        
        # Get admin ID for folder creation
        admin_id = conn.execute('SELECT id FROM users WHERE username = ?', (config['admin_username'],)).fetchone()['id']
        
        # Create sample users if requested
        if config['create_sample_users']:
            create_sample_users(conn)
        
        # Create sample folders if requested
        if config['create_sample_folders']:
            create_sample_folders(conn, admin_id)
        
        # Ensure upload directory exists
        if not ensure_upload_directory(config['upload_dir']):
            conn.execute("ROLLBACK")
            conn.close()
            return False
        
        # Commit all changes
        conn.execute("COMMIT")
        logger.info("Database initialization completed successfully!")
        
        # Display summary
        display_summary(conn)
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        conn.execute("ROLLBACK")
        logger.error(f"Database initialization failed: {e}")
        conn.close()
        return False

def display_summary(conn):
    """Display a summary of the database contents."""
    try:
        user_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        admin_count = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_admin = TRUE').fetchone()['count']
        folder_count = conn.execute('SELECT COUNT(*) as count FROM folders').fetchone()['count']
        
        logger.info("\n=== Database Summary ===")
        logger.info(f"Total Users: {user_count} ({admin_count} admins, {user_count - admin_count} regular users)")
        logger.info(f"Total Folders: {folder_count}")
        
        # Display users
        logger.info("\nUsers:")
        users = conn.execute('SELECT username, email, is_admin FROM users').fetchall()
        for user in users:
            role = "Admin" if user['is_admin'] else "User"
            logger.info(f"  - {user['username']} ({user['email']}) - {role}")
        
        # Display folders
        logger.info("\nFolders:")
        folders = conn.execute('''
            SELECT f.name, f.description, u.username as created_by
            FROM folders f
            LEFT JOIN users u ON f.created_by = u.id
        ''').fetchall()
        
        for folder in folders:
            logger.info(f"  - {folder['name']}: {folder['description']} (Created by: {folder['created_by']})")
        
    except sqlite3.Error as e:
        logger.error(f"Error displaying summary: {e}")

def main():
    """Main entry point for the script."""
    start_time = time.time()
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load configuration
    config = load_config(args)
    
    # Display banner
    logger.info("=" * 60)
    logger.info("PDF Management System - Database Initialization")
    logger.info("=" * 60)
    
    # Initialize database
    success = init_database(config, args.reset)
    
    # Display completion message
    elapsed_time = time.time() - start_time
    if success:
        logger.info("\n" + "=" * 60)
        logger.info(f"Database initialization completed in {elapsed_time:.2f} seconds")
        logger.info("\nLogin credentials:")
        logger.info(f"  Admin: username='{config['admin_username']}', password='{config['admin_password']}'")
        if config['create_sample_users']:
            logger.info("  Users: username='john_doe', password='password123' (and similar for other users)")
        logger.info("=" * 60)
    else:
        logger.error("\n" + "=" * 60)
        logger.error(f"Database initialization failed after {elapsed_time:.2f} seconds")
        logger.error("=" * 60)
        sys.exit(1)

if __name__ == "__main__":
    main()
