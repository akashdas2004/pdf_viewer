# PDF Management System

A secure full-stack web application for managing PDF documents with user access controls.

## Features

### 🔒 Security
- User authentication with bcrypt password hashing
- Role-based access control (Admin/User)
- Secure PDF serving with permission checks
- Download prevention for view-only access
- Right-click and keyboard shortcut protection

### 👨‍💼 Admin Features
- User management (add new users)
- PDF upload and management
- Assign PDFs to specific users
- Control download permissions per user/PDF
- Dashboard with overview of users and PDFs

### 👤 User Features
- Personal dashboard with assigned PDFs
- Secure PDF viewer using PDF.js
- Download PDFs (if permitted)
- Responsive design with Tailwind CSS

## Tech Stack

- **Backend**: Flask, Flask-Login, SQLite
- **Frontend**: HTML, Tailwind CSS, PDF.js
- **Security**: bcrypt, secure file serving
- **Deployment**: Docker, Railway/Render ready

## Quick Start

### Local Development

1. **Install Dependencies**
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

2. **Initialize Database**
   \`\`\`bash
   python scripts/init_database.py
   \`\`\`

3. **Run Application**
   \`\`\`bash
   python app.py
   \`\`\`

4. **Access Application**
   - Open http://localhost:5000
   - Login with admin credentials: `admin` / `admin123`

### Docker Deployment

\`\`\`bash
docker build -t pdf-management .
docker run -p 5000:5000 pdf-management
\`\`\`

## Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: User email
- `password_hash`: Bcrypt hashed password
- `is_admin`: Admin flag
- `created_at`: Registration timestamp

### PDFs Table
- `id`: Primary key
- `filename`: Unique filename on server
- `original_filename`: Original upload filename
- `file_path`: Server file path
- `uploaded_by`: Admin who uploaded
- `upload_date`: Upload timestamp

### User PDF Access Table
- `id`: Primary key
- `user_id`: Reference to user
- `pdf_id`: Reference to PDF
- `can_download`: Download permission flag
- `assigned_date`: Assignment timestamp

## Security Features

### Authentication
- Session-based authentication with Flask-Login
- Bcrypt password hashing
- Secure session management

### File Access Control
- Route-based permission checking
- Secure file serving (no direct file access)
- User-specific PDF access

### PDF Viewer Security
- PDF.js integration for in-browser viewing
- Disabled right-click context menu (when download not allowed)
- Disabled keyboard shortcuts (Ctrl+S, Ctrl+P, F12)
- Disabled text selection and drag-and-drop
- No direct file URL exposure

## Deployment

### Railway
1. Connect your GitHub repository
2. Railway will automatically detect the `railway.toml` configuration
3. Environment variables are set automatically

### Render
1. Connect your GitHub repository
2. Use the `render.yaml` configuration
3. Persistent disk storage for uploaded PDFs

### Environment Variables
- `SECRET_KEY`: Flask secret key (auto-generated in production)
- `FLASK_ENV`: Set to "production" for deployment

## Usage

### Admin Workflow
1. Login with admin credentials
2. Add users via the admin dashboard
3. Upload PDF files
4. Assign PDFs to users with appropriate permissions
5. Monitor user access and manage permissions

### User Workflow
1. Login with provided credentials
2. View assigned PDFs on dashboard
3. Click to view PDFs in secure viewer
4. Download PDFs if permission granted

## File Structure

\`\`\`
pdf-management-app/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker configuration
├── railway.toml          # Railway deployment config
├── render.yaml           # Render deployment config
├── database.db           # SQLite database (created on init)
├── scripts/
│   └── init_database.py  # Database initialization
├── templates/
│   ├── base.html         # Base template
│   ├── login.html        # Login page
│   ├── admin_dashboard.html  # Admin interface
│   ├── user_dashboard.html   # User interface
│   └── pdf_viewer.html   # PDF viewer with PDF.js
└── static/
    └── pdfs/             # Uploaded PDF storage
\`\`\`

## Default Credentials

**Admin Account:**
- Username: `admin`
- Password: `admin123`

**Sample User Accounts:**
- Username: `john_doe`, Password: `password123`
- Username: `jane_smith`, Password: `password123`
- Username: `bob_wilson`, Password: `password123`

## Security Considerations

1. **Change Default Passwords**: Update default admin password in production
2. **HTTPS**: Use HTTPS in production for secure authentication
3. **File Validation**: Only PDF files are accepted for upload
4. **File Size Limits**: 16MB maximum file size
5. **Session Security**: Secure session management with Flask-Login

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source and available under the MIT License.
