from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
import sqlite3
import hashlib
import re
import os
from datetime import datetime, timedelta
from functools import wraps
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('civicvoice.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'civicvoice_secret_key_2026'
CORS(app)

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "civicvoice.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
MAX_FILE_SIZE = 5242880  # 5MB
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp"}
CATEGORIES = ["Roads", "Waste Management", "Water Leakage", "Streetlight", "Other"]
STATUSES = ["Pending", "In Progress", "Resolved"]
PRIORITIES = ["Low", "Normal", "High", "Critical"]
ADMIN_PASSWORD = "Admin@2026!"
SESSION_TIMEOUT = 30
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# Create upload directory
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ============================================
# DATABASE FUNCTIONS
# ============================================
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone TEXT,
        role TEXT NOT NULL CHECK(role IN ('user','admin')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        location TEXT,
        phone TEXT,
        image_path TEXT,
        status TEXT NOT NULL DEFAULT 'Pending'
            CHECK(status IN ('Pending','In Progress','Resolved')),
        priority TEXT DEFAULT 'Normal',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_email) REFERENCES users(email)
    )""")
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success BOOLEAN DEFAULT 0
    )""")
    
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_complaints_email ON complaints(user_email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status)")
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

# ============================================
# SECURITY FUNCTIONS
# ============================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def validate_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Must contain at least 1 uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Must contain at least 1 lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Must contain at least 1 digit"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Must contain at least 1 special character"
    return True, "Password is strong"

def validate_phone(phone):
    cleaned = re.sub(r'[^\d+]', '', phone)
    if re.match(r'^\+?[1-9]\d{9,14}$', cleaned):
        return True, cleaned
    return False, "Invalid phone number"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        conn = get_db()
        user = conn.execute("SELECT role FROM users WHERE email=?", (session['user_email'],)).fetchone()
        conn.close()
        if not user or user['role'] != 'admin':
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# AUTHENTICATION ROUTES
# ============================================
@app.route('/')
def index():
    if 'user_email' in session:
        conn = get_db()
        user = conn.execute("SELECT role FROM users WHERE email=?", (session['user_email'],)).fetchone()
        conn.close()
        if user and user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        phone = data.get('phone', '').strip()
        role = data.get('role', 'user')
        admin_pass = data.get('admin_password', '')
        
        if not name or len(name) < 2:
            return jsonify({"success": False, "message": "Name must be at least 2 characters"}), 400
        
        if not validate_email(email):
            return jsonify({"success": False, "message": "Invalid email format"}), 400
        
        ok, cleaned = validate_phone(phone)
        if not ok:
            return jsonify({"success": False, "message": cleaned}), 400
        
        ok, msg = validate_password(password)
        if not ok:
            return jsonify({"success": False, "message": msg}), 400
        
        if role == "admin":
            if admin_pass != ADMIN_PASSWORD:
                return jsonify({"success": False, "message": "Incorrect admin password!"}), 400
        
        try:
            conn = get_db()
            hashed = hash_password(password)
            conn.execute(
                "INSERT INTO users (name,email,password,phone,role) VALUES (?,?,?,?,?)",
                (name, email, hashed, cleaned, role)
            )
            conn.commit()
            conn.close()
            logger.info(f"User registered: {email} ({role})")
            return jsonify({"success": True, "message": f"{role.upper()} account created successfully!"}), 201
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "message": "Email already exists"}), 400
        except Exception as e:
            return jsonify({"success": False, "message": str(e)}), 500
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not validate_email(email):
            return jsonify({"success": False, "message": "Invalid email format"}), 400
        
        conn = get_db()
        
        # Check account lockout
        threshold = datetime.now() - timedelta(minutes=LOCKOUT_MINUTES)
        fails = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE email=? AND success=0 AND attempt_time>?",
            (email, threshold)
        ).fetchone()[0]
        
        if fails >= MAX_LOGIN_ATTEMPTS:
            conn.close()
            return jsonify({
                "success": False,
                "message": f"Account locked. Try again in {LOCKOUT_MINUTES} minutes."
            }), 429
        
        user = conn.execute(
            "SELECT name,password,role,phone FROM users WHERE email=?",
            (email,)
        ).fetchone()
        
        if user and verify_password(password, user['password']):
            conn.execute("INSERT INTO login_attempts (email,success) VALUES (?,1)", (email,))
            conn.execute("DELETE FROM login_attempts WHERE email=? AND success=0", (email,))
            conn.commit()
            conn.close()
            
            session['user_email'] = email
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            session['user_phone'] = user['phone']
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=SESSION_TIMEOUT)
            
            logger.info(f"User logged in: {email} ({user['role']})")
            return jsonify({
                "success": True,
                "message": "Login successful!",
                "role": user['role']
            }), 200
        else:
            conn.execute("INSERT INTO login_attempts (email,success) VALUES (?,0)", (email,))
            conn.commit()
            conn.close()
            return jsonify({
                "success": False,
                "message": f"Invalid credentials ({fails+1}/{MAX_LOGIN_ATTEMPTS})"
            }), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    logger.info("User logged out")
    return redirect(url_for('login'))

# ============================================
# USER DASHBOARD ROUTES
# ============================================
@app.route('/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/api/complaints', methods=['GET', 'POST'])
@login_required
def manage_complaints():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '')
        location = request.form.get('location', '').strip()
        priority = request.form.get('priority', 'Normal')
        
        if not title or len(title) < 5:
            return jsonify({"success": False, "message": "Title must be at least 5 characters"}), 400
        
        if not description or len(description) < 10:
            return jsonify({"success": False, "message": "Description must be at least 10 characters"}), 400
        
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                if file.content_length > MAX_FILE_SIZE:
                    return jsonify({"success": False, "message": "File exceeds 5MB limit"}), 400
                
                ext = file.filename.rsplit('.', 1)[-1].lower()
                if ext not in ALLOWED_EXTENSIONS:
                    return jsonify({"success": False, "message": f"Only {', '.join(ALLOWED_EXTENSIONS)} files allowed"}), 400
                
                filename = secure_filename(f"complaint_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
                file.save(os.path.join(UPLOAD_DIR, filename))
                image_path = f"uploads/{filename}"
        
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO complaints
                   (user_email,title,description,category,location,phone,status,priority,image_path)
                   VALUES (?,?,?,?,?,?,'Pending',?,?)""",
                (session['user_email'], title, description, category, location, session['user_phone'], priority, image_path)
            )
            conn.commit()
            cid = cur.lastrowid
            conn.close()
            logger.info(f"Complaint #{cid} created by {session['user_email']}")
            return jsonify({
                "success": True,
                "message": f"Complaint #{cid} submitted successfully!",
                "complaint_id": cid
            }), 201
        except Exception as e:
            logger.error(f"Error creating complaint: {e}")
            return jsonify({"success": False, "message": str(e)}), 500
    
    # GET: Retrieve user's complaints
    status_filter = request.args.get('status', 'All')
    category_filter = request.args.get('category', 'All')
    
    conn = get_db()
    q = "SELECT * FROM complaints WHERE user_email=?"
    params = [session['user_email']]
    
    if status_filter and status_filter != "All":
        q += " AND status=?"
        params.append(status_filter)
    if category_filter and category_filter != "All":
        q += " AND category=?"
        params.append(category_filter)
    q += " ORDER BY created_at DESC"
    
    rows = conn.execute(q, params).fetchall()
    conn.close()
    
    complaints = [{
        'id': r['id'],
        'title': r['title'],
        'description': r['description'],
        'category': r['category'],
        'location': r['location'],
        'status': r['status'],
        'priority': r['priority'],
        'image_path': r['image_path'],
        'created_at': r['created_at']
    } for r in rows]
    
    return jsonify(complaints), 200

@app.route('/api/complaints/<int:cid>')
@login_required
def get_complaint(cid):
    conn = get_db()
    r = conn.execute(
        "SELECT * FROM complaints WHERE id=? AND user_email=?",
        (cid, session['user_email'])
    ).fetchone()
    conn.close()
    
    if not r:
        return jsonify({"success": False, "message": "Complaint not found"}), 404
    
    return jsonify({
        'id': r['id'],
        'title': r['title'],
        'description': r['description'],
        'category': r['category'],
        'location': r['location'],
        'status': r['status'],
        'priority': r['priority'],
        'image_path': r['image_path'],
        'created_at': r['created_at']
    }), 200

# ============================================
# ADMIN DASHBOARD ROUTES
# ============================================
@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/api/admin/complaints', methods=['GET'])
@admin_required
def admin_complaints():
    status_filter = request.args.get('status', 'All')
    category_filter = request.args.get('category', 'All')
    search = request.args.get('search', '')
    
    conn = get_db()
    q = "SELECT * FROM complaints WHERE 1=1"
    params = []
    
    if status_filter and status_filter != "All":
        q += " AND status=?"
        params.append(status_filter)
    if category_filter and category_filter != "All":
        q += " AND category=?"
        params.append(category_filter)
    if search:
        q += " AND (title LIKE ? OR description LIKE ? OR user_email LIKE ?)"
        s = f"%{search}%"
        params.extend([s, s, s])
    q += " ORDER BY created_at DESC"
    
    rows = conn.execute(q, params).fetchall()
    conn.close()
    
    complaints = [{
        'id': r['id'],
        'user_email': r['user_email'],
        'title': r['title'],
        'description': r['description'],
        'category': r['category'],
        'location': r['location'],
        'status': r['status'],
        'priority': r['priority'],
        'image_path': r['image_path'],
        'created_at': r['created_at']
    } for r in rows]
    
    return jsonify(complaints), 200

@app.route('/api/admin/complaints/<int:cid>/status', methods=['PUT'])
@admin_required
def update_complaint_status(cid):
    data = request.get_json()
    status = data.get('status', '')
    
    if status not in STATUSES:
        return jsonify({"success": False, "message": "Invalid status"}), 400
    
    conn = get_db()
    conn.execute("UPDATE complaints SET status=? WHERE id=?", (status, cid))
    conn.commit()
    conn.close()
    logger.info(f"Complaint #{cid} status updated to {status}")
    return jsonify({"success": True, "message": "Status updated successfully!"}), 200

@app.route('/api/admin/stats')
@admin_required
def get_stats():
    conn = get_db()
    status = dict(conn.execute(
        "SELECT status, COUNT(*) as count FROM complaints GROUP BY status"
    ).fetchall())
    category = dict(conn.execute(
        "SELECT category, COUNT(*) as count FROM complaints GROUP BY category"
    ).fetchall())
    priority = dict(conn.execute(
        "SELECT priority, COUNT(*) as count FROM complaints GROUP BY priority"
    ).fetchall())
    total = conn.execute("SELECT COUNT(*) FROM complaints").fetchone()[0]
    conn.close()
    
    return jsonify({
        'status': status,
        'category': category,
        'priority': priority,
        'total': total
    }), 200

@app.route('/api/admin/users')
@admin_required
def get_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT id,name,email,phone,role,created_at FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    
    users = [{
        'id': r['id'],
        'name': r['name'],
        'email': r['email'],
        'phone': r['phone'],
        'role': r['role'],
        'created_at': r['created_at']
    } for r in rows]
    
    return jsonify(users), 200

@app.route('/api/admin/users/<email>', methods=['DELETE'])
@admin_required
def delete_user(email):
    if email == session['user_email']:
        return jsonify({"success": False, "message": "Cannot delete yourself!"}), 400
    
    conn = get_db()
    conn.execute("DELETE FROM users WHERE email=?", (email,))
    conn.commit()
    conn.close()
    logger.info(f"User {email} deleted by {session['user_email']}")
    return jsonify({"success": True, "message": "User deleted!"}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)