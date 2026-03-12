import os
import sqlite3
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "civicvoice_secret_key_2024"

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "civicvoice_web.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ADMIN_PASSWORD = "Admin@2026!"

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database Helper
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT, email TEXT UNIQUE, password TEXT, phone TEXT, role TEXT
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS complaints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT, title TEXT, description TEXT, category TEXT,
                location TEXT, phone TEXT, image_path TEXT, status TEXT DEFAULT 'Pending',
                priority TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
        conn.commit()

init_db()

# --- Routes ---

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        role = request.form['role']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        admin_p = request.form.get('admin_password')

        if role == 'admin' and admin_p != ADMIN_PASSWORD:
            flash("Invalid Admin Registration Password!", "danger")
            return redirect(url_for('register'))

        try:
            with get_db() as conn:
                conn.execute("INSERT INTO users (name, email, password, phone, role) VALUES (?,?,?,?,?)",
                             (name, email, password, phone, role))
                conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('index'))
        except:
            flash("Email already exists!", "danger")
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = hashlib.sha256(request.form['password'].encode()).hexdigest()

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password)).fetchone()
        
    if user:
        session['user'] = {'name': user['name'], 'email': user['email'], 'role': user['role']}
        return redirect(url_for('dashboard'))
    
    flash("Invalid credentials!", "danger")
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('index'))
    
    user = session['user']
    with get_db() as conn:
        if user['role'] == 'admin':
            complaints = conn.execute("SELECT * FROM complaints ORDER BY created_at DESC").fetchall()
            # Stats for admin
            stats = conn.execute("SELECT status, count(*) as count FROM complaints GROUP BY status").fetchall()
            return render_template('admin_dashboard.html', complaints=complaints, stats=stats)
        else:
            complaints = conn.execute("SELECT * FROM complaints WHERE user_email=? ORDER BY created_at DESC", 
                                      (user['email'],)).fetchall()
            return render_template('user_dashboard.html', complaints=complaints)

@app.route('/submit_complaint', methods=['POST'])
def submit_complaint():
    if 'user' not in session: return redirect(url_for('index'))
    
    title = request.form['title']
    desc = request.form['description']
    cat = request.form['category']
    loc = request.form['location']
    pri = request.form['priority']
    
    file = request.files.get('image')
    filename = None
    if file and file.filename != '':
        filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    with get_db() as conn:
        conn.execute("""INSERT INTO complaints (user_email, title, description, category, location, image_path, priority) 
                     VALUES (?,?,?,?,?,?,?)""", 
                     (session['user']['email'], title, desc, cat, loc, filename, pri))
        conn.commit()
    
    flash("Complaint submitted successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/update_status/<int:id>', methods=['POST'])
def update_status(id):
    if session['user']['role'] != 'admin': return redirect(url_for('index'))
    new_status = request.form['status']
    with get_db() as conn:
        conn.execute("UPDATE complaints SET status=? WHERE id=?", (new_status, id))
        conn.commit()
    flash(f"Complaint #{id} updated to {new_status}", "info")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)