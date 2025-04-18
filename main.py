import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from cryptography.fernet import Fernet
import os
import time
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define access levels
ACCESS_LEVELS = {
    "Omega": 4,
    "Alpha Prime": 3,
    "Alpha": 2,
    "Beta": 1,
    "Gamma": 0
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect("secure_files.db")
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database tables
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS encryption_keys
        (clearance_level TEXT PRIMARY KEY, key TEXT)''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
        (name TEXT PRIMARY KEY, password TEXT, clearance_level TEXT)''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS files
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        title TEXT,
        encrypted_data BLOB,
        clearance_level TEXT
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        content TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        clearance_level TEXT
    )''')
    
    conn.commit()
    conn.close()

def init_keys():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM encryption_keys")
    existing_keys = {row[0]: row[1] for row in cursor.fetchall()}

    KEYS = {}
    for level in ACCESS_LEVELS:
        if level not in existing_keys:
            key = Fernet.generate_key()
            cursor.execute("INSERT INTO encryption_keys VALUES (?, ?)", 
                         (level, key.decode()))
            KEYS[level] = key
        else:
            KEYS[level] = existing_keys[level].encode()

    conn.commit()
    conn.close()
    return {level: Fernet(KEYS[level]) for level in KEYS}

init_db()
CIPHERS = init_keys()

# Initialize admin user
def init_admin():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO users (name, password, clearance_level) VALUES (?, ?, ?)",
        ("Admin", "admin123", "Alpha Prime"))
    cursor.execute(
        "INSERT OR IGNORE INTO users (name, password, clearance_level) VALUES (?, ?, ?)",
        ("Djaylano", "9137", "Alpha Prime"))
    conn.commit()
    conn.close()

init_admin()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name'].strip()
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT clearance_level, password FROM users WHERE name = ?", (name,))
        user = cursor.fetchone()
        conn.close()

        if not user or user['password'] != password:
            flash('Invalid username or password.', 'danger')
        else:
            session['name'] = name
            session['clearance'] = user['clearance_level']
            flash(f'Welcome, {name}!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'name' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, title, clearance_level FROM files")
    all_files = cursor.fetchall()
    conn.close()

    files = [file for file in all_files 
             if (ACCESS_LEVELS[session['clearance']] >= ACCESS_LEVELS[file['clearance_level']] 
             and not file['filename'].startswith('text_'))]

    return render_template('dashboard.html', 
                         files=files,
                         ACCESS_LEVELS=ACCESS_LEVELS)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'name' not in session:
        return redirect(url_for('login'))

    doc_clearance = request.form.get('doc_clearance', 'Gamma')
    text_content = request.form.get('text_content')

    if text_content:
        filename = f"text_{int(time.time())}.txt"
        title = request.form.get('title')
        content = text_content.encode()
        encrypted_content = CIPHERS[doc_clearance].encrypt(content)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (filename, title, encrypted_data, clearance_level) VALUES (?, ?, ?, ?)",
            (filename, title, encrypted_content, doc_clearance))
        conn.commit()
        conn.close()

        flash(f'Text file "{filename}" has been encrypted and stored.', 'success')
        return redirect(url_for('dashboard'))
    else:
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(url_for('dashboard'))

        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(url_for('dashboard'))

        if not allowed_file(file.filename):
            flash('File type not allowed', 'danger')
            return redirect(url_for('dashboard'))

        filename = secure_filename(file.filename)
        title = request.form.get('title')
        content = file.read()

        encrypted_content = CIPHERS[doc_clearance].encrypt(content)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (filename, title, encrypted_data, clearance_level) VALUES (?, ?, ?, ?)",
            (filename, title, encrypted_content, doc_clearance))
        conn.commit()
        conn.close()

        flash(f'File "{filename}" has been encrypted and stored.', 'success')
        return redirect(url_for('dashboard'))

@app.route('/retrieve_file', methods=['POST'])
def retrieve_file():
    if 'name' not in session:
        return redirect(url_for('login'))

    filename = request.form.get('filename')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_data, clearance_level FROM files WHERE filename = ?", (filename,))
    file = cursor.fetchone()
    conn.close()

    if file and ACCESS_LEVELS[session['clearance']] >= ACCESS_LEVELS[file['clearance_level']]:
        try:
            cipher = CIPHERS[file['clearance_level']]
            decrypted_content = cipher.decrypt(bytes(file['encrypted_data']))
            try:
                # Try to decode as text
                content = decrypted_content.decode('utf-8')
                flash(f'File content: {content}', 'success')
            except UnicodeDecodeError:
                # If file is an image, serve it
                if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                    from flask import send_file
                    import io
                    return send_file(
                        io.BytesIO(decrypted_content),
                        mimetype=f'image/{filename.rsplit(".", 1)[1].lower()}'
                    )
                else:
                    # If not text or image, show binary data length
                    flash(f'Binary file retrieved successfully ({len(decrypted_content)} bytes)', 'success')
        except Exception as e:
            flash(f'Error decrypting file: {str(e)}', 'danger')
    else:
        flash('Access denied or file not found', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'name' not in session or session['clearance'] not in ['Alpha Prime', 'Omega']:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        clearance = request.form.get('clearance')

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (name, password, clearance_level) VALUES (?, ?, ?)",
                         (name, password, clearance))
            conn.commit()
            flash('User added successfully', 'success')
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        conn.close()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, clearance_level FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template('manage_users.html', users=users, access_levels=ACCESS_LEVELS.keys())

import requests  # Add at the top if it's not already there

# Set your local AI endpoint via ngrok
AI_API_URL = "https://a118-143-179-251-66.ngrok-free.app"

@app.route('/ask_gaia', methods=['POST'])
def ask_gaia():
    if 'name' not in session:
        return redirect(url_for('login'))
    
    question = request.form.get('question')
    if not question:
        flash('Please provide a question', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Send the question to your local Mistral model via Ollama/ngrok
        payload = {
            "model": "mistral",
            "prompt": question,
            "stream": False
        }

        response = requests.post(f"{AI_API_URL}/api/generate", json=payload)
        result = response.json()
        answer = result.get("response", "[No response received]")

        # Save answer to database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO messages (sender, receiver, content, clearance_level) VALUES (?, ?, ?, ?)",
            ("GAIA", session['name'], answer, "Gamma")
        )
        conn.commit()
        conn.close()

        flash('GAIA has responded to your question', 'success')
        return jsonify({"response": answer})

    except Exception as e:
        flash(f'Error connecting to local AI: {str(e)}', 'danger')
        return jsonify({"error": str(e)}), 500

def send_message():
    if 'name' not in session:
        return redirect(url_for('login'))

    receiver = request.form.get('receiver')
    content = request.form.get('content')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)",
        (session['name'], receiver, content)
    )
    conn.commit()
    conn.close()

    flash('Message sent successfully', 'success')
    return redirect(url_for('messages'))

@app.route('/settings')
def settings():
    if 'name' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/update_settings', methods=['POST'])
def update_settings():
    if 'name' not in session:
        return redirect(url_for('login'))
    
    theme = request.form.get('theme', 'gaia')
    session['theme'] = theme
    flash('Settings updated successfully.', 'success')
    return redirect(url_for('settings'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
