from flask import Flask, jsonify, request, render_template, send_from_directory
from sqlite3 import connect, Error
from bcrypt import hashpw, gensalt, checkpw
import jwt
import datetime
import os
import uuid
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.update(
    DEBUG=True,
    JSONIFY_PRETTYPRINT_REGULAR=True,
    JSON_SORT_KEYS=False,
    JSON_AS_ASCII=False
)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
WEBHOOK = os.getenv("DCWEBHOOK")
SECRET_KEY = os.urandom(24)

def get_db_connection():
    try:
        conn = connect('database.db')
        conn.row_factory = lambda cursor, row: {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
        return conn
    except Error as e:
        print(f"Database connection error: {e}")
        return None

def initialize_db():
    conn = get_db_connection()
    if conn:
        with conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS login (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    uploader TEXT NOT NULL,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_size INTEGER,
                    mime_type TEXT
                )
            ''')

            default_users = [
                (os.getenv("DEFAULT_USERNAME"), os.getenv("DEFAULT_PASSWORD")),
                (os.getenv("USER_TWO_NAME"), os.getenv("USER_TWO_PASSWORD"))
            ]
            
            for username, password in default_users:
                if username and password:
                    cur = conn.execute("SELECT * FROM login WHERE username = ?", (username,))
                    if not cur.fetchone():
                        hashed = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')
                        conn.execute(
                            "INSERT INTO login (username, password) VALUES (?, ?)",
                            (username, hashed)
                        )
                        print(f"Default user '{username}' created")
        conn.close()


def token_required(f):
    def wrapper(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify(error="Token missing or invalid"), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data["username"]
        except jwt.ExpiredSignatureError:
            return jsonify(error="Token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid token"), 401

        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def log(message):
    if WEBHOOK:
        import requests
        payload = {"content": message}
        try:
            requests.post(WEBHOOK, json=payload)
        except Exception as e:
            print(f"Failed to send log to webhook: {e}")
    print(message)

@app.route("/", methods=["GET"])
def base():
    return render_template("index.html")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")

@app.route("/upload", methods=["POST"])
@token_required
def upload_file():
    if 'file' not in request.files:
        return jsonify(error="No file part"), 400

    file = request.files['file']
    if file.filename == "":
        return jsonify(error="No selected file"), 400

    original_name = secure_filename(file.filename)
    ext = os.path.splitext(original_name)[1]
    filename = f"{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    file.save(filepath)
    file_size = os.path.getsize(filepath)
    
    conn = get_db_connection()
    if conn:
        with conn:
            conn.execute(
                "INSERT INTO files (filename, original_name, uploader, file_size, mime_type) VALUES (?, ?, ?, ?, ?)",
                (filename, original_name, request.user, file_size, file.content_type)
            )
        conn.close()
    
    log(f"File uploaded: {original_name} by {request.user}")
    return jsonify(message="File uploaded successfully", filename=filename, url=f"/cdn/{filename}")

@app.route("/cdn/<filename>", methods=["GET"])
def serve_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/files", methods=["GET"])
@token_required
def get_files():
    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    with conn:
        cur = conn.execute("SELECT * FROM files ORDER BY uploaded_at DESC")
        files = cur.fetchall()
    conn.close()
    return jsonify(files)

@app.route("/files/<int:file_id>", methods=["DELETE"])
@token_required
def delete_file(file_id):
    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    
    with conn:
        cur = conn.execute("SELECT filename FROM files WHERE id = ?", (file_id,))
        file_record = cur.fetchone()
        
        if not file_record:
            conn.close()
            return jsonify(error="File not found"), 404
        
        filepath = os.path.join(UPLOAD_FOLDER, file_record['filename'])
        if os.path.exists(filepath):
            os.remove(filepath)
        
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.close()
    
    log(f"File deleted: {file_record['filename']} by {request.user}")
    return jsonify(message="File deleted successfully")

@app.route("/login", methods=["POST"])
@token_required
def create_login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify(error="Missing username or password"), 400

    username = data["username"]
    password = data["password"]
    hashed = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    try:
        with conn:
            conn.execute("INSERT INTO login (username, password) VALUES (?, ?)", (username, hashed))
        conn.close()
        log(f"New user created: {username} by {request.user}")
        return jsonify(message="User created successfully", username=username), 201
    except Error as e:
        conn.close()
        return jsonify(error="Database error", details=str(e)), 500

@app.route("/auth", methods=["POST"])
def auth_login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify(error="Missing username or password"), 400

    username = data["username"]
    password = data["password"]

    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    with conn:
        cur = conn.execute("SELECT password FROM login WHERE username = ?", (username,))
        row = cur.fetchone()
    conn.close()

    if not row or not checkpw(password.encode('utf-8'), row["password"].encode('utf-8')):
        return jsonify(error="Invalid username or password"), 401

    token = jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    
    log(f"User logged in: {username}")
    return jsonify(message="Authenticated successfully", token=token)

@app.route("/logins", methods=["GET"])
@token_required
def get_logins():
    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    with conn:
        cur = conn.execute("SELECT id, username, created_at FROM login")
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/login/<string:username>", methods=["DELETE"])
@token_required
def delete_login(username):
    if username == request.user:
        return jsonify(error="Cannot delete your own account"), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify(error="Database connection failed"), 500
    with conn:
        cur = conn.execute("DELETE FROM login WHERE username = ?", (username,))
        deleted = cur.rowcount
    conn.close()
    
    if deleted == 0:
        return jsonify(error="User not found"), 404
    
    log(f"User deleted: {username} by {request.user}")
    return jsonify(message=f"Deleted user '{username}' successfully")

@app.errorhandler(400)
def bad_request(e):
    return jsonify(error="Bad Request", status=400, message=str(e)), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify(error="Unauthorized", status=401, message=str(e)), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify(error="Forbidden", status=403, message=str(e)), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify(error="Not Found", status=404, message=str(e)), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify(error="Method Not Allowed", status=405, message=str(e)), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify(error="Internal Server Error", status=500, message=str(e)), 500

if __name__ == "__main__":
    log(f"Starting server with secret key: ```{SECRET_KEY}```")
    initialize_db()
    app.run()