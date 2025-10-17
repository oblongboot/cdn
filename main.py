from flask import Flask, Response, jsonify, request, render_template, send_from_directory
from sqlite3 import connect, Error
from bcrypt import hashpw, gensalt, checkpw
import jwt
import datetime
import os
import requests
import time
import uuid
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import mimetypes

load_dotenv()

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
site = os.getenv("SITE", "https://cdn.zephyrdevelopment.co.uk")
OG_COLOR = os.getenv("OG_COLOR", "#E27712")
OG_SITE_NAME = os.getenv("OG_SITE_NAME", "CDN")
OG_TITLE = os.getenv("OG_TITLE", ":cat2:")
OG_DESC = os.getenv("OG_DESC")

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
                    mime_type TEXT,
                    one_time_view INTEGER DEFAULT 0
                )
            ''')
            try:
                conn.execute("SELECT one_time_view FROM files LIMIT 1")
            except:
                conn.execute("ALTER TABLE files ADD COLUMN one_time_view INTEGER DEFAULT 0")
                print("Added one_time_view column to files table")

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

def log(message, title="CDN", color=None):
    """
    Send a formatted embed to Discord webhook
    
    Args:
        message: The main message content
        title: Title of the embed (default: "CDN Activity")
        color: Hex color code (default: uses OG_COLOR from env)
    """
    if not WEBHOOK:
        return
    
    hex_color = color or OG_COLOR
    color_int = int(hex_color.lstrip('#'), 16)
    
    embed = {
        "embeds": [{
            "title": title,
            "description": message,
            "color": color_int,
            "footer": {
                "text": OG_SITE_NAME
            },
            "timestamp": datetime.datetime.utcnow().isoformat()
        }]
    }
    
    try:
        requests.post(WEBHOOK, json=embed)
    except Exception as e:
        print(f"Failed to send log to webhook: {e}")


def coolerlog(message, title="CDN", color=None, fields=None, thumbnail=None):
    """
    Send a detailed formatted embed to Discord webhook
    
    Args:
        message: The main message content
        title: Title of the embed
        color: Hex color code (default: uses OG_COLOR var)
        fields: List of dicts with 'name', 'value', and optional 'inline' keys
        thumbnail: URL for thumbnail image
    """
    if not WEBHOOK:
        return
    
    hex_color = color or OG_COLOR
    color_int = int(hex_color.lstrip('#'), 16)
    
    embed_data = {
        "title": title,
        "description": message,
        "color": color_int,
        "footer": {
            "text": OG_SITE_NAME
        },
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    if fields:
        embed_data["fields"] = fields
    
    if thumbnail:
        embed_data["thumbnail"] = {"url": thumbnail}
    
    payload = {"embeds": [embed_data]}
    
    try:
        requests.post(WEBHOOK, json=payload)
    except Exception as e:
        print(f"Failed to send log to webhook: {e}")

def log_file_upload(filename, original_name, uploader, file_size, mime_type, one_time_view=False):
    """
    Log file upload with image preview for image files
    """
    time.sleep(3)
    if not WEBHOOK:
        return
    
    hex_color = OG_COLOR
    color_int = int(hex_color.lstrip('#'), 16)
    
    file_url = f"{site}/cdn/{filename}?noEmbed=true"
    
    embed_data = {
        "title": "File Upload" + ("(One-Time View)" if one_time_view else ""),
        "description": f"**{original_name}** uploaded successfully",
        "color": color_int,
        "fields": [
            {"name": "Uploader", "value": uploader, "inline": True},
            {"name": "Size", "value": f"{file_size / 1024:.2f} KB", "inline": True},
            {"name": "Type", "value": mime_type or "Unknown", "inline": True}
        ],
        "footer": {
            "text": OG_SITE_NAME
        },
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    if one_time_view:
        embed_data["fields"].append({"name": "Note", "value": "This file will be deleted after first view", "inline": False})
    
    if mime_type and mime_type.startswith("image"):
        embed_data["image"] = {"url": file_url}
    
    elif mime_type and mime_type.startswith("video"):
        embed_data["description"] += f"\n[View Video]({file_url})"
    
    payload = {"embeds": [embed_data]}
    
    try:
        requests.post(WEBHOOK, json=payload)
    except Exception as e:
        print(f"Failed to send log to webhook: {e}")

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

    one_time_view = 1 if request.form.get('one_time_view') == 'true' else 0

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
                "INSERT INTO files (filename, original_name, uploader, file_size, mime_type, one_time_view) VALUES (?, ?, ?, ?, ?, ?)",
                (filename, original_name, request.user, file_size, file.content_type, one_time_view)
            )
        conn.close()

    log_file_upload(filename, original_name, request.user, file_size, file.content_type, bool(one_time_view))
    return jsonify(
        message="File uploaded successfully", 
        filename=filename, 
        url=f"/cdn/{filename}",
        one_time_view=bool(one_time_view)
    )

@app.route("/cdn/<path:filename>", methods=["GET"])
def serve_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        return Response("File not found", status=404)
    
    conn = get_db_connection()
    file_info = None
    if conn:
        with conn:
            cur = conn.execute("SELECT * FROM files WHERE filename = ?", (filename,))
            file_info = cur.fetchone()
        conn.close()
    
    user_agent = request.headers.get("User-Agent", "").lower()
    is_bot = any(bot in user_agent for bot in [
        "discordbot", "whatsapp", "twitterbot",
        "facebookexternalhit", "slackbot", "bot", "crawler", "spider"
    ])
    
    is_one_time = file_info and file_info.get('one_time_view') == 1
    
    if is_bot:
        mime_type, _ = mimetypes.guess_type(file_path)
        file_url = f"{site}/cdn/{filename}?noEmbed=true"
        
        meta_tags = ""
        if mime_type and mime_type.startswith("video"):
            meta_tags = f"""
                <meta property="og:type" content="video.other" />
                <meta property="og:video" content="{file_url}" />
                <meta property="og:video:url" content="{file_url}" />
                <meta property="og:video:secure_url" content="{file_url}" />
                <meta property="og:video:type" content="{mime_type}" />
                <meta name="twitter:card" content="player" />
                <meta name="twitter:player" content="{file_url}" />
            """
        elif mime_type and mime_type.startswith("image"):
            meta_tags = f"""
                <meta property="og:type" content="image" />
                <meta property="og:image" content="{file_url}" />
                <meta property="og:image:secure_url" content="{file_url}" />
                <meta property="og:url" content="{file_url}" />
                <meta name="twitter:card" content="summary_large_image" />
            """
            if "whatsapp" in user_agent:
                meta_tags += f"""
                    <meta property="og:image:width" content="512" />
                    <meta property="og:image:height" content="512" />
                    <meta property="og:image:type" content="{mime_type}" />
                """
        
        html = f"""<!DOCTYPE html>
<html lang="en" prefix="og: http://ogp.me/ns#">
<head>
    <meta charset="utf-8" />
    <meta name="theme-color" content="{OG_COLOR}" />
    <meta property="og:site_name" content="{OG_SITE_NAME}" />
    <meta property="og:title" content="{OG_TITLE}" />
    <meta property="og:description" content="{OG_DESC}" />
    {meta_tags}
</head>
<body style="margin:0;background:#111;display:flex;justify-content:center;align-items:center;height:100vh;">
</body>
</html>"""
        return Response(html, mimetype="text/html")

    if is_one_time:
        try:
            conn = get_db_connection()
            if conn:
                with conn:
                    conn.execute("DELETE FROM files WHERE filename = ?", (filename,))
                conn.close()
            
            response = send_from_directory(UPLOAD_FOLDER, filename)
            
            @response.call_on_close
            def delete_one_time_file():
                import threading
                def delayed_delete():
                    time.sleep(2)
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        log(f"One-time view file deleted: {filename} (original: {file_info.get('original_name', 'unknown')})")
                    except Exception as e:
                        print(f"Error deleting one-time file: {e}")
                
                threading.Thread(target=delayed_delete, daemon=True).start()
            
            return response
        except Exception as e:
            return Response(f"Error serving file: {e}", status=500)
    
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/cdn/delete/<path:filename>", methods=["DELETE"])
@token_required
def delete_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
        
    try:
        os.remove(file_path)
        conn = get_db_connection()
        if conn:
            with conn:
                conn.execute("DELETE FROM files WHERE filename = ?", (filename,))
            conn.close()
        return jsonify({"success": True, "message": f"{filename} deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    print("start1 (hi twin)")
    log(f"Starting server with secret key: ```{SECRET_KEY}```")
    initialize_db()
    print("start2 (bye twin)")
    app.run(port=3131)