import os
import re
import sqlite3
import secrets
from pathlib import Path
from datetime import timedelta

from flask import (
    Flask, render_template, request, jsonify,
    session, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# =====================================================
# 🐈‍⬛ VIRAL VIDEO — FLASK BACKEND
# =====================================================

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

DB_PATH = BASE_DIR / "viral_video.db"

ALLOWED_EXTENSIONS = {"mp4", "webm", "mov", "m4v"}
MAX_VIDEO_SIZE = 700 * 1024 * 1024  # 700 MB

app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    # শুধু অস্থায়ী পরীক্ষার জন্য; Render-এ স্থায়ী SECRET_KEY সেট করো।
    secret_key = secrets.token_hex(32)

app.config["SECRET_KEY"] = secret_key
app.config["MAX_CONTENT_LENGTH"] = MAX_VIDEO_SIZE
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("RENDER", "").lower() == "true"
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

TELEGRAM_URL = "https://t.me/viralvideo538"


# =====================================================
# DATABASE
# =====================================================

def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                filename TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT DEFAULT '',
                telegram_url TEXT DEFAULT '',
                views INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                video_id INTEGER NOT NULL,
                user_key TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(video_id, user_key),
                FOREIGN KEY(video_id) REFERENCES videos(id)
            );

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                video_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(video_id) REFERENCES videos(id)
            );
        """)


init_db()


# =====================================================
# HELPERS
# =====================================================

def json_error(message, status=400):
    return jsonify({"success": False, "error": message}), status


def current_user():
    return session.get("user")


def is_admin():
    user = current_user()
    return bool(user and user.get("role") == "admin")


def user_key():
    user = current_user()
    if user:
        return "user:" + str(user["id"])
    if not session.get("guest_key"):
        session["guest_key"] = secrets.token_urlsafe(24)
    return "guest:" + session["guest_key"]


def valid_phone(phone):
    return bool(re.fullmatch(r"[0-9+()\-\s]{7,20}", phone or ""))


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def csrf_ok():
    sent = request.headers.get("X-CSRF-Token", "")
    saved = session.get("csrf_token", "")
    return bool(saved and sent and secrets.compare_digest(sent, saved))


@app.before_request
def protect_requests():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not csrf_ok():
            return json_error("পৃষ্ঠা রিফ্রেশ করে আবার চেষ্টা করো।", 400)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["Cache-Control"] = "no-store"

    if os.environ.get("RENDER", "").lower() == "true":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


# =====================================================
# MAIN PAGE / HEALTH
# =====================================================

@app.get("/")
def home():
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
    return render_template(
        "index.html",
        csrf_token=session["csrf_token"]
    )


@app.get("/ping")
def ping():
    return jsonify({
        "status": "ok",
        "service": "Viral Video",
        "online": True
    })


@app.get("/health")
def health():
    return jsonify({"status": "healthy"})


@app.get("/uploads/<path:filename>")
def uploaded_video(filename):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


# =====================================================
# SESSION
# =====================================================

@app.get("/api/session")
def session_status():
    user = current_user()
    return jsonify({
        "authenticated": bool(user),
        "user": user,
        "csrfToken": session.get("csrf_token")
    })


@app.post("/api/logout")
def logout():
    session.clear()
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({
        "success": True,
        "csrfToken": session["csrf_token"]
    })


# =====================================================
# SIGNUP
# =====================================================

@app.post("/api/signup")
def signup():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", ""))

    if not name or len(name) > 60:
        return json_error("নাম লিখো (সর্বোচ্চ ৬০ অক্ষর)।")

    if not valid_phone(phone):
        return json_error("সঠিক ফোন নম্বর দাও।")

    if len(password) < 8 or len(password) > 128:
        return json_error("পাসওয়ার্ড ৮–১২৮ অক্ষরের হতে হবে।")

    admin_phone = os.environ.get("ADMIN_PHONE", "").strip()
    if admin_phone and phone == admin_phone:
        return json_error("এই নম্বরটি ব্যবহার করা যাবে না।", 409)

    try:
        with connect_db() as db:
            cur = db.execute(
                "INSERT INTO users(name, phone, password_hash) VALUES (?, ?, ?)",
                (name, phone, generate_password_hash(password))
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return json_error("এই ফোন নম্বরে অ্যাকাউন্ট আছে। লগইন করো।", 409)

    session.clear()
    session["user"] = {
        "id": user_id,
        "name": name,
        "role": "user"
    }
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True

    return jsonify({
        "success": True,
        "user": session["user"],
        "csrfToken": session["csrf_token"]
    })


# =====================================================
# LOGIN
# =====================================================

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", ""))

    if not phone or not password:
        return json_error("ফোন নম্বর ও পাসওয়ার্ড দাও।")

    # Admin credentials must be set in Render Environment.
    admin_phone = os.environ.get("ADMIN_PHONE", "").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")

    if (
        admin_phone
        and admin_password
        and secrets.compare_digest(phone, admin_phone)
        and secrets.compare_digest(password, admin_password)
    ):
        session.clear()
        session["user"] = {
            "id": "admin",
            "name": "অফিসিয়াল এডমিন",
            "role": "admin"
        }
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return jsonify({
            "success": True,
            "user": session["user"],
            "csrfToken": session["csrf_token"]
        })

    with connect_db() as db:
        row = db.execute(
            "SELECT id, name, phone, password_hash FROM users WHERE phone = ?",
            (phone,)
        ).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        return json_error("ফোন নম্বর অথবা পাসওয়ার্ড সঠিক নয়।", 401)

    session.clear()
    session["user"] = {
        "id": row["id"],
        "name": row["name"],
        "role": "user"
    }
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True

    return jsonify({
        "success": True,
        "user": session["user"],
        "csrfToken": session["csrf_token"]
    })


# =====================================================
# PASSWORD RESET — VERIFICATION REQUIRED
# =====================================================

@app.post("/api/forgot-password")
def forgot_password():
    # Phone number alone is not proof of account ownership.
    # OTP/SMS verification must be configured before enabling reset.
    return json_error(
        "নিরাপদ পাসওয়ার্ড রিসেট চালু করতে OTP যাচাই সেটআপ প্রয়োজন।",
        501
    )


# =====================================================
# VIDEOS
# =====================================================

@app.get("/api/videos")
def get_videos():
    with connect_db() as db:
        rows = db.execute("""
            SELECT id, title, filename, category, description,
                   telegram_url, views, created_at
            FROM videos
            ORDER BY id DESC
        """).fetchall()

        result = []
        for row in rows:
            item = dict(row)
            item["url"] = "/uploads/" + item.pop("filename")
            item["likes"] = db.execute(
                "SELECT COUNT(*) FROM likes WHERE video_id = ?",
                (item["id"],)
            ).fetchone()[0]
            item["comments_count"] = db.execute(
                "SELECT COUNT(*) FROM comments WHERE video_id = ?",
                (item["id"],)
            ).fetchone()[0]
            result.append(item)

    return jsonify({"success": True, "videos": result})


@app.get("/api/videos/<int:video_id>")
def get_video(video_id):
    with connect_db() as db:
        row = db.execute(
            "SELECT * FROM videos WHERE id = ?", (video_id,)
        ).fetchone()

        if not row:
            return json_error("ভিডিও পাওয়া যায়নি।", 404)

        db.execute(
            "UPDATE videos SET views = views + 1 WHERE id = ?",
            (video_id,)
        )
        item = dict(row)
        item["views"] += 1
        item["url"] = "/uploads/" + item.pop("filename")
        item["likes"] = db.execute(
            "SELECT COUNT(*) FROM likes WHERE video_id = ?",
            (video_id,)
        ).fetchone()[0]

    return jsonify({"success": True, "video": item})


# =====================================================
# ADMIN-ONLY VIDEO UPLOAD
# =====================================================

@app.post("/api/admin/videos")
def upload_video():
    if not is_admin():
        return json_error("শুধু অ্যাডমিন ভিডিও আপলোড করতে পারবেন।", 403)

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "ট্রেন্ডিং").strip()
    description = request.form.get("description", "").strip()
    telegram_url = request.form.get("telegram_url", TELEGRAM_URL).strip()
    file = request.files.get("video")

    if not title or len(title) > 120:
        return json_error("ভিডিওর শিরোনাম দাও (সর্বোচ্চ ১২০ অক্ষর)।")

    if not file or not file.filename:
        return json_error("একটি ভিডিও ফাইল নির্বাচন করো।")

    if not allowed_file(file.filename):
        return json_error("শুধু MP4, WEBM, MOV অথবা M4V ফাইল অনুমোদিত।")

    if telegram_url and not (
        telegram_url.startswith("https://t.me/")
        or telegram_url.startswith("https://telegram.me/")
    ):
        return json_error("সঠিক Telegram লিংক দাও।")

    original_name = secure_filename(file.filename)
    extension = original_name.rsplit(".", 1)[1].lower()
    stored_name = secrets.token_hex(16) + "." + extension
    target = UPLOAD_DIR / stored_name

    try:
        file.save(target)

        with connect_db() as db:
            db.execute("""
                INSERT INTO videos
                (title, filename, category, description, telegram_url)
                VALUES (?, ?, ?, ?, ?)
            """, (
                title, stored_name, category[:40],
                description[:2000], telegram_url
            ))
    except Exception:
        target.unlink(missing_ok=True)
        app.logger.exception("Video upload failed")
        return json_error("ভিডিও সংরক্ষণ করা যায়নি।", 500)

    return jsonify({"success": True, "message": "ভিডিও যোগ হয়েছে।"}), 201


# =====================================================
# LIKES
# =====================================================

@app.post("/api/videos/<int:video_id>/like")
def toggle_like(video_id):
    key = user_key()

    with connect_db() as db:
        exists = db.execute(
            "SELECT id FROM videos WHERE id = ?", (video_id,)
        ).fetchone()
        if not exists:
            return json_error("ভিডিও পাওয়া যায়নি।", 404)

        old = db.execute(
            "SELECT id FROM likes WHERE video_id = ? AND user_key = ?",
            (video_id, key)
        ).fetchone()

        if old:
            db.execute("DELETE FROM likes WHERE id = ?", (old["id"],))
            liked = False
        else:
            db.execute(
                "INSERT INTO likes(video_id, user_key) VALUES (?, ?)",
                (video_id, key)
            )
            liked = True

        count = db.execute(
            "SELECT COUNT(*) FROM likes WHERE video_id = ?",
            (video_id,)
        ).fetchone()[0]

    return jsonify({"success": True, "liked": liked, "likes": count})


# =====================================================
# COMMENTS
# =====================================================

@app.get("/api/videos/<int:video_id>/comments")
def get_comments(video_id):
    with connect_db() as db:
        rows = db.execute("""
            SELECT id, user_name, body, created_at
            FROM comments
            WHERE video_id = ?
            ORDER BY id DESC
            LIMIT 100
        """, (video_id,)).fetchall()

    return jsonify({
        "success": True,
        "comments": [dict(row) for row in rows]
    })


@app.post("/api/videos/<int:video_id>/comments")
def add_comment(video_id):
    data = request.get_json(silent=True) or {}
    body = str(data.get("body", "")).strip()

    if not body or len(body) > 1000:
        return json_error("কমেন্ট ১–১০০০ অক্ষরের মধ্যে লিখো।")

    user = current_user()
    name = user["name"] if user else "অতিথি"

    with connect_db() as db:
        exists = db.execute(
            "SELECT id FROM videos WHERE id = ?", (video_id,)
        ).fetchone()
        if not exists:
            return json_error("ভিডিও পাওয়া যায়নি।", 404)

        cur = db.execute("""
            INSERT INTO comments(video_id, user_name, body)
            VALUES (?, ?, ?)
        """, (video_id, name, body))

        row = db.execute(
            "SELECT id, user_name, body, created_at FROM comments WHERE id = ?",
            (cur.lastrowid,)
        ).fetchone()

    return jsonify({"success": True, "comment": dict(row)}), 201


# =====================================================
# ERRORS
# =====================================================

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return json_error("API endpoint পাওয়া যায়নি।", 404)
    return render_template(
        "index.html",
        csrf_token=session.get("csrf_token", "")
    ), 404


@app.errorhandler(413)
def too_large(error):
    return json_error("ফাইলটি ৭০০ MB সীমার চেয়ে বড়।", 413)


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("Unexpected server error")
    return json_error("সার্ভারে সমস্যা হয়েছে। পরে চেষ্টা করো।", 500)


# =====================================================
# START SERVER
# =====================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    print("🐈‍⬛ VIRAL VIDEO — Server starting")
    print("🌐 Port:", port)
    print("📡 Health: /health")
    print("📡 Uptime: /ping")
    app.run(host="0.0.0.0", port=port, debug=False)
