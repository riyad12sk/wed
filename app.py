import os
import secrets
from datetime import timedelta

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    session,
)


# =========================================================
# 🐈‍⬛ VIRAL VIDEO — SECURE FLASK BACKEND
# =========================================================

app = Flask(__name__)


# =========================================================
# SECURITY CONFIGURATION
# =========================================================

# IMPORTANT:
# Render Dashboard → Environment → SECRET_KEY
# এ একটি দীর্ঘ random value সেট করা উচিত।
#
# Environment variable না থাকলে temporary key তৈরি হবে।
# Production-এ Render Environment Variable ব্যবহার করাই উচিত।

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

# Session security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# HTTPS চালু হলে cookie secure হবে
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("RENDER", "").lower() == "true"
)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)


# =========================================================
# REQUEST LIMIT
# =========================================================

# বর্তমানে বড় request আটকানোর জন্য 500 MB limit।
# Actual video upload API তৈরি করার সময় এটাকে প্রয়োজন অনুযায়ী
# আরও নির্দিষ্ট করা হবে।

app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024


# =========================================================
# ALLOWED HTTP METHODS
# =========================================================

ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
}


# =========================================================
# BASIC REQUEST PROTECTION
# =========================================================

@app.before_request
def security_check():
    """
    Basic request-level protection.

    এটি কোনো 100% bot blocker নয়।
    Automated abuse কমানোর জন্য পরবর্তীতে rate-limit,
    CAPTCHA/Turnstile এবং server-side authentication যোগ করা হবে।
    """

    if request.method not in ALLOWED_METHODS:
        return jsonify({
            "success": False,
            "error": "Method not allowed"
        }), 405

    # অস্বাভাবিকভাবে বড় Content-Length থাকলে request reject করা।
    content_length = request.content_length

    if content_length is not None:
        max_size = app.config["MAX_CONTENT_LENGTH"]

        if content_length > max_size:
            return jsonify({
                "success": False,
                "error": "Request too large"
            }), 413


# =========================================================
# SECURITY HEADERS
# =========================================================

@app.after_request
def add_security_headers(response):

    # MIME sniffing বন্ধ
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"

    # Referrer protection
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    # Browser permissions সীমিত
    response.headers["Permissions-Policy"] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=(), "
        "payment=()"
    )

    # Basic XSS protection for old browsers
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Browser-কে HTTPS ব্যবহার করতে বলা
    if os.environ.get("RENDER", "").lower() == "true":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


# =========================================================
# HOME
# =========================================================

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


# =========================================================
# UPTIMEROBOT / HEALTH CHECK
# =========================================================

@app.route("/ping", methods=["GET"])
def ping():
    """
    UptimeRobot এই endpoint-এ request পাঠাতে পারবে।
    """

    return jsonify({
        "status": "ok",
        "service": "Viral Video",
        "online": True
    }), 200


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy"
    }), 200


# =========================================================
# SESSION STATUS
# =========================================================

@app.route("/api/session", methods=["GET"])
def session_status():

    user = session.get("user")

    if not user:
        return jsonify({
            "authenticated": False,
            "user": None
        }), 200

    # Password কখনো session response-এ পাঠানো হবে না।
    safe_user = {
        "id": user.get("id"),
        "name": user.get("name"),
        "role": user.get("role")
    }

    return jsonify({
        "authenticated": True,
        "user": safe_user
    }), 200


# =========================================================
# LOGOUT
# =========================================================

@app.route("/api/logout", methods=["POST"])
def logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    }), 200


# =========================================================
# 404
# =========================================================

@app.errorhandler(404)
def not_found(error):

    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "error": "API endpoint not found"
        }), 404

    return render_template("index.html"), 404


# =========================================================
# 405
# =========================================================

@app.errorhandler(405)
def method_not_allowed(error):

    return jsonify({
        "success": False,
        "error": "Method not allowed"
    }), 405


# =========================================================
# 413
# =========================================================

@app.errorhandler(413)
def request_too_large(error):

    return jsonify({
        "success": False,
        "error": "Request is too large"
    }), 413


# =========================================================
# 500
# =========================================================

@app.errorhandler(500)
def internal_server_error(error):

    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


# =========================================================
# SERVER START
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 10000)
    )

    print("")
    print("🐈‍⬛ ===============================")
    print("🐈‍⬛       VIRAL VIDEO")
    print("🐈‍⬛       Secure Flask Server")
    print("🐈‍⬛ ===============================")
    print("")
    print(f"🌐 Port: {port}")
    print("💚 Health: /health")
    print("📡 UptimeRobot: /ping")
    print("🔐 Debug: OFF")
    print("")

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
        )
