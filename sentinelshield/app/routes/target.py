import time
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify

target_bp = Blueprint("target", __name__)


@target_bp.route("/", methods=["GET"])
def index():
    return jsonify({
        "application": "SentinelShield Demo Target",
        "status": "protected",
        "waf_active": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoints": {
            "home":     "GET /",
            "health":   "GET /health",
            "login":    "POST /login",
            "search":   "GET /search?q=<query>",
            "file":     "GET /file?name=<filename>",
            "ping":     "POST /ping",
            "api_data": "POST /api/data",
            "comment":  "POST /comment",
            "profile":  "GET /profile?user=<username>",
        },
        "test_attacks": {
            "sqli": "curl 'http://localhost:5000/login' -d \"username=' OR 1=1 --&password=x\"",
            "xss":  "curl 'http://localhost:5000/search?q=<script>alert(1)</script>'",
            "lfi":  "curl 'http://localhost:5000/file?name=../../../../etc/passwd'",
            "cmdi": "curl 'http://localhost:5000/ping' -d 'host=localhost; cat /etc/passwd'",
        }
    })


@target_bp.route("/health", methods=["GET"])
def health():
    from app.database import db_manager
    from app.rate_limiter import rate_limiter
    from app.alerts import alert_manager
    stats = db_manager.get_dashboard_stats()
    rate_stats = rate_limiter.get_stats()
    alert_summary = alert_manager.get_summary()
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "waf": {
            "total_requests_processed": stats.get("total_requests", 0),
            "total_threats_blocked":    stats.get("total_threats", 0),
            "currently_blocked_ips":    rate_stats.get("currently_blocked_ips", 0),
            "active_alerts":            alert_summary.get("unacknowledged", 0),
        }
    })


@target_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return jsonify({
            "endpoint": "/login", "method": "POST",
            "fields": ["username", "password"],
            "attack_example": "username=' OR 1=1 --&password=x"
        })
    if request.is_json:
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
    else:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
    FAKE_USERS = {"admin": "admin123", "user": "password", "test": "test"}
    if username in FAKE_USERS and FAKE_USERS[username] == password:
        return jsonify({
            "success": True,
            "message": f"Welcome back, {username}!",
            "token": "fake-jwt-token-for-demo",
            "user": {"username": username, "role": "admin" if username == "admin" else "user"},
        })
    time.sleep(0.1)
    return jsonify({"success": False, "message": "Invalid username or password"}), 401


@target_bp.route("/search", methods=["GET"])
def search():
    query    = request.args.get("q", "")
    category = request.args.get("category", "all")
    page     = request.args.get("page", "1")
    if not query:
        return jsonify({"endpoint": "/search", "usage": "GET /search?q=<query>",
                        "attack_example": "/search?q=<script>alert(1)</script>"})
    FAKE_PRODUCTS = [
        {"id": 1, "name": "Laptop Pro X1",   "category": "electronics", "price": 1299.99},
        {"id": 2, "name": "Wireless Mouse",  "category": "electronics", "price": 29.99},
        {"id": 3, "name": "Python Handbook", "category": "books",       "price": 49.99},
        {"id": 4, "name": "USB-C Hub",       "category": "electronics", "price": 39.99},
        {"id": 5, "name": "Security Basics", "category": "books",       "price": 34.99},
    ]
    results = [p for p in FAKE_PRODUCTS if query.lower() in p["name"].lower()
               or (category != "all" and p["category"] == category)]
    return jsonify({
        "query": query, "category": category,
        "page": int(page) if page.isdigit() else 1,
        "total_results": len(results), "results": results,
        "message": f"Showing results for: {query}",
    })


@target_bp.route("/file", methods=["GET"])
def file_reader():
    filename = request.args.get("name", "")
    if not filename:
        return jsonify({"endpoint": "/file", "usage": "GET /file?name=<filename>",
                        "available": ["readme.txt", "help.txt", "about.txt"],
                        "attack_example": "/file?name=../../../../etc/passwd"})
    SAFE_FILES = {
        "readme.txt": "Welcome to SentinelShield demo application.",
        "help.txt":   "For help, contact support@example.com",
        "about.txt":  "SentinelShield Demo v1.0",
    }
    if filename in SAFE_FILES:
        return jsonify({"filename": filename, "content": SAFE_FILES[filename],
                        "size": len(SAFE_FILES[filename])})
    return jsonify({"filename": filename,
                    "error": f"File '{filename}' not found in allowed directory"}), 404


@target_bp.route("/ping", methods=["GET", "POST"])
def ping():
    if request.method == "GET":
        return jsonify({"endpoint": "/ping", "method": "POST",
                        "fields": ["host", "count"],
                        "attack_example": "host=localhost; cat /etc/passwd"})
    data = request.get_json(silent=True) or request.form
    host  = data.get("host",  "localhost")
    count = data.get("count", "4")
    try:
        count_int = max(1, min(10, int(count)))
    except (ValueError, TypeError):
        count_int = 4
    fake_output = (
        f"PING {host}: 56 data bytes\n"
        + "\n".join([f"64 bytes from {host}: icmp_seq={i} ttl=64 time={12 + i * 1.3:.1f} ms"
                     for i in range(1, count_int + 1)])
        + f"\n--- {host} ping statistics ---\n"
        f"{count_int} packets transmitted, {count_int} received, 0% packet loss"
    )
    return jsonify({"host": host, "count": count_int, "output": fake_output,
                    "note": "Simulated — no real OS command was executed"})


@target_bp.route("/api/data", methods=["GET", "POST"])
def api_data():
    if request.method == "GET":
        return jsonify({"endpoint": "/api/data", "method": "POST",
                        "content_type": "application/json",
                        "attack_examples": [
                            '{"user": {"id": "1 UNION SELECT * FROM users--"}}',
                            '{"search": "<script>alert(1)</script>"}',
                        ]})
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400
    return jsonify({
        "received": True,
        "keys": list(data.keys()) if isinstance(data, dict) else [],
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "message": "Data processed successfully",
    })


@target_bp.route("/comment", methods=["GET", "POST"])
def comment():
    if request.method == "GET":
        return jsonify({"endpoint": "/comment", "method": "POST",
                        "fields": ["author", "text", "email"],
                        "attack_examples": [
                            "text=<script>alert(document.cookie)</script>",
                            "text=<img src=x onerror=alert(1)>",
                        ]})
    author = request.form.get("author", "Anonymous")
    text   = request.form.get("text", "")
    email  = request.form.get("email", "")
    if not text:
        return jsonify({"error": "Comment text is required"}), 400
    comment_id = abs(hash(f"{author}{text}{time.time()}")) % 100000
    return jsonify({
        "success": True, "comment_id": comment_id,
        "author": author, "text": text, "email": email,
        "posted_at": datetime.now(timezone.utc).isoformat(),
        "message": "Comment submitted for moderation",
    })


@target_bp.route("/profile", methods=["GET"])
def profile():
    username = request.args.get("user", "")
    if not username:
        return jsonify({"endpoint": "/profile", "usage": "GET /profile?user=<username>",
                        "attack_example": "/profile?user=admin' OR '1'='1"})
    FAKE_PROFILES = {
        "admin": {"username": "admin", "role": "Administrator", "email": "admin@example.com"},
        "user":  {"username": "user",  "role": "Standard User",  "email": "user@example.com"},
        "test":  {"username": "test",  "role": "Test Account",   "email": "test@example.com"},
    }
    profile_data = FAKE_PROFILES.get(username.lower())
    if profile_data:
        return jsonify({"found": True, "profile": profile_data})
    return jsonify({"found": False, "searched_for": username,
                    "message": f"No profile found for '{username}'"}), 404
