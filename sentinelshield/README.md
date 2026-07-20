# 🛡️ SentinelShield — Advanced Intrusion Detection & Web Protection System

A complete, industry-grade Web Application Firewall (WAF) built with Python/Flask.
Detects SQL Injection, XSS, LFI, Command Injection, and Header Injection attacks in real-time.

---

## Quick Start

### 1. Create and activate virtual environment

```bash
python -m venv venv

# Mac/Linux:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the server

```bash
python run.py
```

### 4. Open the dashboard

```
http://localhost:5000/dashboard
```

### 5. Generate attack data (optional)

```bash
bash simulate_attacks.sh
```

---

## Project Structure

```
sentinelshield/
├── app/
│   ├── __init__.py          Flask app factory
│   ├── waf.py               WAF middleware (before_request hook)
│   ├── config_loader.py     Config helper
│   ├── rules.py             18 compiled attack detection rules
│   ├── analyzer.py          HTTP request inspector
│   ├── rate_limiter.py      Sliding window rate limiter
│   ├── logger.py            Rotating JSON event logger
│   ├── alerts.py            In-memory alert queue
│   ├── database.py          SQLite models + query layer
│   └── routes/
│       ├── target.py        Protected target app (9 endpoints)
│       ├── api.py           Dashboard data API (11 endpoints)
│       └── dashboard.py     Dashboard page route
├── templates/
│   └── dashboard.html       Live ops dashboard UI
├── logs/
│   └── sentinel.json        Rotating JSON log file (auto-created)
├── sentinel.db              SQLite database (auto-created)
├── config.py                Central configuration
├── requirements.txt         Python dependencies
├── run.py                   Application entry point
└── simulate_attacks.sh      Attack simulation script
```

---

## Architecture

```
HTTP Request
    ↓
@before_request (WAF Middleware)
    ↓
Rate Limiter Check  →  Already blocked? → 429 Response
    ↓
Request Analyzer (18 rules × 5 surfaces)
    ↓
Logger + Database + Alert Manager
    ↓
Block Decision (HIGH/CRITICAL → 403, else allow)
    ↓
Flask Route Handler  →  Response
    ↓
@after_request (Security Headers)
```

---

## Attack Detection Rules (18 total)

| ID | Name | Category | Severity |
|---|---|---|---|
| SQLI-001 | Classic OR/AND bypass | SQL_INJECTION | CRITICAL |
| SQLI-002 | SQL comment injection | SQL_INJECTION | HIGH |
| SQLI-003 | UNION-based extraction | SQL_INJECTION | CRITICAL |
| SQLI-004 | Dangerous SQL keywords | SQL_INJECTION | HIGH |
| SQLI-005 | Blind SQLi time delay | SQL_INJECTION | CRITICAL |
| XSS-001 | Script tag injection | XSS | CRITICAL |
| XSS-002 | Event handler injection | XSS | HIGH |
| XSS-003 | JavaScript protocol | XSS | HIGH |
| XSS-004 | DOM manipulation | XSS | MEDIUM |
| XSS-005 | Encoded XSS payload | XSS | HIGH |
| LFI-001 | Path traversal sequences | LFI | HIGH |
| LFI-002 | Sensitive file access | LFI | CRITICAL |
| LFI-003 | Null byte injection | LFI | HIGH |
| CMDI-001 | Shell command chaining | COMMAND_INJECTION | CRITICAL |
| CMDI-002 | Command substitution | COMMAND_INJECTION | CRITICAL |
| CMDI-003 | Dangerous system commands | COMMAND_INJECTION | HIGH |
| HDRI-001 | CRLF header injection | HEADER_INJECTION | HIGH |
| HDRI-002 | Open redirect | HEADER_INJECTION | MEDIUM |

---

## API Endpoints

### Target App (WAF-protected)

| Method | Path | Description |
|---|---|---|
| GET | `/` | Home page |
| GET | `/health` | Health check |
| POST | `/login` | Auth endpoint (SQLi target) |
| GET | `/search?q=` | Search (XSS target) |
| GET | `/file?name=` | File reader (LFI target) |
| POST | `/ping` | Ping tool (CMDi target) |
| POST | `/api/data` | JSON API (nested payload target) |
| POST | `/comment` | Comment form (XSS/CMDi target) |
| GET | `/profile?user=` | Profile lookup |

### Dashboard API (WAF-bypassed)

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard/api/stats` | Summary statistics |
| GET | `/dashboard/api/events` | Paginated event log |
| GET | `/dashboard/api/events/<id>` | Event detail |
| GET | `/dashboard/api/alerts` | Live alert queue |
| POST | `/dashboard/api/alerts/ack` | Acknowledge alerts |
| GET | `/dashboard/api/blocked` | Blocked IPs |
| DELETE | `/dashboard/api/blocked/<ip>` | Unblock an IP |
| GET | `/dashboard/api/timeline` | Hourly attack chart |
| GET | `/dashboard/api/categories` | Category breakdown |
| GET | `/dashboard/api/ip/<addr>` | Per-IP status |
| GET | `/dashboard/api/top-ips` | Top traffic sources |

---

## Test Attacks

```bash
# SQL Injection
curl "http://localhost:5000/login" -d "username=' OR 1=1 --&password=x"

# XSS
curl "http://localhost:5000/search?q=<script>alert(1)</script>"

# LFI
curl "http://localhost:5000/file?name=../../../../etc/passwd"

# Command Injection
curl -X POST "http://localhost:5000/ping" -d "host=localhost; cat /etc/passwd"

# Rate limit trigger (run 25+ times quickly)
for i in $(seq 1 25); do curl -s "http://localhost:5000/login" -d "username=admin&password=wrong"; done
```

---

## Configuration

Edit `config.py` to change:

```python
RATE_LIMIT_MAX_REQUESTS  = 20   # requests before blocking
RATE_LIMIT_WINDOW_SECONDS = 60  # sliding window size
RATE_LIMIT_BLOCK_DURATION = 300 # block duration in seconds
WAF_BLOCK_MODE = True           # False = monitor only (log but don't block)
ALERT_ON_SEVERITY = ["HIGH", "CRITICAL"]  # which severities trigger alerts
```

---

## Dashboard Features

- **Overview**: Stat cards, 24h attack timeline chart, category doughnut chart
- **Event Log**: Paginated table with filters by severity, type, IP, time window
- **Event Detail**: Click any row for full threat match details and request surfaces
- **Live Alerts**: Real-time HIGH/CRITICAL alert feed with acknowledgement
- **Blocked IPs**: Active block list with manual unblock capability
- **Attack Tester**: Built-in tool to fire test payloads and see WAF responses

---

## Built With

- **Flask** — web framework
- **SQLAlchemy** — ORM + SQLite database
- **Chart.js** — dashboard charts
- **IBM Plex Mono** — dashboard typography

---

*SentinelShield is an educational project designed for learning web security concepts.*
