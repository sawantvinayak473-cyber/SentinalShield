# 🛡️ SentinelShield

> **Advanced Web Application Firewall (WAF) & Threat Operations Center**

SentinelShield is a Flask-based cybersecurity project that protects web applications against common web attacks by detecting, monitoring, and blocking malicious requests in real time. It provides a modern Threat Operations Center (TOC) dashboard for security monitoring and attack visualization.

---

## 🌐 Live Demo

**Dashboard:**  
https://sentinalshield.onrender.com/dashboard

**API Home:**  
https://sentinalshield.onrender.com/

---

## 📸 Dashboard Preview

> Add screenshots here

- Dashboard Overview
- Attack Timeline
- Event Logs
- Live Alerts
- Blocked IPs
- Attack Tester

---

# ✨ Features

- 🛡️ Real-time Web Application Firewall
- 🚫 SQL Injection Detection
- 🚫 Cross-Site Scripting (XSS) Detection
- 🚫 Command Injection Detection
- 🚫 Local File Inclusion (LFI) Detection
- 📊 Live Threat Operations Dashboard
- 📈 Request Statistics
- 🚨 Attack Detection & Logging
- 🔥 Active Alert Monitoring
- 📂 REST API Endpoints
- 🌙 Modern Cybersecurity UI

---

# 🏗️ Project Architecture

```
                Incoming Request
                        │
                        ▼
              SentinelShield WAF
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
 SQL Injection      XSS Filter     Command Injection
 Detection          Detection        Detection
        │               │               │
        └───────────────┼───────────────┘
                        │
              Threat Detection Engine
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   Event Logs      Dashboard API     Alerts
```

---

# 🧰 Tech Stack

| Technology | Usage |
|------------|------|
| Python | Backend |
| Flask | Web Framework |
| SQLAlchemy | Database ORM |
| HTML5 | Frontend |
| CSS3 | Styling |
| JavaScript | Dashboard |
| Gunicorn | Production Server |
| Render | Deployment |

---

# 📁 Project Structure

```
sentinelshield/
│
├── app/
│   ├── rules.py
│   ├── waf.py
│   ├── templates/
│   ├── static/
│   └── ...
│
├── logs/
├── config.py
├── requirements.txt
├── run.py
└── README.md
```

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/sawantvinayak473-cyber/SentinalShield.git
```

Go into the project

```bash
cd SentinalShield/sentinelshield
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python run.py
```

Open

```
http://localhost:5000/dashboard
```

---

# 🧪 Attack Testing

The project includes an Attack Tester to simulate common web attacks.

Supported attacks:

- SQL Injection
- Cross Site Scripting (XSS)
- Command Injection
- Local File Inclusion (LFI)

Example SQL Injection

```
' OR 1=1 --
```

Example XSS

```html
<script>alert('XSS')</script>
```

---

# 📊 Dashboard Modules

- Overview
- Event Logs
- Live Alerts
- Blocked IPs
- Attack Tester
- Attack Timeline
- Category Breakdown

---

# 🔒 Security Features

- Request Inspection
- Threat Classification
- Pattern Matching
- Malicious Payload Detection
- Request Logging
- Dashboard Analytics
- REST API Monitoring

---

# 📡 API Endpoints

| Endpoint | Method |
|----------|--------|
| / | GET |
| /dashboard | GET |
| /health | GET |
| /ping | POST |
| /login | POST |
| /search | GET |
| /profile | GET |
| /api/data | POST |

---

# 🌍 Deployment

Hosted on Render using Gunicorn.

```
Build Command
pip install -r requirements.txt
```

```
Start Command
gunicorn run:app
```

---

# 🔮 Future Enhancements

- AI-based Threat Detection
- Machine Learning Attack Classification
- Email Alerts
- Geo-IP Tracking
- User Authentication
- Docker Support
- Prometheus Monitoring
- Grafana Dashboard
- PDF Report Export
- Multi-user SOC Dashboard

---

# 👨‍💻 Author

**Vinayak Sawant**

B.Sc Computer Science Student  
Cybersecurity Enthusiast

GitHub:
https://github.com/sawantvinayak473-cyber

LinkedIn:
(Add your LinkedIn profile)

---

# ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub.

---

# 📄 License

This project is developed for educational and research purposes.
