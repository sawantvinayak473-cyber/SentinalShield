from app import create_app

app = create_app()

if __name__ == "__main__":
    print("=" * 55)
    print("  🛡️  SentinelShield WAF starting...")
    print("  📡  http://localhost:5000")
    print("  📊  http://localhost:5000/dashboard")
    print("  🔍  http://localhost:5000/dashboard/api/status")
    print("=" * 55)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False,
    )
