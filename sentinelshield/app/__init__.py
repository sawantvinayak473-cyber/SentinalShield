import os
from flask import Flask
from flask_cors import CORS


def create_app(config_class=None):
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "..", "static"),
        static_url_path="/static",
    )

    if config_class is None:
        from config import Config
        config_class = Config

    app.config.from_object(config_class)
    CORS(app, resources={r"/dashboard/api/*": {"origins": "*"}})

    from app.waf import WAFMiddleware
    WAFMiddleware(app)

    from app.routes.target import target_bp
    from app.routes.api import api_bp
    from app.routes.dashboard import dashboard_bp

    app.register_blueprint(target_bp)
    app.register_blueprint(api_bp,       url_prefix="/dashboard/api")
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")

    @app.errorhandler(404)
    def not_found(e):
        from flask import jsonify
        return jsonify({"error": "Not found", "status": 404}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        from flask import jsonify
        return jsonify({"error": "Method not allowed", "status": 405}), 405

    @app.errorhandler(500)
    def internal_error(e):
        from flask import jsonify
        return jsonify({"error": "Internal server error", "status": 500}), 500

    from app.logger import sentinel_logger
    sentinel_logger.log_system_event(
        "SYSTEM_START",
        "SentinelShield WAF started successfully",
        extra={
            "block_mode": app.config.get("WAF_BLOCK_MODE"),
            "rate_limit": f"{app.config.get('RATE_LIMIT_MAX_REQUESTS')} req/{app.config.get('RATE_LIMIT_WINDOW_SECONDS')}s",
        }
    )

    return app
