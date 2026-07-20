import json
from datetime import datetime, timezone
from flask import request, jsonify, Response
from app.analyzer import analyzer
from app.rate_limiter import rate_limiter
from app.logger import sentinel_logger
from app.alerts import alert_manager
from app.database import db_manager
from app.config_loader import get_config

_cfg = get_config()

BYPASS_PREFIXES = ["/dashboard", "/static", "/favicon.ico"]
SKIP_METHODS = {"HEAD", "OPTIONS"}


class WAFMiddleware:
    def __init__(self, app):
        self.app = app
        self.block_mode = _cfg.WAF_BLOCK_MODE
        self.alert_severities = set(_cfg.ALERT_ON_SEVERITY)
        app.before_request(self._inspect_request)
        app.after_request(self._add_security_headers)

    def _inspect_request(self):
        try:
            if self._should_bypass(request):
                return None
            ip = self._get_ip()
            rate_result = rate_limiter.check(ip)
            if rate_result.is_blocked and not rate_result.is_rate_limited:
                sentinel_logger.log_system_event(
                    "BLOCKED_IP_ATTEMPT",
                    f"Blocked IP {ip} attempted request to {request.path}",
                    extra={"ip_address": ip, "path": request.path,
                           "method": request.method, "retry_after": rate_result.retry_after}
                )
                return self._blocked_response(
                    reason="IP address is temporarily blocked",
                    retry_after=rate_result.retry_after,
                    event_type="RATE_LIMITED",
                )
            analysis = analyzer.analyze(request)
            sentinel_logger.log_analysis_result(analysis, rate_result)
            db_manager.save_event(analysis, rate_result)
            alert_manager.process_result(analysis, rate_result)
            if rate_result.is_rate_limited and rate_result.blocked_until:
                db_manager.block_ip(
                    ip_address=ip,
                    blocked_until=rate_result.blocked_until,
                    reason=rate_result.block_reason,
                )
            should_block = False
            block_reason = ""
            if rate_result.is_rate_limited:
                should_block = True
                block_reason = rate_result.block_reason
            elif (self.block_mode and analysis.is_threat
                  and analysis.worst_severity in self.alert_severities):
                should_block = True
                categories = ", ".join(sorted(analysis.categories))
                block_reason = f"{analysis.worst_severity} threat detected: {categories}"
            if should_block:
                return self._blocked_response(
                    reason=block_reason,
                    retry_after=rate_result.retry_after if rate_result.is_rate_limited else 0,
                    event_type="RATE_LIMITED" if rate_result.is_rate_limited else "THREAT_DETECTED",
                    analysis=analysis,
                )
            return None
        except Exception as e:
            print(f"[WAFMiddleware] Internal error: {e}", flush=True)
            return None

    def _add_security_headers(self, response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://cdn.jsdelivr.net;"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers.pop("Server", None)
        response.headers["X-Protected-By"] = "SentinelShield"
        return response

    def _should_bypass(self, req) -> bool:
        if req.method in SKIP_METHODS:
            return True
        for prefix in BYPASS_PREFIXES:
            if req.path.startswith(prefix):
                return True
        return False

    def _get_ip(self) -> str:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def _blocked_response(self, reason, retry_after=0, event_type="THREAT_DETECTED", analysis=None) -> Response:
        is_rate_limit = event_type == "RATE_LIMITED"
        body = {
            "blocked": True,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if analysis and analysis.is_threat:
            body["threats_detected"] = len(analysis.threats)
            body["categories"] = sorted(list(analysis.categories))
            body["severity"] = analysis.worst_severity
        if retry_after > 0:
            body["retry_after_seconds"] = retry_after
        status_code = 429 if is_rate_limit else 403
        response = jsonify(body)
        response.status_code = status_code
        if retry_after > 0:
            response.headers["Retry-After"] = str(retry_after)
        return response
