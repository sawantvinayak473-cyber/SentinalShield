from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
from app.database import db_manager
from app.rate_limiter import rate_limiter
from app.alerts import alert_manager
from app.logger import sentinel_logger

api_bp = Blueprint("api", __name__)


def _safe_int(value, default=0, min_val=0, max_val=10000):
    try:
        return max(min_val, min(max_val, int(value)))
    except (ValueError, TypeError):
        return default


@api_bp.route("/stats", methods=["GET"])
def get_stats():
    hours = _safe_int(request.args.get("hours", "24"), default=24, max_val=168)
    db_stats      = db_manager.get_dashboard_stats()
    rate_stats    = rate_limiter.get_stats()
    alert_summary = alert_manager.get_summary()
    log_stats     = sentinel_logger.get_stats(hours=hours)
    return jsonify({
        "status": "ok", "window_hours": hours,
        "lifetime": {
            "total_requests":    db_stats.get("total_requests",    0),
            "total_threats":     db_stats.get("total_threats",     0),
            "total_rate_limits": db_stats.get("total_rate_limits", 0),
            "total_blocked":     db_stats.get("total_blocked",     0),
        },
        "recent": {
            "total_events":      log_stats.get("total_events",      0),
            "threat_events":     log_stats.get("threat_events",     0),
            "allowed_events":    log_stats.get("allowed_events",    0),
            "rate_limit_events": log_stats.get("rate_limit_events", 0),
        },
        "categories": {
            "sql_injection":     db_stats.get("category_SQL_INJECTION",    0),
            "xss":               db_stats.get("category_XSS",              0),
            "lfi":               db_stats.get("category_LFI",              0),
            "command_injection": db_stats.get("category_COMMAND_INJECTION",0),
            "header_injection":  db_stats.get("category_HEADER_INJECTION", 0),
        },
        "rate_limiter": {
            "tracked_ips":      rate_stats.get("total_tracked_ips",    0),
            "blocked_ips":      rate_stats.get("currently_blocked_ips",0),
            "total_violations": rate_stats.get("total_violations",     0),
        },
        "alerts": {
            "total_in_queue": alert_summary.get("total_in_queue",                    0),
            "unacknowledged": alert_summary.get("unacknowledged",                    0),
            "critical_count": alert_summary.get("by_severity", {}).get("CRITICAL",  0),
            "high_count":     alert_summary.get("by_severity", {}).get("HIGH",      0),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@api_bp.route("/events", methods=["GET"])
def get_events():
    page         = _safe_int(request.args.get("page",     "1"),  default=1, min_val=1)
    per_page     = _safe_int(request.args.get("per_page", "50"), default=50, max_val=200)
    severity     = request.args.get("severity",    "").upper() or None
    event_type   = request.args.get("event_type",  "").upper() or None
    ip_filter    = request.args.get("ip",          "") or None
    hours        = _safe_int(request.args.get("hours", "0"), default=0, max_val=168) or None
    threats_only = request.args.get("threats_only", "").lower() == "true"
    offset = (page - 1) * per_page
    result = db_manager.get_recent_events(
        limit=per_page, offset=offset, severity_filter=severity,
        event_type_filter=event_type, ip_filter=ip_filter,
        hours=hours, threats_only=threats_only,
    )
    total_pages = max(1, -(-result["total"] // per_page))
    return jsonify({
        "status": "ok",
        "events": result["events"],
        "pagination": {
            "page": page, "per_page": per_page,
            "total": result["total"], "total_pages": total_pages,
            "has_next": page < total_pages, "has_prev": page > 1,
        },
        "filters_applied": {
            "severity": severity, "event_type": event_type,
            "ip": ip_filter, "hours": hours, "threats_only": threats_only,
        },
    })


@api_bp.route("/events/<int:event_id>", methods=["GET"])
def get_event_detail(event_id: int):
    detail = db_manager.get_event_detail(event_id)
    if not detail:
        return jsonify({"status": "error", "message": f"Event {event_id} not found"}), 404
    return jsonify({"status": "ok", "event": detail})


@api_bp.route("/alerts", methods=["GET"])
def get_alerts():
    limit    = _safe_int(request.args.get("limit", "50"), default=50, max_val=500)
    severity = request.args.get("severity", "").upper() or None
    unacked  = request.args.get("unacknowledged_only", "").lower() == "true"
    alerts   = alert_manager.get_recent(limit=limit, severity_filter=severity, unacknowledged_only=unacked)
    summary  = alert_manager.get_summary()
    return jsonify({"status": "ok", "alerts": alerts, "summary": summary, "count": len(alerts)})


@api_bp.route("/alerts/ack", methods=["POST"])
def acknowledge_alerts():
    data = request.get_json(silent=True) or {}
    if data.get("acknowledge_all"):
        count = alert_manager.acknowledge_all()
        return jsonify({"status": "ok", "acknowledged": count, "message": f"All {count} alerts acknowledged"})
    alert_id = data.get("alert_id", "")
    if not alert_id:
        return jsonify({"status": "error", "message": "Provide 'alert_id' or 'acknowledge_all: true'"}), 400
    success = alert_manager.acknowledge(alert_id)
    if not success:
        return jsonify({"status": "error", "message": f"Alert '{alert_id}' not found"}), 404
    return jsonify({"status": "ok", "acknowledged": 1, "alert_id": alert_id})


@api_bp.route("/blocked", methods=["GET"])
def get_blocked_ips():
    db_blocked  = db_manager.get_blocked_ips()
    mem_blocked = rate_limiter.get_all_blocked()
    db_ip_set   = {b["ip_address"] for b in db_blocked}
    new_blocks  = [b for b in mem_blocked if b["ip_address"] not in db_ip_set]
    combined    = db_blocked + new_blocks
    return jsonify({"status": "ok", "blocked_ips": combined, "count": len(combined),
                    "timestamp": datetime.now(timezone.utc).isoformat()})


@api_bp.route("/blocked/<path:ip_address>", methods=["DELETE"])
def unblock_ip(ip_address: str):
    mem_result = rate_limiter.unblock(ip_address)
    db_result  = db_manager.unblock_ip(ip_address)
    if not mem_result and not db_result:
        return jsonify({"status": "error", "message": f"IP '{ip_address}' was not found"}), 404
    sentinel_logger.log_system_event(
        "IP_UNBLOCKED", f"IP {ip_address} manually unblocked via dashboard",
        extra={"ip_address": ip_address, "action": "manual_unblock"},
    )
    return jsonify({"status": "ok", "unblocked": ip_address,
                    "message": f"IP {ip_address} has been unblocked"})


@api_bp.route("/timeline", methods=["GET"])
def get_timeline():
    hours    = _safe_int(request.args.get("hours", "24"), default=24, max_val=168)
    timeline = db_manager.get_hourly_timeline(hours=hours)
    return jsonify({"status": "ok", "hours": hours, "timeline": timeline,
                    "total_threats": sum(p["count"] for p in timeline)})


@api_bp.route("/categories", methods=["GET"])
def get_categories():
    hours     = _safe_int(request.args.get("hours", "24"), default=24, max_val=168)
    breakdown = db_manager.get_category_breakdown(hours=hours)
    CATEGORY_META = {
        "SQL_INJECTION":    {"label": "SQL Injection", "color": "#E24B4A"},
        "XSS":              {"label": "XSS",           "color": "#EF9F27"},
        "LFI":              {"label": "LFI",           "color": "#D85A30"},
        "COMMAND_INJECTION":{"label": "Cmd Injection", "color": "#534AB7"},
        "HEADER_INJECTION": {"label": "Header Inject", "color": "#185FA5"},
    }
    enriched = []
    for item in breakdown:
        meta = CATEGORY_META.get(item["category"], {"label": item["category"], "color": "#888888"})
        enriched.append({"category": item["category"], "label": meta["label"],
                         "color": meta["color"], "count": item["count"]})
    return jsonify({"status": "ok", "hours": hours, "categories": enriched,
                    "total": sum(i["count"] for i in enriched)})


@api_bp.route("/ip/<path:ip_address>", methods=["GET"])
def get_ip_status(ip_address: str):
    rl_status = rate_limiter.get_status(ip_address)
    events    = db_manager.get_recent_events(limit=100, ip_filter=ip_address)
    total     = events["total"]
    threats   = sum(1 for e in events["events"] if e["is_threat"]) if total > 0 else 0
    threat_pct = round((threats / min(total, 100)) * 100, 1) if total > 0 else 0.0
    return jsonify({
        "status": "ok", "ip_address": ip_address,
        "rate_limiter": rl_status,
        "recent_events": {
            "total_stored": total, "returned": len(events["events"]),
            "threat_count": threats, "threat_percent": threat_pct,
            "events": events["events"][:20],
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@api_bp.route("/top-ips", methods=["GET"])
def get_top_ips():
    n       = _safe_int(request.args.get("n", "10"), default=10, max_val=50)
    top_ips = rate_limiter.get_top_ips(n=n)
    return jsonify({"status": "ok", "top_ips": top_ips, "count": len(top_ips)})


@api_bp.route("/status", methods=["GET"])
def status():
    return jsonify({"api": "online", "version": "1.0.0"})
