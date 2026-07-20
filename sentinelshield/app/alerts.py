from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
import uuid
from typing import Optional

ALERT_SEVERITIES = {"HIGH", "CRITICAL"}
ALWAYS_ALERT_EVENT_TYPES = {"RATE_LIMITED", "REQUEST_BLOCKED"}


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    event_type: str
    severity: str
    ip_address: str
    method: str
    path: str
    categories: list
    message: str
    details: dict = field(default_factory=dict)
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "ip_address": self.ip_address,
            "method": self.method,
            "path": self.path,
            "categories": self.categories,
            "message": self.message,
            "details": self.details,
            "acknowledged": self.acknowledged,
        }


class AlertManager:
    def __init__(self, max_alerts: int = 500):
        self._queue: deque[Alert] = deque(maxlen=max_alerts)
        self._lock = threading.Lock()
        self._total_created = 0
        self._total_by_severity: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        self._total_by_category: dict[str, int] = {}

    def process_result(self, result, rate_result=None) -> Optional[Alert]:
        should_alert = False
        event_type = "THREAT_DETECTED"
        if result.is_threat and result.worst_severity in ALERT_SEVERITIES:
            should_alert = True
        if rate_result and rate_result.should_block:
            should_alert = True
            event_type = "RATE_LIMITED"
        if result.is_threat and rate_result and rate_result.should_block:
            event_type = "REQUEST_BLOCKED"
        if not should_alert:
            return None
        message = self._build_message(result, rate_result, event_type)
        details = {
            "threat_count": len(result.threats),
            "rules_triggered": [t.rule_id for t in result.threats],
            "matched_surfaces": list({t.surface for t in result.threats}),
        }
        if rate_result and rate_result.should_block:
            details["rate_limit"] = {
                "request_count": rate_result.request_count,
                "limit": rate_result.limit,
                "retry_after": rate_result.retry_after,
            }
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=result.timestamp,
            event_type=event_type,
            severity=result.worst_severity if result.is_threat else "HIGH",
            ip_address=result.ip_address,
            method=result.method,
            path=result.path,
            categories=sorted(list(result.categories)),
            message=message,
            details=details,
        )
        self._enqueue(alert)
        return alert

    def get_recent(self, limit: int = 50, severity_filter: str = None,
                   unacknowledged_only: bool = False) -> list[dict]:
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_rank = severity_order.get(severity_filter or "LOW", 1)
        with self._lock:
            all_alerts = list(self._queue)
        all_alerts.reverse()
        filtered = []
        for alert in all_alerts:
            if unacknowledged_only and alert.acknowledged:
                continue
            rank = severity_order.get(alert.severity, 0)
            if rank < min_rank:
                continue
            filtered.append(alert.to_dict())
            if len(filtered) >= limit:
                break
        return filtered

    def acknowledge(self, alert_id: str) -> bool:
        with self._lock:
            for alert in self._queue:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    return True
        return False

    def acknowledge_all(self) -> int:
        count = 0
        with self._lock:
            for alert in self._queue:
                if not alert.acknowledged:
                    alert.acknowledged = True
                    count += 1
        return count

    def get_summary(self) -> dict:
        with self._lock:
            all_alerts = list(self._queue)
        unacked = [a for a in all_alerts if not a.acknowledged]
        by_severity = {"HIGH": 0, "CRITICAL": 0}
        for alert in unacked:
            if alert.severity in by_severity:
                by_severity[alert.severity] += 1
        by_category: dict[str, int] = {}
        for alert in all_alerts:
            for cat in alert.categories:
                by_category[cat] = by_category.get(cat, 0) + 1
        return {
            "total_in_queue": len(all_alerts),
            "unacknowledged": len(unacked),
            "by_severity": by_severity,
            "by_category": by_category,
            "total_created_since_start": self._total_created,
            "total_by_severity_since_start": self._total_by_severity.copy(),
        }

    def _enqueue(self, alert: Alert):
        with self._lock:
            self._queue.append(alert)
            self._total_created += 1
            sev = alert.severity
            if sev in self._total_by_severity:
                self._total_by_severity[sev] += 1
            for cat in alert.categories:
                self._total_by_category[cat] = self._total_by_category.get(cat, 0) + 1

    def _build_message(self, result, rate_result, event_type: str) -> str:
        ip = result.ip_address
        method = result.method
        path = result.path
        if event_type == "REQUEST_BLOCKED":
            cats = ", ".join(sorted(result.categories)) or "unknown"
            return f"BLOCKED: {result.worst_severity} {cats} + rate limit from {ip} on {method} {path}"
        if event_type == "RATE_LIMITED":
            count = rate_result.request_count if rate_result else "?"
            window = rate_result.window_seconds if rate_result else "?"
            return f"IP {ip} rate-limited: {count} requests in {window}s window"
        cats = ", ".join(sorted(result.categories)) or "unknown"
        return f"{result.worst_severity} {cats} detected from {ip} on {method} {path}"


alert_manager = AlertManager(max_alerts=500)
