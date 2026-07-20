import json
import os
import threading
from logging.handlers import RotatingFileHandler
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from app.config_loader import get_config


class EventType:
    THREAT_DETECTED = "THREAT_DETECTED"
    RATE_LIMITED    = "RATE_LIMITED"
    REQUEST_BLOCKED = "REQUEST_BLOCKED"
    REQUEST_ALLOWED = "REQUEST_ALLOWED"
    IP_UNBLOCKED    = "IP_UNBLOCKED"
    SYSTEM_START    = "SYSTEM_START"
    SYSTEM_ERROR    = "SYSTEM_ERROR"


class SentinelLogger:
    def __init__(self, log_file: str, max_bytes: int, backup_count: int):
        self._lock = threading.Lock()
        self._log_file = log_file
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        self._logger = logging.getLogger("sentinel.events")
        self._logger.setLevel(logging.INFO)
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                filename=log_file, maxBytes=max_bytes,
                backupCount=backup_count, encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
        self.log_system_event(EventType.SYSTEM_START, "SentinelShield logger initialised")

    def _write(self, entry: dict) -> bool:
        try:
            with self._lock:
                json_line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
                self._logger.info(json_line)
            return True
        except Exception as e:
            print(f"[SentinelLogger] WRITE FAILED: {e}", flush=True)
            return False

    def log_analysis_result(self, result, rate_result=None) -> bool:
        try:
            has_threat = result.is_threat
            has_rate_limit = rate_result is not None and rate_result.should_block
            if has_threat and has_rate_limit:
                event_type = EventType.REQUEST_BLOCKED
            elif has_threat:
                event_type = EventType.THREAT_DETECTED
            elif has_rate_limit:
                event_type = EventType.RATE_LIMITED
            else:
                event_type = EventType.REQUEST_ALLOWED
            entry = result.to_dict()
            entry["event_type"] = event_type
            if rate_result:
                entry["rate_limit"] = rate_result.to_dict()
            return self._write(entry)
        except Exception as e:
            print(f"[SentinelLogger] log_analysis_result failed: {e}", flush=True)
            return False

    def log_system_event(self, event_type: str, message: str, extra: dict = None) -> bool:
        try:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "severity": "INFO",
                "message": message,
            }
            if extra:
                entry.update(extra)
            return self._write(entry)
        except Exception as e:
            print(f"[SentinelLogger] log_system_event failed: {e}", flush=True)
            return False

    def read_recent(self, limit: int = 100, severity_filter: str = None,
                    category_filter: str = None, ip_filter: str = None) -> list[dict]:
        try:
            log_path = Path(self._log_file)
            if not log_path.exists():
                return []
            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            entries = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            if severity_filter:
                entries = self._filter_by_severity(entries, severity_filter)
            if category_filter:
                entries = [e for e in entries if category_filter in e.get("categories", [])]
            if ip_filter:
                entries = [e for e in entries if e.get("ip_address") == ip_filter]
            return list(reversed(entries[-limit:]))
        except Exception as e:
            print(f"[SentinelLogger] read_recent failed: {e}", flush=True)
            return []

    def get_stats(self, hours: int = 24) -> dict:
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            entries = self.read_recent(limit=10000)
            window_entries = []
            for e in entries:
                try:
                    ts = datetime.fromisoformat(e["timestamp"])
                    if ts >= since:
                        window_entries.append(e)
                except (KeyError, ValueError):
                    continue
            threat_events = [e for e in window_entries if e.get("event_type") in (EventType.THREAT_DETECTED, EventType.REQUEST_BLOCKED)]
            rate_events   = [e for e in window_entries if e.get("event_type") in (EventType.RATE_LIMITED, EventType.REQUEST_BLOCKED)]
            allowed_events= [e for e in window_entries if e.get("event_type") == EventType.REQUEST_ALLOWED]
            category_counts: dict[str, int] = {}
            for e in threat_events:
                for cat in e.get("categories", []):
                    category_counts[cat] = category_counts.get(cat, 0) + 1
            severity_counts: dict[str, int] = {}
            for e in threat_events:
                sev = e.get("worst_severity", "UNKNOWN")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            ip_counts: dict[str, int] = {}
            for e in threat_events:
                ip = e.get("ip_address", "unknown")
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            timeline = []
            for h in range(hours, 0, -1):
                bucket_start = datetime.now(timezone.utc) - timedelta(hours=h)
                bucket_end   = datetime.now(timezone.utc) - timedelta(hours=h - 1)
                count = sum(1 for e in threat_events if self._in_bucket(e.get("timestamp", ""), bucket_start, bucket_end))
                timeline.append({"hour": bucket_start.strftime("%H:00"), "date": bucket_start.strftime("%Y-%m-%d"), "count": count})
            return {
                "window_hours": hours,
                "total_events": len(window_entries),
                "threat_events": len(threat_events),
                "rate_limit_events": len(rate_events),
                "allowed_events": len(allowed_events),
                "category_breakdown": category_counts,
                "severity_breakdown": severity_counts,
                "top_attacking_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
                "timeline": timeline,
            }
        except Exception as e:
            print(f"[SentinelLogger] get_stats failed: {e}", flush=True)
            return {}

    def _filter_by_severity(self, entries: list, min_severity: str) -> list:
        order = {"SAFE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_rank = order.get(min_severity.upper(), 0)
        return [e for e in entries if order.get(e.get("worst_severity", e.get("severity", "")).upper(), 0) >= min_rank]

    def _in_bucket(self, timestamp_str: str, start: datetime, end: datetime) -> bool:
        try:
            ts = datetime.fromisoformat(timestamp_str)
            return start <= ts < end
        except (ValueError, TypeError):
            return False


_cfg = get_config()
sentinel_logger = SentinelLogger(
    log_file=_cfg.LOG_FILE,
    max_bytes=_cfg.LOG_MAX_BYTES,
    backup_count=_cfg.LOG_BACKUP_COUNT,
)
