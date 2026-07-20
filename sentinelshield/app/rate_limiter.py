from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Optional
from app.config_loader import get_config


@dataclass
class RateLimitResult:
    ip_address: str
    is_blocked: bool = False
    is_rate_limited: bool = False
    request_count: int = 0
    limit: int = 0
    window_seconds: int = 0
    block_reason: str = ""
    blocked_until: Optional[datetime] = None
    retry_after: int = 0

    @property
    def should_block(self) -> bool:
        return self.is_blocked or self.is_rate_limited

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "is_blocked": self.is_blocked,
            "is_rate_limited": self.is_rate_limited,
            "request_count": self.request_count,
            "limit": self.limit,
            "window_seconds": self.window_seconds,
            "block_reason": self.block_reason,
            "blocked_until": self.blocked_until.isoformat() if self.blocked_until else None,
            "retry_after": self.retry_after,
        }


@dataclass
class IPRecord:
    timestamps: list = field(default_factory=list)
    is_blocked: bool = False
    blocked_until: Optional[datetime] = None
    block_reason: str = ""
    total_requests: int = 0
    total_violations: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class SlidingWindowRateLimiter:
    def __init__(self, max_requests=20, window_seconds=60, block_duration_seconds=300):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.block_duration = timedelta(seconds=block_duration_seconds)
        self._records: dict[str, IPRecord] = defaultdict(IPRecord)
        self._lock = Lock()

    def check(self, ip_address: str) -> RateLimitResult:
        with self._lock:
            now = datetime.now(timezone.utc)
            record = self._records[ip_address]
            record.total_requests += 1
            record.last_seen = now
            if record.first_seen is None:
                record.first_seen = now

            if record.is_blocked:
                if now < record.blocked_until:
                    remaining = int((record.blocked_until - now).total_seconds())
                    return RateLimitResult(
                        ip_address=ip_address, is_blocked=True,
                        request_count=len(record.timestamps),
                        limit=self.max_requests, window_seconds=self.window_seconds,
                        block_reason=record.block_reason,
                        blocked_until=record.blocked_until, retry_after=remaining,
                    )
                else:
                    record.is_blocked = False
                    record.blocked_until = None
                    record.block_reason = ""
                    record.timestamps = []

            window_start = now - timedelta(seconds=self.window_seconds)
            record.timestamps = [ts for ts in record.timestamps if ts > window_start]
            current_count = len(record.timestamps)

            if current_count >= self.max_requests:
                record.is_blocked = True
                record.blocked_until = now + self.block_duration
                record.block_reason = (
                    f"Exceeded {self.max_requests} requests in {self.window_seconds}s window"
                )
                record.total_violations += 1
                remaining = int(self.block_duration.total_seconds())
                return RateLimitResult(
                    ip_address=ip_address, is_rate_limited=True,
                    request_count=current_count, limit=self.max_requests,
                    window_seconds=self.window_seconds,
                    block_reason=record.block_reason,
                    blocked_until=record.blocked_until, retry_after=remaining,
                )

            record.timestamps.append(now)
            return RateLimitResult(
                ip_address=ip_address, is_blocked=False, is_rate_limited=False,
                request_count=current_count + 1,
                limit=self.max_requests, window_seconds=self.window_seconds,
            )

    def unblock(self, ip_address: str) -> bool:
        with self._lock:
            if ip_address not in self._records:
                return False
            record = self._records[ip_address]
            if not record.is_blocked:
                return False
            record.is_blocked = False
            record.blocked_until = None
            record.block_reason = ""
            record.timestamps = []
            return True

    def get_status(self, ip_address: str) -> dict:
        with self._lock:
            now = datetime.now(timezone.utc)
            if ip_address not in self._records:
                return {"ip_address": ip_address, "known": False, "is_blocked": False,
                        "request_count_in_window": 0, "total_requests": 0, "total_violations": 0}
            record = self._records[ip_address]
            window_start = now - timedelta(seconds=self.window_seconds)
            in_window = sum(1 for ts in record.timestamps if ts > window_start)
            remaining = 0
            if record.is_blocked and record.blocked_until:
                remaining = max(0, int((record.blocked_until - now).total_seconds()))
            return {
                "ip_address": ip_address, "known": True,
                "is_blocked": record.is_blocked,
                "blocked_until": record.blocked_until.isoformat() if record.blocked_until else None,
                "retry_after_seconds": remaining,
                "block_reason": record.block_reason,
                "request_count_in_window": in_window,
                "limit": self.max_requests,
                "window_seconds": self.window_seconds,
                "total_requests": record.total_requests,
                "total_violations": record.total_violations,
                "first_seen": record.first_seen.isoformat() if record.first_seen else None,
                "last_seen": record.last_seen.isoformat() if record.last_seen else None,
            }

    def get_all_blocked(self) -> list[dict]:
        with self._lock:
            now = datetime.now(timezone.utc)
            blocked_list = []
            for ip, record in self._records.items():
                if record.is_blocked and record.blocked_until and now < record.blocked_until:
                    remaining = int((record.blocked_until - now).total_seconds())
                    blocked_list.append({
                        "ip_address": ip,
                        "blocked_until": record.blocked_until.isoformat(),
                        "retry_after_seconds": remaining,
                        "block_reason": record.block_reason,
                        "total_requests": record.total_requests,
                        "total_violations": record.total_violations,
                    })
            return sorted(blocked_list, key=lambda x: x["retry_after_seconds"])

    def get_top_ips(self, n: int = 10) -> list[dict]:
        with self._lock:
            now = datetime.now(timezone.utc)
            window_start = now - timedelta(seconds=self.window_seconds)
            ip_stats = []
            for ip, record in self._records.items():
                in_window = sum(1 for ts in record.timestamps if ts > window_start)
                ip_stats.append({
                    "ip_address": ip,
                    "requests_in_window": in_window,
                    "total_requests": record.total_requests,
                    "total_violations": record.total_violations,
                    "is_blocked": record.is_blocked,
                })
            return sorted(ip_stats, key=lambda x: x["total_requests"], reverse=True)[:n]

    def get_stats(self) -> dict:
        with self._lock:
            now = datetime.now(timezone.utc)
            total_ips = len(self._records)
            blocked_ips = sum(
                1 for r in self._records.values()
                if r.is_blocked and r.blocked_until and now < r.blocked_until
            )
            total_requests = sum(r.total_requests for r in self._records.values())
            total_violations = sum(r.total_violations for r in self._records.values())
            return {
                "total_tracked_ips": total_ips,
                "currently_blocked_ips": blocked_ips,
                "total_requests_seen": total_requests,
                "total_violations": total_violations,
                "config": {
                    "max_requests": self.max_requests,
                    "window_seconds": self.window_seconds,
                    "block_duration_seconds": int(self.block_duration.total_seconds()),
                },
            }

    def cleanup(self) -> int:
        with self._lock:
            now = datetime.now(timezone.utc)
            stale_threshold = now - timedelta(hours=1)
            to_remove = []
            for ip, record in self._records.items():
                if record.is_blocked:
                    continue
                if record.last_seen and record.last_seen < stale_threshold:
                    to_remove.append(ip)
            for ip in to_remove:
                del self._records[ip]
            return len(to_remove)


_cfg = get_config()
rate_limiter = SlidingWindowRateLimiter(
    max_requests=_cfg.RATE_LIMIT_MAX_REQUESTS,
    window_seconds=_cfg.RATE_LIMIT_WINDOW_SECONDS,
    block_duration_seconds=_cfg.RATE_LIMIT_BLOCK_DURATION,
)
