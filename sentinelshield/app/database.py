import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean,
    DateTime, ForeignKey, Index, func, desc, and_, or_,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from app.config_loader import get_config

Base = declarative_base()


class RequestEvent(Base):
    __tablename__ = "request_events"
    id                = Column(Integer, primary_key=True, autoincrement=True)
    timestamp         = Column(DateTime(timezone=True), nullable=False, index=True)
    ip_address        = Column(String(45), nullable=False, index=True)
    method            = Column(String(10), nullable=False)
    path              = Column(Text, nullable=False)
    is_threat         = Column(Boolean, nullable=False, default=False, index=True)
    worst_severity    = Column(String(10), nullable=False, default="SAFE", index=True)
    event_type        = Column(String(30), nullable=False, default="REQUEST_ALLOWED")
    categories_json   = Column(Text, nullable=False, default="[]")
    request_data_json = Column(Text, nullable=False, default="{}")
    was_rate_limited  = Column(Boolean, nullable=False, default=False)
    rate_limit_count  = Column(Integer, nullable=True)
    threats = relationship("ThreatDetail", back_populates="event", cascade="all, delete-orphan", lazy="select")
    __table_args__ = (
        Index("idx_ip_timestamp", "ip_address", "timestamp"),
        Index("idx_severity_timestamp", "worst_severity", "timestamp"),
    )

    @property
    def categories(self) -> list:
        try:
            return json.loads(self.categories_json)
        except (json.JSONDecodeError, TypeError):
            return []

    @categories.setter
    def categories(self, value: list):
        self.categories_json = json.dumps(value if value else [])

    @property
    def request_data(self) -> dict:
        try:
            return json.loads(self.request_data_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    @request_data.setter
    def request_data(self, value: dict):
        self.request_data_json = json.dumps(value if value else {})

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ip_address": self.ip_address,
            "method": self.method,
            "path": self.path,
            "is_threat": self.is_threat,
            "worst_severity": self.worst_severity,
            "event_type": self.event_type,
            "categories": self.categories,
            "was_rate_limited": self.was_rate_limited,
            "rate_limit_count": self.rate_limit_count,
            "threat_count": len(self.threats) if self.threats else 0,
        }


class ThreatDetail(Base):
    __tablename__ = "threat_details"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    event_id      = Column(Integer, ForeignKey("request_events.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id       = Column(String(20),  nullable=False)
    rule_name     = Column(String(100), nullable=False)
    category      = Column(String(30),  nullable=False, index=True)
    severity      = Column(String(10),  nullable=False)
    surface       = Column(String(20),  nullable=False)
    matched_value = Column(Text, nullable=True)
    event = relationship("RequestEvent", back_populates="threats")

    def to_dict(self) -> dict:
        return {
            "id": self.id, "event_id": self.event_id,
            "rule_id": self.rule_id, "rule_name": self.rule_name,
            "category": self.category, "severity": self.severity,
            "surface": self.surface, "matched_value": self.matched_value,
        }


class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    ip_address      = Column(String(45), nullable=False, unique=True, index=True)
    blocked_at      = Column(DateTime(timezone=True), nullable=False)
    blocked_until   = Column(DateTime(timezone=True), nullable=False)
    reason          = Column(Text, nullable=True)
    violation_count = Column(Integer, nullable=False, default=1)
    is_active       = Column(Boolean, nullable=False, default=True, index=True)

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.blocked_until

    def to_dict(self) -> dict:
        now = datetime.now(timezone.utc)
        remaining = max(0, int((self.blocked_until - now).total_seconds()))
        return {
            "id": self.id, "ip_address": self.ip_address,
            "blocked_at": self.blocked_at.isoformat(),
            "blocked_until": self.blocked_until.isoformat(),
            "reason": self.reason, "violation_count": self.violation_count,
            "is_active": self.is_active, "retry_after_seconds": remaining,
            "is_expired": self.is_expired(),
        }


class DashboardStat(Base):
    __tablename__ = "dashboard_stats"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    stat_key   = Column(String(60), nullable=False, unique=True, index=True)
    stat_value = Column(Text, nullable=False, default="0")
    updated_at = Column(DateTime(timezone=True), nullable=False)

    def get_value(self) -> int:
        try:
            return int(self.stat_value)
        except (ValueError, TypeError):
            return 0


class DatabaseManager:
    def __init__(self, database_url: str):
        self._engine = create_engine(database_url, connect_args={"check_same_thread": False}, echo=False)
        self._SessionFactory = sessionmaker(bind=self._engine, autocommit=False, autoflush=False)
        self._lock = threading.Lock()
        Base.metadata.create_all(self._engine)
        self._init_stats()

    @contextmanager
    def _session(self):
        session = self._SessionFactory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def save_event(self, analysis_result, rate_result=None) -> Optional[int]:
        try:
            with self._session() as session:
                has_threat     = analysis_result.is_threat
                has_rate_limit = rate_result is not None and rate_result.should_block
                if has_threat and has_rate_limit:
                    event_type = "REQUEST_BLOCKED"
                elif has_threat:
                    event_type = "THREAT_DETECTED"
                elif has_rate_limit:
                    event_type = "RATE_LIMITED"
                else:
                    event_type = "REQUEST_ALLOWED"
                try:
                    ts = datetime.fromisoformat(analysis_result.timestamp)
                except (ValueError, TypeError):
                    ts = datetime.now(timezone.utc)
                event = RequestEvent(
                    timestamp=ts, ip_address=analysis_result.ip_address,
                    method=analysis_result.method, path=analysis_result.path,
                    is_threat=analysis_result.is_threat,
                    worst_severity=analysis_result.worst_severity,
                    event_type=event_type,
                    categories_json=json.dumps(sorted(list(analysis_result.categories))),
                    request_data_json=json.dumps(analysis_result.request_data),
                    was_rate_limited=has_rate_limit,
                    rate_limit_count=rate_result.request_count if rate_result else None,
                )
                session.add(event)
                session.flush()
                for threat in analysis_result.threats:
                    detail = ThreatDetail(
                        event_id=event.id, rule_id=threat.rule_id,
                        rule_name=threat.rule_name, category=threat.category,
                        severity=threat.severity, surface=threat.surface,
                        matched_value=threat.matched_value,
                    )
                    session.add(detail)
                event_id = event.id
            self._increment_stats(
                is_threat=has_threat, is_rate_limited=has_rate_limit,
                severity=analysis_result.worst_severity,
                categories=list(analysis_result.categories),
            )
            return event_id
        except Exception as e:
            print(f"[DatabaseManager] save_event failed: {e}", flush=True)
            return None

    def get_recent_events(self, limit=50, offset=0, severity_filter=None,
                          event_type_filter=None, ip_filter=None, hours=None,
                          threats_only=False) -> dict:
        try:
            with self._session() as session:
                query = session.query(RequestEvent)
                if threats_only:
                    query = query.filter(RequestEvent.is_threat == True)
                if severity_filter:
                    sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                    min_rank = sev_rank.get(severity_filter.upper(), 1)
                    allowed = [s for s, r in sev_rank.items() if r >= min_rank]
                    query = query.filter(RequestEvent.worst_severity.in_(allowed))
                if event_type_filter:
                    query = query.filter(RequestEvent.event_type == event_type_filter)
                if ip_filter:
                    query = query.filter(RequestEvent.ip_address == ip_filter)
                if hours:
                    since = datetime.now(timezone.utc) - timedelta(hours=hours)
                    query = query.filter(RequestEvent.timestamp >= since)
                total = query.count()
                events = query.order_by(desc(RequestEvent.timestamp)).limit(limit).offset(offset).all()
                return {"events": [e.to_dict() for e in events], "total": total, "limit": limit, "offset": offset}
        except Exception as e:
            print(f"[DatabaseManager] get_recent_events failed: {e}", flush=True)
            return {"events": [], "total": 0, "limit": limit, "offset": offset}

    def get_event_detail(self, event_id: int) -> Optional[dict]:
        try:
            with self._session() as session:
                event = session.query(RequestEvent).get(event_id)
                if not event:
                    return None
                result = event.to_dict()
                result["threats"] = [t.to_dict() for t in event.threats]
                result["request_data"] = event.request_data
                return result
        except Exception as e:
            print(f"[DatabaseManager] get_event_detail failed: {e}", flush=True)
            return None

    def block_ip(self, ip_address: str, blocked_until: datetime, reason: str = "") -> bool:
        try:
            with self._session() as session:
                existing = session.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
                now = datetime.now(timezone.utc)
                if existing:
                    existing.blocked_until = blocked_until
                    existing.blocked_at = now
                    existing.reason = reason
                    existing.is_active = True
                    existing.violation_count += 1
                else:
                    session.add(BlockedIP(
                        ip_address=ip_address, blocked_at=now,
                        blocked_until=blocked_until, reason=reason,
                        violation_count=1, is_active=True,
                    ))
            return True
        except Exception as e:
            print(f"[DatabaseManager] block_ip failed: {e}", flush=True)
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        try:
            with self._session() as session:
                record = session.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
                if record:
                    record.is_active = False
            return True
        except Exception as e:
            print(f"[DatabaseManager] unblock_ip failed: {e}", flush=True)
            return False

    def get_blocked_ips(self) -> list[dict]:
        try:
            with self._session() as session:
                now = datetime.now(timezone.utc)
                records = (session.query(BlockedIP)
                    .filter(BlockedIP.is_active == True, BlockedIP.blocked_until > now)
                    .order_by(desc(BlockedIP.blocked_at)).all())
                return [r.to_dict() for r in records]
        except Exception as e:
            print(f"[DatabaseManager] get_blocked_ips failed: {e}", flush=True)
            return []

    def get_dashboard_stats(self) -> dict:
        try:
            with self._session() as session:
                stats = session.query(DashboardStat).all()
                return {s.stat_key: s.get_value() for s in stats}
        except Exception as e:
            print(f"[DatabaseManager] get_dashboard_stats failed: {e}", flush=True)
            return {}

    def get_category_breakdown(self, hours: int = 24) -> list[dict]:
        try:
            with self._session() as session:
                since = datetime.now(timezone.utc) - timedelta(hours=hours)
                details = (session.query(ThreatDetail.category, func.count(ThreatDetail.id).label("count"))
                    .join(RequestEvent).filter(RequestEvent.timestamp >= since)
                    .group_by(ThreatDetail.category).order_by(desc("count")).all())
                return [{"category": row.category, "count": row.count} for row in details]
        except Exception as e:
            print(f"[DatabaseManager] get_category_breakdown failed: {e}", flush=True)
            return []

    def get_hourly_timeline(self, hours: int = 24) -> list[dict]:
        try:
            timeline = []
            for h in range(hours, 0, -1):
                bucket_start = datetime.now(timezone.utc) - timedelta(hours=h)
                bucket_end   = datetime.now(timezone.utc) - timedelta(hours=h - 1)
                with self._session() as session:
                    count = (session.query(func.count(RequestEvent.id))
                        .filter(RequestEvent.is_threat == True,
                                RequestEvent.timestamp >= bucket_start,
                                RequestEvent.timestamp < bucket_end).scalar())
                timeline.append({
                    "hour": bucket_start.strftime("%H:00"),
                    "date": bucket_start.strftime("%Y-%m-%d"),
                    "label": bucket_start.strftime("%d/%m %H:00"),
                    "count": count or 0,
                })
            return timeline
        except Exception as e:
            print(f"[DatabaseManager] get_hourly_timeline failed: {e}", flush=True)
            return []

    def _init_stats(self):
        stat_keys = [
            "total_requests", "total_threats", "total_rate_limits", "total_blocked",
            "category_SQL_INJECTION", "category_XSS", "category_LFI",
            "category_COMMAND_INJECTION", "category_HEADER_INJECTION",
        ]
        try:
            with self._session() as session:
                for key in stat_keys:
                    exists = session.query(DashboardStat).filter(DashboardStat.stat_key == key).first()
                    if not exists:
                        session.add(DashboardStat(stat_key=key, stat_value="0", updated_at=datetime.now(timezone.utc)))
        except Exception as e:
            print(f"[DatabaseManager] _init_stats failed: {e}", flush=True)

    def _increment_stats(self, is_threat, is_rate_limited, severity, categories):
        try:
            with self._lock:
                with self._session() as session:
                    now = datetime.now(timezone.utc)
                    def _inc(key):
                        stat = session.query(DashboardStat).filter(DashboardStat.stat_key == key).first()
                        if stat:
                            stat.stat_value = str(stat.get_value() + 1)
                            stat.updated_at = now
                    _inc("total_requests")
                    if is_threat:
                        _inc("total_threats")
                        for cat in categories:
                            _inc(f"category_{cat}")
                    if is_rate_limited:
                        _inc("total_rate_limits")
                    if is_threat and is_rate_limited:
                        _inc("total_blocked")
        except Exception as e:
            print(f"[DatabaseManager] _increment_stats failed: {e}", flush=True)


_cfg = get_config()
db_manager = DatabaseManager(database_url=_cfg.SQLALCHEMY_DATABASE_URI)
