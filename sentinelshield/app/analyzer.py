from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import urllib.parse
from typing import Any
from flask import Request
from app.rules import COMPILED_RULES, SEVERITY_ORDER, get_worst_severity


@dataclass
class ThreatMatch:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    surface: str
    matched_value: str
    pattern: str


@dataclass
class AnalysisResult:
    timestamp: str
    ip_address: str
    method: str
    path: str
    is_threat: bool
    threats: list = field(default_factory=list)
    worst_severity: str = "SAFE"
    categories: set = field(default_factory=set)
    request_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "ip_address": self.ip_address,
            "method": self.method,
            "path": self.path,
            "is_threat": self.is_threat,
            "worst_severity": self.worst_severity,
            "categories": sorted(list(self.categories)),
            "threat_count": len(self.threats),
            "threats": [
                {
                    "rule_id": t.rule_id,
                    "rule_name": t.rule_name,
                    "category": t.category,
                    "severity": t.severity,
                    "surface": t.surface,
                    "matched_value": t.matched_value,
                }
                for t in self.threats
            ],
            "request_data": self.request_data,
        }


class RequestAnalyzer:
    MAX_SNIPPET_LENGTH = 200
    INSPECTED_HEADERS = [
        "User-Agent", "Referer", "X-Forwarded-For", "Cookie",
        "Authorization", "Accept-Language", "Content-Type",
    ]

    def __init__(self):
        self.rules = COMPILED_RULES

    def analyze(self, request: Request) -> AnalysisResult:
        ip = self._extract_ip(request)
        surfaces = self._extract_surfaces(request)
        threats = self._scan_surfaces(surfaces)
        return self._build_result(request=request, ip=ip, surfaces=surfaces, threats=threats)

    def _extract_ip(self, request: Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def _extract_surfaces(self, request: Request) -> dict[str, str]:
        surfaces = {}
        raw_url = request.url or ""
        surfaces["url"] = self._decode(raw_url)

        if request.args:
            param_parts = []
            for key, value in request.args.items(multi=True):
                param_parts.append(self._decode(key))
                param_parts.append(self._decode(value))
            surfaces["params"] = " ".join(param_parts)
        else:
            surfaces["params"] = ""

        body_parts = []
        if request.form:
            for key, value in request.form.items(multi=True):
                body_parts.append(self._decode(key))
                body_parts.append(self._decode(value))
        json_data = request.get_json(silent=True, force=False)
        if json_data:
            body_parts.append(self._flatten_json(json_data))
        surfaces["body"] = " ".join(body_parts)

        header_parts = []
        for header_name in self.INSPECTED_HEADERS:
            value = request.headers.get(header_name, "")
            if value:
                header_parts.append(self._decode(value))
        surfaces["headers"] = " ".join(header_parts)

        try:
            raw_body = request.get_data(as_text=False)
            raw_text = raw_body.decode("utf-8", errors="ignore")
            surfaces["raw"] = self._decode(raw_text)
        except Exception:
            surfaces["raw"] = ""

        return surfaces

    def _decode(self, value: str) -> str:
        if not value:
            return ""
        try:
            decoded_once = urllib.parse.unquote_plus(str(value))
            decoded_twice = urllib.parse.unquote_plus(decoded_once)
            return decoded_twice
        except Exception:
            return str(value)

    def _flatten_json(self, data: Any, depth: int = 0) -> str:
        if depth > 10:
            return ""
        if isinstance(data, str):
            return self._decode(data)
        if isinstance(data, (int, float, bool)):
            return str(data)
        if isinstance(data, dict):
            parts = []
            for key, value in data.items():
                parts.append(self._flatten_json(key, depth + 1))
                parts.append(self._flatten_json(value, depth + 1))
            return " ".join(parts)
        if isinstance(data, list):
            return " ".join(self._flatten_json(item, depth + 1) for item in data)
        return ""

    def _scan_surfaces(self, surfaces: dict[str, str]) -> list[ThreatMatch]:
        matches = []
        seen_rule_ids: set[str] = set()

        for surface_name, surface_value in surfaces.items():
            if not surface_value or not surface_value.strip():
                continue
            for rule in self.rules:
                if surface_name not in rule["targets"]:
                    continue
                if rule["id"] in seen_rule_ids:
                    continue
                match = rule["compiled"].search(surface_value)
                if match:
                    seen_rule_ids.add(rule["id"])
                    matched_text = surface_value[
                        max(0, match.start() - 20): match.end() + 20
                    ].strip()
                    if len(matched_text) > self.MAX_SNIPPET_LENGTH:
                        matched_text = matched_text[:self.MAX_SNIPPET_LENGTH] + "…"
                    threat = ThreatMatch(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        surface=surface_name,
                        matched_value=matched_text,
                        pattern=rule["pattern"],
                    )
                    matches.append(threat)
        return matches

    def _build_result(self, request, ip, surfaces, threats) -> AnalysisResult:
        timestamp = datetime.now(timezone.utc).isoformat()
        is_threat = len(threats) > 0
        severities = [t.severity for t in threats]
        worst = get_worst_severity(severities) if severities else "SAFE"
        categories = {t.category for t in threats}
        request_snapshot = {
            name: (value[:500] + "…" if len(value) > 500 else value)
            for name, value in surfaces.items()
            if value
        }
        return AnalysisResult(
            timestamp=timestamp,
            ip_address=ip,
            method=request.method,
            path=request.path,
            is_threat=is_threat,
            threats=threats,
            worst_severity=worst,
            categories=categories,
            request_data=request_snapshot,
        )


analyzer = RequestAnalyzer()
