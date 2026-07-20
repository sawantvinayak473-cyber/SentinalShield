import re


def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


SQL_INJECTION_RULES = [
    {
        "id": "SQLI-001",
        "name": "Classic OR/AND bypass",
        "category": "SQL_INJECTION",
        "severity": "CRITICAL",
        "pattern": r"('|\b)\s*(OR|AND)\s+('?\d+'?\s*=\s*'?\d+'?|'[^']*'\s*=\s*'[^']*')",
        "targets": ["url", "params", "body"],
        "description": "Attempts to bypass authentication using boolean OR/AND logic.",
    },
    {
        "id": "SQLI-002",
        "name": "SQL comment injection",
        "category": "SQL_INJECTION",
        "severity": "HIGH",
        "pattern": r"(--|\/\*|\*\/|#\s)",
        "targets": ["url", "params", "body"],
        "description": "Uses SQL comment syntax to truncate or alter queries.",
    },
    {
        "id": "SQLI-003",
        "name": "UNION-based extraction",
        "category": "SQL_INJECTION",
        "severity": "CRITICAL",
        "pattern": r"\bUNION\b\s+(ALL\s+)?\bSELECT\b",
        "targets": ["url", "params", "body"],
        "description": "UNION SELECT used to extract data from other tables.",
    },
    {
        "id": "SQLI-004",
        "name": "Dangerous SQL keywords",
        "category": "SQL_INJECTION",
        "severity": "HIGH",
        "pattern": r"\b(DROP|INSERT|UPDATE|DELETE|TRUNCATE|ALTER|EXEC|EXECUTE)\b",
        "targets": ["url", "params", "body"],
        "description": "Destructive SQL commands detected in user input.",
    },
    {
        "id": "SQLI-005",
        "name": "Blind SQLi - time delay",
        "category": "SQL_INJECTION",
        "severity": "CRITICAL",
        "pattern": r"\b(SLEEP|WAITFOR\s+DELAY|BENCHMARK|PG_SLEEP)\s*\(",
        "targets": ["url", "params", "body"],
        "description": "Time-based blind SQL injection attempt detected.",
    },
]

XSS_RULES = [
    {
        "id": "XSS-001",
        "name": "Script tag injection",
        "category": "XSS",
        "severity": "CRITICAL",
        "pattern": r"<\s*script[\s\S]*?>|<\s*/\s*script\s*>",
        "targets": ["url", "params", "body", "headers"],
        "description": "Malicious <script> tag injection attempt.",
    },
    {
        "id": "XSS-002",
        "name": "Event handler injection",
        "category": "XSS",
        "severity": "HIGH",
        "pattern": r"\b(on(error|load|click|mouseover|mouseout|keydown|keyup|focus|blur|change|submit|reset|select|unload|abort|beforeunload))\s*=",
        "targets": ["url", "params", "body"],
        "description": "JavaScript event handler injection via HTML attribute.",
    },
    {
        "id": "XSS-003",
        "name": "JavaScript protocol injection",
        "category": "XSS",
        "severity": "HIGH",
        "pattern": r"javascript\s*:",
        "targets": ["url", "params", "body", "headers"],
        "description": "JavaScript URI scheme injection attempt.",
    },
    {
        "id": "XSS-004",
        "name": "DOM manipulation functions",
        "category": "XSS",
        "severity": "MEDIUM",
        "pattern": r"\b(alert|eval|document\.(cookie|write|location)|window\.location|innerHTML|fromCharCode)\s*[\(\.]",
        "targets": ["url", "params", "body"],
        "description": "DOM manipulation or data-stealing JavaScript detected.",
    },
    {
        "id": "XSS-005",
        "name": "Encoded XSS payload",
        "category": "XSS",
        "severity": "HIGH",
        "pattern": r"(%3C|%3E|%27|%22|&lt;|&gt;|&#\d+;|&#x[0-9a-f]+;)",
        "targets": ["url", "params", "body"],
        "description": "URL or HTML encoded XSS evasion technique detected.",
    },
]

LFI_RULES = [
    {
        "id": "LFI-001",
        "name": "Path traversal sequences",
        "category": "LFI",
        "severity": "HIGH",
        "pattern": r"(\.\.\/|\.\.\\|\.\.%2[Ff]|\.\.%5[Cc]){1,}",
        "targets": ["url", "params", "body"],
        "description": "Directory traversal attempt using ../ sequences.",
    },
    {
        "id": "LFI-002",
        "name": "Sensitive system file access",
        "category": "LFI",
        "severity": "CRITICAL",
        "pattern": r"(\/etc\/(passwd|shadow|hosts|group|issue|os-release)|\/proc\/self\/(environ|cmdline|maps)|\/windows\/(system32|win\.ini|boot\.ini))",
        "targets": ["url", "params", "body"],
        "description": "Attempt to access sensitive OS files directly.",
    },
    {
        "id": "LFI-003",
        "name": "Null byte injection",
        "category": "LFI",
        "severity": "HIGH",
        "pattern": r"(%00|\\0)",
        "targets": ["url", "params", "body"],
        "description": "Null byte injection for file path truncation.",
    },
]

COMMAND_INJECTION_RULES = [
    {
        "id": "CMDI-001",
        "name": "Shell command chaining",
        "category": "COMMAND_INJECTION",
        "severity": "CRITICAL",
        "pattern": r"(;|\|{1,2}|&&)\s*(ls|cat|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl|ruby|php)",
        "targets": ["url", "params", "body"],
        "description": "Shell command chaining using semicolon or pipe operators.",
    },
    {
        "id": "CMDI-002",
        "name": "Command substitution",
        "category": "COMMAND_INJECTION",
        "severity": "CRITICAL",
        "pattern": r"(\$\(|\`)",
        "targets": ["url", "params", "body"],
        "description": "Command substitution syntax ($() or backticks) detected.",
    },
    {
        "id": "CMDI-003",
        "name": "Dangerous system commands",
        "category": "COMMAND_INJECTION",
        "severity": "HIGH",
        "pattern": r"\b(wget|curl|chmod|chown|rm\s+-|mv\s+|nc\s+|netcat|nmap|ping\s+-c)\b",
        "targets": ["url", "params", "body"],
        "description": "Known dangerous system utility command detected in input.",
    },
]

HEADER_INJECTION_RULES = [
    {
        "id": "HDRI-001",
        "name": "HTTP header injection (CRLF)",
        "category": "HEADER_INJECTION",
        "severity": "HIGH",
        "pattern": r"(%0[dD]%0[aA]|%0[aA]%0[dD]|\r\n|\n\r)",
        "targets": ["headers", "url"],
        "description": "HTTP response splitting via CRLF header injection.",
    },
    {
        "id": "HDRI-002",
        "name": "Open redirect attempt",
        "category": "HEADER_INJECTION",
        "severity": "MEDIUM",
        "pattern": r"(redirect|return|url|next|target|redir)\s*=\s*https?://",
        "targets": ["url", "params"],
        "description": "Potential open redirect to external URL detected.",
    },
]

ALL_RULES = (
    SQL_INJECTION_RULES
    + XSS_RULES
    + LFI_RULES
    + COMMAND_INJECTION_RULES
    + HEADER_INJECTION_RULES
)

COMPILED_RULES: list[dict] = []
for rule in ALL_RULES:
    compiled_rule = rule.copy()
    compiled_rule["compiled"] = _compile(rule["pattern"])
    COMPILED_RULES.append(compiled_rule)

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def get_worst_severity(severities: list[str]) -> str:
    if not severities:
        return "LOW"
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


CATEGORY_META = {
    "SQL_INJECTION": {
        "label": "SQL Injection", "short": "SQLi", "color": "#E24B4A",
        "description": "Attacker injects SQL commands to manipulate the database.",
    },
    "XSS": {
        "label": "Cross-Site Scripting", "short": "XSS", "color": "#EF9F27",
        "description": "Attacker injects scripts into pages viewed by other users.",
    },
    "LFI": {
        "label": "Local File Inclusion", "short": "LFI", "color": "#D85A30",
        "description": "Attacker reads arbitrary files from the server filesystem.",
    },
    "COMMAND_INJECTION": {
        "label": "Command Injection", "short": "CMDi", "color": "#534AB7",
        "description": "Attacker executes OS shell commands on the server.",
    },
    "HEADER_INJECTION": {
        "label": "Header Injection", "short": "HDRi", "color": "#185FA5",
        "description": "Attacker manipulates HTTP headers to hijack responses.",
    },
}
