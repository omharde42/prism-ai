import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


SECRET_PATTERNS = [
    (r"(?i)(api_key|apikey|secret_key|app_secret|auth_token|access_token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']", "Potential Hardcoded Secret / API Token"),
    (r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----", "Hardcoded Private Key"),
    (r"(?i)postgres://\w+:\w+@\w+", "Hardcoded Database Credentials URI"),
    (r"(?i)mongodb(\+srv)?://\w+:\w+@\w+", "Hardcoded MongoDB Credentials URI"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI API Key"),
]

INJECTION_PATTERNS = [
    (r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*?\+\s*\w+", "Potential SQL Injection via string concatenation"),
    (r"(?i)eval\s*\(", "Dangerous `eval()` call"),
    (r"(?i)exec\s*\(", "Dangerous `exec()` call"),
    (r"(?i)child_process\.exec\s*\(", "Command Injection risk in Node.js child_process.exec"),
    (r"(?i)os\.system\s*\(", "Command Injection risk via os.system"),
    (r"(?i)subprocess\.call\s*\(.*?shell\s*=\s*True", "Command Injection risk via subprocess shell=True"),
]

PATH_TRAVERSAL_PATTERNS = [
    (r"\.\.\/|\.\.\\", "Potential Path Traversal sequence"),
]


class SecurityAnalyzer:
    """Detects security vulnerabilities: hardcoded secrets, injection, auth weaknesses, path traversal."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            # Check if file is config/auth related
            is_auth_file = any(kw in fdiff.new_path.lower() for kw in ["auth", "login", "permission", "jwt", "session", "security", "middleware"])

            for chunk in fdiff.chunks:
                for line_no, line in chunk.added_lines:
                    s_line = line.strip()

                    # 1. Hardcoded Secrets
                    for pattern, title in SECRET_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="security",
                                severity="critical",
                                confidence=0.95,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description="Found suspicious credential or API key hardcoded in added source lines.",
                                impact="Exposing secrets in repository history allows unauthorized account access and potential breach.",
                                recommendation="Move credentials to environment variables or secret management services (Vault, AWS Secrets Manager).",
                                evidence="[REDACTED SECRET]"
                            ))

                    # 2. Injection Vulnerabilities
                    for pattern, title in INJECTION_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="security",
                                severity="high",
                                confidence=0.88,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description="Unsanitized string concatenation or unsafe execution detected.",
                                impact="Attackers could inject malicious input to execute arbitrary commands or manipulate DB queries.",
                                recommendation="Use parameterized queries / ORM methods and avoid shell execution with user inputs.",
                                evidence=s_line
                            ))

                    # 3. Path Traversal
                    FILE_SINK_PATTERNS = [
                        r"open\s*\(", r"read_file\b", r"write_file\b", r"send_file\b",
                        r"fs\.(readFile|writeFile|createReadStream|createWriteStream)",
                        r"file_get_contents\b", r"fopen\b"
                    ]
                    for pattern, title in PATH_TRAVERSAL_PATTERNS:
                        if re.search(pattern, s_line) and "test" not in fdiff.new_path.lower():
                            if any(re.search(sink, s_line) for sink in FILE_SINK_PATTERNS):
                                findings.append(FindingDTO(
                                    category="security",
                                    severity="high",
                                    confidence=0.8,
                                    file=fdiff.new_path,
                                    line=line_no,
                                    title=title,
                                    description="Relative path traversal sequence reaching a file operation sink.",
                                    impact="Allows unauthorized reading or writing of files outside intended directories.",
                                    recommendation="Sanitize user-provided filenames using `os.path.basename` or path validation logic.",
                                    evidence=s_line
                                ))

                    # 4. Authentication logic modification alert
                    if is_auth_file and any(kw in s_line.lower() for kw in ["token", "verify", "role", "admin", "authorize"]):
                        findings.append(FindingDTO(
                            category="security",
                            severity="medium",
                            confidence=0.75,
                            file=fdiff.new_path,
                            line=line_no,
                            title="Authentication or Authorization Logic Modified",
                            description="Modifications detected in security-sensitive authentication/authorization codebase.",
                            impact="Flaws in access control logic can result in privilege escalation or auth bypass.",
                            recommendation="Ensure security review and integration tests cover all branch conditions.",
                            evidence=s_line
                        ))

        return findings
