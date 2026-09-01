import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


SECRET_PATTERNS = [
    (r"(?i)(api_key|apikey|secret_key|app_secret|auth_token|access_token|private_key|aws_secret_access_key)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']", "Potential Hardcoded Secret / API Token", "critical"),
    (r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----", "Hardcoded Private Key", "critical"),
    (r"(?i)(postgres|mysql|mongodb|redis)(\+srv)?://\w+:[^@\s]+@\w+", "Hardcoded Database Credentials URI", "critical"),
    (r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}", "GitHub Personal Access Token", "critical"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI API Key", "critical"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,}", "Slack Token", "critical"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "high"),
]

INJECTION_PATTERNS = [
    (r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*?\+\s*\w+", "Potential SQL Injection via string concatenation", "high"),
    (r"(?i)f[\"'].*?(SELECT|INSERT|UPDATE|DELETE)\s+.*?\{.*?\}", "Potential SQL Injection via f-string formatting", "high"),
    (r"(?i)\b(eval|exec)\s*\(", "Dangerous `eval` / `exec` call", "critical"),
    (r"(?i)child_process\.exec\s*\(", "Command Injection risk in Node.js child_process.exec", "critical"),
    (r"(?i)os\.system\s*\(", "Command Injection risk via os.system", "critical"),
    (r"(?i)subprocess\.(call|Popen|run)\s*\(.*?shell\s*=\s*True", "Command Injection risk via subprocess shell=True", "critical"),
]

AUTH_WEAKNESS_PATTERNS = [
    (r"(?i)verify\s*=\s*False", "Disabled SSL/TLS Certificate Verification", "high", "Disabling TLS verification leaves requests vulnerable to Man-In-The-Middle (MITM) attacks.", "Enable SSL verification in HTTP requests."),
    (r"(?i)jwt\.decode\(.*?verify\s*=\s*False", "Disabled JWT Signature Verification", "critical", "Disabling JWT verification allows token forgery and auth bypass.", "Always verify JWT signatures with appropriate public/secret keys."),
    (r"(?i)algorithms\s*=\s*\[[\"']none[\"']\]", "Insecure JWT 'none' Algorithm Allowed", "critical", "Allowing 'none' algorithm permits unauthenticated users to forge valid tokens.", "Restrict accepted JWT algorithms to secure symmetric or asymmetric algorithms (e.g. HS256, RS256)."),
    (r"(?i)allow_origins\s*=\s*\[[\"']\*[\"']\]", "Overly Permissive CORS Policy", "medium", "Wildcard CORS origin allows any website to make authenticated API requests.", "Specify trusted domain origins explicitly instead of using wildcard `*`."),
]

UNSAFE_DESERIALIZATION_PATTERNS = [
    (r"(?i)pickle\.loads\s*\(", "Unsafe Python Pickle Deserialization", "high", "Pickle deserialization of untrusted input can execute arbitrary python code.", "Use safe serialization formats like JSON or Protocol Buffers."),
    (r"(?i)yaml\.load\s*\([^,)]*\)", "Unsafe PyYAML Load", "high", "yaml.load without Loader=SafeLoader can construct arbitrary Python objects.", "Use `yaml.safe_load()` instead of `yaml.load()`."),
]

WEAK_CRYPTO_PATTERNS = [
    (r"(?i)hashlib\.(md5|sha1)\s*\(", "Weak Cryptographic Hash Function (MD5/SHA1)", "medium", "MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks.", "Use SHA-256 or SHA-512 for cryptographic hashing and bcrypt/argon2 for passwords."),
    (r"(?i)DES\b|RC4\b", "Insecure Encryption Cipher (DES/RC4)", "high", "Legacy ciphers like DES/RC4 are vulnerable to fast key recovery.", "Use AES-256-GCM or ChaCha20-Poly1305."),
]

SSRF_PATH_PATTERNS = [
    (r"\.\.\/|\.\.\\", "Potential Path Traversal Sequence", "high"),
    (r"(?i)requests\.(get|post|put|delete)\s*\(\s*user_input|url_param|req\.", "Potential Server-Side Request Forgery (SSRF)", "high"),
]


class SecurityAnalyzer:
    """Detects security vulnerabilities across 13 security dimensions."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            is_auth_file = any(kw in fdiff.new_path.lower() for kw in ["auth", "login", "permission", "jwt", "session", "security", "middleware", "oauth"])

            for chunk in fdiff.chunks:
                # 0. Security Regression Detection (Removed Security Checks)
                for line_no, del_line in chunk.deleted_lines:
                    del_s = del_line.strip()
                    if any(pat in del_s for pat in ["is_authenticated", "login_required", "check_permission", "verify_jwt", "authorize", "authenticate"]):
                        # Check if equivalent check was re-added in added lines
                        readded = any(any(pat in add_line for pat in ["is_authenticated", "login_required", "check_permission", "verify_jwt", "authorize", "authenticate"]) for _, add_line in chunk.added_lines)
                        if not readded:
                            findings.append(FindingDTO(
                                category="security",
                                severity="critical",
                                confidence=0.95,
                                file=fdiff.new_path,
                                line=line_no,
                                title="SECURITY REGRESSION: Security Authorization Check Removed",
                                description=f"A security validation or authentication check was removed: `{del_s[:80]}`",
                                impact="CRITICAL SECURITY REGRESSION: Removing authorization checks allows unauthenticated or unauthorized access to sensitive application functionality.",
                                recommendation="Restore authorization check or verify that access control is enforced by upstream middleware.",
                                evidence=del_s,
                                symbol="Authorization Check"
                            ))

                for line_no, line in chunk.added_lines:
                    s_line = line.strip()
                    if not s_line or s_line.startswith("#") or s_line.startswith("//"):
                        continue

                    # 1. Hardcoded Secrets
                    for pat_tuple in SECRET_PATTERNS:
                        pattern, title, severity = pat_tuple
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="security",
                                severity=severity,
                                confidence=0.95,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description="Found hardcoded secret, API key, or sensitive credential in added lines.",
                                impact="Credential leak allows unauthorized third-party access to production systems.",
                                recommendation="Revoke secret immediately and load credentials via environment variables or secret vaults.",
                                evidence="[REDACTED SECRET]"
                            ))

                    # 2. Injection Vulnerabilities
                    for pattern, title, severity in INJECTION_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="security",
                                severity=severity,
                                confidence=0.88,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description="Unsanitized user input concatenated into query or command execution sink.",
                                impact="Allows arbitrary command execution or database data exfiltration.",
                                recommendation="Use parameterized queries / ORM APIs and avoid raw shell execution.",
                                evidence=s_line
                            ))

                    # 3. Authentication & Authorization Weaknesses
                    for pattern, title, severity, impact, rec in AUTH_WEAKNESS_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="security",
                                severity=severity,
                                confidence=0.9,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description=f"Security weakness identified: {title}.",
                                impact=impact,
                                recommendation=rec,
                                evidence=s_line
                            ))

                    # 4. Unsafe Deserialization
                    for pattern, title, severity, impact, rec in UNSAFE_DESERIALIZATION_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="security",
                                severity=severity,
                                confidence=0.9,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description="Insecure object deserialization call detected.",
                                impact=impact,
                                recommendation=rec,
                                evidence=s_line
                            ))

                    # 5. Weak Cryptography
                    for pattern, title, severity, impact, rec in WEAK_CRYPTO_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="security",
                                severity=severity,
                                confidence=0.85,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description="Use of outdated or weak cryptographic algorithm.",
                                impact=impact,
                                recommendation=rec,
                                evidence=s_line
                            ))

                    # 6. Path Traversal & SSRF
                    for pattern, title, severity in SSRF_PATH_PATTERNS:
                        if re.search(pattern, s_line) and "test" not in fdiff.new_path.lower():
                            findings.append(FindingDTO(
                                category="security",
                                severity=severity,
                                confidence=0.8,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description="Untrusted input reached path traversal sequence or external request sink.",
                                impact="Exposes local file contents or allows unauthorized internal network probing.",
                                recommendation="Validate and sanitize paths using strict whitelist and restrict outbound HTTP destinations.",
                                evidence=s_line
                            ))

                    # 7. Sensitive Auth File Changes
                    if is_auth_file and any(kw in s_line.lower() for kw in ["token", "verify", "role", "admin", "authorize"]):
                        findings.append(FindingDTO(
                            category="security",
                            severity="medium",
                            confidence=0.75,
                            file=fdiff.new_path,
                            line=line_no,
                            title="Authentication / Authorization Code Modification",
                            description="Modifications in access control or authentication logic detected.",
                            impact="Errors in access control logic can cause unauthorized privilege escalation.",
                            recommendation="Conduct mandatory peer security review and verify unit/integration tests cover auth checks.",
                            evidence=s_line
                        ))

        return findings
