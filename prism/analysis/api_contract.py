import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO

API_BREAKING_PATTERNS = [
    (r"(?i)@router\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]", "API Route Signature Changed or Defined", "medium"),
    (r"(?i)class\s+\w+(Request|Response|DTO|Schema)\b", "API Request/Response Model Modification", "low"),
]


class APIContractEngine:
    """Detects API endpoint route changes, breaking contract modifications, and payload alterations."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            path_lower = fdiff.new_path.lower()
            is_api_file = any(kw in path_lower for kw in ["route", "controller", "endpoint", "api/", "schema", "graphql"])
            if not is_api_file:
                continue

            for chunk in fdiff.chunks:
                # Detect removed API routes (breaking change!)
                for line_no, deleted_line in chunk.deleted_lines:
                    del_s = deleted_line.strip()
                    route_match = re.search(r"@router\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]", del_s, re.IGNORECASE)
                    if route_match:
                        method, path = route_match.group(1).upper(), route_match.group(2)
                        # Check if route was re-added in added lines
                        was_readded = any(f"{method.lower()}" in al.lower() and path in al for _, al in chunk.added_lines)
                        if not was_readded:
                            findings.append(FindingDTO(
                                category="architecture",
                                severity="high",
                                confidence=0.88,
                                file=fdiff.new_path,
                                line=line_no,
                                title=f"Potential Breaking API Change: Route Deletion ({method} {path})",
                                description=f"API route `{method} {path}` was removed from controller schema.",
                                impact="External client applications calling this endpoint will receive 404 Not Found errors.",
                                recommendation="Deprecate API endpoint gracefully before complete deletion or issue major version bump.",
                                evidence=del_s,
                                symbol=f"{method} {path}"
                            ))

                # Analyze added lines for API changes
                for line_no, added_line in chunk.added_lines:
                    s_line = added_line.strip()
                    for pattern, title, severity in API_BREAKING_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="architecture",
                                severity=severity,
                                confidence=0.8,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description="Modification to API contract interface or request/response payload definition.",
                                impact="API consumers may experience payload validation mismatches if non-optional fields were added.",
                                recommendation="Verify client backward-compatibility and update API documentation / OpenAPI schema.",
                                evidence=s_line,
                                symbol="API Endpoint"
                            ))

        return findings
