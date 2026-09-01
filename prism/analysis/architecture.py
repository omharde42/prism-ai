import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


SCHEMA_FILE_PATTERNS = [
    r"migrations\/", r"schema\.sql", r"alembic\/", r"\.prisma$", r"schema\.prisma", r"models\.py$"
]

API_FILE_PATTERNS = [
    r"routes\.py$", r"api\/", r"controllers\/", r"endpoints\/", r"openapi\.yaml", r"swagger\.json"
]


class ArchitectureAnalyzer:
    """Analyzes architecture risk: schema migrations, API contract changes, cross-module coupling, and breaking changes."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        schema_changed = False
        api_changed = False
        modules_changed = set()

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            path = fdiff.new_path.lower()
            parts = [p for p in path.split("/") if p]
            if len(parts) > 1:
                modules_changed.add(parts[0])

            if any(re.search(pat, path) for pat in SCHEMA_FILE_PATTERNS):
                schema_changed = True

            if any(re.search(pat, path) for pat in API_FILE_PATTERNS):
                api_changed = True

            for chunk in fdiff.chunks:
                for line_no, line in chunk.added_lines:
                    s_line = line.strip()

                    # Breaking API change / route removal
                    if "DROP TABLE" in s_line.upper() or "DROP COLUMN" in s_line.upper():
                        findings.append(FindingDTO(
                            category="architecture",
                            severity="high",
                            confidence=0.9,
                            file=fdiff.new_path,
                            line=line_no,
                            title="Database Schema Destructive Modification",
                            description="Destructive DDL drop operation detected in database migration/schema file.",
                            impact="Can lead to irreversible data loss or downtime for running application instances.",
                            recommendation="Ensure multi-phase migration (deprecate column before drop) and backup plan.",
                            evidence=s_line
                        ))

        if schema_changed and api_changed:
            findings.append(FindingDTO(
                category="architecture",
                severity="high",
                confidence=0.85,
                title="Coupled Database Schema & API Contract Modification",
                description="PR contains simultaneous changes to database schema and API route contracts.",
                impact="Increases deployment order dependency and risk of API errors during rolling updates.",
                recommendation="Decouple DB schema migration from API endpoint updates if possible.",
                evidence=f"Modified files: {[f.new_path for f in file_diffs[:5]]}"
            ))

        if len(modules_changed) >= 4:
            findings.append(FindingDTO(
                category="architecture",
                severity="medium",
                confidence=0.8,
                title="Broad Cross-Module Architectural Blast Radius",
                description=f"Changes span {len(modules_changed)} top-level modules: {', '.join(list(modules_changed)[:5])}.",
                impact="High coupling across module boundaries increases regression surface area.",
                recommendation="Decompose PR into smaller module-scoped changes if applicable.",
                evidence=f"Modules: {list(modules_changed)}"
            ))

        return findings
