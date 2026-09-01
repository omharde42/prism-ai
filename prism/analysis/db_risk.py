import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO

DB_DESTRUCTIVE_PATTERNS = [
    (r"(?i)DROP\s+TABLE\s+(\w+)", "Destructive Migration: DROP TABLE", "critical", "Dropping tables causes permanent loss of production data and immediate application breakage.", "Verify table is deprecated and backup exists before dropping in production."),
    (r"(?i)ALTER\s+TABLE\s+(\w+)\s+DROP\s+COLUMN\s+(\w+)", "Destructive Migration: DROP COLUMN", "high", "Dropping columns directly causes errors in running application instances that still read or write the column.", "Use a 2-stage release: first stop using column in code, then drop column in a later deployment."),
    (r"(?i)ALTER\s+TABLE\s+(\w+)\s+RENAME\s+TO\s+(\w+)", "Database Table Rename", "high", "Renaming a database table breaks existing queries from running service instances.", "Create a database view or dual-write strategy during migration window."),
]

DB_PERFORMANCE_LOCKING_PATTERNS = [
    (r"(?i)CREATE\s+INDEX\s+(?!CONCURRENTLY)", "Non-Concurrent Index Creation on Table", "medium", "Creating an index without `CONCURRENTLY` in PostgreSQL locks the table against writes during build.", "Use `CREATE INDEX CONCURRENTLY` for zero-downtime index creation on active production tables."),
    (r"(?i)ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+.*?NOT\s+NULL(?!\s+DEFAULT)", "Adding NOT NULL Column Without Default", "high", "Adding a NOT NULL column without a default value fails on existing table rows.", "Provide a default value or add column as nullable, backfill data, then set NOT NULL."),
]


class DatabaseRiskEngine:
    """Specialized engine for database schema changes, dangerous migrations, and locking risks."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            path_lower = fdiff.new_path.lower()
            is_db_file = any(kw in path_lower for kw in ["migration", "alembic", "flyway", "liquibase", "schema.sql", "db/"])

            if not is_db_file and not fdiff.new_path.endswith(".sql"):
                continue

            for chunk in fdiff.chunks:
                for line_no, line in chunk.added_lines:
                    s_line = line.strip()

                    for pattern, title, severity, impact, rec in DB_DESTRUCTIVE_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="architecture",
                                severity=severity,
                                confidence=0.92,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description=f"Database risk detected: {title}.",
                                impact=impact,
                                recommendation=rec,
                                evidence=s_line,
                                symbol="DB Migration"
                            ))

                    for pattern, title, severity, impact, rec in DB_PERFORMANCE_LOCKING_PATTERNS:
                        if re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="architecture",
                                severity=severity,
                                confidence=0.85,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description=f"Potential database locking or schema constraint issue: {title}.",
                                impact=impact,
                                recommendation=rec,
                                evidence=s_line,
                                symbol="DB Index/Constraint"
                            ))

        return findings
