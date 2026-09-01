import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


DB_MIGRATION_PATTERNS = [
    (r"(?i)ALTER TABLE\s+\w+\s+DROP", "Database Schema Column/Table Deletion", "high", "Dropping columns or tables in production DB schema creates immediate breaking changes for running app instances.", "Use multi-phase zero-downtime migration strategy (deprecate -> stop read/write -> drop in subsequent deployment)."),
    (r"(?i)DROP TABLE|DROP DATABASE", "Destructive Schema Migration (DROP TABLE/DATABASE)", "critical", "Destructive schema deletion can cause irreversible data loss and downtime.", "Ensure database backup is verified and verify table drop is intended."),
    (r"(?i)CREATE INDEX", "Database Index Creation", "low", "Creating indexes on large production tables can lock tables or increase write latency.", "Verify index creation uses `CONCURRENTLY` (PostgreSQL) or non-blocking flags for large tables."),
    (r"(?i)(alembic|migrations|flyway|liquibase)", "Database Schema Migration Modification", "medium", "Database migrations affect shared database state across application versions.", "Ensure backwards-compatible schema changes and test migrations against realistic datasets."),
]

API_CONTRACT_PATTERNS = [
    (r"(?i)@router\.(get|post|put|delete|patch)\b", "API Endpoint Route Definition Modified", "medium", "Changing API route signatures or contract schemas can break client integrations.", "Maintain backwards-compatible API versions or provide clear deprecation headers."),
    (r"(?i)class\s+\w+(Schema|DTO|Request|Response)\b", "API Contract Schema Modified", "low", "Modifying request/response schema definitions can impact client validation.", "Verify schema changes do not remove required response fields."),
]

CORE_LOGIC_PATTERNS = [
    (r"(?i)(payment|billing|stripe|paypal|checkout|pricing)", "Core Business Logic Change (Payment / Billing)", "high", "Modifying core billing/payment flow can lead to financial inaccuracies or failed transactions.", "Require explicit test coverage for edge cases and financial transaction rollbacks."),
    (r"(?i)(dockerfile|docker-compose|\.github\/workflows|terraform|k8s|kubernetes|helm)", "Infrastructure & CI/CD Pipeline Modification", "high", "Modifications to CI/CD workflows, Dockerfiles, or infrastructure configuration impact build and deployment pipelines.", "Test deployment configuration changes in isolated staging environments prior to merging."),
]


class ArchitectureAnalyzer:
    """Detects dangerous architectural changes: API contract shifts, schema migrations, core logic changes, and infrastructure modifications."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            path_lower = fdiff.new_path.lower()

            # 1. Database Schema Migrations
            is_migration_file = any(kw in path_lower for kw in ["migration", "alembic", "schema", "db/"])
            if is_migration_file:
                for chunk in fdiff.chunks:
                    for line_no, line in chunk.added_lines:
                        s_line = line.strip()
                        for pattern, title, severity, impact, rec in DB_MIGRATION_PATTERNS:
                            if re.search(pattern, s_line):
                                findings.append(FindingDTO(
                                    category="architecture",
                                    severity=severity,
                                    confidence=0.85,
                                    file=fdiff.new_path,
                                    line=line_no,
                                    title=title,
                                    description=f"Architectural change detected in schema migration: {title}.",
                                    impact=impact,
                                    recommendation=rec,
                                    evidence=s_line
                                ))

            # 2. API Contract Changes
            is_api_file = any(kw in path_lower for kw in ["route", "controller", "endpoint", "api/", "schema", "graphql"])
            if is_api_file:
                for chunk in fdiff.chunks:
                    for line_no, line in chunk.added_lines:
                        s_line = line.strip()
                        for pattern, title, severity, impact, rec in API_CONTRACT_PATTERNS:
                            if re.search(pattern, s_line):
                                findings.append(FindingDTO(
                                    category="architecture",
                                    severity=severity,
                                    confidence=0.8,
                                    file=fdiff.new_path,
                                    line=line_no,
                                    title=title,
                                    description="Modification to external API interface or contract schema.",
                                    impact=impact,
                                    recommendation=rec,
                                    evidence=s_line
                                ))

            # 3. File-level Infrastructure & Core Business Logic Path Matches
            for pattern, title, severity, impact, rec in CORE_LOGIC_PATTERNS:
                if re.search(pattern, path_lower):
                    findings.append(FindingDTO(
                        category="architecture",
                        severity=severity,
                        confidence=0.85,
                        file=fdiff.new_path,
                        line=1,
                        title=title,
                        description=f"Architectural risk identified in file path: {title}.",
                        impact=impact,
                        recommendation=rec,
                        evidence=f"File path matched: {fdiff.new_path}"
                    ))

            # Line-level checks for core logic patterns
            for chunk in fdiff.chunks:
                for line_no, line in chunk.added_lines:
                    s_line = line.strip()
                    for pattern, title, severity, impact, rec in CORE_LOGIC_PATTERNS:
                        if not re.search(pattern, path_lower) and re.search(pattern, s_line):
                            findings.append(FindingDTO(
                                category="architecture",
                                severity=severity,
                                confidence=0.82,
                                file=fdiff.new_path,
                                line=line_no,
                                title=title,
                                description=f"Architectural risk identified: {title}.",
                                impact=impact,
                                recommendation=rec,
                                evidence=s_line
                            ))

        return findings
