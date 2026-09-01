import pytest
from prism.analysis.diff_analyzer import DiffAnalyzer
from prism.analysis.security import SecurityAnalyzer
from prism.analysis.architecture import ArchitectureAnalyzer
from prism.analysis.dependency import DependencyAnalyzer
from prism.analysis.testing import TestingAnalyzer
from prism.analysis.complexity import ComplexityAnalyzer
from prism.analysis.deduplicator import FindingDeduplicator
from prism.analysis.risk_scoring import RiskScoringEngine
from prism.analysis.types import FindingDTO
from prism.services.github import GitHubService


def test_security_analyzer_expanded():
    diff = """diff --git a/prism/auth.py b/prism/auth.py
new file mode 100644
--- /dev/null
+--- b/prism/auth.py
@@ -0,0 +1,5 @@
+api_key = "sk-12345678901234567890123456789012"
+requests.get("https://internal.api", verify=False)
+exec(user_input)
"""
    file_diffs = DiffAnalyzer.parse_patch(diff)
    findings = SecurityAnalyzer.analyze(file_diffs)

    categories = [f.category for f in findings]
    severities = [f.severity for f in findings]
    titles = [f.title for f in findings]

    assert "security" in categories
    assert any(s in ["high", "critical"] for s in severities)
    assert any("Secret" in t or "API Token" in t for t in titles)
    assert any("SSL" in t or "TLS" in t for t in titles)


def test_architecture_analyzer():
    diff = """diff --git a/migrations/001_initial.sql b/migrations/001_initial.sql
new file mode 100644
--- /dev/null
+--- b/migrations/001_initial.sql
@@ -0,0 +1,2 @@
+ALTER TABLE users DROP COLUMN email;
+DROP TABLE audit_logs;
"""
    file_diffs = DiffAnalyzer.parse_patch(diff)
    findings = ArchitectureAnalyzer.analyze(file_diffs)

    assert len(findings) >= 2
    assert all(f.category == "architecture" for f in findings)
    assert any(f.severity == "critical" for f in findings)


def test_dependency_analyzer():
    diff = """diff --git a/requirements.txt b/requirements.txt
index 111111..222222 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 fastapi==0.100.0
+unpinned-package
"""
    file_diffs = DiffAnalyzer.parse_patch(diff)
    findings = DependencyAnalyzer.analyze(file_diffs)

    assert any(f.category == "dependency" for f in findings)
    assert any("Lockfile Drift" in f.title or "Unpinned" in f.title for f in findings)


def test_finding_deduplicator_priority_sorting():
    f1 = FindingDTO(
        category="security", severity="critical", confidence=0.9,
        title="SQL Injection", description="Desc", file="db.py", line=10
    )
    f2 = FindingDTO(
        category="security", severity="critical", confidence=0.9,
        title="SQL Injection", description="Desc", file="db.py", line=10
    )
    f3 = FindingDTO(
        category="code_quality", severity="low", confidence=0.7,
        title="Leftover Debug", description="Desc", file="app.py", line=5
    )

    deduped = FindingDeduplicator.deduplicate_and_filter([f1, f2, f3])
    assert len(deduped) == 2
    assert deduped[0].category == "security"
    assert deduped[0].priority_score > deduped[1].priority_score


def test_risk_scoring_compound_interaction():
    findings = [
        FindingDTO(
            category="security", severity="critical", confidence=0.9,
            title="Hardcoded Secret", description="Desc", file="auth.py", line=1
        )
    ]
    metrics = {
        "additions": 350,
        "changed_files": 10,
        "sensitive_files_changed": 2,
        "testing_level": "TESTS_REQUIRED"
    }

    result = RiskScoringEngine.calculate_risk(findings, metrics, ai_modifier=5)
    assert result.score >= 70.0
    assert result.risk_level in ["HIGH", "CRITICAL"]
    assert any("Compound High Risk" in d for d in result.drivers)


@pytest.mark.asyncio
async def test_github_service_fetch_user_repos():
    gh = GitHubService()
    repos = await gh.get_user_repositories()
    assert isinstance(repos, list)
