import pytest
from prism.analysis.ai_review import AIReviewer
from prism.analysis.deduplicator import FindingDeduplicator
from prism.analysis.types import FindingDTO


@pytest.mark.asyncio
async def test_ai_reviewer_fallback():
    reviewer = AIReviewer(api_key=None)
    findings = [
        FindingDTO(category="security", severity="critical", confidence=0.95, title="Secret leak", description="Secret exposed")
    ]
    pr_meta = {"title": "Fix auth", "author": "dev", "head_branch": "feat", "base_branch": "main"}
    res = await reviewer.analyze_pr(pr_meta, "diff content", findings)

    assert res["merge_recommendation"] == "BLOCK"
    assert "critical" in res["summary"]


def test_deduplicator():
    f1 = FindingDTO(category="security", severity="critical", confidence=0.9, title="Secret Leak", description="Desc 1", file="auth.py", line=10)
    f2 = FindingDTO(category="security", severity="critical", confidence=0.95, title="Secret Leak", description="Desc 2", file="auth.py", line=10)
    f3 = FindingDTO(category="code_quality", severity="low", confidence=0.2, title="Low Conf", description="Desc 3")  # Below 0.5

    result = FindingDeduplicator.deduplicate_and_filter([f1, f2, f3], confidence_threshold=0.5)

    assert len(result) == 1
    assert result[0].confidence == 0.95  # Keeps higher confidence duplicate
