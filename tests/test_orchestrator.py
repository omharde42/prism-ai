import pytest
from prism.database import Base, engine, SessionLocal
from prism.analysis.orchestrator import AnalysisOrchestrator
from prism.analysis.risk_scoring import RiskScoringEngine
from prism.analysis.types import FindingDTO

TEST_DIFF = """diff --git a/src/server.py b/src/server.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/server.py
@@ -0,0 +1,15 @@
+import os
+def handle_login(req):
+    key = "sk-abcdef12345678901234567890123456"
+    cmd = "ping " + req.host
+    os.system(cmd)
+    try:
+        pass
+    except:
+        print("error")
+"""


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_risk_scoring():
    findings = [
        FindingDTO(category="security", severity="critical", confidence=0.95, title="Secret Leak", description="Desc"),
        FindingDTO(category="security", severity="high", confidence=0.9, title="Command Injection", description="Desc"),
    ]
    metrics = {"additions": 100, "changed_files": 2, "testing_level": "TESTS_RECOMMENDED", "sensitive_files_changed": 1}
    res = RiskScoringEngine.calculate_risk(findings, metrics, ai_modifier=0)

    assert res.score >= 50.0
    assert res.risk_level in ["ELEVATED", "HIGH", "CRITICAL"]
    assert len(res.drivers) >= 2


@pytest.mark.asyncio
async def test_pipeline_orchestration(db_session):
    orchestrator = AnalysisOrchestrator(db=db_session, openai_api_key=None)

    run = await orchestrator.run_pipeline(
        repo_owner="testowner",
        repo_name="testrepo",
        pr_number=42,
        pr_title="Add server login",
        pr_author="testdev",
        head_branch="feature",
        base_branch="main",
        commit_sha="abc1234",
        raw_diff=TEST_DIFF,
    )

    assert run.status == "completed"
    assert run.overall_risk_score > 0
    assert len(run.findings) >= 2
    assert run.risk_score is not None
    assert len(run.risk_score.drivers) > 0
