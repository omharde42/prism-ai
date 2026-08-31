import pytest
from fastapi.testclient import TestClient
from prism.main import app

client = TestClient(app)


def test_dashboard_route():
    response = client.get("/")
    assert response.status_code == 200
    assert "PRISM AI" in response.text
    assert "Overall Risk Score" in response.text


def test_trigger_and_get_analysis_api():
    diff_content = """diff --git a/app.py b/app.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/app.py
@@ -0,0 +1,5 @@
+def test_func():
+    key = "sk-12345678901234567890123456789012"
+    print("test")
+"""
    payload = {
        "owner": "org",
        "repo": "app",
        "pr_number": 10,
        "title": "Add test func",
        "author": "alice",
        "head_branch": "feat",
        "base_branch": "main",
        "commit_sha": "c101010",
        "diff": diff_content,
    }

    resp = client.post("/api/analyze/trigger", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] > 0
    assert data["overall_risk_score"] > 0
    assert len(data["findings"]) > 0

    analysis_id = data["id"]
    get_resp = client.get(f"/api/analyses/{analysis_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["id"] == analysis_id
