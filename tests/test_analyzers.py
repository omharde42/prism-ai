import pytest
from prism.analysis.diff_analyzer import DiffAnalyzer
from prism.analysis.code_quality import CodeQualityAnalyzer
from prism.analysis.security import SecurityAnalyzer
from prism.analysis.testing import TestingAnalyzer
from prism.analysis.complexity import ComplexityAnalyzer

SAMPLE_DIFF = """diff --git a/src/auth.py b/src/auth.py
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/src/auth.py
@@ -0,0 +1,25 @@
+def login(user, password):
+    api_key = "sk-12345678901234567890123456789012"
+    try:
+        if user == "admin":
+            if password == "1234":
+                if True:
+                    if True:
+                        if True:
+                            print("Logged in!")
+    except:
+        pass
+    # TODO: fix auth bypass
+"""


def test_diff_analyzer():
    diffs = DiffAnalyzer.parse_patch(SAMPLE_DIFF)
    assert len(diffs) == 1
    assert diffs[0].new_path == "src/auth.py"
    assert diffs[0].is_new is True
    assert diffs[0].additions > 0


def test_diff_analyzer_quoted_paths_and_plus_plus():
    quoted_diff = '''diff --git "a/src/my file.py" "b/src/my file.py"
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ "b/src/my file.py"
@@ -1,2 +1,2 @@
-old_var = 1
+--new_var = 2
++++added_var = 3
'''
    diffs = DiffAnalyzer.parse_patch(quoted_diff)
    assert len(diffs) == 1
    assert diffs[0].new_path == "src/my file.py"
    assert diffs[0].additions == 2
    assert diffs[0].deletions == 1
    chunk = diffs[0].chunks[0]
    assert chunk.added_lines[0] == (1, "--new_var = 2")
    assert chunk.added_lines[1] == (2, "+++added_var = 3")


def test_analyzers_on_sample_diff():
    diffs = DiffAnalyzer.parse_patch(SAMPLE_DIFF)

    quality_findings = CodeQualityAnalyzer.analyze(diffs)
    security_findings = SecurityAnalyzer.analyze(diffs)
    testing_res = TestingAnalyzer.analyze(diffs)
    complexity_findings = ComplexityAnalyzer.analyze(diffs)

    # Security should catch OpenAI secret
    assert any(f.category == "security" and "Secret" in f.title for f in security_findings)

    # Code quality should catch bare except & TODO & print statement
    assert len(quality_findings) >= 2

    # Testing should flag missing tests for new python file
    assert testing_res["testing_level"] in ["TESTS_RECOMMENDED", "TESTS_REQUIRED"]

    # Complexity should catch deep nesting
    assert len(complexity_findings) > 0
