import re
from typing import List, Dict, Any
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


TEST_FILE_PATTERNS = [
    r"test_",
    r"_test",
    r"\.spec\.",
    r"\.test\.",
    r"tests\/",
    r"testing\/",
]


class TestingAnalyzer:
    """Analyzes test coverage gaps, missing tests for new logic, and test requirement levels."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> Dict[str, Any]:
        """
        Returns a dict containing:
        - testing_level: "NO_TESTS_REQUIRED" | "TESTS_RECOMMENDED" | "TESTS_REQUIRED"
        - findings: List[FindingDTO]
        - summary: Dict[str, int]
        """
        findings: List[FindingDTO] = []

        code_files_changed: List[FileDiff] = []
        test_files_changed: List[FileDiff] = []
        doc_or_config_only = True

        for fdiff in file_diffs:
            if fdiff.is_binary:
                continue

            path = fdiff.new_path.lower()
            is_test_file = any(re.search(pat, path) for pat in TEST_FILE_PATTERNS)

            if is_test_file:
                if not fdiff.is_deleted:
                    test_files_changed.append(fdiff)
            else:
                ext = path.split(".")[-1] if "." in path else ""
                if ext in ["py", "ts", "js", "go", "java", "rs", "cpp", "c", "rb", "php", "cs"]:
                    doc_or_config_only = False
                    code_files_changed.append(fdiff)

        # Assessment logic
        if doc_or_config_only:
            return {
                "testing_level": "NO_TESTS_REQUIRED",
                "findings": [],
                "summary": {
                    "code_files_changed": 0,
                    "test_files_changed": len(test_files_changed),
                    "testing_required": False
                }
            }

        total_code_additions = sum(f.additions for f in code_files_changed)
        has_test_changes = len(test_files_changed) > 0

        testing_level = "NO_TESTS_REQUIRED"

        if total_code_additions >= 10 and not has_test_changes:
            if total_code_additions > 80:
                testing_level = "TESTS_REQUIRED"
                findings.append(FindingDTO(
                    category="testing",
                    severity="high",
                    confidence=0.9,
                    title="Significant Code Changes Without Tests",
                    description=f"PR modifies {len(code_files_changed)} source files with {total_code_additions} additions, but includes no test file modifications.",
                    impact="High risk of regressions and unverified edge cases entering main codebase.",
                    recommendation="Add automated unit or integration test cases for new/modified logic.",
                    evidence=f"Changed files: {[f.new_path for f in code_files_changed[:5]]}"
                ))
            else:
                testing_level = "TESTS_RECOMMENDED"
                findings.append(FindingDTO(
                    category="testing",
                    severity="medium",
                    confidence=0.8,
                    title="New Code Introduced Without Corresponding Tests",
                    description=f"Added {total_code_additions} lines across {len(code_files_changed)} files without updated tests.",
                    impact="Reduces overall test coverage over time.",
                    recommendation="Consider adding unit tests for key branch conditions.",
                    evidence=f"Changed files: {[f.new_path for f in code_files_changed[:3]]}"
                ))

        return {
            "testing_level": testing_level,
            "findings": findings,
            "summary": {
                "code_files_changed": len(code_files_changed),
                "test_files_changed": len(test_files_changed),
                "code_additions": total_code_additions,
                "has_tests": has_test_changes,
            }
        }
