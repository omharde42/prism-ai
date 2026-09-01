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

SENSITIVE_PATH_PATTERNS = [
    r"auth", r"security", r"payment", r"billing", r"migration", r"db\/", r"schema"
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

        # Skip testing requirements for trivial documentation or configuration PRs
        if doc_or_config_only or not code_files_changed:
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

        # Detect modifications to sensitive / core business logic modules
        sensitive_code_files = [
            f for f in code_files_changed
            if any(re.search(pat, f.new_path.lower()) for pat in SENSITIVE_PATH_PATTERNS)
        ]

        testing_level = "NO_TESTS_REQUIRED"

        if sensitive_code_files and not has_test_changes:
            testing_level = "TESTS_REQUIRED"
            findings.append(FindingDTO(
                category="testing",
                severity="high",
                confidence=0.92,
                title="Critical Auth / DB / Billing Logic Changed Without Integration Tests",
                description=f"PR modifies sensitive core module(s) ({', '.join([f.new_path for f in sensitive_code_files[:3]])}) without adding or updating test cases.",
                impact="High engineering risk of unexpected regressions in critical production paths.",
                recommendation="Add integration tests covering positive, negative, and edge case scenarios before merging.",
                evidence=f"Sensitive files modified: {[f.new_path for f in sensitive_code_files]}"
            ))
        elif total_code_additions >= 80 and not has_test_changes:
            testing_level = "TESTS_REQUIRED"
            findings.append(FindingDTO(
                category="testing",
                severity="high",
                confidence=0.9,
                title="Significant Code Additions Without Automated Tests",
                description=f"PR modifies {len(code_files_changed)} source files with +{total_code_additions} additions, but includes no test modifications.",
                impact="High risk of unverified edge cases and regressions entering production.",
                recommendation="Add unit or integration tests for new business logic.",
                evidence=f"Changed files: {[f.new_path for f in code_files_changed[:5]]}"
            ))
        elif total_code_additions >= 15 and not has_test_changes:
            testing_level = "TESTS_RECOMMENDED"
            findings.append(FindingDTO(
                category="testing",
                severity="medium",
                confidence=0.8,
                title="New Code Introduced Without Corresponding Unit Tests",
                description=f"Added {total_code_additions} lines across {len(code_files_changed)} code files without test updates.",
                impact="Reduces overall repository test coverage over time.",
                recommendation="Add targeted unit tests covering new function execution paths.",
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
