import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


DEPENDENCY_FILE_PATTERNS = [
    r"requirements\.txt$", r"package\.json$", r"package-lock\.json$",
    r"pipfile(\.lock)?$", r"go\.mod$", r"cargo\.toml$", r"poetry\.lock$"
]


class DependencyRiskAnalyzer:
    """Analyzes dependency changes, supply chain security, and package updates."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            path = fdiff.new_path.lower()
            is_dep_file = any(re.search(pat, path) for pat in DEPENDENCY_FILE_PATTERNS)

            if is_dep_file:
                for chunk in fdiff.chunks:
                    for line_no, line in chunk.added_lines:
                        s_line = line.strip()

                        # Wildcard or unpinned version requirement
                        if re.search(r"[*>]=|>|latest", s_line) and not re.search(r"==|=", s_line):
                            findings.append(FindingDTO(
                                category="dependencies",
                                severity="medium",
                                confidence=0.85,
                                file=fdiff.new_path,
                                line=line_no,
                                title="Unpinned Dependency Requirement Added",
                                description="Added a dependency without exact version pinning.",
                                impact="Non-deterministic builds; future upstream updates could break production.",
                                recommendation="Pin dependencies to exact semantic versions (e.g. `package==1.2.3`).",
                                evidence=s_line
                            ))

                        # Known risky / HTTP repository source
                        if "http://" in s_line:
                            findings.append(FindingDTO(
                                category="dependencies",
                                severity="high",
                                confidence=0.95,
                                file=fdiff.new_path,
                                line=line_no,
                                title="Insecure HTTP Package Repository Source",
                                description="Package source configured over unencrypted HTTP protocol.",
                                impact="Exposes dependency resolution to Man-In-The-Middle supply chain attacks.",
                                recommendation="Use HTTPS URLs for all package repository mirrors.",
                                evidence=s_line
                            ))

        return findings
