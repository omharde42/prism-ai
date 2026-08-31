import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


COMPLEXITY_KEYWORDS = [
    r"\bif\b", r"\belif\b", r"\belse\b", r"\bfor\b", r"\bwhile\b", r"\bswitch\b",
    r"\bcase\b", r"\bcatch\b", r"\bexcept\b", r"\&\&", r"\|\|", r"\band\b", r"\bor\b"
]


class ComplexityAnalyzer:
    """Analyzes cyclomatic complexity, deeply nested logic, and high-risk structural changes."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            for chunk in fdiff.chunks:
                indent_levels: List[int] = []
                branch_count = 0

                for line_no, line in chunk.added_lines:
                    s_line = line.strip()
                    if not s_line or s_line.startswith("#") or s_line.startswith("//"):
                        continue

                    # Count leading indentation space/tabs
                    indentation = len(line) - len(line.lstrip())
                    indent_levels.append(indentation)

                    # Count decision branches
                    for kw in COMPLEXITY_KEYWORDS:
                        if re.search(kw, s_line):
                            branch_count += 1

                    # Deep indentation detection (e.g. >= 16 spaces or 4+ tabs)
                    if indentation >= 16:
                        findings.append(FindingDTO(
                            category="complexity",
                            severity="medium",
                            confidence=0.85,
                            file=fdiff.new_path,
                            line=line_no,
                            title="Excessive Nesting Depth",
                            description="Deeply nested control structures (4+ indentation levels) make code hard to read and reason about.",
                            impact="Increases risk of logic bugs and cognitive load for maintainers.",
                            recommendation="Refactor into helper functions or use early returns (guard clauses).",
                            evidence=s_line
                        ))

                # If a single diff chunk introduces high cyclomatic complexity additions (> 8 branching statements)
                if branch_count > 8:
                    findings.append(FindingDTO(
                        category="complexity",
                        severity="high",
                        confidence=0.8,
                        file=fdiff.new_path,
                        line=chunk.new_start,
                        title="High Cyclomatic Complexity Introduced",
                        description=f"Added chunk introduces {branch_count} branching points in a single block.",
                        impact="Significantly increases testing paths and likelihood of subtle edge-case bugs.",
                        recommendation="Decompose logic into smaller modular functions.",
                        evidence=f"Hunk starting at line {chunk.new_start}"
                    ))

        return findings
