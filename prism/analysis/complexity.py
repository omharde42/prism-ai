import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


COMPLEXITY_KEYWORDS = [
    r"\bif\b", r"\belif\b", r"\belse\b", r"\bfor\b", r"\bwhile\b", r"\bswitch\b",
    r"\bcase\b", r"\bcatch\b", r"\bexcept\b", r"\&\&", r"\|\|", r"\band\b", r"\bor\b"
]


class ComplexityAnalyzer:
    """Calculates PR complexity using multiple factors: files, lines, logical branching, module boundaries, and nesting depth."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        total_files = len(file_diffs)
        total_additions = sum(f.additions for f in file_diffs if not f.is_binary)
        modules_affected = set()

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            parts = fdiff.new_path.split("/")
            if len(parts) > 1:
                modules_affected.add(parts[0])

            for chunk in fdiff.chunks:
                indent_levels: List[int] = []
                branch_count = 0

                for line_no, line in chunk.added_lines:
                    s_line = line.strip()
                    if not s_line or s_line.startswith("#") or s_line.startswith("//"):
                        continue

                    # Indentation level
                    indentation = len(line) - len(line.lstrip())
                    indent_levels.append(indentation)

                    # Decision branches
                    for kw in COMPLEXITY_KEYWORDS:
                        if re.search(kw, s_line):
                            branch_count += 1

                    # Deep indentation check (>= 16 spaces)
                    if indentation >= 16:
                        findings.append(FindingDTO(
                            category="complexity",
                            severity="medium",
                            confidence=0.85,
                            file=fdiff.new_path,
                            line=line_no,
                            title="Excessive Deep Nesting Depth",
                            description="Deeply nested control structures (4+ indentation levels) significantly increase cognitive load.",
                            impact="Increases risk of logic bugs and makes code harder to maintain and test.",
                            recommendation="Refactor using guard clauses or split into dedicated helper functions.",
                            evidence=s_line
                        ))

                # High cyclomatic complexity block
                if branch_count > 8:
                    findings.append(FindingDTO(
                        category="complexity",
                        severity="high",
                        confidence=0.8,
                        file=fdiff.new_path,
                        line=chunk.new_start,
                        title="High Cyclomatic Complexity Introduced in Diff Chunk",
                        description=f"Diff chunk adds {branch_count} branching points in a single block.",
                        impact="Multiplies necessary test execution paths and edge case risks.",
                        recommendation="Decompose complex logic block into smaller, single-responsibility functions.",
                        evidence=f"Hunk starting at line {chunk.new_start}"
                    ))

        # Cross-module architectural complexity
        if len(modules_affected) >= 5:
            findings.append(FindingDTO(
                category="complexity",
                severity="medium",
                confidence=0.85,
                title="Broad Cross-Module PR Changes",
                description=f"PR touches {len(modules_affected)} distinct top-level modules ({', '.join(list(modules_affected)[:4])}...).",
                impact="High cross-module coupling increases blast radius and risk of unintended side effects.",
                recommendation="Split large multi-module PRs into smaller, focused pull requests.",
                evidence=f"Modules affected: {list(modules_affected)}"
            ))

        # Massive PR footprint
        if total_additions > 600 or total_files > 20:
            findings.append(FindingDTO(
                category="complexity",
                severity="high",
                confidence=0.9,
                title="High Cognitive Load PR Scope",
                description=f"PR modifies {total_files} files with +{total_additions} lines added.",
                impact="Large PRs lead to reviewer fatigue, missed defects, and merge conflict risks.",
                recommendation="Break down into smaller atomic pull requests.",
                evidence=f"Files: {total_files}, Additions: +{total_additions}"
            ))

        return findings
