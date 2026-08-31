import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


class CodeQualityAnalyzer:
    """Analyzes code quality, control flow, error handling, maintainability, breaking changes, and code smells."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            for chunk in fdiff.chunks:
                for line_no, line in chunk.added_lines:
                    s_line = line.strip()

                    # 1. Bare exception handling
                    if re.search(r"except\s*:\s*$", s_line) or re.search(r"catch\s*\(\s*(Exception|Throwable)?\s*\)\s*\{\s*\}", s_line):
                        findings.append(FindingDTO(
                            category="code_quality",
                            severity="medium",
                            confidence=0.9,
                            file=fdiff.new_path,
                            line=line_no,
                            title="Empty or Bare Exception Catch",
                            description="Catching generic exceptions silently masks errors and prevents proper error diagnostics.",
                            impact="Errors may fail silently in production, leaving system state invalid and debugging difficult.",
                            recommendation="Catch specific exception types and log or re-throw appropriately.",
                            evidence=s_line
                        ))

                    # 2. Console/Print debugging statements in production code
                    if not any(fdiff.new_path.endswith(ext) for ext in [".md", ".json", ".yaml", ".txt"]):
                        if re.search(r"console\.log\(", s_line) or re.search(r"print\(", s_line) and "test" not in fdiff.new_path.lower():
                            findings.append(FindingDTO(
                                category="code_quality",
                                severity="low",
                                confidence=0.75,
                                file=fdiff.new_path,
                                line=line_no,
                                title="Leftover Debug Statement",
                                description="Found `console.log` or `print` statement in non-test source code.",
                                impact="Can clutter production logs and potentially leak sensitive object states.",
                                recommendation="Replace debug print statements with structured logger calls or remove them.",
                                evidence=s_line
                            ))

                    # 3. TODO/FIXME left in code
                    if re.search(r"\b(TODO|FIXME|HACK|XXX)\b", s_line):
                        findings.append(FindingDTO(
                            category="code_quality",
                            severity="low",
                            confidence=0.95,
                            file=fdiff.new_path,
                            line=line_no,
                            title="Unresolved TODO / FIXME Marker",
                            description=f"Added a TODO or FIXME comment: `{s_line[:60]}`",
                            impact="Technical debt may remain unaddressed after PR merge.",
                            recommendation="Address the TODO before merging or track it in an issue tracker.",
                            evidence=s_line
                        ))

                    # 4. Potentially dangerous function / type usage
                    if re.search(r"\bany\b", s_line) and fdiff.new_path.endswith((".ts", ".tsx")):
                        if ": any" in s_line or "as any" in s_line:
                            findings.append(FindingDTO(
                                category="code_quality",
                                severity="low",
                                confidence=0.7,
                                file=fdiff.new_path,
                                line=line_no,
                                title="Unsafe TypeScript 'any' Type Usage",
                                description="Bypassing TypeScript type checking using 'any'.",
                                impact="Reduces type safety and can hide runtime type mismatch errors.",
                                recommendation="Use explicit types, generics, or `unknown` with runtime type narrowing.",
                                evidence=s_line
                            ))

        return findings
