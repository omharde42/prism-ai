import re
from typing import List
from prism.analysis.diff_analyzer import FileDiff
from prism.analysis.types import FindingDTO


MANIFEST_FILES = [
    "package.json", "requirements.txt", "pyproject.toml", "go.mod", "cargo.toml",
    "pom.xml", "build.gradle", "gemfile", "composer.json"
]

LOCK_FILES = [
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock",
    "go.sum", "gemfile.lock", "composer.lock"
]


class DependencyAnalyzer:
    """Detects dependency modifications, unpinned dependencies, lockfile drift, and vulnerable package additions."""

    @staticmethod
    def analyze(file_diffs: List[FileDiff]) -> List[FindingDTO]:
        findings: List[FindingDTO] = []

        manifest_changed = False
        lock_changed = False

        for fdiff in file_diffs:
            if fdiff.is_binary or fdiff.is_deleted:
                continue

            fname = fdiff.new_path.split("/")[-1].lower()

            if fname in MANIFEST_FILES:
                manifest_changed = True
            if fname in LOCK_FILES:
                lock_changed = True

            # Analyze added dependency specifications
            if fname == "requirements.txt":
                for chunk in fdiff.chunks:
                    for line_no, line in chunk.added_lines:
                        s_line = line.strip()
                        if s_line and not s_line.startswith("#"):
                            # Check for unpinned dependency (e.g. "requests" without == or >=)
                            if re.match(r"^[A-Za-z0-9_\-]+$", s_line):
                                findings.append(FindingDTO(
                                    category="dependency",
                                    severity="medium",
                                    confidence=0.85,
                                    file=fdiff.new_path,
                                    line=line_no,
                                    title="Unpinned Dependency Specified in requirements.txt",
                                    description=f"Dependency `{s_line}` has no pin or version constraint specified.",
                                    impact="Unpinned dependencies cause non-deterministic builds and breaking updates upon reinstall.",
                                    recommendation=f"Pin exact version constraint (e.g. `{s_line}==1.2.3`).",
                                    evidence=s_line
                                ))

            elif fname == "package.json":
                for chunk in fdiff.chunks:
                    for line_no, line in chunk.added_lines:
                        s_line = line.strip()
                        # Detect wildcard / loose dependency versions (e.g., "*" or "^1.0.0")
                        if re.search(r"\"[^\"]+\"\s*:\s*\"(\*|\^|>|latest)\"", s_line):
                            findings.append(FindingDTO(
                                category="dependency",
                                severity="low",
                                confidence=0.8,
                                file=fdiff.new_path,
                                line=line_no,
                                title="Wildcard or Broad Version Constraint in package.json",
                                description="Loose or wildcard version range in node package manifest.",
                                impact="Broad version ranges can pull in unexpected minor/patch breaking changes.",
                                recommendation="Consider using exact version pins or stricter range definitions.",
                                evidence=s_line
                            ))

            # Detect addition of high-risk / vulnerable packages
            for chunk in fdiff.chunks:
                for line_no, line in chunk.added_lines:
                    s_line = line.strip()
                    if fname in MANIFEST_FILES:
                        if re.search(r"(?i)\b(eval|shelljs|event-stream|flatmap-stream)\b", s_line):
                            findings.append(FindingDTO(
                                category="dependency",
                                severity="high",
                                confidence=0.88,
                                file=fdiff.new_path,
                                line=line_no,
                                title="Addition of High-Risk / Problematic Package",
                                description="Manifest introduces a package known for supply-chain risks or malicious incidents.",
                                impact="Increases vulnerability to supply-chain attacks or dangerous execution models.",
                                recommendation="Audit package source and replace with well-maintained, standard library alternatives.",
                                evidence=s_line
                            ))

        # Check lockfile drift (manifest changed without lockfile update)
        if manifest_changed and not lock_changed:
            findings.append(FindingDTO(
                category="dependency",
                severity="medium",
                confidence=0.9,
                title="Lockfile Drift Detected (Manifest Modified Without Lockfile)",
                description="Dependency manifest (e.g. package.json, requirements.txt) was modified, but no lockfile update was included.",
                impact="Build environments may install different resolved dependency versions, leading to non-reproducible builds.",
                recommendation="Run package manager install command and commit updated lockfile (e.g., package-lock.json).",
                evidence="Manifest modified without corresponding lockfile change."
            ))

        return findings
