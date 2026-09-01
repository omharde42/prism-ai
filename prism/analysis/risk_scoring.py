from dataclasses import dataclass
from typing import List, Dict, Any
from prism.analysis.types import FindingDTO, SEVERITY_WEIGHTS


@dataclass
class RiskResult:
    score: float  # 0.0 to 100.0
    risk_level: str  # LOW, MODERATE, ELEVATED, HIGH, CRITICAL
    drivers: List[str]


class RiskScoringEngine:
    """Calculates explainable engineering risk score (0-100) combining security, complexity, architecture, testing gaps, dependency risk, change scope, confidence, and critical path impact."""

    @staticmethod
    def calculate_risk(
        findings: List[FindingDTO],
        metrics: Dict[str, Any],
        ai_modifier: int = 0
    ) -> RiskResult:
        score = 0.0
        drivers: List[str] = []

        finding_points = 0.0
        sec_count = 0
        crit_count = 0
        arch_count = 0
        dep_count = 0

        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity.lower(), 1.0) * f.confidence * 7.5
            finding_points += weight
            cat = f.category.lower()
            sev = f.severity.lower()

            if cat == "security":
                sec_count += 1
            elif cat == "architecture":
                arch_count += 1
            elif cat == "dependency":
                dep_count += 1

            if sev == "critical":
                crit_count += 1

        score += min(finding_points, 55.0)

        if crit_count > 0:
            drivers.append(f"{crit_count} CRITICAL severity finding(s) detected")
        if sec_count > 0:
            drivers.append(f"{sec_count} Security vulnerability finding(s) identified")
        if arch_count > 0:
            drivers.append(f"{arch_count} Architectural impact risk(s) identified")
        if dep_count > 0:
            drivers.append(f"{dep_count} Dependency risk finding(s) identified")

        # Scope & change size
        additions = metrics.get("additions", 0)
        files_changed = metrics.get("changed_files", 0)

        if additions > 500 or files_changed > 15:
            score += 15.0
            drivers.append(f"Large change scope ({files_changed} files modified, +{additions} lines)")
        elif additions > 200 or files_changed > 7:
            score += 8.0
            drivers.append(f"Moderate PR scope ({files_changed} files modified, +{additions} lines)")

        # Testing gaps
        testing_level = metrics.get("testing_level", "NO_TESTS_REQUIRED")
        if testing_level == "TESTS_REQUIRED":
            score += 15.0
            drivers.append("Missing test coverage for substantial logic changes")
        elif testing_level == "TESTS_RECOMMENDED":
            score += 7.0
            drivers.append("No corresponding test updates included")

        # Sensitive critical paths (auth / db migrations / infrastructure)
        sensitive_files = metrics.get("sensitive_files_changed", 0)
        if sensitive_files > 0:
            score += 10.0
            drivers.append(f"{sensitive_files} sensitive file(s) modified (auth/DB/infra)")

        # Compound risk interaction check (e.g., auth/DB + missing tests)
        if (sec_count > 0 or arch_count > 0 or sensitive_files > 0) and testing_level == "TESTS_REQUIRED":
            score += 10.0
            drivers.append("Compound High Risk: Sensitive architectural/security changes coupled with missing tests")

        # AI score modifier
        score += ai_modifier
        if ai_modifier != 0:
            sign = f"+{ai_modifier}" if ai_modifier > 0 else str(ai_modifier)
            drivers.append(f"AI intelligence risk interaction adjustment ({sign} points)")

        # Clamp score between 0 and 100
        final_score = max(0.0, min(100.0, round(score, 1)))

        # Classification mapping
        if final_score >= 80.0:
            level = "CRITICAL"
        elif final_score >= 60.0:
            level = "HIGH"
        elif final_score >= 40.0:
            level = "ELEVATED"
        elif final_score >= 20.0:
            level = "MODERATE"
        else:
            level = "LOW"

        if not drivers:
            drivers.append("Small diff footprint with clean quality checks")

        return RiskResult(score=final_score, risk_level=level, drivers=drivers)
