from dataclasses import dataclass
from typing import List, Dict, Any
from prism.analysis.types import FindingDTO


@dataclass
class RiskResult:
    score: float  # 0.0 to 100.0
    risk_level: str  # LOW, MODERATE, ELEVATED, HIGH, CRITICAL
    drivers: List[str]


class RiskScoringEngine:
    """Calculates explainable engineering risk score (0-100) and risk level."""

    @staticmethod
    def calculate_risk(
        findings: List[FindingDTO],
        metrics: Dict[str, Any],
        ai_modifier: int = 0
    ) -> RiskResult:
        score = 0.0
        drivers: List[str] = []

        # 1. Severity weight accumulated from findings
        severity_weights = {
            "critical": 30.0,
            "high": 15.0,
            "medium": 7.0,
            "low": 2.0
        }

        finding_points = 0.0
        sec_count = 0
        crit_count = 0

        for f in findings:
            weight = severity_weights.get(f.severity.lower(), 2.0) * f.confidence
            finding_points += weight
            if f.category == "security":
                sec_count += 1
            if f.severity.lower() == "critical":
                crit_count += 1

        score += min(finding_points, 60.0)

        if crit_count > 0:
            drivers.append(f"{crit_count} CRITICAL severity finding(s) detected")
        if sec_count > 0:
            drivers.append(f"{sec_count} Security risk finding(s) identified")

        # 2. Scope & change size weights
        additions = metrics.get("additions", 0)
        files_changed = metrics.get("changed_files", 0)

        if additions > 500 or files_changed > 15:
            score += 15.0
            drivers.append(f"Large change scope ({files_changed} files modified, +{additions} lines)")
        elif additions > 200 or files_changed > 7:
            score += 8.0
            drivers.append(f"Moderate PR scope ({files_changed} files modified, +{additions} lines)")

        # 3. Testing gaps
        testing_level = metrics.get("testing_level", "NO_TESTS_REQUIRED")
        if testing_level == "TESTS_REQUIRED":
            score += 15.0
            drivers.append("Missing test coverage for substantial logic changes")
        elif testing_level == "TESTS_RECOMMENDED":
            score += 7.0
            drivers.append("No corresponding test updates included")

        # 4. Sensitive scope (auth / db migrations / infrastructure)
        sensitive_files = metrics.get("sensitive_files_changed", 0)
        if sensitive_files > 0:
            score += 10.0
            drivers.append(f"{sensitive_files} security/auth/DB sensitive file(s) modified")

        # 5. AI score modifier
        score += ai_modifier

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
            drivers.append("Small diff with clean static quality checks")

        return RiskResult(score=final_score, risk_level=level, drivers=drivers)
