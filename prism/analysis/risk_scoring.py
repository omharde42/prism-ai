from dataclasses import dataclass, field
from typing import List, Dict, Any
from prism.analysis.types import FindingDTO, SEVERITY_WEIGHTS


@dataclass
class RiskResult:
    score: float  # 0.0 to 100.0
    risk_level: str  # LOW, MODERATE, ELEVATED, HIGH, CRITICAL
    drivers: List[str]
    dimension_scores: Dict[str, float] = field(default_factory=dict)


class RiskScoringEngine:
    """Calculates explainable engineering risk score (0-100) and multi-dimension scores combining security, complexity, architecture, testing gaps, dependency risk, change scope, confidence, and compound risk interactions."""

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
        quality_count = 0
        testing_count = 0
        complexity_count = 0

        sec_penalty = 0.0
        quality_penalty = 0.0
        testing_penalty = 0.0
        arch_penalty = 0.0
        complexity_penalty = 0.0

        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity.lower(), 1.0) * f.confidence * 7.5
            finding_points += weight
            cat = f.category.lower()
            sev = f.severity.lower()

            item_penalty = SEVERITY_WEIGHTS.get(sev, 1.0) * f.confidence * 15.0

            if cat == "security":
                sec_count += 1
                sec_penalty += item_penalty
            elif cat == "architecture":
                arch_count += 1
                arch_penalty += item_penalty
            elif cat == "dependency":
                dep_count += 1
                arch_penalty += item_penalty * 0.5
            elif cat == "code_quality":
                quality_count += 1
                quality_penalty += item_penalty
            elif cat == "testing":
                testing_count += 1
                testing_penalty += item_penalty
            elif cat == "complexity":
                complexity_count += 1
                complexity_penalty += item_penalty

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
        if testing_count > 0:
            drivers.append(f"{testing_count} Test coverage gap(s) identified")

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
            testing_penalty += 25.0
            drivers.append("Missing test coverage for substantial logic changes")
        elif testing_level == "TESTS_RECOMMENDED":
            score += 7.0
            testing_penalty += 12.0
            drivers.append("No corresponding test updates included")

        # Sensitive critical paths (auth / db migrations / infrastructure)
        sensitive_files = metrics.get("sensitive_files_changed", 0)
        if sensitive_files > 0:
            score += 10.0
            arch_penalty += 15.0
            drivers.append(f"{sensitive_files} sensitive file(s) modified (auth/DB/infra)")

        # Compound Risk Interaction Rules (Risk Correlation Engine)
        # 1. Auth/DB + Missing Tests
        if (sec_count > 0 or arch_count > 0 or sensitive_files > 0) and testing_level == "TESTS_REQUIRED":
            score += 12.0
            drivers.append("Compound High Risk: Sensitive architectural/security changes coupled with missing tests")

        # 2. High Complexity + DB Migration
        if complexity_count > 0 and arch_count > 0:
            score += 8.0
            drivers.append("COMPOUND RISK: Complex code changes paired with database schema migrations")

        # 3. Security Regression / Critical Finding + High Scope
        if crit_count > 0 and (additions > 200 or files_changed > 5):
            score += 10.0
            drivers.append("COMPOUND RISK: Critical defect identified within a large PR scope")

        # AI score modifier
        score += ai_modifier
        if ai_modifier != 0:
            sign = f"+{ai_modifier}" if ai_modifier > 0 else str(ai_modifier)
            drivers.append(f"AI intelligence risk interaction adjustment ({sign} points)")

        # Clamp score between 0 and 100
        final_score = max(0.0, min(100.0, round(score, 1)))

        # Calculate 0-100 quality dimension scores (100 = best quality, 0 = worst)
        security_dim = max(0.0, min(100.0, round(100.0 - sec_penalty, 1)))
        code_quality_dim = max(0.0, min(100.0, round(100.0 - quality_penalty, 1)))
        testing_dim = max(0.0, min(100.0, round(100.0 - testing_penalty, 1)))
        architecture_dim = max(0.0, min(100.0, round(100.0 - arch_penalty, 1)))
        maintainability_dim = max(0.0, min(100.0, round(100.0 - complexity_penalty, 1)))

        dimension_scores = {
            "security": security_dim,
            "code_quality": code_quality_dim,
            "testing": testing_dim,
            "architecture": architecture_dim,
            "maintainability": maintainability_dim,
            "overall_risk": final_score,
        }

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

        return RiskResult(
            score=final_score,
            risk_level=level,
            drivers=drivers,
            dimension_scores=dimension_scores,
        )
