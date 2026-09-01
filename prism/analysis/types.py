from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}


@dataclass
class FindingDTO:
    category: str  # security, code_quality, testing, complexity, architecture, dependency
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0 to 1.0
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    evidence: Optional[str] = None
    status: str = "OPEN"
    symbol: Optional[str] = None
    user_feedback: Optional[str] = None

    @property
    def priority_score(self) -> float:
        """Calculate finding priority score = Severity Weight * Confidence."""
        weight = SEVERITY_WEIGHTS.get(self.severity.lower(), 1.0)
        return round(weight * self.confidence, 3)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["priority_score"] = self.priority_score
        return data
