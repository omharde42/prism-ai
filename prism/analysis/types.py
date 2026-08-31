from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class FindingDTO:
    category: str  # security, code_quality, testing, complexity, architecture
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0 to 1.0
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
