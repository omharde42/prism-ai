from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class FindingSchema(BaseModel):
    id: int
    category: str
    severity: str
    confidence: float
    file: Optional[str] = None
    line: Optional[int] = None
    title: str
    description: str
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    evidence: Optional[str] = None
    status: str = "OPEN"
    symbol: Optional[str] = None
    user_feedback: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class FindingFeedbackRequest(BaseModel):
    feedback: str  # useful, false_positive, not_useful
    status: Optional[str] = None  # OPEN, RESOLVED, SUPPRESSED


class QualityGateResponse(BaseModel):
    passed: bool
    status: str  # PASSED, FAILED
    reason: str
    risk_score: float
    critical_findings_count: int
    high_findings_count: int


class HistoryComparisonResponse(BaseModel):
    current_run_id: int
    previous_run_id: Optional[int] = None
    current_score: float
    previous_score: Optional[float] = None
    score_delta: float
    risk_trend: str
    resolved_findings: List[FindingSchema] = []
    new_findings: List[FindingSchema] = []
    remaining_findings: List[FindingSchema] = []


class AnalysisRunResponse(BaseModel):
    id: int
    pull_request_id: int
    pr_number: Optional[int] = None
    commit_sha: str
    status: str
    overall_risk_score: float
    risk_level: str
    summary: Optional[str] = None
    merge_recommendation: str
    parent_analysis_id: Optional[int] = None
    risk_trend: str = "STABLE"
    score_delta: float = 0.0
    blast_radius: str = "LOW"
    dimension_scores: Optional[dict] = None
    execution_metrics: Optional[dict] = None
    metrics: Optional[dict] = None
    drivers: List[str] = []
    findings: List[FindingSchema] = []

    model_config = ConfigDict(from_attributes=True)


class ManualTriggerRequest(BaseModel):
    owner: str
    repo: str
    pr_number: int
    title: str
    author: str
    head_branch: str
    base_branch: str
    commit_sha: str
    diff: str


class GitHubAnalyzeRequest(BaseModel):
    owner: str
    repo: str
    pr_number: int
