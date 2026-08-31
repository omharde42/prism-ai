from typing import List, Optional
from pydantic import BaseModel


class FindingSchema(BaseModel):
    id: int
    category: str
    severity: str
    confidence: float
    file: Optional[str]
    line: Optional[int]
    title: str
    description: str
    impact: Optional[str]
    recommendation: Optional[str]
    evidence: Optional[str]

    class Config:
        from_attributes = True


class AnalysisRunResponse(BaseModel):
    id: int
    pull_request_id: int
    pr_number: Optional[int] = None
    commit_sha: str
    status: str
    overall_risk_score: float
    risk_level: str
    summary: Optional[str]
    merge_recommendation: str
    metrics: Optional[dict]
    drivers: List[str] = []
    findings: List[FindingSchema] = []

    class Config:
        from_attributes = True


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
