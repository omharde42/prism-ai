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

    model_config = ConfigDict(from_attributes=True)


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
