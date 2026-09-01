import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header, BackgroundTasks

logger = logging.getLogger(__name__)
from sqlalchemy.orm import Session

from prism.database import get_db, PullRequest, AnalysisRun, Repository
from prism.services.github import GitHubService
from prism.analysis.orchestrator import AnalysisOrchestrator
from prism.database.models import Finding
from prism.api.schemas import (
    AnalysisRunResponse,
    ManualTriggerRequest,
    GitHubAnalyzeRequest,
    FindingFeedbackRequest,
    QualityGateResponse,
    HistoryComparisonResponse,
    FindingSchema,
)

router = APIRouter()


@router.get("/github/repos")
async def list_github_repositories():
    """Fetch user accessible GitHub repositories."""
    gh_service = GitHubService()
    try:
        repos = await gh_service.get_user_repositories()
        return repos
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch repositories: {str(e)}")


@router.get("/github/repos/{owner}/{repo}/pulls")
async def list_github_pull_requests(owner: str, repo: str, state: str = "open"):
    """Fetch Pull Requests for a given repository."""
    gh_service = GitHubService()
    try:
        prs = await gh_service.get_repository_pull_requests(owner, repo, state=state)
        return prs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch pull requests: {str(e)}")


@router.post("/analyze/github", response_model=AnalysisRunResponse)
async def analyze_github_pr(
    req: GitHubAnalyzeRequest,
    db: Session = Depends(get_db),
):
    """Fetch real GitHub PR data and run full 10-layer PRISM analysis pipeline."""
    gh_service = GitHubService()
    try:
        pr_data = await gh_service.get_pull_request(req.owner, req.repo, req.pr_number)
        raw_diff = await gh_service.get_pull_request_diff(req.owner, req.repo, req.pr_number)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"GitHub API Error: {str(e)}")

    title = pr_data.get("title", f"PR #{req.pr_number}")
    author = pr_data.get("user", {}).get("login", "unknown")
    head_branch = pr_data.get("head", {}).get("ref", "head")
    base_branch = pr_data.get("base", {}).get("ref", "main")
    commit_sha = pr_data.get("head", {}).get("sha", "head_sha")

    orchestrator = AnalysisOrchestrator(db=db)
    run = await orchestrator.run_pipeline(
        repo_owner=req.owner,
        repo_name=req.repo,
        pr_number=req.pr_number,
        pr_title=title,
        pr_author=author,
        head_branch=head_branch,
        base_branch=base_branch,
        commit_sha=commit_sha,
        raw_diff=raw_diff,
    )

    # Post GitHub Feedback (Summary, Status & Inline comments for high-confidence findings)
    try:
        status_state = "failure" if run.overall_risk_score >= 80 or run.merge_recommendation == "BLOCK" else "success"
        status_desc = f"PRISM Risk Score: {round(run.overall_risk_score)}/100 ({run.risk_level})"
        await gh_service.create_commit_status(req.owner, req.repo, commit_sha, status_state, status_desc)

        summary_md = GitHubService.format_prism_markdown_summary(run)
        await gh_service.create_issue_comment(req.owner, req.repo, req.pr_number, summary_md)

        # Inline findings publishing for high-confidence findings
        high_conf_findings = [f for f in (run.findings or []) if f.confidence >= 0.8 and f.file and f.line]
        for f in high_conf_findings[:5]:
            inline_body = f"**[PRISM {f.severity.upper()}] {f.title}**\n\n{f.description}\n\n**Recommendation:** {f.recommendation or 'Review code location.'}"
            await gh_service.create_pull_request_review_comment(req.owner, req.repo, req.pr_number, commit_sha, inline_body, f.file, f.line)
    except Exception as e:
        logger.warning(f"Failed to post GitHub PR feedback: {str(e)}")

    drivers = run.risk_score.drivers if run.risk_score else []
    pr_num = run.pull_request.pr_number if run.pull_request else None
    return AnalysisRunResponse(
        id=run.id,
        pull_request_id=run.pull_request_id,
        pr_number=pr_num,
        commit_sha=run.commit_sha,
        status=run.status,
        overall_risk_score=run.overall_risk_score,
        risk_level=run.risk_level,
        summary=run.summary,
        merge_recommendation=run.merge_recommendation,
        parent_analysis_id=run.parent_analysis_id,
        risk_trend=run.risk_trend,
        score_delta=run.score_delta,
        blast_radius=run.blast_radius,
        dimension_scores=run.dimension_scores,
        execution_metrics=run.execution_metrics,
        metrics=run.metrics,
        drivers=drivers,
        findings=run.findings,
    )


@router.get("/analyses/{analysis_id}/quality-gate", response_model=QualityGateResponse)
def evaluate_quality_gate(
    analysis_id: int,
    max_risk_score: float = 75.0,
    block_on_critical: bool = True,
    db: Session = Depends(get_db),
):
    """Evaluates configurable quality gate policy for a given PR analysis run."""
    run = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    findings = run.findings or []
    crit_count = sum(1 for f in findings if f.severity.lower() == "critical")
    high_count = sum(1 for f in findings if f.severity.lower() == "high")

    passed = True
    reasons = []

    if run.overall_risk_score > max_risk_score:
        passed = False
        reasons.append(f"Overall risk score ({run.overall_risk_score}) exceeds maximum threshold ({max_risk_score})")

    if block_on_critical and crit_count > 0:
        passed = False
        reasons.append(f"PR contains {crit_count} critical severity finding(s)")

    reason_str = "All merge quality gates passed successfully." if passed else " | ".join(reasons)
    return QualityGateResponse(
        passed=passed,
        status="PASSED" if passed else "FAILED",
        reason=reason_str,
        risk_score=run.overall_risk_score,
        critical_findings_count=crit_count,
        high_findings_count=high_count,
    )


@router.get("/analyses/{analysis_id}/history-comparison", response_model=HistoryComparisonResponse)
def get_history_comparison(analysis_id: int, db: Session = Depends(get_db)):
    """Compares current analysis run against its parent run to track risk trend and resolved/new findings."""
    run = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    prev_run = None
    if run.parent_analysis_id:
        prev_run = db.query(AnalysisRun).filter(AnalysisRun.id == run.parent_analysis_id).first()

    if not prev_run:
        return HistoryComparisonResponse(
            current_run_id=run.id,
            previous_run_id=None,
            current_score=run.overall_risk_score,
            previous_score=None,
            score_delta=0.0,
            risk_trend=run.risk_trend or "STABLE",
            resolved_findings=[],
            new_findings=[FindingSchema.model_validate(f) for f in (run.findings or [])],
            remaining_findings=[],
        )

    curr_findings = run.findings or []
    prev_findings = prev_run.findings or []

    curr_keys = {(f.category, f.file or "", f.line or 0, f.title) for f in curr_findings}
    prev_keys = {(f.category, f.file or "", f.line or 0, f.title) for f in prev_findings}

    resolved = [FindingSchema.model_validate(f) for f in prev_findings if (f.category, f.file or "", f.line or 0, f.title) not in curr_keys]
    new_items = [FindingSchema.model_validate(f) for f in curr_findings if (f.category, f.file or "", f.line or 0, f.title) not in prev_keys]
    remaining = [FindingSchema.model_validate(f) for f in curr_findings if (f.category, f.file or "", f.line or 0, f.title) in prev_keys]

    return HistoryComparisonResponse(
        current_run_id=run.id,
        previous_run_id=prev_run.id,
        current_score=run.overall_risk_score,
        previous_score=prev_run.overall_risk_score,
        score_delta=run.score_delta,
        risk_trend=run.risk_trend,
        resolved_findings=resolved,
        new_findings=new_items,
        remaining_findings=remaining,
    )


@router.post("/findings/{finding_id}/feedback")
def submit_finding_feedback(finding_id: int, req: FindingFeedbackRequest, db: Session = Depends(get_db)):
    """Allows developers to mark findings as useful, false_positive, or resolved."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.user_feedback = req.feedback
    if req.status:
        finding.status = req.status
    elif req.feedback == "false_positive":
        finding.status = "SUPPRESSED"
    elif req.feedback == "resolved":
        finding.status = "RESOLVED"

    db.commit()
    db.refresh(finding)
    return {"status": "success", "finding_id": finding.id, "user_feedback": finding.user_feedback, "finding_status": finding.status}


@router.post("/webhooks/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
):
    body_bytes = await request.body()

    if not GitHubService.verify_webhook_signature(body_bytes, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if x_github_event != "pull_request":
        return {"status": "ignored", "reason": f"Event {x_github_event} not supported"}

    payload = await request.json()
    action = payload.get("action")

    if action not in ["opened", "synchronize", "reopened"]:
        return {"status": "ignored", "reason": f"Action {action} not processed"}

    pr_data = payload.get("pull_request", {})
    repo_data = payload.get("repository", {})

    owner = repo_data.get("owner", {}).get("login")
    repo = repo_data.get("name")
    pr_number = pr_data.get("number")
    title = pr_data.get("title")
    author = pr_data.get("user", {}).get("login")
    head_branch = pr_data.get("head", {}).get("ref")
    base_branch = pr_data.get("base", {}).get("ref")
    commit_sha = pr_data.get("head", {}).get("sha")

    gh_service = GitHubService()
    raw_diff = await gh_service.get_pull_request_diff(owner, repo, pr_number)

    orchestrator = AnalysisOrchestrator(db=db)
    analysis_run = await orchestrator.run_pipeline(
        repo_owner=owner,
        repo_name=repo,
        pr_number=pr_number,
        pr_title=title,
        pr_author=author,
        head_branch=head_branch,
        base_branch=base_branch,
        commit_sha=commit_sha,
        raw_diff=raw_diff,
    )

    # Post GitHub Feedback asynchronously for webhook event
    try:
        status_state = "failure" if analysis_run.overall_risk_score >= 80 or analysis_run.merge_recommendation == "BLOCK" else "success"
        status_desc = f"PRISM Risk Score: {round(analysis_run.overall_risk_score)}/100 ({analysis_run.risk_level})"
        await gh_service.create_commit_status(owner, repo, commit_sha, status_state, status_desc)

        summary_md = GitHubService.format_prism_markdown_summary(analysis_run)
        await gh_service.create_issue_comment(owner, repo, pr_number, summary_md)
    except Exception as e:
        logger.warning(f"Failed to post webhook GitHub PR feedback: {str(e)}")

    return {"status": "success", "analysis_id": analysis_run.id, "risk_score": analysis_run.overall_risk_score}


@router.post("/analyze/trigger", response_model=AnalysisRunResponse)
async def trigger_manual_analysis(
    req: ManualTriggerRequest,
    db: Session = Depends(get_db),
):
    orchestrator = AnalysisOrchestrator(db=db)
    run = await orchestrator.run_pipeline(
        repo_owner=req.owner,
        repo_name=req.repo,
        pr_number=req.pr_number,
        pr_title=req.title,
        pr_author=req.author,
        head_branch=req.head_branch,
        base_branch=req.base_branch,
        commit_sha=req.commit_sha,
        raw_diff=req.diff,
    )

    drivers = run.risk_score.drivers if run.risk_score else []
    pr_num = run.pull_request.pr_number if run.pull_request else None
    return AnalysisRunResponse(
        id=run.id,
        pull_request_id=run.pull_request_id,
        pr_number=pr_num,
        commit_sha=run.commit_sha,
        status=run.status,
        overall_risk_score=run.overall_risk_score,
        risk_level=run.risk_level,
        summary=run.summary,
        merge_recommendation=run.merge_recommendation,
        parent_analysis_id=run.parent_analysis_id,
        risk_trend=run.risk_trend,
        score_delta=run.score_delta,
        blast_radius=run.blast_radius,
        dimension_scores=run.dimension_scores,
        execution_metrics=run.execution_metrics,
        metrics=run.metrics,
        drivers=drivers,
        findings=run.findings,
    )


@router.get("/analyses/{analysis_id}", response_model=AnalysisRunResponse)
def get_analysis_by_id(analysis_id: int, db: Session = Depends(get_db)):
    run = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")

    drivers = run.risk_score.drivers if run.risk_score else []
    pr_num = run.pull_request.pr_number if run.pull_request else None
    return AnalysisRunResponse(
        id=run.id,
        pull_request_id=run.pull_request_id,
        pr_number=pr_num,
        commit_sha=run.commit_sha,
        status=run.status,
        overall_risk_score=run.overall_risk_score,
        risk_level=run.risk_level,
        summary=run.summary,
        merge_recommendation=run.merge_recommendation,
        parent_analysis_id=run.parent_analysis_id,
        risk_trend=run.risk_trend,
        score_delta=run.score_delta,
        blast_radius=run.blast_radius,
        dimension_scores=run.dimension_scores,
        execution_metrics=run.execution_metrics,
        metrics=run.metrics,
        drivers=drivers,
        findings=run.findings,
    )
