from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header, BackgroundTasks
from sqlalchemy.orm import Session

from prism.database import get_db, PullRequest, AnalysisRun, Repository
from prism.services.github import GitHubService
from prism.analysis.orchestrator import AnalysisOrchestrator
from prism.api.schemas import AnalysisRunResponse, ManualTriggerRequest, RealPRAnalyzeRequest

router = APIRouter()


@router.get("/github/repos")
async def list_github_repos(limit: int = 30):
    gh_service = GitHubService()
    repos = await gh_service.list_user_repositories(limit=limit)
    return [
        {
            "id": r.get("id"),
            "full_name": r.get("full_name"),
            "owner": r.get("owner", {}).get("login"),
            "name": r.get("name"),
            "private": r.get("private", False),
            "default_branch": r.get("default_branch", "main"),
        }
        for r in repos
    ]


@router.get("/github/repos/{owner}/{repo}/pulls")
async def list_github_pulls(owner: str, repo: str, state: str = "open", limit: int = 30):
    gh_service = GitHubService()
    try:
        pulls = await gh_service.list_pull_requests(owner, repo, state=state, limit=limit)
        return [
            {
                "number": p.get("number"),
                "title": p.get("title"),
                "author": p.get("user", {}).get("login"),
                "head_branch": p.get("head", {}).get("ref"),
                "base_branch": p.get("base", {}).get("ref"),
                "commit_sha": p.get("head", {}).get("sha"),
                "state": p.get("state"),
            }
            for p in pulls
        ]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch PRs from GitHub: {str(e)}")


@router.post("/github/analyze", response_model=AnalysisRunResponse)
async def analyze_real_github_pr(
    req: RealPRAnalyzeRequest,
    db: Session = Depends(get_db),
):
    gh_service = GitHubService()
    try:
        pr_data = await gh_service.get_pull_request(req.owner, req.repo, req.pr_number)
        raw_diff = await gh_service.get_pull_request_diff(req.owner, req.repo, req.pr_number)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not retrieve PR #{req.pr_number} from GitHub: {str(e)}")

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

    drivers = run.risk_score.drivers if run.risk_score else []
    pr_num = run.pull_request.pr_number if run.pull_request else req.pr_number
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
        metrics=run.metrics,
        drivers=drivers,
        findings=run.findings,
    )


@router.post("/webhooks/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
):
    body_bytes = await request.body()

    # Verify signature
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
        metrics=run.metrics,
        drivers=drivers,
        findings=run.findings,
    )
