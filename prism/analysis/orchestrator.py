import datetime
import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from prism.database.models import Repository, PullRequest, AnalysisRun, Finding, RiskScore
from prism.analysis.diff_analyzer import DiffAnalyzer
from prism.analysis.code_quality import CodeQualityAnalyzer
from prism.analysis.security import SecurityAnalyzer
from prism.analysis.testing import TestingAnalyzer
from prism.analysis.complexity import ComplexityAnalyzer
from prism.analysis.architecture import ArchitectureAnalyzer
from prism.analysis.dependency_risk import DependencyRiskAnalyzer
from prism.analysis.ai_review import AIReviewer
from prism.analysis.deduplicator import FindingDeduplicator
from prism.analysis.risk_scoring import RiskScoringEngine
from prism.analysis.types import FindingDTO

logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """Orchestrates end-to-end PR analysis pipeline."""

    def __init__(self, db: Session, openai_api_key: Optional[str] = None):
        self.db = db
        self.ai_reviewer = AIReviewer(api_key=openai_api_key)

    async def run_pipeline(
        self,
        repo_owner: str,
        repo_name: str,
        pr_number: int,
        pr_title: str,
        pr_author: str,
        head_branch: str,
        base_branch: str,
        commit_sha: str,
        raw_diff: str,
    ) -> AnalysisRun:
        full_repo_name = f"{repo_owner}/{repo_name}"

        # 1. Ensure Repository record
        repo = self.db.query(Repository).filter(Repository.full_name == full_repo_name).first()
        if not repo:
            repo = Repository(full_name=full_repo_name, owner=repo_owner, name=repo_name, default_branch=base_branch)
            self.db.add(repo)
            self.db.commit()
            self.db.refresh(repo)

        # 2. Ensure PullRequest record with concurrency protection
        pr = self.db.query(PullRequest).filter(
            PullRequest.repository_id == repo.id,
            PullRequest.pr_number == pr_number
        ).first()

        if not pr:
            try:
                pr = PullRequest(
                    repository_id=repo.id,
                    pr_number=pr_number,
                    title=pr_title,
                    author=pr_author,
                    head_branch=head_branch,
                    base_branch=base_branch,
                )
                self.db.add(pr)
                self.db.commit()
            except IntegrityError:
                self.db.rollback()
                pr = self.db.query(PullRequest).filter(
                    PullRequest.repository_id == repo.id,
                    PullRequest.pr_number == pr_number
                ).first()
        else:
            pr.title = pr_title
            pr.head_branch = head_branch
            pr.base_branch = base_branch
            pr.updated_at = datetime.datetime.utcnow()
            self.db.commit()

        self.db.refresh(pr)

        # 3. Create AnalysisRun record
        analysis_run = AnalysisRun(
            pull_request_id=pr.id,
            commit_sha=commit_sha,
            status="running",
        )
        self.db.add(analysis_run)
        self.db.commit()
        self.db.refresh(analysis_run)

        try:
            # 4. Parse diff
            file_diffs = DiffAnalyzer.parse_patch(raw_diff)

            # Metrics
            total_additions = sum(f.additions for f in file_diffs)
            total_deletions = sum(f.deletions for f in file_diffs)
            changed_files_count = len(file_diffs)
            sensitive_files = sum(
                1 for f in file_diffs
                if any(kw in f.new_path.lower() for kw in ["auth", "security", "migration", "db", "docker", "k8s", "ci"])
            )

            # 5. Static Analyzers
            quality_findings = CodeQualityAnalyzer.analyze(file_diffs)
            security_findings = SecurityAnalyzer.analyze(file_diffs)
            testing_result = TestingAnalyzer.analyze(file_diffs)
            complexity_findings = ComplexityAnalyzer.analyze(file_diffs)
            architecture_findings = ArchitectureAnalyzer.analyze(file_diffs)
            dependency_findings = DependencyRiskAnalyzer.analyze(file_diffs)

            static_findings: List[FindingDTO] = (
                quality_findings
                + security_findings
                + testing_result["findings"]
                + complexity_findings
                + architecture_findings
                + dependency_findings
            )

            # 6. AI Intelligence Analysis
            pr_metadata = {
                "title": pr_title,
                "author": pr_author,
                "head_branch": head_branch,
                "base_branch": base_branch,
            }
            ai_res = await self.ai_reviewer.analyze_pr(pr_metadata, raw_diff, static_findings)

            ai_findings: List[FindingDTO] = [
                FindingDTO(
                    category=f["category"],
                    severity=f["severity"],
                    confidence=f["confidence"],
                    title=f["title"],
                    description=f["description"],
                    file=f.get("file"),
                    line=f.get("line"),
                    impact=f.get("impact"),
                    recommendation=f.get("recommendation"),
                    evidence=f.get("evidence"),
                )
                for f in ai_res.get("ai_findings", [])
            ]

            # 7. Deduplicate & filter findings
            all_findings = FindingDeduplicator.deduplicate_and_filter(static_findings + ai_findings)

            # 8. Risk Scoring Engine
            metrics_dict = {
                "additions": total_additions,
                "deletions": total_deletions,
                "changed_files": changed_files_count,
                "sensitive_files_changed": sensitive_files,
                "testing_level": testing_result["testing_level"],
            }

            risk_res = RiskScoringEngine.calculate_risk(
                findings=all_findings,
                metrics=metrics_dict,
                ai_modifier=ai_res.get("risk_score_modifier", 0),
            )

            # 9. Persist results in Database
            analysis_run.status = "completed"
            analysis_run.overall_risk_score = risk_res.score
            analysis_run.risk_level = risk_res.risk_level
            analysis_run.summary = ai_res.get("summary", "Analysis completed successfully.")
            analysis_run.merge_recommendation = ai_res.get("merge_recommendation", "REVIEW_REQUIRED")
            analysis_run.metrics = metrics_dict
            analysis_run.completed_at = datetime.datetime.utcnow()

            # Save Risk Score details
            risk_score_obj = RiskScore(
                analysis_run_id=analysis_run.id,
                score=risk_res.score,
                risk_level=risk_res.risk_level,
                drivers=risk_res.drivers,
            )
            self.db.add(risk_score_obj)

            # Save Findings
            for f in all_findings:
                finding_obj = Finding(
                    analysis_run_id=analysis_run.id,
                    category=f.category,
                    severity=f.severity,
                    confidence=f.confidence,
                    file=f.file,
                    line=f.line,
                    title=f.title,
                    description=f.description,
                    impact=f.impact,
                    recommendation=f.recommendation,
                    evidence=f.evidence,
                )
                self.db.add(finding_obj)

            self.db.commit()
            self.db.refresh(analysis_run)
            return analysis_run

        except Exception as e:
            logger.exception("Error executing PRISM analysis pipeline")
            analysis_run.status = "failed"
            analysis_run.error_message = str(e)
            self.db.commit()
            raise e
