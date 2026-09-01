import datetime
import logging
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from prism.database.models import Repository, PullRequest, AnalysisRun, Finding, RiskScore
from prism.analysis.diff_analyzer import DiffAnalyzer
from prism.analysis.code_quality import CodeQualityAnalyzer
from prism.analysis.security import SecurityAnalyzer
from prism.analysis.testing import TestingAnalyzer
from prism.analysis.complexity import ComplexityAnalyzer
from prism.analysis.architecture import ArchitectureAnalyzer
from prism.analysis.dependency import DependencyAnalyzer
from prism.analysis.context_engine import ContextEngine
from prism.analysis.db_risk import DatabaseRiskEngine
from prism.analysis.api_contract import APIContractEngine
from prism.analysis.ai_review import AIReviewer
from prism.analysis.ai_verifier import AIVerifier
from prism.analysis.deduplicator import FindingDeduplicator
from prism.analysis.risk_scoring import RiskScoringEngine
from prism.analysis.types import FindingDTO

logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """Orchestrates 10-layer PR risk intelligence analysis pipeline."""

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
        source_context: Optional[str] = None,
    ) -> AnalysisRun:
        full_repo_name = f"{repo_owner}/{repo_name}"

        # 1. GitHub metadata / Repository record creation
        repo = self.db.query(Repository).filter(Repository.full_name == full_repo_name).first()
        if not repo:
            repo = Repository(full_name=full_repo_name, owner=repo_owner, name=repo_name, default_branch=base_branch)
            self.db.add(repo)
            self.db.commit()
            self.db.refresh(repo)

        # 2. PullRequest record with concurrency handling
        pr = self.db.query(PullRequest).filter(
            PullRequest.repository_id == repo.id,
            PullRequest.pr_number == pr_number
        ).first()

        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

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
            pr.updated_at = now_utc
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
            start_time = datetime.datetime.now(datetime.timezone.utc)

            # 4. Diff Analysis & Codebase Context Engine
            file_diffs = DiffAnalyzer.parse_patch(raw_diff)
            context_impact = ContextEngine.calculate_impact(file_diffs)
            symbols = ContextEngine.extract_symbols(file_diffs)
            rel_context = ContextEngine.build_relevant_context(file_diffs)

            total_additions = sum(f.additions for f in file_diffs)
            total_deletions = sum(f.deletions for f in file_diffs)
            changed_files_count = len(file_diffs)
            sensitive_files = len(context_impact.get("sensitive_files_affected", []))

            # 5. Multi-Engine Deterministic Layer
            static_start = datetime.datetime.now(datetime.timezone.utc)
            quality_findings = CodeQualityAnalyzer.analyze(file_diffs)
            security_findings = SecurityAnalyzer.analyze(file_diffs)
            testing_result = TestingAnalyzer.analyze(file_diffs)
            complexity_findings = ComplexityAnalyzer.analyze(file_diffs)
            architecture_findings = ArchitectureAnalyzer.analyze(file_diffs)
            dependency_findings = DependencyAnalyzer.analyze(file_diffs)
            db_risk_findings = DatabaseRiskEngine.analyze(file_diffs)
            api_contract_findings = APIContractEngine.analyze(file_diffs)
            static_duration_ms = (datetime.datetime.now(datetime.timezone.utc) - static_start).total_seconds() * 1000.0

            static_findings: List[FindingDTO] = (
                quality_findings
                + security_findings
                + testing_result["findings"]
                + complexity_findings
                + architecture_findings
                + dependency_findings
                + db_risk_findings
                + api_contract_findings
            )

            # 6. AI Reasoning & Verification Layer
            ai_start = datetime.datetime.now(datetime.timezone.utc)
            pr_metadata = {
                "title": pr_title,
                "author": pr_author,
                "head_branch": head_branch,
                "base_branch": base_branch,
            }
            ai_res = await self.ai_reviewer.analyze_pr(
                pr_metadata=pr_metadata,
                raw_diff=raw_diff,
                static_findings=static_findings,
                source_context=source_context or rel_context
            )
            ai_duration_ms = (datetime.datetime.now(datetime.timezone.utc) - ai_start).total_seconds() * 1000.0

            ai_findings_raw: List[FindingDTO] = [
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
                    symbol=f.get("symbol"),
                )
                for f in ai_res.get("ai_findings", [])
            ]

            # Cross-examine AI findings to filter hallucinations
            ai_findings = AIVerifier.verify_findings(ai_findings_raw, file_diffs)

            # 7. Deduplication & Prioritization
            all_findings = FindingDeduplicator.deduplicate_and_filter(static_findings + ai_findings)

            # 8. Risk Aggregation & Scoring Engine
            metrics_dict = {
                "additions": total_additions,
                "deletions": total_deletions,
                "changed_files": changed_files_count,
                "sensitive_files_changed": sensitive_files,
                "testing_level": testing_result["testing_level"],
                "test_recommendations": testing_result.get("test_recommendations", []),
                "symbols_changed_count": len(symbols),
            }

            risk_res = RiskScoringEngine.calculate_risk(
                findings=all_findings,
                metrics=metrics_dict,
                ai_modifier=ai_res.get("risk_score_modifier", 0),
            )

            # 9. History Comparison & Risk Trend Detection
            prev_run = self.db.query(AnalysisRun).filter(
                AnalysisRun.pull_request_id == pr.id,
                AnalysisRun.id != analysis_run.id,
                AnalysisRun.status == "completed"
            ).order_by(AnalysisRun.id.desc()).first()

            parent_id = prev_run.id if prev_run else None
            score_delta = 0.0
            risk_trend = "STABLE"

            if prev_run:
                score_delta = round(risk_res.score - prev_run.overall_risk_score, 1)
                if score_delta <= -3.0:
                    risk_trend = "IMPROVING"
                elif score_delta >= 3.0:
                    risk_trend = "RISKIER"
                else:
                    risk_trend = "STABLE"

            total_duration_ms = (datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds() * 1000.0
            execution_metrics = {
                "static_analysis_ms": round(static_duration_ms, 2),
                "ai_latency_ms": round(ai_duration_ms, 2),
                "total_ms": round(total_duration_ms, 2),
            }

            # 10. Persist results in Database
            analysis_run.status = "completed"
            analysis_run.overall_risk_score = risk_res.score
            analysis_run.risk_level = risk_res.risk_level
            analysis_run.summary = ai_res.get("summary", "Analysis completed successfully.")
            analysis_run.merge_recommendation = ai_res.get("merge_recommendation", "REVIEW_REQUIRED")
            analysis_run.parent_analysis_id = parent_id
            analysis_run.score_delta = score_delta
            analysis_run.risk_trend = risk_trend
            analysis_run.blast_radius = context_impact["blast_radius"]
            analysis_run.dimension_scores = risk_res.dimension_scores
            analysis_run.execution_metrics = execution_metrics
            analysis_run.metrics = metrics_dict
            analysis_run.completed_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

            risk_score_obj = RiskScore(
                analysis_run_id=analysis_run.id,
                score=risk_res.score,
                risk_level=risk_res.risk_level,
                drivers=risk_res.drivers,
            )
            self.db.add(risk_score_obj)

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
                    status=f.status,
                    symbol=f.symbol,
                    user_feedback=f.user_feedback,
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
