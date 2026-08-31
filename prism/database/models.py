import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Text,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import relationship
from prism.database.session import Base


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(255), unique=True, index=True, nullable=False)  # e.g. "owner/repo"
    owner = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    default_branch = Column(String(100), default="main")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    pull_requests = relationship("PullRequest", back_populates="repository", cascade="all, delete-orphan")


class PullRequest(Base):
    __tablename__ = "pull_requests"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False, index=True)
    pr_number = Column(Integer, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    author = Column(String(255), nullable=False)
    head_branch = Column(String(255), nullable=False)
    base_branch = Column(String(255), nullable=False)
    status = Column(String(50), default="open")  # open, closed, merged
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    repository = relationship("Repository", back_populates="pull_requests")
    analyses = relationship("AnalysisRun", back_populates="pull_request", cascade="all, delete-orphan")


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id = Column(Integer, primary_key=True, index=True)
    pull_request_id = Column(Integer, ForeignKey("pull_requests.id"), nullable=False, index=True)
    commit_sha = Column(String(100), nullable=False, index=True)
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    overall_risk_score = Column(Float, default=0.0)
    risk_level = Column(String(50), default="LOW")  # LOW, MODERATE, ELEVATED, HIGH, CRITICAL
    summary = Column(Text, nullable=True)
    merge_recommendation = Column(String(100), default="APPROVE")  # APPROVE, REVIEW_REQUIRED, BLOCK
    metrics = Column(JSON, nullable=True)  # { "changed_files": 5, "additions": 100, "deletions": 20 }
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    pull_request = relationship("PullRequest", back_populates="analyses")
    findings = relationship("Finding", back_populates="analysis_run", cascade="all, delete-orphan")
    risk_score = relationship("RiskScore", uselist=False, back_populates="analysis_run", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    analysis_run_id = Column(Integer, ForeignKey("analysis_runs.id"), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)  # security, code_quality, testing, complexity, architecture
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    confidence = Column(Float, default=1.0)  # 0.0 to 1.0
    file = Column(String(500), nullable=True, index=True)
    line = Column(Integer, nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    analysis_run = relationship("AnalysisRun", back_populates="findings")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    analysis_run_id = Column(Integer, ForeignKey("analysis_runs.id"), nullable=False, unique=True, index=True)
    score = Column(Float, nullable=False)  # 0.0 - 100.0
    risk_level = Column(String(50), nullable=False)
    drivers = Column(JSON, nullable=False)  # List of string reasons for high score
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    analysis_run = relationship("AnalysisRun", back_populates="risk_score")
