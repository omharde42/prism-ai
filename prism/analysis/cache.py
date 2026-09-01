import hashlib
from typing import Dict, Any, Optional

_ANALYSIS_CACHE: Dict[str, Dict[str, Any]] = {}


class IncrementalAnalysisCache:
    """Caches analysis results by commit SHA and raw diff hash to prevent redundant static/AI analysis."""

    @staticmethod
    def get_cache_key(repo_name: str, pr_number: int, commit_sha: str, raw_diff: str) -> str:
        diff_hash = hashlib.sha256(raw_diff.encode("utf-8")).hexdigest()
        return f"{repo_name}:{pr_number}:{commit_sha}:{diff_hash}"

    @staticmethod
    def get(cache_key: str) -> Optional[Dict[str, Any]]:
        return _ANALYSIS_CACHE.get(cache_key)

    @staticmethod
    def put(cache_key: str, data: Dict[str, Any]) -> None:
        _ANALYSIS_CACHE[cache_key] = data

    @staticmethod
    def clear() -> None:
        _ANALYSIS_CACHE.clear()
