from typing import List
from prism.analysis.types import FindingDTO
from prism.config import settings


class FindingDeduplicator:
    """Filters low confidence findings and deduplicates redundant findings across static and AI checks."""

    @staticmethod
    def deduplicate_and_filter(
        findings: List[FindingDTO],
        confidence_threshold: float = settings.SUPPRESS_LOW_CONFIDENCE_THRESHOLD,
    ) -> List[FindingDTO]:
        """Filters out findings with confidence below threshold and removes duplicates based on (category, file, line, title)."""
        filtered: List[FindingDTO] = []
        seen_keys = set()

        # Sort higher severity & confidence first
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity.lower(), 0), f.confidence),
            reverse=True,
        )

        for f in sorted_findings:
            if f.confidence < confidence_threshold:
                continue

            # Key for duplicate identification
            normalized_file = (f.file or "").strip().lower()
            normalized_title = (f.title or "").strip().lower()
            key = (f.category.lower(), normalized_file, f.line or 0, normalized_title)

            if key in seen_keys:
                continue

            seen_keys.add(key)
            filtered.append(f)

        return filtered
