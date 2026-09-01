from typing import List
from prism.analysis.types import FindingDTO, SEVERITY_WEIGHTS
from prism.config import settings


class FindingDeduplicator:
    """Filters low confidence findings, deduplicates redundant findings across static and AI layers, keeping highest priority score and ranking findings by Impact x Confidence x Severity."""

    @staticmethod
    def deduplicate_and_filter(
        findings: List[FindingDTO],
        confidence_threshold: float = settings.SUPPRESS_LOW_CONFIDENCE_THRESHOLD,
    ) -> List[FindingDTO]:
        """Filters out findings below confidence threshold, removes duplicates keeping higher confidence, and sorts by priority score."""
        # Sort findings so higher confidence & higher priority items are processed first
        sorted_input = sorted(
            findings,
            key=lambda f: (f.priority_score, f.confidence),
            reverse=True,
        )

        filtered: List[FindingDTO] = []
        seen_keys = set()

        for f in sorted_input:
            if f.confidence < confidence_threshold:
                continue

            normalized_file = (f.file or "").strip().lower()
            normalized_title = (f.title or "").strip().lower()
            key = (f.category.lower(), normalized_file, f.line or 0, normalized_title)

            if key in seen_keys:
                continue

            seen_keys.add(key)
            filtered.append(f)

        return filtered
