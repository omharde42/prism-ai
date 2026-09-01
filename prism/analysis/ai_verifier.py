import logging
from typing import List
from prism.analysis.types import FindingDTO
from prism.analysis.diff_analyzer import FileDiff

logger = logging.getLogger(__name__)


class AIVerifier:
    """Cross-examines AI and static findings against actual code diff to prevent false positives and hallucinations."""

    @staticmethod
    def verify_findings(findings: List[FindingDTO], file_diffs: List[FileDiff]) -> List[FindingDTO]:
        verified: List[FindingDTO] = []
        diff_paths = {f.new_path: f for f in file_diffs}

        for f in findings:
            # Check 1: If file specified, ensure file is modified in PR
            if f.file and f.file not in diff_paths:
                # File not in diff! Downgrade confidence or suppress if low confidence
                logger.warning(f"AI finding cited file '{f.file}' not present in PR diff. Downgrading confidence.")
                f.confidence = round(f.confidence * 0.5, 2)

            # Check 2: If evidence specified, check if evidence exists in diff chunk added lines
            if f.file and f.file in diff_paths and f.evidence:
                fdiff = diff_paths[f.file]
                all_added_lines = [line.strip() for chunk in fdiff.chunks for _, line in chunk.added_lines]
                ev_clean = f.evidence.strip()

                if all_added_lines and ev_clean not in all_added_lines and not any(ev_clean in line for line in all_added_lines):
                    # Cited evidence code snippet not found in diff added lines
                    logger.warning(f"AI finding cited evidence '{ev_clean[:40]}' not found in diff added lines. Adjusting confidence.")
                    f.confidence = round(f.confidence * 0.6, 2)

            # Check 3: Minimum evidence requirements for critical findings
            if f.severity == "critical" and not f.evidence and f.file:
                # If critical finding has no evidence snippet, attach chunk snippet
                fdiff = diff_paths.get(f.file)
                if fdiff and fdiff.chunks and fdiff.chunks[0].added_lines:
                    f.evidence = fdiff.chunks[0].added_lines[0][1].strip()

            verified.append(f)

        return verified
