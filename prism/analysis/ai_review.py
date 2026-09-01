import json
import logging
from typing import List, Dict, Any, Optional
import httpx

from prism.config import settings
from prism.analysis.types import FindingDTO

logger = logging.getLogger(__name__)


class AIReviewer:
    """AI-powered PR intelligence reasoning engine with schema validation and fallback handling."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.OPENAI_API_KEY
        self.model = settings.OPENAI_MODEL

    async def analyze_pr(
        self,
        pr_metadata: Dict[str, Any],
        raw_diff: str,
        static_findings: List[FindingDTO],
    ) -> Dict[str, Any]:
        """
        Sends truncated PR diff and static findings to OpenAI LLM (or fallback heuristic if API key not available).
        Returns structured analysis JSON:
        {
          "summary": str,
          "risk_score_modifier": int (-10 to +20),
          "ai_findings": List[FindingDTO dicts],
          "merge_recommendation": "APPROVE" | "REVIEW_REQUIRED" | "BLOCK"
        }
        """
        if not self.api_key:
            logger.info("OPENAI_API_KEY not configured. Using heuristic AI fallback analysis.")
            return self._heuristic_fallback(pr_metadata, raw_diff, static_findings)

        # Context truncation to protect token limit
        diff_lines = raw_diff.splitlines()
        if len(diff_lines) > settings.MAX_DIFF_LINES_FOR_AI:
            truncated_diff = "\n".join(diff_lines[: settings.MAX_DIFF_LINES_FOR_AI]) + f"\n... [Truncated {len(diff_lines) - settings.MAX_DIFF_LINES_FOR_AI} lines]"
        else:
            truncated_diff = raw_diff

        findings_summary = [
            {"category": f.category, "severity": f.severity, "title": f.title, "file": f.file}
            for f in static_findings[:10]
        ]

        prompt = f"""You are PRISM, an AI Pull Request Engineering Risk Intelligence Engine.
Analyze the following PR across security, testing, architecture, dependencies, and complex interactions, then produce a structured JSON report.

PR Title: {pr_metadata.get('title', '')}
Author: {pr_metadata.get('author', '')}
Branch: {pr_metadata.get('head_branch', '')} -> {pr_metadata.get('base_branch', '')}

Detected Deterministic Analyzer Findings:
{json.dumps(findings_summary, indent=2)}

PR Raw Diff (Truncated):
{truncated_diff}

Identify risk interactions (e.g., auth modifications combined with DB migrations or missing tests) and actionable recommendations.

Respond strictly in valid JSON format matching this schema:
{{
  "summary": "High-level 2-3 sentence engineering risk overview",
  "risk_score_modifier": 0,
  "merge_recommendation": "APPROVE" | "REVIEW_REQUIRED" | "BLOCK",
  "ai_findings": [
    {{
      "category": "architecture" | "security" | "code_quality" | "testing" | "complexity",
      "severity": "low" | "medium" | "high" | "critical",
      "confidence": 0.85,
      "title": "Short issue title",
      "description": "Clear explanation",
      "file": "path/to/file",
      "line": 10,
      "impact": "Production impact",
      "recommendation": "Actionable fix suggestion",
      "evidence": "Code snippet"
    }}
  ]
}}
"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a senior principal software engineer performing PR risk assessment. Output valid JSON only."},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=float(settings.LLM_TIMEOUT_SECONDS),
                )
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                return self._validate_and_normalize_ai_response(parsed)
        except Exception as e:
            logger.warning(f"AI LLM analysis failed or timed out ({str(e)}). Falling back to heuristic mode.")
            return self._heuristic_fallback(pr_metadata, raw_diff, static_findings)

    def _validate_and_normalize_ai_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validates AI LLM output schema."""
        summary = data.get("summary", "AI review completed.")
        try:
            modifier = int(data.get("risk_score_modifier", 0))
        except (ValueError, TypeError):
            modifier = 0
        modifier = max(-10, min(20, modifier))
        rec = data.get("merge_recommendation", "REVIEW_REQUIRED")
        if rec not in ["APPROVE", "REVIEW_REQUIRED", "BLOCK"]:
            rec = "REVIEW_REQUIRED"

        ai_findings = []
        raw_findings = data.get("ai_findings", [])
        if isinstance(raw_findings, list):
            for item in raw_findings:
                if isinstance(item, dict) and "title" in item and "category" in item:
                    ai_findings.append({
                        "category": str(item.get("category", "code_quality")),
                        "severity": str(item.get("severity", "medium")),
                        "confidence": float(item.get("confidence", 0.8)),
                        "title": str(item.get("title")),
                        "description": str(item.get("description", "")),
                        "file": item.get("file"),
                        "line": item.get("line"),
                        "impact": item.get("impact"),
                        "recommendation": item.get("recommendation"),
                        "evidence": item.get("evidence"),
                    })

        return {
            "summary": summary,
            "risk_score_modifier": modifier,
            "merge_recommendation": rec,
            "ai_findings": ai_findings,
        }

    def _heuristic_fallback(
        self,
        pr_metadata: Dict[str, Any],
        raw_diff: str,
        static_findings: List[FindingDTO],
    ) -> Dict[str, Any]:
        """Provides deterministic fallback summary and findings if LLM is offline/unconfigured."""
        critical_count = sum(1 for f in static_findings if f.severity == "critical")
        high_count = sum(1 for f in static_findings if f.severity == "high")

        if critical_count > 0:
            rec = "BLOCK"
            summary = f"PR contains {critical_count} critical issue(s) including security/logic risks that should be resolved before merge."
        elif high_count > 0:
            rec = "REVIEW_REQUIRED"
            summary = f"PR contains {high_count} high-priority finding(s) requiring thorough peer review."
        else:
            rec = "APPROVE"
            summary = "PR changes look clean with no high-severity static risks identified."

        return {
            "summary": summary,
            "risk_score_modifier": 0,
            "merge_recommendation": rec,
            "ai_findings": [],
        }
