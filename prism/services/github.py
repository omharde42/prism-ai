import hmac
import hashlib
import logging
from typing import Dict, Any, List, Optional
import httpx

from prism.config import settings

logger = logging.getLogger(__name__)


class GitHubService:
    def __init__(self, token: Optional[str] = None):
        self.token = token or settings.GITHUB_TOKEN
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "PRISM-Intelligence-Engine/1.0",
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    @staticmethod
    def verify_webhook_signature(payload_body: bytes, signature_header: Optional[str], secret: Optional[str] = None) -> bool:
        """Verify secret signature for GitHub Webhooks (X-Hub-Signature-256)."""
        secret_key = secret if secret is not None else settings.GITHUB_WEBHOOK_SECRET
        if not secret_key:
            return False
        if not signature_header:
            return False

        sha_type, signature = signature_header.split("=", 1) if "=" in signature_header else ("", "")
        if sha_type != "sha256":
            return False

        mac = hmac.new(secret_key.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256)
        expected_signature = mac.hexdigest()
        return hmac.compare_digest(expected_signature, signature)

    async def get_user_repositories(self) -> List[Dict[str, Any]]:
        """Fetch repositories accessible to the authenticated user or token."""
        url = "https://api.github.com/user/repos?sort=updated&per_page=100"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self.headers, timeout=15.0)
            if resp.status_code == 401:
                # Return empty list or public fallback repos if token is invalid/not provided
                return []
            resp.raise_for_status()
            return resp.json()

    async def get_repository_pull_requests(self, owner: str, repo: str, state: str = "open") -> List[Dict[str, Any]]:
        """Fetch Pull Requests for a specific repository."""
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls?state={state}&per_page=50"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self.headers, timeout=15.0)
            resp.raise_for_status()
            return resp.json()

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
        """Fetch PR details from GitHub API."""
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self.headers, timeout=15.0)
            resp.raise_for_status()
            return resp.json()

    async def get_pull_request_files(self, owner: str, repo: str, pr_number: int) -> List[Dict[str, Any]]:
        """Fetch changed files list for a PR."""
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=self.headers, timeout=15.0)
            resp.raise_for_status()
            return resp.json()

    async def get_pull_request_diff(self, owner: str, repo: str, pr_number: int) -> str:
        """Fetch raw diff string for a PR."""
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}.diff"
        headers = dict(self.headers)
        headers["Accept"] = "application/vnd.github.v3.diff"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=20.0)
            resp.raise_for_status()
            return resp.text

    async def get_file_content(self, owner: str, repo: str, filepath: str, ref: str = "main") -> Optional[str]:
        """Fetch raw source file content from GitHub API."""
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{filepath}"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=self.headers, timeout=10.0)
                if resp.status_code == 200:
                    return resp.text
        except Exception as e:
            logger.warning(f"Could not fetch source file content for {filepath}: {str(e)}")
        return None

    async def create_issue_comment(self, owner: str, repo: str, pr_number: int, body: str) -> Dict[str, Any]:
        """Post a comment on a PR issue thread."""
        url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=self.headers, json={"body": body}, timeout=15.0)
            resp.raise_for_status()
            return resp.json()

    async def create_commit_status(
        self, owner: str, repo: str, sha: str, state: str, description: str, context: str = "PRISM Risk Check"
    ) -> Dict[str, Any]:
        """Create commit status on GitHub PR commit."""
        url = f"https://api.github.com/repos/{owner}/{repo}/statuses/{sha}"
        payload = {
            "state": state,
            "description": description[:140],
            "context": context,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=self.headers, json=payload, timeout=15.0)
            resp.raise_for_status()
            return resp.json()
