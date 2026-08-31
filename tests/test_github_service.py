import hmac
import hashlib
import pytest
from prism.services.github import GitHubService


def test_verify_webhook_signature():
    secret = "test_secret_123"
    body = b'{"action": "opened", "number": 1}'

    mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256)
    valid_sig = f"sha256={mac.hexdigest()}"

    # Valid signature
    assert GitHubService.verify_webhook_signature(body, valid_sig, secret=secret) is True

    # Invalid signature
    assert GitHubService.verify_webhook_signature(body, "sha256=invalid", secret=secret) is False

    # Missing signature when secret is set
    assert GitHubService.verify_webhook_signature(body, None, secret=secret) is False

    # Missing secret key returns False (fails closed)
    assert GitHubService.verify_webhook_signature(body, valid_sig, secret=None) is False
