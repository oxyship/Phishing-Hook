"""
Hook — unit tests for detector.py

Tests cover:
  - Legitimate emails score low (< 0.30)
  - Obvious phishing scores high (> 0.70)
  - Individual tactics are detected correctly
  - API error handling / propagation
  - Edge-case inputs
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import anthropic
import pytest

from hook.detector import (
    AnalysisResult,
    HookDetector,
    HookError,
    TacticsDetected,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(result: AnalysisResult) -> MagicMock:
    """Wrap an AnalysisResult in a minimal mock API response."""
    mock_resp = MagicMock()
    mock_resp.parsed_output = result
    mock_resp.stop_reason = "end_turn"
    return mock_resp


def _safe_result(**kwargs) -> AnalysisResult:
    defaults = dict(
        risk_score=0.05,
        verdict="safe",
        tactics=TacticsDetected(),
        explanation="Legitimate newsletter with no suspicious indicators.",
        recommended_action="Safe to read and engage.",
    )
    defaults.update(kwargs)
    return AnalysisResult(**defaults)


def _phishing_result(**kwargs) -> AnalysisResult:
    defaults = dict(
        risk_score=0.95,
        verdict="phishing",
        tactics=TacticsDetected(
            urgency=True,
            impersonation=True,
            credential_harvesting=True,
            suspicious_links=True,
            spoofing=True,
        ),
        explanation=(
            "Classic credential-harvesting phish impersonating a major bank. "
            "Uses urgency ('24 hours'), suspicious link to paypa1.com, and "
            "requests password via email."
        ),
        recommended_action="Delete immediately. Report to your IT/security team.",
    )
    defaults.update(kwargs)
    return AnalysisResult(**defaults)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

LEGIT_EMAIL = """\
Subject: Your May 2024 newsletter from TechBlog
From: newsletter@techblog.com

Hi there,

This month we cover Python 3.13 features, the latest in AI tooling, and our
new tutorial series on distributed systems.

Read online: https://techblog.com/newsletter/may-2024

Unsubscribe: https://techblog.com/unsubscribe?token=abc123

-- TechBlog Team
"""

PHISHING_EMAIL = """\
Subject: ⚠️ URGENT: Your account will be suspended in 24 hours
From: security-alert@paypa1.com

Dear Customer,

We have detected unusual activity on your PayPal account. Your account will be
PERMANENTLY SUSPENDED within 24 hours unless you verify your identity NOW.

Click here to verify: http://paypa1-security.ru/verify?id=83726

You will need to provide:
  - Full name
  - Password
  - Credit card number
  - Social Security Number

Failure to act IMMEDIATELY will result in permanent account closure.

PayPal Security Team
"""


# ---------------------------------------------------------------------------
# Risk score tests
# ---------------------------------------------------------------------------


class TestRiskScores:
    def test_legitimate_email_scores_low(self):
        """Legitimate emails must score below 0.30."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _safe_result(risk_score=0.05)
            )
            detector = HookDetector()
            result = detector.analyze(LEGIT_EMAIL)

        assert result.risk_score < 0.30, (
            f"Expected risk < 0.30 for legit email, got {result.risk_score}"
        )
        assert result.verdict == "safe"

    def test_phishing_email_scores_high(self):
        """Obvious phishing emails must score above 0.70."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _phishing_result(risk_score=0.95)
            )
            detector = HookDetector()
            result = detector.analyze(PHISHING_EMAIL)

        assert result.risk_score > 0.70, (
            f"Expected risk > 0.70 for phishing email, got {result.risk_score}"
        )
        assert result.verdict == "phishing"

    def test_suspicious_email_is_middle_range(self):
        """A suspicious-but-not-definitive email should land in 0.40–0.70."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                AnalysisResult(
                    risk_score=0.55,
                    verdict="suspicious",
                    tactics=TacticsDetected(urgency=True),
                    explanation="Uses some urgency language but sender domain looks legitimate.",
                    recommended_action="Verify by contacting the sender through official channels.",
                )
            )
            detector = HookDetector()
            result = detector.analyze("Subject: Please update your info\n\nSee link.")

        assert 0.40 <= result.risk_score <= 0.70
        assert result.verdict == "suspicious"


# ---------------------------------------------------------------------------
# Tactic detection tests
# ---------------------------------------------------------------------------


class TestTacticDetection:
    def test_urgency_tactic_detected(self):
        """Urgency flag must be set when the email uses fear/time pressure."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _phishing_result(
                    tactics=TacticsDetected(urgency=True),
                )
            )
            detector = HookDetector()
            result = detector.analyze(PHISHING_EMAIL)

        assert result.tactics.urgency is True

    def test_impersonation_tactic_detected(self):
        """Impersonation flag must be set when sender fakes a known brand."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _phishing_result(
                    tactics=TacticsDetected(impersonation=True),
                )
            )
            detector = HookDetector()
            result = detector.analyze(PHISHING_EMAIL)

        assert result.tactics.impersonation is True

    def test_credential_harvesting_detected(self):
        """Credential-harvesting flag set when email requests sensitive data."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _phishing_result(
                    tactics=TacticsDetected(credential_harvesting=True),
                )
            )
            detector = HookDetector()
            result = detector.analyze(PHISHING_EMAIL)

        assert result.tactics.credential_harvesting is True

    def test_suspicious_links_detected(self):
        """Suspicious-links flag set for lookalike/HTTP domains."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _phishing_result(
                    tactics=TacticsDetected(suspicious_links=True),
                )
            )
            detector = HookDetector()
            result = detector.analyze(PHISHING_EMAIL)

        assert result.tactics.suspicious_links is True

    def test_spoofing_detected(self):
        """Spoofing flag set for mismatched sender address."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _phishing_result(
                    tactics=TacticsDetected(spoofing=True),
                )
            )
            detector = HookDetector()
            result = detector.analyze(PHISHING_EMAIL)

        assert result.tactics.spoofing is True

    def test_no_tactics_on_safe_email(self):
        """Safe emails should have all tactic flags set to False."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _safe_result(tactics=TacticsDetected())
            )
            detector = HookDetector()
            result = detector.analyze(LEGIT_EMAIL)

        t = result.tactics
        assert not any([
            t.urgency,
            t.impersonation,
            t.credential_harvesting,
            t.suspicious_links,
            t.spoofing,
        ]), "Expected no tactics detected for safe email"

    def test_all_tactics_detected_simultaneously(self):
        """All five tactics can be flagged in a single analysis."""
        all_tactics = TacticsDetected(
            urgency=True,
            impersonation=True,
            credential_harvesting=True,
            suspicious_links=True,
            spoofing=True,
        )
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _phishing_result(tactics=all_tactics)
            )
            detector = HookDetector()
            result = detector.analyze(PHISHING_EMAIL)

        t = result.tactics
        assert all([
            t.urgency,
            t.impersonation,
            t.credential_harvesting,
            t.suspicious_links,
            t.spoofing,
        ]), "Expected all five tactics to be detected"


# ---------------------------------------------------------------------------
# API error handling
# ---------------------------------------------------------------------------


class TestAPIErrorHandling:
    def test_api_connection_error_propagates(self):
        """Network errors from the Anthropic SDK must propagate unchanged."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.side_effect = anthropic.APIConnectionError(
                request=MagicMock()
            )
            detector = HookDetector()
            with pytest.raises(anthropic.APIConnectionError):
                detector.analyze(LEGIT_EMAIL)

    def test_rate_limit_error_propagates(self):
        """Rate-limit errors must propagate so callers can implement backoff."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_response = MagicMock()
            mock_response.status_code = 429
            mock_response.headers = {}
            mock_client.messages.parse.side_effect = anthropic.RateLimitError(
                message="rate limit exceeded",
                response=mock_response,
                body=None,
            )
            detector = HookDetector()
            with pytest.raises(anthropic.RateLimitError):
                detector.analyze(LEGIT_EMAIL)

    def test_authentication_error_propagates(self):
        """Auth errors must propagate so the caller knows the key is invalid."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.headers = {}
            mock_client.messages.parse.side_effect = anthropic.AuthenticationError(
                message="invalid api key",
                response=mock_response,
                body=None,
            )
            detector = HookDetector()
            with pytest.raises(anthropic.AuthenticationError):
                detector.analyze(LEGIT_EMAIL)

    def test_none_parsed_output_raises_Hook_error(self):
        """If the model returns no parseable JSON, HookError is raised."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_resp = MagicMock()
            mock_resp.parsed_output = None
            mock_resp.stop_reason = "refusal"
            mock_client.messages.parse.return_value = mock_resp
            detector = HookDetector()
            with pytest.raises(HookError, match="no parseable result"):
                detector.analyze(LEGIT_EMAIL)

    def test_bad_request_error_wrapped_as_Hook_error(self):
        """BadRequestError from the SDK is wrapped into HookError."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.headers = {}
            mock_client.messages.parse.side_effect = anthropic.BadRequestError(
                message="invalid request",
                response=mock_response,
                body=None,
            )
            detector = HookDetector()
            with pytest.raises(HookError):
                detector.analyze(LEGIT_EMAIL)


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_empty_string_raises_value_error(self):
        detector = HookDetector()
        with pytest.raises(ValueError, match="must not be empty"):
            detector.analyze("")

    def test_whitespace_only_raises_value_error(self):
        detector = HookDetector()
        with pytest.raises(ValueError, match="must not be empty"):
            detector.analyze("   \n\t  ")

    def test_result_contains_explanation(self):
        """Every result must include a non-empty explanation string."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _safe_result(explanation="All signals point to a legitimate email.")
            )
            detector = HookDetector()
            result = detector.analyze(LEGIT_EMAIL)

        assert isinstance(result.explanation, str)
        assert len(result.explanation) > 10

    def test_result_contains_recommended_action(self):
        """Every result must include a recommended action for the recipient."""
        with patch("hook.detector.anthropic.Anthropic") as MockClient:
            mock_client = MockClient.return_value
            mock_client.messages.parse.return_value = _make_response(
                _safe_result(recommended_action="Safe to read.")
            )
            detector = HookDetector()
            result = detector.analyze(LEGIT_EMAIL)

        assert isinstance(result.recommended_action, str)
        assert len(result.recommended_action) > 0
