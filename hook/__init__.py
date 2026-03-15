"""Hook — AI-powered phishing email detector."""

from .detector import AnalysisResult, HookDetector, HookError, TacticsDetected

__all__ = [
    "HookDetector",
    "AnalysisResult",
    "TacticsDetected",
    "HookError",
]
