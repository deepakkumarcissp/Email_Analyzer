"""DKCISSP Email Analyzer — open-source phishing / BEC email triage."""

from .engine import EmailAnalyzer, analyze_email

__version__ = "1.0.0"
__all__ = ["EmailAnalyzer", "analyze_email", "__version__"]
