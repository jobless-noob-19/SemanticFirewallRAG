"""
Sensitive Data Detector
Project: SemanticFirewallRAG

Detects potentially sensitive data using deterministic pattern matching.
This module reports findings only: it does not redact text, validate
whether credentials are active, call an LLM, or make blocking decisions.
"""

import re
from typing import Dict, List, Pattern, TypedDict

from utils.logger import get_logger


logger = get_logger("sensitive_data_detector", "sensitive_data_detector.log")

MAX_DOCUMENT_LENGTH = 1_000_000

# These rules detect potential exposure, not confirmed active credentials.
# Keep patterns reasonably conservative and exclude obvious example values.
PATTERNS: Dict[str, Pattern[str]] = {
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        re.IGNORECASE,
    ),
    "email_address": re.compile(
        r"(?<![\w.+-])"
        r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
        r"@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
        r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
        r"(?![\w-]|\.(?=[A-Za-z0-9.-]))",
        re.IGNORECASE,
    ),
    # A context label is required to reduce matches against arbitrary numbers.
    "phone_number": re.compile(
        r"(?<!\w)(?:\+\d{1,3}[\s().-]*)?"
        r"(?:\(?\d{2,4}\)?[\s.-]*)"
        r"\d{3,4}[\s.-]*\d{3,4}(?!\w)"
    ),
    "password": re.compile(
        r"\b(?:password|passwd|pwd)\b[\"']?\s*[:=]\s*"
        r"""(?:"([^"\r\n]{1,256})"|'([^'\r\n]{1,256})'|([^\s,;#]{1,256}))""",
        re.IGNORECASE,
    ),
    "api_key": re.compile(
        r"\b(?:api[_ -]?key|client[_ -]?secret|access[_ -]?token|"
        r"auth[_ -]?token|secret[_ -]?key)\b[\"']?\s*[:=]\s*"
        r"""(?:"([^"\r\n]{8,512})"|'([^'\r\n]{8,512})'|([^\s,;#]{8,512}))""",
        re.IGNORECASE,
    ),
    # Recognize a few common token families, not every arbitrary long string.
    "access_token": re.compile(
        r"\b(?:sk-[A-Za-z0-9_-]{16,}|"
        r"gh[pousr]_[A-Za-z0-9]{20,}|"
        r"AKIA[A-Z0-9]{16})\b"
    ),
    # JWT-shaped values are recognized only after an Authorization Bearer label.
    # This structural match does not validate a JWT signature or authenticity.
    "bearer_jwt": re.compile(
        r"\bAuthorization\s*:\s*Bearer\s+"
        r"([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
        re.IGNORECASE,
    ),
}

PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change-me",
    "example",
    "example_key",
    "example-token",
    "fake",
    "insert_key_here",
    "not-a-real-key",
    "placeholder",
    "replace_me",
    "replace-with-your-key",
    "test",
    "test_key",
    "your_api_key",
    "your_key",
    "your_secret",
    "your_token",
}

# Phone numbers are detected only when introduced by a phone-related label.
PHONE_CONTEXT_PATTERN = re.compile(
    r"\b(?:phone(?:\s+number)?|mobile(?:\s+number)?|telephone|tel|contact\s+number)"
    r"\b\s*(?:(?:[:=])|(?:is))\s*$",
    re.IGNORECASE,
)


class Finding(TypedDict):
    category: str
    start: int
    end: int
    match_type: str


class Assessment(TypedDict):
    has_sensitive_data: bool
    findings: List[Finding]
    finding_count: int


def _is_placeholder(value: str) -> bool:
    """Return True for obvious placeholder/example values."""
    normalized = value.strip().strip("\"'`").lower()
    normalized = re.sub(r"\s+", "_", normalized)
    if normalized in PLACEHOLDER_VALUES:
        return True
    if normalized.startswith(("your_", "replace_", "insert_", "example_")):
        return True
    if re.fullmatch(r"(?:x{3,}|0{4,}|[*_.-]{4,})", normalized):
        return True
    return False


def _extract_assignment_value(match: re.Match[str]):
    """Return the captured assignment value and its exact character span."""
    for group_index, group_value in enumerate(match.groups(), start=1):
        if group_value is not None:
            return group_value, match.start(group_index), match.end(group_index)
    return "", match.end(), match.end()


class SensitiveDataDetector:
    """Detect potentially sensitive data without exposing matched values."""

    def __init__(self) -> None:
        self.patterns = PATTERNS
        logger.info("Sensitive data detector initialized")

    def assess(self, text: str) -> Assessment:
        """
        Assess text and return finding metadata.

        Raises:
            TypeError: If text is not a string.
            ValueError: If text is empty, whitespace-only, or too large.
        """
        if not isinstance(text, str):
            logger.warning("Assessment rejected: input is not a string")
            raise TypeError("text must be a string")

        if not text.strip():
            logger.warning("Assessment rejected: input is empty")
            raise ValueError("text must not be empty")

        if len(text) > MAX_DOCUMENT_LENGTH:
            logger.warning("Assessment rejected: input exceeds size limit")
            raise ValueError(
                f"text must not exceed {MAX_DOCUMENT_LENGTH} characters"
            )

        findings: List[Finding] = []

        # Email addresses and private-key headers can be detected directly.
        for category in ("private_key", "email_address"):
            for match in self.patterns[category].finditer(text):
                findings.append({
                    "category": category,
                    "start": match.start(),
                    "end": match.end(),
                    "match_type": "pattern_match",
                })

        # Credential assignments: ignore clearly illustrative placeholders.
        for category in ("password", "api_key"):
            pattern = self.patterns[category]
            for match in pattern.finditer(text):
                value, value_start, value_end = _extract_assignment_value(match)
                if _is_placeholder(value):
                    continue

                # Report the exact captured value span, excluding quotes and label.
                findings.append({
                    "category": category,
                    "start": value_start,
                    "end": value_end,
                    "match_type": "pattern_match",
                })

        for match in self.patterns["access_token"].finditer(text):
            value = match.group(0)
            if _is_placeholder(value):
                continue

            # A contextual assignment is more informative than a second,
            # overlapping token-family finding for the same value.
            covered_by_assignment = any(
                finding["category"] in ("api_key", "password")
                and finding["start"] <= match.start()
                and finding["end"] >= match.end()
                for finding in findings
            )
            if covered_by_assignment:
                continue

            findings.append({
                "category": "access_token",
                "start": match.start(),
                "end": match.end(),
                "match_type": "pattern_match",
            })

        # Report only the token span, excluding the authorization label.
        for match in self.patterns["bearer_jwt"].finditer(text):
            token_start, token_end = match.span(1)
            findings.append({
                "category": "access_token",
                "start": token_start,
                "end": token_end,
                "match_type": "pattern_match",
            })

        # Phone patterns need a phone-related label immediately before them.
        for match in self.patterns["phone_number"].finditer(text):
            prefix = text[max(0, match.start() - 40):match.start()]
            if not PHONE_CONTEXT_PATTERN.search(prefix):
                continue
            digits = re.sub(r"\D", "", match.group(0))
            if not 7 <= len(digits) <= 15:
                continue
            findings.append({
                "category": "phone_number",
                "start": match.start(),
                "end": match.end(),
                "match_type": "pattern_match",
            })

        # Stable ordering makes output deterministic. For exact duplicate spans,
        # category provides a deterministic tie-breaker.
        findings.sort(key=lambda item: (item["start"], item["end"], item["category"]))

        # De-duplicate identical category/span findings while preserving order.
        unique_findings: List[Finding] = []
        seen = set()
        for finding in findings:
            key = (finding["category"], finding["start"], finding["end"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        result: Assessment = {
            "has_sensitive_data": bool(unique_findings),
            "findings": unique_findings,
            "finding_count": len(unique_findings),
        }

        logger.info(
            "Sensitive data assessment completed; findings=%d, detected=%s",
            result["finding_count"],
            result["has_sensitive_data"],
        )
        return result
