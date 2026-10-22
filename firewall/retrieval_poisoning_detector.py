
"""
Retrieval Poisoning Detector
Project: SemanticFirewallRAG

Assesses retrieved document text for suspicious embedded instructions.
This module does not modify documents, retrieve data, call an LLM,
or make application-level blocking decisions.
"""

import re
from typing import Dict, List, Pattern, Tuple

from utils.logger import get_logger


logger = get_logger(
    "retrieval_poisoning_detector",
    "retrieval_poisoning_detector.log",
)


MAX_DOCUMENT_LENGTH = 1_000_000

RISK_THRESHOLDS = {
    "LOW": 0.30,
    "MEDIUM": 0.60,
}

# Provisional Version 1 weights.
# These are engineering heuristics, not calibrated probabilities.
CATEGORY_WEIGHTS = {
    "instruction_override": 0.35,
    "sensitive_disclosure": 0.35,
    "secret_extraction": 0.35,
    "task_redirection": 0.25,
    "retrieval_manipulation": 0.20,
}


# Each category contains patterns describing combinations of words
# that indicate potentially malicious instructions. Isolated words
# such as "system", "secret", or "ignore" are not sufficient.
INDICATOR_PATTERNS: Dict[str, Tuple[Pattern[str], ...]] = {
    "instruction_override": (
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b"
            r"(?:[\s,;:]+[\w'-]+){0,4}"
            r"[\s,;:]+(?:all\s+)?"
            r"(?:previous|prior|preceding|earlier|existing|"
            r"system|developer)\s+instructions?\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:override|bypass|disregard)\s+"
            r"(?:the\s+)?(?:system|developer)\s+"
            r"(?:prompt|instructions?|rules?|message)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bforget\s+(?:everything|all\s+rules|"
            r"all\s+instructions)\b",
            re.IGNORECASE,
        ),
    ),
    "sensitive_disclosure": (
        re.compile(
            r"\b(?:reveal|disclose|expose|print|output|"
            r"show|repeat|dump|leak|provide)\b"
            r"(?:[\s,;:]+[\w'-]+){0,5}"
            r"[\s,;:]+(?:the\s+)?"
            r"(?:hidden|secret|internal|confidential|"
            r"full|original|entire)?\s*"
            r"(?:system\s+prompt|developer\s+message|"
            r"developer\s+instructions?|hidden\s+prompt|"
            r"internal\s+instructions?|confidential\s+information)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:reveal|disclose|expose|leak|dump)\s+"
            r"(?:all\s+)?(?:confidential|private)\s+"
            r"(?:data|information|records)\b",
            re.IGNORECASE,
        ),
    ),
    "secret_extraction": (
        re.compile(
            r"\b(?:reveal|expose|print|output|dump|"
            r"disclose|leak|extract|return|provide)\b"
            r"(?:[\s,;:]+[\w'-]+){0,4}"
            r"[\s,;:]+(?:all\s+)?"
            r"(?:api\s+keys?|access\s+tokens?|"
            r"passwords?|credentials?|private\s+keys?|"
            r"authentication\s+tokens?|secrets)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:send|transmit|exfiltrate)\b"
            r"(?:[\s,;:]+[\w'-]+){0,4}"
            r"[\s,;:]+(?:the\s+)?"
            r"(?:credentials?|api\s+keys?|passwords?|secrets)\b",
            re.IGNORECASE,
        ),
    ),
    "task_redirection": (
        re.compile(
            r"\b(?:ignore|disregard|abandon|stop\s+answering)\b"
            r"(?:[\s,;:]+[\w'-]+){0,5}"
            r"[\s,;:]+(?:the\s+)?"
            r"(?:user'?s?\s+)?(?:original\s+)?"
            r"(?:question|request|task|query)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:instead|rather)\s*,?\s*"
            r"(?:answer|respond|output|perform|execute|"
            r"follow|do)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:do\s+not|don't|never)\s+"
            r"(?:answer|address|respond\s+to)\s+"
            r"(?:the\s+)?(?:user'?s?\s+)?"
            r"(?:original\s+)?(?:question|request|query)\b",
            re.IGNORECASE,
        ),
    ),
    "retrieval_manipulation": (
        re.compile(
            r"\b(?:treat|consider|regard)\s+"
            r"(?:this|the\s+following|retrieved)\s+"
            r"(?:document|content|text|context)\s+"
            r"as\s+(?:the\s+)?"
            r"(?:system|developer)\s+"
            r"(?:prompt|message|instructions?|authority)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:trust|prioritize|obey|follow)\b"
            r"(?:[\s,;:]+[\w'-]+){0,4}"
            r"[\s,;:]+(?:this\s+)?(?:document|content|"
            r"context|text)\s+"
            r"(?:over|above|instead\s+of)\s+"
            r"(?:the\s+)?(?:system|developer|original)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:follow|obey)\s+(?:all\s+)?"
            r"(?:instructions|commands)\s+"
            r"in\s+this\s+document\b",
            re.IGNORECASE,
        ),
    ),
}


# These cues are used only when they occur near a match in the same
# sentence. They indicate that the phrase may be discussed rather
# than issued as an instruction.
EDUCATIONAL_CONTEXT_PATTERNS = (
    re.compile(
        r"\b(?:for\s+example|for\s+instance|e\.g\.|"
        r"an?\s+example\s+of|example\s+payload|"
        r"sample\s+(?:attack|payload|prompt)|"
        r"attack\s+(?:example|pattern|payload))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:an?\s+attacker|prompt\s+injection|"
        r"malicious\s+prompt|attackers?)\b"
        r"(?:[\s,;:]+[\w'-]+){0,6}"
        r"[\s,;:]+(?:might|may|could|can)\s+"
        r"(?:say|write|use|include|instruct|attempt)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:the\s+phrase|the\s+instruction|"
        r"this\s+payload|the\s+payload|the\s+example)\b"
        r"(?:[\s,;:]+[\w'-]+){0,5}"
        r"[\s,;:]+(?:illustrates|demonstrates|"
        r"represents|describes|is\s+an?\s+example)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:detect|identify|recognize|recognise|"
        r"defend\s+against|protect\s+against|"
        r"mitigate|prevent)\b"
        r"(?:[\s,;:]+[\w'-]+){0,5}"
        r"[\s,;:]+(?:prompt\s+injection|"
        r"malicious\s+instructions?|these\s+attacks?)\b",
        re.IGNORECASE,
    ),
)


def _split_sentences(text: str) -> List[str]:
    """Split text into approximate sentences for local context checks."""
    return [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+|\n+", text)
        if part.strip()
    ]


def _is_educational_context(sentence: str, match: re.Match) -> bool:
    """
    Determine whether a match is likely being discussed educationally.

    This is a heuristic, not a semantic guarantee. A context cue must
    occur within a bounded distance of the matched instruction.
    """
    match_start = match.start()

    context_start = max(0, match_start - 140)
    context_end = min(len(sentence), match.end() + 100)
    context = sentence[context_start:context_end]

    return any(
        pattern.search(context)
        for pattern in EDUCATIONAL_CONTEXT_PATTERNS
    )

def _is_negated_instruction(
    sentence: str,
    match_start: int,
) -> bool:
    """Identify instructions explicitly described as prohibited."""
    preceding_text = sentence[:match_start]
    # Only inspect a short window immediately before the matched phrase.
    preceding_text = preceding_text[-60:]

    negation_patterns = [
        r"\bnot\s+to\s*$",
        r"\bnever\s+to\s*$",
        r"\bmust\s+not\s*$",
        r"\bshould\s+not\s*$",
        r"\bdo\s+not\s*$",
        r"\bdon't\s*$",
        r"\bavoid\s*$",
        r"\bprohibited\s+from\s*$",
        r"\bforbidden\s+to\s*$",
    ]
    return any(
        re.search(pattern, preceding_text, re.IGNORECASE)
        for pattern in negation_patterns
    )


class RetrievalPoisoningDetector:
    """Assess retrieved document text for suspicious instructions."""

    def __init__(self) -> None:
        """Initialize the deterministic detection rules."""
        self.indicator_patterns = INDICATOR_PATTERNS
        self.category_weights = CATEGORY_WEIGHTS.copy()

        logger.info("Retrieval poisoning detector initialized")

    def assess(self, document_text: str) -> dict:
        """
        Assess a document and return a structured risk result.

        Args:
            document_text: Original retrieved document text.

        Returns:
            Dictionary containing suspicion status, score, risk level,
            matched indicator categories, and an explanatory reason.

        Raises:
            TypeError: If document_text is not a string.
            ValueError: If the document is empty, whitespace-only,
                or exceeds MAX_DOCUMENT_LENGTH.
        """
        if not isinstance(document_text, str):
            logger.warning(
                "Assessment rejected: document input is not a string"
            )
            raise TypeError("document_text must be a string")

        if not document_text.strip():
            logger.warning(
                "Assessment rejected: document input is empty"
            )
            raise ValueError("document_text must not be empty")

        if len(document_text) > MAX_DOCUMENT_LENGTH:
            logger.warning(
                "Assessment rejected: document exceeds size limit"
            )
            raise ValueError(
                f"document_text must not exceed "
                f"{MAX_DOCUMENT_LENGTH} characters"
            )

        logger.info(
            "Document assessment started; character_count=%d",
            len(document_text),
        )

        matched_indicators = self._detect_indicators(document_text)
        risk_score = self._calculate_risk_score(matched_indicators)
        risk_level = self._determine_risk_level(risk_score)
        is_suspicious = bool(matched_indicators)

        reason = self._build_reason(
            matched_indicators,
            risk_level,
        )

        result = {
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "matched_indicators": matched_indicators,
            "reason": reason,
        }

        logger.info(
            "Assessment completed; suspicious=%s, "
            "risk_score=%.2f, risk_level=%s, indicators=%s",
            is_suspicious,
            risk_score,
            risk_level,
            matched_indicators,
        )

        return result

    def _detect_indicators(self, document_text: str) -> List[str]:
        """
        Return unique indicator categories supported by active matches.

        Educational-context matches are excluded from scoring.
        The document text itself is never modified.
        """
        detected_categories = set()

        for sentence in _split_sentences(document_text):
            for category, patterns in self.indicator_patterns.items():
                if category in detected_categories:
                    continue

                for pattern in patterns:
                    for match in pattern.finditer(sentence):
                        if _is_educational_context(sentence, match):
                            logger.debug(
                                "Educational-context match excluded; "
                                "category=%s",
                                category,
                            )
                            continue
                        if (
                            category == "instruction_override"
                            and _is_negated_instruction(
                                sentence, 
                                match.start(),
                            )
                        ):
                            logger.debug(
                                "Negated instruction excluded; category=%s",
                                category,
                            )
                            continue

                        detected_categories.add(category)
                        # One category is counted once per document.
                        break

                    if category in detected_categories:
                        break

        indicators = sorted(detected_categories)

        if indicators:
            logger.warning(
                "Suspicious document indicators detected: %s",
                indicators,
            )
        else:
            logger.info("No active suspicious indicators detected")

        return indicators

    def _calculate_risk_score(
        self,
        matched_indicators: List[str],
    ) -> float:
        """
        Calculate the capped sum of distinct category weights.

        Repeated occurrences of the same category do not increase
        the score. Returned values are rounded to two decimal places.
        """
        score = sum(
            self.category_weights[indicator]
            for indicator in set(matched_indicators)
        )

        return round(min(1.0, max(0.0, score)), 2)

    @staticmethod
    def _determine_risk_level(risk_score: float) -> str:
        """Map a numerical score to the approved risk thresholds."""
        if risk_score < RISK_THRESHOLDS["LOW"]:
            return "LOW"

        if risk_score < RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"

        return "HIGH"

    @staticmethod
    def _build_reason(
        matched_indicators: List[str],
        risk_level: str,
    ) -> str:
        """Create a deterministic explanation for the assessment."""
        if not matched_indicators:
            return (
                "No active suspicious instruction indicators "
                "were detected by the configured rules"
            )

        if len(matched_indicators) > 1:
            return (
                "Multiple distinct suspicious instruction "
                "categories detected"
            )

        return (
            f"Suspicious instruction indicator detected: "
            f"{matched_indicators[0]}"
        )
