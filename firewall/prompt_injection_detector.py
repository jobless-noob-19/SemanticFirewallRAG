import re
from typing import Dict, List
from utils.logger import get_logger
logger = get_logger("prompt_injection_detector","prompt_injection_detector.log")

class PromptInjectionDetector:
    """
    Rule-based detector for prompt injection attempts.
    It only returns detection information and a normalized score.
    """

    def __init__(self):
        logger.info("Initializing PromptInjectionDetector...")

        self.patterns = {
            "instruction_override": [
                re.compile(
                    r"\bignore\s+(?:all\s+)?(?:the\s+)?"
                    r"(?:previous|prior|above|earlier)\s+instructions?\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\bdisregard\s+(?:all\s+)?(?:the\s+)?"
                    r"(?:(?:previous|prior|above|earlier)\s+instructions?"
                    r"|instructions?\s+(?:above|previous|prior|earlier))\b",
                    re.IGNORECASE
                ),
                re.compile( 
                    r"\boverride\s+(?:the\s+)?"
                    r"(?:previous|current|existing|original)\s+instructions?\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\bforget\s+(?:all\s+)?(?:the\s+)?"
                    r"(?:previous|prior|above|earlier)\s+instructions?\b",
                    re.IGNORECASE
                ),
            ],

            "instruction_hierarchy_manipulation": [
                re.compile(
                    r"\btreat\s+(?:this|the\s+following)\s+"
                    r"(?:as|like)\s+(?:a\s+)?"
                    r"(?:system|developer|higher[-\s]?priority)\s+"
                    r"instruction\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\b(?:system|developer)\s+instructions?\s+"
                    r"(?:should|must|will)\s+"
                    r"(?:be\s+)?(?:replaced|overridden|ignored)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\b(?:take|takes)\s+precedence\s+over\s+"
                    r"(?:the\s+)?(?:system|developer|previous|original)\s+"
                    r"instructions?\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\b(?:higher|highest)\s+priority\s+"
                    r"instruction\b",
                    re.IGNORECASE
                ),
            ],

            "user_instruction_escalation": [
                re.compile(
                    r"\btreat\s+(?:my|this)\s+(?:message|text|input|"
                    r"prompt)\s+as\s+(?:a\s+)?"
                    r"(?:system|developer|admin|administrator)\s+"
                    r"instruction\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\bconsider\s+(?:this|the\s+following)\s+"
                    r"(?:message|text|input|prompt)\s+"
                    r"(?:to\s+be|as)\s+(?:a\s+)?"
                    r"(?:system|developer|admin|administrator)\s+"
                    r"instruction\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\b(?:my|this)\s+(?:message|prompt|input)\s+"
                    r"(?:has|should\s+have)\s+"
                    r"(?:system|developer|administrator)\s+"
                    r"(?:level|priority|authority)\b",
                    re.IGNORECASE
                ),
            ],

            "context_manipulation": [
                re.compile(
                    r"\bignore\s+(?:the\s+)?"
                    r"(?:retrieved|provided|given|supplied)\s+"
                    r"(?:context|documents?|information)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\bdisregard\s+(?:the\s+)?"
                    r"(?:retrieved|provided|given|supplied)\s+"
                    r"(?:context|documents?|information)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\boverride\s+(?:the\s+)?"
                    r"(?:retrieved|provided|given|supplied)\s+"
                    r"(?:context|documents?)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\breplace\s+(?:the\s+)?"
                    r"(?:retrieved|provided|given|supplied)\s+"
                    r"(?:context|documents?)\b",
                    re.IGNORECASE
                ),
            ],

            "contextual_instruction_injection": [
                re.compile(
                    r"\bfollow\s+(?:the\s+)?instructions?\s+"
                    r"(?:contained|embedded|included)\s+"
                    r"(?:in|within)\s+(?:the\s+)?"
                    r"(?:document|context|text|retrieved\s+content)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\b(?:instructions?|commands?)\s+"
                    r"(?:embedded|hidden|contained|included)\s+"
                    r"(?:in|within)\s+(?:the\s+)?"
                    r"(?:document|context|text|content)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\bwhen\s+(?:this|the\s+following)\s+"
                    r"(?:text|document|content)\s+is\s+"
                    r"(?:retrieved|provided|included),?\s+"
                    r"(?:follow|execute|obey)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\btreat\s+(?:the\s+)?(?:retrieved|provided|"
                    r"document|contextual)\s+(?:text|content|data)"
                    r"\s+as\s+(?:instructions?|commands?)\b",
                    re.IGNORECASE
                ),
            ],

            "task_manipulation": [
                re.compile(
                    r"\binstead\s+of\s+(?:answering|performing|"
                    r"doing)\s+(?:the\s+)?(?:original|requested|"
                    r"intended)\s+(?:task|question),?\s+"
                    r"(?:do|perform|execute)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\b(?:your|the)\s+(?:new|actual|real)\s+"
                    r"task\s+is\s+now\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\breplace\s+(?:the\s+)?(?:original|current|"
                    r"intended)\s+(?:task|objective)\b",
                    re.IGNORECASE
                ),
                re.compile(
                    r"\bstop\s+(?:answering|following)\s+"
                    r"(?:the\s+)?(?:original|current|requested)\s+"
                    r"(?:task|question|instructions?)\b",
                    re.IGNORECASE
                ),
            ],
        }

        self.category_weights = {
            "instruction_override": 0.30,
            "instruction_hierarchy_manipulation": 0.30,
            "user_instruction_escalation": 0.30,
            "context_manipulation": 0.30,
            "contextual_instruction_injection": 0.25,
            "task_manipulation": 0.25,
        }

        logger.info("PromptInjectionDetector initialized successfully")

    @staticmethod
    def _normalize_query(query: str) -> str:
        """
        Normalize whitespace while preserving the actual content.
        """
        return re.sub(r"\s+", " ", query.strip())

    def detect(self, query: str) -> Dict:
        """
        Analyze a query for prompt injection patterns.

        Parameters
        ----------
        query : str User-provided query.
        Returns
        -------
        Dict
            Detection result containing:
            - is_injection
            - matched_patterns
            - score
        """
        logger.info("Running prompt injection detection...")

        if query is None:
            logger.warning("Prompt injection detector received None input")

            return {
                "is_injection": False,
                "matched_patterns": [],
                "score": 0.0
            }

        if not isinstance(query, str):
            logger.warning(
                "Invalid input type received: %s",
                type(query).__name__
            )

            return {
                "is_injection": False,
                "matched_patterns": [],
                "score": 0.0
            }

        normalized_query = self._normalize_query(query)

        if not normalized_query:
            logger.info("Empty query received")

            return {
                "is_injection": False,
                "matched_patterns": [],
                "score": 0.0
            }

        matched_categories: List[str] = []

        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern.search(normalized_query):
                    matched_categories.append(category)

                    logger.warning(
                        "Prompt injection pattern detected: %s",
                        category
                    )

                    # One match per category is enough.
                    break

        # Remove duplicates while preserving order.
        matched_categories = list(dict.fromkeys(matched_categories)) 

        # Score based on unique categories.
        score = sum(
            self.category_weights.get(category, 0.0)
            for category in matched_categories
        )

        # Normalize to [0.0, 1.0].
        score = min(score, 1.0)

        is_injection = len(matched_categories) > 0

        result = {
            "is_injection": is_injection,
            "matched_patterns": matched_categories,
            "score": round(score, 2)
        }

        logger.info("Prompt injection detection completed: %s",result)

        return result