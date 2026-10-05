import re

from utils.logger import get_logger


logger = get_logger("jailbreak_detector", "jailbreak_detector.log")


class JailbreakDetector:
    """
    Detect potential jailbreak attempts in user queries.

    The detector uses rule-based pattern matching to identify
    common jailbreak indicators.
    """

    def __init__(self):
        logger.info("Initializing JailbreakDetector...")

        self.jailbreak_patterns = [
            r"\bignore\s+(all\s+)?previous\s+instructions\b",
            r"\bignore\s+(all\s+)?prior\s+instructions\b",
            r"\bforget\s+(all\s+)?previous\s+instructions\b",
            r"\bforget\s+(all\s+)?prior\s+instructions\b",

            r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
            r"\bdisregard\s+(all\s+)?prior\s+instructions\b",

            r"\boverride\s+(your\s+)?instructions\b",
            r"\bbypass\s+(your\s+)?(rules|restrictions|safety)\b",

            r"\bignore\s+your\s+(rules|guidelines|instructions)\b",

            r"\bact\s+as\s+(an?\s+)?unrestricted\b",
            r"\bact\s+as\s+(an?\s+)?uncensored\b",

            r"\byou\s+are\s+now\s+(an?\s+)?unrestricted\b",
            r"\byou\s+are\s+now\s+(an?\s+)?uncensored\b",

            r"\bdeveloper\s+mode\b",
            r"\bdan\s+mode\b",

            r"\bdisable\s+(your\s+)?(safety|safeguards|restrictions)\b",

            r"\breveal\s+(your\s+)?system\s+prompt\b",
            r"\bshow\s+(me\s+)?(your\s+)?system\s+prompt\b",
        ]

        logger.info("JailbreakDetector initialized successfully")

    def detect(self, query):
        """
        Detect whether a query contains jailbreak indicators.

        Args:
            query (str): User query.

        Returns:
            dict: Detection result containing:
                - is_jailbreak
                - matched_patterns
                - score
        """

        if not isinstance(query, str):
            raise TypeError("Query must be a string")

        query = query.strip()

        if not query:
            return {
                "is_jailbreak": False,
                "matched_patterns": [],
                "score": 0.0
            }

        matched_patterns = []

        for pattern in self.jailbreak_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                matched_patterns.append(pattern)

        # Simple normalized score.
        # Multiple matched indicators increase confidence.
        score = min(len(matched_patterns) / 3, 1.0)

        is_jailbreak = len(matched_patterns) > 0

        result = {
            "is_jailbreak": is_jailbreak,
            "matched_patterns": matched_patterns,
            "score": score
        }

        logger.info(
            "Jailbreak detection completed: is_jailbreak=%s, score=%.2f",
            is_jailbreak,
            score
        )

        return result