import math
from utils.logger import get_logger

logger=get_logger("risk_engine","risk_engine.log")

class RiskEngine:
    """Combines jailbreak and prompt injection detector scores into overall risk score"""
    JAILBREAK_WEIGHT=0.5
    PROMPT_INJECTION_WEIGHT=0.5
    LOW_THRESHOLD=0.30
    HIGH_THRESHOLD=0.70
    HIGH_RISK_OVERRIDE_THRESHOLD=0.90

    def __int__(self):
        logger.into("Initializing RiskEngine...")

    def _validate_score(self, score, score_name):
        """Validate that a detector score is a finite numeric value between 0.0 and 1.0"""
        logger.debug("Validating %s score: %r", score_name, score)
        if isinstance(score, bool) or not isinstance(score, (int,float)):
            raise ValueError(f"{score_name} must be a numeric value between 0 and 1")

        if not math.isfinite(score):
            raise ValueError(f"{score_name} must be a finite numeric value between 0 and 1")

        if not 0.0<=score<=1.0:
            raise ValueError(f"{score_name} must be between 0 and 1")

        return float(score)

    def calculate_risk_score(self, jailbreak_score, prompt_injection_score):
        """Calculate the weighted overall risk score."""

        logger.info("Starting risk score calculation")
        jailbreak_score=self._validate_score(jailbreak_score,"jailbreak_score")
        prompt_injection_score=self._validate_score(prompt_injection_score,"prompt_injection_score")
        logger.info("Detector scores - jailbreak: %.3f, prompt_injection: %.3f",jailbreak_score, prompt_injection_score)
        risk_score=(jailbreak_score*self.JAILBREAK_WEIGHT+prompt_injection_score*self.PROMPT_INJECTION_WEIGHT)
        logger.info("Calculated risk score: %.6f", risk_score)
        return risk_score

    def determine_risk_level(self, risk_score, jailbreak_score, prompt_injection_score):
        """Determine the risk level from the calculated score."""

        logger.debug("Determining risk level for score: %.6f", risk_score)
        if (jailbreak_score >= self.HIGH_RISK_OVERRIDE_THRESHOLD or prompt_injection_score >= self.HIGH_RISK_OVERRIDE_THRESHOLD):
            logger.info("High-risk override triggered")
            return "HIGH"
        if risk_score < self.LOW_THRESHOLD:
            return "LOW"
        if risk_score < self.HIGH_THRESHOLD:
            return "MEDIUM"
        return "HIGH"

    def determine_decision(self, risk_level):
        """
        Map the risk level to a security decision.
        """

        decision_map = {
            "LOW": "ALLOW",
            "MEDIUM": "REVIEW",
            "HIGH": "BLOCK"
        }
        if risk_level not in decision_map:
            raise ValueError(f"Invalid risk level: {risk_level}")
        decision = decision_map[risk_level]
        logger.info("Risk level: %s | Decision: %s",risk_level, decision)
        return decision

    def assess(self, jailbreak_score, prompt_injection_score):
        """
        Perform a complete risk assessment.

        Returns:
            dict: Structured risk assessment result.
        """

        logger.info("Starting complete risk assessment")
        jailbreak_score = self._validate_score(jailbreak_score,"jailbreak_score")
        prompt_injection_score = self._validate_score(prompt_injection_score,"prompt_injection_score")
        risk_score = self.calculate_risk_score(jailbreak_score, prompt_injection_score)

        risk_level = self.determine_risk_level(risk_score, jailbreak_score, prompt_injection_score)

        decision = self.determine_decision(risk_level)
        result = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "decision": decision,
            "signals": {
                "jailbreak_score": jailbreak_score,
                "prompt_injection_score": prompt_injection_score
            }
        }

        logger.info(
            "Risk assessment completed: level= %s, decision= %s",
            risk_level,
            decision
        )

        return result