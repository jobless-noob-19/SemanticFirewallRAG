import pytest
import math

from risk_scoring.risk_engine import RiskEngine


@pytest.fixture
def risk_engine():
    return RiskEngine()


# ---------------------------------------------------------
# Basic scoring tests
# ---------------------------------------------------------

def test_both_scores_zero(risk_engine):
    result = risk_engine.assess(0.0, 0.0)

    assert result["risk_score"] == 0.0
    assert result["risk_level"] == "LOW"
    assert result["decision"] == "ALLOW"


def test_jailbreak_only(risk_engine):
    result = risk_engine.assess(0.8, 0.0)

    assert result["risk_score"] == 0.4
    assert result["risk_level"] == "MEDIUM"
    assert result["decision"] == "REVIEW"


def test_injection_only(risk_engine):
    result = risk_engine.assess(0.0, 0.8)

    assert result["risk_score"] == 0.4
    assert result["risk_level"] == "MEDIUM"
    assert result["decision"] == "REVIEW"


def test_both_high(risk_engine):
    result = risk_engine.assess(0.9, 0.9)

    assert result["risk_score"] == 0.9
    assert result["risk_level"] == "HIGH"
    assert result["decision"] == "BLOCK"


def test_both_medium(risk_engine):
    result = risk_engine.assess(0.6, 0.6)

    assert result["risk_score"] == 0.6
    assert result["risk_level"] == "MEDIUM"
    assert result["decision"] == "REVIEW"


# ---------------------------------------------------------
# Mathematical correctness
# ---------------------------------------------------------

def test_weighted_score_calculation(risk_engine):
    result = risk_engine.assess(0.8, 0.6)

    expected_score = (0.8 * 0.5) + (0.6 * 0.5)

    assert result["risk_score"] == expected_score


def test_score_is_between_zero_and_one(risk_engine):
    test_cases = [
        (0.0, 0.0),
        (0.2, 0.4),
        (0.5, 0.7),
        (1.0, 0.0),
        (0.0, 1.0),
        (1.0, 1.0),
    ]

    for jailbreak_score, injection_score in test_cases:
        result = risk_engine.assess(
            jailbreak_score,
            injection_score
        )

        assert 0.0 <= result["risk_score"] <= 1.0


# ---------------------------------------------------------
# Risk-level tests
# ---------------------------------------------------------

def test_low_risk(risk_engine):
    result = risk_engine.assess(0.2, 0.2)

    assert result["risk_score"] == 0.2
    assert result["risk_level"] == "LOW"


def test_medium_risk(risk_engine):
    result = risk_engine.assess(0.5, 0.5)

    assert result["risk_score"] == 0.5
    assert result["risk_level"] == "MEDIUM"


def test_high_risk(risk_engine):
    result = risk_engine.assess(0.8, 0.8)

    assert result["risk_score"] == 0.8
    assert result["risk_level"] == "HIGH"


def test_boundary_0_30(risk_engine):
    result = risk_engine.assess(0.3, 0.3)

    assert result["risk_score"] == 0.3
    assert result["risk_level"] == "MEDIUM"


def test_boundary_0_70(risk_engine):
    result = risk_engine.assess(0.7, 0.7)

    assert result["risk_score"] == 0.7
    assert result["risk_level"] == "HIGH"


# ---------------------------------------------------------
# Decision tests
# ---------------------------------------------------------

def test_low_risk_allows(risk_engine):
    result = risk_engine.assess(0.1, 0.1)

    assert result["decision"] == "ALLOW"


def test_medium_risk_requires_review(risk_engine):
    result = risk_engine.assess(0.5, 0.5)

    assert result["decision"] == "REVIEW"


def test_high_risk_blocks(risk_engine):
    result = risk_engine.assess(0.8, 0.8)

    assert result["decision"] == "BLOCK"


# ---------------------------------------------------------
# High-risk override tests
# ---------------------------------------------------------

def test_jailbreak_high_risk_override(risk_engine):
    result = risk_engine.assess(0.9, 0.0)

    assert result["risk_score"] == 0.45
    assert result["risk_level"] == "HIGH"
    assert result["decision"] == "BLOCK"


def test_injection_high_risk_override(risk_engine):
    result = risk_engine.assess(0.0, 0.9)

    assert result["risk_score"] == 0.45
    assert result["risk_level"] == "HIGH"
    assert result["decision"] == "BLOCK"


# ---------------------------------------------------------
# Validation tests
# ---------------------------------------------------------

def test_invalid_jailbreak_score(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess("high", 0.5)


def test_invalid_injection_score(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(0.5, "high")


def test_negative_score(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(-0.1, 0.5)


def test_score_above_one(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(1.1, 0.5)


def test_none_score(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(None, 0.5)


def test_boolean_score(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(True, 0.5)


# ---------------------------------------------------------
# Additional validation edge cases
# ---------------------------------------------------------

def test_nan_jailbreak_score(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(float("nan"), 0.5)


def test_infinite_injection_score(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(0.5, float("inf"))


def test_negative_infinity_score(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(float("-inf"), 0.5)


def test_list_score_is_rejected(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess([], 0.5)


def test_dictionary_score_is_rejected(risk_engine):
    with pytest.raises(ValueError):
        risk_engine.assess(0.5, {})


# ---------------------------------------------------------
# Override boundary tests
# ---------------------------------------------------------

def test_override_just_below_threshold(risk_engine):
    result = risk_engine.assess(0.899, 0.0)

    assert result["risk_score"] == 0.4495
    assert result["risk_level"] == "MEDIUM"
    assert result["decision"] == "REVIEW"


def test_override_at_threshold(risk_engine):
    result = risk_engine.assess(0.90, 0.0)

    assert result["risk_score"] == 0.45
    assert result["risk_level"] == "HIGH"
    assert result["decision"] == "BLOCK"


def test_override_just_above_threshold(risk_engine):
    result = risk_engine.assess(0.901, 0.0)

    assert result["risk_level"] == "HIGH"
    assert result["decision"] == "BLOCK"


# ---------------------------------------------------------
# Maximum and minimum score tests
# ---------------------------------------------------------

def test_both_scores_one(risk_engine):
    result = risk_engine.assess(1.0, 1.0)

    assert result["risk_score"] == 1.0
    assert result["risk_level"] == "HIGH"
    assert result["decision"] == "BLOCK"


def test_maximum_score_with_zero_other_score(risk_engine):
    result = risk_engine.assess(1.0, 0.0)

    assert result["risk_score"] == 0.5
    assert result["risk_level"] == "HIGH"
    assert result["decision"] == "BLOCK"


# ---------------------------------------------------------
# Output structure tests
# ---------------------------------------------------------

def test_result_contains_expected_fields(risk_engine):
    result = risk_engine.assess(0.4, 0.2)

    assert set(result.keys()) == {
        "risk_score",
        "risk_level",
        "decision",
        "signals",
    }

    assert set(result["signals"].keys()) == {
        "jailbreak_score",
        "prompt_injection_score",
    }


def test_scores_in_result_are_normalized(risk_engine):
    result = risk_engine.assess(0.4, 0.2)

    assert result["signals"]["jailbreak_score"] == 0.4
    assert result["signals"]["prompt_injection_score"] == 0.2
