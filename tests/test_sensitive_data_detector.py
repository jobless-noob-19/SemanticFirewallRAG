import logging

import pytest

from firewall.sensitive_data_detector import (
    MAX_DOCUMENT_LENGTH,
    SensitiveDataDetector,
)


@pytest.fixture
def detector():
    return SensitiveDataDetector()


def categories(result):
    return [finding["category"] for finding in result["findings"]]


def test_benign_document_has_no_findings(detector):
    result = detector.assess(
        "This document explains how a retrieval-augmented generation system works."
    )
    assert result == {
        "has_sensitive_data": False,
        "findings": [],
        "finding_count": 0,
    }


def test_detects_email_address(detector):
    text = "Contact support at analyst@example.com for assistance."
    result = detector.assess(text)
    matches = [f for f in result["findings"] if f["category"] == "email_address"]
    assert len(matches) == 1
    finding = matches[0]
    assert text[finding["start"]:finding["end"]] == "analyst@example.com"


def test_detects_password_assignment_without_returning_value(detector):
    text = 'password="N0tARealPassword!123"'
    result = detector.assess(text)
    finding = next(f for f in result["findings"] if f["category"] == "password")
    assert text[finding["start"]:finding["end"]] == "N0tARealPassword!123"
    assert "N0tARealPassword!123" not in repr(result)


def test_detects_api_key_assignment(detector):
    text = 'api_key="aB3dE6gH9jK2mN5pQ8rT"'
    result = detector.assess(text)
    assert "api_key" in categories(result)
    assert "aB3dE6gH9jK2mN5pQ8rT" not in repr(result)


def test_detects_common_token_families(detector):
    text = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    result = detector.assess(text)
    assert "access_token" in categories(result)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in repr(result)


def test_detects_private_key_header_only(detector):
    text = "-----BEGIN RSA PRIVATE KEY-----\n[redacted key body]"
    result = detector.assess(text)
    finding = next(f for f in result["findings"] if f["category"] == "private_key")
    assert text[finding["start"]:finding["end"]] == "-----BEGIN RSA PRIVATE KEY-----"
    assert "[redacted key body]" not in repr(result)


def test_detects_labeled_phone_number(detector):
    text = "Phone: +1 (415) 555-0132"
    result = detector.assess(text)
    finding = next(f for f in result["findings"] if f["category"] == "phone_number")
    assert text[finding["start"]:finding["end"]] == "+1 (415) 555-0132"


def test_ignores_unlabeled_number_sequence(detector):
    result = detector.assess("The build identifier is 415-555-0132.")
    assert "phone_number" not in categories(result)


@pytest.mark.parametrize(
    "text",
    [
        'api_key="YOUR_API_KEY"',
        "password=changeme",
        "access_token=replace-with-your-key",
        "api_key=XXXXXXXX",
        "The docs use the placeholder YOUR_SECRET in examples.",
    ],
)
def test_ignores_obvious_placeholders(detector, text):
    result = detector.assess(text)
    assert result["finding_count"] == 0


def test_multiple_categories_in_one_document(detector):
    text = (
        "Email: analyst@example.com; "
        'password="UniquePass!456"; '
        'api_key="uN1queApiKeyValue987654"'
    )
    result = detector.assess(text)
    assert {"email_address", "password", "api_key"}.issubset(set(categories(result)))
    assert result["finding_count"] >= 3


def test_repeated_occurrences_are_reported_separately(detector):
    text = "a@example.com and b@example.com"
    result = detector.assess(text)
    email_findings = [f for f in result["findings"] if f["category"] == "email_address"]
    assert len(email_findings) == 2


def test_case_variations_for_assignment_labels(detector):
    result = detector.assess('PASSWORD="CaseSensitiveValue987!"')
    assert "password" in categories(result)


def test_unicode_around_sensitive_value(detector):
    text = "使用者 📧 analyst@example.com — 完了"
    result = detector.assess(text)
    assert "email_address" in categories(result)


def test_empty_input_raises_value_error(detector):
    with pytest.raises(ValueError, match="must not be empty"):
        detector.assess("")


@pytest.mark.parametrize("text", [" ", "\t\n  "])
def test_whitespace_only_input_raises_value_error(detector, text):
    with pytest.raises(ValueError, match="must not be empty"):
        detector.assess(text)


@pytest.mark.parametrize("value", [None, 42, b"email@example.com", [], {}])
def test_non_string_input_raises_type_error(detector, value):
    with pytest.raises(TypeError, match="must be a string"):
        detector.assess(value)


def test_oversized_input_raises_value_error(detector):
    with pytest.raises(ValueError, match="must not exceed"):
        detector.assess("a" * (MAX_DOCUMENT_LENGTH + 1))


def test_exact_size_limit_is_accepted(detector):
    text = "a" * MAX_DOCUMENT_LENGTH
    result = detector.assess(text)
    assert result["has_sensitive_data"] is False
    assert result["finding_count"] == 0


def test_result_schema_and_types(detector):
    result = detector.assess("Contact analyst@example.com")
    assert set(result) == {"has_sensitive_data", "findings", "finding_count"}
    assert isinstance(result["has_sensitive_data"], bool)
    assert isinstance(result["findings"], list)
    assert isinstance(result["finding_count"], int)

    for finding in result["findings"]:
        assert set(finding) == {"category", "start", "end", "match_type"}
        assert isinstance(finding["category"], str)
        assert isinstance(finding["start"], int)
        assert isinstance(finding["end"], int)
        assert isinstance(finding["match_type"], str)
        assert finding["match_type"] == "pattern_match"


def test_output_is_deterministic(detector):
    text = 'Email analyst@example.com; password="UniquePass!456"'
    assert detector.assess(text) == detector.assess(text)


def test_input_is_not_mutated(detector):
    text = 'password="UniquePass!456" and analyst@example.com'
    original = text
    detector.assess(text)
    assert text == original


def test_logs_do_not_contain_complete_secret_values(detector, caplog):
    secret_password = "UniquePass!456"
    secret_key = "uN1queApiKeyValue987654"
    text = f'password="{secret_password}" api_key="{secret_key}"'

    with caplog.at_level(logging.INFO, logger="sensitive_data_detector"):
        detector.assess(text)

    assert secret_password not in caplog.text
    assert secret_key not in caplog.text


def test_error_messages_do_not_include_invalid_input(detector):
    secret = "do-not-leak-this@example.com"
    with pytest.raises(TypeError) as exc_info:
        detector.assess(secret.encode("utf-8"))
    assert secret not in str(exc_info.value)


def test_email_followed_by_sentence_period_excludes_period(detector):
    text = "Contact analyst@example.com."
    result = detector.assess(text)
    finding = next(f for f in result["findings"] if f["category"] == "email_address")
    assert text[finding["start"]:finding["end"]] == "analyst@example.com"


@pytest.mark.parametrize(
    ("text", "category", "expected_value"),
    [
        ('{"password": "JsonPassword!456"}', "password", "JsonPassword!456"),
        ('{"api_key": "JsonApiKeyValue987654"}', "api_key", "JsonApiKeyValue987654"),
    ],
)
def test_detects_json_style_credential_assignments(
    detector, text, category, expected_value
):
    result = detector.assess(text)
    finding = next(f for f in result["findings"] if f["category"] == category)
    assert text[finding["start"]:finding["end"]] == expected_value


def test_token_inside_api_key_assignment_is_not_reported_twice(detector):
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    text = f'api_key="{token}"'
    result = detector.assess(text)
    matching = [
        f for f in result["findings"]
        if text[f["start"]:f["end"]] == token
    ]
    assert len(matching) == 1
    assert matching[0]["category"] == "api_key"


@pytest.mark.parametrize(
    "text",
    [
        "analyst@@example.com",
        "analyst@example",
        "analyst@example..com",
        "analyst@-example.com",
    ],
)
def test_rejects_malformed_email_addresses(detector, text):
    result = detector.assess(text)
    assert "email_address" not in categories(result)


# ---------------------------------------------------------
# Additional false-positive and missed-detection tests
# Append these to test_sensitive_data_detector.py
# ---------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected_category"),
    [
        # Common token formats
        (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature",
            "access_token",
        ),
        (
            'access_token="SyntheticAccessToken987654321"',
            "api_key",
        ),
        # Phone numbers in natural-language contexts
        (
            "Phone number is +1 (415) 555-0132",
            "phone_number",
        ),
        (
            "Mobile: 9876543210",
            "phone_number",
        ),
    ],
)
def test_additional_sensitive_data_formats(
    detector, text, expected_category
):
    result = detector.assess(text)
    assert expected_category in categories(result)


@pytest.mark.parametrize(
    "text",
    [
        "The password field stores the user's credential.",
        "This document explains API key rotation.",
        "The build identifier is 123456789012.",
        "The example uses YOUR_API_KEY as a placeholder.",
        "Email validation rejects analyst@@example.com.",
    ],
)
def test_benign_or_non_secret_contexts_have_no_findings(
    detector, text
):
    result = detector.assess(text)
    assert result["finding_count"] == 0


@pytest.mark.parametrize(
    ("text", "expected_category"),
    [
        ('{"password": "SyntheticJsonPass!456"}', "password"),
        ('{"api_key": "SyntheticJsonApiKey987654"}', "api_key"),
        ("Contact analyst@example.com.", "email_address"),
        ("Phone: +1 (415) 555-0132", "phone_number"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
    ],
)
def test_regression_cases_for_supported_formats(
    detector, text, expected_category
):
    result = detector.assess(text)
    assert expected_category in categories(result)


def test_findings_have_valid_character_offsets(detector):
    text = 'Contact analyst@example.com and password="SyntheticPass!456"'
    result = detector.assess(text)

    for finding in result["findings"]:
        assert 0 <= finding["start"] < finding["end"] <= len(text)

    email = next(
        f for f in result["findings"]
        if f["category"] == "email_address"
    )
    assert text[email["start"]:email["end"]] == "analyst@example.com"


def test_findings_are_sorted_by_position(detector):
    text = 'password="SyntheticPass!456" contact analyst@example.com'
    result = detector.assess(text)

    starts = [finding["start"] for finding in result["findings"]]
    assert starts == sorted(starts)


def test_results_do_not_expose_token_values(detector):
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    result = detector.assess(secret)

    assert "access_token" in categories(result)
    assert secret not in repr(result)


def test_ordinary_password_discussion_is_not_a_finding(detector):
    text = "Never store a password in plain text."
    result = detector.assess(text)

    assert "password" not in categories(result)


def test_placeholder_api_key_in_json_is_ignored(detector):
    text = '{"api_key": "YOUR_API_KEY"}'
    result = detector.assess(text)

    assert "api_key" not in categories(result)


# ---------------------------------------------------------
# Additional false-positive and missed-detection tests
# Append these to test_sensitive_data_detector.py
# ---------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected_category"),
    [
        # Common token formats
        (
            "Authorization: Bearer "
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature",
            "access_token",
        ),
        (
            'access_token="SyntheticAccessToken987654321"',
            "api_key",
        ),
        # Phone numbers in natural-language contexts
        (
            "Phone number is +1 (415) 555-0132",
            "phone_number",
        ),
        (
            "Mobile: 9876543210",
            "phone_number",
        ),
    ],
)
def test_additional_sensitive_data_formats(
    detector, text, expected_category
):
    result = detector.assess(text)
    assert expected_category in categories(result)


@pytest.mark.parametrize(
    "text",
    [
        "The password field stores the user's credential.",
        "This document explains API key rotation.",
        "The build identifier is 123456789012.",
        "The example uses YOUR_API_KEY as a placeholder.",
        "Email validation rejects analyst@@example.com.",
    ],
)
def test_benign_or_non_secret_contexts_have_no_findings(
    detector, text
):
    result = detector.assess(text)
    assert result["finding_count"] == 0


@pytest.mark.parametrize(
    ("text", "expected_category"),
    [
        ('{"password": "SyntheticJsonPass!456"}', "password"),
        ('{"api_key": "SyntheticJsonApiKey987654"}', "api_key"),
        ("Contact analyst@example.com.", "email_address"),
        ("Phone: +1 (415) 555-0132", "phone_number"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
    ],
)
def test_regression_cases_for_supported_formats(
    detector, text, expected_category
):
    result = detector.assess(text)
    assert expected_category in categories(result)


def test_findings_have_valid_character_offsets(detector):
    text = 'Contact analyst@example.com and password="SyntheticPass!456"'
    result = detector.assess(text)

    for finding in result["findings"]:
        assert 0 <= finding["start"] < finding["end"] <= len(text)

    email = next(
        f for f in result["findings"]
        if f["category"] == "email_address"
    )
    assert text[email["start"]:email["end"]] == "analyst@example.com"


def test_findings_are_sorted_by_position(detector):
    text = 'password="SyntheticPass!456" contact analyst@example.com'
    result = detector.assess(text)

    starts = [finding["start"] for finding in result["findings"]]
    assert starts == sorted(starts)


def test_results_do_not_expose_token_values(detector):
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    result = detector.assess(secret)

    assert "access_token" in categories(result)
    assert secret not in repr(result)


def test_ordinary_password_discussion_is_not_a_finding(detector):
    text = "Never store a password in plain text."
    result = detector.assess(text)

    assert "password" not in categories(result)


def test_placeholder_api_key_in_json_is_ignored(detector):
    text = '{"api_key": "YOUR_API_KEY"}'
    result = detector.assess(text)

    assert "api_key" not in categories(result)

def test_bearer_label_without_jwt_shape_is_not_enough(detector):
    result = detector.assess(
        "Authorization: Bearer ordinary-user-session"
    )
    assert "access_token" not in categories(result)