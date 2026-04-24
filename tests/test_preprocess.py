from security_rag.preprocess import normalize_event


def test_redaction_and_tags():
    event = {
        "timestamp": "2026-04-24T10:00:00Z",
        "host": "srv-auth-01",
        "event_type": "login",
        "severity": "high",
        "src_ip": "203.0.113.2",
        "message": "Login failed for user",
        "token": "supersecrettokenvalue",
    }
    normalized = normalize_event(event)
    assert normalized.raw["token"] == "[REDACTED]"
    assert "auth_failure" in normalized.tags
