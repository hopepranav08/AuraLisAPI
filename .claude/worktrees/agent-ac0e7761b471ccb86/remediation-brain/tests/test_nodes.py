# tests/test_nodes.py — Phase 3 Node Unit Tests
#
# Run with:
#   pip install pytest pytest-asyncio pytest-mock
#   pytest tests/test_nodes.py -v
#
# All GitHub API calls are mocked — tests run without a real GITHUB_TOKEN.
# All tests use in-memory LangGraph state without a database.
import asyncio
import json
import os
import sys

import pytest
import pytest_asyncio

# Ensure the remediation-brain package root is on the path when running
# from the tests/ subdirectory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent import nodes


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_state(path: str, extra: dict = None) -> dict:
    """Build a minimal valid IncidentState dict for testing."""
    base = {
        "raw_event":           {"method": "GET", "path": path, "status_code": 200},
        "incident_id":         "test-1234-abcd",
        "pii_findings":        [],
        "drift_scores":        [],
        "planned_actions":     [],
        "executed_actions":    [],
        "human_notes":         [],
        "reasoning_trace":     [],
        "enforcement_approved": False,
        "is_pii_exposed":      False,
        "spec_diff":           None,
        "github_pr_url":       None,
        "classification":      None,
        "severity":            None,
        "report":              None,
    }
    if extra:
        base.update(extra)
    return base


# A minimal OpenAPI 3.0 spec used in tests that exercise GitHub fetching.
_MOCK_SPEC = {
    "openapi": "3.0.0",
    "info":    {"title": "Test API", "version": "3.0"},
    "paths": {
        "/api/v1/users": {
            "get": {
                "deprecated": True,
                "summary": "legacy user list",
            }
        },
        "/api/v3/users": {
            "get": {
                "summary": "current user list",
            }
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: AnalyzerNode — active zombie via GitHub spec
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_active_zombie(mocker):
    """
    Endpoint present in spec with deprecated:true → active_zombie, severity=high.
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=_MOCK_SPEC)

    state  = _make_state("/api/v1/users")
    result = await nodes.analyze_node(state)

    assert result["classification"] == "active_zombie"
    assert result["severity"]       == "high"
    assert result["is_pii_exposed"] is False
    assert result["spec_diff"]["found_in_spec"]      is True
    assert result["spec_diff"]["deprecated_in_spec"] is True
    assert result["spec_diff"]["used_github_spec"]   is True


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: AnalyzerNode — PII detection → critical severity
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_pii_critical(mocker):
    """
    Active zombie endpoint with SSN in payload → is_pii_exposed=True, critical.
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=_MOCK_SPEC)

    # Inject SSN pattern into the raw event (simulates captured payload data)
    state = _make_state("/api/v1/users", extra={
        "raw_event": {
            "method":      "POST",
            "path":        "/api/v1/users",
            "status_code": 200,
            "payload":     "user_ssn=123-45-6789",   # triggers SSN pattern
        }
    })
    result = await nodes.analyze_node(state)

    assert result["is_pii_exposed"] is True
    assert "ssn" in result["pii_findings"]
    assert result["severity"]       == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: AnalyzerNode — shadow API (not in spec)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_shadow(mocker):
    """
    Endpoint not present in the OpenAPI spec at all → shadow, severity=medium.
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=_MOCK_SPEC)

    state  = _make_state("/api/v2/mystery-endpoint")
    result = await nodes.analyze_node(state)

    assert result["classification"]             == "shadow"
    assert result["severity"]                   == "medium"
    assert result["spec_diff"]["found_in_spec"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: AnalyzerNode — GitHub fetch failure → heuristic fallback
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_github_fallback(mocker):
    """
    When _fetch_openapi_spec returns None (e.g., no GITHUB_TOKEN),
    AnalyzerNode must fall back to path-prefix heuristics and NOT crash.
    """
    mocker.patch.object(nodes, "_fetch_openapi_spec", return_value=None)

    state  = _make_state("/api/v1/payments")
    result = await nodes.analyze_node(state)

    # /api/v1/ prefix → classified as active_zombie even without the spec
    assert result["classification"]                == "active_zombie"
    assert result["spec_diff"]["used_github_spec"] is False
    assert "severity" in result


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: PlannerNode — zombie+PII → escalate_to_ciso in planned_actions
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_plan_node_actions():
    """
    Active zombie with PII → planned_actions includes quarantine_gateway
    and escalate_to_ciso.
    """
    state = _make_state("/api/v1/users", extra={
        "classification":     "active_zombie",
        "severity":           "critical",
        "is_pii_exposed":     True,
        "enforcement_approved": True,
    })
    result = await nodes.plan_node(state)

    actions = result["planned_actions"]
    assert any("quarantine_gateway" in a for a in actions), actions
    assert any("escalate_to_ciso"   in a for a in actions), actions
    assert any("krakend_block"      in a for a in actions), actions
    assert any("spin_up_honeypot"   in a for a in actions), actions


@pytest.mark.asyncio
async def test_plan_node_low_severity():
    """Low severity → only log_only action, no garrison/escalate."""
    state  = _make_state("/api/v3/users", extra={
        "classification": "unknown",
        "severity":       "low",
        "is_pii_exposed": False,
        "enforcement_approved": False,
    })
    result = await nodes.plan_node(state)
    assert any("log_only" in a for a in result["planned_actions"])
    assert not any("quarantine_gateway" in a for a in result["planned_actions"])


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: EnforcerNode — stub mode when GITHUB_TOKEN is absent
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enforce_stub_mode(mocker):
    """
    When _github is None, enforce_node runs in stub mode:
    - Does NOT crash
    - Returns github_pr_url = None
    - executed_actions contains a STUB marker
    """
    mocker.patch.object(nodes, "_github", None)
    mocker.patch.object(nodes, "_github_repo", "")

    krakend_block = nodes._build_krakend_410_block("/api/v1/users", "test-1234-abcd")
    state = _make_state("/api/v1/users", extra={
        "classification":     "active_zombie",
        "severity":           "critical",
        "is_pii_exposed":     True,
        "enforcement_approved": True,
        "planned_actions": [
            "quarantine_gateway:/api/v1/users",
            f"krakend_block:{json.dumps(krakend_block)}",
        ],
    })

    result = await nodes.enforce_node(state)

    assert result["github_pr_url"] is None
    assert any("STUB" in a for a in result["executed_actions"]), result["executed_actions"]


@pytest.mark.asyncio
async def test_enforce_generates_pr(mocker):
    """
    When GitHub client is available, enforce_node must attempt PR creation.
    Mock the full PyGithub chain and assert the returned PR URL is captured.
    """
    # Build a mock GitHub PR object
    mock_pr     = mocker.MagicMock()
    mock_pr.html_url = "https://github.com/hopepranav08/AuraLisAPI/pull/42"

    mock_file    = mocker.MagicMock()
    mock_file.content = __import__("base64").b64encode(b'{"version":3,"endpoints":[]}').decode()
    mock_file.sha     = "abc123sha"

    mock_branch  = mocker.MagicMock()
    mock_branch.commit.sha = "deadbeef"

    mock_repo    = mocker.MagicMock()
    mock_repo.get_contents.return_value = mock_file
    mock_repo.get_branch.return_value   = mock_branch
    mock_repo.create_git_ref.return_value = mocker.MagicMock()
    mock_repo.update_file.return_value    = mocker.MagicMock()
    mock_repo.create_pull.return_value    = mock_pr

    mock_github = mocker.MagicMock()
    mock_github.get_repo.return_value = mock_repo

    mocker.patch.object(nodes, "_github",      mock_github)
    mocker.patch.object(nodes, "_github_repo", "hopepranav08/AuraLisAPI")

    # Also need to mock the GithubException import inside the function
    mocker.patch("github.GithubException", Exception)

    krakend_block = nodes._build_krakend_410_block("/api/v1/users", "test-1234-abcd")
    state = _make_state("/api/v1/users", extra={
        "classification":     "active_zombie",
        "severity":           "critical",
        "is_pii_exposed":     True,
        "enforcement_approved": True,
        "planned_actions": [
            "quarantine_gateway:/api/v1/users",
            f"krakend_block:{json.dumps(krakend_block)}",
        ],
        "pii_findings":    ["ssn"],
        "reasoning_trace": ["[analyze] active zombie detected"],
    })

    result = await nodes.enforce_node(state)

    # PR URL should be captured from the mocked PR object
    assert result["github_pr_url"] == "https://github.com/hopepranav08/AuraLisAPI/pull/42"
    assert any("PR created" in a for a in result["executed_actions"]), result["executed_actions"]
    # PyGithub chain should have been called
    mock_github.get_repo.assert_called_once_with("hopepranav08/AuraLisAPI")
    mock_repo.create_pull.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# Test 7: _detect_pii — entropy analysis catches high-entropy tokens
# ─────────────────────────────────────────────────────────────────────────────

def test_detect_pii_entropy():
    """High-entropy base64-like token triggers high_entropy_value finding."""
    # 32-char high-entropy string simulating a base64-encoded value
    high_entropy = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHQ="
    findings = nodes._detect_pii(f"token={high_entropy}")
    assert "high_entropy_value" in findings


def test_detect_pii_email():
    findings = nodes._detect_pii("contact: alice@example.com for support")
    assert "email" in findings


def test_detect_pii_credit_card():
    findings = nodes._detect_pii("card: 4111 1111 1111 1111")
    assert "credit_card" in findings


def test_detect_pii_clean():
    """Normal API path string should produce no PII findings."""
    findings = nodes._detect_pii("/api/v3/products?page=2&limit=20")
    assert findings == []
