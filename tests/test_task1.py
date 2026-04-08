"""Smoke tests for Task 1: Single IP Blocker."""

import sre_defender_env.server.sre_defender_env_environment as env_mod


def test_reset_task1_returns_correct_structure(api_client):
    resp = api_client.post("/reset", json={"task_id": 1})
    assert resp.status_code == 200
    body = resp.json()
    assert "observation" in body
    obs = body["observation"]
    assert obs["task_id"] == 1
    assert obs["current_score"] == 0.0
    assert obs["error_message"] == ""


def test_append_deny_rule_succeeds(api_client):
    api_client.post("/reset", json={"task_id": 1})
    resp = api_client.post("/step", json={"action": {
        "action_type": "append_nginx_rule",
        "rule_content": "deny 1.2.3.4;",
    }})
    assert resp.status_code == 200
    obs = resp.json()["observation"]
    assert obs["error_message"] == ""


def test_read_file_contains_appended_rule(api_client):
    api_client.post("/reset", json={"task_id": 1})
    # Append the rule
    api_client.post("/step", json={"action": {
        "action_type": "append_nginx_rule",
        "rule_content": "deny 1.2.3.4;",
    }})
    # Read the rules file (use the patched path)
    resp = api_client.post("/step", json={"action": {
        "action_type": "read_file",
        "filepath": env_mod._AGENT_RULES,
    }})
    assert resp.status_code == 200
    obs = resp.json()["observation"]
    assert "deny 1.2.3.4" in obs["log_tail"]


def test_invalid_action_type_returns_422(api_client):
    api_client.post("/reset", json={"task_id": 1})
    resp = api_client.post("/step", json={"action": {"action_type": "execute_command"}})
    # Pydantic Literal validation rejects invalid action_type at HTTP boundary
    assert resp.status_code == 422
