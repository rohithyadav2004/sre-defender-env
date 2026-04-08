"""Smoke tests for Task 2: Rate Limiter."""

import sre_defender_env.server.sre_defender_env_environment as env_mod


def test_reset_task2_returns_task_id_2(api_client):
    resp = api_client.post("/reset", json={"task_id": 2})
    assert resp.status_code == 200
    obs = resp.json()["observation"]
    assert obs["task_id"] == 2
    assert obs["current_score"] == 0.0


def test_append_rate_limit_rule_succeeds(api_client):
    api_client.post("/reset", json={"task_id": 2})
    resp = api_client.post("/step", json={"action": {
        "action_type": "append_nginx_rule",
        "rule_content": "limit_req zone=per_ip burst=5 nodelay;",
    }})
    assert resp.status_code == 200
    obs = resp.json()["observation"]
    assert obs["error_message"] == ""


def test_read_file_contains_rate_limit_rule(api_client):
    api_client.post("/reset", json={"task_id": 2})
    api_client.post("/step", json={"action": {
        "action_type": "append_nginx_rule",
        "rule_content": "limit_req zone=per_ip burst=5 nodelay;",
    }})
    resp = api_client.post("/step", json={"action": {
        "action_type": "read_file",
        "filepath": env_mod._AGENT_RULES,
    }})
    assert resp.status_code == 200
    assert "limit_req" in resp.json()["observation"]["log_tail"]


def test_reset_clears_malicious_ips(api_client):
    # Simulate malicious IPs from a previous episode
    env_mod.MALICIOUS_IPS.add("192.168.1.100")
    assert len(env_mod.MALICIOUS_IPS) > 0
    api_client.post("/reset", json={"task_id": 2})
    assert len(env_mod.MALICIOUS_IPS) == 0
