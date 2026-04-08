"""Smoke tests for Task 3: Express Middleware Injector."""

GOOD_MIDDLEWARE = (
    "'use strict';\n"
    "const express = require('express');\n"
    "const app = express();\n"
    "app.use(express.json());\n"
    "app.use('/api/process', (req, res, next) => {\n"
    "  if (req.body && req.body.command !== undefined) {\n"
    "    return res.status(403).json({ status: 'forbidden' });\n"
    "  }\n"
    "  next();\n"
    "});\n"
    "app.post('/api/process', (req, res) => res.json({ status: 'ok' }));\n"
    "app.get('/health', (req, res) => res.status(200).json({ status: 'healthy' }));\n"
    "app.listen(3000);\n"
)

BAD_JS = "this is not valid javascript {{{;;;"


def test_reset_task3_returns_task_id_3(api_client):
    resp = api_client.post("/reset", json={"task_id": 3})
    assert resp.status_code == 200
    obs = resp.json()["observation"]
    assert obs["task_id"] == 3


def test_write_valid_middleware_succeeds(api_client):
    """Valid app.js that passes health check returns no error."""
    api_client.post("/reset", json={"task_id": 3})
    resp = api_client.post("/step", json={"action": {
        "action_type": "write_express_middleware",
        "file_content": GOOD_MIDDLEWARE,
    }})
    assert resp.status_code == 200
    obs = resp.json()["observation"]
    # Health check is mocked to succeed so no error expected
    assert obs["error_message"] == ""


def test_write_bad_js_triggers_rollback(api_client, monkeypatch):
    """Invalid JS causes health check failure, triggering rollback."""
    import sre_defender_env.server.sre_defender_env_environment as env_mod
    from pathlib import Path

    # Override _ping_node on the class to simulate health check failure for this test only
    monkeypatch.setattr(
        "sre_defender_env.server.sre_defender_env_environment.SreDefenderEnvEnvironment._ping_node",
        lambda self: False,
    )

    api_client.post("/reset", json={"task_id": 3})
    original_content = Path(env_mod._APP_JS).read_text()

    resp = api_client.post("/step", json={"action": {
        "action_type": "write_express_middleware",
        "file_content": BAD_JS,
    }})
    assert resp.status_code == 200
    obs = resp.json()["observation"]
    # Should have rolled back and reported an error
    assert obs["error_message"] != ""
    assert "Rolled back" in obs["error_message"] or "failed" in obs["error_message"].lower()
    # app.js should be restored to original content
    assert Path(env_mod._APP_JS).read_text() == original_content
