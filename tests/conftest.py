"""Shared pytest fixtures for SRE Defender Env smoke tests.

Patches all Docker-specific paths with temp files and mocks all
subprocess/network calls so tests run on any dev machine without
nginx, Node.js, or a running environment server.
"""

import pytest
from unittest.mock import MagicMock


@pytest.fixture(autouse=True)
def patch_env_paths(tmp_path, monkeypatch):
    """Replace /app/* paths with temp files and patch all external calls."""
    import sre_defender_env.server.sre_defender_env_environment as env_mod

    # Create temp files that mirror Docker layout
    rules = tmp_path / "agent_rules.conf"
    rules.write_text("# Agent firewall rules — append only\n")

    access_log = tmp_path / "nginx_access.log"
    access_log.write_text("")

    app_js = tmp_path / "app.js"
    app_js.write_text(
        "'use strict';\n"
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.json());\n"
        "app.get('/health', (req, res) => res.json({ status: 'healthy' }));\n"
        "app.listen(3000);\n"
    )
    app_js_orig = tmp_path / "app.js.orig"
    app_js_orig.write_text(app_js.read_text())

    # Patch module-level path constants
    monkeypatch.setattr(env_mod, "_AGENT_RULES", str(rules))
    monkeypatch.setattr(env_mod, "_ACCESS_LOG", str(access_log))
    monkeypatch.setattr(env_mod, "_APP_JS", str(app_js))
    monkeypatch.setattr(env_mod, "_APP_JS_ORIG", str(app_js_orig))
    monkeypatch.setattr(env_mod, "_NGINX_CONF", "/dev/null")

    # Prevent actual subprocess calls
    monkeypatch.setattr(
        "sre_defender_env.server.sre_defender_env_environment.subprocess.run",
        lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        "sre_defender_env.server.sre_defender_env_environment.subprocess.Popen",
        lambda *a, **kw: MagicMock(stderr=MagicMock(read=lambda n: b"")),
    )

    # Prevent traffic generator thread from actually starting.
    # We patch _run_traffic (the thread target) to be a no-op so the
    # real threading.Thread starts but exits immediately without sending
    # any HTTP traffic.  Do NOT patch threading.Thread itself — doing so
    # would break ThreadPoolExecutor worker threads used by anyio/starlette
    # TestClient, causing all async requests to hang.
    monkeypatch.setattr(
        "sre_defender_env.server.sre_defender_env_environment._run_traffic",
        lambda stop_event, task_id: None,
    )

    # Prevent health check pings from hanging
    monkeypatch.setattr(
        "sre_defender_env.server.sre_defender_env_environment.urllib.request.urlopen",
        lambda *a, **kw: MagicMock(),
    )

    # Prevent close() from wiping agent_rules.conf and app.js between
    # requests.  The HTTP server calls close() after every /step, which
    # would erase rules appended in a previous step, making multi-step
    # tests impossible without this patch.
    monkeypatch.setattr(
        env_mod.SreDefenderEnvEnvironment,
        "close",
        lambda self: None,
    )

    yield tmp_path


@pytest.fixture
def api_client():
    """Return a synchronous TestClient connected to the FastAPI app."""
    from fastapi.testclient import TestClient
    from sre_defender_env.server.app import app
    return TestClient(app)
