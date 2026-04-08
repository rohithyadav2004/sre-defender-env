# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""SRE Defender Env — Environment implementation."""

import asyncio
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import SreDefenderAction, SreDefenderObservation
except ImportError:
    from models import SreDefenderAction, SreDefenderObservation


# ---------------------------------------------------------------------------
# Module-level shared state
# ---------------------------------------------------------------------------

# Populated by traffic generator (Task 2), read by grader.
# Cleared on every reset() so stale IPs don't bleed across episodes.
MALICIOUS_IPS: set[str] = set()
_MALICIOUS_IPS_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Docker paths — patched in tests via monkeypatch
# ---------------------------------------------------------------------------
_NGINX_CONF = "/app/config/nginx.conf"
_AGENT_RULES = "/app/config/agent_rules.conf"
_APP_JS = "/app/sandbox/node/app.js"
_APP_JS_ORIG = "/app/sandbox/node/app.js.orig"
_ACCESS_LOG = "/app/logs/nginx_access.log"

_AGENT_RULES_DEFAULT = "# Agent firewall rules — append only\n"

# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------
# nginx log_format:
#   '$remote_addr - $http_x_forwarded_for - "$request" $status $body_bytes_sent'
# Example: 127.0.0.1 - 1.2.3.4 - "POST /login HTTP/1.1" 403 25
_LOG_RE = re.compile(
    r'\S+ - (\S+) - "(\S+) (\S+) [^"]*" (\d+) \d+'
)


def _parse_log_line(line: str) -> tuple[str, str, int] | None:
    """Return (xff_ip, path, status) or None if line does not match."""
    m = _LOG_RE.match(line.strip())
    if not m:
        return None
    xff = m.group(1)    # $http_x_forwarded_for (or '-' if absent)
    path = m.group(3)   # request path
    status = int(m.group(4))
    return xff, path, status


# ---------------------------------------------------------------------------
# Traffic generator (runs inside a daemon thread)
# ---------------------------------------------------------------------------

async def _async_traffic(stop_event: threading.Event, task_id: int) -> None:
    """Send 80% legit / 20% malicious HTTP traffic to nginx on port 8080."""
    import random
    try:
        import aiohttp
    except ImportError:
        return  # aiohttp not available in test environment

    def _legit_ip() -> str:
        return f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _malicious_ip() -> str:
        ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        with _MALICIOUS_IPS_LOCK:
            MALICIOUS_IPS.add(ip)
        return ip

    base = "http://localhost:8080"

    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            try:
                if task_id == 1:
                    # Legit: GET /api/data + POST /login from 10.0.x.x
                    ip = _legit_ip()
                    hdrs = {"X-Forwarded-For": ip}
                    await session.get(f"{base}/api/data", headers=hdrs)
                    await session.post(f"{base}/login",
                                       json={"username": "user", "password": "pass"},
                                       headers=hdrs)
                    # Malicious: flood /login from fixed 1.2.3.4
                    for _ in range(4):
                        await session.post(f"{base}/login",
                                           json={"username": "admin", "password": "x"},
                                           headers={"X-Forwarded-For": "1.2.3.4"})

                elif task_id == 2:
                    # Legit: normal rate from 10.0.x.x
                    await session.get(f"{base}/api/data",
                                      headers={"X-Forwarded-For": _legit_ip()})
                    # Malicious: burst of 6 requests from the SAME 192.168.x.x IP.
                    # Per-IP rate limit (burst=5 nodelay) allows the first 5 and
                    # rejects the 6th+ with 429. Using one IP per iteration is
                    # required — unique IPs each get a fresh bucket and never hit
                    # the limit.
                    attacker_ip = _malicious_ip()
                    for _ in range(6):
                        await session.get(f"{base}/api/data",
                                          headers={"X-Forwarded-For": attacker_ip})

                elif task_id == 3:
                    # Legit: POST /api/process without command field
                    await session.post(f"{base}/api/process",
                                       json={"data": "hello"},
                                       headers={"X-Forwarded-For": _legit_ip()})
                    # Malicious: POST /api/process with command field
                    await session.post(f"{base}/api/process",
                                       json={"command": "cat /etc/passwd"},
                                       headers={"X-Forwarded-For": _legit_ip()})

            except Exception:
                pass  # nginx/node may not be ready yet; silently retry

            await asyncio.sleep(0.1)


def _run_traffic(stop_event: threading.Event, task_id: int) -> None:
    """Daemon thread entry point — wraps async traffic loop."""
    asyncio.run(_async_traffic(stop_event, task_id))


# ---------------------------------------------------------------------------
# Environment class
# ---------------------------------------------------------------------------

class SreDefenderEnvEnvironment(Environment):
    """
    SRE Defender environment.

    Manages nginx + Node.js process state. Not safe for concurrent sessions.
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = False

    def __init__(self) -> None:
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._task_id: int = 1
        self._log_offset: int = 0
        self._traffic_thread: threading.Thread | None = None
        self._stop_event: threading.Event = threading.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reset(self, task_id: int = 1, **kwargs) -> SreDefenderObservation:
        """Reset episode. Stops old traffic thread, wipes nginx rules, starts fresh."""
        # Step 0: stop previous traffic thread
        if self._traffic_thread is not None and self._traffic_thread.is_alive():
            self._stop_event.set()
            self._traffic_thread.join(timeout=2)

        self._task_id = task_id
        self._state = State(episode_id=str(uuid4()), step_count=0)

        # Wipe agent nginx rules
        try:
            Path(_AGENT_RULES).write_text(_AGENT_RULES_DEFAULT)
            subprocess.run(
                ["nginx", "-c", _NGINX_CONF, "-s", "reload"],
                timeout=5,
                check=False,
                capture_output=True,
            )
        except Exception:
            pass

        # Restore original app.js; restart node only if the file was modified.
        # (Node.js does not auto-reload on file change — must kill & let supervisord
        # restart it.  Skipping the kill when unchanged avoids a brief 502 window
        # that would otherwise hurt task 1/2 scores on the same container restart.)
        try:
            orig = Path(_APP_JS_ORIG)
            current = Path(_APP_JS)
            if orig.exists():
                orig_bytes = orig.read_bytes()
                if not current.exists() or current.read_bytes() != orig_bytes:
                    current.write_bytes(orig_bytes)
                    self._kill_node_proc()
        except Exception:
            pass

        # Clear malicious IPs from previous episode
        with _MALICIOUS_IPS_LOCK:
            MALICIOUS_IPS.clear()

        # Record episode-start log offset (Option B: byte-offset tracking)
        log_path = Path(_ACCESS_LOG)
        self._log_offset = log_path.stat().st_size if log_path.exists() else 0

        # Start traffic generator
        self._stop_event = threading.Event()
        self._traffic_thread = threading.Thread(
            target=_run_traffic,
            args=(self._stop_event, task_id),
            daemon=True,
        )
        self._traffic_thread.start()

        return SreDefenderObservation(
            done=False,
            reward=0.0,
            current_score=0.0,
            task_id=task_id,
            server_status=self._check_server(),
            log_tail=f"Episode reset. Task {task_id} ready.",
        )

    def step(self, action: SreDefenderAction) -> SreDefenderObservation:  # type: ignore[override]
        """Dispatch action, compute score lazily from nginx log."""
        self._state.step_count += 1
        obs = self._dispatch(action)
        score = self._compute_score()
        obs.current_score = score
        obs.reward = score
        return obs

    @property
    def state(self) -> State:
        return self._state

    def close(self) -> None:
        """Stop traffic thread and restore environment files to clean state."""
        if self._traffic_thread is not None and self._traffic_thread.is_alive():
            self._stop_event.set()
            self._traffic_thread.join(timeout=2)
        # Restore files so next container start begins clean
        try:
            Path(_AGENT_RULES).write_text(_AGENT_RULES_DEFAULT)
        except Exception:
            pass
        try:
            orig = Path(_APP_JS_ORIG)
            if orig.exists():
                shutil.copy(orig, _APP_JS)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Action dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, action: SreDefenderAction) -> SreDefenderObservation:
        if action.action_type == "read_file":
            return self._read_file(action)
        if action.action_type == "append_nginx_rule":
            return self._append_nginx_rule(action)
        if action.action_type == "write_express_middleware":
            return self._write_express_middleware(action)
        # Literal validation in model prevents reaching here, but kept for safety
        return SreDefenderObservation(
            done=False, reward=0.0, task_id=self._task_id,
            error_message=f"Unknown action_type: {action.action_type!r}",
        )

    def _read_file(self, action: SreDefenderAction) -> SreDefenderObservation:
        filepath = action.filepath or ""
        try:
            content = Path(filepath).read_text(errors="replace")
            tail = "\n".join(content.splitlines()[-100:])
        except Exception as exc:
            return SreDefenderObservation(
                done=False, reward=0.0, task_id=self._task_id,
                error_message=str(exc),
            )
        return SreDefenderObservation(
            done=False, reward=0.0, task_id=self._task_id,
            log_tail=tail, server_status=self._check_server(),
        )

    def _append_nginx_rule(self, action: SreDefenderAction) -> SreDefenderObservation:
        rule = (action.rule_content or "").strip()
        try:
            with open(_AGENT_RULES, "a") as fh:
                fh.write(f"\n{rule}\n")
            result = subprocess.run(
                ["nginx", "-c", _NGINX_CONF, "-s", "reload"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                return SreDefenderObservation(
                    done=False, reward=0.0, task_id=self._task_id,
                    error_message=f"nginx reload failed: {result.stderr}",
                    server_status="degraded",
                )
        except Exception as exc:
            return SreDefenderObservation(
                done=False, reward=0.0, task_id=self._task_id,
                error_message=str(exc), server_status="degraded",
            )
        return SreDefenderObservation(
            done=False, reward=0.0, task_id=self._task_id,
            log_tail=self._tail_access_log(20),
            server_status=self._check_server(),
        )

    def _write_express_middleware(self, action: SreDefenderAction) -> SreDefenderObservation:
        new_content = action.file_content or ""
        backup: str | None = None

        try:
            app_path = Path(_APP_JS)
            if app_path.exists():
                backup = app_path.read_text()

            # Write new app.js
            app_path.write_text(new_content)

            # Kill current node process; supervisord (autorestart=true) will
            # restart it with the new app.js already on disk.
            # NOTE: pkill is NOT present in this Docker image — use /proc scan.
            self._kill_node_proc()

            # Give supervisord time to restart node (startsecs default is 1s)
            time.sleep(2)
            health_ok = self._ping_node()

            if not health_ok:
                # Read crash output from supervisord-managed stderr log
                crash_log = ""
                try:
                    node_err = Path("/app/logs/node_stderr.log")
                    if node_err.exists():
                        crash_log = "\n".join(
                            node_err.read_text(errors="replace").splitlines()[-30:]
                        )
                except Exception:
                    pass
                # Rollback
                if backup is not None:
                    app_path.write_text(backup)
                    self._kill_node_proc()  # restart node with restored app.js
                return SreDefenderObservation(
                    done=False, reward=0.0, task_id=self._task_id,
                    error_message=(
                        f"Node.js failed health check. Rolled back to previous app.js.\n"
                        f"Crash log:\n{crash_log}"
                    ),
                    server_status="degraded",
                )

        except Exception as exc:
            if backup is not None:
                try:
                    Path(_APP_JS).write_text(backup)
                except Exception:
                    pass
            return SreDefenderObservation(
                done=False, reward=0.0, task_id=self._task_id,
                error_message=str(exc), server_status="degraded",
            )

        return SreDefenderObservation(
            done=False, reward=0.0, task_id=self._task_id,
            log_tail="Middleware deployed and health check passed.",
            server_status="healthy",
        )

    # ------------------------------------------------------------------
    # Scoring (lazy log parsing — Option B: byte-offset)
    # ------------------------------------------------------------------

    def _compute_score(self) -> float:
        log_path = Path(_ACCESS_LOG)
        if not log_path.exists():
            return 0.0
        try:
            with open(_ACCESS_LOG, "rb") as fh:
                fh.seek(self._log_offset)
                data = fh.read().decode("utf-8", errors="replace")
        except Exception:
            return 0.0

        total_malicious = malicious_blocked = 0
        total_legit = legit_allowed = 0

        with _MALICIOUS_IPS_LOCK:
            malicious_snapshot = frozenset(MALICIOUS_IPS)

        for line in data.splitlines():
            parsed = _parse_log_line(line)
            if parsed is None:
                continue
            xff, path, status = parsed

            if self._task_id == 1:
                if xff == "1.2.3.4":
                    total_malicious += 1
                    if status == 403:
                        malicious_blocked += 1
                else:
                    total_legit += 1
                    if status == 200:
                        legit_allowed += 1

            elif self._task_id == 2:
                # Malicious = 192.168.x.x IPs (traffic generator always uses this range)
                # or any IP in MALICIOUS_IPS (populated by traffic thread when available).
                # Accepting both 429 (rate-limit) and 403 (deny) as "blocked".
                is_malicious_xff = xff.startswith("192.168.") or xff in malicious_snapshot
                if is_malicious_xff:
                    total_malicious += 1
                    if status in (403, 429):
                        malicious_blocked += 1
                else:
                    total_legit += 1
                    if status == 200:
                        legit_allowed += 1

            elif self._task_id == 3:
                if path == "/api/process":
                    if status == 403:
                        total_malicious += 1
                        malicious_blocked += 1
                    elif status == 200:
                        total_legit += 1
                        legit_allowed += 1

        if total_malicious == 0 or total_legit == 0:
            return 0.0  # no traffic yet
        if legit_allowed == 0:
            return 0.0  # anti-exploit: agent blocked all legit traffic
        # Laplace smoothing on the malicious side only (+1 pseudocount).
        # Keeps score > 0 once traffic is flowing (prevents cold-start 0.0),
        # while preserving the anti-exploit property via the explicit check above.
        raw = ((malicious_blocked + 1) / (total_malicious + 1)) * (legit_allowed / total_legit)
        return min(raw, 0.999)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _kill_node_proc(self) -> None:
        """Kill any running node app.js process via /proc scan.

        pkill is not present in the Docker image, so we scan /proc directly
        and use os.kill(). supervisord (autorestart=true) will restart node
        using the new app.js that was written to disk before this call.
        """
        for pid_entry in Path("/proc").iterdir():
            if not pid_entry.name.isdigit():
                continue
            try:
                cmdline = (
                    (pid_entry / "cmdline")
                    .read_bytes()
                    .replace(b"\x00", b" ")
                    .decode(errors="replace")
                )
                if "node" in cmdline and "app.js" in cmdline:
                    os.kill(int(pid_entry.name), signal.SIGKILL)
            except Exception:
                pass

    def _tail_access_log(self, n: int = 20) -> str:
        log_path = Path(_ACCESS_LOG)
        if not log_path.exists():
            return ""
        try:
            lines = log_path.read_text(errors="replace").splitlines()
            return "\n".join(lines[-n:])
        except Exception:
            return ""

    def _ping_node(self) -> bool:
        try:
            urllib.request.urlopen("http://localhost:3000/health", timeout=2)
            return True
        except Exception:
            return False

    def _check_server(self) -> str:
        return "healthy" if self._ping_node() else "degraded"
