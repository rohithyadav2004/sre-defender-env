#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
SRE Defender Env — Hackathon baseline inference script.

Environment variables (all required):
    API_BASE_URL   OpenAI-compatible LLM API endpoint
    MODEL_NAME     Model identifier (e.g. "Qwen/Qwen2.5-72B-Instruct")
    HF_TOKEN       API key for the LLM endpoint
    OPENENV_URL    Base URL of the running OpenEnv server (e.g. http://localhost:8000)

Stdout format (exact — judges parse these):
    [START] {"model": "...", "env": "sre_defender_env", "tasks": [1,2,3]}
    [STEP]  {"task": N, "step": N, "action_type": "...", "score": 0.0}
    [END]   {"task_scores": [0.0, 0.0, 0.0], "mean_score": 0.0}

Must complete in < 20 minutes total.
"""

import json
import os
import sys
import time

# Load .env file if present (optional — falls back to real env vars if not installed)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from openai import OpenAI

try:
    from sre_defender_env.models import SreDefenderAction
    from sre_defender_env.client import SreDefenderEnv
except ImportError:
    sys.path.insert(0, os.path.dirname(__file__))
    from models import SreDefenderAction
    from client import SreDefenderEnv


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_BASE_URL = os.environ["API_BASE_URL"]
MODEL_NAME = os.environ["MODEL_NAME"]
HF_TOKEN = os.environ["HF_TOKEN"]
OPENENV_URL = os.environ.get("OPENENV_URL", "http://localhost:8000").rstrip("/")

llm = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are an autonomous SRE agent defending a live Nginx + Node.js stack against Layer 7 attacks.

You have exactly 3 action types. Always respond with ONLY valid JSON — no markdown, no explanation:

1. Read a file (use this first to investigate):
   {"action_type": "read_file", "filepath": "<absolute path>"}

2. Append a firewall rule to nginx (for IP blocking or rate limiting):
   {"action_type": "append_nginx_rule", "rule_content": "<nginx directive>"}

3. Replace the Node.js backend with a new version containing middleware:
   {"action_type": "write_express_middleware", "file_content": "<complete app.js source>"}

Scoring: (malicious_blocked / total_malicious) × (legit_allowed / total_legit)
Blocking ALL traffic → score = 0.0. Be surgical — block only the attackers.

Key paths:
  /app/logs/nginx_access.log   — nginx access log; format: IP - XFF_IP - "METHOD PATH HTTP" STATUS bytes
  /app/config/agent_rules.conf — your writable nginx rules (append deny/limit_req directives here)
  /app/sandbox/node/app.js     — Express.js backend you can rewrite for Task 3

Rules already available in nginx (pre-defined zones):
  limit_req_zone per_ip  — rate-limit by X-Forwarded-For IP
  limit_req_zone login_zone — rate-limit by X-Forwarded-For IP on /login
"""

_TASK_HINTS = {
    1: (
        "TASK 1 — Credential Stuffing Blocker (Easy)\n"
        "A brute-force attack is flooding POST /login from a single IP address.\n"
        "Your goal:\n"
        "  1. Read /app/logs/nginx_access.log to identify the attacking IP\n"
        "  2. Append 'deny <IP>;' to block it via append_nginx_rule\n"
        "Legitimate traffic comes from different IPs — do NOT block them.\n"
        "Score improves as you block the attacker while keeping legit traffic through."
    ),
    2: (
        "TASK 2 — Rate Limiting / DDoS Defender (Medium)\n"
        "Distributed IPs are sending high-volume requests to exhaust the server.\n"
        "Your goal:\n"
        "  1. Read /app/logs/nginx_access.log to identify the attacking IP range\n"
        "  2. Either block the attacking subnet or apply per-IP rate limiting:\n"
        "     - Subnet block: append_nginx_rule with 'deny <subnet/mask>;'\n"
        "     - Rate limit:   append_nginx_rule with 'limit_req zone=per_ip burst=5 nodelay;'\n"
        "Legitimate traffic comes from a different subnet — do NOT block it.\n"
        "Score improves as you throttle/block attackers while keeping legit traffic through."
    ),
    3: (
        "TASK 3 — Zero-Day Payload Defender (Hard)\n"
        "Attackers are POSTing malicious JSON payloads to /api/process with a 'command' field.\n"
        "Legitimate requests POST to /api/process WITHOUT a 'command' field.\n"
        "Your goal:\n"
        "  1. Read /app/sandbox/node/app.js to understand the current Express.js backend\n"
        "  2. Rewrite it via write_express_middleware — add middleware BEFORE the /api/process\n"
        "     route that checks req.body.command and returns 403 if present\n"
        "  3. The /health endpoint (GET /health → 200) MUST remain intact for the rollback check\n"
        "Score: 403 on 'command' requests = malicious blocked; 200 on normal requests = legit allowed."
    ),
}


def _build_user_message(obs, task_id: int, step: int) -> str:
    hint = _TASK_HINTS.get(task_id, "")
    current_score = getattr(obs, "current_score", 0.0)
    server_status = getattr(obs, "server_status", "unknown")
    error_message = getattr(obs, "error_message", "") or "(none)"
    log_tail = getattr(obs, "log_tail", "") or "(empty)"
    # Trim to 40 lines to stay within Groq's 8000-token-per-request limit
    lines = log_tail.splitlines()
    if len(lines) > 40:
        log_tail = "\n".join(lines[-40:])
    return (
        f"{hint}\n\n"
        f"--- Step {step} | Score: {current_score:.4f} | Server: {server_status} ---\n"
        f"Last error: {error_message}\n\n"
        f"Observation:\n{log_tail}\n\n"
        "Respond with a single JSON action object."
    )


# ---------------------------------------------------------------------------
# Task execution loop
# ---------------------------------------------------------------------------

def run_task(task_id: int, max_steps: int = 10) -> tuple[float, list[float]]:
    """Run one task via WebSocket. Returns (final_score, per_step_rewards)."""
    # IMPORTANT: Use WebSocket client — NOT raw HTTP.
    # Raw HTTP /reset and /step create a fresh env per-request and immediately
    # call close(), so the traffic state is lost. WebSocket keeps one persistent
    # session alive across all calls.
    env_client = SreDefenderEnv(base_url=OPENENV_URL)
    sync_env = env_client.sync()

    with sync_env:
        result = sync_env.reset(task_id=task_id)
        obs = result.observation

        # Give the traffic generator a moment to produce log data
        time.sleep(3)

        last_score = 0.0
        step_rewards: list[float] = []
        # Sliding-window context: keep only the most recent exchange so the
        # conversation never exceeds ~4 messages (system + prev_user +
        # prev_assistant + current_user), staying well within Groq's 8k TPM limit.
        prev_exchange: tuple[str, str] | None = None  # (user_msg, assistant_raw)

        for step in range(1, max_steps + 1):
            user_msg = _build_user_message(obs, task_id, step)

            # Build minimal message list for this call
            messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
            if prev_exchange is not None:
                messages.append({"role": "user",      "content": prev_exchange[0]})
                messages.append({"role": "assistant", "content": prev_exchange[1]})
            messages.append({"role": "user", "content": user_msg})

            # Ask LLM for next action
            try:
                completion = llm.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    temperature=0.1,
                    max_tokens=1024,
                )
                raw = completion.choices[0].message.content.strip()

                if not raw:
                    raise ValueError("LLM returned empty response")

                # Strip markdown code fences if present
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                raw = raw.strip()

                action_dict = json.loads(raw)
                action = SreDefenderAction(**action_dict)

                # Advance sliding window on success
                prev_exchange = (user_msg, raw)

            except Exception as exc:
                print(
                    f"[STEP] {json.dumps({'task': task_id, 'step': step, 'action_type': 'llm_error', 'score': last_score, 'error': str(exc)})}",
                    flush=True,
                )
                time.sleep(1)
                continue

            # Execute action
            try:
                result = sync_env.step(action)
            except Exception as exc:
                print(
                    f"[STEP] {json.dumps({'task': task_id, 'step': step, 'action_type': action.action_type, 'score': last_score, 'error': str(exc)})}",
                    flush=True,
                )
                time.sleep(1)
                continue

            obs = result.observation
            last_score = float(obs.current_score)
            done = bool(result.done) or last_score >= 0.95
            step_rewards.append(last_score)

            print(
                f"[STEP] {json.dumps({'task': task_id, 'step': step, 'action_type': action.action_type, 'reward': last_score, 'score': last_score, 'done': done})}",
                flush=True,
            )

            if done:
                break

            time.sleep(1)  # let traffic accumulate between steps

    return last_score, step_rewards


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(
        f"[START] {json.dumps({'model': MODEL_NAME, 'env': 'sre_defender_env', 'tasks': [1, 2, 3]})}",
        flush=True,
    )

    task_scores: list[float] = []
    all_rewards: list[float] = []

    for task_id in [1, 2, 3]:
        score, rewards = run_task(task_id)
        task_scores.append(round(score, 4))
        all_rewards.extend(rewards)

    mean_score = round(sum(task_scores) / len(task_scores), 4)
    success = mean_score >= 0.5
    print(
        f"[END] {json.dumps({'success': success, 'task_scores': task_scores, 'mean_score': mean_score, 'score': mean_score, 'rewards': all_rewards})}",
        flush=True,
    )


if __name__ == "__main__":
    main()
