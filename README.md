---
title: SRE Defender Env
emoji: 🛡️
colorFrom: red
colorTo: orange
sdk: docker
app_port: 8000
license: mit
pinned: false
---

# SRE Defender Env

An [OpenEnv](https://github.com/meta-pytorch/OpenEnv) environment for the **Meta × Scaler Hackathon (Round 1)**.

## What This Environment Models

Site Reliability Engineers (SREs) are constantly defending live web infrastructure from Layer 7 (application-layer) cyber attacks. Unlike network-layer attacks, these attacks mimic legitimate HTTP traffic — making them invisible to simple firewalls and requiring semantic understanding of the application logic.

This environment simulates an **autonomous SRE agent** defending a live Nginx + Node.js stack against three escalating attack patterns. A background traffic generator continuously fires 80% legitimate / 20% malicious HTTP requests at the server while the agent operates. The agent must analyze logs, write precise firewall rules, and deploy custom middleware — all without taking the business offline.

This is a real task with real-world tooling (Nginx directives, Express.js middleware). The exact same actions an SRE would take manually can be discovered and executed by an LLM agent.

---

## Anti-Exploit Reward Function

```
score = (malicious_blocked / total_malicious) × (legit_allowed / total_legit)
```

This formula defeats the most common RL exploit: **blocking all traffic**. If the agent writes a blanket `deny all;` rule:
- `legit_allowed = 0` → `score = 0.0`

The agent is forced to be **surgical** — identify and block only the attacker while keeping legitimate users online. Partial credit is awarded at every step as the agent incrementally improves its defense.

---

## The 3 Tasks

### Task 1 — Credential Stuffing Blocker (Easy)
- **Attack:** A single IP address floods `POST /login` at high volume (credential stuffing)
- **Observable signal:** nginx access log shows repeated 200s from one IP on `/login`
- **Agent goal:** Identify the IP and write a targeted `deny` rule
- **Difficulty:** Easy — single IP, pattern obvious in logs

### Task 2 — Rate Limiter / DDoS Defender (Medium)
- **Attack:** Distributed IPs from a private subnet send high-volume requests to exhaust server capacity
- **Observable signal:** access log shows bursts from multiple IPs in the same /16 subnet
- **Agent goal:** Apply subnet-level blocking or per-IP rate limiting; must not affect legitimate traffic from a different subnet
- **Difficulty:** Medium — requires understanding IP ranges and nginx rate-limit directives

### Task 3 — Zero-Day Payload Defender (Hard)
- **Attack:** Rotating IPs POST to `/api/process` with a malicious JSON payload containing a `command` field (command injection canary)
- **Observable signal:** access log shows 200s on `/api/process`; app.js source shows the vulnerable endpoint
- **Agent goal:** Read `app.js`, write Express.js middleware that inspects `req.body.command` and returns 403 before the route handler; restart Node.js
- **Difficulty:** Hard — requires reading source code, writing syntactically valid JavaScript middleware, and surviving a health-check rollback gate
- **Anti-cheat:** If the new `app.js` crashes Node.js, the environment auto-rolls back and returns the crash log

---

## Action Space

```python
class SreDefenderAction(Action):
    action_type: Literal["read_file", "append_nginx_rule", "write_express_middleware"]
    filepath: str | None       # required for read_file
    rule_content: str | None   # required for append_nginx_rule
    file_content: str | None   # required for write_express_middleware (full app.js)
```

| Action | Description | When to use |
|--------|-------------|-------------|
| `read_file` | Returns last 100 lines of any readable file | Investigate logs, read source code |
| `append_nginx_rule` | Appends a directive to `agent_rules.conf` and reloads nginx | Block IPs, rate-limit |
| `write_express_middleware` | Overwrites `app.js`, restarts Node.js, verifies health | Defend against payload attacks |

**Key readable paths:**
- `/app/logs/nginx_access.log` — nginx access log (`IP - XFF - "METHOD PATH HTTP" STATUS bytes`)
- `/app/config/agent_rules.conf` — current firewall rules
- `/app/sandbox/node/app.js` — Express.js backend source

---

## Observation Space

```python
class SreDefenderObservation(Observation):
    reward: float          # current episode score (0.0–1.0)
    current_score: float   # same as reward; anti-exploit formula result
    log_tail: str          # last 100 lines of file read, or last 20 nginx log lines
    server_status: Literal["healthy", "degraded", "down", "unknown"]
    task_id: int           # active task (1, 2, or 3)
    error_message: str     # rollback crash log (Task 3) or nginx reload error
```

---

## Baseline Scores

Measured with `openai/gpt-oss-120b` via Groq API:

| Task | Score | Steps to Solve |
|------|-------|----------------|
| Task 1 (Easy) | ~0.94 | 8–10 |
| Task 2 (Medium) | ~0.86 | 8–10 |
| Task 3 (Hard) | ~1.0 | 2 |
| **Mean** | **~0.93** | — |

Task 3 achieves near-perfect because the middleware pattern is unambiguous once the agent reads `app.js`.

---

## Environment Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker Container                                    │
│                                                      │
│  ┌──────────────┐    ┌──────────┐    ┌──────────┐   │
│  │ OpenEnv API  │    │  Nginx   │    │ Node.js  │   │
│  │  :8000       │    │  :8080   │    │  :3000   │   │
│  └──────┬───────┘    └────┬─────┘    └────┬─────┘   │
│         │                 │  proxy         │         │
│  ┌──────▼───────┐    ┌────▼─────────────────────┐   │
│  │  FastAPI     │    │  Traffic Generator        │   │
│  │  WS /ws      │    │  80% legit / 20% attack   │   │
│  │  POST /reset │    │  aiohttp daemon thread    │   │
│  │  POST /step  │    └───────────────────────────┘   │
│  └──────────────┘                                    │
└─────────────────────────────────────────────────────┘
         ▲
         │ WebSocket
  inference.py (runs on judge's machine)
```

Supervisord manages nginx, Node.js, and uvicorn as persistent processes with auto-restart.

---

## Setup & Usage

### Run with Docker (recommended)

```bash
# Build
docker build -t sre-defender-env .

# Run
docker run -p 8000:8000 sre-defender-env
```

### Run inference.py

```bash
# Install dependencies (one-time)
pip install -r requirements-inference.txt

# Configure (OPENENV_URL defaults to http://localhost:8000)
export API_BASE_URL="https://api-inference.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
export HF_TOKEN="hf_..."
export OPENENV_URL="http://localhost:8000"   # or https://<your-space>.hf.space

python inference.py
```

### Expected output

```
[START] {"model": "...", "env": "sre_defender_env", "tasks": [1, 2, 3]}
[STEP]  {"task": 1, "step": 1, "action_type": "read_file", "reward": 0.0, "score": 0.0, "done": false}
[STEP]  {"task": 1, "step": 2, "action_type": "append_nginx_rule", "reward": 0.85, "score": 0.85, "done": false}
...
[END]   {"success": true, "task_scores": [0.94, 0.86, 1.0], "mean_score": 0.933, "score": 0.933, "rewards": [...]}
```

### Local development (without Docker)

```bash
source ../.venv/bin/activate
pytest tests/ -v
uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_BASE_URL` | Yes | — | OpenAI-compatible LLM endpoint |
| `MODEL_NAME` | Yes | — | Model identifier |
| `HF_TOKEN` | Yes | — | API key for the LLM endpoint |
| `OPENENV_URL` | No | `http://localhost:8000` | Running OpenEnv server URL |

---

## Design Decisions

**Why Nginx + Node.js?** These are the most common production web stacks. The agent uses real CLI tools (nginx directives, JavaScript) — not toy syntax invented for the environment.

**Why the anti-exploit reward?** Standard RL reward functions for security tasks reward blocking attacks, which causes agents to block everything. The multiplicative formula `blocked × allowed` forces precision over aggression.

**Why temporal state?** The traffic generator runs continuously as a daemon thread. Log entries accumulate while the agent reasons. This creates realistic pressure: the longer the agent takes, the more attack traffic reaches the backend.

**Why a rollback gate on Task 3?** If the agent writes syntactically invalid JavaScript, Node.js crashes and the backend goes down. The environment detects this, reverts to the working backup, and returns the crash log as the error_message — exactly like a real CI/CD pipeline.
