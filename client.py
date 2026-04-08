# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""SRE Defender Env — WebSocket client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import SreDefenderAction, SreDefenderObservation


class SreDefenderEnv(EnvClient[SreDefenderAction, SreDefenderObservation, State]):
    """
    WebSocket client for SreDefenderEnvEnvironment.

    Example:
        >>> with SreDefenderEnv(base_url="http://localhost:8000") as env:
        ...     env.reset()
        ...     result = env.step(SreDefenderAction(
        ...         action_type="read_file",
        ...         filepath="/app/logs/nginx_access.log"
        ...     ))
        ...     print(result.observation.log_tail)
    """

    def _step_payload(self, action: SreDefenderAction) -> Dict:
        payload: Dict = {"action_type": action.action_type}
        if action.filepath is not None:
            payload["filepath"] = action.filepath
        if action.rule_content is not None:
            payload["rule_content"] = action.rule_content
        if action.file_content is not None:
            payload["file_content"] = action.file_content
        return payload

    def _parse_result(self, payload: Dict) -> StepResult[SreDefenderObservation]:
        obs_data = payload.get("observation", {})
        observation = SreDefenderObservation(
            reward=float(obs_data.get("reward", 0.0)),
            log_tail=obs_data.get("log_tail", ""),
            current_score=float(obs_data.get("current_score", 0.0)),
            server_status=obs_data.get("server_status", "unknown"),
            task_id=int(obs_data.get("task_id", 1)),
            error_message=obs_data.get("error_message", ""),
            done=payload.get("done", False),
        )
        return StepResult(
            observation=observation,
            reward=float(payload.get("reward", 0.0)),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
