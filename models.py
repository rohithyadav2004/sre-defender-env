# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Data models for the SRE Defender Env environment."""

from typing import Literal

from openenv.core.env_server.types import Action, Observation
from pydantic import Field, model_validator


class SreDefenderAction(Action):
    """Agent action — one of three whitelisted types."""

    action_type: Literal["read_file", "append_nginx_rule", "write_express_middleware"] = Field(
        ...,
        description="Whitelisted action type",
    )
    filepath: str | None = Field(default=None, description="Used by read_file")
    rule_content: str | None = Field(default=None, description="Used by append_nginx_rule")
    file_content: str | None = Field(default=None, description="Used by write_express_middleware")

    @model_validator(mode="after")
    def check_companion_field(self) -> "SreDefenderAction":
        if self.action_type == "read_file" and self.filepath is None:
            raise ValueError("filepath is required when action_type is 'read_file'")
        if self.action_type == "append_nginx_rule" and self.rule_content is None:
            raise ValueError("rule_content is required when action_type is 'append_nginx_rule'")
        if self.action_type == "write_express_middleware" and self.file_content is None:
            raise ValueError("file_content is required when action_type is 'write_express_middleware'")
        return self


class SreDefenderObservation(Observation):
    """Observation returned after every reset() and step()."""

    # Override base class (bool | int | float | None) to always be float
    reward: float = Field(default=0.0, ge=0.0, le=1.0, description="Current episode score (mirrors current_score)")
    log_tail: str = Field(default="", description="File contents or last 100 log lines")
    current_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="(malicious_blocked/total_malicious) x (legit_allowed/total_legit)",
    )
    server_status: Literal["healthy", "degraded", "down", "unknown"] = Field(default="unknown", description="Server health")
    task_id: int = Field(default=1, ge=1, le=3, description="Active task: 1, 2, or 3")
    error_message: str = Field(default="", description="Rollback crash log (Task 3) or error details")
