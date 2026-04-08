import pytest
from pydantic import ValidationError


def test_action_read_file():
    from sre_defender_env.models import SreDefenderAction
    action = SreDefenderAction(action_type="read_file", filepath="/app/logs/nginx_access.log")
    assert action.action_type == "read_file"
    assert action.filepath == "/app/logs/nginx_access.log"
    assert action.rule_content is None
    assert action.file_content is None


def test_action_append_nginx_rule():
    from sre_defender_env.models import SreDefenderAction
    action = SreDefenderAction(action_type="append_nginx_rule", rule_content="deny 1.2.3.4;")
    assert action.action_type == "append_nginx_rule"
    assert action.rule_content == "deny 1.2.3.4;"
    assert action.filepath is None


def test_action_write_middleware():
    from sre_defender_env.models import SreDefenderAction
    action = SreDefenderAction(
        action_type="write_express_middleware",
        file_content="const express = require('express'); const app = express();"
    )
    assert action.action_type == "write_express_middleware"
    assert action.file_content is not None


def test_action_rejects_invalid_type():
    from sre_defender_env.models import SreDefenderAction
    with pytest.raises(ValidationError):
        SreDefenderAction(action_type="execute_command", filepath="/etc/passwd")


def test_action_read_file_requires_filepath():
    from sre_defender_env.models import SreDefenderAction
    with pytest.raises(ValidationError):
        SreDefenderAction(action_type="read_file")  # no filepath


def test_observation_reward_bounds():
    from sre_defender_env.models import SreDefenderObservation
    with pytest.raises(ValidationError):
        SreDefenderObservation(done=False, reward=1.5)  # out of bounds


def test_action_requires_action_type():
    from sre_defender_env.models import SreDefenderAction
    with pytest.raises(ValidationError):
        SreDefenderAction()


def test_observation_reward_is_float():
    from sre_defender_env.models import SreDefenderObservation
    obs = SreDefenderObservation(done=False)
    assert isinstance(obs.reward, float)
    assert obs.reward == 0.0


def test_observation_current_score_matches_reward():
    from sre_defender_env.models import SreDefenderObservation
    obs = SreDefenderObservation(done=False, reward=0.75, current_score=0.75)
    assert obs.reward == 0.75
    assert obs.current_score == 0.75


def test_observation_defaults():
    from sre_defender_env.models import SreDefenderObservation
    obs = SreDefenderObservation(done=False)
    assert obs.log_tail == ""
    assert obs.server_status == "unknown"
    assert obs.task_id == 1
    assert obs.error_message == ""
