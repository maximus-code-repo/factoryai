"""Tests for the authenticated Amazon Bedrock chat handler."""

import importlib.util
from pathlib import Path

import pytest


HANDLER_PATH = (
    Path(__file__).parents[1]
    / "amplify"
    / "functions"
    / "chat_agent"
    / "handler.py"
)


def load_handler_module():
    spec = importlib.util.spec_from_file_location("chat_agent_handler", HANDLER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeBedrock:
    def __init__(self):
        self.request = None

    def converse(self, **kwargs):
        self.request = kwargs
        return {
            "output": {
                "message": {
                    "content": [
                        {"text": "Review the critical findings first."}
                    ]
                }
            },
            "usage": {"inputTokens": 42, "outputTokens": 8},
        }


def authenticated_event(arguments):
    return {"identity": {"sub": "user-123"}, "arguments": arguments}


def test_chat_uses_nova_with_history_and_report_summaries(monkeypatch):
    handler = load_handler_module()
    bedrock = FakeBedrock()
    quota_users = []
    monkeypatch.setattr(handler, "_bedrock_client", lambda: bedrock)
    monkeypatch.setattr(handler, "_consume_quota", quota_users.append)

    result = handler.handler(
        authenticated_event({
            "message": "What should I investigate?",
            "historyJson": (
                '[{"role":"user","content":"Hello"},'
                '{"role":"assistant","content":"How can I help?"}]'
            ),
            "reportContextJson": '{"reports":[{"riskBand":"critical"}]}',
        }),
        None,
    )

    assert result == {
        "answer": "Review the critical findings first.",
        "modelId": "us.amazon.nova-2-lite-v1:0",
        "inputTokens": 42,
        "outputTokens": 8,
    }
    assert bedrock.request["modelId"] == "us.amazon.nova-2-lite-v1:0"
    assert bedrock.request["messages"][-1]["content"][0]["text"] == (
        "What should I investigate?"
    )
    assert "logsentinel_reports" in bedrock.request["system"][1]["text"]
    assert bedrock.request["inferenceConfig"]["maxTokens"] == 1_200
    assert quota_users == ["user-123"]


def test_chat_rejects_empty_message(monkeypatch):
    handler = load_handler_module()
    monkeypatch.setattr(handler, "_bedrock_client", lambda: FakeBedrock())

    with pytest.raises(ValueError, match="message is required"):
        handler.handler(authenticated_event({"message": "  "}), None)


def test_chat_rejects_malformed_history(monkeypatch):
    handler = load_handler_module()
    monkeypatch.setattr(handler, "_bedrock_client", lambda: FakeBedrock())

    with pytest.raises(ValueError, match="not valid JSON"):
        handler.handler(
            authenticated_event({
                "message": "Hello",
                "historyJson": "not-json",
            }),
            None,
        )


def test_chat_requires_authenticated_identity():
    handler = load_handler_module()

    with pytest.raises(PermissionError, match="authenticated user"):
        handler.handler({"arguments": {"message": "Hello"}}, None)


def test_chat_rejects_out_of_order_history(monkeypatch):
    handler = load_handler_module()
    monkeypatch.setattr(handler, "_consume_quota", lambda _user_id: None)

    with pytest.raises(ValueError, match="out of order"):
        handler.handler(
            authenticated_event({
                "message": "Hello",
                "historyJson": (
                    '[{"role":"assistant","content":"Unexpected first response"}]'
                ),
            }),
            None,
        )


def test_chat_enforces_daily_quota(monkeypatch):
    handler = load_handler_module()

    class QuotaExceeded(Exception):
        response = {
            "Error": {"Code": "ConditionalCheckFailedException"}
        }

    class FullUsageTable:
        def update_item(self, **_kwargs):
            raise QuotaExceeded()

    monkeypatch.setattr(handler, "_usage_table", lambda: FullUsageTable())

    with pytest.raises(PermissionError, match="Daily chat limit"):
        handler._consume_quota("user-123")
