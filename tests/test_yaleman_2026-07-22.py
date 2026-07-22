"""Tests for bugs discovered during repository review, found by yaleman on 2026-07-22."""

from typing import Any, List, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sam_bot.misp import MispCustomConnector


import logging

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


@pytest.fixture
def misp_connector() -> MispCustomConnector:
    """Create a MispCustomConnector with a mocked PyMISP connection."""
    with patch("sam_bot.misp.PyMISP"):
        connector = MispCustomConnector(
            misp_url="https://misp.example.com",
            misp_key="test-key",
            misp_ssl=True,
            debug=True,
        )
    return connector


class TestGetCommAndTagsDuplicateTag:
    """Bug: get_comm_and_tags crashes with ValueError on duplicate tag: lines.

    The second `tag:` line calls tags.remove("tlp:green") but "tlp:green"
    was already removed by the first tag: line, raising ValueError.
    """

    def test_duplicate_tag_lines_do_not_crash_and_do_filter(
        self, misp_connector: MispCustomConnector
    ) -> None:
        input_text = "tag: tlp:red\ntag: tlp:amber\ntype: phish\n"
        comment, tags = misp_connector.get_comm_and_tags(input_text)
        assert "tlp:amber" in tags
        assert "tlp:red" not in tags


class TestMispSendDomainIpAssociation:
    """Bug: IP+domain association check is broken.

    In misp_send, line 166: `if "domain:" in strInput.splitlines()` checks
    for an exact line match of "domain:", not whether any line contains "domain:".
    This means IPs are never associated with domains in domain-ip objects.
    """

    def test_ip_with_domain_creates_domain_ip_object(
        self, misp_connector: MispCustomConnector
    ) -> None:
        input_text = "domain: evil.com\nip: 1.2.3.4\ntag: tlp:green\ntype: phish\n"
        captured_objects: List[Any] = []

        def capture_submit(
            misp: Any, misp_event: Any, original_misp_objects: Any
        ) -> Tuple[List[Any], List[Any]]:
            captured_objects.extend(original_misp_objects)
            return ([], [])

        with patch.object(misp_connector, "submit_to_misp", side_effect=capture_submit):
            with patch.object(misp_connector.misp, "add_event") as mock_add_event:
                mock_add_event.return_value = {
                    "Event": {"id": "1", "uuid": "test-uuid"}
                }
                with patch.object(misp_connector.misp, "tag"):
                    with patch.object(misp_connector.misp, "publish") as mock_publish:
                        mock_publish.return_value = {
                            "Event": {"id": "1"},
                            "errors": False,
                        }
                        misp_connector.misp_send(0, input_text, "test", "testuser")

        domain_ip_objects = [obj for obj in captured_objects if obj.name == "domain-ip"]
        assert len(domain_ip_objects) == 1, (
            f"Expected 1 domain-ip object with both domain and ip, "
            f"got {len(domain_ip_objects)}. "
            f"Objects: {[(o.name, [a.type for a in o.attributes]) for o in captured_objects]}"
        )
        attr_types = [a.type for a in domain_ip_objects[0].attributes]
        assert "domain" in attr_types
        assert "ip" in attr_types or "ip-dst" in attr_types

    def test_multiple_domains_create_separate_objects(
        self, misp_connector: MispCustomConnector
    ) -> None:
        input_text = "domain: evil.com\nip: 1.2.3.4\ndomain: bad.org\nip: 5.6.7.8\ntag: tlp:green\ntype: phish\n"
        captured_objects: List[Any] = []

        def capture_submit(
            misp: Any, misp_event: Any, original_misp_objects: Any
        ) -> Tuple[List[Any], List[Any]]:
            captured_objects.extend(original_misp_objects)
            return ([], [])

        with patch.object(misp_connector, "submit_to_misp", side_effect=capture_submit):
            with patch.object(misp_connector.misp, "add_event") as mock_add_event:
                mock_add_event.return_value = {
                    "Event": {"id": "1", "uuid": "test-uuid"}
                }
                with patch.object(misp_connector.misp, "tag"):
                    with patch.object(misp_connector.misp, "publish") as mock_publish:
                        mock_publish.return_value = {
                            "Event": {"id": "1"},
                            "errors": False,
                        }
                        misp_connector.misp_send(0, input_text, "test", "testuser")

        domain_ip_objects = [obj for obj in captured_objects if obj.name == "domain-ip"]
        assert len(domain_ip_objects) == 2, (
            f"Expected 2 domain-ip objects, got {len(domain_ip_objects)}. "
            f"Objects: {[(o.name, [a.type for a in o.attributes]) for o in captured_objects]}"
        )
        # First domain-ip should have evil.com and 1.2.3.4
        first_attrs = [a.value for a in domain_ip_objects[0].attributes]
        assert "evil.com" in first_attrs
        assert "1.2.3.4" in first_attrs
        # Second domain-ip should have bad.org and 5.6.7.8
        second_attrs = [a.value for a in domain_ip_objects[1].attributes]
        assert "bad.org" in second_attrs
        assert "5.6.7.8" in second_attrs


class TestHandleMessageFallthrough:
    """Bug: handle_message always returns 403 due to fallthrough.

    Lines 229-230 in __main__.py are at function scope, not inside the else
    block. Every code path (files, hi, etc.) gets its return_value overwritten
    with 403 "Unhandled message type".
    """

    def test_hi_message_returns_200_not_403(self) -> None:
        from sam_bot.__main__ import handle_message

        event_data = {
            "event": {
                "type": "message",
                "text": "hi",
                "user": "U123",
                "channel": "C123",
                "subtype": None,
            }
        }
        with patch("sam_bot.__main__.slack_client") as mock_client:
            mock_client.chat_postMessage = AsyncMock(
                return_value=MagicMock(get=lambda x: "ok")
            )
            response, status = handle_message(event_data)
            assert status == 200, f"Expected 200 but got {status}: {response}"

    def test_files_message_returns_200_not_403(self) -> None:
        from sam_bot.__main__ import handle_message

        event_data = {
            "event": {
                "type": "message",
                "text": "",
                "user": "U123",
                "channel": "C123",
                "files": [
                    {
                        "mode": "snippet",
                        "url_private_download": "https://example.com/file",
                        "title": "test snippet",
                    }
                ],
            }
        }
        with patch("sam_bot.__main__.threading.Thread") as mock_thread:
            mock_thread_instance = MagicMock()
            mock_thread.return_value = mock_thread_instance
            response, status = handle_message(event_data)
            assert status == 200, f"Expected 200 but got {status}: {response}"


class TestHiSubstringMatch:
    """Bug: 'hi' in message text matches substrings like 'this', 'ship'.

    The check `"hi" in message.get("text")` matches any message containing
    the letters "hi" anywhere, not just the word "hi".
    """

    def test_this_does_not_trigger_hi_response(self) -> None:
        from sam_bot.__main__ import handle_message

        event_data = {
            "event": {
                "type": "message",
                "text": "this is a test message about shipping",
                "user": "U123",
                "channel": "C123",
                "subtype": None,
            }
        }
        with patch("sam_bot.__main__.slack_client") as mock_client:
            mock_client.chat_postMessage = AsyncMock()
            response, status = handle_message(event_data)
            mock_client.chat_postMessage.assert_not_called()
