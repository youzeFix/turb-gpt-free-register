# -*- coding: utf-8 -*-
"""通用 API 取码客户端：缓存破坏参数与 401/429 的处理。"""
import json
import unittest
from unittest.mock import patch

from core import generic_api_mail_client as g
from core.generic_api_mail_client import (
    GenericApiEmailAccount,
    _error_code,
    _retry_after_seconds,
    fetch_latest_otp,
)


class _Response:
    def __init__(self, status_code, payload=None, text=None, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload or {}, ensure_ascii=False)
        self.headers = headers or {}

    def json(self):
        return self._payload if self._payload is not None else json.loads(self.text)


class _Session:
    """按脚本依次返回响应，并记录请求过的 URL。

    脚本用完后持续返回最后一个响应，模拟真实服务"状态不变"的持续行为。
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []
        self.proxies = {}
        self.trust_env = True

    def get(self, url, **_kwargs):
        self.urls.append(url)
        if self.responses:
            self._last = self.responses.pop(0)
            return self._last
        return getattr(self, "_last", _Response(200, {}))


class ErrorCodeTests(unittest.TestCase):
    def test_extracts_nested_code(self):
        payload = {"error": {"code": "INVALID_API_KEY", "message": "API Key 无效"}}
        self.assertEqual(_error_code(json.dumps(payload, ensure_ascii=False)), "INVALID_API_KEY")

    def test_handles_plain_text(self):
        self.assertEqual(_error_code("not json"), "")

    def test_retry_after_seconds(self):
        self.assertEqual(_retry_after_seconds(_Response(429, headers={"Retry-After": "4"})), 4.0)
        self.assertEqual(
            _retry_after_seconds(_Response(429, headers={"X-Retry-After-Ms": "1500"})), 1.5
        )
        self.assertEqual(_retry_after_seconds(_Response(429)), 0.0)


class CacheBusterFallbackTests(unittest.TestCase):
    """带缓存破坏参数被判凭据非法时，要自动退回干净 URL。"""

    def setUp(self):
        g._NO_CACHE_BUSTER_URLS.clear()

    def tearDown(self):
        g._NO_CACHE_BUSTER_URLS.clear()

    def test_401_invalid_api_key_falls_back_to_clean_url(self):
        code_url = "http://127.0.0.1:8788/api/v1/otp?token=abc"
        session = _Session([
            _Response(401, {"error": {"code": "INVALID_API_KEY", "message": "API Key 无效"}}),
            _Response(200, {"otp": "123456", "time": "2026-10-22T10:51:34+08:00"}),
        ])
        account = GenericApiEmailAccount(email="a@icloud.com", code_url=code_url)
        with patch.object(g, "_new_http_session", return_value=session), \
             patch.object(g, "get_account_context", return_value=account), \
             patch.object(g.time, "sleep"):
            code = fetch_latest_otp("a@icloud.com", after_ts=None, max_wait=5, settle_seconds=0)

        self.assertEqual(code, "123456")
        # 第一次带 _otp_poll，第二次必须是原始 URL
        self.assertIn("_otp_poll", session.urls[0])
        self.assertEqual(session.urls[1], code_url)
        self.assertIn(code_url, g._NO_CACHE_BUSTER_URLS)

    def test_401_invalid_api_key_is_not_retried_when_url_is_clean(self):
        code_url = "http://127.0.0.1:8788/api/v1/otp?token=abc"
        # 事先标记成"不要再加缓存破坏参数"，模拟第二次请求就是干净 URL
        g._NO_CACHE_BUSTER_URLS.add(code_url)
        session = _Session([
            _Response(401, {"error": {"code": "INVALID_API_KEY", "message": "API Key 无效"}}),
        ])
        account = GenericApiEmailAccount(email="a@icloud.com", code_url=code_url)
        with patch.object(g, "_new_http_session", return_value=session), \
             patch.object(g, "get_account_context", return_value=account), \
             patch.object(g.time, "sleep"):
            with self.assertRaises(g.GenericApiMailError) as ctx:
                fetch_latest_otp("a@icloud.com", after_ts=None, max_wait=2, settle_seconds=0)
        self.assertIn("401", str(ctx.exception))
        # 干净 URL 仍然 401 属于真实凭据问题：应直接用原始 URL 继续轮询，
        # 不能再加缓存破坏参数，也不应把它加进回退名单。
        self.assertTrue(session.urls)
        for used in session.urls:
            self.assertEqual(used, code_url)
            self.assertNotIn("_otp_poll", used)

    def test_429_backs_off_instead_of_pretending_no_code(self):
        code_url = "http://127.0.0.1:8788/api/v1/otp?token=abc"
        session = _Session([
            _Response(429, {"error": {"code": "RATE_LIMITED", "message": "刷新较多"}},
                      headers={"Retry-After": "2"}),
            _Response(200, {"otp": "654321", "time": "2026-10-22T10:51:34+08:00"}),
        ])
        account = GenericApiEmailAccount(email="a@icloud.com", code_url=code_url)
        slept = []
        with patch.object(g, "_new_http_session", return_value=session), \
             patch.object(g, "get_account_context", return_value=account), \
             patch.object(g.time, "sleep", side_effect=lambda s: slept.append(s)):
            code = fetch_latest_otp("a@icloud.com", after_ts=None, max_wait=10, settle_seconds=0)
        self.assertEqual(code, "654321")
        # 429 时应按 Retry-After 退避
        self.assertTrue(any(abs(s - 2.0) < 0.01 for s in slept), slept)


if __name__ == "__main__":
    unittest.main()
