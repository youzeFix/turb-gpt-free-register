# -*- coding: utf-8 -*-
"""OTP 等待的后缀熔断（core/email_provider）离线测试。"""
import unittest
from unittest.mock import patch

from core.email_provider import (
    EmailSuffixBlockedError,
    _SUFFIX_BLOCK_THRESHOLD,
    _clear_suffix_fails,
    _email_suffix,
    _fetch_otp_with_suffix_breaker,
    _record_suffix_fail,
    _suffix_fail_count,
)


class SuffixBreakerTests(unittest.TestCase):
    def setUp(self):
        _clear_suffix_fails("blocked.com")
        _clear_suffix_fails("ok.com")

    def test_suffix_extracted(self):
        self.assertEqual(_email_suffix("A.B@Outlook.COM "), "outlook.com")

    def test_success_resets_fail_count(self):
        _record_suffix_fail("ok.com")
        _record_suffix_fail("ok.com")
        self.assertEqual(_suffix_fail_count("ok.com"), 2)
        code = _fetch_otp_with_suffix_breaker(
            "a@ok.com", "generic_api", lambda e, **k: "123456", {}, 123.0)
        self.assertEqual(code, "123456")
        self.assertEqual(_suffix_fail_count("ok.com"), 0)

    def test_blocked_after_threshold_fails_immediately(self):
        for _ in range(_SUFFIX_BLOCK_THRESHOLD):
            _record_suffix_fail("blocked.com")
        with self.assertRaises(EmailSuffixBlockedError):
            _fetch_otp_with_suffix_breaker(
                "a@blocked.com", "remail", lambda e, **k: "123456", {}, 123.0)
        # fetch 未被调用：快速失败不等待
        self.assertEqual(_suffix_fail_count("blocked.com"), _SUFFIX_BLOCK_THRESHOLD)

    def test_timeout_error_still_recorded_and_reraised(self):
        def timeout_fetch(email, **kwargs):
            raise RuntimeError("等待 Remail 验证码超时")

        with self.assertRaises(RuntimeError):
            _fetch_otp_with_suffix_breaker("a@blocked.com", "remail", timeout_fetch, {}, 123.0)
        self.assertEqual(_suffix_fail_count("blocked.com"), 1)

    def test_threshold_hit_reraises_with_hint(self):
        def timeout_fetch(email, **kwargs):
            raise RuntimeError("等待验证码超时")

        for _ in range(_SUFFIX_BLOCK_THRESHOLD - 1):
            _record_suffix_fail("blocked.com")
        with self.assertRaises(RuntimeError) as ctx:
            _fetch_otp_with_suffix_breaker("a@blocked.com", "remail", timeout_fetch, {}, 123.0)
        self.assertIn("后缀熔断", str(ctx.exception))

    def test_different_suffixes_independent(self):
        for _ in range(_SUFFIX_BLOCK_THRESHOLD):
            _record_suffix_fail("blocked.com")
        with self.assertRaises(EmailSuffixBlockedError):
            _fetch_otp_with_suffix_breaker("a@blocked.com", "remail", lambda e, **k: "1", {}, 123.0)
        # 其他后缀不受影响
        code = _fetch_otp_with_suffix_breaker(
            "b@other.com", "generic_api", lambda e, **k: "654321", {}, 123.0)
        self.assertEqual(code, "654321")


if __name__ == "__main__":
    unittest.main()
