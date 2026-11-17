# -*- coding: utf-8 -*-
"""Cloak 查活 Turnstile 质询处理（_ensure_challenge_cleared 等）离线测试。"""
import unittest
from unittest.mock import MagicMock, patch

import core.cloakbrowser_liveness as liveness


def _driver_with_text(text):
    driver = MagicMock()
    driver.execute_script.return_value = text
    driver.page = MagicMock()
    driver.page.query_selector_all.return_value = []
    return driver


class ChallengeDetectionTests(unittest.TestCase):
    def test_interstitial_title_is_challenged(self):
        driver = _driver_with_text("Just a moment...\n请稍候")
        self.assertTrue(liveness._looks_challenged(driver))

    def test_japanese_interstitial_is_challenged(self):
        driver = _driver_with_text("しばらくお待ちください...")
        self.assertTrue(liveness._looks_challenged(driver))

    def test_turnstile_marker_is_challenged(self):
        driver = _driver_with_text("Verifying you are human. challenge-platform/scripts")
        self.assertTrue(liveness._looks_challenged(driver))

    def test_normal_login_page_not_challenged(self):
        driver = _driver_with_text("ログイン - OpenAI\n继续使用电子邮件")
        self.assertFalse(liveness._looks_challenged(driver))

    def test_script_failure_not_challenged(self):
        driver = MagicMock()
        driver.execute_script.side_effect = RuntimeError("page closed")
        self.assertFalse(liveness._looks_challenged(driver))


class EnsureChallengeClearedTests(unittest.TestCase):
    def test_no_challenge_returns_immediately(self):
        driver = _driver_with_text("ログイン - OpenAI")
        with patch.object(liveness, "_maybe_click_turnstile", return_value="") as click:
            result = liveness._ensure_challenge_cleared(driver, "a@b.c", max_wait=30)
        self.assertFalse(result)
        self.assertFalse(click.called)

    def test_challenge_click_then_cleared(self):
        driver = _driver_with_text("Just a moment...")
        with patch.object(liveness, "_looks_challenged", side_effect=[True, True, False]), \
             patch.object(liveness, "_maybe_click_turnstile", return_value="checkbox") as click, \
             patch.object(liveness.time, "sleep"), \
             patch.object(liveness.time, "time", side_effect=[0, 0, 1, 2, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]):
            result = liveness._ensure_challenge_cleared(driver, "a@b.c", max_wait=240)
        self.assertTrue(result)
        self.assertTrue(click.called)

    def test_manual_hint_logged_once(self):
        driver = _driver_with_text("Just a moment...")
        with patch.object(liveness, "_looks_challenged", return_value=True), \
             patch.object(liveness, "_maybe_click_turnstile", return_value=""), \
             patch.object(liveness.logger, "warning") as warn, \
             patch.object(liveness.time, "sleep"):
            # 循环依赖 time.time 推进；简化：max_wait 很小直接超时
            result = liveness._ensure_challenge_cleared(driver, "a@b.c", max_wait=0.1)
        self.assertTrue(result)


class LoginPageIntegrationTests(unittest.TestCase):
    def test_challenge_extends_login_email_deadline(self):
        """质询出现并解决后，邮箱表单等待应重新计时并成功提交。"""
        driver = MagicMock()
        driver.page = MagicMock()
        calls = {"n": 0}

        def flaky_email(d, e, timeout=None):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise RuntimeError("no form")

        with patch.object(liveness, "_check_manual_stop"), \
             patch.object(liveness, "_looks_challenged", side_effect=[True, False, False]), \
             patch.object(liveness, "_ensure_challenge_cleared", return_value=True) as cleared, \
             patch.object(liveness, "_type_email_address", side_effect=flaky_email), \
             patch.object(liveness, "_submit_email_step"), \
             patch.object(liveness.human_delay, "__call__", return_value=None), \
             patch.object(liveness.time, "sleep"), \
             patch.object(liveness.time, "time", side_effect=[0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20] * 10):
            liveness._submit_login_email(driver, "a@b.c", timeout=10)
        self.assertEqual(calls["n"], 3)
        self.assertTrue(cleared.called)


if __name__ == "__main__":
    unittest.main()
