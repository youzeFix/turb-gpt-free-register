# -*- coding: utf-8 -*-
"""CloakBrowser 浏览器查活（core/cloakbrowser_liveness.py）离线测试。"""
import unittest
from unittest.mock import MagicMock, patch

import core.cloakbrowser_liveness as liveness
import core.live_check_service as live_service


def _session_info():
    return {"accessToken": "new-at", "user": {"id": "u1"}, "account": {"planType": "free"}}


def _driver_pair():
    driver = MagicMock()
    driver.current_url = "https://chatgpt.com/"
    opened = MagicMock()
    opened.profile_id = "p1"
    opened.fingerprint = {"userAgent": "ua", "locale": "ja", "timezone": "Asia/Tokyo"}
    return driver, opened


class RunCloakLivenessTests(unittest.TestCase):
    def _patch_common(self, driver, opened, **overrides):
        base = {
            "build_cloak_driver": (driver, opened),
            "_maybe_accept": None,
            "_fetch_chatgpt_session": _session_info(),
            "BrowserDataSaver": MagicMock(),
        }
        base.update(overrides)
        return patch.multiple(
            liveness,
            **{k: (v if k == "build_cloak_driver" else v) for k, v in base.items()},
        )

    def test_password_login_success(self):
        driver, opened = _driver_pair()
        with patch.object(liveness, "_maybe_accept"), \
             patch.object(liveness, "_submit_login_email"), \
             patch.object(liveness, "_fill_login_password_if_present", return_value="next_step"), \
             patch.object(liveness, "_fetch_chatgpt_session", return_value=_session_info()), \
             patch.object(liveness, "build_cloak_driver", return_value=(driver, opened)):
            result = liveness.run_cloak_liveness("a@b.c", proxy="http://127.0.0.1:7897")
        self.assertTrue(result["ok"])
        self.assertEqual(result["access_token"], "new-at")
        self.assertEqual(result["driver"], "cloak")
        self.assertEqual(result["status"], "live")

    def test_otp_login_success_invokes_on_authenticated(self):
        driver, opened = _driver_pair()
        seen = {}
        def on_authenticated(result, drv):
            seen["drv"] = drv
            result["plan_result"] = {"ok": True}
            return result
        with patch.multiple(
            liveness,
            _maybe_accept=MagicMock(),
            _submit_login_email=MagicMock(),
            _fill_login_password_if_present=MagicMock(return_value="email_otp"),
            _submit_email_otp=MagicMock(),
            _fetch_chatgpt_session=MagicMock(return_value=_session_info()),
        ), patch.object(liveness, "build_cloak_driver", return_value=(driver, opened)):
            result = liveness.run_cloak_liveness("a@b.c", on_authenticated=on_authenticated)
        self.assertTrue(result["plan_result"]["ok"])
        self.assertIs(seen["drv"], driver)

    def test_otp_timeout_maps_to_failed(self):
        driver, opened = _driver_pair()
        with patch.multiple(
            liveness,
            _maybe_accept=MagicMock(),
            _submit_login_email=MagicMock(),
            _fill_login_password_if_present=MagicMock(return_value="email_otp"),
            _submit_email_otp=MagicMock(side_effect=RuntimeError("邮箱 OTP 等待超时")),
        ), patch.object(liveness, "build_cloak_driver", return_value=(driver, opened)):
            result = liveness.run_cloak_liveness("a@b.c")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "failed")
        self.assertIn("RuntimeError", result["error"])

    def test_account_unusable_maps_to_deactivated(self):
        from core.openai_auth import AccountUnusableError
        driver, opened = _driver_pair()
        with patch.multiple(
            liveness,
            _maybe_accept=MagicMock(),
            _submit_login_email=MagicMock(),
            _fill_login_password_if_present=MagicMock(return_value="email_otp"),
            _submit_email_otp=MagicMock(side_effect=AccountUnusableError("账号已废", error_code="account_deactivated")),
        ), patch.object(liveness, "build_cloak_driver", return_value=(driver, opened)):
            result = liveness.run_cloak_liveness("a@b.c")
        self.assertEqual(result["status"], "deactivated")
        self.assertEqual(result["error"], "account_deactivated")

    def test_no_session_token_maps_to_failed(self):
        driver, opened = _driver_pair()
        with patch.multiple(
            liveness,
            _maybe_accept=MagicMock(),
            _submit_login_email=MagicMock(),
            _fill_login_password_if_present=MagicMock(return_value="next_step"),
            _fetch_chatgpt_session=MagicMock(return_value={"accessToken": ""}),
        ), patch.object(liveness, "build_cloak_driver", return_value=(driver, opened)):
            result = liveness.run_cloak_liveness("a@b.c")
        self.assertEqual(result["status"], "failed")

    def test_missing_email_raises(self):
        with self.assertRaises(ValueError):
            liveness.run_cloak_liveness("")

    def test_submit_login_email_retries_until_form_ready(self):
        driver, opened = _driver_pair()
        calls = {"n": 0}
        def flaky(driver_, email_, timeout=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("no form yet")
        with patch.object(liveness, "_type_email_address", side_effect=flaky), \
             patch.object(liveness, "_submit_email_step") as submit, \
             patch.object(liveness, "_check_manual_stop"), \
             patch.object(liveness.human_delay, "__call__", return_value=None), \
             patch.object(liveness.time, "sleep", return_value=None):
            liveness._submit_login_email(driver, "a@b.c", timeout=30)
        self.assertEqual(calls["n"], 3)
        self.assertTrue(submit.called)

    def test_browser_proxy_uses_registration_pool_not_plan_pool(self):
        from types import SimpleNamespace
        cfg = SimpleNamespace(PROXY_POOL=["http://clash:7897"], PLAN_CHECK_PROXY=["http://resi:1"])
        for _ in range(5):
            proxy = live_service._browser_live_check_proxy(cfg)
            self.assertEqual(proxy, "http://clash:7897")

    def test_browser_proxy_empty_pool_returns_none(self):
        from types import SimpleNamespace
        cfg = SimpleNamespace(PROXY_POOL=[], PLAN_CHECK_PROXY=["http://resi:1"])
        self.assertIsNone(live_service._browser_live_check_proxy(cfg))

    def test_cloak_branch_runs_browser_driver_offline(self):
        """LIVE_CHECK_DRIVER=cloak 时 _run_live_check 必须走 mock 浏览器驱动，
        绝不能触碰真实浏览器/网络（本测试全程离线）。"""
        import core.cloakbrowser_liveness as cloak_liveness
        slot = MagicMock()
        with patch("config.roxybrowser.LIVE_CHECK_DRIVER", "cloak"), \
             patch.object(live_service, "_browser_live_check_proxy", return_value="http://clash:7897"), \
             patch.object(cloak_liveness, "run_cloak_liveness",
                          return_value={"ok": True, "status": "live", "access_token": "at",
                                        "session": {}, "driver": "cloak"}) as browser_mock, \
             patch.object(live_service.db, "get_account", return_value={
                 "id": 7, "email": "fixture@example.com", "email_source": "remail",
                 "access_token": "old"}), \
             patch.object(live_service.db, "mark_account_live_check_running", return_value=True), \
             patch.object(live_service.db, "update_account_liveness", return_value=True) as update_mock, \
             patch.object(live_service.db, "claim_account_live_check", return_value=True), \
             patch.object(live_service, "_QUEUE_SLOTS", slot), \
             patch("config.proxy.PLAN_CHECK_TIMEOUT", 5.0):
            result = live_service._run_live_check(
                account_id=7, email="fixture@example.com", proxy=None,
                trigger="test", run_id="run-1",
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["driver"], "cloak")
        self.assertTrue(browser_mock.called)
        self.assertTrue(update_mock.called)


if __name__ == "__main__":
    unittest.main()
