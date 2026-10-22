# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core import domain_probe
from core.domain_probe import (
    VERDICT_ACCEPTED,
    VERDICT_INCONCLUSIVE,
    VERDICT_REJECTED,
    ProbeResult,
    is_create_account_failure,
    normalize_domain,
)


class NormalizeDomainTests(unittest.TestCase):
    def test_strips_whitespace_and_at_sign(self):
        self.assertEqual(normalize_domain("  MyDomain.com "), "mydomain.com")
        self.assertEqual(normalize_domain("@mydomain.com"), "mydomain.com")

    def test_strips_mailbox_address(self):
        self.assertEqual(normalize_domain("abc@mydomain.com"), "mydomain.com")

    def test_strips_path(self):
        self.assertEqual(normalize_domain("https://mydomain.com/"), "mydomain.com")


class CreateAccountFailureTests(unittest.TestCase):
    def test_detects_english(self):
        self.assertTrue(is_create_account_failure("Failed to create account. Please try again"))

    def test_detects_japanese(self):
        self.assertTrue(is_create_account_failure("アカウントを作成できませんでした。もう一度お試しください"))

    def test_detects_chinese(self):
        self.assertTrue(is_create_account_failure("无法创建账户"))

    def test_ignores_other_errors(self):
        self.assertFalse(is_create_account_failure("Password is too short"))
        self.assertFalse(is_create_account_failure(""))


class ProbeDomainTests(unittest.TestCase):
    def test_invalid_domain_is_inconclusive_without_browser(self):
        with patch("core.cloakbrowser_driver.build_cloak_driver") as build:
            result = domain_probe.probe_domain("not-a-domain")
        build.assert_not_called()
        self.assertEqual(result.verdict, VERDICT_INCONCLUSIVE)
        self.assertEqual(result.stage, domain_probe.STAGE_INPUT)

    def test_rejected_on_email_submit(self):
        class FakeDriver:
            current_url = "https://chatgpt.com/auth/error?error=undefined"

            def __init__(self):
                self.visited = []

            def get(self, url):
                self.visited.append(url)

            def quit(self):
                pass

        driver = FakeDriver()
        with patch("core.cloakbrowser_driver.build_cloak_driver", return_value=(driver, object())), \
             patch("core.roxy_registration._wait_for_email_input", return_value=object()), \
             patch("core.roxy_registration._submit_email_and_wait_next",
                   side_effect=RuntimeError("邮箱提交后未进入密码页/验证码页")), \
             patch("core.roxy_registration._is_email_verification_page", return_value=False):
            result = domain_probe.probe_domain("bad-domain.com")

        self.assertEqual(result.verdict, VERDICT_REJECTED)
        self.assertEqual(result.stage, domain_probe.STAGE_EMAIL_SUBMIT)
        self.assertIn("bad-domain.com", result.probe_email)

    def test_rejected_on_register_stage(self):
        class FakeDriver:
            current_url = "https://auth.openai.com/create-account/password"

            def __init__(self):
                self.scripts = []

            def get(self, url):
                pass

            def execute_script(self, script, *args):
                self.scripts.append(script)
                return True

            def quit(self):
                pass

        driver = FakeDriver()
        page_state = {
            "url": "https://auth.openai.com/create-account/password",
            "errors": ["Failed to create account. Please try again"],
        }
        with patch("core.cloakbrowser_driver.build_cloak_driver", return_value=(driver, object())), \
             patch("core.roxy_registration._wait_for_email_input", return_value=object()), \
             patch("core.roxy_registration._submit_email_and_wait_next", return_value="otp"), \
             patch("core.roxy_registration._is_email_verification_page", return_value=True), \
             patch("core.roxy_registration._click_continue_with_password_if_present",
                   return_value={"ok": True}), \
             patch("core.roxy_registration._is_signup_password_page", return_value=True), \
             patch("core.roxy_registration._password_page_state", return_value=page_state):
            result = domain_probe.probe_domain("blocked-domain.com")

        self.assertEqual(result.verdict, VERDICT_REJECTED)
        self.assertEqual(result.stage, domain_probe.STAGE_REGISTER)
        self.assertIn("建号被拒", result.detail)

    def test_accepted_when_register_succeeds(self):
        class FakeDriver:
            current_url = "https://auth.openai.com/email-verification"

            def get(self, url):
                pass

            def execute_script(self, script, *args):
                return True

            def quit(self):
                pass

        driver = FakeDriver()
        state = {"url": "https://auth.openai.com/email-verification", "errors": []}
        # 第一次调用：已经进入密码页；第二次：仍在密码页；第三次：提交后已离开
        password_page_calls = [True, True, False]
        with patch("core.cloakbrowser_driver.build_cloak_driver", return_value=(driver, object())), \
             patch("core.roxy_registration._wait_for_email_input", return_value=object()), \
             patch("core.roxy_registration._submit_email_and_wait_next", return_value="otp"), \
             patch("core.roxy_registration._is_email_verification_page", return_value=True), \
             patch("core.roxy_registration._click_continue_with_password_if_present",
                   return_value={"ok": True}), \
             patch("core.roxy_registration._is_signup_password_page",
                   side_effect=password_page_calls), \
             patch("core.roxy_registration._password_page_state", return_value=state):
            result = domain_probe.probe_domain("good-domain.com")

        self.assertEqual(result.verdict, VERDICT_ACCEPTED)
        self.assertEqual(result.stage, domain_probe.STAGE_REGISTER)

    def test_probe_result_to_dict(self):
        data = ProbeResult("a.com", VERDICT_ACCEPTED, domain_probe.STAGE_REGISTER).to_dict()
        self.assertEqual(data["domain"], "a.com")
        self.assertEqual(data["verdict"], VERDICT_ACCEPTED)
        self.assertIn("elapsed", data)


class ProbeRetryTests(unittest.TestCase):
    """邮箱提交步的"拒绝"可能是偶发失败，必须重试后再下结论。"""

    def test_retries_on_email_submit_rejection(self):
        rejected = ProbeResult(
            domain="d.com",
            verdict=VERDICT_REJECTED,
            stage=domain_probe.STAGE_EMAIL_SUBMIT,
            detail="被拒",
        )
        accepted = ProbeResult(
            domain="d.com",
            verdict=VERDICT_ACCEPTED,
            stage=domain_probe.STAGE_REGISTER,
            detail="建号接口通过",
        )
        calls = []

        def fake_probe(_driver, _domain, **_kwargs):
            calls.append(1)
            return rejected if len(calls) == 1 else accepted

        with patch("core.domain_probe._probe_with_driver", side_effect=fake_probe), \
             patch("core.domain_probe.time.sleep"):
            result = domain_probe._probe_with_retry(
                object(), "d.com", check_register=True, attempts=3
            )
        self.assertEqual(len(calls), 2)
        self.assertEqual(result.verdict, VERDICT_ACCEPTED)

    def test_gives_up_after_max_attempts(self):
        rejected = ProbeResult(
            domain="d.com",
            verdict=VERDICT_REJECTED,
            stage=domain_probe.STAGE_EMAIL_SUBMIT,
            detail="被拒",
        )
        calls = []

        def fake_probe(_driver, _domain, **_kwargs):
            calls.append(1)
            return rejected

        with patch("core.domain_probe._probe_with_driver", side_effect=fake_probe), \
             patch("core.domain_probe.time.sleep"):
            result = domain_probe._probe_with_retry(
                object(), "d.com", check_register=True, attempts=3
            )
        self.assertEqual(len(calls), 3)
        self.assertEqual(result.verdict, VERDICT_REJECTED)
        self.assertIn("重试 3 次", result.detail)

    def test_register_rejection_is_not_retried(self):
        rejected = ProbeResult(
            domain="d.com",
            verdict=VERDICT_REJECTED,
            stage=domain_probe.STAGE_REGISTER,
            detail="建号被拒",
        )
        calls = []

        def fake_probe(_driver, _domain, **_kwargs):
            calls.append(1)
            return rejected

        with patch("core.domain_probe._probe_with_driver", side_effect=fake_probe), \
             patch("core.domain_probe.time.sleep"):
            result = domain_probe._probe_with_retry(
                object(), "d.com", check_register=True, attempts=3
            )
        self.assertEqual(len(calls), 1)
        self.assertEqual(result.verdict, VERDICT_REJECTED)


class ProbeDomainsTests(unittest.TestCase):
    def test_deduplicates_and_normalizes(self):
        captured = {}

        def fake_probe(domains, **_kwargs):
            captured["domains"] = list(domains)
            return []

        with patch("core.cloakbrowser_driver.build_cloak_driver", side_effect=Exception("no browser")):
            results = domain_probe.probe_domains(["A.com", "a.com", " b.com "], check_register=False)
        self.assertEqual(captured, {})  # 启动浏览器失败时走异常分支
        self.assertEqual(len(results), 2)
        self.assertEqual([item.domain for item in results], ["a.com", "b.com"])

    def test_empty_input_returns_empty(self):
        self.assertEqual(domain_probe.probe_domains([]), [])
        self.assertEqual(domain_probe.probe_domains(None), [])


if __name__ == "__main__":
    unittest.main()
