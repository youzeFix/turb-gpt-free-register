# -*- coding: utf-8 -*-
"""查活 CF 预热缓存（core/cf_warm.py）离线测试。"""
import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import core.cf_warm as cf_warm


_RESID_PROXY = (
    "http://regfac01_custom_zone_JP_sid_12554321_time_10:pw@us.ipwo.net:7878"
)


def _write_cache(tmpdir: str, payload: dict, proxy=_RESID_PROXY):
    path = Path(tmpdir) / "cf_warm" / f"{cf_warm.exit_key_for_proxy(proxy)}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


class ExitKeyTests(unittest.TestCase):
    def test_extract_sid_from_residential_username(self):
        self.assertEqual(cf_warm.exit_key_for_proxy(_RESID_PROXY), "sid_12554321")

    def test_extract_clash_localhost(self):
        self.assertEqual(
            cf_warm.exit_key_for_proxy("http://127.0.0.1:7897"), "127.0.0.1:7897"
        )

    def test_empty_input(self):
        self.assertEqual(cf_warm.exit_key_for_proxy(""), "")
        self.assertEqual(cf_warm.exit_key_for_proxy(None), "")


class LoadWarmedTests(unittest.TestCase):
    def test_fresh_cache_contains_injectable_cf_bm(self):
        now = time.time()
        with TemporaryDirectory() as tmpdir, patch.object(cf_warm, "_WARM_DIR", Path(tmpdir) / "cf_warm"):
            _write_cache(tmpdir, {
                "exit_key": "sid_12554321",
                "warmed_at": now - 60,
                "cookies": [
                    {"name": "__cf_bm", "value": "v1", "domain": ".auth.openai.com", "path": "/"},
                    {"name": "oai-did", "value": "device", "domain": ".openai.com", "path": "/"},
                ],
            })
            data = cf_warm.load_warmed_exit(_RESID_PROXY)
            self.assertIsNotNone(data)
            names = [c["name"] for c in data["usable_cookies"]]
            self.assertEqual(names, ["__cf_bm"])

    def test_expired_cache_is_rejected(self):
        with TemporaryDirectory() as tmpdir, patch.object(cf_warm, "_WARM_DIR", Path(tmpdir) / "cf_warm"):
            _write_cache(tmpdir, {
                "exit_key": "sid_12554321",
                "warmed_at": time.time() - cf_warm._MAX_AGE_SECONDS - 60,
                "cookies": [{"name": "__cf_bm", "value": "v", "domain": ".auth.openai.com"}],
            })
            self.assertIsNone(cf_warm.load_warmed_exit(_RESID_PROXY))

    def test_exit_mismatch_is_rejected(self):
        with TemporaryDirectory() as tmpdir, patch.object(cf_warm, "_WARM_DIR", Path(tmpdir) / "cf_warm"):
            _write_cache(tmpdir, {
                "exit_key": "sid_99999999",
                "warmed_at": time.time(),
                "cookies": [{"name": "__cf_bm", "value": "v", "domain": ".auth.openai.com"}],
            })
            self.assertIsNone(cf_warm.load_warmed_exit(_RESID_PROXY))

    def test_clash_proxy_filename_is_windows_safe(self):
        """clash 出口键含冒号，缓存文件名必须转成合法字符。"""
        with TemporaryDirectory() as tmpdir, patch.object(cf_warm, "_WARM_DIR", Path(tmpdir) / "cf_warm"):
            proxy = "http://127.0.0.1:7897"
            path = cf_warm.warmed_cache_path(proxy)
            self.assertNotIn(":", path.name)
            self.assertEqual(path, Path(tmpdir) / "cf_warm" / "127.0.0.1_7897.json")
            self.assertEqual(cf_warm.exit_key_for_proxy(proxy), "127.0.0.1:7897")
            # 文件名非法字符替换后 JSON 内仍保留真实 exit_key 用于匹配
            payload = {
                "exit_key": "127.0.0.1:7897",
                "warmed_at": time.time() - 30,
                "cookies": [{"name": "__cf_bm", "value": "v", "domain": ".auth.openai.com"}],
            }
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertIsNotNone(cf_warm.load_warmed_exit(proxy))

    def test_missing_file(self):
        with TemporaryDirectory() as tmpdir, patch.object(cf_warm, "_WARM_DIR", Path(tmpdir) / "cf_warm"):
            self.assertIsNone(cf_warm.load_warmed_exit(_RESID_PROXY))
            self.assertIsNone(cf_warm.load_warmed_exit(None))


class PlatformFieldsTests(unittest.TestCase):
    def test_windows_chrome_ua_fields(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
        fields = cf_warm._platform_fields_from_ua(ua)
        self.assertEqual(fields["user_agent"], ua)
        self.assertEqual(fields["browser_os"], "Windows")
        self.assertEqual(fields["navigator_platform"], "Win32")
        self.assertEqual(fields["chrome_major"], "156")
        self.assertEqual(fields["navigator_vendor"], "Google Inc.")
        self.assertIn('"Google Chrome";v="156"', fields["sec_ch_ua"])
        self.assertEqual(fields["sec_ch_ua_platform"], '"Windows"')

    def test_edge_brand(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0"
        fields = cf_warm._platform_fields_from_ua(ua)
        self.assertIn('"Microsoft Edge";v="156"', fields["sec_ch_ua"])

    def test_unknown_ua_returns_empty(self):
        self.assertEqual(cf_warm._platform_fields_from_ua("curl/8.0"), {})


class ApplyWarmedTests(unittest.TestCase):
    def setUp(self):
        self.warmed = {
            "exit_key": "sid_12554321",
            "age_seconds": 30,
            "usable_cookies": [
                {"name": "__cf_bm", "value": "bm-v1", "domain": ".auth.openai.com", "path": "/"},
            ],
        }

    def test_supports_browser_session_wrapper(self):
        """BrowserSession 的注入目标应是内部 HTTP 客户端的 Cookie Jar。"""
        class _Jar:
            def __init__(self):
                self.items = []

            def set(self, name, value, domain=None, path=None):
                self.items.append((name, value, domain, path))

        class _Session:
            def __init__(self):
                self.cookies = _Jar()

        class _BrowserSession:
            def __init__(self):
                self.session = _Session()
                self.browser_profile = {"user_agent": "old-ua"}

        browser = _BrowserSession()
        self.assertTrue(cf_warm.apply_warmed_cf_cookies(browser, self.warmed))
        self.assertEqual(
            browser.session.cookies.items,
            [("__cf_bm", "bm-v1", ".auth.openai.com", "/")],
        )
        # warmed 带 ua 时应同步画像
        self.warmed["ua"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
        browser2 = _BrowserSession()
        cf_warm.apply_warmed_cf_cookies(browser2, self.warmed)
        self.assertEqual(browser2.browser_profile["chrome_major"], "156")

    def test_injects_into_session_cookie_jar(self):
        class _Jar:
            def __init__(self):
                self.items = []

            def set(self, name, value, domain=None, path=None):
                self.items.append((name, value, domain, path))

        class _Session:
            def __init__(self):
                self.cookies = _Jar()

        session = _Session()
        self.assertTrue(cf_warm.apply_warmed_cf_cookies(session, self.warmed))
        self.assertEqual(
            session.cookies.items,
            [("__cf_bm", "bm-v1", ".auth.openai.com", "/")],
        )

    def test_none_warmed_is_noop(self):
        class _Session:
            cookies = None

        self.assertFalse(cf_warm.apply_warmed_cf_cookies(_Session(), None))
        self.assertFalse(cf_warm.apply_warmed_cf_cookies(_Session(), {"usable_cookies": []}))


if __name__ == "__main__":
    unittest.main()
