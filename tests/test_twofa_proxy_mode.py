# -*- coding: utf-8 -*-
"""TWOFA_PROXY_MODE 解析（core/twofa_service._resolve_twofa_proxy）测试。"""
import unittest
from unittest.mock import patch

import core.twofa_service as twofa_service


class ResolveProxyModeTests(unittest.TestCase):
    def test_plan_check_uses_plan_pool_and_reports_target(self):
        """plan_check 模式从 PLAN_CHECK_PROXY 随机选出口，预热目标=选中的真实出口。"""
        plan_pool = [
            "http://u1:p@us.ipwo.net:7878",
            "http://u2:p@us.ipwo.net:7878",
        ]
        twofa_mod = twofa_service
        with patch.object(twofa_mod._twofa_cfg, "TWOFA_PROXY_MODE", "plan_check"), \
        patch("config.proxy.PLAN_CHECK_PROXY", plan_pool), \
        patch("config.proxy.PLAN_CHECK_UPSTREAM_PROXY", ""):
            transport, relay, source, warm_target = twofa_mod._resolve_twofa_proxy(None)
        self.assertIn(transport, plan_pool)
        self.assertIsNone(relay)
        self.assertEqual(source, "plan_check")
        self.assertIn(warm_target, plan_pool)
        self.assertEqual(warm_target, transport)

    def test_plan_check_falls_back_to_pool_when_plan_pool_empty(self):
        twofa_mod = twofa_service
        with patch.object(twofa_mod._twofa_cfg, "TWOFA_PROXY_MODE", "plan_check"), \
        patch("config.proxy.PLAN_CHECK_PROXY", []), \
        patch("config.proxy.PROXY_POOL", []):
            transport, relay, source, warm_target = twofa_mod._resolve_twofa_proxy(None)
        self.assertEqual(source, "pool_fallback")
        self.assertIsNone(warm_target)

    def test_invalid_mode_raises(self):
        with patch.object(twofa_service._twofa_cfg, "TWOFA_PROXY_MODE", "bogus"):
            with self.assertRaises(ValueError):
                twofa_service._resolve_twofa_proxy(None)

    def test_saved_proxy_reports_warm_target(self):
        saved = "http://127.0.0.1:7897"
        twofa_mod = twofa_service
        with patch.object(twofa_mod._twofa_cfg, "TWOFA_PROXY_MODE", "saved"), \
        patch("config.proxy.PROXY_POOL", []) , \
        patch("config.proxy.PROXY_POOL_UPSTREAM_PROXY", ""):
            transport, relay, source, warm_target = twofa_mod._resolve_twofa_proxy(saved)
        self.assertEqual(source, "saved")
        self.assertEqual(warm_target, saved)
        self.assertEqual(transport, saved)


if __name__ == "__main__":
    unittest.main()
