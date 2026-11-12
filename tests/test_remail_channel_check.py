# -*- coding: utf-8 -*-
"""Remail 通道体检（tools/remail_channel_check.py + core 探测函数）离线测试。"""
import unittest
from unittest.mock import MagicMock, patch

import core.remail_client as remail
from tools import remail_channel_check as tool


class EvaluateOrderDeadTests(unittest.TestCase):
    def test_final_status_is_dead(self):
        self.assertIn("status=failed", remail.evaluate_order_dead({"status": "failed"}) or "")
        self.assertIn("status=refunded", remail.evaluate_order_dead({"status": "refunded"}) or "")
        self.assertIn("status=closed", remail.evaluate_order_dead({"status": "closed"}) or "")

    def test_active_purchase_order_alive(self):
        self.assertIsNone(remail.evaluate_order_dead({
            "status": "active", "serviceMode": "purchase",
            "expiresAt": "2999-01-01T00:00:00Z",
        }))

    def test_code_order_expired_by_expires_at(self):
        self.assertIn("code 模式订单已过期", remail.evaluate_order_dead({
            "status": "active", "serviceMode": "code",
            "expiresAt": "2026-08-01T00:00:00Z",
        }) or "")

    def test_code_order_not_expired_alive(self):
        self.assertIsNone(remail.evaluate_order_dead({
            "status": "active", "serviceMode": "code",
            "expiresAt": "2999-01-01T00:00:00Z",
        }))


class ProbePickupTests(unittest.TestCase):
    def test_server_404_is_dead(self):
        with patch.object(remail, "_request", side_effect=remail.RemailError(
                "Remail 请求失败 (GET /v1/pickup): HTTP 404; order not found")):
            result = remail.probe_pickup_channel("a@b.c", "tok")
        self.assertTrue(result["dead"])
        self.assertFalse(result["ok"])

    def test_server_5xx_is_not_dead(self):
        with patch.object(remail, "_request", side_effect=remail.RemailError(
                "Remail 请求失败 (GET /v1/pickup): HTTP 500; internal error")):
            result = remail.probe_pickup_channel("a@b.c", "tok")
        self.assertFalse(result["dead"])
        self.assertFalse(result["ok"])

    def test_network_error_is_not_dead(self):
        with patch.object(remail, "_request", side_effect=OSError("connection reset")):
            result = remail.probe_pickup_channel("a@b.c", "tok")
        self.assertFalse(result["dead"])

    def test_success_is_alive(self):
        with patch.object(remail, "_request", return_value={"items": []}):
            result = remail.probe_pickup_channel("a@b.c", "tok")
        self.assertTrue(result["ok"])
        self.assertFalse(result["dead"])

    def test_missing_token_is_dead(self):
        result = remail.probe_pickup_channel("a@b.c", "")
        self.assertTrue(result["dead"])


class CheckAccountTests(unittest.TestCase):
    def _account(self):
        return {"id": 7, "email": "x@outlook.com", "email_source": "remail"}

    def test_restore_none_means_dead(self):
        with patch.object(tool, "restore_account_context", return_value=None):
            result = tool.check_account(self._account())
        self.assertEqual(result["state"], "dead")

    def test_final_order_detail_is_dead(self):
        ctx = MagicMock()
        ctx.order_no = "R123"
        ctx.service_token = "tok"
        with patch.object(tool, "restore_account_context", return_value=ctx), \
             patch.object(tool, "get_order_detail", return_value={"status": "closed"}):
            result = tool.check_account(self._account())
        self.assertEqual(result["state"], "dead")
        self.assertIn("status=closed", result["reason"])

    def test_pickup_ambiguous_error_is_unknown(self):
        ctx = MagicMock()
        ctx.order_no = "R123"
        ctx.service_token = "tok"
        with patch.object(tool, "restore_account_context", return_value=ctx), \
             patch.object(tool, "get_order_detail", return_value={"status": "active", "serviceMode": "purchase"}), \
             patch.object(tool, "probe_pickup_channel", return_value={"ok": False, "dead": False, "error": "500"}):
            result = tool.check_account(self._account())
        self.assertEqual(result["state"], "unknown")

    def test_pickup_ok_is_alive(self):
        ctx = MagicMock()
        ctx.order_no = "R123"
        ctx.service_token = "tok"
        with patch.object(tool, "restore_account_context", return_value=ctx), \
             patch.object(tool, "get_order_detail", return_value={"status": "active", "serviceMode": "purchase"}), \
             patch.object(tool, "probe_pickup_channel", return_value={"ok": True, "dead": False, "error": None}):
            result = tool.check_account(self._account())
        self.assertEqual(result["state"], "alive")


if __name__ == "__main__":
    unittest.main()
