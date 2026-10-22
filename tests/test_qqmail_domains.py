# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch

from core import qqmail_client
from core.qqmail_client import email_domains, pick_email_domain


class EmailDomainsTests(unittest.TestCase):
    def test_single_domain(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "mydomain.com", create=True):
            self.assertEqual(email_domains(), ["mydomain.com"])

    def test_multiple_domains_split_by_comma(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "a.com,b.com", create=True):
            self.assertEqual(email_domains(), ["a.com", "b.com"])

    def test_multiple_domains_split_by_semicolon_and_space(self):
        raw = "a.com; b.com\nc.com"
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", raw, create=True):
            self.assertEqual(email_domains(), ["a.com", "b.com", "c.com"])

    def test_deduplicates_and_normalizes(self):
        raw = "A.com, a.com ,@B.com"
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", raw, create=True):
            self.assertEqual(email_domains(), ["a.com", "b.com"])

    def test_ignores_invalid_entries(self):
        raw = "a.com, -, nodot, b.com"
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", raw, create=True):
            self.assertEqual(email_domains(), ["a.com", "b.com"])

    def test_empty(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "", create=True):
            self.assertEqual(email_domains(), [])


class PickEmailDomainTests(unittest.TestCase):
    def test_raises_without_config(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "", create=True):
            with self.assertRaisesRegex(qqmail_client.QQMailClientError, "EMAIL_DOMAIN"):
                pick_email_domain()

    def test_single_domain_returned(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "only.com", create=True):
            self.assertEqual(pick_email_domain(), "only.com")

    def test_picks_least_used_domain(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "a.com,b.com", create=True), \
             patch("core.db.count_domain_emails_by_domain",
                   return_value={"a.com": 5, "b.com": 1}):
            self.assertEqual(pick_email_domain(), "b.com")

    def test_tie_keeps_config_order(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "a.com,b.com", create=True), \
             patch("core.db.count_domain_emails_by_domain",
                   return_value={"a.com": 2, "b.com": 2}):
            self.assertEqual(pick_email_domain(), "a.com")

    def test_unknown_domain_count_is_zero(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "a.com,b.com", create=True), \
             patch("core.db.count_domain_emails_by_domain", return_value={"a.com": 3}):
            self.assertEqual(pick_email_domain(), "b.com")


class PickDomainEmailTests(unittest.TestCase):
    def test_uses_rotated_domain(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "a.com,b.com", create=True), \
             patch("core.db.count_domain_emails_by_domain",
                   return_value={"a.com": 9, "b.com": 0}), \
             patch("core.db.claim_next_domain_email") as claim:
            email = qqmail_client.pick_domain_email()
        self.assertTrue(email.endswith("@b.com"))
        claim.assert_called_once_with(email)

    def test_generated_address_shape(self):
        with patch.object(qqmail_client._email_cfg, "EMAIL_DOMAIN", "a.com", create=True), \
             patch("core.db.claim_next_domain_email"):
            email = qqmail_client.pick_domain_email()
        local, _, domain = email.partition("@")
        self.assertEqual(domain, "a.com")
        self.assertEqual(len(local), 8)
        self.assertTrue(local.isalnum())


if __name__ == "__main__":
    unittest.main()
