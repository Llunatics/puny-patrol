#!/usr/bin/env python3
"""Tests for puny_patrol.py watchdog mode — run with: python3 -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from puny_patrol import (
    WatchError, brand_sld, fetch_ct_names, run_watch, watch_relevance,
)

BRANDS = ["klikbca.co.id", "tokopedia.com"]


def relevance(name, brands=BRANDS):
    hit = watch_relevance(name, brands)
    return hit[1] if hit else None


class TestBrandSld(unittest.TestCase):
    def test_multi_level_tld(self):
        self.assertEqual(brand_sld("klikbca.co.id"), "klikbca")

    def test_plain_tld(self):
        self.assertEqual(brand_sld("tokopedia.com"), "tokopedia")

    def test_url_input(self):
        self.assertEqual(brand_sld("https://login.klikbca.co.id/x"), "klikbca")


class TestWatchRelevance(unittest.TestCase):
    def test_exact_brand_other_tld(self):
        self.assertEqual(relevance("klikbca.net"), "EXACT_BRAND_OTHER_TLD")

    def test_homograph_cyrillic(self):
        self.assertEqual(relevance("klіkbca.co.id"), "SKELETON_HOMOGRAPH")

    def test_leet_spoof(self):
        self.assertEqual(relevance("klikbc4.com"), "LEET_HYPHEN_SPOOF")

    def test_dist1(self):
        self.assertEqual(relevance("klikbcb.co.id"), "TYPOSQUAT_DIST1")

    def test_dist2_long_brand(self):
        self.assertEqual(relevance("tokopedai.com"), "TYPOSQUAT_DIST1")
        self.assertEqual(relevance("tokopida.com"), "TYPOSQUAT_DIST2")

    def test_brand_combo_token(self):
        self.assertEqual(relevance("klikbca-login.com"), "BRAND_COMBO")

    def test_subdomain_brand(self):
        self.assertEqual(relevance("klikbca.co.id.evil.com"), "SUBDOMAIN_BRAND")

    def test_own_domain_skipped(self):
        self.assertIsNone(relevance("klikbca.co.id"))
        self.assertIsNone(relevance("login.klikbca.co.id"))

    def test_unrelated_skipped(self):
        self.assertIsNone(relevance("random-shop.com"))
        self.assertIsNone(relevance("google.com"))

    def test_short_brand_no_dist_false_positive(self):
        # 'ovo' vs 'ova' is distance 1 but too short to trust.
        self.assertIsNone(relevance("ova.id", ["ovo.id"]))
        # ...yet an exact SLD on another TLD still alerts.
        self.assertEqual(relevance("ovo.net", ["ovo.id"]),
                         "EXACT_BRAND_OTHER_TLD")

    def test_non_catalog_brand_protected(self):
        # Watchdog relevance is brand-relative, not catalog-relative.
        self.assertEqual(relevance("mybrandd.com", ["mybrand.com"]),
                         "TYPOSQUAT_DIST1")


class TestFetchCtNames(unittest.TestCase):
    def test_wildcard_dedupe_multiline(self):
        data = [
            {"name_value": "*.klikbca.co.id\nklikbca.co.id"},
            {"name_value": "KLIKBCA.CO.ID."},
            {"name_value": "evil-klikbca.com"},
            {"other": "ignored"},
        ]
        names = fetch_ct_names("klikbca.co.id",
                               opener=lambda url: data)
        self.assertEqual(names, ["evil-klikbca.com", "klikbca.co.id"])

    def test_default_template_searches_sld_substring(self):
        seen = {}

        def opener(url):
            seen["url"] = url
            return []
        fetch_ct_names("tokopedia.com", opener=opener)
        # Substring query: catches other-TLD copies and brand combos,
        # not just subdomains of the brand itself.
        self.assertIn("q=%25.tokopedia%25", seen["url"])

    def test_unparseable_brand_with_sld_template_errors(self):
        with self.assertRaises(WatchError):
            fetch_ct_names("not a domain at all !!!",
                           url_template="https://x/?q=%25.{sld}%25",
                           opener=lambda url: [])

    def test_opener_error_becomes_watch_error(self):
        with self.assertRaises(WatchError):
            fetch_ct_names("klikbca.co.id",
                           opener=lambda url: (_ for _ in ()).throw(
                               RuntimeError("boom")))


class TestRunWatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "state.json")

    def tearDown(self):
        self.tmp.cleanup()

    def fake_feed(self, mapping):
        def fetcher(brand):
            return sorted(mapping.get(brand, []))
        return fetcher

    def test_first_run_alerts_second_run_quiet(self):
        feed = {"klikbca.co.id": ["klikbca.co.id", "klikbcb.co.id",
                                  "random-shop.com"]}
        alerts = run_watch(["klikbca.co.id"], self.state,
                           fetcher=self.fake_feed(feed))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["name"], "klikbcb.co.id")
        self.assertEqual(alerts[0]["reason"], "TYPOSQUAT_DIST1")
        # Repeat with identical feed: nothing new, no re-alert.
        self.assertEqual(run_watch(["klikbca.co.id"], self.state,
                                   fetcher=self.fake_feed(feed)), [])
        # One genuinely new typosquat appears: exactly one alert.
        feed["klikbca.co.id"].append("klikbca-login.com")
        alerts = run_watch(["klikbca.co.id"], self.state,
                           fetcher=self.fake_feed(feed))
        self.assertEqual([a["name"] for a in alerts], ["klikbca-login.com"])
        self.assertEqual(alerts[0]["reason"], "BRAND_COMBO")

    def test_state_file_written_and_scoped_per_brand(self):
        feed = {"klikbca.co.id": ["klikbcb.co.id"],
                "tokopedia.com": ["tokopediaa.com"]}
        run_watch(["klikbca.co.id", "tokopedia.com"], self.state,
                  fetcher=self.fake_feed(feed))
        with open(self.state, encoding="utf-8") as fh:
            state = json.load(fh)
        self.assertIn("klikbcb.co.id", state["brands"]["klikbca.co.id"])
        self.assertIn("tokopediaa.com", state["brands"]["tokopedia.com"])
        self.assertIn("last_check", state)

    def test_partial_failure_keeps_good_brand_state(self):
        def fetcher(brand):
            if brand == "tokopedia.com":
                raise WatchError("down")
            return ["klikbcb.co.id"]
        alerts = run_watch(["klikbca.co.id", "tokopedia.com"], self.state,
                           fetcher=fetcher)
        self.assertEqual(len(alerts), 1)
        with open(self.state, encoding="utf-8") as fh:
            state = json.load(fh)
        self.assertIn("klikbca.co.id", state["brands"])
        self.assertNotIn("tokopedia.com", state["brands"])

    def test_total_failure_raises_and_writes_nothing(self):
        def fetcher(brand):
            raise WatchError("down")
        with self.assertRaises(WatchError):
            run_watch(["klikbca.co.id"], self.state, fetcher=fetcher)
        self.assertFalse(os.path.exists(self.state))

    def test_no_brands_is_usage_error(self):
        with self.assertRaises(WatchError):
            run_watch([], self.state, fetcher=self.fake_feed({}))


if __name__ == "__main__":
    unittest.main()
