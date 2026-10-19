#!/usr/bin/env python3
"""Tests for puny_patrol.py — run with: python3 -m unittest discover -s tests"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from puny_patrol import (
    analyze_domain, damerau_levenshtein, decode_domain, label_scripts,
    main, split_registrable, to_skeleton,
)


def verdict(domain):
    r = analyze_domain(domain)
    return r["verdict"], r["score"], r["reasons"]


class TestDecode(unittest.TestCase):
    def test_punycode_decode_lowercase(self):
        raw, uni, flags = decode_domain("XN--NXASMQ6B.example")
        self.assertEqual(uni[0], "βόλοσ")
        self.assertIn("PUNYCODE_INPUT", flags)

    def test_invalid_punycode_handled(self):
        raw, uni, flags = decode_domain("xn--invlid-.com")
        self.assertTrue("INVALID_PUNYCODE" in flags
                        or uni[0] == "xn--invlid-")


class TestScripts(unittest.TestCase):
    def test_pure_latin(self):
        scripts, flags = label_scripts("tokopedia")
        self.assertEqual(scripts, {"LATIN"})
        self.assertEqual(flags, [])

    def test_mixed_latin_cyrillic(self):
        scripts, flags = label_scripts("tokopediа")  # trailing Cyrillic а
        self.assertTrue(any(f.startswith("MIXED_SCRIPT") for f in flags))

    def test_japanese_allowed(self):
        scripts, flags = label_scripts("日本語ドメイン")
        self.assertFalse(any(f.startswith("MIXED_SCRIPT") for f in flags))

    def test_stacked_diacritics(self):
        scripts, flags = label_scripts("á́b")
        self.assertIn("EXCESSIVE_COMBINING_MARKS", flags)


class TestSkeleton(unittest.TestCase):
    def test_dotless_i(self):
        self.assertEqual(to_skeleton("klıkbca"), "klikbca")

    def test_cyrillic_paypal(self):
        # was a vacuous `or True` check; the real skeleton is "paypal".
        self.assertEqual(to_skeleton("раураl"), "paypal")

    def test_leet(self):
        self.assertEqual(to_skeleton("b4nk", apply_leet=True), "bank")

    def test_multi_confusable(self):
        self.assertEqual(to_skeleton("rn"), "m")


class TestRegistrable(unittest.TestCase):
    def test_indonesian_multi_tld(self):
        subs, sld, tld = split_registrable(
            ["portal", "sso", "pajak", "go", "id"])
        self.assertEqual((sld, tld), ("pajak", "go.id"))
        self.assertEqual(subs, ["portal", "sso"])

    def test_simple(self):
        subs, sld, tld = split_registrable(["tokopedia", "com"])
        self.assertEqual((sld, tld), ("tokopedia", "com"))


class TestDistance(unittest.TestCase):
    def test_transposition(self):
        self.assertEqual(damerau_levenshtein("mandiri", "madniri"), 1)

    def test_identical(self):
        self.assertEqual(damerau_levenshtein("tokopedia", "tokopedia"), 0)

    def test_empty(self):
        self.assertEqual(damerau_levenshtein("abc", ""), 3)


class TestClean(unittest.TestCase):
    def test_official_short(self):
        v, s, r = verdict("bsi.co.id")
        self.assertEqual((v, s), ("CLEAN", 0))

    def test_bni_despite_dist1(self):
        v, s, r = verdict("bni.co.id")
        self.assertEqual(v, "CLEAN")

    def test_official_subdomain(self):
        v, s, r = verdict("portal.sso.pajak.go.id")
        self.assertEqual(v, "CLEAN")
        self.assertIn("OFFICIAL_SUBDOMAIN", r)

    def test_hyphenated_official(self):
        v, s, r = verdict("bpjs-kesehatan.go.id")
        self.assertEqual(v, "CLEAN")

    def test_unrelated_ascii(self):
        v, s, r = verdict("google.com")
        self.assertEqual(v, "CLEAN")

    def test_single_script_han(self):
        v, s, r = verdict("中国.id")
        self.assertEqual(v, "CLEAN")

    def test_hyphenated_ascii(self):
        v, s, r = verdict("kemenkeu-ri.go.id")
        self.assertEqual(v, "CLEAN")


class TestHomograph(unittest.TestCase):
    def test_mixed_script(self):
        v, s, r = verdict("tokopediа.com")  # Cyrillic а
        self.assertEqual(v, "MALICIOUS")
        self.assertGreaterEqual(s, 60)
        self.assertTrue(any(x.startswith("SKELETON_HOMOGRAPH") for x in r))

    def test_whole_script_confusable(self):
        v, s, r = verdict("klıkbca.co.id")  # dotless ı
        self.assertEqual(v, "MALICIOUS")

    def test_full_cyrillic(self):
        v, s, r = verdict("ѕһорее.co.id")
        self.assertEqual(v, "MALICIOUS")


class TestTyposquat(unittest.TestCase):
    def test_leet_hyphen(self):
        v, s, r = verdict("b4nk-mandiri.co.id")
        self.assertEqual(v, "MALICIOUS")
        self.assertTrue(any(x.startswith("LEET_HYPHEN_SPOOF") for x in r))

    def test_leet_digit(self):
        v, s, r = verdict("telkomse1.com")
        self.assertEqual(v, "MALICIOUS")

    def test_brand_combo(self):
        v, s, r = verdict("bca-login.com")
        self.assertEqual(v, "SUSPICIOUS")
        self.assertTrue(any(x.startswith("BRAND_COMBO") for x in r))

    def test_brand_combo_unexpected_tld(self):
        v, s, r = verdict("klikbca-indonesia.com")
        self.assertEqual(v, "SUSPICIOUS")

    def test_unexpected_tld(self):
        v, s, r = verdict("shopee.net")
        self.assertEqual(v, "SUSPICIOUS")
        self.assertTrue(any(x.startswith("UNEXPECTED_TLD") for x in r))

    def test_dist1_typosquat(self):
        v, s, r = verdict("tokopedai.com")
        self.assertEqual(v, "MALICIOUS")
        self.assertTrue(any(x.startswith("TYPOSQUAT_DIST1") for x in r))


class TestSubdomainBrand(unittest.TestCase):
    def test_phish_subdomain(self):
        v, s, r = verdict("klikbca.co.id.evil.com")
        self.assertEqual(v, "SUSPICIOUS")
        self.assertTrue(any(x.startswith("SUBDOMAIN_BRAND") for x in r))

    def test_short_subdomain(self):
        v, s, r = verdict("bca.evil.com")
        self.assertEqual(v, "SUSPICIOUS")

    def test_official_subdomain_still_clean(self):
        v, s, r = verdict("mail.klikbca.co.id")
        self.assertEqual(v, "CLEAN")

    def test_innocent_subdomain_clean(self):
        v, s, r = verdict("blog.example.com")
        self.assertEqual(v, "CLEAN")


class TestDeterminism(unittest.TestCase):
    def test_brand_reports_stable_across_hash_seeds(self):
        # BRAND_TLDS is a set: iteration must not leak into output.
        code = ("from puny_patrol import analyze_domain;"
                "print(analyze_domain('bca-bri-tokopedia.com')['reasons'])")
        outs = set()
        for seed in ("0", "1", "42"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = subprocess.run([sys.executable, "-c", code],
                               capture_output=True, text=True, env=env)
            self.assertEqual(p.returncode, 0, msg=p.stderr)
            outs.add(p.stdout.strip())
        self.assertEqual(len(outs), 1, msg="nondeterministic output: %s" % outs)


class TestUrlAndPunycode(unittest.TestCase):
    def test_url_input(self):
        v, s, r = verdict("https://tokopediа.com/login?x=1")
        self.assertEqual(v, "MALICIOUS")

    def test_broken_punycode(self):
        v, s, r = verdict("xn--invlid-.com")
        self.assertEqual(v, "SUSPICIOUS")
        self.assertIn("INVALID_PUNYCODE", r)

    def test_garbage_punycode(self):
        v, s, r = verdict("xn--80ak6aa92bd.com")
        self.assertEqual(v, "SUSPICIOUS")
        self.assertIn("INVALID_PUNYCODE", r)


class TestCli(unittest.TestCase):
    def test_table_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["tokopediа.com", "google.com"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("MALICIOUS", out)
        self.assertIn("CLEAN", out)

    def test_json_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["--json", "bca-login.com"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]["verdict"], "SUSPICIOUS")

    def test_min_score(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["--min-score", "60", "bca-login.com", "tokopediа.com"])
        out = buf.getvalue()
        self.assertNotIn("bca-login.com", out)
        self.assertIn("tokopediа.com", out)

    def test_file_input(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as f:
            f.write("# comment\n\ngoogle.com\ntokopediа.com\n")
            path = f.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--file", path])
            self.assertEqual(rc, 0)
            self.assertIn("2 domain(s) checked", buf.getvalue())
        finally:
            os.unlink(path)

    def test_empty_input(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["   "])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()


class TestInvariants(unittest.TestCase):
    def test_score_always_capped(self):
        # Regression: SINGLE_SCRIPT_NON_LATIN early return bypassed the
        # min(score, 100) cap (fuzz found score=130 with verdict CLEAN).
        r = analyze_domain("α-b9.9\u200bа0bו@ו1@9α中.αа")
        self.assertLessEqual(r["score"], 100)
        self.assertGreaterEqual(r["score"], 0)

    def test_verdict_matches_score(self):
        for d in ["google.com", "tokopediа.com", "bca-login.com",
                  "xn--80ak6aa92bd.com", "klikbca.co.id.evil.com"]:
            r = analyze_domain(d)
            if r["score"] >= 60:
                self.assertEqual(r["verdict"], "MALICIOUS", msg=d)
            elif r["score"] >= 25:
                self.assertEqual(r["verdict"], "SUSPICIOUS", msg=d)
            else:
                self.assertEqual(r["verdict"], "CLEAN", msg=d)

    def test_fuzz_no_crash_invariants(self):
        import random
        random.seed(20261020)
        alpha = "abcXYZ019.-_"
        uni = ["\u0430", "\u03b1", "\u05d5", "\u4e2d", "\u0301",
               "\u200b", "xn--", "@", "/", ":", " "]
        for _ in range(1500):
            s = "".join(random.choice(alpha + "".join(uni))
                        for _ in range(random.randint(0, 60)))
            r = analyze_domain(s)
            if r is None:
                continue
            self.assertIn(r["verdict"], ("CLEAN", "SUSPICIOUS", "MALICIOUS"))
            self.assertGreaterEqual(r["score"], 0)
            self.assertLessEqual(r["score"], 100)
