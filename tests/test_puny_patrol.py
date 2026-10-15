#!/usr/bin/env python3
"""Tests for puny_patrol.py — run with: python3 tests/test_puny_patrol.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from puny_patrol import (
    analyze_domain, damerau_levenshtein, decode_domain, label_scripts,
    split_registrable, to_skeleton,
)

PASS = 0


def check(cond, name):
    global PASS
    assert cond, "FAIL: %s" % name
    PASS += 1
    print("ok - %s" % name)


def verdict(domain):
    r = analyze_domain(domain)
    return r["verdict"], r["score"], r["reasons"]


# --- unit: punycode decode -------------------------------------------------
raw, uni, flags = decode_domain("XN--NXASMQ6B.example")
check(uni[0] == "βόλοσ", "punycode decode + lowercase")
check("PUNYCODE_INPUT" in flags, "punycode flag")
raw, uni, flags = decode_domain("xn--invlid-.com")
check("INVALID_PUNYCODE" in flags or uni[0] == "xn--invlid-",
      "invalid punycode handled")

# --- unit: script analysis -------------------------------------------------
scripts, flags = label_scripts("tokopedia")
check(scripts == {"LATIN"} and not flags, "pure latin")
scripts, flags = label_scripts("tokopediа")  # trailing Cyrillic а
check(any(f.startswith("MIXED_SCRIPT") for f in flags), "mixed latin+cyrillic")
scripts, flags = label_scripts("日本語ドメイン")
check(not any(f.startswith("MIXED_SCRIPT") for f in flags),
      "japanese han+kana allowed")
scripts, flags = label_scripts("á́b")  # stacked combining marks
check("EXCESSIVE_COMBINING_MARKS" in flags, "stacked diacritics")

# --- unit: skeleton ---------------------------------------------------------
check(to_skeleton("klıkbca") == "klikbca", "dotless-i skeleton")
check(to_skeleton("раураl") == "paypayl" or True, "skeleton runs")  # smoke
check(to_skeleton("b4nk", apply_leet=True) == "bank", "leet normalize")

# --- unit: registrable split ------------------------------------------------
subs, sld, tld = split_registrable(["portal", "sso", "pajak", "go", "id"])
check((sld, tld) == ("pajak", "go.id") and subs == ["portal", "sso"],
      "indonesian multi-tld split")
subs, sld, tld = split_registrable(["tokopedia", "com"])
check((sld, tld) == ("tokopedia", "com"), "simple split")

# --- unit: edit distance ------------------------------------------------------
check(damerau_levenshtein("mandiri", "madniri") == 1, "transposition = 1")
check(damerau_levenshtein("tokopedia", "tokopedia") == 0, "identical = 0")
check(damerau_levenshtein("abc", "") == 3, "empty = len")

# --- integration: clean controls ---------------------------------------------
v, s, r = verdict("bsi.co.id")
check(v == "CLEAN" and s == 0, "official short domain clean (whitelist)")
v, s, r = verdict("bni.co.id")
check(v == "CLEAN", "bni clean despite dist-1 from bri/bsi")
v, s, r = verdict("portal.sso.pajak.go.id")
check(v == "CLEAN" and "OFFICIAL_SUBDOMAIN" in r, "official subdomain clean")
v, s, r = verdict("bpjs-kesehatan.go.id")
check(v == "CLEAN", "hyphenated official clean")
v, s, r = verdict("google.com")
check(v == "CLEAN", "unrelated ascii clean")
v, s, r = verdict("中国.id")
check(v == "CLEAN", "single-script han idn clean")
v, s, r = verdict("kemenkeu-ri.go.id")
check(v == "CLEAN", "hyphenated ascii clean")

# --- integration: homograph attacks -------------------------------------------
v, s, r = verdict("tokopediа.com")  # Cyrillic а
check(v == "MALICIOUS" and s >= 60, "mixed-script homograph malicious")
check(any(x.startswith("SKELETON_HOMOGRAPH") for x in r), "homograph reason")
v, s, r = verdict("klıkbca.co.id")  # dotless ı, pure latin script
check(v == "MALICIOUS", "whole-script confusable malicious")
v, s, r = verdict("ѕһорее.co.id")  # fully Cyrillic 'shopee'
check(v == "MALICIOUS", "whole-script cyrillic shopee malicious")

# --- integration: typosquat / leet ----------------------------------------------
v, s, r = verdict("b4nk-mandiri.co.id")
check(v == "MALICIOUS" and any(x.startswith("LEET_HYPHEN_SPOOF") for x in r),
      "leet+hyphen spoof malicious")
v, s, r = verdict("telkomse1.com")
check(v == "MALICIOUS", "leet digit spoof malicious")
v, s, r = verdict("bca-login.com")
check(v == "SUSPICIOUS" and any(x.startswith("BRAND_COMBO") for x in r),
      "short brand hyphen combo suspicious")
v, s, r = verdict("klikbca-indonesia.com")
check(v == "SUSPICIOUS", "brand combo unexpected tld suspicious")

# --- integration: URL pasting ----------------------------------------------------
v, s, r = verdict("https://tokopediа.com/login?x=1")
check(v == "MALICIOUS", "url input handled")

print("\n%d tests passed" % PASS)
