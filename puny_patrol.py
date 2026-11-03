#!/usr/bin/env python3
"""puny-patrol: detect IDN homograph & typosquatting attacks on domain names.

Reads domain names (one per line) from a file or stdin, analyzes each for
signs of impersonation attacks, and prints a verdict table (or JSON):

  * IDN homograph  — Punycode / mixed-script / confusable-Unicode spoofs
                     (e.g. Cyrillic 'а' standing in for Latin 'a')
  * Typosquat      — edit-distance / leetspeak / hyphen tricks against a
                     bundled catalog of popular Indonesian domains
                     (banks, e-commerce, gov, telco)

Verdicts: CLEAN (0-24), SUSPICIOUS (25-59), MALICIOUS (60-100).

Watchdog mode (--watch) polls Certificate Transparency logs (crt.sh)
for newly issued certificates resembling your own brands and alerts on
first sight; state is kept in a JSON file so repeats stay quiet.

Stdlib only. Exit codes: 0 = success, 1 = input/usage error,
2 = watchdog usage/fetch/state error, 10 = watchdog found new alerts.
Ctrl-C exits gracefully (130).
"""

import argparse
import json
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from encodings import idna

# Clean exit on broken pipes (e.g. `puny_patrol.py list.txt | head`).
try:
    from signal import SIG_DFL, SIGPIPE, signal
    signal(SIGPIPE, SIG_DFL)
except Exception:
    pass

VERSION = "1.2.1"

# ---------------------------------------------------------------------------
# Confusable skeleton map (subset of Unicode confusables, UTS #39)
# ---------------------------------------------------------------------------
# Maps non-ASCII lookalikes to their ASCII base. Curated for IDN attack
# relevance (Cyrillic, Greek, Armenian, Latin-extended); NOT exhaustive.
# Multi-character sequences ('rn' -> 'm') are handled separately.
CONFUSABLE_MAP = {
    # Cyrillic small letters
    'а': 'a',  # U+0430
    'е': 'e',  # U+0435
    'о': 'o',  # U+043E
    'р': 'p',  # U+0440
    'с': 'c',  # U+0441
    'у': 'y',  # U+0443
    'х': 'x',  # U+0445
    'ѕ': 's',  # U+0455 DZE
    'і': 'i',  # U+0456 BYELORUSSIAN-UKRAINIAN I
    'ј': 'j',  # U+0458 JE
    'һ': 'h',  # U+04BB SHHA
    'ԁ': 'd',  # U+0501 KOMI DE
    'к': 'k',  # U+043A KA
    'м': 'm',  # U+043C EM
    'н': 'h',  # U+043D EN
    'в': 'b',  # U+0432 VE
    # Greek small letters
    'α': 'a',  # U+03B1
    'ε': 'e',  # U+03B5
    'ι': 'i',  # U+03B9
    'ο': 'o',  # U+03BF
    'ρ': 'p',  # U+03C1
    'υ': 'u',  # U+03C5
    'ν': 'v',  # U+03BD
    'κ': 'k',  # U+03BA
    'μ': 'u',  # U+03BC MU
    'ω': 'w',  # U+03C9 OMEGA
    # Armenian small letters
    'օ': 'o',  # U+0585 OH
    'ո': 'n',  # U+0578 VO
    # Latin extended / IPA lookalikes
    'ı': 'i',  # U+0131 DOTLESS I
    'ɡ': 'g',  # U+0261 SCRIPT SMALL G
    'ɪ': 'i',  # U+026A SMALL CAPITAL I
}

# Multi-character visual confusables, applied before single-char mapping.
MULTI_CONFUSABLES = (
    ('rn', 'm'),
    ('vv', 'w'),
    ('cl', 'd'),
)

# Leetspeak normalization for typosquat detection.
LEET_MAP = str.maketrans({
    '0': 'o', '1': 'l', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b',
})

# ---------------------------------------------------------------------------
# Protected brand catalog (popular Indonesian domains)
# ---------------------------------------------------------------------------
# Official domains analysts care about. An exact registrable-domain match is
# CLEAN; everything else is compared against the SLD column.
OFFICIAL_DOMAINS = {
    # Banking & fintech
    "klikbca.co.id", "bca.co.id", "bankmandiri.co.id", "bri.co.id",
    "bni.co.id", "bsi.co.id", "cimbniaga.co.id", "danamon.co.id",
    "permata.co.id", "btn.co.id", "gopay.co.id", "ovo.id", "dana.id",
    "linkaja.id", "flip.id",
    # E-commerce & travel
    "tokopedia.com", "shopee.co.id", "bukalapak.com", "blibli.com",
    "lazada.co.id", "traveloka.com", "tiket.com", "gojek.com",
    "grab.com", "halodoc.com",
    # Government & BUMN
    "pajak.go.id", "bpjs-kesehatan.go.id", "bpjsketenagakerjaan.go.id",
    "kemkes.go.id", "kominfo.go.id", "polri.go.id", "ojk.go.id",
    "bi.go.id", "pedulilindungi.id",
    # Telco & utilities
    "telkomsel.com", "indosatooredoo.com", "xl.co.id", "smartfren.com",
    "pln.co.id", "pertamina.com",
}

# Multi-level public suffixes that must be stripped before SLD comparison
# (Indonesian second-level ccTLDs + a few common ones).
MULTI_TLDS = {
    "co.id", "go.id", "ac.id", "or.id", "web.id", "sch.id",
    "mil.id", "net.id", "desa.id", "my.id", "biz.id",
    "co.uk", "com.sg", "co.jp",
}

# Official TLD(s) per protected SLD, for cross-TLD spoof detection.
BRAND_TLDS = {}
for _d in OFFICIAL_DOMAINS:
    _parts = _d.rsplit(".", 2)
    if len(_parts) == 3 and f"{_parts[1]}.{_parts[2]}" in MULTI_TLDS:
        _sld, _tld = _parts[0], f"{_parts[1]}.{_parts[2]}"
    else:
        _sld, _tld = _parts[-2], _parts[-1]
    BRAND_TLDS.setdefault(_sld, set()).add(_tld)
del _d, _parts, _sld, _tld

# Dots that can separate labels (ASCII + IDNA-valid alternatives).
LABEL_SEP = re.compile(r"[.\u3002\uff0e\uff61]")

# Strips scheme / userinfo / port / path from pasted URLs.
URL_HOST = re.compile(
    r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?"  # scheme
    r"(?:[^@/]+@)?"                        # userinfo
    r"([^/:?#\s]+)"                        # host
)

# ---------------------------------------------------------------------------
# Punycode / normalization
# ---------------------------------------------------------------------------

def decode_domain(domain):
    """Split into labels, decode Punycode, NFKC-normalize.

    Returns (raw_labels, unicode_labels, flags).
    """
    raw_labels = [l for l in LABEL_SEP.split(domain.strip().lower()) if l != ""]
    uni_labels, flags = [], []
    for label in raw_labels:
        if label.startswith("xn--"):
            try:
                decoded = unicodedata.normalize("NFKC", idna.ToUnicode(label))
                uni_labels.append(decoded)
                flags.append("PUNYCODE_INPUT")
            except (UnicodeError, ValueError):
                uni_labels.append(label)
                flags.append("INVALID_PUNYCODE")
        else:
            uni_labels.append(unicodedata.normalize("NFKC", label))
    return raw_labels, uni_labels, sorted(set(flags))


# ---------------------------------------------------------------------------
# Script analysis
# ---------------------------------------------------------------------------

KNOWN_SCRIPTS = {
    "LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "HAN",
    "HIRAGANA", "KATAKANA", "HANGUL", "THAI", "DEVANAGARI", "ARMENIAN",
}


def char_script(ch):
    """Best-effort Unicode script of one character (stdlib only)."""
    cat = unicodedata.category(ch)
    if cat in ("Mn", "Mc", "Me"):
        return "INHERITED"
    if cat[0] in "NPSZ" or ch == "-":
        return "COMMON"
    name = unicodedata.name(ch, "")
    if not name:
        return "UNKNOWN"
    first = name.split(" ", 1)[0]
    if first in ("CJK", "IDEOGRAPHIC"):
        return "HAN"
    return first if first in KNOWN_SCRIPTS else first


def label_scripts(label):
    """Return (set_of_scripts, flags) for one label."""
    scripts, flags = set(), []
    combining_run = 0
    for ch in label:
        script = char_script(ch)
        if script == "UNKNOWN":
            flags.append("UNASSIGNED_CHAR")
        elif script == "INHERITED":
            combining_run += 1
            if combining_run > 1:
                flags.append("EXCESSIVE_COMBINING_MARKS")
        elif script == "COMMON":
            combining_run = 0
        else:
            combining_run = 0
            scripts.add(script)
    # Japanese (Kanji + Kana) and Korean (Hanja + Hangul) legitimately mix.
    if scripts <= {"HAN", "HIRAGANA", "KATAKANA"} or scripts <= {"HAN", "HANGUL"}:
        return scripts, flags
    if len(scripts) > 1:
        flags.append("MIXED_SCRIPT(%s)" % "+".join(sorted(scripts)))
    return scripts, flags


# ---------------------------------------------------------------------------
# Skeleton / confusables
# ---------------------------------------------------------------------------

def to_skeleton(label, apply_leet=False):
    """Reduce a label to its ASCII visual skeleton."""
    nfd = unicodedata.normalize("NFD", label)
    stripped = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    for seq, rep in MULTI_CONFUSABLES:
        stripped = stripped.replace(seq, rep)
    skel = "".join(CONFUSABLE_MAP.get(c, c) for c in stripped)
    if apply_leet:
        skel = skel.translate(LEET_MAP)
    return skel


# ---------------------------------------------------------------------------
# Registrable domain
# ---------------------------------------------------------------------------

def split_registrable(labels):
    """Split labels into (subdomains, sld, tld)."""
    if len(labels) < 2:
        return [], labels[0] if labels else "", ""
    if len(labels) >= 3 and f"{labels[-2]}.{labels[-1]}" in MULTI_TLDS:
        return labels[:-3], labels[-3], f"{labels[-2]}.{labels[-1]}"
    return labels[:-2], labels[-2], labels[-1]


# ---------------------------------------------------------------------------
# Edit distance (Damerau-Levenshtein, optimal string alignment)
# ---------------------------------------------------------------------------

def damerau_levenshtein(a, b):
    """Edit distance with adjacent transposition = 1. Stdlib only."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    prev2 = None
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]

# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

# Score weights. Tuned so a single strong signal (homograph, leet-spoof)
# lands in MALICIOUS territory while weak hints stay SUSPICIOUS.
W_MIXED_SCRIPT = 65
W_SKELETON_HOMOGRAPH = 85
W_LEET_HYPHEN_SPOOF = 75
W_DIST1 = 70
W_DIST2 = 35
W_UNEXPECTED_TLD = 45
W_BRAND_COMBO = 40
W_COMBINING_MARKS = 40
W_UNASSIGNED_CHAR = 50
# Invalid Punycode: a broken xn-- label can never be a real registered
# domain (registries validate IDNA) — worth flagging in triage even when
# no other signal fires.
W_INVALID_PUNYCODE = 30


def analyze_domain(raw):
    """Analyze one domain. Returns dict(input, unicode, verdict, score, reasons)."""
    m = URL_HOST.match(raw.strip())
    host = m.group(1) if m else raw.strip()
    host = host.rstrip(".")
    if not host:
        return None

    _raw_labels, labels, flags = decode_domain(host)
    reasons = list(flags)
    score = 0
    for f in flags:
        if f == "INVALID_PUNYCODE":
            score += W_INVALID_PUNYCODE

    # Per-label script analysis (covers subdomains too).
    scripts_per_label = []
    for label in labels:
        scripts, sflags = label_scripts(label)
        scripts_per_label.append(scripts)
        for f in sflags:
            reasons.append(f)
            if f.startswith("MIXED_SCRIPT"):
                score += W_MIXED_SCRIPT
            elif f == "EXCESSIVE_COMBINING_MARKS":
                score += W_COMBINING_MARKS
            elif f == "UNASSIGNED_CHAR":
                score += W_UNASSIGNED_CHAR

    subdomains, sld, tld = split_registrable(labels)
    registrable = f"{sld}.{tld}" if tld else sld

    # Exact official domain (incl. legitimate subdomains under it) = CLEAN,
    # unless a label itself carries script-level spoofing.
    spoofy = any(f.startswith("MIXED_SCRIPT") or f in
                 ("EXCESSIVE_COMBINING_MARKS", "UNASSIGNED_CHAR")
                 for f in reasons)
    if registrable in OFFICIAL_DOMAINS and not spoofy:
        if subdomains:
            reasons.append("OFFICIAL_SUBDOMAIN")
        else:
            reasons.append("OFFICIAL_TARGET_MATCH")
        return _result(raw, labels, "CLEAN", 0, reasons)

    # Single-script non-Latin IDN that doesn't impersonate a Latin brand.
    all_scripts = set().union(*scripts_per_label) if scripts_per_label else set()
    if all_scripts and all_scripts <= KNOWN_SCRIPTS - {"LATIN"}:
        skel = to_skeleton(sld)
        if skel not in BRAND_TLDS:
            reasons.append("SINGLE_SCRIPT_NON_LATIN(%s)"
                           % "+".join(sorted(all_scripts)))
            return _result(raw, labels, "CLEAN", min(score, 100), reasons)

    skeleton = to_skeleton(sld)

    # 1. Confusable homograph: skeleton matches a protected brand, but the
    #    raw SLD is not the brand itself.
    if skeleton in BRAND_TLDS and sld != skeleton:
        reasons.append("SKELETON_HOMOGRAPH(%s)" % skeleton)
        score += W_SKELETON_HOMOGRAPH
    # Whole-script homograph caught above too (pure Cyrillic 'ѕһорее'
    # skeletonizes to 'shopee').

    # 2. Leetspeak / hyphen trick: strip hyphens, normalize leet, compare.
    leet_norm = sld.replace("-", "").translate(LEET_MAP)
    if leet_norm in BRAND_TLDS and sld != leet_norm:
        reasons.append("LEET_HYPHEN_SPOOF(%s)" % leet_norm)
        score += W_LEET_HYPHEN_SPOOF

    # 3. Brand-as-token: protected brand embedded as hyphenated token on a
    #    different/unexpected TLD (e.g. klikbca-indonesia.com).
    for brand in sorted(BRAND_TLDS):
        if brand != sld and brand in re.split(r"[-_.]", sld):
            reasons.append("BRAND_COMBO(%s)" % brand)
            score += W_BRAND_COMBO
            break

    # 3b. Brand in subdomain: klikbca.co.id.evil.com — the registrable SLD
    # is innocent, but a subdomain impersonates the brand (classic phish).
    sub_brand = None
    for sub in subdomains:
        sub_skel = to_skeleton(sub)
        for brand in sorted(BRAND_TLDS):
            if sub_skel == brand or brand in re.split(r"[-_.]", sub_skel):
                sub_brand = brand
                break
        if sub_brand:
            break
    if sub_brand:
        reasons.append("SUBDOMAIN_BRAND(%s)" % sub_brand)
        score += W_BRAND_COMBO

    # 4. Cross-TLD spoof: exact brand SLD on a non-official TLD.
    if sld in BRAND_TLDS and tld and tld not in BRAND_TLDS[sld]:
        reasons.append("UNEXPECTED_TLD(.%s)" % tld)
        score += W_UNEXPECTED_TLD

    # 5. Edit-distance typosquat (Damerau-Levenshtein on skeleton form).
    #    Short labels (<=4) are guarded: bri/bni/bsi are distance 1 apart.
    if len(skeleton) > 4:
        best, best_d = None, None
        for brand in BRAND_TLDS:
            if abs(len(skeleton) - len(brand)) > 2:
                continue
            d = damerau_levenshtein(skeleton, brand)
            if best_d is None or d < best_d:
                best, best_d = brand, d
        if best_d == 1 and len(skeleton) >= 5:
            # Skip when already explained by a stronger signal.
            if not any(r.startswith(("SKELETON_HOMOGRAPH", "LEET_HYPHEN_SPOOF"))
                       for r in reasons):
                reasons.append("TYPOSQUAT_DIST1(%s)" % best)
                score += W_DIST1
        elif best_d == 2 and len(skeleton) >= 8:
            if not any(r.startswith(("SKELETON_HOMOGRAPH", "LEET_HYPHEN_SPOOF",
                                      "TYPOSQUAT_DIST1")) for r in reasons):
                reasons.append("TYPOSQUAT_DIST2(%s)" % best)
                score += W_DIST2

    score = min(score, 100)
    if score >= 60:
        verdict = "MALICIOUS"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
        if not reasons:
            reasons.append("NO_FINDINGS")
    return _result(raw, labels, verdict, score, reasons)


def _result(raw, labels, verdict, score, reasons):
    # De-duplicate reasons while preserving order.
    seen, uniq = set(), []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return {
        "input": raw.strip(),
        "unicode": ".".join(labels),
        "verdict": verdict,
        "score": score,
        "reasons": uniq,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_TERM_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _term_safe(s):
    """Strip control chars so untrusted input can't inject terminal escapes.

    Only used for human-readable terminal output; --json keeps raw values
    (json.dumps escapes them safely).
    """
    return _TERM_UNSAFE.sub("", s if isinstance(s, str) else str(s))


def render_table(results):
    header = "%-28s | %-24s | %-10s | %-5s | %s" % (
        "INPUT", "UNICODE", "VERDICT", "SCORE", "REASONS")
    print(header)
    print("-" * len(header))
    for r in results:
        reasons = ", ".join(r["reasons"]) if r["reasons"] else "-"
        print("%-28s | %-24s | %-10s | %-5d | %s" % (
            _term_safe(r["input"][:28]), _term_safe(r["unicode"][:24]),
            r["verdict"], r["score"], reasons))
    print("%d domain(s) checked: %d malicious, %d suspicious, %d clean" % (
        len(results),
        sum(1 for r in results if r["verdict"] == "MALICIOUS"),
        sum(1 for r in results if r["verdict"] == "SUSPICIOUS"),
        sum(1 for r in results if r["verdict"] == "CLEAN"),
    ))


# ---------------------------------------------------------------------------
# Watchdog mode: monitor Certificate Transparency logs for new
# typosquat/homograph domains aimed at your own brands
# ---------------------------------------------------------------------------
# One poll per invocation — schedule it with cron / a systemd timer, e.g.:
#   0 * * * * /path/to/puny_patrol.py --watch --brands bca.co.id \
#       --state ~/.puny-patrol-watch.json >> ~/puny-watch.log 2>&1
# Exit codes: 0 = no new brand-like names, 10 = new alerts,
# 2 = usage/state/fetch failure. A failed fetch never touches the state
# file, so a transient crt.sh outage cannot swallow an alert.

CT_URL_TEMPLATE = "https://crt.sh/?q=%25.{sld}%25&output=json"
WATCH_EXIT_ALERT = 10


class WatchError(Exception):
    pass


class WatchFetchError(WatchError):
    """All CT fetches failed (transient) — retryable in --loop mode,
    unlike usage/state errors which fail immediately either way."""
    pass


def _watch_host(domain):
    """Bare hostname from a brand/pasted-URL string."""
    m = URL_HOST.match(domain.strip())
    host = m.group(1) if m else domain.strip()
    return host.rstrip(".")


def brand_sld(brand):
    """Registrable SLD of a watched brand domain ('' if unparseable)."""
    _raw, labels, _flags = decode_domain(_watch_host(brand))
    _subs, sld, tld = split_registrable(labels)
    return sld if tld else ""


def watch_relevance(name, brands):
    """Return (brand_domain, reason) if `name` looks like an attack on one
    of the watched `brands`, else None.

    Relevance is brand-relative (skeleton / leet / edit distance /
    brand-token / subdomain), NOT catalog-relative: a watched brand need
    not be in OFFICIAL_DOMAINS to be protected here.
    """
    _raw, labels, _flags = decode_domain(_watch_host(name))
    if not labels:
        return None
    subs, sld, tld = split_registrable(labels)
    registrable = f"{sld}.{tld}" if tld else sld

    pairs = []
    for brand_domain in brands:
        _r, blabels, _f = decode_domain(_watch_host(brand_domain))
        if not blabels:
            continue
        _bs, bsld, btld = split_registrable(blabels)
        breg = f"{bsld}.{btld}" if btld else bsld
        pairs.append((".".join(blabels), breg, brand_sld(brand_domain)))
    # The brand's own certs (including its subdomains) are not attacks.
    # Compared on the brand's REGISTRABLE domain, so watching
    # 'www.tokopedia.com' still skips tokopedia.com itself — comparing
    # against the full brand string used to alert on the brand's own apex.
    if any(registrable == breg for _d, breg, _s in pairs):
        return None

    skeleton = to_skeleton(sld)
    leet_norm = sld.replace("-", "").translate(LEET_MAP)
    for brand_domain, _bdomain, brand in sorted(pairs, key=lambda p: p[0]):
        if not brand:
            continue
        brand_skel = to_skeleton(brand)
        if skeleton == brand_skel:
            if sld == brand:
                return brand_domain, "EXACT_BRAND_OTHER_TLD"
            return brand_domain, "SKELETON_HOMOGRAPH"
        if leet_norm == brand_skel and sld != leet_norm:
            return brand_domain, "LEET_HYPHEN_SPOOF"
        if brand_skel != sld and brand_skel in re.split(r"[-_.]", skeleton):
            return brand_domain, "BRAND_COMBO"
        if len(skeleton) >= 5 and len(brand_skel) >= 5:
            d = damerau_levenshtein(skeleton, brand_skel)
            if d == 1:
                return brand_domain, "TYPOSQUAT_DIST1"
            if d == 2 and len(skeleton) >= 8 and len(brand_skel) >= 8:
                return brand_domain, "TYPOSQUAT_DIST2"
    # Brand impersonated in a subdomain: klikbca.co.id.evil.com
    for label in subs:
        lab_skel = to_skeleton(label)
        for brand_domain, _bdomain, brand in sorted(pairs, key=lambda p: p[0]):
            if not brand:
                continue
            brand_skel = to_skeleton(brand)
            if lab_skel == brand_skel or brand_skel in re.split(r"[-_.]", lab_skel):
                return brand_domain, "SUBDOMAIN_BRAND"
    return None


def fetch_ct_names(brand, url_template=CT_URL_TEMPLATE, timeout=30,
                   opener=None):
    """Certificate names for `brand` from a crt.sh-style JSON feed.

    Returns a sorted, de-duplicated list of lowercase hostnames.
    Wildcards are stripped to their base name; multi-line name_value
    fields are split. `opener` (url -> parsed JSON) exists so tests and
    offline setups can run without network.

    The default template searches crt.sh for identities CONTAINING the
    brand SLD, which is what catches other-TLD copies (tokopedia.id),
    brand combos (klikbca-login.com) and subdomain impersonation
    (klikbca.co.id.evil.com). Honest recall limit: a pure edit-distance
    or homograph variant that does not embed the SLD string
    (tokopedai.com, tokopediа.com with a Cyrillic а) will NOT match the
    substring query — use --ct-url with a broader feed (e.g. a
    certstream-derived list) if that recall matters. Note the relevance
    engine still scores dist/homograph signals for any name the feed
    does return; only the feed's recall is substring-limited.
    """
    sld = brand_sld(brand)
    if "{sld}" in url_template and not sld:
        raise WatchError("cannot derive SLD from brand %r" % brand)
    url = url_template.format(brand=brand, sld=sld)
    if opener is not None:
        try:
            data = opener(url)
        except Exception as exc:
            raise WatchError("CT fetch failed for %s: %s" % (brand, exc))
    else:
        req = urllib.request.Request(
            url, headers={"User-Agent": "puny-patrol-watchdog/" + VERSION})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.load(resp)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise WatchError("CT fetch failed for %s: %s" % (brand, exc))
    names = set()
    if isinstance(data, list):
        for entry in data:
            value = entry.get("name_value", "") if isinstance(entry, dict) else ""
            for line in value.splitlines():
                line = line.strip().lower().rstrip(".")
                if line.startswith("*."):
                    line = line[2:]
                if line:
                    names.add(line)
    return sorted(names)


def load_watch_state(path):
    """Load watchdog state; missing file -> fresh state, corrupt file ->
    warning + fresh state (re-alerting beats silently missing alerts)."""
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
        if not isinstance(state, dict):
            raise ValueError("top level is not an object")
        return state
    except FileNotFoundError:
        return {"version": 1, "brands": {}}
    except (OSError, ValueError) as exc:
        print("puny-patrol: warning: unreadable state %s (%s); starting fresh"
              % (path, exc), file=sys.stderr)
        return {"version": 1, "brands": {}}


def save_watch_state(path, state):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True, ensure_ascii=False)
    except OSError as exc:
        raise WatchError("cannot write state %s: %s" % (path, exc))


def run_watch(brands, state_path, url_template=CT_URL_TEMPLATE, timeout=30,
              fetcher=None):
    """One watchdog poll. Returns the list of new alerts.

    Each alert: {name, brand, reason, verdict, score}. `verdict`/`score`
    come from the regular analyzer (context only — alerting itself is
    driven by brand relevance, so watched brands outside the bundled
    catalog still alert). Only brands that fetched successfully update
    the state file; if every fetch fails, nothing is saved.
    """
    if not brands:
        raise WatchError("no brands given (use --brands or --brands-file)")
    # Normalize state keys: case, trailing dot, and URL-wrapped spellings
    # of one brand must share a key, or a spelling change re-alerts
    # everything that brand ever saw. (One-time cost: state files written
    # by v1.2.0 under a non-normalized key re-alert once.)
    normed, _seen_keys = [], set()
    for _b in brands:
        _nb = _watch_host(_b).strip().lower()
        if _nb and _nb not in _seen_keys:
            _seen_keys.add(_nb)
            normed.append(_nb)
    brands = normed
    if not brands:
        raise WatchError("no brands given (use --brands or --brands-file)")
    state = load_watch_state(state_path)
    seen_map = state.get("brands", {})
    if not isinstance(seen_map, dict):
        seen_map = {}
    alerts, failed, alerted = [], [], set()
    for brand in brands:
        try:
            if fetcher is not None:
                names = fetcher(brand)
            else:
                names = fetch_ct_names(brand, url_template, timeout)
        except WatchError as exc:
            print("puny-patrol: %s" % exc, file=sys.stderr)
            failed.append(brand)
            continue
        seen = set(seen_map.get(brand, []))
        for name in names:
            if name in seen:
                continue
            hit = watch_relevance(name, brands)
            # One alert per domain per poll: brands sharing an SLD
            # (tokopedia.com + tokopedia.co.id) used to alert twice for
            # the same name in a single run.
            if hit is not None and name not in alerted:
                alerted.add(name)
                brand_domain, reason = hit
                verdict = analyze_domain(name)
                alerts.append({
                    "name": name,
                    "brand": brand_domain,
                    "reason": reason,
                    "verdict": verdict["verdict"] if verdict else "CLEAN",
                    "score": verdict["score"] if verdict else 0,
                })
        seen_map[brand] = sorted(seen | set(names))
    if failed and len(failed) == len(brands):
        raise WatchFetchError("all CT fetches failed; state not saved")
    state["brands"] = seen_map
    state["last_check"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_watch_state(state_path, state)
    return alerts


def render_watch(alerts, json_output=False):
    if json_output:
        print(json.dumps(alerts, indent=2, ensure_ascii=False))
        return
    if not alerts:
        print("watchdog: no new brand-like domains")
        return
    print("watchdog: %d NEW brand-like domain(s):" % len(alerts))
    for a in alerts:
        print("  %-28s brand=%s reason=%s verdict=%s score=%d" % (
            _term_safe(a["name"][:28]), _term_safe(a["brand"]), a["reason"],
            a["verdict"], a["score"]))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def iter_inputs(args):
    if args.domains:
        for d in args.domains:
            yield d
    elif args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        yield line
        except OSError as exc:
            print("puny-patrol: cannot read %s: %s" % (args.file, exc),
                  file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("puny-patrol: reading domains from stdin (Ctrl-D to finish)...",
                  file=sys.stderr)
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="puny-patrol",
        description="Detect IDN homograph & typosquatting attacks on domain "
                    "names. Verdicts: CLEAN / SUSPICIOUS / MALICIOUS.")
    ap.add_argument("domains", nargs="*",
                    help="domains to check (default: read stdin)")
    ap.add_argument("-f", "--file", metavar="PATH",
                    help="read domains from file (one per line, # = comment)")
    ap.add_argument("--json", action="store_true",
                    help="output JSON instead of table")
    ap.add_argument("--min-score", type=int, default=0, metavar="N",
                    help="only show results with score >= N")
    ap.add_argument("--watch", action="store_true",
                    help="watchdog mode: poll CT logs for new domains "
                         "resembling --brands, alert on first sight")
    ap.add_argument("--brands", metavar="DOMAINS",
                    help="comma-separated brand domains to watch")
    ap.add_argument("--brands-file", metavar="PATH",
                    help="file with one brand domain per line (# = comment)")
    ap.add_argument("--state", metavar="PATH",
                    default=".puny-patrol-watch-state.json",
                    help="watchdog state file "
                         "(default: .puny-patrol-watch-state.json)")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="in --watch mode, repeat polling every SECONDS "
                         "(0 = poll once)")
    ap.add_argument("--ct-url", metavar="TEMPLATE", default=CT_URL_TEMPLATE,
                    help="CT feed URL template with {brand} and {sld} "
                         "placeholders (default: crt.sh substring search)")
    ap.add_argument("--ct-timeout", type=int, default=30, metavar="SECONDS",
                    help="CT fetch timeout (default: 30)")
    ap.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = ap.parse_args(argv)

    if args.watch:
        if args.loop < 0 or args.ct_timeout <= 0:
            print("puny-patrol: --loop must be >= 0 and --ct-timeout > 0",
                  file=sys.stderr)
            return 2
        brands = []
        if args.brands:
            brands += [b.strip() for b in args.brands.split(",") if b.strip()]
        if args.brands_file:
            try:
                with open(args.brands_file, encoding="utf-8",
                          errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            brands.append(line)
            except OSError as exc:
                print("puny-patrol: cannot read %s: %s"
                      % (args.brands_file, exc), file=sys.stderr)
                return 2
        while True:
            try:
                alerts = run_watch(brands, args.state,
                                   args.ct_url, args.ct_timeout)
            except WatchFetchError as exc:
                # Transient crt.sh outage: in --loop mode stay alive and
                # retry next interval (a dead watchdog alerts nobody);
                # single-shot mode still fails loudly with exit 2.
                print("puny-patrol: %s" % exc, file=sys.stderr)
                if args.loop <= 0:
                    return 2
                time.sleep(args.loop)
                continue
            except WatchError as exc:
                print("puny-patrol: %s" % exc, file=sys.stderr)
                return 2
            render_watch(alerts, args.json)
            if args.loop <= 0:
                return WATCH_EXIT_ALERT if alerts else 0
            time.sleep(args.loop)

    results = []
    for raw in iter_inputs(args):
        r = analyze_domain(raw)
        if r and r["score"] >= args.min_score:
            results.append(r)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        render_table(results)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
