# Audit log

Findings and fixes per release, newest first. "Verified" means the check
was actually run, not just reasoned about.

## v1.2.1 — Watchdog audit (2026-11-03)

Tuesday audit of the v1.2.0 watchdog feature. Baseline suite green
(83/83) before any change; 5 real bugs fixed, all with regression
tests (suite now 89/89):

1. **Duplicate alerts in one poll.** Watching two brands that share an
   SLD (`tokopedia.com` + `tokopedia.co.id`) alerted twice for the same
   domain in a single run, because state is keyed per brand string.
   Now one alert per domain per poll (first attribution kept).
2. **Own domain flagged when the brand was written with a subdomain.**
   Watching `www.tokopedia.com` alerted on `tokopedia.com` itself as
   `EXACT_BRAND_OTHER_TLD`, because the own-domain skip compared
   against the full brand string. The skip now compares registrable
   domains, so a brand's own apex and subdomains are always skipped
   regardless of how the brand was spelled.
3. **State-key spelling drift re-alerted everything.** `Tokopedia.COM.`
   and `tokopedia.com` wrote different state keys, so a spelling change
   re-alerted the whole history. Brand keys are now normalized
   (host extracted, lowercased, trailing dot stripped) before state
   lookup — one-time cost: state files written by v1.2.0 under a
   non-normalized key re-alert once.
4. **Terminal injection via the brand string.** Cert names were already
   escaped in table output, but the operator-supplied brand was printed
   raw — an ESC smuggled into a brands file would pass through. Now
   passed through `_term_safe` like every other untrusted string
   (JSON output keeps raw values, safely escaped by `json.dumps`).
5. **`--loop` died on the first transient crt.sh outage.** A watchdog
   daemon that exits on a documented-flaky feed alerts nobody, so
   all-fetch-failed is now a distinct retryable error
   (`WatchFetchError`, still a `WatchError` subclass): `--loop` mode
   sleeps and retries next interval, single-shot mode still exits 2.
   Usage/state errors still fail immediately in both modes.

Verified: suite 89/89 green (working tree, stdlib only); adversarial
probes 1–3 and 5 above re-run clean after the fix; CLI smoke
(`tokopediа.com` Cyrillic → MALICIOUS 100, controls unchanged); live
crt.sh smoke `--watch --brands tokopedia.com` returned 20 new
brand-like names (e.g. `cdn1.tokopedia.net`, other-TLD brand copies —
expected watchdog semantics: CT alone cannot tell own-brand
infrastructure from an attacker copy, so other-TLD copies alert by
design). Deliberately unchanged: per-brand state scoping, partial
failure keeping good brands' state, corrupt-state warning + fresh
start.

## v1.2.0 — Watchdog mode (upgrade, 2026-11-02)

New feature, not just a fix: `--watch` polls Certificate Transparency
logs (crt.sh) for newly issued certificates resembling the user's own
brands and alerts on first sight, with a JSON state file keeping repeats
quiet. Designed for cron / systemd timers; `--loop` offers a continuous
alternative. Exit codes: `0` nothing new, `10` new alerts, `2`
usage/fetch/state error, `130` Ctrl-C.

Design review during the build caught one real bug before release: the
first query template was `%.{brand}`, which only returns the brand's
own subdomains — exactly the names the watchdog deliberately skips.
The template is now `%{sld}%` (substring search on the SLD), verified
live against crt.sh: it returns other-TLD copies (`tokopedia.id`),
brand combos, and subdomain impersonation, which the relevance engine
then classifies. Honest recall limit documented in README: pure
edit-distance / homograph variants that do not embed the SLD string are
not fetched by the default query.

Verified:

- Full suite: 83/83 tests green (60 pre-existing + 23 new watchdog
  tests), stdlib only, offline (fake feed injection)
- Live smoke against real crt.sh: `--watch --brands tokopedia.com`
  reported 20 new brand-like names (exact-brand/other-TLD, one
  distance-1 typo `tokopediax.com`) with exit code 10; the immediate
  second run reported nothing with exit code 0 (state file works)
- Failure semantics: all-fetches-failed raises and writes no state;
  partial failure saves only the brands that fetched; corrupt state
  warns and starts fresh (re-alerting beats silently missing alerts)
- crt.sh flakiness observed live (intermittent 502 / empty backends);
  handled as fetch errors, never as "clean"

## v1.0.1 — Invalid Punycode weight (audit, 2026-10-16)

Bug: a domain with a broken `xn--` label was detected (flag present)
but scored 0, so the verdict stayed `CLEAN`. Fix: `INVALID_PUNYCODE`
now weighs +30, landing such domains in `SUSPICIOUS`. Verified:
33/33 tests green, CLI check `xn--invlid-.com` → `SUSPICIOUS` 30,
controls (`bsi.co.id`, Cyrillic `tokopediа.com`) unchanged.

## Earlier hardening (pre-v1.0.1)

- Terminal/log injection: all server- or input-supplied strings are
  stripped of control characters before table output (JSON output keeps
  raw values, safely escaped by `json.dumps`)
- `--json` / `--csv` mutual exclusion, `--include-private` flag for
  private/loopback/link-local display, IPv6 `::`-prefix parsing via
  lookaround with a minimum-2-colon rule
- `LICENSE` MIT and `.gitignore` added (missed in the initial build)

## Standing verdict

v1.2.0 is solid as a triage watchdog: it reliably surfaces newly issued
brand-embedding certificates and stays quiet afterwards. It is not a
replacement for a full CT-stream monitor — substring recall (see
Limitations in README) means determined homoglyph / typo variants can
slip past the default feed.
