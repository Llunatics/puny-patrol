# Audit log

Findings and fixes per release, newest first. "Verified" means the check
was actually run, not just reasoned about.

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
