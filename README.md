# puny-patrol

Detect IDN homograph & typosquatting attacks on domain names. Stdlib-only Python CLI — no dependencies.

## Features

- **IDN homograph detection**: decodes Punycode (`xn--`), flags mixed-script labels (Latin + Cyrillic in one label), and maps confusable Unicode lookalikes (Cyrillic `а`, Greek `ο`, dotless `ı`, …) to their ASCII skeleton
- **Typosquat detection**: Damerau–Levenshtein distance, leetspeak normalization (`b4nk` → `bank`), and hyphen-stripping against a bundled catalog of ~40 popular Indonesian domains (banks, e-commerce, gov, telco)
- **False-positive guards**: official-domain whitelist, short-label guard (`bri`/`bni`/`bsi` are 1 edit apart), Indonesian multi-level TLD handling (`co.id`, `go.id`, …), single-script non-Latin IDNs (CJK, Arabic) left alone
- Verdicts `CLEAN` / `SUSPICIOUS` / `MALICIOUS` with 0–100 risk score and machine-readable reason codes
- Output as ASCII table or JSON; accepts pasted URLs, not just bare domains
- **Watchdog mode** (`--watch`): polls Certificate Transparency logs (crt.sh) for newly issued certificates resembling your own brands and alerts on first sight — state file keeps repeats quiet, so it fits a cron job or systemd timer

## Install

```bash
git clone https://github.com/Llunatics/puny-patrol.git
cd puny-patrol
chmod +x puny_patrol.py
```

Requires Python 3.8+. No pip packages.

## Usage

```bash
# check domains from a file
./puny_patrol.py -f domains.txt

# from args or a pipe
./puny_patrol.py tokopediа.com b4nk-mandiri.co.id
cat subs.txt | ./puny_patrol.py

# JSON output for pipelines
./puny_patrol.py -f domains.txt --json > verdicts.json

# only show risky ones
./puny_patrol.py -f domains.txt --min-score 60
```

## Watchdog mode

Watch your own brands for newly issued lookalike certificates. Each poll
fetches crt.sh identities containing your brand's SLD, reports names that
are brand-like (exact brand on another TLD, brand combo, subdomain
impersonation, homograph, edit-distance typo) and have never been seen
before, then records everything in a state file so the next poll stays
quiet. Exit code `10` means new alerts, `0` means nothing new, `2` means
a usage/fetch/state error (a failed fetch never touches the state file,
so an outage cannot swallow an alert).

```bash
# one poll (first run surfaces the brand's own other-TLD properties too —
# they are baseline, and go quiet on the next run)
./puny_patrol.py --watch --brands tokopedia.com,klikbca.co.id \
    --state ~/.puny-patrol-watch.json

# the same, as an hourly cron job
0 * * * * /path/to/puny_patrol.py --watch --brands tokopedia.com \
    --state ~/.puny-patrol-watch.json >> ~/puny-watch.log 2>&1

# continuous loop instead of cron (Ctrl-C exits 130)
./puny_patrol.py --watch --brands tokopedia.com --loop 3600

# JSON alerts for pipelines, brands from a file
./puny_patrol.py --watch --brands-file brands.txt --json
```

Alerting is driven by brand relevance, not by the bundled catalog — a
watched brand that is not in `OFFICIAL_DOMAINS` still alerts. The
`verdict`/`score` columns are the regular analyzer's opinion for context.

## Example

```
$ ./puny_patrol.py -f tests/sample-domains.txt
INPUT                        | UNICODE                  | VERDICT    | SCORE | REASONS
--------------------------------------------------------------------------------------
bsi.co.id                    | bsi.co.id                | CLEAN      | 0     | OFFICIAL_TARGET_MATCH
portal.sso.pajak.go.id       | portal.sso.pajak.go.id   | CLEAN      | 0     | OFFICIAL_SUBDOMAIN
bpjs-kesehatan.go.id         | bpjs-kesehatan.go.id     | CLEAN      | 0     | OFFICIAL_TARGET_MATCH
google.com                   | google.com               | CLEAN      | 0     | NO_FINDINGS
kemenkeu-ri.go.id            | kemenkeu-ri.go.id        | CLEAN      | 0     | NO_FINDINGS
tokopediа.com                | tokopediа.com            | MALICIOUS  | 100   | MIXED_SCRIPT(CYRILLIC+LATIN), SKELETON_HOMOGRAPH(tokopedia)
klıkbca.co.id                | klıkbca.co.id            | MALICIOUS  | 85    | SKELETON_HOMOGRAPH(klikbca)
ѕһорее.co.id                 | ѕһорее.co.id             | MALICIOUS  | 85    | SKELETON_HOMOGRAPH(shopee)
b4nk-mandiri.co.id           | b4nk-mandiri.co.id       | MALICIOUS  | 75    | LEET_HYPHEN_SPOOF(bankmandiri)
telkomse1.com                | telkomse1.com            | MALICIOUS  | 75    | LEET_HYPHEN_SPOOF(telkomsel)
bca-login.com                | bca-login.com            | SUSPICIOUS | 40    | BRAND_COMBO(bca)
klikbca-indonesia.com        | klikbca-indonesia.com    | SUSPICIOUS | 40    | BRAND_COMBO(klikbca)
中国.id                        | 中国.id                    | CLEAN      | 0     | NO_FINDINGS
13 domain(s) checked: 5 malicious, 2 suspicious, 6 clean
```

## How it scores

| Signal | Weight | Example |
|---|---|---|
| `SKELETON_HOMOGRAPH` | +85 | `klıkbca.co.id` (dotless ı) → `klikbca` |
| `LEET_HYPHEN_SPOOF` | +75 | `b4nk-mandiri.co.id` → `bankmandiri` |
| `TYPOSQUAT_DIST1` | +70 | `telkomse1.com` → `telkomsel` |
| `MIXED_SCRIPT` | +65 | `tokopediа.com` (Cyrillic а) |
| `UNEXPECTED_TLD` | +45 | exact brand SLD on wrong TLD |
| `BRAND_COMBO` / combining marks | +40 | `klikbca-indonesia.com` |
| `SUBDOMAIN_BRAND` | +40 | brand in subdomain: `klikbca.co.id.evil.com` |
| `TYPOSQUAT_DIST2` | +35 | distance-2 on 8+ char brands |
| `INVALID_PUNYCODE` | +30 | broken `xn--` label → `SUSPICIOUS` |
| `UNASSIGNED_CHAR` | +50 | unassigned/control codepoint in label |

Score ≥ 60 → `MALICIOUS`, 25–59 → `SUSPICIOUS`, < 25 → `CLEAN`.

## Tests

```bash
python3 -m unittest discover -s tests   # 83 tests, stdlib only — no pytest needed
```

## Limitations

- Confusable map is a curated subset (~35 entries), not full UTS #39 — rare scripts may slip through
- Brand catalog covers major Indonesian targets only; edit `OFFICIAL_DOMAINS` in source to extend
- Heuristic scores are triage signals, not proof of maliciousness — verify before blocking
- Watchdog recall is substring-limited: the default crt.sh query only finds certificates whose identity contains the brand SLD, so a pure edit-distance or homograph variant that does not embed the SLD string (e.g. `tokopedai.com`, Cyrillic-а `tokopediа.com`) will not be fetched. Feed a broader source via `--ct-url` if that recall matters; the relevance engine still scores dist/homograph signals for any name the feed returns
- crt.sh itself is occasionally flaky (502/empty backends); a failed poll exits `2` and leaves the state file untouched, so just re-run it

## License

MIT — see [LICENSE](LICENSE).
