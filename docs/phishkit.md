# phishkit — email & phishing analysis toolkit

Parses `.eml` / `.msg` / raw MIME, extracts every header and body artifact, runs 45 detection
rules, scores the message, and produces a verdict with defanged IOCs ready for a ticket or a
blocklist.

**`docs/PHISHING_BUILD_SPEC.md` is the detection-engineering specification** — email anatomy and
delivery, header grammars, SPF/DKIM/DMARC semantics, every rule's logic and weight, false-positive
sources, ATT&CK mapping, the tooling stack with disclosure discipline, and the SOC triage
workflow. Hand that file to a coding model to build from, or read it as the reference; `phishkit/`
is the working implementation of it.

## Install

Nothing to install: run from the `soc-workbench` folder (or `pip install -e .` there for the
`phish` command). Python 3.10+, no dependencies — the parser is built on the stdlib `email`
package, and Outlook `.msg` files are read natively (the `extract-msg` package is only an
optional fallback). `.mbox` mailboxes are split into one result per message.

## Quick start

```bash
python -m phishkit analyze samples/phishkit/ -v
python -m phishkit analyze samples/phishkit/ -f html -o report.html
python tools/make_phish_samples.py      # regenerate the 10 bundled samples (.eml, .msg, .mbox)
```

## Commands

| Command | Purpose |
|---|---|
| `phish analyze <files\|dirs>` | Full triage: artifacts, findings, verdict, IOCs (`-f console\|json\|markdown\|html`) |
| `phish headers <file>` | Header artifacts, delivery path oldest-first, authentication results |
| `phish urls <file>` | Every URL, defanged, with per-URL red flags and unwrapped redirect chains |
| `phish attachments <file>` | Hashes, flags, embedded links; `--extract DIR` saves them safely |
| `phish iocs <files>` | Export indicators (`text\|json\|csv\|misp\|stix\|blocklist`) |
| `phish defang` / `refang` | Convert indicators for safe sharing or live use |
| `phish enrich <file>` | VirusTotal / urlscan / IPinfo / AbuseIPDB lookups (needs API keys) |
| `phish rules` | List all 45 rules and the verdict thresholds |

Exit code is 1 when any message is judged phishing or malicious, so it drops into a pipeline.

## What it detects

**Header & identity** — display-name spoofing, brand impersonation, Reply-To and Return-Path
divergence, BCC delivery, disposable and free-webmail senders, lookalike sending domains,
high-abuse TLDs, missing or single-hop delivery paths.

**Authentication** — SPF (with the full result→action table), DKIM, DMARC alignment and policy.
Passing all three *reduces* the score rather than short-circuiting the analysis, because an
attacker's own domain passes all three.

**URLs** — shorteners, lookalike domains (four techniques), bare-IP links, tracking pixels,
anchor-text/href mismatch, credential paths, abused hosting platforms, redirect chains unwrapped
through Safe Links / Proofpoint / Mimecast, userinfo `@` tricks, punycode.

**Attachments** — double extensions, executables, macro-capable formats, magic-byte/extension
mismatch, archives and ISO containers, empty-body delivery, and URLs embedded inside PDFs
(including compressed streams) and OOXML relationship targets.

**Social engineering** — urgency, threat, credential-request and BEC language; deliberate brand
misspellings (`netllx`, `paypa1`, `micros0ft`); generic greetings; executive targeting.

## Extending

**A new rule** — add a function to `detectors.py` returning `Finding` objects and append it to
`ALL_CHECKS`. Give it an ID in the existing scheme, a weight, a description that explains *why*,
and a recommendation.

**A new brand** — add its legitimate domains to `BRANDS` and its keywords to `BRAND_KEYWORDS` in
`brands.py`. Lookalike detection picks it up automatically.

**A new input format** — write a parser producing a `ParsedEmail`. No detector changes.

## Tests

```bash
python tests/test_phishkit.py     # or, for every toolkit at once: python run_tests.py
```

66 tests covering parsing (including native `.msg`, renamed files and `.mbox`), every analysis primitive, a positive case for each detector, and a
negative case for every rule that could over-fire — a legitimate GitHub notification that must
score 0, marketing mail with urgency + a tracking pixel + a shortener that must stay below the
phishing threshold, and an internal newsletter with 15 links that must stay clean.

Lookalike detection is validated separately at 14/14 true positives, 0/26 false positives.

## Three things worth knowing

**Received headers are prepended.** Index 0 is the *last* hop — your own gateway. Walking the
list forwards and taking the first IP reports your mail server as the attacker. Walk it backwards
and skip RFC1918 relays.

**Passing SPF/DKIM/DMARC does not mean trustworthy.** It means the domain is real. An attacker's
own domain passes all three, and so does a compromised legitimate account — which is why the BEC
sample in the corpus passes every check and is still the most dangerous message in it.

**Submitting an indicator is a disclosure.** Hash lookups are free. Uploading a file to a public
sandbox may expose customer data; scanning a campaign-unique URL tells the operator they were
detected. Order of operations: hash lookup → passive search → active scan → sandbox upload.
Spec §11.2.
