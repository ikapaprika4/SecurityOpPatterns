# SOC Workbench

Four SOC toolkits behind one drag-and-drop window: **phishkit** (email),
**evtxkit** (Windows event logs), **nsmkit** (network logs) and **trafkit**
(packet captures). Drop evidence in any mix and get back *cases*: a
verdict, the findings and their evidence, indicators, the details, and
ready-to-use exports.

## Start

1. Double-click **`SOC Workbench.bat`**.
2. Drop files, folders or `.zip` archives anywhere on the window, or use
   **Add files**, **Folder** or **Paste** (raw email source or log lines).
   You can also drop them onto the `.bat` icon to open the workbench with
   them already analysed.

**Samples** loads the bundled demo evidence for every toolkit.

Needs **Python 3.10+** and nothing else. If `pywebview` is installed it
opens as a desktop window; otherwise it opens in your default browser
(`pip install pywebview` to switch). From a terminal:

```bash
python -m socworkbench
```
```bash
python -m socworkbench evidence.zip capture.pcapng
```

Flags: `--browser` (always use the browser), `--no-open` (just serve and
print the URL), `--port N`. In browser mode, **Quit** stops it, and it also
stops by itself 15 minutes after the last tab closes.

## What you can drop

| Evidence | Recognised formats | Analysed by | One case per |
|---|---|---|---|
| Email | `.eml`, Outlook `.msg`, `.mbox` | phishkit | message |
| Windows events | `.evtx`, Event Viewer / `wevtutil` XML, JSON/JSONL (Winlogbeat/ECS, evtx_dump, EvtxECmd, flat), `ConsoleHost_history.txt` | evtxkit | host (Security + Sysmon from one machine correlate) |
| Network logs | firewall, IDS, VPN, WAF/web, DNS logs; JSON; CSV | nsmkit | drop (cross-device correlation is the point) |
| Packet captures | `.pcap`, `.pcapng`, gzip-compressed | trafkit + nsmkit flow detectors | capture |

Files are recognised by **content**, so a wrong or missing extension is
fine: a `.msg` saved as `.eml`, a capture called `capture.bin`, or logs
saved as `.txt`. Folders are walked. `.zip` archives are opened, including
ones protected with the sample-sharing passwords `infected`, `malware` or
`virus`. Anything that isn't evidence is listed as skipped, with the
reason.

## What a case gives you

* **Verdict** and severity counts. Email is scored (benign → malicious);
  the other kits report their worst finding. Damaged or unreadable
  evidence is marked as such and never shown as "clean".
* **Findings**: the rule, severity, confidence, what it means, the
  evidence (frames, event records, log lines), the recommended action and
  the MITRE ATT&CK technique.
* **Details**: the kit's own view.
  * Email: SPF/DKIM/DMARC, delivery path, links, attachments, headers.
  * Windows: an attack timeline and event statistics.
  * Network logs: correlated incidents, VPN session pivots, and the top
    blocked sources, failed logins and IDS signatures.
  * Captures: protocol hierarchy, hosts, conversations, DNS, HTTP, TLS,
    files transferred and cleartext credentials. The credentials are
    masked; click one to reveal it.
* **Indicators**: defanged, each marked *block* or *context*. Legitimate
  and shared infrastructure (webmail providers, a brand's real site, the
  mail provider's servers, internal hosts) is context and never lands in a
  blocklist.
* **Exports**: HTML report (self-contained, printable), JSON, indicator
  CSV and blocklist for every case, plus MISP and STIX 2.1 for email,
  iptables, Cisco IOS, pf and netsh ACLs for captures, and Snort/Suricata
  rules for network logs.

## Safety

The workbench reads attacker-supplied files, so:

* **Everything stays on this computer.** The server listens only on
  127.0.0.1, on a random port. Every API request must carry a per-session
  token, and every request's Host header is checked (against DNS
  rebinding).
* **Evidence is only read, never opened or executed.** Email attachments
  are hashed in memory and never written to disk. From a `.zip`, only
  recognised evidence is extracted, into a private temporary folder that is
  deleted when the workbench closes.
* **Evidence is shown as text, never rendered as HTML.** URLs are defanged
  and never clickable, and a strict Content-Security-Policy stops the page
  from loading or contacting anything outside the workbench.

If something goes wrong, `%LOCALAPPDATA%\SOCWorkbench\logs\last-run.log` has
the details. It is kept outside this folder on purpose, because it
contains local paths.

## The toolkits on their own

Every toolkit still works from the command line, as before:

```bash
python -m phishkit analyze samples/phishkit/ -v
python -m evtxkit analyze samples/evtxkit/rdp_brute_force.jsonl
python -m nsmkit analyze samples/nsmkit/ -f html -o report.html
python -m trafkit analyze samples/trafkit/http_traffic.pcapng
```

`pip install -e .` puts `socwb`, `phish`, `evtxkit`, `nsm` and `trafkit`
on your PATH. Each toolkit's manual is in `docs/<kit>.md`, and its
detection spec is in `docs/*_BUILD_SPEC.md`.

Optional packages (none is required):

| Package | Only for |
|---|---|
| `pywebview` | the desktop window instead of a browser tab |
| `python-evtx` | reading `.evtx` on a system other than Windows (Windows uses the built-in `wevtutil`) |
| `extract-msg` | a fallback `.msg` reader (`.msg` is read natively) |
| `scapy` | regenerating the sample captures, and the opt-in comparison backend |

## Windows event logs as a web service (AWS)

evtxkit also runs as a small cloud service: someone opens a page, uploads a
Windows event log, and gets the report back, without touching Docker, AWS or
any code.

```
browser --> upload page (Lambda function URL, access code per person)
        --> S3 uploads bucket (pre-signed POST: one key, 64 MB, 5 minutes)
        --> S3 event --> Lambda --> ECS Fargate task (s3_wrapper.py + evtxkit)
            (the upload is deleted as soon as it has been analysed)
        --> S3 reports bucket (report.md + status.json, removed within two days)
        --> the page polls and shows it
```

- The page also offers the bundled sample logs, each with the result it should
  give, so it can be tried without a log of your own.
- Try the whole flow on your own machine, no AWS account needed (S3 and Fargate
  are replaced by local stand-ins; everything else is the real code):

  ```bash
  python tools/local_upload_flow.py
  ```

- Setting it up on AWS, step by step, with the least-privilege policies and what
  a working result looks like: [`aws/UPLOAD-FLOW.md`](aws/UPLOAD-FLOW.md).
- `s3_wrapper.py` is the container's entry point, `aws/lambda/` holds the two
  functions and the page, `tools/access_codes.py` makes the access codes (only
  fingerprints are stored) and `tools/build_lambdas.py` packages the functions.

Known limits of this first version: access is by a code per person, not by
accounts; a Lambda function URL has no rate limiting; real `.evtx` files are read
by evtxkit's own reader on Linux, which matches Windows' `wevtutil` on the logs
tested so far but differs in rare value formatting. The runbook lists what is
left out.

## Folder layout

```
SOC Workbench.bat    launcher (double-click, or drop files on it)
socworkbench/        the app: recognition, engine, exports, local server, web UI
phishkit/ evtxkit/ nsmkit/ trafkit/    the four toolkits
soccore/             shared code: native pcap/pcapng reader, address classes, sliding windows
samples/<kit>/       synthetic demo evidence (what "Samples" loads)
tests/               python run_tests.py runs every suite
tools/               sample generators, packet reader comparison, upload-flow helpers
aws/                 the AWS upload service: runbook, policies, task definition, Lambda functions
docs/                toolkit manuals, build specs, CHANGES.md
```

**The sample data is synthetic.** IP addresses come from the documentation
ranges (RFC 5737), and attacker domains use the reserved `.example` TLD
(RFC 2606). The few values that must sit on real services for a rule to
fire (Gmail, bit.ly, pages.dev) are made-up demo names. The Gmail addresses
can't exist at all, because Gmail doesn't allow `_` in usernames. Some
samples contain attack command lines on purpose, because they are what the
detectors must catch, so an antivirus may flag them. None of them contains
executable code.

**What changed from the original four zips**, including the bugs that were
fixed: [`docs/CHANGES.md`](docs/CHANGES.md).
