# Phishing & Email Analysis — Detection Engineering Build Spec

**Purpose.** A complete, implementation-ready specification for building email/phishing analysis
tooling. Written to be handed directly to a code-generating model or a developer. Every rule
states its inputs, logic, weight, false-positive sources, MITRE ATT&CK mapping, and analyst action.

**Scope.** Email anatomy and delivery, header and body analysis, attachment reconstruction and
triage, link manipulation and tracking pixels, credential harvesting, the phishing taxonomy,
SPF/DKIM/DMARC/S-MIME, the analyst tooling stack, IOC extraction and defanging, and the SOC
triage workflow.

**Companion implementation.** `phishkit/` — a working Python reference implementation.
45 rules, 56 passing tests, no mandatory dependencies. See §13.

---

## Table of contents

1. [Email anatomy and delivery](#1-email-anatomy-and-delivery)
2. [Artifact collection checklist](#2-artifact-collection-checklist)
3. [Parsing model](#3-parsing-model)
4. [Header analysis](#4-header-analysis)
5. [Authentication: SPF, DKIM, DMARC, S/MIME](#5-authentication-spf-dkim-dmarc-smime)
6. [Body and URL analysis](#6-body-and-url-analysis)
7. [Attachment analysis](#7-attachment-analysis)
8. [Social engineering analysis](#8-social-engineering-analysis)
9. [Detection rules and scoring](#9-detection-rules-and-scoring)
10. [IOC extraction, defanging and export](#10-ioc-extraction-defanging-and-export)
11. [Tooling and enrichment](#11-tooling-and-enrichment)
12. [SOC workflow and prevention controls](#12-soc-workflow-and-prevention-controls)
13. [Reference implementation](#13-reference-implementation)

---

## 1. Email anatomy and delivery

### 1.1 The address

```
        david @ example.com
        ─────   ───────────
        username  domain
```

| Part | Meaning | Analysis relevance |
|---|---|---|
| **Username** (local part) | The mailbox on the destination system | Random strings (`gibberish`, `vgmpv_yh0hyvo`) indicate bulk generation |
| **`@`** | Separates user from domain; tells the system where to route | Inside a *URL*, `@` means everything to its left is ignored — a spoofing primitive (§6.5) |
| **Domain** | The mail server responsible for receiving | The identity that matters. Every impersonation check compares claimed brand against this |

The postal analogy: domain = the building, username = the person in it.

### 1.2 Protocols

| Protocol | Role |
|---|---|
| **SMTP** | Sends mail (client → server, server → server) |
| **POP3** | Downloads to a single device; typically removes from server |
| **IMAP** | Syncs across devices; messages stay on the server |

POP3 vs IMAP matters forensically: with POP3 the only copy may be on one endpoint, so a
server-side hunt for a campaign will miss it.

### 1.3 The journey (and where each artifact comes from)

```
1. Sender's client → sender's mail server            SMTP
2. Sending server queries DNS for the recipient MX
3. DNS returns the recipient's mail server
4. Message crosses the internet                       ← each hop stamps a Received: header
5. Recipient's client connects to their mail server
6. Message downloaded (POP3) or synced (IMAP)
```

Every server in step 4 **prepends** a `Received:` header. That ordering is the single most
misread detail in header analysis — see §4.2.

### 1.4 Structure

| Part | Contains |
|---|---|
| **Header** | Metadata: From, To, Reply-To, Subject, Date, Received chain, authentication results |
| **Body** | The message — `text/plain`, `text/html`, or both as MIME alternatives |
| **Attachments** | MIME parts with `Content-Disposition: attachment`, usually base64-encoded |

The inbox view shows a curated subset. **Always analyse the raw source** (`View → Message Source`,
Ctrl+U) — the originating IP, Reply-To, authentication results and the real `href` behind every
button exist only there.

---

## 2. Artifact collection checklist

The fixed set to extract from every message, before any judgement:

**Header**

| Artifact | Why |
|---|---|
| Sender email address | Where it originated; the identity being claimed |
| Sender display name | What the user sees — the spoofing surface |
| Sender IP address | Reverse lookup, geolocation, reputation |
| Subject line | Urgency / call to action |
| Recipient (To / Cc / **Bcc**) | Who was targeted; BCC = hidden distribution |
| **Reply-To** | Where responses actually go — the BEC tell |
| Return-Path | The envelope sender; what SPF validates |
| Date and time | Timeline, off-hours delivery |
| Message-ID | Campaign correlation; absence is itself a signal |

**Body**

| Artifact | Why |
|---|---|
| URLs and hyperlinks | Expand shorteners; compare anchor text to href |
| Attachment name(s) | Extension, double extension, format-vs-purpose mismatch |
| Attachment hash (SHA256) | Reputation lookup without disclosing the file |

---

## 3. Parsing model

### 3.1 Normalised structure

```python
@dataclass
class ParsedEmail:
    source_path: str; raw: bytes; file_sha256: str
    # header artifacts
    from_addr, reply_to, return_path, sender: EmailAddress | None
    to, cc, bcc: list[EmailAddress]
    subject: str; date: datetime | None; message_id: str
    x_originating_ip: str; originating_ip: str
    received_chain: list[ReceivedHop]
    all_headers: list[tuple[str, str]]
    # body
    body_text: str; body_html: str
    urls: list[ExtractedURL]; attachments: list[Attachment]
    # authentication
    auth: AuthenticationResults
    is_bcc_delivery: bool; parse_errors: list[str]
```

`EmailAddress` splits `raw` into `display_name`, `address`, and derives `local_part` / `domain`.
Almost every header rule is a comparison between `display_name` and `domain`.

### 3.2 Parsing rules that matter

1. **Never raise.** Attackers break MIME structure deliberately to defeat parsers. Every failure
   appends to `parse_errors` and returns a partial result. A parser that throws is a parser that
   can be silenced by a malformed boundary.
2. **Decode RFC 2047 encoded-words** (`=?utf-8?B?...?=`) in Subject, display names and filenames.
   Attackers encode to hide keywords from naive string matching.
3. **Walk every MIME part.** Body text and attachments can appear at any nesting depth.
4. **Keep the raw bytes.** Hash the whole file for campaign correlation, and quote raw lines as
   evidence in findings.
5. **`.msg` (Outlook)** needs `extract_msg`; convert to MIME and reuse the same path. Degrade with
   a clear message when the package is absent rather than failing silently.

### 3.3 Attachment reconstruction

The base64 blob following the MIME headers *is* the file:

```
Content-Type: application/pdf
Content-Disposition: attachment; filename="Invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcfsj6IKNSAwIG9iago8PC9MZW5ndGggNiAwIFI...
```

`email.message.Message.get_payload(decode=True)` handles the decode. Manually, CyberChef's
`From_Base64` recipe or a base64→file converter does the same — useful when you have only a
pasted header dump and not the `.eml`.

**Handling extracted samples safely:** write with mode `0600`, rename to `.bin` so a
double-click cannot execute it, and never write into a directory that is being watched by a
sync client or scanned by a real-time AV that will quarantine it mid-analysis.

---

## 4. Header analysis

### 4.1 Identity fields and what a mismatch means

| Field | Set by | Spoofable | What a mismatch indicates |
|---|---|---|---|
| **Display name** | Sender, freely | Trivially | The primary deception surface — clients show it, hide the address |
| **From** (header) | Sender | Yes | The identity the user believes; DMARC aligns against this |
| **Return-Path** | Envelope `MAIL FROM` | Yes, but SPF checks it | Differs from From → how a message passes SPF while displaying a spoofed sender |
| **Reply-To** | Sender | Yes | Replies diverted to attacker infrastructure — the BEC mechanic |
| **Sender** | Sender | Yes | On-behalf-of; unusual in consumer mail |

The four canonical mismatches to test:

```
display_name contains an email address ≠ From address       → PH-HDR-001
display_name claims a brand ∉ From domain's brand           → PH-HDR-002
Reply-To domain ≠ From domain                               → PH-HDR-004
Return-Path domain ≠ From domain                            → PH-HDR-005
```

### 4.2 The Received chain — read it backwards

**Received headers are prepended.** Index 0 is the *last* hop (your own MTA); the highest index
is the *originating* server. Walking the list forwards and taking the first IP reports your own
mail gateway as the attacker.

```python
def originating_ip(hops):
    # oldest first: reversed(hops)
    for hop in reversed(hops):
        ip = hop.from_ip
        if ip and not is_private(ip):     # skip internal relays
            return ip
    ...
```

Parse each hop into `from_host`, `from_ip` (prefer the bracketed literal — that is what the
server actually observed), `by_host`, `with_protocol`, `timestamp`. Compute per-hop delays;
a large gap indicates queuing or an intermediary relay.

`X-Originating-IP` (and `X-Sender-IP`, `X-Source-IP`) short-circuit this when present, but they
are sender-supplied in some clients — prefer the Received chain when they disagree.

### 4.3 BCC detection

Two independent signals:

```
no To and no Cc header at all
OR the envelope recipient (Delivered-To / X-Envelope-To) appears in neither To nor Cc
```

BCC hides the recipient list — it conceals campaign scope and prevents recipients from seeing
each other. Combined with an empty body and an attachment (§7.5) it is a strong pattern.

### 4.4 Sender domain reputation signals

| Signal | Weight |
|---|---|
| **Disposable provider** (mailinator, guerrillamail, yopmail…) | high |
| **Free webmail** + a claimed corporate/brand identity | high — organisations send from their own domains |
| Free webmail alone | none — legitimate for individuals |
| **High-abuse TLD** (`.zip .mov .top .xyz .click .tk .gq .cf .ml`) | low — a weight, never a verdict |
| Missing Message-ID | low — points to a script rather than a mail client |
| Single-hop or absent Received chain | low/medium — direct injection or stripped headers |

`.zip` and `.mov` deserve special mention: they are valid TLDs *and* file extensions, so
`invoice.zip` in body text auto-links to a live domain in many clients.

---

## 5. Authentication: SPF, DKIM, DMARC, S/MIME

### 5.1 SPF — is this server allowed to send for this domain?

A DNS TXT record listing authorised senders. The receiving server looks it up and evaluates the
connecting IP against it.

```
v=spf1 ip4:127.0.0.1 include:_spf.google.com -all
────── ─────────────  ────────────────────── ────
version  IPv4 allowed   domain allowed        fail all others
```

Mechanisms: `ip4:` / `ip6:` (address), `a` / `mx` (the domain's own records), `include:`
(delegate to another domain's record), `all` (the catch-all, always last).

Qualifiers on `all`: `-all` fail (reject) · `~all` softfail (accept and flag) · `?all` neutral ·
`+all` pass-everything (effectively no protection).

**Result → prescribed action** (implement this table exactly):

| Result | Action | Meaning |
|---|---|---|
| **Pass** | Accept | Server is authorised |
| **Neutral** | Accept | Domain explicitly takes no position |
| **None** | Accept | No SPF record published |
| **SoftFail** | **Flag** | Not authorised, but `~all` asks receivers to accept and mark suspicious |
| **PermError** | **Flag** | Record unparseable, or the 10-DNS-lookup limit exceeded |
| **Fail** | **Reject** | Not authorised, `-all` |
| **TempError** | **Reject** | Transient DNS failure |

**SPF's limitation:** it validates the *envelope* sender (`Return-Path`), not the `From:` header
the user sees, and it **breaks on forwarding** because the forwarder's IP is not in the original
domain's record. That is the gap DKIM and DMARC close.

### 5.2 DKIM — was this message altered, and does the domain vouch for it?

The sending server signs the message with a private key; the receiver fetches the public key from
DNS at `<selector>._domainkey.<domain>` and verifies.

```
v=DKIM1; k=rsa; p=<public_key>
──────── ─────  ──────────────
version  key type  public key
```

DKIM **survives forwarding** (the signature covers the message, not the connection), which makes
it the stronger of the two and the foundation for DMARC.

`permerror` causes: invalid signature, missing or wrong DNS record, a forwarder or mailing list
modifying the body or headers, or a misconfigured setup. On a forwarded message, a DKIM failure
is far more meaningful than an SPF failure.

### 5.3 DMARC — alignment and policy

DMARC ties SPF and DKIM results to the domain in the **From header** the user actually sees.

```
v=DMARC1; p=quarantine; rua=mailto:postmaster@website.com
────────  ────────────  ───────────────────────────────
version   policy        aggregate report destination
```

Tags: `p=` policy (`none` | `quarantine` | `reject`) · `sp=` subdomain policy · `pct=` rollout
percentage · `rua=` aggregate reports · `ruf=` forensic reports · `adkim=`/`aspf=` alignment
strictness (`r` relaxed, `s` strict).

**Alignment is the whole point.** DMARC passes when SPF *or* DKIM passes **and** the
corresponding domain aligns with the From domain:

```
SPF alignment:  Return-Path domain  ≈  From domain
DKIM alignment: header.d            ≈  From domain
(relaxed: organisational domain match; strict: exact)
```

Without alignment, an attacker registers `evil.example`, publishes a valid SPF record for it,
sends from an authorised host, **passes SPF**, and still displays `From: service@paypal.com`.
DMARC is what makes that fail.

`p=none` is a monitoring-only policy — a DMARC "fail" under `p=none` still gets delivered. When
you report a DMARC failure, state the policy, because it determines whether the control actually
did anything.

### 5.4 Parsing authentication results

```
Authentication-Results: mx.example.org;
  spf=fail smtp.mailfrom=sultanbogor.example;
  dkim=permerror header.d=beginpro.example;
  dmarc=fail p=reject header.from=sultanbogor.example
```

Also read `Received-SPF:`, `ARC-Authentication-Results:` and vendor `X-` headers
(`X-Forefront-Antispam-Report`, `X-MS-Exchange-Authentication-Results`).

**Two implementation traps:**

1. **Attribute the domain by the keyword in the *same* match.** A look-behind window picks up
   the previous clause's keyword and silently swaps the SPF and DKIM domains.

   ```python
   # correct: capture the key alongside the domain
   _AUTH_DOMAIN = re.compile(
       r"\b(?P<key>header\.d|header\.from|smtp\.mailfrom|envelope-from)\s*=\s*"
       r"[<]?(?:(?P<local>[A-Za-z0-9._%+\-]+)@)?"
       r"(?P<domain>[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})", re.I)
   ```

2. **Make the local part non-greedy against the domain.** `([A-Za-z0-9._%+\-]*@?)([A-Za-z0-9.\-]+\.\w{2,})`
   parses `smtp.mailfrom=sultanbogor.example` as domain `r.example`. Require the `@` when a local
   part is present.

**Trust boundary:** these headers are assertions by *whoever wrote them*. An attacker can forge
`Authentication-Results` in a message they compose. Only the header added by **your own boundary
MTA** (normally the topmost) is trustworthy. Take the first assertion of each method and ignore
lower ones.

### 5.5 What passing authentication does and does not prove

| Passes SPF+DKIM+DMARC | Interpretation |
|---|---|
| ✅ | The message genuinely came from infrastructure authorised by the From domain |
| ❌ | The sender is trustworthy |

An attacker's **own** domain passes all three. A **compromised legitimate account** (BEC) passes
all three. Authentication proves the domain is real; it says nothing about intent. This is why
the BEC sample in §13 passes SPF, DKIM and DMARC and is still the most dangerous message in the
corpus — and why a passing result should reduce the score (a negative weight) rather than
short-circuit the analysis.

### 5.6 S/MIME

Public-key cryptography applied to the message itself, providing two independent features:

| Feature | Mechanism | Provides |
|---|---|---|
| **Digital signature** | Sender signs with their **private** key; recipient verifies with the sender's **public** key | Authentication (identity via certificate), Non-repudiation (cannot deny sending), Integrity (detects post-signing changes) |
| **Encryption** | Sender encrypts with the **recipient's public** key; only the recipient's private key decrypts | Confidentiality |

Sequence: Bob signs with his private key → shares his public key with Mary → obtains Mary's
public key → encrypts → Mary verifies with Bob's public key and decrypts with her private key.
Both then hold each other's certificates for future correspondence.

Detection relevance: S/MIME parts appear as `application/pkcs7-signature` or
`application/pkcs7-mime`. A *broken* signature on a normally-signed correspondent is a strong
tamper signal. Encrypted bodies are opaque to content scanning — a policy consideration, not a
detection.

---

## 6. Body and URL analysis

### 6.1 Extract from three places

A URL present in only one of these is usually the interesting one:

| Source | What it is |
|---|---|
| **Rendered text** | What the user reads |
| **HTML `href` / `src`** | Where the click actually goes |
| **Raw source** | Obfuscated, commented-out, or hidden elements |

Regexes:

```python
_HREF_RE = re.compile(
    r"""<\s*a\b[^>]*?href\s*=\s*(?P<q>["']?)(?P<url>[^"'\s>]+)(?P=q)[^>]*>(?P<text>.*?)</\s*a\s*>""",
    re.I | re.S)
_SRC_RE  = re.compile(
    r"""<\s*(?P<tag>img|iframe|script|link|form|embed|source)\b[^>]*?"""
    r"""(?:src|action|href)\s*=\s*(?P<q>["']?)(?P<url>[^"'\s>]+)(?P=q)""", re.I)
_URL_RE  = re.compile(r"""\b(?:(?:https?|ftp|file)://|www\d?\.)[^\s<>"'`\]\)\}]{2,2000}""", re.I)
```

Capture the **anchor text** with the href — the comparison between them is a rule of its own.
Skip `mailto:`, `tel:`, `javascript:`, `data:`, `cid:` and fragments.

### 6.2 Link manipulation — anchor text vs href

The shipping-notification pattern: anchor text reads `ups.example/track/1Z999AA10123456784`,
the href is `http://198.51.100.203/track/redirect.php?id=8891`.

**Only fire when the anchor text is itself URL- or domain-shaped.** "Cancel the order" is a
label, not a claimed destination — treating every call-to-action as a mismatch makes the rule
useless. Compare registrable domains, not full hostnames, so `mail.github.com` vs
`github.com/settings` does not fire.

### 6.3 URL shorteners

Maintain a set (`bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `ow.ly`, `is.gd`, `cutt.ly`,
`rebrand.ly`, `rb.gy`, `t.ly`, `linktr.ee`, `shorturl.at`, …). A shortener hides the destination
from both the user and content filters. Legitimate transactional mail links to its own domain.

**Expand without visiting**: wheregoes.com, urlscan.io, or appending `+` / `/preview` on some
services. Never click to find out.

### 6.4 Redirect chains and link rewriting

Corporate gateways rewrite links (Microsoft Safe Links, Proofpoint URL Defense, Mimecast,
Cisco/Symantec Click Protect). **Unwrap before judging** — a wrapped malicious URL still reaches
the user, and an un-unwrapped one looks like a trusted Microsoft domain.

```python
REWRAPPERS = {
    "safelinks.protection.outlook.com": ("url",),
    "urldefense.proofpoint.com": ("u",), "urldefense.com": ("u",),
    "protect-us.mimecast.com": ("u",), "protect.mimecast.com": ("u",),
    "clicktime.symantec.com": ("u",), "secure-web.cisco.com": ("u",),
    "linkprotect.cudasvc.com": ("a",), "google.com": ("q", "url"),
}
```

Unwrap recursively (cap ~6) and keep the chain as evidence — it shows what the rewriter was
hiding. Multi-stage redirection is the mechanism behind layered lures: a share page, then a
document page, then the login portal.

### 6.5 Per-URL red flags

| Flag | Detection | Why |
|---|---|---|
| **IP literal** | host parses as an IP | Legitimate services use named hosts with certificates |
| **Lookalike domain** | §6.6 | The harvesting page's home |
| **Credential path** | path contains `login`, `signin`, `verify`, `account`, `secure`, `billing`, `password`, `owa`, `webmail`… | Shape of a harvesting portal |
| **Userinfo `@`** | `@` in netloc | Everything left of `@` is ignored by the browser — `https://paypal.com@evil.ru/` goes to evil.ru |
| **Deep subdomain chain** | ≥5 labels | Pushes a trusted-looking name left of the real domain |
| **Very long URL** | >150 chars | Length obscures the destination |
| **Heavy percent-encoding** | ≥4 `%XX` | Obfuscation |
| **Punycode** | host contains `xn--` | IDN homoglyph of a real brand |
| **Abused hosting** | host in a known-abused-platform set | Good domain reputation, attacker-controlled content |

The abused-hosting set matters because it defeats reputation checks by design: Firebase, Azure
Blob, `*.web.app`, `*.pages.dev`, `*.workers.dev`, `*.netlify.app`, `*.vercel.app`,
`*.github.io`, `*.glitch.me`, `*.repl.co`, `*.duckdns.org`, `*.ngrok-free.app`,
`*.000webhostapp.com`, `*.wixsite.com`, Google Forms/Docs/Sites, `*.typeform.com`,
`*.jotform.com`. The platform's trustworthiness says nothing about the page.

### 6.6 Lookalike domain detection

Four techniques, in decreasing obviousness:

| Technique | Example | Detection |
|---|---|---|
| **exact-skeleton** | `paypa1.com`, `netfIix.com`, `micros0ft.com`, `arnazon.com` | Fold to a visual skeleton; compare |
| **typo** | `gogle.com`, `linkedln.com` | Levenshtein ≤1 (short brands) or ≤2 |
| **brand-in-label** | `paypal-secure.com`, `verify-apple-id.net`, `applesupport.co` | Brand as a delimiter-separated token, or glued to a decoy affix at a token edge |
| **brand-subdomain** | `paypal.com.verify-account.ru` | Brand appears in a subdomain of an unrelated registrable domain |

The last is the most convincing to a human: the real brand appears **left** of the actual domain,
and readers parse left to right.

**Skeleton folding — apply case-sensitive swaps first:**

```python
CASE_HOMOGLYPHS = {"I": "l", "O": "0", "S": "5", "B": "8", "Z": "2", "G": "6"}
HOMOGLYPHS = {"0":"o","1":"l","3":"e","4":"a","5":"s","$":"s","@":"a","|":"l",
              "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","і":"i",  # Cyrillic
              "α":"a","ο":"o","ρ":"p","ν":"v","ι":"i"}                   # Greek
MULTI = [("rn","m"), ("vv","w"), ("cl","d"), ("ii","u"), ("nn","m")]
```

A capital `I` is visually identical to a lowercase `l` in most sans-serif fonts — that is how
`netfIix.com` reads as `netflix.com`. **Lowercasing before folding destroys this signal**, so
`registrable()` (which lowercases) must not be the source of the string you fold.

**Two precision guards, both learned from false positives:**

1. **Anchor substring matches at a token edge.** `"delivery"` contains `"live"` — without
   anchoring, `live-stream.tv` matches `live.com`. Require the brand to be a whole
   hyphen/underscore token, or to start/end a token with a decoy affix in the remainder.
2. **Brand labels that are ordinary English words need a second signal.** `live`, `target`,
   `chase`, `stripe`, `meta`, `apple`, `shell`, `orange`, `square`, `discover` — require a decoy
   affix elsewhere in the domain, or `apple-orchard-farm.co.uk` and `chase-the-sun.blog` become
   phishing.

Also exclude the brand's own infrastructure first: `paypalobjects.com` and `microsoftonline.com`
are legitimate and must be checked against the brand's domain set before any similarity test.

Validation target: on the reference implementation, 14/14 true positives and 0/26 false
positives.

### 6.7 Tracking pixels

A tiny or hidden remote image whose only purpose is to fire a request on open, telling the sender
the mailbox is live, when it was read, and often the client and IP — confirming the address as a
target for follow-up. **This is why mail clients block remote images by default.**

```python
def is_tracking_pixel(img_tag, url):
    dims = parse width/height
    if width <= 3 and height <= 3:                      return True
    if CSS display:none | visibility:hidden | opacity:0: return True
    if url matches (pixel|beacon|track|open\.gif|spacer|clear\.gif|1x1|blank\.gif|wt\.gif):
                                                         return True
    if width == 1 or height == 1:                        return True
```

Marketing mail also uses them. Weight `medium`; the finding is that remote content should not be
loaded, and the tracking host is an IOC.

---

## 7. Attachment analysis

### 7.1 Extraction and hashing

For each part with a filename or `Content-Disposition: attachment`: decode the payload, record
`filename`, `content_type`, `content_disposition`, `transfer_encoding`, `size`, and compute
**MD5, SHA1 and SHA256**. SHA256 is the lookup key; MD5/SHA1 appear in older feeds and reports.

```bash
sha256sum shady_attachment.pdf
025ba9ce4a2118a9ca7b115c8869ff73bc16bad3732ba359cef1e60ad8f961f9  shady_attachment.pdf
```

### 7.2 Dangerous extension classes

```python
DANGEROUS = {  # direct execution / scripting
  "exe","scr","com","pif","cpl","msi","msp","bat","cmd","vb","vbs","vbe","js","jse",
  "ws","wsf","wsc","wsh","ps1","ps1xml","psc1","scf","lnk","inf","reg","hta","jar",
  "py","sh","apk","iso","img","vhd","chm","dll","ocx","url","settingcontent-ms",
  "library-ms","appref-ms","diagcab","application","gadget"}

MACRO_CAPABLE = {  # legacy Office + explicit macro formats
  "doc","dot","xls","xlt","xla","ppt","pot","pps",
  "docm","dotm","xlsm","xltm","xlam","pptm","potm","ppam","ppsm","sldm","mht","mhtml"}

ARCHIVE = {"zip","rar","7z","gz","tar","bz2","cab","ace","arj","lzh","xz"}
```

Note `.dot` and `.dotm` specifically: a **Word template** is a bizarre format for a receipt or
invoice, and that mismatch between format and stated purpose is itself the finding.

### 7.3 Double extensions

```python
def has_double_extension(filename):
    parts = filename.lower().split(".")
    return len(parts) >= 3 and parts[-2] in BENIGN_EXT and parts[-1] in DANGEROUS
```

`invoice.pdf.exe` — Windows hides known extensions by default, so the user sees `invoice.pdf`.
Weight this highest of all attachment rules.

### 7.4 Magic bytes vs. extension

```
MZ      (0x4D5A)   PE executable — .exe/.dll/.scr/.sys
%PDF               PDF
PK      (0x504B)   ZIP container — includes all OOXML (.docx/.xlsx/.pptx)
D0 CF 11 E0        OLE2 compound file — legacy Office (.doc/.xls/.ppt/.dot)
7F 45 4C 46        ELF
```

A file whose content starts `MZ` but is named `.pdf` is a renamed executable. Deliberate
mislabelling defeats extension-based filtering *and* misleads the user — treat as critical.

### 7.5 Embedded URLs — the link hidden inside the file

Putting the URL in a document instead of the body keeps it away from link scanners and URL
reputation checks that only read the body. **Extract and analyse embedded URLs exactly as if
they had been in the body.**

**PDF** — link annotations plus plaintext, including inside compressed streams:

```python
re.finditer(rb"/URI\s*\(([^)]{4,2000})\)", data)                    # link annotations
re.finditer(rb"https?://[^\s<>\"'()\\\]]{4,500}", data)             # plaintext
# then zlib.decompress each  stream...endstream  and repeat both
```

**OOXML** (`.docx`/`.xlsx`/`.pptx`, ZIP containers) — external relationship targets:

```python
zipfile → any *.rels: Target="https://..." TargetMode="External"
        → presence of word/vbaProject.bin or */vbaProject.bin ⇒ VBA macros present
```

**Filter XML namespace declarations** or every OOXML file yields a dozen
`schemas.openxmlformats.org` / `www.w3.org` "links" that swamp the one real external target:

```python
NS_NOISE = ("schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org",
            "purl.org", "schemas.xmlsoap.org", "docs.oasis-open.org")
```

### 7.6 Structural signals

| Signal | Weight | Why |
|---|---|---|
| **Empty body + attachment** | high | The message's entire purpose is delivery; a legitimate sender explains what they are sending |
| **Archive attachment** | medium | Contents opaque to filters |
| **ISO / IMG container** | medium-high | Also bypasses Mark-of-the-Web, so extracted files skip the "downloaded from the internet" warning |
| **Password-protected archive** (password in the body) | high | Defeats AV scanning by design |

### 7.7 Payload behaviour to expect

When a document link executes a payload (`regasms.exe` in the DHL sample), the intent is:

- **Persistence** — backdoor, scheduled task, run key, service
- **Data exfiltration** — files, credentials, browser-stored passwords
- **Ransomware** — encrypt and demand payment

A sandbox run failing to execute does not lower the severity: the *attempt* to execute code on
the endpoint is the finding.

---

## 8. Social engineering analysis

### 8.1 Taxonomy

| Type | Definition |
|---|---|
| **Spam** | Unsolicited bulk mail |
| **Malspam** | Bulk mail carrying a malicious payload |
| **Phishing** | Impersonates a trusted entity to obtain sensitive information |
| **Spear phishing** | Targeted at a specific individual/org, using personalised detail |
| **Whaling** | Spear phishing aimed at executives (CEO, CFO) for data or financial access |
| **BEC** | Adversary uses a legitimate (often compromised) account to induce fraudulent action |
| **Smishing** | Delivered by SMS |
| **Vishing** | Conducted by voice call |

### 8.2 Anatomy of a phishing email

| Characteristic | Detection |
|---|---|
| Spoofed From address | §4.1 |
| Urgent subject or message | §8.3 |
| Brand impersonation | §6.6 + display-name/domain comparison |
| Grammar & spelling issues | §8.4 — **weak and getting weaker** |
| Generic content ("Dear Customer") | greeting term list |
| Hidden or shortened links | §6.3, §6.2 |
| Malicious attachments | §7 |

### 8.3 Lure scoring

Category term lists, weighted; subject-line hits weigh more because that is where pressure is
applied first:

```
urgency     ×4   urgent, immediately, act now, expires today, within 24 hours,
                 final notice, last warning, action required, time sensitive
threat      ×4   suspended, deactivated, locked, terminated, unauthorized,
                 will be deleted, legal action, avoid interruption, failure to comply
credential  ×6   verify your account, confirm your identity, update your billing,
                 re-enter, sign in to continue, unlock your account, payment details
BEC         ×5   wire transfer, change of bank, updated bank details, quick favour,
                 are you at your desk, keep this confidential, I'm in a meeting,
                 purchase gift cards, sent from my iPhone
financial   ×2   invoice, refund, transaction, gift card, overdue, tax refund, prize
greeting    +3   dear customer/user/client/member/valued customer/account holder
CTA         ×2   click here, download document, view document, open the attached
misspelling ×8   §8.4
subject pressure +5
```

Fire a "high social-engineering density" finding at a combined score ≥30. The point is the
**combination** — multiple independent lure categories together — not any single term.

### 8.4 Deliberate brand misspellings

```
netllx netflx netlfix netfilx  → Netflix
microsof micosoft mircosoft    → Microsoft
paypa1 payapl paypall          → PayPal
amazom arnazon                 → Amazon
app1e aple appie               → Apple
goggle gogle googie            → Google
linkedln 1inkedin              → LinkedIn
0utlook outiook                → Outlook
```

These are **techniques, not typos** — a near-miss spelling reads correctly at a glance while
evading exact-match brand filters. Weight them high.

But treat general grammar and spelling quality as a **weak** signal: with AI, attackers generate
polished, error-free copy. Do not build a rule that depends on the message reading badly. The
structural signals — sender mismatch, authentication failure, lookalike domain, hidden link —
are what survive.

### 8.5 BEC

The hardest class to detect because it has **no technical payload**: no link, no attachment. The
payload is the instruction. It typically passes SPF, DKIM and DMARC (the account is real, or the
attacker's domain is properly configured), so the gateway has nothing to catch.

Detection is the combination:

```
(no URL) AND (no attachment) AND (BEC terms present)
  → optionally + Reply-To divergence
  → optionally + executive title in subject/body
  → optionally + free-webmail sender with a corporate display name
```

Response is procedural, not technical: **verify out of band** on a known-good number. Never
confirm by replying to the thread.

---

## 9. Detection rules and scoring

### 9.1 Rule catalogue

Rule ID scheme: `PH-HDR-*` header/identity · `PH-AUTH-*` authentication · `PH-URL-*` links ·
`PH-ATT-*` attachments · `PH-SOC-*` social engineering.

| ID | Title | Sev | Score | ATT&CK |
|---|---|---|---|---|
| PH-HDR-001 | Display name contains a different email address than the real sender | critical | +35 | T1566.002 |
| PH-HDR-002 | Display name impersonates a brand the domain does not belong to | critical | +30/+40¹ | T1566.002 |
| PH-HDR-003 | Generic authority display name from an unrelated domain | medium | +12 | T1566 |
| PH-HDR-004 | Reply-To differs from From | high/low² | +22/+3 | T1534 |
| PH-HDR-005 | Return-Path domain ≠ From domain | medium | +14 | T1566 |
| PH-HDR-006 | Recipient BCC'd rather than addressed | medium | +12 | T1566 |
| PH-HDR-007 | Disposable email provider | high | +20 | T1566 |
| PH-HDR-008 | Corporate identity from free webmail | high | +18 | T1566.002 |
| PH-HDR-009 | Sending domain imitates a brand | critical | +35 | T1583.001 |
| PH-HDR-010 | High-abuse TLD | low | +8 | — |
| PH-HDR-011/012 | No / single-hop Received chain | medium/low | +10/+5 | — |
| PH-HDR-013 | Missing Message-ID | low | +6 | — |
| PH-HDR-014 | Body impersonates a brand the sender is not | high | +20 | T1566.002 |
| PH-AUTH-001 | SPF fail / softfail / permerror / temperror / neutral / none | crit→low | +30/18/12/10/5/6 | T1566 |
| PH-AUTH-002 | DKIM fail / permerror / temperror / none | crit→low | +28/16/8/6 | T1566 |
| PH-AUTH-003 | DMARC fail | critical | +32 | T1566 |
| PH-AUTH-004 | No DMARC evaluation despite an SPF/DKIM failure | medium | +10 | — |
| PH-AUTH-005 | No Authentication-Results header | medium | +8 | — |
| PH-AUTH-006 | **SPF+DKIM+DMARC all pass** | info | **−12** | — |
| PH-URL-001 | URL shortener | high | +20 | T1566.002 |
| PH-URL-002 | Link domain imitates a brand | critical | +35 | T1583.001 |
| PH-URL-003 | Link to a bare IP | high | +25 | T1566.002 |
| PH-URL-004 | Tracking pixel | medium | +12 | T1598 |
| PH-URL-005 | Link text ≠ destination | critical | +30 | T1566.002 |
| PH-URL-006 | Credential/payment path on a non-brand host | high | +18 | T1566.002, T1056 |
| PH-URL-007 | Hosted on a commonly abused platform | medium | +12 | T1583.006 |
| PH-URL-008 | Passes through a redirect/rewriting service | medium | +10 | — |
| PH-URL-009 | No link points back to the sender's domain | low | +6 | — |
| PH-ATT-001 | Double extension | critical | +40 | T1566.001, T1036.007 |
| PH-ATT-002 | Executable attachment | critical | +38 | T1566.001, T1204.002 |
| PH-ATT-003 | Macro-capable document | high | +22 | T1566.001, T1221 |
| PH-ATT-004 | Attachment contains embedded links | high | +24 | T1566.001 |
| PH-ATT-005 | File type ≠ extension (magic bytes) | critical | +35 | T1036.008 |
| PH-ATT-006 | Archive/container attachment | medium | +14 | T1566.001, T1553.005 |
| PH-ATT-007 | Empty body with an attachment | high | +20 | T1566.001 |
| PH-SOC-001 | Deliberately misspelled brand name | high | +22 | T1566 |
| PH-SOC-002 | Artificial urgency / consequence framing | med-high | +10/+16 | T1566 |
| PH-SOC-003 | Requests credentials or payment details | high | +25 | T1598.003 |
| PH-SOC-004 | BEC pattern (no link, no attachment) | critical | +28 | T1534 |
| PH-SOC-005 | Generic greeting | low | +6 | T1566 |
| PH-SOC-006 | Executive impersonation/targeting | high | +18 | T1566, T1534 |
| PH-SOC-007 | Attention-grabbing subject formatting | low | +4 | — |
| PH-SOC-008 | High social-engineering density | medium | +8 | — |

¹ +40 when the sender is also free webmail. ² `high` when the Reply-To is on a different
organisational domain; `low` when same-org (a legitimate no-reply → support pattern). Two
accounts at a free or disposable provider (gmail.com → another gmail.com mailbox) are two
different people, never "same-org", so that is `high` too.

### 9.2 Verdicts

```
score ≥ 50 AND weaponised attachment  → MALICIOUS
score ≥ 50                            → PHISHING
score ≥ 25                            → SUSPICIOUS
score ≥ 10                            → SPAM
otherwise                             → BENIGN
```

**MALICIOUS is reserved for weaponised mail** — one carrying an executable, double-extension or
macro-capable attachment. A credential-harvesting page with no payload is PHISHING however high
it scores. The distinction changes the response (host containment and hash hunting vs. credential
reset and URL blocking), so collapsing them misleads the responder.

### 9.3 Design rules

1. **No single indicator decides.** Weighted sum, thresholded. This is what keeps legitimate
   marketing mail (urgency + tracking pixel + shortener) out of the phishing bucket while a
   spoofed sender with a lookalike link lands squarely in it.
2. **Negative weights exist.** Passing authentication reduces the score. A model that can only
   accumulate suspicion will eventually flag everything.
3. **Severity and confidence are orthogonal.** Severity = impact if true; confidence =
   probability it is true. Keep them separate or the queue stops being triageable.
4. **Every rule carries a recommendation.** A finding an analyst cannot act on is noise.
5. **A broken rule must not kill the case.** Wrap each check in try/except and emit an error
   finding.
6. **Three mandatory exclusions on the cleartext-credentials rule** (PH-MITM-style), or it becomes
   a false-positive engine: skip WAF-blocked events, skip events carrying an attack signature,
   and require the submitter to be internal. An external POST to `/admin/login.php` is someone
   attacking *you*.

---

## 10. IOC extraction, defanging and export

### 10.1 Defanging

Not cosmetic. An analyst pastes indicators into tickets, chat and reports that render links as
clickable; one accidental click on a live phishing URL from a corporate machine is an incident.
**Everything that leaves the tool toward a human is defanged.**

```
http://www.suspiciousdomain.com  →  hxxp[://]www[.]suspiciousdomain[.]com
1.2.3.4                          →  1[.]2[.]3[.]4
bob@evil.com                     →  bob[@]evil[.]com
```

Defang only the dots in the **host** portion so paths stay readable. Implement `refang()` too —
machine formats (MISP, STIX, blocklists) need live values.

### 10.2 Indicator set

```
sender_addresses, sender_domains, reply_to
originating_ips (Received chain + X-Originating-IP)
urls (+ every step of each redirect chain), url_domains
attachment_names, attachment_md5 / sha1 / sha256
message_ids, subjects
```

Include **URLs extracted from inside attachments** — they are frequently the only live indicator.

### 10.3 Export formats

| Format | Values | Use |
|---|---|---|
| text | defanged | reading, tickets |
| json | defanged | tooling |
| csv | defanged, `type,misp_type,value` | spreadsheets, bulk import |
| **misp** | **refanged** | MISP event with typed attributes and `to_ids` flags |
| **stix** | **refanged** | STIX 2.1 indicator bundle with patterns |
| **blocklist** | **refanged** | paste into a gateway, proxy or firewall |

MISP type mapping: `email-src`, `email-reply-to`, `domain`, `ip-src`, `url`, `filename`,
`sha256`, `md5`, `sha1`, `email-subject`, `email-message-id`.

### 10.4 Only export indicators from bad verdicts

Merging a benign message's artifacts into a blocklist is how a SOC ends up blocking `github.com`.
Filter by verdict before merging across a corpus; provide an explicit `--all` override for
corpus-wide extraction, and print how many messages were skipped.

---

## 11. Tooling and enrichment

### 11.1 The analyst stack

| Purpose | Tools |
|---|---|
| **Header analysis** | Google Admin Toolbox **Messageheader**, **MHA** (mha.azurewebsites.net) |
| **SPF/DKIM/DMARC records** | dmarcian **SPF Surveyor**, **DKIM Inspector/Validator**, **Domain Checker** |
| **IP geolocation / ownership** | **IPinfo**, AbuseIPDB |
| **URL investigation** | **URLScan.io** (browses the site for you, screenshots the landing page) |
| **IP/domain/hash reputation** | **Cisco Talos Reputation Center**, **VirusTotal** |
| **Malware sandboxes** | **ANY.RUN** (interactive), **Hybrid Analysis**, **Joe Sandbox** |
| **Encoding / extraction** | **CyberChef** (`From_Base64`, `Extract_URLs`, `Defang_URL`, `Defang_IP_Addresses`) |
| **End-to-end platform** | **PhishTool** — rendered HTML, raw HTML, message source, authentication results, transmission path, URLs, attachments, VirusTotal integration, and case resolution in one place |

### 11.2 Disclosure discipline — the part tooling guides omit

Submitting an indicator **is a disclosure**. Two directions of risk:

| Action | Risk |
|---|---|
| **Hash lookup** (VT by SHA256) | None. The hash reveals nothing about content. **Always safe.** |
| **File upload** to a public sandbox | The file may contain customer data, internal documents, or the recipient's identity. Public VT/ANY.RUN submissions are searchable by anyone. |
| **URL submission** to a scanner | A campaign-unique URL (one embedding a victim identifier) tells the operator their campaign was detected, and may burn your detection. |
| **Passive urlscan search** | Safe — queries existing results, submits nothing. **Prefer this.** |

Order of operations: hash lookup → passive search → active scan → sandbox upload. Default
`visibility="unlisted"` on any submission, and never `"public"` for anything embedding a
recipient identifier.

### 11.3 Enrichment implementation

Offline by default. Read keys from the environment (`VT_API_KEY`, `URLSCAN_API_KEY`,
`IPINFO_TOKEN`, `ABUSEIPDB_API_KEY`). Every enrichment result is data, `_error`, or `_skipped` —
**a missing key must never look like a clean verdict.**

---

## 12. SOC workflow and prevention controls

### 12.1 Triage workflow

```
1. Acquire      user report / mail-gateway quarantine → obtain the raw .eml/.msg
2. Contain      do not click; do not load remote images; do not reply
3. Extract      header artifacts + body artifacts (§2)
4. Analyse      identity mismatches → authentication → URLs → attachments → language
5. Enrich       hash lookup → passive search → active scan (§11.2)
6. Decide       verdict from the weighted score (§9.2)
7. Document     findings, IOCs, notes — the case file
8. Respond      §12.2
9. Resolve      close with verdict + flagged artifacts (the PhishTool "Resolve" model)
10. Hunt        search the estate for the same sender / URL / hash — who else received it?
```

Step 10 is the one most often skipped and the one that most changes outcomes. One reported
message is almost never one delivered message.

### 12.2 Response actions by verdict

| Verdict | Actions |
|---|---|
| **Malicious** | Purge from all mailboxes · block sender, domain, URL, hash at gateway/proxy/EDR · hunt for delivery and clicks · if executed, isolate the host and start IR |
| **Phishing** | Purge · block sender/domain/URL · **reset credentials for anyone who clicked** · check for new mailbox rules and OAuth grants (post-compromise persistence) |
| **Suspicious** | Quarantine · request more context from the reporter · monitor the sender |
| **Spam** | Filter · add to the bulk rules |
| **Benign** | Release · thank the reporter — reporting behaviour must not be discouraged |

### 12.3 Prevention controls

**Technical**

| Control | What it does |
|---|---|
| **SPF / DKIM / DMARC** | Authenticate senders; publish `p=reject` on your own domains and enforce inbound |
| **Email filtering** | IP and domain reputation blocking/quarantine (Spamhaus and similar) |
| **Secure Email Gateway (SEG)** | Detects impersonation, spoofing and phishing patterns other filters miss |
| **Link rewriting** (Safe Links) | Replaces URLs with redirected ones so the destination is scanned at click time — defeats "clean at delivery, weaponised later" |
| **Sandboxing** (Safe Attachments) | Detonates attachments and links in isolation before delivery |
| **Disable macros by default** | Removes the largest document-attachment vector |
| **Block dangerous extensions** at the gateway | `.exe .scr .js .vbs .hta .iso .img .lnk` and friends |

**User-facing**

| Control | Purpose |
|---|---|
| **External-sender banners** | Cheap, effective context for impersonation of internal staff |
| **Trust/warning indicators** | "Suspicious link", verified-sender marks |
| **One-click phishing report button** | Reporting friction is the binding constraint on detection speed |
| **Awareness training** | Recognising social engineering, not just spotting typos |
| **Phishing simulations** | Test and reinforce; measure the report rate, not only the click rate |

Note the framing: the report rate is the metric that improves outcomes. A population that clicks
less but reports nothing gives the SOC no visibility.

### 12.4 MITRE ATT&CK mapping

| Technique | ID |
|---|---|
| Phishing | T1566 |
| Phishing: Spearphishing Attachment | T1566.001 |
| Phishing: Spearphishing Link | T1566.002 |
| Phishing for Information | T1598 |
| Phishing for Information: Spearphishing Link | T1598.003 |
| Internal Spearphishing (BEC) | T1534 |
| Acquire Infrastructure: Domains | T1583.001 |
| Compromise Infrastructure: Web Services | T1583.006 |
| User Execution: Malicious File | T1204.002 |
| Masquerading: Double File Extension | T1036.007 |
| Masquerading: Masquerade File Type | T1036.008 |
| Template Injection | T1221 |
| Subvert Trust Controls: Mark-of-the-Web Bypass | T1553.005 |
| Network Sniffing | T1040 |
| Unsecured Credentials in Files | T1552.001 |

---

## 13. Reference implementation

```
phishkit/
├── __init__.py      analyze() / analyze_file() / analyze_bytes() / analyze_directory()
├── models.py        ParsedEmail, EmailAddress, ReceivedHop, ExtractedURL, Attachment,
│                    AuthenticationResults, Finding, AnalysisResult, Verdict, PhishType
├── parser.py        .eml/.msg/MIME parsing, Received chain, auth-results, attachments,
│                    PDF and OOXML embedded-URL extraction
├── brands.py        brand→domain map, homoglyph skeletons, lookalike detection
├── urls.py          extraction, shorteners, rewrapper unwrapping, tracking pixels,
│                    per-URL red flags, anchor-vs-href mismatch
├── social.py        lure term lists, language scoring, phish-type classification
├── detectors.py     45 rules, scoring, verdict mapping
├── iocs.py          defang/refang, collection, CSV/MISP/STIX/blocklist export
├── enrich.py        VirusTotal, urlscan.io, IPinfo, AbuseIPDB (offline by default)
├── report.py        console / JSON / Markdown / self-contained HTML
└── cli.py           analyze | headers | urls | attachments | iocs | defang | refang |
                     enrich | rules
```

```bash
python make_samples.py samples        # 8 .eml samples modelled on the campaign patterns
python tests/test_phishkit.py         # 56 tests, positive AND negative cases

python -m phishkit.cli analyze samples/ -v
python -m phishkit.cli analyze samples/ -f html -o report.html
python -m phishkit.cli headers samples/4_netflix_pdf.eml --all
python -m phishkit.cli urls samples/2_shipping_pixel.eml
python -m phishkit.cli attachments samples/6_dhl_xlsx.eml --extract /tmp/quarantine
python -m phishkit.cli iocs samples/ -f blocklist
python -m phishkit.cli defang "http://evil.com/login"
python -m phishkit.cli rules
```

```python
from phishkit import analyze_file
r = analyze_file("suspicious.eml")
print(r.verdict.value, r.score)                   # phishing 183
for f in r.findings:
    print(f.rule_id, f.severity, f.title)
print(r.iocs["urls"])                             # defanged
```

### Sample corpus and expected verdicts

| Sample | Pattern | Expected |
|---|---|---|
| `1_paypal_shortener.eml` | Spoofed display name + shortener + branded HTML | PHISHING |
| `2_shipping_pixel.eml` | Generic authority sender + tracking pixel + link manipulation | PHISHING |
| `3_credential_harvest.eml` | Brand layering + Safe Links-wrapped redirect chain | PHISHING |
| `4_netflix_pdf.eml` | Brand misspelling + PDF with an embedded link | PHISHING |
| `5_apple_dot_bcc.eml` | BCC delivery + empty body + `.dot` attachment | **MALICIOUS** |
| `6_dhl_xlsx.eml` | Branded HTML + macro-capable `.xlsm` with a remote target | **MALICIOUS** |
| `7_bec_wire.eml` | No link, no attachment, SPF/DKIM/DMARC all **pass** | PHISHING (bec) |
| `8_legitimate.eml` | Real GitHub notification, all auth passing | **BENIGN (score 0)** |

**Validation status:** 56/56 tests pass. Lookalike detection: 14/14 true positives, 0/26 false
positives. The legitimate control sample scores 0 and the marketing-mail control (urgency +
tracking pixel + shortener, all auth passing) stays below the phishing threshold.

---

## Appendix — implementation traps worth knowing

Each of these produced a wrong answer during development:

1. **Received headers are prepended.** Index 0 is the last hop. Walking forwards reports your own
   gateway as the origin. Skip RFC1918 hops when selecting the originating IP.
2. **`_AUTH_DOMAIN` local-part greediness.** `([A-Za-z0-9._%+\-]*@?)([A-Za-z0-9.\-]+\.\w{2,})`
   parses `smtp.mailfrom=sultanbogor.example` as `r.example`. Require `@` when a local part is present.
3. **Attribute auth domains by the keyword in the same match**, not a look-behind window — a
   window picks up the previous clause and swaps the SPF and DKIM domains.
4. **Fold homoglyphs before lowercasing.** Capital `I` ≡ lowercase `l`; `registrable()` lowercases,
   so do not source the folded string from it.
5. **Anchor brand substring matches at token edges.** `"delivery"` contains `"live"`.
6. **Ordinary-word brand labels need a second signal.** `apple-orchard-farm.co.uk` is a farm.
7. **Filter XML namespaces from OOXML URL extraction**, or every document yields a dozen
   `schemas.openxmlformats.org` "links".
8. **Anchor-text mismatch only when the text is domain-shaped.** "Cancel the order" is a label.
9. **Only export IOCs from non-benign verdicts**, or a corpus run puts `github.com` on the blocklist.
10. **`MALICIOUS` ≠ high score.** Reserve it for weaponised attachments; the response differs.
