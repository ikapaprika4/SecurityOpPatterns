"""
Brand impersonation reference data and lookalike-domain detection.

Two questions this module answers:
  1. Does the message *claim* to be a brand (display name, subject, body, logos)?
  2. Does the sending / link domain actually belong to that brand?

The gap between those two answers is brand impersonation, and it is the single
most reusable phishing signal — it survives rewording, translation, and AI
polish, because the attacker cannot change who they need you to believe they are.
"""

from __future__ import annotations

import re
from typing import Optional

# --------------------------------------------------------------------------
# Brand → legitimate domains
# --------------------------------------------------------------------------

BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.co.uk", "paypalobjects.com", "paypal-communication.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                  "live.com", "outlook.com", "sharepoint.com", "onedrive.com",
                  "microsoft365.com", "azure.com", "windows.com", "msn.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com",
               "googleapis.com", "gstatic.com", "goo.gl"},
    "apple": {"apple.com", "icloud.com", "itunes.com", "me.com", "mac.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonaws.com", "aws.amazon.com",
               "amazon.de", "amazon.in", "primevideo.com"},
    "netflix": {"netflix.com", "nflxext.com", "nflximg.net", "netflix.net"},
    "dhl": {"dhl.com", "dhl.de", "dhlexpress.com", "dhlparcel.com"},
    "fedex": {"fedex.com", "fedex.co.uk"},
    "ups": {"ups.com", "upsmail.com"},
    "usps": {"usps.com", "usps.gov"},
    "adobe": {"adobe.com", "adobelogin.com", "acrobat.com", "adobesign.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "linkedin": {"linkedin.com", "licdn.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com", "fbcdn.net"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "citibank": {"citi.com", "citibank.com"},
    "americanexpress": {"americanexpress.com", "aexp.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebaystatic.com"},
    "stripe": {"stripe.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "slack": {"slack.com", "slack-edge.com"},
    "github": {"github.com", "githubusercontent.com"},
    "hmrc": {"hmrc.gov.uk", "gov.uk"},
    "irs": {"irs.gov"},
    "walmart": {"walmart.com"},
    "target": {"target.com"},
    "att": {"att.com"},
    "verizon": {"verizon.com"},
    "spotify": {"spotify.com"},
}

# Terms that identify a brand in display names, subjects and body text.
BRAND_KEYWORDS: dict[str, set[str]] = {
    "paypal": {"paypal", "pay pal"},
    "microsoft": {"microsoft", "office 365", "office365", "onedrive", "sharepoint",
                  "outlook", "ms teams", "microsoft teams", "windows"},
    "google": {"google", "gmail", "g suite", "google drive"},
    "apple": {"apple", "icloud", "itunes", "apple id", "app store"},
    "amazon": {"amazon", "aws", "prime video"},
    "netflix": {"netflix", "netflx", "netlfix", "netfilx", "netllx", "netflix billing"},
    "dhl": {"dhl", "dhl express"},
    "fedex": {"fedex", "federal express"},
    "ups": {"ups", "united parcel"},
    "usps": {"usps", "postal service"},
    "adobe": {"adobe", "acrobat", "adobe sign", "adobe pdf"},
    "docusign": {"docusign", "docu sign"},
    "dropbox": {"dropbox"},
    "linkedin": {"linkedin"},
    "facebook": {"facebook", "meta"},
    "chase": {"chase bank", "jpmorgan"},
    "wellsfargo": {"wells fargo"},
    "bankofamerica": {"bank of america", "bofa"},
    "hsbc": {"hsbc"},
    "barclays": {"barclays"},
    "citibank": {"citibank", "citi bank"},
    "americanexpress": {"american express", "amex"},
    "ebay": {"ebay"},
    "stripe": {"stripe"},
    "coinbase": {"coinbase"},
    "binance": {"binance"},
    "zoom": {"zoom meeting", "zoom video"},
    "slack": {"slack"},
    "github": {"github"},
    "hmrc": {"hmrc", "hm revenue"},
    "irs": {"irs", "internal revenue"},
    "spotify": {"spotify"},
}

# Generic sender identities used to borrow authority without naming a brand.
GENERIC_AUTHORITY = {
    "distribution center", "distribution centre", "shipping department",
    "billing department", "accounts payable", "it helpdesk", "it support",
    "help desk", "security team", "hr department", "human resources",
    "payroll", "system administrator", "postmaster", "mail delivery",
    "customer service", "customer support", "account services", "support team",
}


# --------------------------------------------------------------------------
# Lookalike detection
# --------------------------------------------------------------------------

# Characters an attacker substitutes to build a domain that reads correctly at
# a glance: rn→m, 0→o, 1→l, vv→w, plus Cyrillic/Greek homoglyphs (IDN spoofing).
HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b",
    "9": "g", "$": "s", "@": "a", "!": "i", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ѡ": "w", "ν": "v", "ο": "o",
    "α": "a", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ϲ": "c",
}

MULTI_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"), ("nn", "m")]


# Case-sensitive swaps applied BEFORE lowercasing: a capital I is visually
# identical to a lowercase l in most sans-serif fonts, which is how
# "netfIix.com" reads as "netflix.com". Lowercasing first destroys the signal.
CASE_HOMOGLYPHS = {"I": "l", "O": "0", "S": "5", "B": "8", "Z": "2", "G": "6"}


def skeleton(s: str) -> str:
    """Fold a string to its visual skeleton so homoglyph swaps collapse together."""
    pre = "".join(CASE_HOMOGLYPHS.get(c, c) for c in s)
    out = "".join(HOMOGLYPHS.get(c, c) for c in pre.lower())
    for src, dst in MULTI_HOMOGLYPHS:
        out = out.replace(src, dst)
    return out.replace("-", "").replace("_", "").replace(".", "")


def levenshtein(a: str, b: str, cap: int = 4) -> int:
    """Edit distance with early exit — we only care about small distances."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


# Suffixes appended to a brand to make a plausible-looking domain.
# Brand labels that are also ordinary English words. A bare token match on one
# of these is not evidence; it needs a decoy affix elsewhere in the domain.
AMBIGUOUS_LABELS = {"live", "target", "chase", "stripe", "meta", "apple",
                    "shell", "orange", "square", "discover", "mint", "monitor"}

_DECOY_AFFIXES = ("secure", "login", "signin", "account", "accounts", "verify",
                  "verification", "support", "service", "services", "billing",
                  "update", "confirm", "auth", "portal", "mail", "online", "my",
                  "web", "help", "id", "customer", "alert", "notice", "team")


def registrable(domain: str) -> str:
    """Best-effort eTLD+1. Swap for the Public Suffix List in production."""
    parts = domain.strip(".").lower().split(".")
    if len(parts) < 2:
        return domain.lower()
    multi = {"co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au",
             "co.nz", "com.br", "co.in", "com.cn", "com.tr", "co.za", "com.mx"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in multi:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def brand_of_domain(domain: str) -> Optional[str]:
    """Return the brand a domain legitimately belongs to, if any."""
    d = domain.lower().strip(".")
    for brand, domains in BRANDS.items():
        for legit in domains:
            if d == legit or d.endswith("." + legit):
                return brand
    return None


def lookalike_brand(domain: str) -> Optional[tuple[str, str, str]]:
    """
    Detect a domain that imitates a brand.

    Returns `(brand, legitimate_domain, technique)` or None. Techniques:
      exact-skeleton   homoglyph/typo that folds to the real domain (microsofl.com)
      typo             edit distance 1-2 from the real domain (paypa1.com, gogle.com)
      brand-in-label   brand name plus a decoy affix (paypal-secure.com)
      brand-subdomain  brand name in a subdomain of an unrelated site
                       (paypal.com.verify-account.ru) -- the most convincing form,
                       because the real brand appears left of the actual domain
    """
    d_orig = domain.strip(".")
    d = d_orig.lower()
    if brand_of_domain(d):
        return None                                   # genuinely the brand
    reg = registrable(d)
    reg_label = reg.split(".")[0]
    # Keep the original casing for the skeleton so I/l confusion survives:
    # registrable() lowercases, so slice the cased original by the same length.
    reg_label_cased = d_orig[len(d_orig) - len(reg):].split(".")[0] if len(reg) <= len(d_orig) else reg_label
    if reg_label_cased.lower() != reg_label:
        reg_label_cased = reg_label
    sub_labels = d[: -len(reg)].strip(".").split(".") if d.endswith(reg) and d != reg else []
    sub_labels_cased = (d_orig[: -len(reg)].strip(".").split(".")
                        if d.endswith(reg) and d != reg else [])
    if len(sub_labels_cased) != len(sub_labels):
        sub_labels_cased = sub_labels
    reg_skel = skeleton(reg_label_cased)
    reg_tokens_cased = [t for t in re.split(r"[-_]", reg_label_cased) if t]
    reg_tokens_lower = [t.lower() for t in reg_tokens_cased]

    for brand, legit_domains in BRANDS.items():
        for legit in legit_domains:
            legit_label = legit.split(".")[0]

            # Short brand names (dhl, ups, irs) only match as a whole token --
            # as a substring they collide with ordinary words.
            if len(legit_label) < 4:
                if legit_label in reg_tokens_lower and reg_label != legit_label:
                    return (brand, legit, "brand-in-label")
                continue

            if reg_skel == skeleton(legit_label) and reg_label != legit_label:
                return (brand, legit, "exact-skeleton")

            # The brand appears as its own hyphen/underscore-delimited token,
            # exactly or as a homoglyph: paypal-secure, billing-secure-netfIix.
            if reg_label != legit_label:
                for tok, tok_cased in zip(reg_tokens_lower, reg_tokens_cased):
                    if not (tok == legit_label or skeleton(tok_cased) == skeleton(legit_label)):
                        continue
                    # Brand names that are also ordinary English words need a
                    # second signal, or "live-stream.tv" reads as live.com.
                    if legit_label in AMBIGUOUS_LABELS:
                        others = " ".join(t for t in reg_tokens_lower if t != tok)
                        if not any(afx in others for afx in _DECOY_AFFIXES):
                            continue
                    return (brand, legit, "brand-in-label")

            dist = levenshtein(reg_label, legit_label, cap=2)
            if 0 < dist <= (1 if len(legit_label) <= 6 else 2):
                return (brand, legit, "typo")

            # The brand is glued to a decoy word inside a single token
            # (paypalsecure, applesupport). Anchored at a token edge so the
            # brand is not merely a coincidental substring -- "delivery"
            # contains "live", which must not match live.com.
            for tok in reg_tokens_lower:
                if tok == legit_label or legit_label not in tok:
                    continue
                if not (tok.startswith(legit_label) or tok.endswith(legit_label)):
                    continue
                rest = tok.replace(legit_label, "", 1)
                if any(a in rest for a in _DECOY_AFFIXES) or rest.isdigit():
                    return (brand, legit, "brand-in-label")

            for lab, lab_cased in zip(sub_labels, sub_labels_cased):
                if lab in (legit_label, legit) or skeleton(lab_cased) == skeleton(legit_label):
                    return (brand, legit, "brand-subdomain")
    return None


def brands_mentioned(text: str) -> set[str]:
    """Which brands the message claims to be, from display name / subject / body."""
    low = (text or "").lower()
    found = set()
    for brand, keywords in BRAND_KEYWORDS.items():
        for kw in keywords:
            if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", low):
                found.add(brand)
                break
    return found
