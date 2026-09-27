"""
Social-engineering language analysis.

The lure is the one part of a phishing email the attacker cannot remove: they
must create a reason to act. Grammar and spelling tells are no longer reliable
(AI writes clean copy), but the *pressure structure* — urgency, threat,
authority, a single call to action — remains, because it is the mechanism.

Everything here returns scores, never verdicts. Language alone is weak evidence;
combined with a failed SPF and a lookalike domain it is strong.
"""

from __future__ import annotations

import re
from typing import Optional

# --------------------------------------------------------------------------
# Lure categories
# --------------------------------------------------------------------------

URGENCY_TERMS = [
    "urgent", "immediately", "immediate action", "act now", "right away",
    "as soon as possible", "asap", "time sensitive", "time-sensitive",
    "expires today", "expires in", "expiring", "within 24 hours",
    "within 48 hours", "final notice", "last warning", "last chance",
    "before it's too late", "don't delay", "do not delay", "hurry",
    "limited time", "deadline", "prompt attention", "action required",
    "response required", "requires your attention", "attention required",
]

THREAT_TERMS = [
    "suspended", "suspension", "deactivated", "disabled", "terminated",
    "locked", "lock your account", "closed", "restricted", "on hold",
    "unauthorized", "unauthorised", "fraudulent", "compromised", "breach",
    "will be deleted", "permanently removed", "legal action", "penalty",
    "fine", "prosecution", "failure to comply", "avoid interruption",
    "avoid termination", "service interruption", "cannot be processed",
]

CREDENTIAL_TERMS = [
    "verify your account", "verify your identity", "confirm your identity",
    "confirm your account", "update your account", "update your payment",
    "update your billing", "validate your account", "re-enter", "reenter",
    "sign in to continue", "log in to continue", "login to continue",
    "click here to verify", "confirm your password", "update your password",
    "reset your password", "unlock your account", "reactivate your account",
    "billing information", "payment information", "payment details",
    "card details", "security question", "two-factor",
]

FINANCIAL_TERMS = [
    "invoice", "receipt", "payment", "refund", "transaction", "wire transfer",
    "bank transfer", "gift card", "gift cards", "bitcoin", "cryptocurrency",
    "purchase", "order confirmation", "billing", "overdue", "outstanding balance",
    "tax refund", "prize", "lottery", "inheritance", "beneficiary", "compensation",
]

# Business Email Compromise: no link, no attachment — just an authority-backed
# request for money or data, usually with a secrecy and channel-change element.
BEC_TERMS = [
    "wire transfer", "change of bank", "banking details", "updated bank details",
    "new account details", "invoice payment", "vendor payment", "payment run",
    "are you at your desk", "are you available", "quick favour", "quick favor",
    "i need you to", "keep this confidential", "between us", "don't tell",
    "do not discuss", "handle this discreetly", "i'm in a meeting",
    "in a meeting", "sent from my iphone", "purchase gift cards", "buy gift cards",
    "urgent payment", "process this payment", "confirm the payment",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear client", "dear member", "dear sir",
    "dear madam", "dear sir/madam", "dear account holder", "dear valued customer",
    "dear subscriber", "dear friend", "hello user", "hi there", "dear email user",
    "dear beneficiary", "attention user", "valued customer",
]

CALL_TO_ACTION = [
    "click here", "click below", "click the link", "click the button",
    "download document", "download here", "view document", "open the attached",
    "see attached", "review the attached", "follow the link", "tap here",
    "get started", "continue here", "proceed here", "confirm now", "verify now",
    "update now", "sign in here", "log in here", "access document",
]

# Spelling errors that survive AI polish because they are deliberate — a
# misspelled brand dodges exact-match filters while still reading correctly.
BRAND_MISSPELLINGS = {
    "netllx": "Netflix", "netflx": "Netflix", "netlfix": "Netflix",
    "netfilx": "Netflix", "nettflix": "Netflix",
    "microsof": "Microsoft", "micosoft": "Microsoft", "mircosoft": "Microsoft",
    "micro soft": "Microsoft", "microsft": "Microsoft",
    "paypa1": "PayPal", "payapl": "PayPal", "paypall": "PayPal", "pay-pal": "PayPal",
    "amazom": "Amazon", "amazone": "Amazon", "arnazon": "Amazon",
    "app1e": "Apple", "aple": "Apple", "appie": "Apple",
    "goggle": "Google", "gogle": "Google", "googie": "Google",
    "faceb00k": "Facebook", "facbook": "Facebook",
    "linkedln": "LinkedIn", "1inkedin": "LinkedIn",
    "dhI": "DHL", "dh1": "DHL",
    "0utlook": "Outlook", "outiook": "Outlook",
    "whatsap": "WhatsApp", "whatapp": "WhatsApp",
}


def _count(text: str, terms: list[str]) -> list[str]:
    low = (text or "").lower()
    return [t for t in terms if t in low]


class SocialAnalysis:
    """Container for the lure features found in a message."""

    def __init__(self) -> None:
        self.urgency: list[str] = []
        self.threat: list[str] = []
        self.credential: list[str] = []
        self.financial: list[str] = []
        self.bec: list[str] = []
        self.generic_greeting: list[str] = []
        self.call_to_action: list[str] = []
        self.misspellings: dict[str, str] = {}
        self.excessive_caps: bool = False
        self.excessive_punctuation: bool = False
        self.score: int = 0

    def as_dict(self) -> dict:
        return {
            "urgency": self.urgency, "threat": self.threat,
            "credential_request": self.credential, "financial": self.financial,
            "bec_indicators": self.bec, "generic_greeting": self.generic_greeting,
            "call_to_action": self.call_to_action,
            "brand_misspellings": self.misspellings,
            "excessive_caps": self.excessive_caps,
            "excessive_punctuation": self.excessive_punctuation,
            "score": self.score,
        }


def analyse_language(subject: str, body: str) -> SocialAnalysis:
    """Score the lure. Subject terms weigh more — that is where pressure is applied."""
    sa = SocialAnalysis()
    combined = f"{subject}\n{body}"

    sa.urgency = _count(combined, URGENCY_TERMS)
    sa.threat = _count(combined, THREAT_TERMS)
    sa.credential = _count(combined, CREDENTIAL_TERMS)
    sa.financial = _count(combined, FINANCIAL_TERMS)
    sa.bec = _count(combined, BEC_TERMS)
    sa.generic_greeting = _count(body, GENERIC_GREETINGS)
    sa.call_to_action = _count(combined, CALL_TO_ACTION)

    low = combined.lower()
    for wrong, right in BRAND_MISSPELLINGS.items():
        if re.search(rf"(?<![a-z0-9]){re.escape(wrong)}(?![a-z0-9])", low):
            sa.misspellings[wrong] = right

    letters = [c for c in (subject or "") if c.isalpha()]
    if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.6:
        sa.excessive_caps = True
    if re.search(r"[!?]{2,}", subject or "") or (subject or "").count("!") >= 2:
        sa.excessive_punctuation = True

    sub_low = (subject or "").lower()
    score = 0
    score += min(len(sa.urgency), 3) * 4
    score += min(len(sa.threat), 3) * 4
    score += min(len(sa.credential), 3) * 6
    score += min(len(sa.bec), 3) * 5
    score += min(len(sa.financial), 3) * 2
    score += 3 if sa.generic_greeting else 0
    score += min(len(sa.call_to_action), 2) * 2
    score += len(sa.misspellings) * 8
    score += 3 if sa.excessive_caps else 0
    score += 2 if sa.excessive_punctuation else 0
    # Pressure in the subject line is the attacker's opening move.
    if any(t in sub_low for t in URGENCY_TERMS + THREAT_TERMS):
        score += 5
    sa.score = score
    return sa


def classify_phish_type(subject: str, body: str, has_attachment: bool,
                        has_url: bool, recipient_count: int,
                        exec_targeted: bool = False) -> list[str]:
    """
    Best-effort classification of the vector, using the taxonomy:
    spam / malspam / phishing / spear phishing / whaling / BEC.
    """
    sa = analyse_language(subject, body)
    types: list[str] = []

    if sa.bec and not has_url and not has_attachment:
        types.append("bec")
    if exec_targeted:
        types.append("whaling")
    if sa.credential or (has_url and (sa.urgency or sa.threat)):
        types.append("phishing")
    if has_attachment and (sa.urgency or sa.threat or sa.financial):
        types.append("malspam")
    if recipient_count > 20 and not sa.credential:
        types.append("spam")
    if not types:
        types.append("spam" if sa.score < 10 else "phishing")
    return list(dict.fromkeys(types))


EXECUTIVE_TITLES = (
    "ceo", "chief executive", "cfo", "chief financial", "coo", "cto", "ciso",
    "chief information", "president", "vice president", "vp ", "director",
    "head of finance", "managing director", "chairman", "board member",
    "general counsel", "controller", "treasurer",
)


def targets_executive(text: str) -> Optional[str]:
    low = (text or "").lower()
    for title in EXECUTIVE_TITLES:
        if title in low:
            return title.strip()
    return None
