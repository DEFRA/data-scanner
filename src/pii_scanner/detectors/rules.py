from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

from . import fakes
from .validators import (
    POSTCODE_AREAS,
    digits_only,
    looks_patterned,
    luhn_valid,
    nhs_number_valid,
    nino_valid,
    postcode_area,
)

CATEGORIES = {
    "person_name": "Person name",
    "street_address": "Street address",
    "postcode": "UK postcode",
    "email": "Email address",
    "uk_phone": "UK phone number",
    "dob": "Date of birth",
    "nino": "National Insurance number",
    "bank_account": "Bank sort code and account",
    "payment_card": "Payment card number",
    "passport": "Passport number",
    "driving_licence": "UK driving licence",
    "vehicle_reg": "Vehicle registration",
    "ip_address": "IP address",
    "device_id": "Device identifier",
    "location": "Location coordinates",
    "media": "Photograph, signature or scanned document",
    "case_text": "Correspondence or case notes",
    "customer_ref": "Customer/business reference (CRN, SBI, FRN, CPH)",
    "nhs_number": "NHS number",
    "special_category": "Special category data (health, ethnicity etc.)",
}

# Identify a person directly
IDENTIFIER_RULES = frozenset({
    "person_name", "email", "uk_phone", "dob", "nino", "bank_account", "payment_card", "passport",
    "driving_licence", "vehicle_reg", "customer_ref", "nhs_number",
})
# Only personal data when linked to an individual: dropped outside data files unless an identifier is on the same line
LINKABLE_RULES = frozenset({"postcode", "street_address", "ip_address", "device_id", "location", "case_text"})
COOCCURRENCE_RULES = IDENTIFIER_RULES | LINKABLE_RULES | {"special_category"}


@dataclass
class Candidate:
    rule: str
    value: str
    norm: str
    severity: float
    confidence: float
    fake: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def category(self) -> str:
        return CATEGORIES[self.rule]


# Email ---------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"(?<![\w.%+\-])([A-Za-z0-9][A-Za-z0-9._%+\-]{0,63})@"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![\w\-])"
)
_FILE_TLDS = frozenset(
    "png jpg jpeg gif svg webp ico js mjs cjs ts tsx jsx css scss less json html htm md py java rb go vue map "
    "woff woff2 ttf eot txt xml yml yaml lock zip gz tar pdf csv sh".split()
)


def detect_email(line: str, ctx: str) -> list[Candidate]:
    out = []
    for m in EMAIL_RE.finditer(line):
        local, domain = m.group(1).lower(), m.group(2).lower()
        tld = domain.rsplit(".", 1)[-1]
        if tld in _FILE_TLDS or domain.endswith(fakes.RESERVED_EMAIL_SUFFIXES):
            continue
        if domain.endswith(fakes.SERVICE_EMAIL_DOMAINS) or local in fakes.ROLE_LOCAL_PARTS:
            continue
        if re.fullmatch(r"[0-9a-f]{16,}", local):
            continue  # hashes/keys in DSNs
        c = Candidate("email", m.group(0), f"{local}@{domain}", 4.0, 0.9)
        if domain in fakes.PERSONAL_EMAIL_DOMAINS:
            c.severity = 6.0
            c.notes.append("personal webmail domain")
        elif domain.endswith(fakes.WORK_EMAIL_SUFFIXES):
            c.severity = 2.5
            c.notes.append("public sector work address")
        if domain in fakes.FAKE_EMAIL_DOMAINS:
            c.fake.append("placeholder email domain")
        if local in fakes.FAKE_EMAIL_LOCAL_PARTS:
            c.fake.append("placeholder email local part")
        elif any(h in local for h in fakes.FAKE_EMAIL_LOCAL_HINTS):
            c.fake.append("test-like email local part")
        out.append(c)
    return out


# Phone ---------------------------------------------------------------------

PHONE_RE = re.compile(
    r"(?<![\w+.\-/:])"
    r"((?:\+|00)44[ \-]?(?:\(0\)[ \-]?)?\d(?:[ \-]?\d){8,9}"
    r"|\(?0\d{2,4}\)?(?:[ \-]?\d){6,8})"
    r"(?![\w.\-/:])"
)


def _national(raw: str) -> str:
    d = digits_only(raw.replace("(0)", ""))
    if d.startswith("0044"):
        d = "0" + d[4:]
    elif raw.lstrip().startswith("+44") or d.startswith("44") and len(d) == 12:
        d = "0" + d[2:]
    return d


def detect_phone(line: str, ctx: str) -> list[Candidate]:
    out = []
    for m in PHONE_RE.finditer(line):
        nat = _national(m.group(1))
        if len(nat) != 11 and not (len(nat) == 10 and nat.startswith("01")):
            continue
        if nat.startswith("07"):
            if nat[2] in "06":  # 070 personal numbering, 076 pagers
                continue
            c = Candidate("uk_phone", m.group(1), nat, 6.0, 0.8, notes=["mobile"])
        elif nat.startswith(("01", "02")):
            c = Candidate("uk_phone", m.group(1), nat, 4.0, 0.6, notes=["landline"])
        else:
            continue  # 03/08/09 are non-geographic business numbers
        if not re.search(r"[ \-()+]", m.group(1)):
            c.confidence -= 0.2
        if nat.startswith(fakes.OFCOM_DRAMA_PREFIXES):
            c.fake.append("Ofcom reserved drama number")
        if looks_patterned(nat[1:]):
            c.fake.append("repeated or sequential digits")
        out.append(c)
    return out


# National Insurance --------------------------------------------------------

NINO_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2}) ?(\d{2}) ?(\d{2}) ?(\d{2}) ?([A-Da-d])(?![A-Za-z0-9])")
NINO_KW = re.compile(r"\b(ni|nino|ni[ _-]?number|national[ _-]?insurance)\b|nino|nationalinsurance", re.I)


def detect_nino(line: str, ctx: str) -> list[Candidate]:
    out = []
    for m in NINO_RE.finditer(line):
        norm = "".join(m.groups()).upper()
        if norm.startswith("QQ"):
            out.append(Candidate("nino", m.group(0), norm, 9.0, 0.9, fake=["HMRC example QQ prefix"]))
            continue
        if not nino_valid(norm):
            continue
        conf = 0.9 if NINO_KW.search(ctx) else 0.6
        c = Candidate("nino", m.group(0), norm, 9.0, conf)
        if norm in fakes.EXAMPLE_NINOS:
            c.fake.append("well known example NINO")
        if looks_patterned(norm[2:8]):
            c.fake.append("repeated or sequential digits")
        out.append(c)
    return out


# NHS number ----------------------------------------------------------------

NHS_RE = re.compile(r"(?<![\w\-])(\d{3})([ \-]?)(\d{3})\2(\d{4})(?![\w\-])")
NHS_KW = re.compile(r"nhs", re.I)


def detect_nhs(line: str, ctx: str) -> list[Candidate]:
    if not NHS_KW.search(ctx):
        return []
    out = []
    for m in NHS_RE.finditer(line):
        d = m.group(1) + m.group(3) + m.group(4)
        if not nhs_number_valid(d):
            continue
        c = Candidate("nhs_number", m.group(0), d, 9.0, 0.9 if m.group(2) else 0.7)
        if d.startswith("999"):
            c.fake.append("NHS test number range (999)")
        if looks_patterned(d):
            c.fake.append("repeated or sequential digits")
        out.append(c)
    return out


# Payment card --------------------------------------------------------------

CARD_RE = re.compile(
    r"(?<![\w\-.:/])(\d{4}([ \-]?)\d{4}\2\d{4}\2\d{4}(?:\d{3})?|3[47]\d{2}([ \-]?)\d{6}\3\d{5}|\d{13,19})(?![\w\-.:/])"
)
# Must name a card explicitly: bare "card", "payment" or "credit" match CSS classes, repo names and accounting columns
CARD_KW = re.compile(
    r"card[ _\-]?(?:number|num|no\b|details)|cardnumber|cardno|(?:credit|debit|payment|bank)[ _\-]?card|"
    r"\bpan\b|\bvisa\b|master[ _\-]?card|\bamex\b|american express|\bcc[ _\-]?(?:num|number|no)\b|ccnumber",
    re.I,
)
_NUMBER_BEFORE = re.compile(r"\d[\d.]*[ \t,;]+$")
_NUMBER_AFTER = re.compile(r"^[ \t,;]+\d")


def _card_brand_ok(d: str) -> bool:
    n = len(d)
    if d[0] == "4":
        return n in (13, 16, 19)
    if 51 <= int(d[:2]) <= 55 or 2221 <= int(d[:4]) <= 2720:
        return n == 16
    if d[:2] in ("34", "37"):
        return n == 15
    if d.startswith(("6011", "65")) or 644 <= int(d[:3]) <= 649:
        return 16 <= n <= 19
    return False


def detect_card(line: str, ctx: str) -> list[Candidate]:
    out = []
    has_kw = bool(CARD_KW.search(line))
    for m in CARD_RE.finditer(line):
        d = digits_only(m.group(1))
        if not 13 <= len(d) <= 19 or not luhn_valid(d) or not _card_brand_ok(d):
            continue
        formatted = bool(re.search(r"[ \-]", m.group(1)))
        if not has_kw and not formatted:
            continue
        if formatted and not has_kw:
            # Space separated grids of numbers (rasters, readings) and runs of years are not card numbers
            groups = re.split(r"[ \-]", m.group(1))
            if _NUMBER_BEFORE.search(line[: m.start()]) or _NUMBER_AFTER.search(line[m.end():]):
                continue
            if all(1900 <= int(g) <= 2099 for g in groups if len(g) == 4):
                continue
        c = Candidate("payment_card", m.group(1), d, 9.0, 0.9 if has_kw else 0.6)
        if d in fakes.TEST_CARDS or d.startswith(("400000", "4242")):
            c.fake.append("published test card number")
        elif looks_patterned(d):
            c.fake.append("repeated or sequential digits")
        out.append(c)
    return out


# Bank details --------------------------------------------------------------

SORT_KW = re.compile(r"sort[ _\-]?code|sortcode", re.I)
SORT_RE = re.compile(r"(?<![\w\-/.])(\d{2})([ \-]?)(\d{2})\2(\d{2})(?![\w\-/.])")
ACCOUNT_RE = re.compile(r"(?<![\w\-/.])(\d{8})(?![\w\-/.])")


def detect_bank(line: str, ctx: str) -> list[Candidate]:
    if not SORT_KW.search(ctx):
        return []
    out = []
    accounts = ACCOUNT_RE.findall(ctx)
    for m in SORT_RE.finditer(line):
        sort = m.group(1) + m.group(3) + m.group(4)
        acct = next((a for a in accounts if sort not in a), None)
        if not acct:
            continue
        c = Candidate("bank_account", f"{sort} {acct}", f"{sort}{acct}", 9.0, 0.8)
        if looks_patterned(sort) or looks_patterned(acct) or sort == "000000":
            c.fake.append("repeated or sequential digits")
        out.append(c)
    return out


# Date of birth -------------------------------------------------------------

DOB_KW = re.compile(r"\b(dob|d\.o\.b\.?|born)\b|date[\s_\-]?of[\s_\-]?birth|birth[\s_\-]?date|birthday", re.I)
_MONTHS = "jan feb mar apr may jun jul aug sep oct nov dec".split()
DATE_RE = re.compile(
    r"(?<!\d)(?:(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})|(\d{4})-(\d{2})-(\d{2})"
    r"|(\d{1,2})(?:st|nd|rd|th)?\s+(" + "|".join(_MONTHS) + r")[a-z]*\.?,?\s+(\d{4}))(?!\d)",
    re.I,
)


def detect_dob(line: str, ctx: str) -> list[Candidate]:
    if not DOB_KW.search(line):
        return []
    out = []
    this_year = date.today().year
    for m in DATE_RE.finditer(line):
        if not DOB_KW.search(line[max(0, m.start() - 40): m.start()]):
            continue
        g = m.groups()
        try:
            if g[0]:
                d, mo, y = int(g[0]), int(g[1]), int(g[2])
            elif g[3]:
                y, mo, d = int(g[3]), int(g[4]), int(g[5])
            else:
                d, mo, y = int(g[6]), _MONTHS.index(g[7].lower()[:3]) + 1, int(g[8])
            dt = date(y, mo, d)
        except ValueError:
            continue
        if not 1900 <= y <= this_year:
            continue
        c = Candidate("dob", m.group(0), dt.isoformat(), 6.0, 0.8)
        if (d, mo) == (1, 1) or y in (1900, 1970, 2000):
            c.fake.append("placeholder date")
        out.append(c)
    return out


# Passport ------------------------------------------------------------------

PASSPORT_KW = re.compile(r"passport", re.I)
PASSPORT_RE = re.compile(r"(?<![\w\-])(\d{9})(?![\w\-])")


def detect_passport(line: str, ctx: str) -> list[Candidate]:
    if not PASSPORT_KW.search(line):
        return []
    out = []
    for m in PASSPORT_RE.finditer(line):
        c = Candidate("passport", m.group(1), m.group(1), 8.0, 0.7)
        if looks_patterned(m.group(1)):
            c.fake.append("repeated or sequential digits")
        out.append(c)
    return out


# Driving licence -----------------------------------------------------------

DL_RE = re.compile(
    r"(?<![A-Za-z0-9])([A-Z9]{5}\d(?:[05]\d|[16][0-2])(?:0[1-9]|[12]\d|3[01])\d[A-Z9]{2}\d[A-Z]{2})(?![A-Za-z0-9])"
)
DL_KW = re.compile(r"licen[cs]e|driv", re.I)


def detect_driving_licence(line: str, ctx: str) -> list[Candidate]:
    out = []
    for m in DL_RE.finditer(line):
        v = m.group(1)
        month = int(v[6:8])
        if not (1 <= month <= 12 or 51 <= month <= 62):
            continue
        if sum(ch.isalpha() for ch in v[:5]) < 2:
            continue
        c = Candidate("driving_licence", v, v, 8.0, 0.85 if DL_KW.search(ctx) else 0.5)
        if v in fakes.EXAMPLE_DRIVING_LICENCES:
            c.fake.append("DVLA published example")
        out.append(c)
    return out


# Postcode ------------------------------------------------------------------

POSTCODE_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{1,2}\d[A-Z\d]?) (\d[A-Z]{2})(?![A-Za-z0-9])")


def detect_postcode(line: str, ctx: str) -> list[Candidate]:
    out = []
    for m in POSTCODE_RE.finditer(line):
        if postcode_area(m.group(1)) not in POSTCODE_AREAS:
            continue
        pc = f"{m.group(1)} {m.group(2)}"
        c = Candidate("postcode", pc, pc, 2.0, 0.7)
        if pc in fakes.EXAMPLE_POSTCODES:
            c.fake.append("well known example postcode")
        out.append(c)
    return out


DIGIT_DETECTORS = (
    detect_phone, detect_nino, detect_nhs, detect_card, detect_bank, detect_dob, detect_passport,
    detect_driving_licence, detect_postcode,
)
