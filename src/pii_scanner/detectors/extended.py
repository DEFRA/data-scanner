"""Detectors for addresses, vehicles, network/device/location data, Defra references, case text and special category data."""
from __future__ import annotations

import ipaddress
import re

from .rules import Candidate
from .validators import looks_patterned, luhn_valid

# Street address -------------------------------------------------------------

_SUFFIX = (
    r"Road|Rd|Street|St|Lane|Ln|Avenue|Ave|Close|Drive|Way|Court|Crescent|Place|Gardens|Terrace|Grove|Hill|"
    r"Square|Row|Mews|Walk|Green|Rise|Parade|Vale|Wharf|Gate|Meadows?|Fields?|Croft|Chase|End|Lea"
)
_WORD = r"[A-Z][a-z']+"
ADDRESS_RE = re.compile(
    rf"(?<![\w.])(\d{{1,4}}[A-Za-z]?,?\s+(?:{_WORD}\s+){{1,3}}(?:{_SUFFIX})\.?)(?![\w])"
    rf"|(?<![\w])((?:{_WORD}\s+){{1,2}}(?:Farm|Farmhouse|Cottage|Cottages|Barn|Barns))(?![\w])"
)
_FAKE_ADDRESS = re.compile(r"\b(test|fake|example|sample|dummy|mock|any|some|my|your|downing|baker|acacia)\b", re.I)


def detect_address(line: str, ctx: str) -> list[Candidate]:
    out = []
    for m in ADDRESS_RE.finditer(line):
        value = m.group(1) or m.group(2)
        norm = " ".join(value.lower().replace(",", " ").split())
        c = Candidate("street_address", value, norm, 3.0, 0.6 if m.group(1) else 0.4)
        if _FAKE_ADDRESS.search(value):
            c.fake.append("placeholder address wording")
        out.append(c)
    return out


# Vehicle registration -------------------------------------------------------

VRM_KW = re.compile(
    r"\b(reg|registration|vrm|vrn|vehicle|number ?plate|numberplate|car|van|lorry|trailer|tractor)\b"
    r"|vehicleReg|regNumber|registrationNumber|numberPlate", re.I,
)
VRM_RE = re.compile(
    r"(?<![A-Za-z0-9])("
    r"[A-HJ-PR-Y][A-HJ-PR-Z](?:0[2-9]|[1-7]\d) ?[A-HJ-PR-Z]{3}"  # current: AB12 CDE
    r"|[A-HJ-NP-Y]\d{1,3} ?[A-Z]{3}"  # prefix: A123 BCD
    r"|[A-Z]{3} ?\d{1,3}[A-HJ-NP-Y]"  # suffix: ABC 123D
    r")(?![A-Za-z0-9])"
)
_FAKE_VRM = frozenset({"AB12CDE", "AB51ABC", "XX00XXX", "AB12ABC", "AA00AAA", "AB01CDE", "TE57VRN"})


def detect_vehicle(line: str, ctx: str) -> list[Candidate]:
    if not VRM_KW.search(ctx):
        return []
    out = []
    for m in VRM_RE.finditer(line):
        norm = m.group(1).replace(" ", "")
        c = Candidate("vehicle_reg", m.group(1), norm, 4.0, 0.8 if VRM_KW.search(line) else 0.6)
        letters = re.sub(r"\d", "", norm)
        if norm in _FAKE_VRM or len(set(letters)) == 1 or letters in ("ABC", "ABCDE", "XYZ"):
            c.fake.append("placeholder registration")
        out.append(c)
    return out


# IP address -----------------------------------------------------------------

IPV4_RE = re.compile(r"(?<![\w.:/-])((?:\d{1,3}\.){3}\d{1,3})(?![\w.:-])")
IPV6_RE = re.compile(r"(?<![\w:.])((?:[0-9A-Fa-f]{1,4}:){2,7}(?::|[0-9A-Fa-f]{1,4})(?:[0-9A-Fa-f:]*))(?![\w:.])")
_VERSION_KW = re.compile(r"version|\bv\d|release|semver|build", re.I)
# Public resolvers and well-known service addresses, not personal
_SERVICE_IPS = frozenset({"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"})


def detect_ip(line: str, ctx: str) -> list[Candidate]:
    out = []
    for regex in (IPV4_RE, IPV6_RE):
        for m in regex.finditer(line):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            if not ip.is_global or str(ip) in _SERVICE_IPS:
                continue
            if ip.version == 4 and _VERSION_KW.search(line):
                continue
            out.append(Candidate("ip_address", m.group(1), str(ip), 2.5, 0.6))
    return out


# Device identifiers ---------------------------------------------------------

IMEI_KW = re.compile(r"imei", re.I)
IMEI_RE = re.compile(r"(?<![\w-])(\d{15})(?![\w-])")
MAC_KW = re.compile(r"\bmac\b|macAddress|mac_address|hardware|device", re.I)
MAC_RE = re.compile(r"(?<![\w:-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![\w:-])")
AD_ID_KW = re.compile(r"idfa|gaid|aaid|advertising[ _-]?id|device[ _-]?id|deviceId|udid", re.I)
UUID_RE = re.compile(r"(?<![\w-])([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})(?![\w-])")


def detect_device(line: str, ctx: str) -> list[Candidate]:
    out = []
    if IMEI_KW.search(ctx):
        for m in IMEI_RE.finditer(line):
            if luhn_valid(m.group(1)):
                c = Candidate("device_id", m.group(1), "imei:" + m.group(1), 4.0, 0.8, notes=["IMEI"])
                if looks_patterned(m.group(1)):
                    c.fake.append("repeated or sequential digits")
                out.append(c)
    if MAC_KW.search(ctx):
        for m in MAC_RE.finditer(line):
            norm = m.group(1).lower().replace("-", ":")
            if norm in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or len(set(norm.replace(":", ""))) <= 2:
                continue
            out.append(Candidate("device_id", m.group(1), "mac:" + norm, 2.5, 0.6, notes=["MAC address"]))
    if AD_ID_KW.search(line):
        for m in UUID_RE.finditer(line):
            norm = m.group(1).lower()
            c = Candidate("device_id", m.group(1), "uuid:" + norm, 3.0, 0.6, notes=["device/advertising ID"])
            if len(set(norm.replace("-", ""))) <= 2:
                c.fake.append("placeholder identifier")
            out.append(c)
    return out


# Location -------------------------------------------------------------------

LATLON_RE = re.compile(r"(?<![\w.])(-?\d{1,3}\.\d{4,})\s*[,;\s]\s*(-?\d{1,3}\.\d{4,})(?![\w.])")
GRID_RE = re.compile(r"(?<![A-Za-z0-9])([HNOST][A-HJ-Z]) ?(\d{4,5}) ?(\d{4,5})(?![A-Za-z0-9])")


def _uk(lat: float, lon: float) -> bool:
    return 49.8 <= lat <= 60.9 and -8.7 <= lon <= 1.8


def detect_location(line: str, ctx: str) -> list[Candidate]:
    out = []
    for m in LATLON_RE.finditer(line):
        a, b = float(m.group(1)), float(m.group(2))
        if _uk(a, b):
            lat, lon = a, b
        elif _uk(b, a):  # GeoJSON order
            lat, lon = b, a
        else:
            continue
        out.append(Candidate("location", m.group(0), f"{lat:.4f},{lon:.4f}", 2.5, 0.6, notes=["UK lat/long"]))
    for m in GRID_RE.finditer(line):
        if len(m.group(2)) != len(m.group(3)):
            continue
        norm = f"{m.group(1)}{m.group(2)}{m.group(3)}"
        out.append(Candidate("location", m.group(0), norm, 2.5, 0.6, notes=["OS grid reference"]))
    return out


# Defra customer / business references ---------------------------------------

CRN_KW = re.compile(r"(?i:crn)|(?i:customer[ _-]?ref)")
SBI_KW = re.compile(r"(?i:\bsbi)|Sbi|SBI|(?i:single[ _-]?business[ _-]?id)")
FRN_KW = re.compile(r"(?i:\bfrn)|Frn|FRN|(?i:firm[ _-]?ref)")
CPH_KW = re.compile(r"(?i:\bcph)|Cph|CPH|(?i:county[ _-]?parish[ _-]?holding)|(?i:holding[ _-]?(?:number|no))")
NUM9_RE = re.compile(r"(?<![\w\-./])(\d{9})(?![\w\-./])")
NUM10_RE = re.compile(r"(?<![\w\-./])(\d{10})(?![\w\-./])")
CPH_RE = re.compile(r"(?<![\w/])(\d{2})/(\d{3})/(\d{4})(?![\w/])")
# Validation range boundaries used across Defra services
_BOUNDARY_REFS = frozenset({"105000000", "999999999", "1050000000", "1000000000", "9999999999"})
_FAKE_CPH = frozenset({"121231234", "123456789", "223334444", "111111111", "000000000"})


def _ref(kind: str, value: str, severity: float, line_kw: bool) -> Candidate:
    c = Candidate("customer_ref", value, f"{kind}:{value}", severity, 0.85 if line_kw else 0.6, notes=[kind])
    if value in _BOUNDARY_REFS or looks_patterned(value) or (len(value) >= 8 and len(set(value)) <= 3):
        c.fake.append("repeated, sequential or boundary value")
    return c


def detect_customer_ref(line: str, ctx: str) -> list[Candidate]:
    out = []
    crn, sbi, frn, cph = (kw.search(line) for kw in (CRN_KW, SBI_KW, FRN_KW, CPH_KW))
    if sbi:
        for m in NUM9_RE.finditer(line):
            if 105000000 <= int(m.group(1)) <= 999999999:
                out.append(_ref("SBI", m.group(1), 4.0, True))
    if crn or frn:
        kind, severity = ("CRN", 5.0) if crn else ("FRN", 4.0)
        for m in NUM10_RE.finditer(line):
            v = int(m.group(1))
            if (kind == "CRN" and 1050000000 <= v) or (kind == "FRN" and 1000000000 <= v):
                out.append(_ref(kind, m.group(1), severity, True))
    if cph:
        for m in CPH_RE.finditer(line):
            digits = "".join(m.groups())
            c = _ref("CPH", digits, 3.0, True)
            if digits in _FAKE_CPH:
                c.fake.append("placeholder holding number")
            out.append(c)
    return out


# Honorific names, correspondence and case notes -----------------------------

HONORIFIC_RE = re.compile(
    r"(?<![\w])(Mr|Mrs|Ms|Miss|Mx|Dr|Sir|Dame|Lady|Lord)\.? ([A-Z][a-z]+(?:[\-'][A-Z][a-z]+)?)"
    r"(?: ([A-Z][a-z]+(?:[\-'][A-Z][a-z]+)?))?(?![\w])"
)
_HONORIFIC_FAKES = frozenset({"test", "tester", "example", "bloggs", "doe", "fake", "dummy", "user", "sample", "who", "smith"})
_NOT_SURNAMES = frozenset({"and", "or", "the", "of", "in", "street", "road", "lane", "drive", "madam", "sir"})

CASE_PATTERNS = (
    ("salutation", re.compile(r"^\W*(Dear|Hi|Hello)\s+(Mr|Mrs|Ms|Miss|Mx|Dr|Sir|Madam)\b")),
    ("sign-off", re.compile(r"^\W*(Yours (sincerely|faithfully)|Kind regards|Best regards|Warm regards)\b", re.I)),
    ("email header", re.compile(r"^\W*(From|Sent|To|Cc):\s+\S.*(@|\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*day\b)")),
    ("case wording", re.compile(
        r"\b(case ?notes?|complainant|witness statement|safeguarding|vulnerable (adult|person|customer)|"
        r"warning letter|enforcement notice|subject access request|next of kin)\b", re.I)),
)


def detect_honorific(line: str, ctx: str) -> list[Candidate]:
    out = []
    for m in HONORIFIC_RE.finditer(line):
        names = [n for n in (m.group(2), m.group(3)) if n and n.lower() not in _NOT_SURNAMES]
        if not names:
            continue
        value = " ".join([m.group(1), *names])
        c = Candidate("person_name", value, value.lower().replace(".", ""), 3.0, 0.7, notes=["title and name"])
        if any(n.lower() in _HONORIFIC_FAKES for n in names):
            c.fake.append("placeholder name")
        out.append(c)
    return out


def detect_case_text(line: str, ctx: str) -> list[Candidate]:
    out = []
    for label, regex in CASE_PATTERNS:
        m = regex.search(line)
        if m:
            out.append(Candidate("case_text", label, label, 4.0, 0.6, notes=[f"{label}: {m.group(0).strip()[:40]}"]
                                 if label == "case wording" else [label]))
    return out


# Special category data ------------------------------------------------------

SPECIAL_TERMS = {
    "health": (
        r"diagnos(?:is|ed|es)|disabilit(?:y|ies)|medical condition|mental health|depression|anxiety|"
        r"dementia|cancer|diabet(?:es|ic)|epilep(?:sy|tic)|\bHIV\b|pregnan(?:t|cy)|miscarriage|medication|"
        r"prescription|sick note|fit note|sickness absence|illness|terminally ill|hospitali[sz]ed|autism|"
        r"\bADHD\b|dyslexi[ac]|heart condition|wheelchair user|medical records?|health condition"
    ),
    "ethnicity": r"ethnic(?:ity| origin| group)|racial",
    "religion": r"religion|religious belief",
    "sexuality": r"sexual orientation|\bgay\b|lesbian|bisexual|transgender|sex life",
    "politics": r"political (?:opinion|affiliation|party member)",
    "trade union": r"trade union",
    "genetic/biometric": r"genetic data|biometric data|dna profile",
    "criminal": r"criminal (?:record|conviction|offence)|convicted|prosecuted|arrested|offender",
}
SPECIAL_RE = {k: re.compile(v, re.I) for k, v in SPECIAL_TERMS.items()}
SPECIAL_ANY = re.compile("|".join(f"(?:{v})" for v in SPECIAL_TERMS.values()), re.I)


def detect_special(line: str, ctx: str) -> list[Candidate]:
    if not SPECIAL_ANY.search(line):
        return []
    out = []
    for group, regex in SPECIAL_RE.items():
        m = regex.search(line)
        if m:
            term = m.group(0).lower()
            out.append(Candidate("special_category", f"{group}: {term}", f"{group}:{term}", 7.0, 0.5,
                                 notes=[f"{group} term '{term}'"]))
    return out
