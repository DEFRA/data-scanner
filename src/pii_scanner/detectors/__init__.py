from __future__ import annotations

from . import extended
from .rules import CATEGORIES, COOCCURRENCE_RULES, DIGIT_DETECTORS, IDENTIFIER_RULES, LINKABLE_RULES, Candidate, detect_email

DIGIT_ONLY = (*DIGIT_DETECTORS, extended.detect_vehicle, extended.detect_ip, extended.detect_device,
              extended.detect_location, extended.detect_customer_ref)
TEXT = (extended.detect_address, extended.detect_honorific, extended.detect_case_text, extended.detect_special)

# Values that are descriptions rather than personal data, shown as-is
_DESCRIPTIVE = frozenset({"media", "case_text", "special_category"})


def detect(line: str, ctx: str) -> list[Candidate]:
    """Run all regex detectors on one line; ctx is the surrounding window used for keyword checks."""
    out: list[Candidate] = []
    if "@" in line:
        out += detect_email(line, ctx)
    if any(ch.isdigit() for ch in line):
        for fn in DIGIT_ONLY:
            out += fn(line, ctx)
    for fn in TEXT:
        out += fn(line, ctx)
    return out


def mask(rule: str, value: str) -> str:
    """Partially redact a value so the report is useful for triage without exposing it."""
    v = value.strip()
    if rule in _DESCRIPTIVE:
        return v
    if rule == "email" and "@" in v:
        local, domain = v.rsplit("@", 1)
        return f"{local[:1]}***@{domain}"
    if rule == "person_name":
        return " ".join(p[:1] + "*" * min(len(p) - 1, 4) for p in v.split())
    if rule == "dob":
        return "**-**-" + v[:4] if len(v) == 10 and v[4] == "-" else "**/**/****"
    if rule == "postcode":
        return v.split(" ")[0] + " ***"
    if rule == "payment_card":
        digits = "".join(ch for ch in v if ch.isdigit())
        return "**** " + digits[-4:]
    if rule == "location" and "," in v:
        return ", ".join(p[: p.find(".") + 2] + "**" for p in v.split(","))
    if rule == "ip_address":
        sep = "." if "." in v else ":"
        return v.split(sep)[0] + sep + "***"
    if rule in ("customer_ref", "device_id") and ":" in v:
        kind, _, rest = v.partition(":")
        return f"{kind.upper()} {_generic(rest)}"
    if rule == "street_address":
        words = v.split()
        return " ".join(w if i == len(words) - 1 else w[:1] + "*" * (len(w) - 1) for i, w in enumerate(words))
    return _generic(v)


def _generic(v: str) -> str:
    keep_start, keep_end = (2, 2) if len(v) >= 8 else (1, 1)
    middle = "".join("*" if ch.isalnum() else ch for ch in v[keep_start:-keep_end])
    return v[:keep_start] + middle + v[-keep_end:]


__all__ = ["CATEGORIES", "COOCCURRENCE_RULES", "IDENTIFIER_RULES", "LINKABLE_RULES", "Candidate", "detect", "mask"]
