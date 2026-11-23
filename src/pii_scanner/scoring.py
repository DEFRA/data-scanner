from __future__ import annotations

from dataclasses import dataclass, field

from .detectors import Candidate

TIER_WEIGHT = {"data": 1.2, "wiki": 1.0, "code": 0.8, "docs": 0.6, "test": 0.4}
BAND_THRESHOLDS = (("High", 6.0), ("Medium", 3.5), ("Low", 1.5))
BAND_ORDER = ("High", "Medium", "Low", "Minimal", "Likely fake")


@dataclass
class Signals:
    tier: str
    data_like: bool = False
    window: list[str] = field(default_factory=list)  # fake hints from surrounding lines
    faker_in_file: bool = False
    cooccurring: int = 0  # other personal data types on the same line/record
    bulk: int = 1  # distinct values of the same type in the same file change
    matches_author: bool = False


def score(c: Candidate, s: Signals) -> tuple[float, str, list[str]]:
    reasons = [f"{c.category} (base {c.severity:g}, confidence {c.confidence:.1f})", *c.notes]
    mult = TIER_WEIGHT[s.tier]
    reasons.append(f"{s.tier} file x{mult}")
    if s.data_like and s.tier in ("test", "docs"):
        mult *= 1.2
        reasons.append("data-style file x1.2")

    def apply(factor: float, why: str) -> None:
        nonlocal mult
        mult *= factor
        reasons.append(f"{why} x{factor}")

    if "fake/example wording nearby" in s.window:
        apply(0.5, "fake/example wording nearby")
    if "test wording nearby" in s.window and s.tier != "test":
        apply(0.8, "test wording nearby")
    if "placeholder name nearby" in s.window:
        apply(0.4, "placeholder name nearby")
    if s.faker_in_file:
        apply(0.4, "file uses a fake data library")
    if s.matches_author:
        apply(0.3, "matches the commit author (already public in git metadata)")
    if s.cooccurring >= 2:
        apply(1.8, f"{s.cooccurring} other personal data types on the same line")
    elif s.cooccurring == 1:
        apply(1.4, "another personal data type on the same line")
    if s.bulk >= 500:
        apply(2.0, f"{s.bulk} distinct values in one file change (bulk data)")
    elif s.bulk >= 50:
        apply(1.6, f"{s.bulk} distinct values in one file change")
    elif s.bulk >= 10:
        apply(1.3, f"{s.bulk} distinct values in one file change")

    value = round(min(10.0, c.severity * c.confidence * mult), 2)
    if c.fake:
        reasons = [*c.fake, *reasons]
        return value, "Likely fake", reasons
    band = next((name for name, t in BAND_THRESHOLDS if value >= t), "Minimal")
    return value, band, reasons
