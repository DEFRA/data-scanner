from __future__ import annotations

import re

_SEQUENCES = ("012345", "123456", "234567", "345678", "456789", "987654", "876543", "765432", "654321")


def digits_only(s: str) -> str:
    return re.sub(r"\D", "", s)


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def nhs_number_valid(digits: str) -> bool:
    if len(digits) != 10:
        return False
    total = sum(int(d) * w for d, w in zip(digits[:9], range(10, 1, -1)))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    return check != 10 and check == int(digits[9])


_NINO_VALID = re.compile(r"^(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$")


def nino_valid(nino: str) -> bool:
    return bool(_NINO_VALID.match(nino))


def looks_patterned(digits: str) -> bool:
    """Repeated or sequential digit runs typical of hand-typed fake values."""
    if len(digits) >= 4 and len(set(digits)) <= 2:
        return True
    if re.search(r"(\d)\1{4,}", digits):
        return True
    return any(seq in digits for seq in _SEQUENCES)


# Outward code areas in current use (Royal Mail)
POSTCODE_AREAS = frozenset("""
AB AL B BA BB BD BF BH BL BN BR BS BT BX CA CB CF CH CM CO CR CT CV CW DA DD DE DG DH DL DN DT DY E EC EH EN EX
FK FY G GL GU GY HA HD HG HP HR HS HU HX IG IM IP IV JE KA KT KW KY L LA LD LE LL LN LS LU M ME MK ML N NE NG
NN NP NR NW OL OX PA PE PH PL PO PR RG RH RM S SA SE SG SK SL SM SN SO SP SR SS ST SW SY TA TD TF TN TQ TR TS
TW UB W WA WC WD WF WN WR WS WV YO ZE
""".split())


def postcode_area(postcode: str) -> str:
    m = re.match(r"[A-Z]+", postcode)
    return m.group(0) if m else ""
