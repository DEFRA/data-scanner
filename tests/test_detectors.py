"""All personal-looking values in these tests are synthetic."""
from pii_scanner.detectors import detect, mask
from pii_scanner.detectors.rules import detect_bank, detect_card, detect_dob, detect_driving_licence, detect_email, detect_nhs, detect_nino, detect_phone, detect_postcode
from pii_scanner.detectors.validators import luhn_valid, nhs_number_valid
from pii_scanner.scoring import Signals, score


def make_nhs(prefix9: str) -> str:
    total = sum(int(d) * w for d, w in zip(prefix9, range(10, 1, -1)))
    check = 11 - total % 11
    check = 0 if check == 11 else check
    assert check != 10, "pick another prefix"
    return prefix9 + str(check)


def make_luhn(prefix: str) -> str:
    for d in "0123456789":
        if luhn_valid(prefix + d):
            return prefix + d
    raise AssertionError


def rules(cands):
    return [c.rule for c in cands]


def test_email_classification_and_exclusions():
    [c] = detect_email("contact jonathan.watson.fx@gmail.com now", "")
    assert c.severity == 6.0 and not c.fake
    assert detect_email("a@example.com b@test.example git@github.com logo@2x.png info@acme.co.uk", "") == []
    [w] = detect_email("owner: jo.bloggs@defra.gov.uk", "")
    assert "public sector work address" in w.notes
    [f] = detect_email("tester99@gmail.com", "")
    assert f.fake


def test_uk_phone():
    [m] = detect_phone("call 07911 482736 today", "")
    assert m.norm == "07911482736" and not m.fake
    [l] = detect_phone("+44 (0)20 7183 2947", "")
    assert l.norm == "02071832947"
    [d] = detect_phone("07700 900482", "")
    assert "Ofcom reserved drama number" in d.fake
    assert detect_phone("0345 335 5577 helpline", "") == []
    assert detect_phone("version 1.07911482736", "") == []


def test_nino():
    [n] = detect_nino("NI number JT 48 27 39 B", "NI number JT 48 27 39 B")
    assert n.norm == "JT482739B" and n.confidence == 0.9 and not n.fake
    [q] = detect_nino("QQ123456C", "")
    assert q.fake
    assert detect_nino("BG482739A", "") == []


def test_nhs_number_needs_keyword_and_checksum():
    nhs = make_nhs("485777361")
    formatted = f"{nhs[:3]} {nhs[3:6]} {nhs[6:]}"
    assert nhs_number_valid(nhs)
    [c] = detect_nhs(f"NHS number: {formatted}", f"NHS number: {formatted}")
    assert c.norm == nhs and not c.fake
    assert detect_nhs(formatted, "no keyword here") == []
    bad = nhs[:9] + str((int(nhs[9]) + 1) % 10)
    assert detect_nhs(f"nhs {bad}", "nhs") == []
    test_range = make_nhs("999123457")
    [t] = detect_nhs(f"nhs {test_range}", "nhs")
    assert t.fake


def test_payment_card():
    card = make_luhn("453201511283036")
    spaced = " ".join(card[i:i + 4] for i in range(0, 16, 4))
    [c] = detect_card(spaced, "")
    assert c.norm == card and not c.fake
    assert detect_card(card, "") == []  # unformatted needs a keyword
    assert detect_card(f"card_number: {card}", "") != []
    assert detect_card(card, "card_number on a nearby line") == []  # keyword must be on the line or column
    [t] = detect_card("4242 4242 4242 4242", "")
    assert t.fake


def test_payment_card_false_positive_shapes():
    card = make_luhn("453201511283036")
    spaced = " ".join(card[i:i + 4] for i in range(0, 16, 4))
    assert detect_card(f"0.25 1.75 {spaced} 3.5 12.0", "") == []  # raster/readings grid
    assert detect_card(f"value=0.{card}", "") == []  # digits after a decimal point
    assert detect_card(f"12:{card}", "") == []
    assert detect_card(f"payment_reference: {card}", "") == []  # 'payment' alone is not a card keyword
    assert detect_card(f"govuk-summary-card {card}", "") == []
    visa13 = make_luhn("453201511283")
    assert len(visa13) == 13 and detect_card(f"card number {visa13}", "") != []
    mc15 = make_luhn("51051051051051")
    assert detect_card(f"card number {mc15}", "") == []  # Mastercard must be 16 digits
    years = "2019 2020 2021 2023"
    assert detect_card(years, "") == []


def test_bank_dob_licence_postcode():
    [b] = detect_bank("sort code 20-45-77 account 41927365", "sort code 20-45-77 account 41927365")
    assert b.norm == "20457741927365"
    assert detect_bank("released 20-45-77", "released 20-45-77") == []
    [d] = detect_dob("dob: 14/07/1983", "")
    assert d.norm == "1983-07-14"
    assert detect_dob("created 14/07/1983", "") == []
    assert detect_dob("dob field is optional. " + "x" * 60 + " issued 14/07/2021", "") == []
    [l] = detect_driving_licence("MORGA753116SM9IJ", "")
    assert l.fake
    [p] = detect_postcode("12 Park Row, Leeds LS1 4AP", "")
    assert p.norm == "LS1 4AP"
    assert detect_postcode("QQ1 4AP", "") == []


def test_detect_prefilter_and_combined():
    assert detect("const x = foo(bar)", "") == []
    found = rules(detect("Jonathan, jonathan.watson.fx@gmail.com, 07911 482736, LS1 4AP", ""))
    assert sorted(found) == ["email", "postcode", "uk_phone"]


def test_mask_hides_value():
    assert mask("email", "jonathan.watson.fx@gmail.com") == "j***@gmail.com"
    assert mask("uk_phone", "07911482736") == "07*******36"
    assert mask("payment_card", "4532015112830366") == "**** 0366"
    assert mask("nino", "JT482739B") == "JT*****9B"
    assert mask("person_name", "Jonathan Watson") == "J**** W****"


def test_scoring_tiers_and_fakes():
    [c] = detect_email("jonathan.watson.fx@gmail.com", "")
    _, data_band, _ = score(c, Signals(tier="data", cooccurring=2))
    _, test_band, _ = score(c, Signals(tier="test", faker_in_file=True))
    assert data_band == "High"
    assert test_band in ("Low", "Minimal")
    [f] = detect_phone("07700 900482", "")
    assert score(f, Signals(tier="data"))[1] == "Likely fake"
