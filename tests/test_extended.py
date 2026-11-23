"""Coverage of the extended personal data categories. All values are synthetic."""
import io

from PIL import Image
from PIL.TiffImagePlugin import IFDRational

from pii_scanner import blobs, ner
from pii_scanner.detectors import detect, mask
from pii_scanner.detectors.extended import (
    detect_address, detect_case_text, detect_customer_ref, detect_device, detect_honorific, detect_ip,
    detect_location, detect_special, detect_vehicle,
)


def test_spacy_person_needs_a_given_name_and_no_tech_words():
    assert ner._person("Docker Compose") is None
    assert ner._person("Natural England") is None
    assert ner._person("Service Worker") is None
    assert ner._person("Hawthorn Lindqvist") is None  # first word is not a known given name
    assert ner._person("Johnny Watson").norm == "johnny watson"
    assert ner._person("Johnnie Watson") is not None
    assert ner.CAPITALISED_PAIR.search("const x = docker.compose()") is None
    assert ner.CAPITALISED_PAIR.search("name: Johnny Watson")


def test_street_address_and_farm():
    [a] = detect_address("Delivered to 14 Hawthorn Close, Leeds", "")
    assert a.norm == "14 hawthorn close"
    [f] = detect_address("Holding at Lower Brook Farm", "")
    assert f.value == "Lower Brook Farm"
    [fake] = detect_address("1 Test Street", "")
    assert fake.fake
    assert mask("street_address", "14 Hawthorn Close") == "1* H******* Close"


def test_vehicle_registration_needs_keyword():
    [v] = detect_vehicle("vehicle reg: KX19 PLM", "vehicle reg: KX19 PLM")
    assert v.norm == "KX19PLM" and not v.fake
    assert detect_vehicle("KX19 PLM", "no keyword") == []
    [f] = detect_vehicle("reg AB12 CDE", "reg AB12 CDE")
    assert f.fake


def test_ip_addresses_public_only():
    [ip] = detect_ip("client_ip=81.174.152.33", "")
    assert ip.norm == "81.174.152.33"
    assert detect_ip("10.0.0.4 192.168.1.20 127.0.0.1 203.0.113.9 8.8.8.8", "") == []
    assert detect_ip("version 2.14.1.33", "") == []
    [v6] = detect_ip("remote 2a00:23c4:9f1e:4d01::1a", "")
    assert v6.rule == "ip_address"


def test_device_identifiers():
    imei = "356938035643809"
    [i] = detect_device(f"imei: {imei}", f"imei: {imei}")
    assert i.norm == f"imei:{imei}"
    [m] = detect_device("mac_address: 3c:22:fb:91:4e:07", "mac_address")
    assert m.notes == ["MAC address"]
    [u] = detect_device("deviceId: 6f1c2a9e-8b3d-4c71-a0e2-5d9b7f13c4aa", "")
    assert u.norm.startswith("uuid:")


def test_location_uk_only():
    [l] = detect_location("lat, lon: 53.80081, -1.54912", "")
    assert l.norm == "53.8008,-1.5491"
    [g] = detect_location("[-1.54912, 53.80081]", "")
    assert g.norm == "53.8008,-1.5491"
    assert detect_location("40.71280, -74.00601", "") == []
    [os] = detect_location("grid ref SE 2987 3345", "")
    assert os.norm == "SE29873345"


def test_defra_references():
    [sbi] = detect_customer_ref("sbi: 106284731", "")
    assert sbi.norm == "SBI:106284731" and not sbi.fake
    [crn] = detect_customer_ref('"crn": "1103847261"', "")
    assert crn.norm == "CRN:1103847261"
    [frn] = detect_customer_ref("frn=1102938475", "")
    assert frn.norm == "FRN:1102938475"
    [cph] = detect_customer_ref("cph: 44/215/0378", "")
    assert cph.norm == "CPH:442150378"
    [fake] = detect_customer_ref("sbi: 123456789", "")
    assert fake.fake
    assert detect_customer_ref("id: 106284731", "") == []
    assert detect_customer_ref("sbi: 104999999", "") == []  # below SBI range
    assert mask("customer_ref", "SBI:106284731") == "SBI 10*****31"


def test_honorific_names_and_case_text():
    [n] = detect_honorific("Dear Mrs Watson-Hale,", "")
    assert n.norm == "mrs watson-hale"
    [fake] = detect_honorific("Mr Test", "")
    assert fake.fake
    labels = {c.value for c in detect_case_text("Dear Mr Patel,", "")}
    assert labels == {"salutation"}
    assert {c.value for c in detect_case_text("Case notes: complainant called back", "")} == {"case wording"}
    assert detect_case_text("To: support", "") == []


def test_special_category_terms():
    [s] = detect_special("Medical condition: type 1 diabetes", "")
    assert s.rule == "special_category" and s.norm.startswith("health:")
    assert detect_special("button disabled while loading", "") == []


def test_tabular_labelling_gives_column_keywords():
    row = blobs.labelled("csv", "name,date_of_birth,crn", "Ada Pemberton,14/07/1983,1103847261")
    assert "date_of_birth: 14/07/1983" in row
    rules = {c.rule for c in detect(row, row)}
    assert {"dob", "customer_ref"} <= rules


def _jpeg_with_exif() -> bytes:
    img = Image.new("RGB", (4, 4))
    exif = Image.Exif()
    exif[271] = "Apple"
    exif[272] = "iPhone 12"
    exif[0x8825] = {1: "N", 2: (IFDRational(53), IFDRational(48), IFDRational(3)),
                    3: "W", 4: (IFDRational(1), IFDRational(32), IFDRational(57))}
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=exif)
    return buf.getvalue()


def test_media_exif_and_file_names():
    ev = blobs.inspect_media("photos/visit.jpg", "jpg", _jpeg_with_exif())
    assert ev and ev.gps and 53.7 < ev.gps[0] < 53.9 and -1.6 < ev.gps[1] < -1.5
    assert any("camera EXIF" in n for n in ev.notes)
    sig = blobs.inspect_media("uploads/signature.png", "png", b"not really a png")
    assert sig and sig.severity >= 6
    assert blobs.inspect_media("assets/logo.png", "png", b"not really a png") is None
