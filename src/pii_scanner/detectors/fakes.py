"""Values reserved or widely published for testing, so they cannot be real personal data."""

# Ofcom numbers reserved for TV/radio drama, national format prefixes
OFCOM_DRAMA_PREFIXES = (
    "07700900",
    "02079460",
    "01134960", "01144960", "01154960", "01164960", "01174960", "01184960",
    "01214960", "01314960", "01414960", "01514960", "01614960",
    "02896496", "02920180",
    "01632960",
)

# Payment provider published test card numbers (Stripe, Worldpay, GOV.UK Pay, Adyen etc.)
TEST_CARDS = frozenset({
    "4242424242424242", "4000056655665556", "5555555555554444", "2223003122003222",
    "5200828282828210", "5105105105105100", "378282246310005", "371449635398431",
    "6011111111111117", "6011000990139424", "3056930009020004", "36227206271667",
    "3566002020360505", "6200000000000005", "4111111111111111", "4012888888881881",
    "4222222222222", "4444333322221111", "4917610000000000", "4000000000000002",
    "4000000000009995", "5101180000000007", "4917610000000000003", "4462030000000000",
    "6759649826438453", "5454545454545454", "4988438843884305", "5136333333333335",
    "4006000000000600", "4000000000000077", "4000000000003220", "4000002500003155",
    "4000000760000002", "4000001240000000", "4000008260000000", "4000058260000005",
})

EXAMPLE_NINOS = frozenset({"AB123456C", "AA123456A", "AB123456A", "AB123456D", "AA000000A"})

# DVLA published example licence numbers
EXAMPLE_DRIVING_LICENCES = frozenset({"MORGA753116SM9IJ", "MORGA657054SM9IJ"})

EXAMPLE_POSTCODES = frozenset({"SW1A 1AA", "SW1A 2AA", "AA1 1AA", "AB1 2CD", "XX1 1XX", "EC1A 1BB", "W1A 0AX"})

RESERVED_EMAIL_SUFFIXES = (
    ".example", ".test", ".invalid", ".localhost", ".local", ".internal",
    "example.com", "example.net", "example.org", "example.co.uk", "example.gov.uk",
)

FAKE_EMAIL_DOMAINS = frozenset({
    "test.com", "testing.com", "test.co.uk", "test.gov.uk", "fake.com", "fakemail.com", "email.com",
    "domain.com", "company.com", "acme.com", "foo.com", "bar.com", "foobar.com", "abc.com", "xyz.com",
    "somewhere.com", "nowhere.com", "mailinator.com", "yopmail.com", "sharklasers.com",
    "guerrillamail.com", "notreal.com", "dummy.com", "mock.com", "sample.com", "email.co.uk",
    "mail.test", "address.com", "emailaddress.com", "myemail.com", "youremail.com", "mydomain.com",
    "yourdomain.com", "host.com", "server.com", "users.noreply.github.com",
})

# Not personal data: infrastructure/service addresses that look like emails
SERVICE_EMAIL_DOMAINS = (
    "github.com", "noreply.github.com", "sentry.io", "amazonaws.com", "gserviceaccount.com",
    "iam.gserviceaccount.com", "azurewebsites.net", "docker.com", "gitlab.com", "bitbucket.org",
    "localhost", "notifications.service.gov.uk",
)

ROLE_LOCAL_PARTS = frozenset({
    "info", "admin", "administrator", "support", "contact", "enquiries", "enquiry", "helpdesk", "help",
    "noreply", "no-reply", "donotreply", "do-not-reply", "team", "hello", "webmaster", "postmaster",
    "hostmaster", "abuse", "security", "privacy", "digital", "service", "services", "office", "sales",
    "git", "root", "mailer-daemon", "notifications", "feedback", "data.protection", "dataprotection",
    "foi", "press", "media", "jobs", "careers", "accounts", "billing", "devops", "ops", "alerts",
})

FAKE_EMAIL_LOCAL_HINTS = ("test", "fake", "dummy", "example", "sample", "mock", "demo", "placeholder", "noone")

FAKE_EMAIL_LOCAL_PARTS = frozenset({
    "john.doe", "jane.doe", "johndoe", "janedoe", "joe.bloggs", "joebloggs", "fred.bloggs", "john.smith",
    "jane.smith", "someone", "somebody", "user", "user1", "user2", "foo", "bar", "foo.bar", "a", "b",
    "abc", "xyz", "me", "you", "name", "first.last", "firstname.lastname", "email", "username",
})

PERSONAL_EMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com",
    "live.co.uk", "msn.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "btinternet.com", "aol.com",
    "aol.co.uk", "icloud.com", "me.com", "mac.com", "protonmail.com", "proton.me", "sky.com",
    "talktalk.net", "virginmedia.com", "ntlworld.com", "blueyonder.co.uk", "tiscali.co.uk",
    "btopenworld.com", "gmx.com", "gmx.co.uk", "mail.com", "zoho.com", "fastmail.com",
})

WORK_EMAIL_SUFFIXES = (
    ".gov.uk", ".gov.scot", ".gov.wales", ".nhs.uk", "nhs.net", ".police.uk", ".mod.uk",
    "naturalengland.org.uk", "environment-agency.gov.uk", "marinemanagement.org.uk", "cefas.co.uk",
    "jncc.gov.uk", "kew.org", "forestryengland.uk", "defra.onmicrosoft.com",
)

PLACEHOLDER_NAMES = (
    "joe bloggs", "fred bloggs", "jane doe", "john doe", "john smith", "jane smith", "a n other",
    "test user", "mr test", "mrs test", "joe public", "john q public", "max mustermann", "foo bar",
    "firstname lastname", "first name", "last name", "lorem ipsum",
)
