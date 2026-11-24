# pii-scan: personal data scanner for public GitHub repositories

`pii-scan` looks for personal data and PII that has been committed by mistake to an organisation's public GitHub repositories (DEFRA by default). It scans **every public, non-fork repository and its full git history**, including:

- all branches and tags
- pull request branches (`refs/pull/*/head`), because closed and unmerged PR commits stay publicly visible on GitHub
- repository wikis
- spreadsheets, Word documents, PDFs and images anywhere in history

Each run produces a static HTML report:

- a summary page linking to per-repository detail
- separate review queues for production code and for test code
- pages and CSV exports grouped by repository, by GitHub team (write access or above) and by commit author
- full CSV and JSON exports

Your review decisions are kept between runs, so you can rerun it regularly to get a fresh snapshot.

> **The output is sensitive.** The report and database don't store raw values, but they do point to the exact files and lines where personal data was found. Don't publish the report, commit it, or paste findings into public GitHub issues.

---

## Contents

1. [What it detects](#what-it-detects)
2. [What it deliberately ignores](#what-it-deliberately-ignores)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Quick start](#quick-start)
6. [Scanning several organisations](#scanning-several-organisations)
7. [Commands and options](#commands-and-options)
8. [Configuration](#configuration)
9. [How findings are scored](#how-findings-are-scored)
10. [Reading the report](#reading-the-report)
11. [Triage workflow](#triage-workflow)
12. [Running it repeatedly](#running-it-repeatedly)
13. [Speed](#speed)
14. [What to do with a confirmed finding](#what-to-do-with-a-confirmed-finding)
15. [Data handling and security](#data-handling-and-security)
16. [Limitations](#limitations)
17. [Troubleshooting](#troubleshooting)
18. [Development](#development)

---

## What it detects

| Personal data type | Rule name | How it is detected | Main false positive controls |
| --- | --- | --- | --- |
| Names | `person_name` | Title plus name (`Mr Patel`, `Dear Mrs Watson-Hale`), plus a local spaCy model that finds people's names | The first word must be a known given name (from ONS and US SSA name lists), and no word may be a technical term (`Docker Compose`, `Natural England`). Outside data files, documents and wikis a name is only reported on the same line as an email, phone number, NI number or other identifier. Staff names, placeholder names and names in credits are ignored |
| Addresses and postcodes linked to an individual | `street_address`, `postcode` | Street address patterns (`14 Hawthorn Close`, `Lower Brook Farm`), UK postcodes checked against valid postcode areas | Only reported when something that identifies a person is on the same line or spreadsheet row. In data files a name counts; elsewhere it must be an email, phone number, NI number or similar (name and address pairs in code are almost always licence headers or sample text). Known example postcodes (`SW1A 1AA`) are marked fake |
| Email addresses | `email` | Email pattern, classified as personal webmail (higher risk) or other | Internal addresses (`*.gov.uk` and Defra group bodies), open source project addresses, staff commit addresses, reserved example domains, `noreply`, service and role mailboxes (`info@`, `support@`) and image names like `logo@2x.png` are ignored; test-looking addresses are marked fake |
| Phone numbers | `uk_phone` | UK mobiles and landlines in national or `+44` format | Ofcom drama numbers (`07700 900xxx`, `020 7946 0xxx` etc.) are marked fake; 03/08/09 non-geographic numbers ignored |
| Dates of birth | `dob` | A date within 40 characters of a keyword (`dob`, `date of birth`, `born`...) or in a column with that heading | Placeholder dates (1 Jan, 1900, 1970, 2000) |
| National Insurance numbers | `nino` | Format plus HMRC prefix validation | `QQ` prefix and common examples (`AB123456C`) are marked fake |
| Bank details and payment cards | `bank_account`, `payment_card` | Sort code plus 8-digit account near a "sort code" keyword; card numbers checked with the Luhn checksum, card network prefix and the right length for that network (Visa 13/16/19, Mastercard 16, Amex 15) | Unformatted numbers need a card keyword ("card number", `cardNumber`, "credit card", Visa...) on the same line or as the column heading. Space-grouped numbers inside a run of other numbers (rasters, readings), groups that are all years, and digits after a decimal point, `:` or `/` are ignored. Published test cards (Stripe, GOV.UK Pay etc.) are marked fake |
| Passport or driving licence numbers | `passport`, `driving_licence` | 9-digit passport number next to "passport"; DVLA licence format including the encoded date of birth | DVLA published example licences |
| Vehicle registration numbers | `vehicle_reg` | Current, prefix and suffix UK formats when a vehicle keyword is nearby | Placeholder plates (`AB12 CDE`) |
| IP addresses, device identifiers and location data | `ip_address`, `device_id`, `location` | Public IPv4 and IPv6 addresses; IMEI (Luhn), MAC addresses and advertising/device IDs next to keywords; UK latitude/longitude pairs and OS grid references; GPS position saved in photos | Private, reserved, documentation and public DNS IPs are ignored. All of these are only reported on the same line or row as an email, phone number or other identifier (a name alone is not enough, because place names are easily mistaken for people). A photo's GPS position is always reported |
| Photographs, signatures and scanned documents | `media` | Images with camera details or GPS saved in the file (EXIF); file names suggesting signatures, passports, ID cards, bank statements; phone formats (HEIC); PDFs with image-only pages (scans) | Images without camera details or suggestive names are ignored (icons, UI assets) |
| Free text from real cases | `case_text` | Letter greetings and sign-offs, forwarded email headers, case wording (case notes, complainant, safeguarding, witness statement...) | Only reported when linked to a person or in data files and wikis |
| Customer or business reference numbers | `customer_ref` | CRN (10 digits, from 1050000000), SBI (9 digits, 105000000 to 999999999), FRN (10 digits), CPH holding numbers (`12/345/6789`), each only next to its keyword or column heading | Repeated, sequential and range-boundary values are marked fake |
| Special category data | `special_category`, `nhs_number` | Health, ethnicity, religion, sexuality, political, trade union, genetic/biometric and criminal record terms; NHS numbers with a valid checksum next to "NHS" | A special category term is only reported if something identifying a person is within 3 lines; NHS 999 test numbers are marked fake |

**Spreadsheets and CSVs:** column headings are attached to each value before detection. A date in a `date_of_birth` column or a number in a `crn` column is found even when the row itself has no keyword.

**Where it looks:**
- **Text files:** every line added in every commit on every branch, tag and PR branch.
- **`xlsx`/`xlsm`, `docx` and `pdf` files:** text extracted from every version in history.
- **Images (`jpg`, `jpeg`, `png`, `tif`, `tiff`, `heic`, `heif`, `bmp`, `webp`):** file names and photo details (EXIF) of every version in history.
- **Wikis:** the full history of each repository's wiki.

**Skipped:** lockfiles, minified files, source maps, SVGs, `node_modules`, `vendor` and `dist` directories, and lines longer than 4000 characters (usually generated code). You can change this in `config.toml`.

**Large text files** (over 2 MB, usually datasets or dumps) are not diffed through history. Instead, the first 5,000 lines of each version are checked, which is enough to spot bulk personal data without reading every row. Findings from them say "large file: only the first 5000 lines were checked". Spreadsheets are sampled the same way (the first 5,000 rows of each sheet), and PDFs are read up to 300 pages.

---

## What it deliberately ignores

The aim is to find **personal data about members of the public that was committed by mistake**, not contact details that are meant to be there. These rules are all in the `[suppress]` section of `config.toml` and can be changed.

| What | Why | What is ignored |
| --- | --- | --- |
| **Published content**: READMEs, Markdown and other docs, `docs/` folders, web page templates (`njk`, `html`, `hbs`, `ejs`, `pug`, `liquid`, `cshtml`/Razor, `erb`...), locale and content files (`locales/`, `i18n/`, `content/`, `strings.xml`, `.po`, `.resx`), and `public/`, `static/`, `wwwroot/`, `assets/` folders | Contact details on web pages and in READMEs are published on purpose | Names, emails, phone numbers, addresses, postcodes, letter wording, CRN/SBI/FRN/CPH, photos and coordinates. **NI, NHS, card, bank, date of birth, passport, licence, vehicle and special category data are still reported** |
| **Manifests and credits**: `package.json`, `pom.xml`, `*.csproj`, `*.nuspec`, `setup.py`, `pyproject.toml`, `composer.json`, `Chart.yaml`, `catalog-info.yaml`, `CODEOWNERS`, `AUTHORS`, `CONTRIBUTORS`, `LICENSE`, `NOTICE`, `.github/`, Dockerfiles | These name the people who maintain the code | Names, emails, phone numbers, addresses and postcodes |
| **Author credits anywhere**: lines with `@author`, `Copyright`, `(c) 2021`, `All rights reserved`, `author:`, `maintainers =`, `<developer>` | Licence headers and vendored code credit their authors | Names, emails, phone numbers, addresses and postcodes on that line |
| **Internal email domains**: all `*.gov.uk`, plus `naturalengland.org.uk`, `marinemanagement.org.uk`, `cefas.co.uk`, `kew.org`, `forestryengland.uk` | Staff contact details are not the risk this tool is for | The address itself, and any name on the same line (assumed to be the same member of staff) |
| **Open source and vendor domains**: `apache.org`, `osgeo.org`, `eclipse.org`, `mozilla.org`, `microsoft.com`, `google.com` and others | Found in vendored libraries and licence headers | The address |
| **Staff**: everyone who has committed to any scanned repository, and every member of the GitHub organisation who has a public name | They are developers, not service users | Their names and commit email addresses, anywhere |
| **Test repositories**: repos named like `*-tests`, `*-journey-tests`, `*-performance-tests`, `*-test-suite`, `*-mock`, `*-stub`, `*-prototype` | The whole repository is test code | Nothing is ignored, but everything goes in Queue B (tests) and is scored as test data |

Add supplier domains to `internal_email_domains`, more paths to a `[[suppress.paths]]` entry, or a new `[[suppress.paths]]` entry of your own, then run `pii-scan scan --full`.

---

## Prerequisites

- Linux, macOS or WSL
- Python 3.12 or later
- `git` 2.38 or later
- GitHub CLI (`gh`), logged in: `gh auth login`. It's used to list repositories, look up usernames, and (if you are a member of the organisation) list teams and members. The default `gh` login scopes include `read:org`, which teams need.
- Disk space for local copies of every repository (several GB for the whole DEFRA organisation)

## Installation

```bash
cd data-scanner
python3 -m venv .venv
.venv/bin/pip install -e '.[ner,dev]'
.venv/bin/python -m spacy download en_core_web_md
```

The `ner` extra installs spaCy, which finds people's names. It's free and runs entirely on your machine. Without it the scanner still works, but only finds names written with a title (`Mr Smith`).

If you use `uv` instead: `uv venv && uv pip install -e '.[ner,dev]'`.

The examples below call `.venv/bin/pii-scan`. If you activate the virtual environment (`source .venv/bin/activate`), you can just type `pii-scan`.

## Quick start

```bash
# Try it on a few repositories first
.venv/bin/pii-scan run --limit 10
.venv/bin/pii-scan report --open

# Whole organisation
.venv/bin/pii-scan run
```

`run` runs these steps in order: `inventory`, `fetch`, `scan`, `enrich`, `teams`, `report`. The first run downloads every repository and can take a long time. Later runs only download and scan new commits.

## Scanning several organisations

By default only the `DEFRA` organisation is scanned. All organisations share one database (`data/scanner.db`) and one set of local copies (`data/mirrors/<org>/`), so scanning another organisation never overwrites earlier results, and triage decisions carry over.

1. Allow the GitHub CLI to read the enterprise. This opens a browser to approve it, and you need to be a member of the enterprise:
   ```bash
   gh auth refresh -h github.com -s read:enterprise
   ```
2. Find the enterprise's slug (the `slug` value in the output, for example `defra`):
   ```bash
   gh api graphql -f query='{ viewer { enterprises(first: 20) { nodes { slug } } } }'
   ```
3. List its organisations:
   ```bash
   .venv/bin/pii-scan orgs defra
   ```
   It prints an `orgs = [...]` line. Replace the `orgs` line in `config.toml` with it. Keep `DEFRA` (and any organisation you've already scanned) in the list so it stays in the report. If you're not an enterprise member, ask an enterprise owner for the list and type it in yourself.
4. Scan only the organisations that are new to you with `--org`. Others in the database are left alone:
   ```bash
   .venv/bin/pii-scan run --org Org-One,Org-Two
   ```
   Without `--org`, every organisation in `orgs` is updated (incrementally, so ones with no new commits are quick).
5. Open `reports/index.html`. It lists each organisation with counts only and links to its own report in `reports/<org>/`.

Each `reports/<org>/` folder is self-contained (its own pages, `findings.csv`, `findings.json`, `exports/` and stylesheet) and holds only that organisation's findings, so you can zip it and send it to that organisation's admins. Don't send the whole `reports/` folder.

Staff suppression covers the whole enterprise: commit authors and members of any organisation in the database are treated as staff in every organisation. Teams and members are read per organisation, which needs you to be a member of each one; otherwise a warning is printed and those pages show no teams.

Run one `pii-scan` at a time against the same database. To scan several organisations, pass them all to one `--org`.

---

## Commands and options

Every command accepts `--config/-c PATH` (default `config.toml` in the current directory) and `--help`. `inventory`, `fetch`, `scan`, `run` and `teams` also accept `--org a,b`, which replaces `orgs` from the config for that command.

### `pii-scan run`

Runs the whole pipeline.

| Option | Meaning |
| --- | --- |
| `--org a,b` | Only these organisations (default: `orgs` in the config). The report is still rebuilt for every organisation |
| `--repos a,b,c` | Only these repository names |
| `--limit N` | Only the first N repositories (alphabetical) |
| `--full` | Rescan all history instead of only new commits. Use this after changing detection rules or config |
| `--skip-fetch` | Don't refresh the repository list or download; scan the local copies you already have |
| `--ner-scope off\|targeted\|all` | Override the name detection scope (see [Configuration](#configuration)) |

### `pii-scan inventory`

Lists the organisation's public repositories with `gh api` and records each repo's name, URL, archived flag, default branch, last push time and wiki flag. Forks and anything in `exclude_repos` are left out. It also records the organisation's members, whose names are then treated as staff (see [What it deliberately ignores](#what-it-deliberately-ignores)).

### `pii-scan fetch [--repos ...] [--limit N]`

Creates or updates a local bare copy of each repository under `data/mirrors/<org>/`, including branches, tags and PR branches. It also copies each repository's wiki if one exists.

### `pii-scan scan [--repos ...] [--limit N] [--full] [--ner-scope ...]`

Scans the local copies and records findings in `data/scanner.db`. Each repository is scanned incrementally unless you pass `--full` or its history has been rewritten (see [Running it repeatedly](#running-it-repeatedly)). The biggest repositories are started first, and the 10 slowest are listed at the end.

### `pii-scan enrich`

Looks up the GitHub username behind each commit that introduced a High, Medium or Low finding. The git author name in a commit isn't necessarily a GitHub username.

- Only one commit is looked up per author email address, and the answer is reused for all their commits and on later runs.
- Lookups are batched, about 50 per GitHub GraphQL request, so even the whole organisation takes a handful of requests.
- If the GraphQL rate limit runs low, it waits for it to reset rather than stopping.
- Emails with no GitHub account are remembered and only rechecked after 30 days.

### `pii-scan teams`

Records which GitHub teams have **write, maintain or admin** access to each repository (child teams inherit their parent team's access). This needs you to be a member of the organisation. Teams you can't see (secret teams you're not in) are left out. Shown on repository pages, the summary and the Teams page.

### `pii-scan report [--org a,b] [--open]`

Rebuilds `reports/` from the database: one folder per organisation and the top-level index. It's fast, so run it after importing triage decisions. With `--org`, only those organisations' folders (and the index) are replaced.

### `pii-scan orgs ENTERPRISE [--exclude a,b]`

Lists the organisations in a GitHub enterprise and prints them as an `orgs = [...]` line for `config.toml`. Needs enterprise membership and the `read:enterprise` scope.

### `pii-scan triage export [FILE] [--bands High,Medium,Low] [--include-triaged] [--org a,b]`

Writes findings to a CSV file (default `triage.csv`) for review. See [Triage workflow](#triage-workflow).

### `pii-scan triage import FILE [--reviewer NAME]`

Records the decisions from an edited triage CSV.

---

## Configuration

`config.toml` is read from the current directory. Paths are relative to the config file.

| Section | Key | Default | Meaning |
| --- | --- | --- | --- |
| `[github]` | `orgs` | `["DEFRA"]` | Organisations to scan (overridden by `--org`) |
| | `include_forks` | `false` | Include forked repositories |
| | `exclude_repos` | `[]` | Repository names to skip |
| `[paths]` | `data_dir` | `data` | Local copies, database and secret key |
| | `reports_dir` | `reports` | Report output (replaced on every `report`) |
| `[fetch]` | `workers` | `8` | Parallel downloads |
| | `include_wikis` | `true` | Copy and scan wikis |
| `[scan]` | `workers` | `4` | Parallel scan processes. Each loads its own spaCy model (about 400 MB), so lower this if memory is tight |
| | `max_memory_mb` | `0` | Most extra memory one repository may use inside a worker. `0` sizes it from the RAM available when the scan starts (Linux and WSL; on macOS, which swaps rather than killing processes, `0` means no limit). A repository that goes over is recorded as an error and retried on the next run |
| | `max_line_length` | `4000` | Longer lines are skipped as generated or minified |
| | `large_file_bytes` | `2000000` | Text files bigger than this are sampled instead of diffed through history |
| | `large_file_sample_lines` | `5000` | Lines checked from the start of each version of a large file |
| | `include_documents` | `true` | Scan office, PDF and image files in history |
| | `max_document_bytes` | `20000000` | Bigger binary files are skipped and listed in the report under *Documents not scanned* |
| | `exclude_globs` | lockfiles, vendored and generated code | Paths not scanned |
| `[ner]` | `scope` | `targeted` | `off`: titled names only. `targeted`: data files, documents and wikis outside test folders, plus any line that already has other personal data. `all`: every added line (slow, and finds many false names in source code) |
| | `model` | `en_core_web_md` | spaCy model. `en_core_web_lg` is slightly more accurate and uses more memory |
| | `max_lines_per_file` | `2000` | Cap on name-detection lines per file change |
| `[tiers]` | `test_patterns` | test, spec, fixtures, mocks, cypress... | Regexes that put a path in the **test** tier (Queue B) |
| | `test_repo_patterns` | `-tests`, `-journey-tests`, `-mock`, `-stub`, `-prototype`... | Regexes on the repository name that put the whole repository in the test tier |
| | `docs_patterns` | docs, examples, README, seeds... | Regexes for the **docs** tier (Queue B) |
| | `data_extensions` | csv, xlsx, sql, txt, log, pdf... | Extensions that count as **data** files (Queue A, scored higher) |
| | `data_patterns` | data, exports, dumps, backups... | Directory names that count as data |
| | `ner_extensions` | none | Extra extensions name detection runs on in `targeted` scope |
| `[suppress]` | `internal_email_domains` | `.gov.uk` and Defra group bodies | Never reported; a name on the same line is treated as staff too. Add suppliers here |
| | `ignore_email_domains` | open source and vendor domains | Never reported |
| | `ignore_staff` | `true` | Ignore names and emails of org members and all commit authors |
| | `authorship_patterns`, `authorship_rules` | `@author`, `Copyright`, `author:`... | Lines that credit authors, and the rules skipped on them |
| | `[[suppress.paths]]` | published content, manifests and credits | Each entry has a `name`, the `rules` to skip, and path `patterns` (regexes) |
| `[enrich]` | `bands` | `High, Medium, Low` | Bands to look up GitHub usernames for |

After changing `[tiers]`, `[suppress]`, `exclude_globs` or `[ner]`, run `pii-scan scan --full` so existing findings are rescored.

---

## How findings are scored

Every finding gets a **score from 0 to 10**, a **band**, a **tier** and a **queue**. The *Why* column in the report lists every factor that went into the score.

### Score

```
score = base severity x confidence x tier weight x context factors   (capped at 10)
```

- **Base severity** reflects how harmful the data type is. For example, card, bank, NI and NHS numbers are 9; passports and licences 8; special category data 7; personal webmail and mobile numbers 6; work email addresses 2.5; postcodes 2.
- **Confidence** reflects how sure the pattern match is, for example whether a supporting keyword was found or the value is formatted the way people usually write it.
- **Tier weight** depends on where the file is:

  | Tier | Weight | Matches | Queue |
  | --- | --- | --- | --- |
  | data | 1.2 | csv, xlsx, sql, logs, `data/`, `exports/`... | A |
  | wiki | 1.0 | repository wikis | A |
  | code | 0.8 | everything else | A |
  | docs | 0.6 | docs, examples, README, seeds | B |
  | test | 0.4 | tests, specs, fixtures, mocks, cypress, "Test Data" | B |

- **Context factors:**

  | Factor | Effect |
  | --- | --- |
  | Data-style file inside a test or docs folder | x1.2 |
  | "fake / example / dummy / mock" wording within 3 lines | x0.5 |
  | Test wording nearby (outside test folders) | x0.8 |
  | Placeholder name nearby | x0.4 |
  | File imports a fake data library (faker, chance, mimesis, Bogus...) | x0.4 |
  | Value matches the commit author's own name or email (already public in git) | x0.3 |
  | Another personal data type on the same line / row | x1.4 (one) or x1.8 (two or more) |
  | Many distinct values of the same type in one file change | x1.3 (10+), x1.6 (50+), x2.0 (500+) |

### Bands

| Band | Meaning | Suggested action |
| --- | --- | --- |
| **High** (score 6+) | Very likely real personal data, often several types together or bulk data | Review first |
| **Medium** (3.5 to 6) | Plausibly real | Review |
| **Low** (1.5 to 3.5) | Probably fake, a work contact, or a single weak signal | Review when time allows, or sample |
| **Minimal** (under 1.5) | Very weak signal | Not in queues; listed on each repository page |
| **Likely fake** | Matches a known test or reserved value (Ofcom drama number, test card, `QQ` NI number, NHS 999 range, placeholder) | Not in queues; listed on each repository page |

### Queues

- **Queue A:** production code, data files and wikis. Personal data here is most likely to be real.
- **Queue B:** tests, fixtures, docs and examples. Real data does turn up in test fixtures (copied from live systems), so review this separately rather than ignoring it.

### Linked data

Some types only count as personal data when they relate to a person:
- postcodes and street addresses
- IP addresses and device identifiers
- locations
- correspondence and case wording

These are only reported when something that identifies a person is on the same line or spreadsheet row:

| Type | In data files, documents and wikis | Everywhere else |
| --- | --- | --- |
| Postcodes, street addresses, case wording | a strong identifier (email, phone, NI number, date of birth, CRN...) or a person's name | a strong identifier |
| Locations, IP addresses, device identifiers | a strong identifier (or, for locations, the photo they came from) | a strong identifier |
| Names | can be reported on their own | a strong identifier |

So a dataset of property addresses or flood-zone coordinates is not reported, but a spreadsheet row with a name, address and phone number is.

Special category terms always need an identifier within 3 lines.

### Test and docs locations

To keep the scan fast, test and docs files (Queue B) get a lighter check:
- spreadsheets and large files are sampled from their first 500 rows (rather than 5,000)
- name detection only runs on lines that already hold an email, phone number or other strong identifier, up to 200 lines per file version

Real data copied into a test fixture still shows up, because it almost always comes with emails or phone numbers.

### Large files

At most 100 distinct values of each type are listed per file. The highest-scoring one says how many more there are (for example "+1076 more distinct values of this type in this file not listed"). The full count is also shown in the bulk factor.

---

## Reading the report

Open `reports/index.html` for the list of organisations, then an organisation's `reports/<org>/index.html`. The pages and exports below are per organisation. The report uses [GOV.UK Design System](https://design-system.service.gov.uk/) components set in Arial, with a Defra header and green navigation like the [Defra digital service manual](https://digital.defra.gov.uk/service-manual). Every page shows an OFFICIAL-SENSITIVE warning as a reminder that it's sensitive.

In any table, select a column heading to sort it, and use the *Filter* box above it to narrow the rows.

**Priority order:** repositories are ranked by Queue A High findings, then Queue A Medium, Queue B High, Queue A Low and Queue B Medium (priority 1 is the one to investigate first). Every list of findings is grouped by repository in that order, then by band and score within each repository. The *Priority* column shows the rank; sort by it to return to the default order after sorting by another column. The rank is also the `priority` column in every CSV export.

### Summary page

- **Findings needing review:** counts per band for Queue A and Queue B, each split into active and archived repositories, plus how many active and archived repositories have something to review. Each number opens the queue already filtered to that band and status (for example `queue-a.html?band=High&archived=1`).
- **Repositories by band:** how many active and archived repositories have at least one finding needing review in each band, for Queue A, Queue B and either queue. A repository with findings in several bands is counted in each, and the *Any band* row counts each repository once.
- **Sources:** how many reviewable findings came from code history, documents/images, or wikis.
- **Changes since previous run:** new findings, and findings that have gone (usually because history was rewritten).
- **Still exposed on the default branch vs history only**, split into active and archived repositories:
  - *Still present:* the value is in the current version of the file on the default branch, so anyone browsing the repo can see it.
  - *History only:* it has been deleted but can still be reached through the commit link and anyone's existing clone.
- **By type:** counts per data type for High, Medium and Low (each split active/archived), plus Minimal and Likely fake totals.
- **Repositories with findings:** in priority order, sortable and filterable (including an *Active/Archived* filter). Shows teams with write access, archived flag, last commit date and counts per queue and band. Archived repositories with findings are counted separately because making them private is often the quickest fix. Download the table with *Download as CSV*.
- **Documents not scanned:** spreadsheets, Word files, PDFs and images that were corrupt, password protected or over `max_document_bytes`. Each repository page lists them with a link, so you can open them by hand. Only populated for scans made since this feature was added; run `pii-scan scan --full` to fill it in for older results.
- **Errors:** repositories that failed to download or scan.

### Finding tables (queue, repository, new and triaged pages)

| Column | Meaning |
| --- | --- |
| Priority | Repository rank (see *Priority order* above). Shown where findings from several repositories are listed |
| Band, Score | See [How findings are scored](#how-findings-are-scored). A blue **new** tag means it first appeared in the latest run |
| Repo | Repository page, with an **archived** tag if applicable and the teams with write access underneath |
| Type | Data type, plus the tier and source (`document` for office/PDF/image files, `wiki`) |
| Value (masked) | A partly hidden value for triage, for example `m***@gmail.com`, `07*******36`, `**** 0366`, `CRN 11******61`. Media, case wording and special category findings show a description instead |
| File | Link to the file **at the commit that introduced it**, to the exact line for text files. For documents the sheet/row, table or page is shown |
| Introduced | Link to the earliest commit that added this value to this file, and its author date |
| Author | Git author name and, where it could be found, a link to the GitHub user |
| Default branch | *Still present*, *History only* or *Unknown* |
| Seen | How many commits added this value to this file |
| Why | Every factor behind the score |
| Triage | Recorded decision and note, plus the start of the fingerprint used for triage |

Above each table is a filter panel:

- a text box that searches the repository, type, author, path and other visible text
- drop-downs for *Band*, *Queue*, *Repository status* (active or archived), *Default branch* (still present, history only, unknown), *Type*, *Tier*, *Source*, *Team* and *New since previous run*. Each only lists values found in that table, and is hidden when there's nothing to choose between
- a count of the rows shown, and *Clear filters*
- **Download filtered CSV**, which saves the rows currently shown, in their current order, with the same columns as `findings.csv`. The file is built in your browser from data already in the page, so nothing is sent anywhere. Filters can also be preset with the page address, for example `queue-b.html?band=High&archived=0&teams=Flood%20Devs`.

### Teams and Authors pages

- **Teams** (`teams.html`): one row per GitHub team with write, maintain or admin access, with counts per queue and band across all its repositories and its most common data types. A finding counts towards every team with access to its repository, so totals overlap. Findings in repositories with no such team are grouped under *(no team with write access)*. Each team has its own page listing its findings.
- **Authors** (`authors.html`): one row per person who first committed findings, by GitHub username where `enrich` found one, otherwise by commit email. Each author has their own page.

Only High, Medium and Low findings that haven't been triaged away are counted on these pages and in their CSVs.

### Exports

- `reports/<org>/findings.csv`: every active finding in that organisation with full links, teams and reasons. Cells starting with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheet apps don't run them as formulas.
- `reports/<org>/findings.json`: the same data for scripts.
- `reports/<org>/exports/by-repo.csv`, `by-team.csv`, `by-author.csv`: one summary row per repository, team or author, with counts per queue and band.
- `reports/<org>/exports/repos/<org>__<repo>.csv`, `teams/<team>.csv`, `authors/<author>.csv`: the reviewable findings for one repository, team or author, ready to send to the people who need to act. Every page in the report links to its own CSV.

### Interpreting common patterns

- **One file with hundreds of High findings across several types** (for example a spreadsheet with names, mobiles, dates of birth and holding numbers) is probably a real data extract. Treat it as a possible incident.
- **Personal webmail or mobile numbers in Queue B** often means a developer used their own or a colleague's details as test data. Those are still real and still personal data.
- **The same value in many repositories** is usually a shared test fixture. Check it once and triage it as `fake` everywhere.
- **Public sector work addresses** are no longer reported (see [What it deliberately ignores](#what-it-deliberately-ignores)). If you want them back, remove `.gov.uk` from `internal_email_domains`.
- **Lots of Low email findings in one repository's Java, XSL or XSD files** usually means a copy of a third-party project (for example a vendored GeoNetwork source tree) with its contributors' addresses. Add that folder to `exclude_globs` (for example `"**/core-geonetwork*/**"`) if you're happy it's unmodified upstream code.

---

## Triage workflow

1. Export the findings that need a decision:
   ```bash
   .venv/bin/pii-scan triage export triage.csv               # High, Medium, Low without a decision
   .venv/bin/pii-scan triage export triage.csv --bands High  # just High
   .venv/bin/pii-scan triage export triage.csv --org Org-One # one organisation
   ```
2. Open `triage.csv` in a spreadsheet and fill in `status` (and optionally `note`) for each row. Use the `file_url` and `commit_url` links to check the context.

   | status | Use when |
   | --- | --- |
   | `confirmed` | Real personal data that needs fixing |
   | `false_positive` | Not personal data (detector mistake) |
   | `fake` | Looks personal but is made up |
   | `accepted` | Real, but fine to be public (for example a published work contact) |
   | `remediated` | Removed and history cleaned |
   | `clear` | Remove a previous decision |

3. Import and rebuild the report:
   ```bash
   .venv/bin/pii-scan triage import triage.csv --reviewer "Your Name"
   .venv/bin/pii-scan report
   ```

Decisions are stored against each finding's **fingerprint**, which stays the same across runs. That means:
- Findings marked `false_positive`, `fake`, `accepted` or `remediated` are hidden from the queues and shown on the *Triaged* page.
- `confirmed` findings stay visible with a tag.

`triage*.csv` files are gitignored because they contain links to personal data.

---

## Running it repeatedly

```bash
.venv/bin/pii-scan run            # incremental: only new commits since the last scan
.venv/bin/pii-scan run --full     # rescan everything, for example after changing rules or config
```

- **Incremental scans:** the scanner remembers every branch, tag and PR tip it scanned in each repository. The next scan only reads commits that weren't reachable before. A repository with no new commits is skipped.
- **Rewritten history:** if a branch was force-pushed or deleted, that repository automatically gets a full rescan. Findings that have gone show as no longer present in "Changes since previous run".
- **Interrupted runs:** each repository is saved as soon as it finishes, so after a crash or Ctrl-C you can run `pii-scan run --skip-fetch` (without `--full`) and only the unfinished repositories are scanned.
- **Lost connection:** an organisation that can't be listed after 3 attempts keeps its previous repository list, with a warning. A download that receives nothing for 5 minutes is abandoned and recorded as a fetch error. Run `pii-scan fetch` again to retry; finished repositories only fetch new commits.
- **Killed workers:** if the operating system kills a scan worker (usually out of memory), only the repositories it was working on are retried on their own. If one still fails it is recorded as an error and the run carries on.
- **"Still present" check:** redone for files that changed on the default branch or have new findings. Files whose default-branch version hasn't changed since the last check are skipped. `--full` rechecks everything.
- **Run history:** every run records which organisations it scanned. Each organisation's summary compares the latest two runs that included it, so scanning one organisation doesn't make another's findings look new.
- **Different scopes:** `--repos` and `--limit` work for quick checks. The report always shows the latest state of every repository scanned so far.

---

## Speed

The first full scan of the whole organisation is the slow one. After that, `run` is incremental and only reads new commits, so it is usually much quicker.

What the scanner does to keep the full scan down:

- **Biggest repositories start first**, so one huge repository doesn't start last and stretch the run.
- **Large text files are sampled, not diffed** (see `large_file_bytes`). Datasets with many versions were the biggest single cost.
- **Name detection (spaCy) only runs where it's useful:** data files, documents and wikis outside test folders, and lines with at least two capitalised words in a row. Lines already seen in an earlier version of the file reuse the earlier result.
- **Published content and manifests skip name detection entirely.**
- **Images are only opened when they can carry camera details** (`jpg`, `tif`, `webp`). `png` and `bmp` are judged by file name.
- **The commit that added each document is found in one pass** over the history, rather than one search per document.
- **PDFs are parsed once** for both text and scanned pages.

At the end of each scan the 10 slowest repositories are printed, with how many lines were checked and how many went through name detection. The same figures are stored on the `repos` table (`scan_seconds`, `scan_lines`, `scan_ner_lines`). If one repository dominates, consider excluding its data folders with `exclude_globs`.

More `[scan] workers` helps if you have the memory: each worker needs about 400 MB for spaCy plus working memory.

---

## What to do with a confirmed finding

Deleting the file in a new commit **doesn't** remove the data. It stays in history, in PR branches, in GitHub's cached views, and in everyone's forks and clones.

1. **Treat it as a potential data incident.** Follow Defra's data protection incident process and tell the Data Protection Officer and security team. Don't raise a public issue or PR that describes the data.
2. **Reduce exposure quickly.** If the repository doesn't need to be public (especially if it's archived), ask an organisation owner to make it private.
3. **Remove the data from history.** Use `git filter-repo` or BFG on a fresh clone, then force-push all affected branches and tags. Coordinate with the repository owners, because everyone needs to re-clone.
4. **Ask GitHub to purge cached data.** Contact GitHub Support with the repository and commit SHAs to remove cached views and PR branches. Pull request branches can't be force-pushed by you.
5. **Check forks.** Forks made by other accounts keep their own copy.
6. **Mark the finding `remediated`** and rerun to confirm it has gone.

---

## Data handling and security

- **No raw values stored:**
  - Matches are kept in memory only while a repository is scanned.
  - The database and report store a masked value plus an HMAC fingerprint, keyed with a random secret in `data/secret.key` (created on first run, permissions `600`).
  - Without that key, a fingerprint can't be matched against a guessed value.
- **What is shown:** file paths, commit links and author names, all of which are already public on GitHub. A file name can itself contain a person's name.
- **Keep it out of git:** `data/`, `reports/` and `triage*.csv` are gitignored. Keep them on an encrypted, access-controlled device.
- **HTML report:** marked `noindex` and contains no external resources: the stylesheet and Defra logo are copied into `reports/assets/`, and no web fonts are used. All repository content is escaped.
- **GitHub access:** the scanner only reads public repositories with your `gh` login. It never writes to GitHub.

---

## Limitations

- **Content in images isn't read.** There is no OCR or face detection. Photos and scans are flagged from camera details, GPS, file names and image-only PDF pages. A screenshot of personal data with a generic file name won't be found.
- **Some file types aren't converted.** Old `.xls`, `.doc`, `.pptx`, `.odt`/`.ods`, `.msg` and archives (`.zip`) aren't extracted. Git LFS files are only seen as pointer files. Corrupt, password protected and oversized files are listed under *Documents not scanned* rather than being silently skipped.
- **Names and free text are heuristic.** Expect some missed names (single first names, lower case, first names not in the ONS or US SSA lists) and some false ones (product or place names that start with a common first name). Case notes are detected from typical wording and greetings, not by understanding the content.
- **Staff filtering can hide a real leak** of a member of staff's own personal data, for example their gmail address in a data file. That is a deliberate trade-off; set `ignore_staff = false` to check.
- **Large files are sampled.** Personal data that only appears after the first 5,000 lines of a big file isn't found.
- **Linked data rules can miss things.** A postcode or IP address on its own line in source code isn't reported, by design.
- **Keyword-gated rules need context.** Passport numbers, CRN/SBI/FRN/CPH, vehicle registrations, IMEI and MAC addresses, NHS numbers and dates of birth need a keyword or column heading nearby.
- **Some public places aren't covered:** issues, PR comments, gists, releases, Actions logs, and commits only reachable by SHA (deleted branches that never had a PR).
- **Merge commits:** only changes that came from a merge conflict resolution aren't scanned.
- **Commit metadata isn't scanned.** Git author names and emails are themselves personal data but expected to be public.

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `gh: command not found` or 401 errors | Install the GitHub CLI and run `gh auth login` |
| `spaCy model ... missing, name detection disabled` | `.venv/bin/python -m spacy download en_core_web_md` |
| Out of memory, or `MemoryBudgetExceeded` against a repository | Lower `[scan] workers` (each worker needs about 400 MB plus its working memory), raise `[scan] max_memory_mb` for the one big repository, or set `[ner] scope = "off"`. Repositories that hit the budget are retried automatically on the next `scan` |
| `Worker process was killed by the OS` against a repository | The OS ran out of memory even for that repository alone. Close other programs, lower `workers`, or add the repository to `exclude_repos` |
| `UserWarning` messages from openpyxl | These are suppressed. If you still see them, they come from another library and can be ignored |
| `GitHub GraphQL rate limit nearly used; waiting...` | Normal on a big first `enrich`. It waits for the limit to reset and carries on |
| `Could not read DEFRA teams` | You need to be a member of the organisation, and your `gh` login needs `read:org` (`gh auth refresh -s read:org`) |
| A repository listed under errors | Check the message. Network errors usually clear on the next `fetch` |
| Too many findings from one kind of file | Add its directory or extension to `exclude_globs` or a tier pattern, then `scan --full` |
| Start from scratch | Delete `data/scanner.db`. Keep `data/mirrors` to avoid downloading again, and keep `data/secret.key` if you want existing triage files to still match |

---

## Development

```bash
.venv/bin/pytest -q
```

- `tests/test_detectors.py` and `tests/test_extended.py` check every detector, including fake-value handling and masking.
- `tests/test_resilience.py` checks that a killed worker only fails its own repository, the memory budget aborts one repository and the worker carries on, oversized files are skipped without being loaded, and corrupt documents are told apart from empty ones.
- `tests/test_scanner.py` builds a synthetic git repository and checks:
  - the introducing commit, author and line
  - PR-only commits
  - spreadsheets, photos with GPS, and CSV column headings
  - "history only" status
  - incremental scans
  - that no raw value ever appears in findings or the HTML report
  - that report pages load nothing from outside `reports/`
- `tests/test_multi_org.py` checks that each organisation's report folder and exports contain only its own findings, that "new since previous run" is worked out per organisation, the `--org` filter, and that an organisation that can't be listed keeps its repositories.

All values in the tests are made up.

### Project layout

```
config.toml                    settings
LICENCE                        Open Government Licence v3.0
src/pii_scanner/
  cli.py                       commands
  inventory.py, fetch.py       repository list and local copies
  runner.py                    worker pool that survives killed workers; automatic memory budget
  scanner.py                   history, document/media and wiki scanning; "still present" check; per repo memory watchdog
  detectors/rules.py           names/contact/ID/financial rules
  detectors/extended.py        address, vehicle, IP, device, location, CRN/SBI/FRN/CPH, case text, special category
  detectors/fakes.py           known test and reserved values
  detectors/validators.py      checksums and format checks
  blobs.py                     office/PDF text, image details (EXIF), scanned PDF detection
  ner.py                       spaCy name detection, given-name and technical-word filters
  data/given_names.txt         given names list (built by scripts/build_given_names.py)
  context.py, scoring.py       tiers, suppression rules, fake-data signals, scoring and bands
  store.py                     SQLite database
  github.py                    GitHub GraphQL: batched username lookups, teams, members, enterprise organisations
  enrich.py                    username, team and member refresh
  report.py, templates/        per-organisation HTML, CSV and JSON reports, team and author pages, organisation index
  static/                      compiled report stylesheet and Defra logo, copied to reports/assets/
  triage.py                    triage export/import
scripts/
  build_given_names.py         rebuild the given names list
  build_report_css.sh          rebuild the report stylesheet from report.scss
  report.scss                  report styles: GOV.UK Frontend in Arial plus Defra header, navigation and footer
  compare_repos.py             rescan named repos and compare counts with the last run (no database changes)
```

### Given names list

`src/pii_scanner/data/given_names.txt` combines:
- ONS *Baby names in England and Wales: from 1996* (names given to at least 10 babies), Office for National Statistics, licensed under the [Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/)
- US Social Security Administration top 1,000 names per year 1880 to 2008 (public domain)

Rebuild it with `.venv/bin/python scripts/build_given_names.py`.

### Report styling

The report uses [GOV.UK Frontend](https://frontend.design-system.service.gov.uk/) with `$govuk-font-family` set to Arial, so the GDS Transport font is never loaded. The header, green service navigation and footer follow the [Defra digital service manual](https://digital.defra.gov.uk/service-manual) rather than the GOV.UK service header.

The compiled `src/pii_scanner/static/report.min.css` is committed, so building reports doesn't need Node. After changing `scripts/report.scss`, or to upgrade GOV.UK Frontend, run:

```bash
scripts/build_report_css.sh                                # uses the pinned version
GOVUK_FRONTEND_VERSION=6.7.0 scripts/build_report_css.sh   # try a newer release
```

The script needs Node and npm, installs `govuk-frontend` and `sass` in a temporary folder, and fails if the output references any external file. Then run `pii-scan report` to rebuild the report from the database without rescanning.

### Tuning rules

`scripts/compare_repos.py repo-a repo-b` rescans the named repositories with the current rules and prints before and after counts per data type, without changing the database. Use it to check a rule change on the repositories that prompted it before running a full rescan.

### Adding a detector

1. Write a function `detect_x(line, ctx) -> list[Candidate]` in `detectors/extended.py`. Set `norm` to a stable normalised value; it becomes part of the fingerprint. Add any known fake values to `fake`.
2. Add the rule to `CATEGORIES` in `detectors/rules.py`. Also add it to `IDENTIFIER_RULES` or `LINKABLE_RULES` if it should affect the linked data rules.
3. Register it in `DIGIT_ONLY` or `TEXT` in `detectors/__init__.py`, and add masking in `mask()` if the default isn't suitable.
4. Add tests with synthetic values, then run `pii-scan scan --full`.

---

## Licence

THIS INFORMATION IS LICENSED UNDER THE CONDITIONS OF THE OPEN GOVERNMENT LICENCE found at:

<http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3>

The full text of the licence terms is in [LICENCE](./LICENCE).

The following attribution statement MUST be cited in your products and applications when using this information.

> Contains public sector information licensed under the Open Government license v3

### About the licence

The Open Government Licence (OGL) was developed by the Controller of Her Majesty's Stationery Office (HMSO) to enable
information providers in the public sector to license the use and re-use of their information under a common open
licence.

It is designed to encourage use and re-use of information freely and flexibly, with only a few conditions.
