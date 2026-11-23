from __future__ import annotations

import re
from dataclasses import dataclass

from .config import Config
from .detectors.fakes import PLACEHOLDER_NAMES

FAKE_KW_RE = re.compile(
    r"\b(fake|faked|dummy|mock(?:ed)?|example|sample|placeholder|lorem|ipsum|fictional|fictitious|"
    r"stub(?:bed)?|fixture|faker|synthetic|made[ \-]up|not[ \-]real)\b",
    re.I,
)
TEST_KW_RE = re.compile(r"\b(test|testing|tests|spec|describe|it\(|expect\(|assert)\b", re.I)
FAKER_RE = re.compile(
    r"@faker-js/faker|\bfaker\b|\bFaker\b|from faker import|chance\.js|new Chance\(|\bmimesis\b|"
    r"factory_boy|\bBogus\b|casual\.|randomUser|@ngneat/falso",
)
PLACEHOLDER_RE = re.compile("|".join(re.escape(n) for n in PLACEHOLDER_NAMES), re.I)


@dataclass(frozen=True)
class PathInfo:
    tier: str  # test | docs | data | code | wiki
    queue: str  # A (production/data/wiki) | B (test/docs)
    ext: str
    data_like: bool


class PathClassifier:
    def __init__(self, cfg: Config, repo: str = ""):
        self.test = [re.compile(p, re.I) for p in cfg.test_patterns]
        self.docs = [re.compile(p, re.I) for p in cfg.docs_patterns]
        self.data_dirs = [re.compile(p, re.I) for p in cfg.data_patterns]
        self.data_ext = set(cfg.data_extensions)
        self.ner_ext = set(cfg.data_extensions) | set(cfg.ner_extensions)
        self.test_repo = any(re.search(p, repo, re.I) for p in cfg.test_repo_patterns)
        self.suppress = [
            ([re.compile(p, re.I) for p in s.get("patterns", [])], frozenset(s.get("rules", [])))
            for s in cfg.suppress_paths
        ]
        self.authorship = re.compile("|".join(cfg.authorship_patterns), re.I) if cfg.authorship_patterns else None
        self.authorship_rules = frozenset(cfg.authorship_rules)
        self.internal_domains = tuple(d.lower() for d in cfg.internal_email_domains)
        self.ignored_domains = tuple(d.lower() for d in cfg.ignore_email_domains)
        self._cache: dict[tuple[str, bool], PathInfo] = {}
        self._suppressed: dict[str, frozenset[str]] = {}

    def classify(self, path: str, wiki: bool = False) -> PathInfo:
        key = (path, wiki)
        if key not in self._cache:
            self._cache[key] = self._classify(path, wiki)
        return self._cache[key]

    def suppressed(self, path: str, wiki: bool = False) -> frozenset[str]:
        """Rules not reported for this path because its contents are published or credit authors on purpose."""
        if wiki:
            return frozenset()
        if path not in self._suppressed:
            rules: frozenset[str] = frozenset()
            for patterns, rs in self.suppress:
                if any(p.search(path) for p in patterns):
                    rules |= rs
            self._suppressed[path] = rules
        return self._suppressed[path]

    def authorship_line(self, text: str) -> bool:
        return bool(self.authorship and self.authorship.search(text))

    def email_domain_ignored(self, email: str) -> bool:
        return _domain_in(email, self.internal_domains + self.ignored_domains)

    def email_internal(self, email: str) -> bool:
        return _domain_in(email, self.internal_domains)

    def ner_eligible(self, path: str) -> bool:
        return path.rsplit(".", 1)[-1].lower() in self.ner_ext if "." in path else False

    def _classify(self, path: str, wiki: bool) -> PathInfo:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        data_like = ext in self.data_ext or any(p.search(path) for p in self.data_dirs)
        if wiki:
            return PathInfo("wiki", "A", ext, data_like)
        if self.test_repo or any(p.search(path) for p in self.test):
            return PathInfo("test", "B", ext, data_like)
        if any(p.search(path) for p in self.docs):
            return PathInfo("docs", "B", ext, data_like)
        if data_like:
            return PathInfo("data", "A", ext, True)
        return PathInfo("code", "A", ext, False)


def _domain_in(email: str, suffixes: tuple[str, ...]) -> bool:
    domain = email.rsplit("@", 1)[-1].lower()
    return any(domain == s.lstrip(".") or domain.endswith("." + s.lstrip(".")) for s in suffixes)


def context_signals(window: str) -> list[str]:
    """Fake-data hints from the lines around a match."""
    signals = []
    if FAKE_KW_RE.search(window):
        signals.append("fake/example wording nearby")
    if TEST_KW_RE.search(window):
        signals.append("test wording nearby")
    if PLACEHOLDER_RE.search(window):
        signals.append("placeholder name nearby")
    return signals


def file_uses_faker(content: str) -> bool:
    return bool(FAKER_RE.search(content))
