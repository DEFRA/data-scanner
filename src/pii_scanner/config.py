from __future__ import annotations

import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    orgs: list[str] = field(default_factory=lambda: ["DEFRA"])
    include_forks: bool = False
    exclude_repos: list[str] = field(default_factory=list)
    data_dir: Path = Path("data")
    reports_dir: Path = Path("reports")
    fetch_workers: int = 8
    include_wikis: bool = True
    scan_workers: int = 4
    max_memory_mb: int = 0  # per repo memory growth in a scan worker; 0 sizes it from available RAM
    max_line_length: int = 4000
    include_documents: bool = True
    max_document_bytes: int = 20_000_000
    exclude_globs: list[str] = field(default_factory=list)
    ner_scope: str = "targeted"
    ner_model: str = "en_core_web_md"
    ner_max_lines_per_file: int = 2000
    test_patterns: list[str] = field(default_factory=list)
    docs_patterns: list[str] = field(default_factory=list)
    data_extensions: list[str] = field(default_factory=list)
    data_patterns: list[str] = field(default_factory=list)
    ner_extensions: list[str] = field(default_factory=list)
    test_repo_patterns: list[str] = field(default_factory=list)
    large_file_bytes: int = 2_000_000
    large_file_sample_lines: int = 5000
    internal_email_domains: list[str] = field(default_factory=list)
    ignore_email_domains: list[str] = field(default_factory=list)
    ignore_staff: bool = True
    authorship_patterns: list[str] = field(default_factory=list)
    authorship_rules: list[str] = field(default_factory=list)
    suppress_paths: list[dict] = field(default_factory=list)  # {name, rules, patterns}
    enrich_bands: list[str] = field(default_factory=lambda: ["High", "Medium", "Low"])

    @property
    def mirrors_dir(self) -> Path:
        return self.data_dir / "mirrors"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "scanner.db"

    def hmac_key(self) -> bytes:
        key_path = self.data_dir / "secret.key"
        if not key_path.exists():
            self.data_dir.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(secrets.token_bytes(32))
            key_path.chmod(0o600)
        return key_path.read_bytes()


def load_config(path: Path) -> Config:
    raw = tomllib.loads(path.read_text()) if path.exists() else {}
    gh, paths, fetch, scan, ner, tiers, enrich, suppress = (
        raw.get(k, {}) for k in ("github", "paths", "fetch", "scan", "ner", "tiers", "enrich", "suppress")
    )
    base = path.parent.resolve() if path.exists() else Path.cwd()
    cfg = Config()
    cfg.orgs = gh.get("orgs", cfg.orgs)
    cfg.include_forks = gh.get("include_forks", cfg.include_forks)
    cfg.exclude_repos = gh.get("exclude_repos", cfg.exclude_repos)
    cfg.data_dir = base / paths.get("data_dir", "data")
    cfg.reports_dir = base / paths.get("reports_dir", "reports")
    cfg.fetch_workers = fetch.get("workers", cfg.fetch_workers)
    cfg.include_wikis = fetch.get("include_wikis", cfg.include_wikis)
    cfg.scan_workers = scan.get("workers", cfg.scan_workers)
    cfg.max_memory_mb = scan.get("max_memory_mb", cfg.max_memory_mb)
    cfg.max_line_length = scan.get("max_line_length", cfg.max_line_length)
    cfg.include_documents = scan.get("include_documents", cfg.include_documents)
    cfg.max_document_bytes = scan.get("max_document_bytes", cfg.max_document_bytes)
    cfg.exclude_globs = scan.get("exclude_globs", cfg.exclude_globs)
    cfg.ner_scope = ner.get("scope", cfg.ner_scope)
    cfg.ner_model = ner.get("model", cfg.ner_model)
    cfg.ner_max_lines_per_file = ner.get("max_lines_per_file", cfg.ner_max_lines_per_file)
    cfg.test_patterns = tiers.get("test_patterns", cfg.test_patterns)
    cfg.docs_patterns = tiers.get("docs_patterns", cfg.docs_patterns)
    cfg.data_extensions = tiers.get("data_extensions", cfg.data_extensions)
    cfg.data_patterns = tiers.get("data_patterns", cfg.data_patterns)
    cfg.ner_extensions = tiers.get("ner_extensions", cfg.ner_extensions)
    cfg.test_repo_patterns = tiers.get("test_repo_patterns", cfg.test_repo_patterns)
    cfg.large_file_bytes = scan.get("large_file_bytes", cfg.large_file_bytes)
    cfg.large_file_sample_lines = scan.get("large_file_sample_lines", cfg.large_file_sample_lines)
    cfg.internal_email_domains = suppress.get("internal_email_domains", cfg.internal_email_domains)
    cfg.ignore_email_domains = suppress.get("ignore_email_domains", cfg.ignore_email_domains)
    cfg.ignore_staff = suppress.get("ignore_staff", cfg.ignore_staff)
    cfg.authorship_patterns = suppress.get("authorship_patterns", cfg.authorship_patterns)
    cfg.authorship_rules = suppress.get("authorship_rules", cfg.authorship_rules)
    cfg.suppress_paths = suppress.get("paths", cfg.suppress_paths)
    cfg.enrich_bands = enrich.get("bands", cfg.enrich_bands)
    return cfg
