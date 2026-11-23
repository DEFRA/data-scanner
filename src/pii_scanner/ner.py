"""Named entity recognition (people, places) with spaCy, run locally."""
from __future__ import annotations

import re
from functools import cache
from pathlib import Path

from .detectors import Candidate
from .detectors.fakes import PLACEHOLDER_NAMES

_nlp = None
_NAME_TOKEN = re.compile(r"^[A-Z][a-z]+(?:[\-'][A-Z]?[a-z]+)*$")
_PLACEHOLDERS = frozenset(PLACEHOLDER_NAMES)
# A person name needs at least two capitalised words next to each other; lines without one skip spaCy
CAPITALISED_PAIR = re.compile(r"\b[A-Z][a-z'\-]+[ ,]+[A-Z][a-z'\-]+")
# Words that spaCy tags as people in technical text but are not names
NOT_NAME_WORDS = frozenset("""
docker compose kubernetes helm terraform azure aws amazon google microsoft github gitlab jenkins sonar sonarcloud
node react redux angular vue express hapi jest mocha chai cypress playwright selenium webpack babel eslint prettier
nunjucks govuk gov frontend backend redis postgres postgresql mongo mongodb mysql sql oracle elastic elasticsearch
kafka rabbit spring boot java python django flask ruby rails gem dotnet net core blazor razor swagger openapi
lambda function service worker server client api gateway portal admin manager defra apha rpa natural england
environment agency flood water forest marine farming payments payment scheme schemes rural
map maps layer layers data dataset model models view views page pages form forms field fields button table
release build test tests pull request issue branch commit merge main master develop feature bug fix hot
monday tuesday wednesday thursday friday saturday sunday january february march july
september october november december street road avenue drive
lorem ipsum dolor sit amet
""".split())


@cache
def given_names() -> frozenset[str]:
    path = Path(__file__).parent / "data" / "given_names.txt"
    return frozenset(path.read_text(encoding="utf-8").split()) if path.exists() else frozenset()
# Measured on ~1000 character spreadsheet rows: batch 256 peaks near 1 GB, batch 16 near 60 MB, same speed
BATCH_SIZE = 16


class NerUnavailable(RuntimeError):
    pass


def load(model: str):
    global _nlp
    if _nlp is None:
        try:
            import spacy
        except ImportError as e:
            raise NerUnavailable("spaCy is not installed: pip install -e '.[ner]'") from e
        try:
            _nlp = spacy.load(model, disable=["parser", "lemmatizer", "tagger", "attribute_ruler", "morphologizer"])
        except OSError as e:
            raise NerUnavailable(f"spaCy model {model} missing: python -m spacy download {model}") from e
    return _nlp


def entities(model: str, texts: list[str]) -> list[tuple[list[Candidate], bool]]:
    """For each text: (person name candidates, whether a place was mentioned)."""
    nlp = load(model)
    out = []
    for doc in nlp.pipe(texts, batch_size=BATCH_SIZE):
        people, has_place = [], False
        for ent in doc.ents:
            if ent.label_ in ("GPE", "LOC", "FAC"):
                has_place = True
            elif ent.label_ == "PERSON":
                c = _person(ent.text)
                if c:
                    people.append(c)
        out.append((people, has_place))
    return out


def _person(text: str) -> Candidate | None:
    tokens = text.strip().split()
    if not 2 <= len(tokens) <= 4 or len(text) > 40:
        return None
    if not all(_NAME_TOKEN.match(t) for t in tokens):
        return None
    lowered = [t.lower() for t in tokens]
    if any(t in NOT_NAME_WORDS for t in lowered):
        return None
    names = given_names()
    if names and lowered[0] not in names:
        return None
    norm = " ".join(lowered)
    c = Candidate("person_name", " ".join(tokens), norm, 3.0, 0.6)
    if norm in _PLACEHOLDERS:
        c.fake.append("placeholder name")
    return c
