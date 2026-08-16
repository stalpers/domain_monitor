"""Lexical feature extraction.

The canonical feature set for this problem, per the 2024 Annals of Telecommunications
survey and the ScienceDirect n-gram paper this project's design cites: length, entropy,
digit/vowel/consonant ratios, and n-gram statistics against a reference corpus.

These features never fire an alert on their own -- see the design note in scoring.py.
A ~96%-accurate classifier on a balanced benchmark degrades to roughly 20% precision
against a real zone's ~1% malicious base rate (worked through in the project plan), so
lexical signals here are *enrichment*: they explain and rank a watchlist hit, or feed a
future classifier via ``--export-features``, but do not independently alert.

Pure functions, no I/O, so they are trivially unit-testable and safe to run over an
entire zone during a backfill.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .ngram import NgramModel

VOWELS = frozenset("aeiou")
CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")
DIGITS = frozenset("0123456789")


@dataclass(frozen=True, slots=True)
class LexicalFeatures:
    """One label's lexical fingerprint. All fields are cheap and deterministic."""

    label: str
    length: int
    entropy: float                 # Shannon entropy in bits/char
    digit_ratio: float
    vowel_ratio: float
    consonant_ratio: float
    hyphen_count: int
    max_consonant_run: int
    unique_char_ratio: float       # distinct chars / length -- low for repetition, e.g. "aaaa1111"
    is_idn: bool

    def as_dict(self) -> dict[str, float | int | bool | str]:
        """Flat mapping for CSV export (``--export-features``) and for a future model."""
        return {
            "label": self.label,
            "length": self.length,
            "entropy": round(self.entropy, 4),
            "digit_ratio": round(self.digit_ratio, 4),
            "vowel_ratio": round(self.vowel_ratio, 4),
            "consonant_ratio": round(self.consonant_ratio, 4),
            "hyphen_count": self.hyphen_count,
            "max_consonant_run": self.max_consonant_run,
            "unique_char_ratio": round(self.unique_char_ratio, 4),
            "is_idn": self.is_idn,
        }


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character. 0.0 for a repeated single character, higher for a
    string that looks close to uniformly random -- the classic DGA tell."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def max_run(text: str, charset: frozenset[str]) -> int:
    """Longest run of consecutive characters drawn from ``charset``."""
    best = current = 0
    for ch in text:
        if ch in charset:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def extract(label: str) -> LexicalFeatures:
    """Extract lexical features from a single DNS label (no TLD, already lowercased)."""
    text = label.lower()
    length = len(text)
    is_idn = text.startswith("xn--") or not text.isascii()

    if length == 0:
        return LexicalFeatures(text, 0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0.0, is_idn)

    digits = sum(1 for c in text if c in DIGITS)
    vowels = sum(1 for c in text if c in VOWELS)
    consonants = sum(1 for c in text if c in CONSONANTS)

    return LexicalFeatures(
        label=text,
        length=length,
        entropy=shannon_entropy(text),
        digit_ratio=digits / length,
        vowel_ratio=vowels / length,
        consonant_ratio=consonants / length,
        hyphen_count=text.count("-"),
        max_consonant_run=max_run(text, CONSONANTS),
        unique_char_ratio=len(set(text)) / length,
        is_idn=is_idn,
    )


def randomness_score(features: LexicalFeatures, model: NgramModel | None = None) -> float:
    """Compose lexical features into a single 0-1 "how DGA-like is this" score.

    Weighted sum of interpretable components, not a learned model, so every contributing
    term can be named in an alert. Roughly: high entropy, long consonant runs and low
    n-gram likelihood (relative to the reference corpus) push the score up; being a
    plausible IDN label does not by itself.

    Deliberately never consulted to decide whether to alert -- see the module docstring.
    """
    if features.length == 0:
        return 0.0

    # Entropy for random alphanumeric text tops out around 4.7-5.2 bits/char; normalise
    # against that ceiling rather than log2(26) so typical English-ish words (~3.0-3.5)
    # don't already read as "half random".
    entropy_component = min(1.0, features.entropy / 4.8)

    # A DGA string is usually short-to-medium and low on vowels; a long consonant run
    # (>=4) is the strongest single tell of a pronounceability failure.
    run_component = min(1.0, features.max_consonant_run / 5.0)

    vowel_deficit = max(0.0, 0.35 - features.vowel_ratio) / 0.35

    ngram_component = 0.0
    if model is not None and model.trained:
        # Low corpus likelihood (relative to what the .ch zone actually looks like) is
        # the single most discriminative signal available, and the one every cited paper
        # leans on hardest.
        ngram_component = 1.0 - model.likelihood(features.label)

    weights = {
        "entropy": 0.30, "run": 0.20, "vowel_deficit": 0.15, "ngram": 0.35,
    }
    if model is None or not model.trained:
        # Redistribute the n-gram weight rather than silently score lower when no model
        # is available (e.g. a rule evaluated before `model build` has ever run).
        total = weights["entropy"] + weights["run"] + weights["vowel_deficit"]
        weights = {k: v / total for k, v in weights.items() if k != "ngram"}
        ngram_component = 0.0
        weights["ngram"] = 0.0

    score = (
        weights["entropy"] * entropy_component
        + weights["run"] * run_component
        + weights["vowel_deficit"] * vowel_deficit
        + weights.get("ngram", 0.0) * ngram_component
    )
    return max(0.0, min(1.0, score))
