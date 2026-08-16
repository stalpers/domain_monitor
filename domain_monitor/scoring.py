"""Composing typosquat and lexical signals into an explainable assessment.

The one rule this module exists to enforce: **lexical/randomness signals never fire an
alert on their own.** They rank and explain a match that already fired for a watchlist
reason. This is not a stylistic choice -- it is the direct consequence of the project's
base-rate analysis: a ~96%-accurate lexical classifier on a balanced benchmark degrades to
roughly 20% precision against a real zone's ~1% malicious base rate. A specific question
("is this a squat of a brand I named") has a small false-positive surface; "does this
string look random" does not, at the volumes a zone monitor sees. See
:class:`Assessment.fires` for where that boundary is actually enforced in code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .lexical import LexicalFeatures, extract, randomness_score
from .ngram import NgramModel
from .typosquat import Watchlist

#: Per-method base weight. Homoglyphs and bit-flips are the least likely to occur by
#: coincidence (a skeleton collision or a single-bit match is a strong, specific signal),
#: so they weight highest; a generic bounded edit-distance match weights lowest, since it
#: is the method most prone to short-brand collisions (see typosquat.py).
METHOD_WEIGHTS: dict[str, float] = {
    "homoglyph": 1.0,
    "bitsquat": 0.9,
    "tld_variant": 0.9,
    "combosquat": 0.8,
    "keyboard": 0.7,
    "omission": 0.6, "insertion": 0.6, "transposition": 0.6,
    "repetition": 0.6, "replacement": 0.6,
    "hyphenation": 0.5,
}
DEFAULT_METHOD_WEIGHT = 0.5

#: Lexical signals contribute a small nudge to score, for ranking multiple watchlist
#: hits against each other -- never enough to matter on their own, and structurally
#: incapable of producing a hit with no watchlist signal present (see ``assess`` below).
LEXICAL_WEIGHT = 0.1


@dataclass(frozen=True, slots=True)
class Signal:
    """One contributing piece of evidence, named so an alert can quote it directly."""

    name: str
    category: str          # "watchlist" | "lexical"
    weight: float
    reason: str
    detail: str = ""
    brand: str | None = None
    distance: int | None = None


@dataclass(slots=True)
class Assessment:
    """The full picture for one label: every signal found, and the features behind them."""

    label: str
    signals: list[Signal] = field(default_factory=list)
    features: LexicalFeatures | None = None
    score: float = 0.0

    @property
    def watchlist_signals(self) -> list[Signal]:
        return [s for s in self.signals if s.category == "watchlist"]

    @property
    def lexical_signals(self) -> list[Signal]:
        return [s for s in self.signals if s.category == "lexical"]

    @property
    def fires(self) -> bool:
        """Whether this assessment justifies an alert.

        The enforcement point for the module's central rule: true only when at least one
        *watchlist* signal is present. A name can have an arbitrarily high randomness
        score and this stays ``False``.
        """
        return bool(self.watchlist_signals)


def assess(
    label: str,
    watchlist: Watchlist | None = None,
    model: NgramModel | None = None,
    *,
    tld: str | None = None,
) -> Assessment:
    """Score one label against a watchlist and the lexical/n-gram baseline.

    ``label`` is the SLD only (no TLD) -- callers strip it, since ``Watchlist.check`` and
    ``lexical.extract`` both operate on labels.
    """
    features = extract(label)
    rscore = randomness_score(features, model)

    signals: list[Signal] = []
    if watchlist is not None:
        for match in watchlist.check(label, tld=tld):
            weight = METHOD_WEIGHTS.get(match.method, DEFAULT_METHOD_WEIGHT)
            signals.append(Signal(
                name=match.method, category="watchlist", weight=weight,
                reason=f"{match.method} of brand {match.brand!r}", detail=match.detail,
                brand=match.brand, distance=match.distance,
            ))

    if rscore > 0:
        signals.append(Signal(
            name="randomness", category="lexical", weight=rscore,
            reason=f"lexical randomness score {rscore:.2f}",
            detail=(
                f"entropy={features.entropy:.2f} bits/char, "
                f"max consonant run={features.max_consonant_run}, "
                f"vowel ratio={features.vowel_ratio:.2f}"
            ),
        ))

    watchlist_total = sum(s.weight for s in signals if s.category == "watchlist")
    lexical_total = sum(s.weight for s in signals if s.category == "lexical")
    score = round(watchlist_total + LEXICAL_WEIGHT * lexical_total, 4)

    return Assessment(label=label, signals=signals, features=features, score=score)
