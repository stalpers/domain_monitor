"""A character n-gram model trained on the zone itself.

The design choice this makes, and why: every cited paper trains its n-gram/entropy
baseline on a generic "benign domains" corpus (usually a top-sites list). That is a worse
fit here than the obvious alternative -- **train on the `.ch` zone the monitor already
has**. It needs no download, it is the actual population being scored (Swiss naming
conventions, German/French/Italian words, the DE/FR/IT mix), and at ~2.6M names it is far
larger than any public "benign domains" dataset. Malicious names are too rare (~1% or
less, per the design's base-rate analysis) to meaningfully bias what "normal" looks like.

Character trigrams with Laplace-smoothed frequencies, scored by average log-probability
and mapped to 0-1 via a sigmoid centred on the training corpus's own mean. That keeps the
score self-calibrating: what counts as "unusual" is relative to what `.ch` actually looks
like, not to some fixed external threshold.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

BOUNDARY = "^"      # padding character marking label start/end, so edge n-grams count too


@dataclass(slots=True)
class NgramModel:
    """A trained (or empty) character n-gram model for one TLD."""

    order: int = 3
    tld: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    total_ngrams: int = 0
    vocab_size: int = 0
    mean_log_prob: float = 0.0
    std_log_prob: float = 1.0
    sample_count: int = 0

    @property
    def trained(self) -> bool:
        return self.sample_count > 0 and self.total_ngrams > 0

    def _ngrams(self, label: str) -> list[str]:
        padded = BOUNDARY * (self.order - 1) + label + BOUNDARY * (self.order - 1)
        return [padded[i : i + self.order] for i in range(len(padded) - self.order + 1)]

    def _ngram_log_prob(self, ngram: str) -> float:
        # Laplace (add-one) smoothing: every possible n-gram, seen or not, gets nonzero
        # probability, so a label containing an n-gram absent from training does not
        # blow up to -inf.
        count = self.counts.get(ngram, 0)
        return math.log((count + 1) / (self.total_ngrams + self.vocab_size))

    def train(self, labels: list[str]) -> None:
        """Fit the model to a batch of labels. Call repeatedly to stream a large zone."""
        for label in labels:
            for ng in self._ngrams(label):
                self.counts[ng] = self.counts.get(ng, 0) + 1
        self.total_ngrams = sum(self.counts.values())
        self.vocab_size = len(self.counts)
        self.sample_count += len(labels)

    def finalise(self, calibration_labels: list[str]) -> None:
        """Compute the mean/std used to centre the sigmoid, from a labelled sample.

        Separate from ``train`` because it must run *after* all counts are in: computing
        it incrementally per-batch would bias the mean toward whatever was trained first.
        """
        if not self.trained or not calibration_labels:
            return
        scores = [self._avg_log_prob(label) for label in calibration_labels]
        n = len(scores)
        self.mean_log_prob = sum(scores) / n
        variance = sum((s - self.mean_log_prob) ** 2 for s in scores) / n
        self.std_log_prob = math.sqrt(variance) or 1.0

    def _avg_log_prob(self, label: str) -> float:
        ngrams = self._ngrams(label)
        if not ngrams:
            return self.mean_log_prob
        return sum(self._ngram_log_prob(ng) for ng in ngrams) / len(ngrams)

    def likelihood(self, label: str) -> float:
        """0-1: how consistent ``label`` is with the training corpus. 0.5 is average.

        Unicode labels will generally score low, since their characters are rare or
        absent in an ASCII-majority `.ch` training set -- this is informative (an
        unusual-for-the-zone label is worth a human's attention) but should not be read
        as "malicious": it also fires on legitimate IDN registrations.
        """
        if not self.trained:
            return 0.5
        # A small or low-diversity training set (a sparse zone, or a handful of very
        # similar names) can make std_log_prob collapse to a near-zero float without
        # tripping the `or 1.0` guard in finalise() -- close enough to zero to send the
        # z-score into the thousands and overflow math.exp. Clamping z is a strictly
        # defensive bound: the sigmoid already saturates to 0/1 well inside this range
        # for any well-conditioned model, so this only protects the degenerate case.
        std = self.std_log_prob if self.std_log_prob > 1e-9 else 1e-9
        z = (self._avg_log_prob(label) - self.mean_log_prob) / std
        z = max(-50.0, min(50.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def to_json(self) -> str:
        return json.dumps({
            "order": self.order,
            "tld": self.tld,
            "counts": self.counts,
            "total_ngrams": self.total_ngrams,
            "vocab_size": self.vocab_size,
            "mean_log_prob": self.mean_log_prob,
            "std_log_prob": self.std_log_prob,
            "sample_count": self.sample_count,
        })

    @classmethod
    def from_json(cls, payload: str) -> NgramModel:
        data = json.loads(payload)
        return cls(**data)


def build_from_labels(labels: list[str], *, order: int = 3, tld: str = "") -> NgramModel:
    """Train and calibrate a model from an in-memory label list. Used by tests and by
    ``model build`` when the whole set fits comfortably in memory for one TLD."""
    model = NgramModel(order=order, tld=tld)
    model.train(labels)
    model.finalise(labels)
    return model


# --- persistence --------------------------------------------------------------------

CHUNK = 10_000


def build_from_zone(session: Session, tld: str, *, order: int = 3) -> NgramModel:
    """Train a model from every currently in-zone domain of one TLD.

    Streams via ``yield_per`` rather than loading all labels at once -- the whole point
    of training on the real zone is that it may be millions of names.
    """
    from .models import Domain

    model = NgramModel(order=order, tld=tld)
    stmt = (
        select(Domain.name)
        .where(Domain.tld == tld, Domain.currently_in_zone.is_(True))
        .execution_options(yield_per=CHUNK)
    )

    batch: list[str] = []
    calibration: list[str] = []
    for (name,) in session.execute(stmt):
        label = name.rsplit(".", 1)[0] if "." in name else name
        batch.append(label)
        if len(calibration) < 50_000:       # a sample is enough to fit mean/std stably
            calibration.append(label)
        if len(batch) >= CHUNK:
            model.train(batch)
            batch.clear()
    if batch:
        model.train(batch)

    model.finalise(calibration)
    logger.info(
        ".%s: trained %d-gram model on %d names (%d distinct n-grams)",
        tld, order, model.sample_count, model.vocab_size,
    )
    return model


def save_model(session: Session, model: NgramModel) -> None:
    from .models import NgramModelRecord, utcnow

    record = session.get(NgramModelRecord, model.tld)
    payload = model.to_json()
    if record is None:
        session.add(NgramModelRecord(
            tld=model.tld, order=model.order, payload=payload,
            sample_count=model.sample_count, trained_at=utcnow(),
        ))
    else:
        record.order = model.order
        record.payload = payload
        record.sample_count = model.sample_count
        record.trained_at = utcnow()


def load_model(session: Session, tld: str) -> NgramModel | None:
    from .models import NgramModelRecord

    record = session.get(NgramModelRecord, tld)
    if record is None:
        return None
    return NgramModel.from_json(record.payload)
