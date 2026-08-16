"""Typosquat, combosquat and homoglyph detection against a curated brand watchlist.

This module works **discriminatively**, the opposite direction from a tool like
dnstwist: dnstwist starts from a brand and *generates* thousands of permutations to go
look up. Here we start from an observed, already-registered name (one `ADDED_TO_ZONE`
event) and ask whether it is a squat of something on the watchlist. That is the cheaper
direction when the population being checked is a stream of real events rather than a
brand's full permutation space, and it is why every detector below is built around a
prefilter (skeleton hash, bit-flip set membership, length bucket) rather than distance
maths against every brand for every candidate.

Every match names the **method** that fired -- ``homoglyph``, ``omission``, ``insertion``,
``transposition``, ``repetition``, ``replacement``, ``keyboard``, ``bitsquat``,
``combosquat``, ``hyphenation``, ``tld_variant`` -- because "a rule matched" is not an
explanation and every alert in this project must be able to say why it fired.

Precision is the design constraint (see the project plan's base-rate analysis), which is
why ``combosquat`` requires a hyphen or a recognised keyword touching the brand rather
than a bare substring match: "cooperative.ch" must not fire on a watchlisted "coop".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .confusables import has_non_ascii_confusable, skeleton

#: Keywords whose adjacency to a brand name is itself suspicious -- the vocabulary of
#: credential-harvesting and account-takeover phishing kits. Deliberately the gate for
#: combosquat detection rather than a bare substring test, and deliberately narrower than
#: "words that sound security-related": generic business vocabulary like "service",
#: "support", "portal", "help" or "online" was tried and dropped -- it collides with
#: ordinary Swiss company naming (garage-sbb-**service**.ch) at a rate that defeats the
#: point of the gate. What survives is vocabulary specific to the credential/payment
#: action a phishing page asks the visitor to take, which does not have that problem.
COMBOSQUAT_KEYWORDS = frozenset({
    "login", "signin", "secure", "account", "verify", "sso", "auth",
    "banking", "webmail", "payment", "security", "password", "authentication",
})

# Same-row keyboard adjacency only (left/right neighbours). This is a deliberate
# simplification of full staggered-key geometry, and it is the dominant source of real
# single-key-slip typos, which is what this detector targets.
_QWERTY_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
_QWERTZ_ROWS = ("qwertzuiop", "asdfghjkl", "yxcvbnm")   # Swiss/German layout: y/z swapped
_AZERTY_ROWS = ("azertyuiop", "qsdfghjklm", "wxcvbn")   # French layout


def _adjacency_map(rows: tuple[str, ...]) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = {}
    for row in rows:
        for i, ch in enumerate(row):
            neighbours = set()
            if i > 0:
                neighbours.add(row[i - 1])
            if i < len(row) - 1:
                neighbours.add(row[i + 1])
            adjacency[ch] = neighbours
    return adjacency


KEYBOARD_LAYOUTS: dict[str, dict[str, set[str]]] = {
    "qwertz": _adjacency_map(_QWERTZ_ROWS),   # first: Switzerland's own keyboard layout
    "qwerty": _adjacency_map(_QWERTY_ROWS),
    "azerty": _adjacency_map(_AZERTY_ROWS),
}

DEFAULT_METHODS = frozenset({
    "homoglyph", "typo", "keyboard", "bitsquat", "combosquat", "hyphenation",
})


@dataclass(frozen=True, slots=True)
class SquatMatch:
    """One detector firing against one brand. Everything an alert needs to explain itself."""

    brand: str
    method: str
    observed: str
    distance: int | None
    detail: str
    is_homograph: bool = False


def bounded_edit_distance(a: str, b: str, max_distance: int) -> int | None:
    """Restricted Damerau-Levenshtein (insert/delete/substitute/adjacent-transpose),
    capped at ``max_distance``. Returns ``None`` if the true distance exceeds it --
    callers use that to skip a candidate without caring how far off it actually is.

    Early-exits per row once every cell in it is already over the bound, since no
    completion of that row can recover to within it.
    """
    la, lb = len(a), len(b)
    if abs(la - lb) > max_distance:
        return None
    if a == b:
        return 0

    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j

    for i in range(1, la + 1):
        row_min = d[i][0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            best = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                best = min(best, d[i - 2][j - 2] + 1)
            d[i][j] = best
            row_min = min(row_min, best)
        if row_min > max_distance:
            return None

    result = d[la][lb]
    return result if result <= max_distance else None


def classify_edit(observed: str, brand: str) -> str:
    """Best-effort human label for a single-edit difference. Heuristic, not exhaustive --
    good enough to make an alert readable, not a formal edit-script derivation."""
    if len(observed) == len(brand) + 1:
        for i in range(len(observed)):
            if observed[:i] + observed[i + 1 :] == brand:
                if i > 0 and observed[i] == observed[i - 1]:
                    return "repetition"
                return "insertion"
        return "insertion"
    if len(observed) == len(brand) - 1:
        return "omission"
    if len(observed) == len(brand):
        for i in range(len(observed) - 1):
            swapped = observed[:i] + observed[i + 1] + observed[i] + observed[i + 2 :]
            if swapped == brand:
                return "transposition"
        return "replacement"
    return "typo"


def bitsquat_variants(word: str) -> set[str]:
    """Every single-bit-flip of ``word`` that is still a legal domain character.

    Bitsquatting exploits memory errors in resolvers/routers, not human perception, so
    unlike the other detectors here it has nothing to do with how a name *looks* --
    the variant can be visually unrelated to the brand. dnstwist implements the same idea.
    """
    variants: set[str] = set()
    for i, ch in enumerate(word):
        code = ord(ch)
        if code >= 128:
            continue
        for bit in range(8):
            flipped = code ^ (1 << bit)
            if flipped >= 128:
                continue
            fchar = chr(flipped).lower()
            if fchar.isalnum() or fchar == "-":
                variants.add(word[:i] + fchar + word[i + 1 :])
    variants.discard(word)
    return variants


def _keyboard_adjacent(observed: str, brand: str, layouts: tuple[str, ...]) -> str | None:
    """Whether a single-character substitution sits on a keyboard-adjacent key.

    Only ever considered for equal-length strings with exactly one differing position --
    a keyboard slip does not also change the length.
    """
    if len(observed) != len(brand):
        return None
    diffs = [(i, o, b) for i, (o, b) in enumerate(zip(observed, brand)) if o != b]
    if len(diffs) != 1:
        return None
    _, o_char, b_char = diffs[0]
    for layout in layouts:
        if b_char in KEYBOARD_LAYOUTS.get(layout, {}).get(o_char, set()):
            return layout
    return None


def _combosquat_detail(label: str, brand: str, *, require_keyword: bool) -> str | None:
    """A brand touching a hyphen or a suspicious keyword, not a bare substring.

    The bare-substring version of this check is a precision disaster: a watchlist
    entry for "coop" would fire on "cooperative.ch", "recoop.ch", every co-op society
    in the country. Requiring an explicit separator or a keyword from a known-suspicious
    vocabulary keeps the false-positive surface small for an ordinary-length brand.

    ``require_keyword`` tightens this further for short brands (see
    ``Watchlist.min_length_for_distance``): a bare hyphen next to a 3-4 letter brand is
    still too weak a signal on its own -- "chicken-coop.ch" and
    "garage-sbb-service.ch" both false-trigger on hyphen adjacency alone in testing. For
    those brands only a keyword adjacency counts; the hyphen may still be present between
    the brand and the keyword ("coop-login.ch"), it just can't be the *only* evidence.
    """
    if brand not in label or label == brand:
        return None
    idx = label.find(brand)
    before, after = label[:idx], label[idx + len(brand) :]
    before_hyphen, after_hyphen = before.endswith("-"), after.startswith("-")
    before_core = before[:-1] if before_hyphen else before
    after_core = after[1:] if after_hyphen else after

    for kw in COMBOSQUAT_KEYWORDS:
        if after_core.startswith(kw):
            sep = "hyphen-separated, " if after_hyphen else ""
            return f"{sep}keyword {kw!r} immediately follows the brand name"
        if before_core.endswith(kw):
            sep = "hyphen-separated, " if before_hyphen else ""
            return f"{sep}keyword {kw!r} immediately precedes the brand name"

    if (before_hyphen or after_hyphen) and not require_keyword:
        return "hyphen-separated from the brand name"
    return None


@dataclass(slots=True)
class Watchlist:
    """A curated brand list plus the indexes that make checking it against a stream of
    candidate names cheap: an O(1) skeleton lookup for homoglyphs, an O(1) set lookup for
    bit-flips, and a length-bucket filter before anything pays for edit-distance."""

    brands: list[str]
    max_distance: int = 1
    methods: frozenset[str] = field(default_factory=lambda: DEFAULT_METHODS)
    keyboard_layouts: tuple[str, ...] = ("qwertz", "qwerty", "azerty")
    home_tlds: dict[str, str] = field(default_factory=dict)

    #: Brands shorter than this skip ``typo``/``keyboard`` and the bare-hyphen half of
    #: ``combosquat`` entirely. Found empirically, not theoretically: "ubs" is
    #: edit-distance 1 from "usb", "ups" and "pubs", and "chicken-coop" is hyphen-adjacent
    #: to "coop". Short brands (3-4 letters, common for Swiss institutions -- UBS, SBB,
    #: PTT, coop) still get homoglyph, bitsquat, and keyword-gated combosquat, which stay
    #: precise regardless of length.
    min_length_for_distance: int = 5

    _skeleton_index: dict[str, str] = field(init=False, repr=False)
    _bitflip_index: dict[str, str] = field(init=False, repr=False)
    _by_length: dict[int, list[str]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.brands = [b.strip().lower() for b in self.brands if b.strip()]
        self._skeleton_index = {}
        self._bitflip_index = {}
        self._by_length = {}
        for brand in self.brands:
            self._skeleton_index.setdefault(skeleton(brand), brand)
            for variant in bitsquat_variants(brand):
                self._bitflip_index.setdefault(variant, brand)
            self._by_length.setdefault(len(brand), []).append(brand)

    def _candidates_near(self, length: int) -> list[str]:
        """Brands within ``max_distance`` of ``length`` -- a distance-N edit cannot
        change length by more than N, so this is a safe, cheap prefilter."""
        out: list[str] = []
        for delta in range(-self.max_distance, self.max_distance + 1):
            out.extend(self._by_length.get(length + delta, []))
        return out

    def check(self, label: str, *, tld: str | None = None) -> list[SquatMatch]:
        """Every technique that claims ``label`` is a squat of something watchlisted."""
        matches: list[SquatMatch] = []
        label = label.lower()

        if "homoglyph" in self.methods:
            skel = skeleton(label)
            brand = self._skeleton_index.get(skel)
            if brand and label != brand:
                homograph = has_non_ascii_confusable(label)
                matches.append(SquatMatch(
                    brand=brand, method="homoglyph", observed=label, distance=0,
                    detail=f"folds to {skel!r}, matching brand {brand!r}"
                    + (" via a non-ASCII homoglyph" if homograph else ""),
                    is_homograph=homograph,
                ))

        if "bitsquat" in self.methods:
            brand = self._bitflip_index.get(label)
            if brand and brand != label:
                matches.append(SquatMatch(
                    brand=brand, method="bitsquat", observed=label, distance=1,
                    detail=f"single-bit-flip variant of brand {brand!r}",
                ))

        if "typo" in self.methods:
            for brand in self._candidates_near(len(label)):
                if brand == label or len(brand) < self.min_length_for_distance:
                    continue
                dist = bounded_edit_distance(label, brand, self.max_distance)
                if dist is None:
                    continue
                kind = classify_edit(label, brand)
                matches.append(SquatMatch(
                    brand=brand, method=kind, observed=label, distance=dist,
                    detail=f"edit distance {dist} from brand {brand!r} ({kind})",
                ))

        if "keyboard" in self.methods:
            for brand in self._by_length.get(len(label), []):
                if brand == label or len(brand) < self.min_length_for_distance:
                    continue
                layout = _keyboard_adjacent(label, brand, self.keyboard_layouts)
                if layout:
                    matches.append(SquatMatch(
                        brand=brand, method="keyboard", observed=label, distance=1,
                        detail=f"single keyboard-adjacent substitution from {brand!r} "
                               f"on {layout}",
                    ))

        if "combosquat" in self.methods:
            for brand in self.brands:
                require_keyword = len(brand) < self.min_length_for_distance
                detail = _combosquat_detail(label, brand, require_keyword=require_keyword)
                if detail:
                    matches.append(SquatMatch(
                        brand=brand, method="combosquat", observed=label, distance=None,
                        detail=f"contains brand {brand!r}, {detail}",
                    ))

        if "hyphenation" in self.methods:
            dehyphenated = label.replace("-", "")
            if dehyphenated != label and dehyphenated in self.brands:
                matches.append(SquatMatch(
                    brand=dehyphenated, method="hyphenation", observed=label, distance=None,
                    detail=f"brand {dehyphenated!r} with hyphen(s) inserted",
                ))

        if "tld_variant" in self.methods and tld and label in self.brands:
            home = self.home_tlds.get(label)
            if home and home != tld:
                matches.append(SquatMatch(
                    brand=label, method="tld_variant", observed=label, distance=None,
                    detail=f"exact brand name registered under .{tld}, expected .{home}",
                ))

        return matches
