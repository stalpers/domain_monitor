"""Homoglyph folding: map a name to a canonical "skeleton" so squatting becomes exact match.

The idea (and the term) come from Unicode TR39's confusables skeleton algorithm: fold every
character that *looks like* another to one canonical form, then two names that render
identically to a human become byte-identical to a computer. ``examp1e`` and ``example``
both skeletonise to ``example``; so does the Cyrillic homograph ``ехаmple`` (е,х,а are
Cyrillic). Once names are skeletons, detecting a homoglyph squat against a brand list is a
single dict lookup, not a distance computation against every brand.

Three tables, applied longest-match-first:

* ``_UNICODE_CONFUSABLES`` -- single non-ASCII characters that render like an ASCII letter:
  Cyrillic, Greek, fullwidth Latin, and common diacritics. This is what an IDN homograph
  attack actually uses, since `.ch` permits IDN labels.
* ``_ASCII_CONFUSABLES`` -- single ASCII characters substituted for a visually similar one
  (``0``->``o``, ``1``->``l``, ``5``->``s``, ``vv``->``w`` handled below).
* ``_SEQUENCE_CONFUSABLES`` -- multi-character sequences that read as one letter
  (``rn``->``m``, ``vv``->``w``, ``cl``->``d``, ``ii``->``u``). These are the classic
  brand-impersonation substitutions (``rnicrosoft``, ``paypaI``) and must be matched before
  the single-character tables or ``rn`` would fold to ``r`` + ``n`` instead of ``m``.

This module is pure and has no I/O.
"""

from __future__ import annotations

from .names import to_display

# Deliberately a short list. Each entry is checked against the false-positive corpus
# (tests/test_typosquat.py) before it earns a place here -- an aggressive sequence table
# raises recall on generative fuzzing tools but *lowers precision* here, exactly the
# trade-off the base-rate analysis in the design says to avoid. Longest-match-first so
# multi-character sequences are tried before falling through to single characters.
_SEQUENCE_CONFUSABLES: list[tuple[str, str]] = [
    ("rn", "m"),   # the canonical brand-impersonation substitution: rnicrosoft, arnazon
    ("vv", "w"),   # paypaI -> paypal-style visual doubling: vvow -> wow
    ("cl", "d"),   # in most sans-serif fonts "cl" and "d" are near-indistinguishable
]

# Digits and punctuation substituted for a visually similar ASCII letter -- the classic
# "leetspeak" squat: paypa1, examp1e, g00gle, faceb00k.
_ASCII_CONFUSABLES: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "$": "s",
    "@": "a",
    "!": "i",
    "|": "l",
}

# Non-ASCII characters that render like an ASCII letter. Not exhaustive against the full
# Unicode confusables table (which is >6000 entries and not fetchable in this environment),
# but covers the scripts actually used in homograph attacks: Cyrillic and Greek letters that
# are near-perfect glyph matches for Latin ones, fullwidth Latin (common in some IDN
# spoofing), and the accented Latin letters IDN registrations commonly carry.
_UNICODE_CONFUSABLES: dict[str, str] = {
    # Cyrillic lookalikes (lowercase) -- the highest-value set, since these are visually
    # near-indistinguishable from Latin in most fonts.
    "а": "a", "в": "b", "с": "c", "е": "e", "н": "h", "к": "k",
    "м": "m", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y",
    "х": "x", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ԛ": "q",
    "ѡ": "w", "ν": "v", "ⅰ": "i",
    # Cyrillic uppercase (a domain is lowercased before skeletonising, but kept here for
    # direct calls to skeleton() on non-normalised input).
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h",
    "О": "o", "Р": "p", "С": "c", "Т": "t", "Х": "x",
    # Greek lookalikes.
    "α": "a", "β": "b", "ε": "e", "η": "h", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t",
    "Υ": "y", "Χ": "x",
    # Fullwidth Latin (U+FF00 block) -- occasionally used in IDN spoofing.
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e", "ｆ": "f",
    "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j", "ｋ": "k", "ｌ": "l",
    "ｍ": "m", "ｎ": "n", "ｏ": "o", "ｐ": "p", "ｑ": "q", "ｒ": "r",
    "ｓ": "s", "ｔ": "t", "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x",
    "ｙ": "y", "ｚ": "z",
    # Common accented Latin -- these are legitimate in Swiss/French/German names, so
    # folding them is what lets "café" and "cafe" collide as a squat pair, which is
    # exactly the intended behaviour for a homoglyph check.
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a", "ā": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e", "ē": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i", "ī": "i",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "ø": "o", "ō": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u", "ū": "u",
    "ç": "c", "ñ": "n", "ý": "y", "ÿ": "y",
    "ß": "ss",
}

_SORTED_SEQUENCES = sorted(_SEQUENCE_CONFUSABLES, key=lambda p: -len(p[0]))


def skeleton(name: str) -> str:
    """Fold ``name`` to its canonical homoglyph-invariant form.

    Decodes punycode to Unicode first: the pipeline stores names as punycode A-labels
    (``xn--...``), and skeletonising that form directly would never see the Cyrillic or
    accented characters it exists to catch. Operates on the label (no TLD), since folding
    ``.ch`` itself would be meaningless and homoglyph squats target the label.
    """
    label = name.split(".", 1)[0] if "." in name else name
    text = to_display(label).lower()

    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        matched = False
        for seq, replacement in _SORTED_SEQUENCES:
            if text.startswith(seq, i):
                out.append(replacement)
                i += len(seq)
                matched = True
                break
        if matched:
            continue

        ch = text[i]
        if ch in _UNICODE_CONFUSABLES:
            out.append(_UNICODE_CONFUSABLES[ch])
        elif ch in _ASCII_CONFUSABLES:
            out.append(_ASCII_CONFUSABLES[ch])
        else:
            out.append(ch)
        i += 1

    return "".join(out)


def has_non_ascii_confusable(name: str) -> bool:
    """Whether folding this name actually involved a non-ASCII homoglyph.

    Distinguishes "examp1e" (ASCII leetspeak -- still worth flagging, but a different
    method) from "ехаmple" (Cyrillic homograph -- the more dangerous case, since it is
    often visually perfect and the raw bytes differ completely from the brand name).
    """
    label = name.split(".", 1)[0] if "." in name else name
    return not to_display(label).isascii()
