"""Domain name normalisation.

Every name entering the system passes through :func:`normalise_name` before it is stored
or compared. Without a single canonical form the zone diff produces phantom add/remove
pairs -- ``Zürich.ch`` and ``xn--zrich-kva.ch`` are the same registration, and `.ch` has
a lot of umlaut domains.
"""

from __future__ import annotations

import idna


def normalise_name(name: str) -> str:
    """Canonical storage form: lowercase, no trailing dot, IDN as a punycode A-label.

    Note what this deliberately does **not** do: strip a leading ``www.``. ``www.ch`` is
    itself a registrable domain, and stripping the prefix silently turns it into ``ch``.
    """
    s = name.strip().lower().rstrip(".")
    if not s or s.isascii():
        return s
    try:
        return idna.encode(s, uts46=True).decode("ascii")
    except idna.IDNAError:
        # Encode label by label so one unencodable label does not discard the whole name.
        out = []
        for label in s.split("."):
            try:
                out.append(idna.encode(label, uts46=True).decode("ascii"))
            except idna.IDNAError:
                out.append(label)
        return ".".join(out)


def to_display(name: str) -> str:
    """Unicode form, for humans. Falls back to the input if it will not decode."""
    if "xn--" not in name:
        return name
    try:
        return idna.decode(name)
    except idna.IDNAError:
        return name


def tld_of(name: str) -> str:
    """The last label of a normalised name."""
    return name.rsplit(".", 1)[-1] if "." in name else ""
