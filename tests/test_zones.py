"""Zone file acquisition: the one-name-per-line format, and real BIND presentation format.

This is a regression suite for a production incident: ``_iter_file_names`` used to treat
every line of a ``*_ZONE_FILE`` as a bare domain name with no parsing at all. Fed a real
zone dump (which is what someone pointing this at "the zone file" naturally has), every
field of every RR line -- TTLs, record types, RRSIG/NSEC rdata -- was staged verbatim as a
"name". SQLite has no VARCHAR length limit and stored the garbage silently; PostgreSQL
enforced ``VARCHAR(255)`` and raised ``StringDataRightTruncation`` after 9.25M rows.
"""

from __future__ import annotations

import pytest

from domain_monitor.config import ZoneSource
from domain_monitor.zones import (
    TransferResult,
    ZoneError,
    _iter_file_names,
    _looks_like_domain_name,
    stage_zone,
)

# A realistic slice of what `dig axfr ch.` / a Switch zone dump actually looks like:
# tab-separated owner/TTL/class/type/rdata, DNSSEC records interleaved with NS, a
# continuation line (leading whitespace reuses the previous owner), and the zone apex's
# own NS RRset (which is the zone's nameservers, not a delegation).
REALISTIC_ZONE_FILE = """\
; a full-line comment, as BIND emits at the top of a transfer
ch.\t\t3600\tIN\tSOA\ta.nic.ch. hostmaster.nic.ch. 1 2 3 4 5
ch.\t\t3600\tIN\tNS\ta.nic.ch.
\t\t3600\tIN\tNS\tb.nic.ch.
nfc24.ch.\t\t3600\tin\tns\tns1.torn.sui-inter.net.
nfc24.ch.\t\t3600\tin\tns\tns2.torn.sui-inter.net.
nfc3000.ch.\t\t900\tin\trrsig\tnsec 13 2 900 20260908231341 20260809223155 48631 ch. ivkhua59bv8nutaqht4bpihjwhvyysvwwnksfozuek0mmdzv+j2/kfpm tytwubg2t0exjuniaxprf1osnuipja==
nfc3000.ch.\t\t900\tin\tnsec\tnfcard.ch. ns ds rrsig nsec
nfc3000.ch.\t\t3600\tin\trrsig\tds 13 2 3600 20260908154056 20260809150155 48631 ch. qiqvuwyrbzx3uqrxuyricwqcnblrcujnaklktgimj0xufrtab9aeszue yr0llaynvmlf9tsz9qsrqcsdcozwuw==
nfc3000.ch.\t\t3600\tin\tds\t50921 13 2 0357ce6a4e60d87e923e360cb6518fee915c555b8114f308c968bc58 43411e25
nfc3000.ch.\t\t3600\tin\tns\tns41.infomaniak.com.
\t\t3600\tin\tns\tns42.infomaniak.com.
example.ch.\t\t3600\tin\ta\t192.0.2.1
"""


class TestPresentationFormatParsing:
    def test_only_ns_owners_are_yielded(self, tmp_path):
        path = tmp_path / "ch.zone"
        path.write_text(REALISTIC_ZONE_FILE, encoding="utf-8")
        names = set(_iter_file_names(path, "ch"))
        assert {n.rstrip(".") for n in names} == {"nfc24.ch", "nfc3000.ch"}

    def test_zone_apex_is_not_a_delegation(self, tmp_path):
        path = tmp_path / "ch.zone"
        path.write_text(REALISTIC_ZONE_FILE, encoding="utf-8")
        names = {n.rstrip(".") for n in _iter_file_names(path, "ch")}
        assert "ch" not in names

    def test_dnssec_and_a_records_never_appear_as_names(self, tmp_path):
        """The exact bug: RRSIG/NSEC/DS/A rdata must never be yielded as a 'name'."""
        path = tmp_path / "ch.zone"
        path.write_text(REALISTIC_ZONE_FILE, encoding="utf-8")
        for name in _iter_file_names(path, "ch"):
            assert "\t" not in name
            assert " " not in name
            assert len(name) < 100

    def test_continuation_line_reuses_the_previous_owner(self, tmp_path):
        path = tmp_path / "ch.zone"
        path.write_text(REALISTIC_ZONE_FILE, encoding="utf-8")
        names = [n.rstrip(".") for n in _iter_file_names(path, "ch")]
        # nfc3000.ch has two NS lines, the second via continuation; both must resolve to
        # the same owner, not an empty or garbage one.
        assert names.count("nfc3000.ch") == 2

    def test_a_record_does_not_leak_as_a_name(self, tmp_path):
        path = tmp_path / "ch.zone"
        path.write_text(REALISTIC_ZONE_FILE, encoding="utf-8")
        names = {n.rstrip(".") for n in _iter_file_names(path, "ch")}
        assert "example.ch" not in names


class TestBareNameFormatStillWorks:
    """The simple format documented in .env.example, and used by existing fixtures."""

    def test_one_name_per_line(self, tmp_path):
        path = tmp_path / "names.txt"
        path.write_text("a.ch\nb.ch\nc.ch\n", encoding="utf-8")
        assert list(_iter_file_names(path, "ch")) == ["a.ch", "b.ch", "c.ch"]

    def test_comments_and_blank_lines_are_skipped(self, tmp_path):
        path = tmp_path / "names.txt"
        path.write_text("# header\na.ch\n\n; another comment\nb.ch\n", encoding="utf-8")
        assert list(_iter_file_names(path, "ch")) == ["a.ch", "b.ch"]

    def test_trailing_dot_is_preserved_for_normalise_name_to_strip(self, tmp_path):
        path = tmp_path / "names.txt"
        path.write_text("a.ch.\n", encoding="utf-8")
        assert list(_iter_file_names(path, "ch")) == ["a.ch."]


class TestMissingFile:
    def test_missing_file_raises_zone_error(self, tmp_path):
        with pytest.raises(ZoneError):
            list(_iter_file_names(tmp_path / "does-not-exist.zone", "ch"))


class TestLooksLikeDomainName:
    def test_a_plausible_name_passes(self):
        assert _looks_like_domain_name("example.ch") is True

    def test_the_original_incident_payload_is_rejected(self):
        """This literal string was staged into PostgreSQL before the fix."""
        garbage = "nfc24.ch.\t\t3600\tin\tns\tns1.torn.sui-inter.net"
        assert _looks_like_domain_name(garbage) is False

    def test_empty_string_is_rejected(self):
        assert _looks_like_domain_name("") is False

    def test_oversized_name_is_rejected(self):
        assert _looks_like_domain_name("a" * 300 + ".ch") is False


class TestStageZoneWithARealZoneFile:
    """End to end: a realistic zone dump staged through stage_zone() must produce only
    the delegated names, and must not crash regardless of database column limits."""

    def test_only_delegated_names_are_staged(self, session, tmp_path):
        path = tmp_path / "ch.zone"
        path.write_text(REALISTIC_ZONE_FILE, encoding="utf-8")
        source = ZoneSource(tld="ch", file_path=path)

        result = stage_zone(session, run_id=1, source=source)

        assert isinstance(result, TransferResult)
        assert result.complete is True
        assert result.name_count == 2  # nfc24.ch, nfc3000.ch -- deduped, apex excluded

    def test_malformed_entries_are_skipped_not_staged(self, session, tmp_path):
        """Simulates what the pre-fix parser would have produced, arriving via the
        `names=` override used by tests -- proving the defensive check catches it even if
        a future parser regresses."""
        source = ZoneSource(tld="ch")
        bad = "nfc24.ch.\t\t3600\tin\tns\tns1.torn.sui-inter.net"
        result = stage_zone(session, run_id=1, source=source, names=["good.ch", bad])
        assert result.name_count == 1


class TestDuplicateNamesAcrossBatches:
    """Real zone data legitimately repeats an owner name -- most commonly a domain with
    two NS records, which yields the same name twice. Production hit this exact case: a
    name landing on both sides of a 10,000-row batch flush isn't caught by the per-batch
    in-memory dedup (which is cleared on every flush, deliberately, to avoid holding a
    multi-million-name set in memory), so the second copy collided with the unique
    constraint on (run_id, name) and crashed the whole transfer with a UniqueViolation.
    The fix upserts each batch, silently not re-inserting a conflicting row, on either
    backend."""

    def test_a_name_repeated_across_a_batch_boundary_does_not_crash(
        self, session, monkeypatch
    ):
        import domain_monitor.zones as zones_module

        monkeypatch.setattr(zones_module, "BATCH_SIZE", 2)
        source = ZoneSource(tld="ch")
        # "dup.ch" is the last name before a flush, then the first name after it --
        # exactly the boundary-straddling case that crashed in production.
        names = ["a.ch", "dup.ch", "dup.ch", "b.ch"]

        result = stage_zone(session, run_id=1, source=source, names=names)

        assert result.complete is True
        assert result.name_count == 3  # a.ch, dup.ch, b.ch -- deduplicated
