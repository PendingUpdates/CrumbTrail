import contextlib
import copy
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from crumbtrail.cli import LAB_CLIENT, main
from crumbtrail.events import analyze
from crumbtrail.native import data_path, run_local
from crumbtrail.report import write_report
from crumbtrail.storage import Case, CaseError, LOGS, case_lock, digest, encode, records, save


class CrumbTrailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.case = Case.create(self.base / "case", "2026-10-30T20:00:00Z", "2026-10-30T22:00:00Z", "CT-TEST")
        self.case.bind(LAB_CLIENT, "LAB-WIN01")
        # Explicitly authored synthetic providers keep positive rule coverage.
        # The untouched providerless demo is covered separately in test_providers.
        self.raw = data_path("windows-providers.jsonl").read_bytes()
        self.rows = records(self.raw)

    def preserve(self, rows=None, client=LAB_CLIENT, simulation=True):
        raw = self.raw if rows is None else b"\n".join(encode(row) for row in rows) + b"\n"
        return self.case.preserve(raw, client, "test-export", simulation, {"filename": "windows-providers.jsonl"})

    def test_packaged_artifact_requires_explicit_export_directory(self):
        # Static contract only: a real VQL precondition run is a separate gate.
        artifact = data_path("Custom.CrumbTrail.WindowsTriage.yaml").read_text()
        self.assertIn("default: ''", artifact)
        self.assertIn("AND LogDirectory =~ '[^[:space:]]'", artifact)
        self.assertNotIn("%SystemRoot%", artifact)
        self.assertNotIn("System32", artifact)

    def test_original_bytes_and_manifest_hash_are_preserved(self):
        raw = self.raw.replace(b"\n", b"\r\n")
        entry = self.case.preserve(raw, LAB_CLIENT, "test-export", True)
        self.assertEqual((self.case.root / entry["path"]).read_bytes(), raw)
        self.assertEqual(entry["sha256"], digest(raw))
        self.assertEqual(self.case.verify(), 1)

    def test_tampered_raw_evidence_blocks_analysis(self):
        entry = self.preserve()
        (self.case.root / entry["path"]).write_bytes(b"tampered")
        with self.assertRaisesRegex(CaseError, "verification failed"):
            analyze(self.case)

    def test_provenance_cannot_silently_change(self):
        self.preserve()
        with self.assertRaisesRegex(CaseError, "different source provenance"):
            self.case.preserve(self.raw, LAB_CLIENT, "test-export", False)
        manifest = self.case.manifest()
        manifest["artifacts"][0]["provenance"]["simulation"] = False
        save(self.case.root / "manifest.json", manifest)
        with self.assertRaisesRegex(CaseError, "provenance checksum"):
            self.case.verify()

    def test_wrong_hostname_rejected_before_raw_write(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["System"]["Computer"] = "OTHER-HOST"
        with self.assertRaisesRegex(CaseError, "hostname"):
            self.preserve(rows)
        self.assertEqual(self.case.manifest()["artifacts"], [])

    def test_binding_immutable_and_hostname_unique(self):
        with self.assertRaisesRegex(CaseError, "immutable"):
            self.case.bind(LAB_CLIENT, "other-host")
        with self.assertRaisesRegex(CaseError, "different client"):
            self.case.bind("C.1111111111111111", "lab-win01")

    def test_fixture_dedup_retains_both_raw_references(self):
        self.preserve()
        result = analyze(self.case)
        self.assertEqual(result["summary"], dict(events=21, findings=4, gaps=0, artifacts=1,
                         raw_event_rows=22, excluded_outside_window=0, duplicate_rows=1,
                         unclassified_events=0))
        self.assertEqual(sum(len(e["references"]) for e in result["events"]), 22)
        self.assertEqual(len([e for e in result["events"] if len(e["references"]) == 2]), 1)

    def test_utc_normalization_and_chronological_sort(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["TimeCreated"] = "2026-10-30T16:27:00-04:00"
        rows = list(reversed(rows))
        self.preserve(rows)
        events = analyze(self.case)["events"]
        self.assertEqual(events[0]["timestamp_utc"], "2026-10-30T20:27:00Z")
        self.assertTrue(all(e["timestamp_utc"].endswith("Z") for e in events))

    def test_naive_timestamp_rejected(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["TimeCreated"] = "2026-10-30T20:27:00"
        with self.assertRaisesRegex(CaseError, "timezone"):
            self.preserve(rows)

    def test_native_fractional_time_takes_precedence_over_formatted_seconds(self):
        rows = [copy.deepcopy(self.rows[0])]
        rows[0]["TimeCreated"] = "2026-10-30T20:27:00Z"
        # Native VQL uses Unix seconds for SystemTime; its top-level display can lose fractions.
        from datetime import datetime
        precise = datetime.fromisoformat("2026-10-30T20:27:00.894341+00:00").timestamp()
        rows[0]["System"]["TimeCreated"] = {"SystemTime": precise}
        self.preserve(rows)
        event = analyze(self.case)["events"][0]
        self.assertEqual(event["timestamp_utc"], "2026-10-30T20:27:00.894341Z")
        self.assertEqual(event["timestamp_original"], precise)
        self.assertEqual(event["timestamp_source"], "System.TimeCreated.SystemTime")
        self.assertEqual(event["references"][0]["timestamp_original"], precise)

    def test_native_iso_time_keeps_fraction_and_invalid_native_time_cannot_fall_back(self):
        rows = [copy.deepcopy(self.rows[0])]
        rows[0]["System"]["TimeCreated"] = {"SystemTime": "2026-10-30T20:27:00.1234567Z"}
        self.preserve(rows)
        event = analyze(self.case)["events"][0]
        self.assertEqual(event["timestamp_utc"], "2026-10-30T20:27:00.1234567Z")
        self.assertEqual(event["timestamp_original"], "2026-10-30T20:27:00.1234567Z")
        rows[0]["System"]["TimeCreated"]["SystemTime"] = "invalid"
        with self.assertRaisesRegex(CaseError, "timestamp"):
            self.preserve(rows)

    def test_fractional_case_window_uses_authoritative_native_time(self):
        self.case.meta.update(start="2026-10-30T20:27:00.800000Z", end="2026-10-30T20:27:00.950000Z")
        save(self.case.root / "case.json", self.case.meta)
        inside = copy.deepcopy(self.rows[0])
        inside["System"]["TimeCreated"] = {"SystemTime": "2026-10-30T20:27:00.8943413Z"}
        outside = copy.deepcopy(inside)
        outside["System"]["TimeCreated"]["SystemTime"] = "2026-10-30T20:27:00.9900000Z"
        self.preserve([inside, outside])
        result = analyze(self.case)
        self.assertEqual(result["summary"]["events"], 1)
        self.assertEqual(result["summary"]["excluded_outside_window"], 1)
        self.assertEqual(result["events"][0]["timestamp_utc"], "2026-10-30T20:27:00.8943413Z")

    def test_missing_coverage_and_row_limit_visible(self):
        rows = [row for row in self.rows if row.get("CrumbTrailRowType") != "coverage"]
        self.preserve(rows)
        self.assertEqual(len(analyze(self.case)["gaps"]), 5)
        other = Case.create(self.base / "limit", self.case.meta["start"], self.case.meta["end"])
        other.bind(LAB_CLIENT, "LAB-WIN01")
        rows = copy.deepcopy(self.rows)
        rows[-1]["AtLimit"] = True
        other.preserve(encode(rows), LAB_CLIENT, "test", True)
        self.assertIn("row limit", analyze(other)["gaps"][0]["reason"])

    def test_coverage_mismatch_is_a_gap(self):
        rows = copy.deepcopy(self.rows)
        rows[-1]["Events"] = 999
        self.preserve(rows)
        self.assertIn("count differs", analyze(self.case)["gaps"][0]["reason"])

    def test_duplicate_coverage_cannot_mask_a_row_limit(self):
        rows = copy.deepcopy(self.rows)
        limited = copy.deepcopy(rows[-1])
        limited["AtLimit"] = True
        rows.insert(0, limited)
        with self.assertRaisesRegex(CaseError, "Duplicate coverage"):
            self.preserve(rows)

    def test_case_byte_budget_checked_before_evidence_write(self):
        with patch("crumbtrail.storage.MAX_CASE_BYTES", len(self.raw) - 1):
            with self.assertRaisesRegex(CaseError, "256 MiB"):
                self.preserve()
        self.assertEqual(self.case.manifest()["artifacts"], [])

    def test_concurrent_cli_writer_fails_without_changing_first_evidence(self):
        entry = self.preserve()
        manifest_before = (self.case.root / "manifest.json").read_bytes()
        source = self.base / "second.jsonl"
        source.write_bytes(encode(self.rows[0]))
        with case_lock(self.case.root):
            second = subprocess.run([sys.executable, "-m", "crumbtrail", "import", "--root", str(self.case.root),
                                     "--client-id", LAB_CLIENT, "--file", str(source), "--simulation"],
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(second.returncode, 1)
        self.assertIn("already in use", second.stderr)
        self.assertEqual((self.case.root / "manifest.json").read_bytes(), manifest_before)
        self.assertEqual((self.case.root / entry["path"]).read_bytes(), self.raw)
        self.assertEqual(self.case.verify(), 1)

    def test_benign_file_burst_is_not_a_recovery_finding(self):
        self.preserve()
        result = analyze(self.case)
        burst = [f for f in result["findings"] if f["rule"] == "file-burst"]
        self.assertEqual(len(burst), 1)
        referenced = [e for e in result["events"] if e["event_id"] in burst[0]["event_ids"]]
        self.assertFalse(any(e["account"] == "lab\\backup" for e in referenced))
        self.assertIn("establish encryption", burst[0]["interpretation"])

    def test_same_logon_id_does_not_join_other_hosts(self):
        self.preserve([self.rows[0]])
        self.case.bind("C.1111111111111111", "OTHER-HOST")
        process = copy.deepcopy(self.rows[1])
        process["System"]["Computer"] = "OTHER-HOST"
        self.preserve([process], client="C.1111111111111111")
        self.assertEqual(analyze(self.case)["findings"], [])

    def test_simulation_does_not_join_real_evidence(self):
        self.preserve([self.rows[0]])
        self.preserve([self.rows[1]], simulation=False)
        self.assertEqual(analyze(self.case)["findings"], [])

    def test_case_window_filters_derived_events_only(self):
        self.case.meta["end"] = "2026-10-30T20:28:00Z"
        save(self.case.root / "case.json", self.case.meta)
        entry = self.preserve()
        result = analyze(self.case)
        self.assertEqual(result["summary"]["events"], 1)
        self.assertEqual(result["summary"]["excluded_outside_window"], 21)
        self.assertEqual((self.case.root / entry["path"]).read_bytes(), self.raw)

    def test_html_escapes_evidence_and_csv_neutralizes_formulas(self):
        rows = [copy.deepcopy(self.rows[1])]
        rows[0]["EventData"]["CommandLine"] = '=cmd|\'<script>alert("x")</script>\'!A0'
        self.preserve(rows)
        write_report(self.case, analyze(self.case))
        html = (self.case.root / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("default-src 'none'", html)
        with (self.case.root / "timeline.csv").open(encoding="utf-8-sig", newline="") as stream:
            table = list(csv.DictReader(stream))
        self.assertTrue(table[0]["command_line"].startswith("'="))

    def test_unregistered_raw_file_is_not_silently_ignored(self):
        self.preserve()
        (self.case.root / "raw" / "orphan.json").write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(CaseError, "Unregistered"):
            self.case.verify()

    def test_demo_is_deterministic_and_refuses_overwrite(self):
        roots = [self.base / "one", self.base / "two"]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            for root in roots:
                self.assertEqual(main(["demo", "--root", str(root)]), 0)
            self.assertEqual(main(["demo", "--root", str(roots[0])]), 1)
        first, second = [json.loads((root / "timeline.json").read_text(encoding="utf-8")) for root in roots]
        self.assertEqual(first["events"], second["events"])
        self.assertEqual(first["findings"], second["findings"])
        for result in (first, second):
            self.assertEqual(result["summary"]["events"], 21)
            self.assertEqual(result["summary"]["unclassified_events"], 21)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["session_view"]["summary"]["sessions"], 0)
            self.assertEqual(result["session_view"]["summary"]["unlinked_events"], 21)
            self.assertEqual(sum(len(event["references"]) for event in result["events"]), 22)
            self.assertTrue(all(event["classification"]["status"] == "missing-provider" for event in result["events"]))

    def test_native_parser_requires_explicit_log_directory(self):
        executable = self.base / "collector.exe"
        executable.write_bytes(b"inert")
        with patch("crumbtrail.native.subprocess.run") as run:
            with self.assertRaisesRegex(CaseError, "explicitly"):
                run_local(self.case, LAB_CLIENT, executable)
            run.assert_not_called()

    def test_cli_gap_status_is_two_and_report_exists(self):
        source = self.base / "one.jsonl"
        source.write_bytes(encode(self.rows[0]))
        with contextlib.redirect_stdout(io.StringIO()):
            result = main(["import", "--root", str(self.case.root), "--client-id", LAB_CLIENT,
                           "--file", str(source), "--simulation"])
        self.assertEqual(result, 2)
        self.assertTrue((self.case.root / "report.html").is_file())


if __name__ == "__main__":
    unittest.main()
