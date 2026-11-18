import codecs
import copy
import csv
import io
import json
import tempfile
import unittest
from contextlib import contextmanager
from html import escape
from pathlib import Path
from unittest.mock import patch

from crumbtrail.events import analyze
from crumbtrail.native import data_path
from crumbtrail.report import REPORT_FILENAMES, write_report
from crumbtrail.storage import Case, CaseError, atomic_writer, case_lock, encode, records


CLIENT = "C.0123456789abcdef"
FORMATTED_COMMAND = 'Write-Output "Café, <draft> & notes"\nnext line'


class ReportOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.raw = data_path("windows-providers.jsonl").read_bytes()
        self.case = self.new_case("case")
        self.result = analyze(self.case)

    def new_case(self, name):
        case = Case.create(self.base / name, "2026-10-30T20:00:00Z", "2026-10-30T22:00:00Z", "CT-REPORT")
        self.enterContext(case_lock(case.root))
        case = Case(case.root)
        case.bind(CLIENT, "LAB-WIN01")
        case.preserve(self.raw, CLIENT, "report-fixture", True)
        return case

    def add_formatted_event(self):
        row = copy.deepcopy(records(self.raw)[1])
        row["System"]["EventRecordID"] = 987654
        row["EventData"]["CommandLine"] = FORMATTED_COMMAND
        self.case.preserve(encode([row]), CLIENT, "report-format-fixture", True)
        self.result = analyze(self.case)

    def evidence_bytes(self, case=None):
        case = case or self.case
        names = ["case.json", "manifest.json"] + [entry["path"] for entry in case.manifest()["artifacts"]]
        return {name: (case.root / name).read_bytes() for name in names}

    def output_bytes(self):
        return {name: (self.case.root / name).read_bytes() for name in REPORT_FILENAMES}

    def assert_evidence_unchanged(self, before, case=None):
        case = case or self.case
        self.assertEqual(self.evidence_bytes(case), before)
        self.assertEqual(case.verify(), len(case.manifest()["artifacts"]))

    def test_existing_reports_regenerate_without_changing_evidence(self):
        write_report(self.case, self.result)
        first = self.output_bytes()
        self.add_formatted_event()
        evidence = self.evidence_bytes()

        write_report(self.case, self.result)
        regenerated = self.output_bytes()
        for name in ("timeline.json", "timeline.csv", "report.html"):
            self.assertNotEqual(regenerated[name], first[name])
        write_report(self.case, self.result)
        self.assertEqual(self.output_bytes(), regenerated)
        self.assert_evidence_unchanged(evidence)
        self.assertEqual(list(self.case.root.glob("*.tmp")), [])

    def test_formats_references_and_synthetic_labels_are_preserved(self):
        self.add_formatted_event()
        evidence = self.evidence_bytes()
        write_report(self.case, self.result)
        outputs = self.output_bytes()

        self.assertEqual(outputs["timeline.json"], encode(self.result) + b"\n")
        self.assertEqual(outputs["sessions.json"], encode(self.result["session_view"]) + b"\n")
        csv_bytes = outputs["timeline.csv"]
        header = b"event_id,timestamp_utc,hostname,channel,event_code,kind,label,account,image,command_line,target,simulation\r\n"
        self.assertTrue(csv_bytes.startswith(codecs.BOM_UTF8 + header))
        self.assertEqual(csv_bytes.count(codecs.BOM_UTF8), 1)
        self.assertNotIn(b"\r\r\n", csv_bytes)
        exported = list(csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig"), newline="")))
        self.assertEqual(len(exported), len(self.result["events"]))
        self.assertIn(FORMATTED_COMMAND, [row["command_line"] for row in exported])
        self.assertTrue(all(row["simulation"] == "True" for row in exported))
        self.assertEqual([row["timestamp_utc"] for row in exported],
                         [event["timestamp_utc"] for event in self.result["events"]])

        html = outputs["report.html"].decode("utf-8")
        self.assertIn(escape(FORMATTED_COMMAND, quote=True), html)
        self.assertIn("[SYNTHETIC]", html)
        self.assertIn("default-src 'none'", html)
        saved = json.loads(outputs["timeline.json"])
        for event, persisted in zip(self.result["events"], saved["events"]):
            self.assertEqual(persisted["references"], event["references"])
            self.assertIn('id="' + event["event_id"] + '"', html)
            for ref in event["references"]:
                self.assertIn('href="' + ref["artifact"] + '">raw ' + ref["sha256"][:12] + " row " + str(ref["row"]), html)
        self.assert_evidence_unchanged(evidence)

    def test_directory_destination_rejected_before_any_report_changes(self):
        for index, invalid_name in enumerate(REPORT_FILENAMES):
            with self.subTest(destination=invalid_name):
                case = self.new_case("invalid-" + str(index))
                (case.root / invalid_name).mkdir()
                previous = {}
                for name in REPORT_FILENAMES:
                    if name != invalid_name:
                        previous[name] = ("previous complete " + name).encode("utf-8")
                        (case.root / name).write_bytes(previous[name])
                evidence = self.evidence_bytes(case)
                with self.assertRaisesRegex(CaseError, "Report destination must be a regular file"):
                    write_report(case, self.result)
                self.assertTrue((case.root / invalid_name).is_dir())
                self.assertEqual({name: (case.root / name).read_bytes() for name in previous}, previous)
                self.assert_evidence_unchanged(evidence, case)
                self.assertEqual(list(case.root.glob("*.tmp")), [])

    def test_pre_replacement_io_failure_retains_previous_csv_and_html(self):
        for failed_name in ("timeline.csv", "report.html"):
            with self.subTest(destination=failed_name):
                write_report(self.case, self.result)
                previous = (self.case.root / failed_name).read_bytes()
                evidence = self.evidence_bytes()
                changed = copy.deepcopy(self.result)
                changed["events"][0]["label"] += " revised presentation"

                @contextmanager
                def fail_before_replace(path, **options):
                    with atomic_writer(path, **options) as stream:
                        yield stream
                        if Path(path).name == failed_name:
                            raise OSError("simulated pre-replacement I/O failure")

                with patch("crumbtrail.report.atomic_writer", fail_before_replace):
                    with self.assertRaisesRegex(OSError, "simulated pre-replacement I/O failure"):
                        write_report(self.case, changed)
                self.assertEqual((self.case.root / failed_name).read_bytes(), previous)
                self.assertEqual(list(self.case.root.glob("*.tmp")), [])
                self.assert_evidence_unchanged(evidence)


if __name__ == "__main__":
    unittest.main()
