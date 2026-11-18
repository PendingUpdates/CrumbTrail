"""Synthetic provider contracts; no native reader or collector is invoked."""
import copy
import csv
import json
import tempfile
import unittest
from pathlib import Path

from crumbtrail.cli import LAB_CLIENT
from crumbtrail.events import analyze, correlate, normalize
from crumbtrail.native import data_path
from crumbtrail.report import write_report
from crumbtrail.sessions import build_session_view
from crumbtrail.storage import Case, digest, encode, records


AUDIT = "Microsoft-Windows-Security-Auditing"
EVENTLOG = "Microsoft-Windows-Eventlog"
SYSMON = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
UNKNOWN = "Synthetic.Unlisted.Provider"
GUID = "11111111-1111-1111-1111-111111111111"

# These independent expectations describe the supported public event contract.
SUPPORTED = (
    ("Security", AUDIT, 4624, "logon.success"),
    ("Security", AUDIT, 4625, "logon.failure"),
    ("Security", AUDIT, 4688, "process"),
    ("Security", AUDIT, 4697, "service"),
    ("Security", AUDIT, 4698, "task"),
    ("Security", AUDIT, 4634, "event"),
    ("Security", AUDIT, 4608, "event"),
    ("Security", EVENTLOG, 1102, "log.clear"),
    ("System", EVENTLOG, 104, "log.clear"),
    ("System", "Service Control Manager", 7045, "service"),
    (SYSMON_CHANNEL, SYSMON, 1, "process"),
    (SYSMON_CHANNEL, SYSMON, 3, "network"),
    (SYSMON_CHANNEL, SYSMON, 11, "file"),
    (SYSMON_CHANNEL, SYSMON, 15, "file"),
    ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104, "script"),
    ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116, "detection"),
    ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1117, "detection"),
)

LEGACY_SHA256 = "d7f72f479398fd399230f6f9e576ca42a2c3338f335d056754a30c1b33469540"
POSITIVE_SHA256 = "9ea230e76849477e337d233861887641b6eb8a2817d0d18f4ec2e80c88fd3aaa"
# Frozen public identity calculation with case ID CT-PROVIDER-LEGACY and the
# bound LAB_CLIENT/lab-win01/root identity. Classification must not rekey it.
LEGACY_EVENT_IDS = {
    "EVT-0e1d896cf0fde059a1685a90", "EVT-19b960551177169b2349f6be",
    "EVT-1e4d859837e7b918937e11db", "EVT-272892fb922475ac90cd2d7f",
    "EVT-2ac69cfb2ed558368f29383b", "EVT-2e9eea46a3965e8985e3e50d",
    "EVT-36a89af0081b13b1848ea2dc", "EVT-62790d2ee739d898b778367b",
    "EVT-791bc7602bd6812e5736a4a3", "EVT-832e9074c61632924b6f4b14",
    "EVT-83667b4f7de368197027d368", "EVT-9488a15f6ca42709d1b1fe12",
    "EVT-984d56e44fbacafb0f327ade", "EVT-9a19c1aa01ce3a79a848567b",
    "EVT-a7e64ccdfc53c52443d53a0a", "EVT-b5ed7aa0bf10fa7a5c02c43f",
    "EVT-ec9f5b40f9ff80436aece3f9", "EVT-ee10f024bcdb07cef0538145",
    "EVT-f110f0c58d26bf47f6cead95", "EVT-f130f9c2b8c2fb976234f700",
    "EVT-fc7b7376b0b43c662791374e",
}
# The separately authored provider fixture intentionally has new bytes and IDs.
POSITIVE_EVENT_IDS = {
    "EVT-0ee81bfb24cc2e322e91fe49", "EVT-0f3666e236548198b2375f90",
    "EVT-0f8940f12d46a9f51db8e582", "EVT-112f0ba2a28385e761e51e16",
    "EVT-14e9d385a7ee2a6bec90eab8", "EVT-1dcaa86230052de849d964de",
    "EVT-2c42336a18b59fbc694df97d", "EVT-3357029f4953df44e4a6c478",
    "EVT-38a21b7c71a14644d75110e1", "EVT-3f38351cc2be83d7e4112cc9",
    "EVT-4e2918f4152ce69ebcfcf01c", "EVT-4f3320b9c8a7fe7ffa0fb89e",
    "EVT-57ffb2cb534ca10656b8e1ad", "EVT-5eea1a6d86cfc8d49c61978d",
    "EVT-686984968ca56a1c6f26c5d1", "EVT-7b6b3393ce527020ef649595",
    "EVT-95371e37cc9e822253d8b720", "EVT-ae54e092bde736f3a4d55f7e",
    "EVT-b03bcbd73dba001795de70c1", "EVT-e0d2bb63908cc8ed78cf95a2",
    "EVT-fcebc18a72d4e9fe583756aa",
}


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "case"
        self.case = Case.create(self.root, "2026-10-30T20:00:00Z", "2026-10-30T22:00:00Z", "CT-PROVIDER-LEGACY")
        self.bound = self.case.bind(LAB_CLIENT, "LAB-WIN01")

    def row(self, channel="Security", provider=AUDIT, code=4624, record=1, minute=1):
        system = {"Computer": "LAB-WIN01"}
        if provider is not None:
            system["Provider"] = {"Name": provider}
        return {
            "CrumbTrailRowType": "event", "TimeCreated": f"2026-10-30T20:{minute:02}:00Z",
            "Channel": channel, "EventID": code, "EventRecordID": record, "System": system,
            "EventData": {"TargetLogonId": "0x42", "TargetUserName": "synthetic-user",
                          "ProcessGuid": GUID, "Image": r"C:\Synthetic\example.exe",
                          "CommandLine": "example.exe --sample", "TargetFilename": r"C:\Synthetic\sample.txt",
                          "ServiceName": "SyntheticService", "TaskName": "SyntheticTask"},
        }

    def event(self, **arguments):
        row = self.row(**arguments)
        event = normalize(self.case, row, self.bound, True)
        event["references"] = [{"artifact": "raw/synthetic.json", "sha256": digest(encode(row)),
                                "row": row["EventRecordID"], "provenance": {"simulation": True}}]
        return event

    def positive_result(self):
        raw = data_path("windows-providers.jsonl").read_bytes()
        self.case.preserve(raw, LAB_CLIENT, "authored-provider-fixture", True)
        return analyze(self.case)

    def test_all_17_supported_provider_channel_event_mappings_keep_semantics(self):
        for channel, provider, code, kind in SUPPORTED:
            with self.subTest(channel=channel, provider=provider, code=code):
                row = self.row(channel, provider, code)
                before = copy.deepcopy(row)
                event = normalize(self.case, row, self.bound, True)
                self.assertEqual(event["classification"]["status"], "supported")
                self.assertTrue(event["classification"]["reason"])
                self.assertEqual(event["kind"], kind)
                self.assertFalse(event["label"].startswith("Unclassified"))
                self.assertEqual(event["provider"], provider)
                self.assertEqual(event["timestamp_utc"], row["TimeCreated"])
                self.assertEqual(event["record_id"], row["EventRecordID"])
                self.assertTrue(event["simulation"])
                self.assertEqual(row, before)

    def test_missing_unknown_mismatched_and_unsupported_events_stay_generic(self):
        variants = (
            (None, "Security", 4624, "missing-provider"),
            ("", "Security", 4624, "missing-provider"),
            (" \t ", "Security", 4624, "missing-provider"),
            (UNKNOWN, "Security", 4624, "unsupported-provider"),
            (" " + AUDIT + " ", "Security", 4624, "unsupported-provider"),
            (SYSMON, "Security", 4624, "unsupported-event"),
            (AUDIT, "Security", 1102, "unsupported-event"),
            (AUDIT, "Security", 9999, "unsupported-event"),
            (SYSMON, "System", 1, "unsupported-event"),
        )
        for provider, channel, code, status in variants:
            with self.subTest(provider=provider, channel=channel, code=code):
                row = self.row(channel, provider, code)
                original = copy.deepcopy(row)
                event = normalize(self.case, row, self.bound, True)
                self.assertEqual(event["classification"]["status"], status)
                self.assertEqual(event["kind"], "event")
                self.assertTrue(event["label"].startswith("Unclassified "))
                self.assertIn(event["classification"]["reason"], event["label"])
                self.assertEqual(event["provider"], provider or "")
                self.assertEqual(event["source_logon_ids"], [{"field": "TargetLogonId", "raw": "0x42", "value": "66"}])
                for field in ("account", "image", "command_line", "target", "process_guid", "parent_process_guid", "logon_id"):
                    self.assertEqual(event[field], "")
                self.assertIsNone(event["sha256"])
                self.assertEqual(row, original)

    def test_provider_representations_and_case_matching_retain_source_text(self):
        supplied = AUDIT.swapcase()
        identifiers = set()
        for level, shape in (("System", "object"), ("System", "text"), ("row", "object"), ("row", "text")):
            with self.subTest(level=level, shape=shape):
                row = self.row(provider=None)
                container = row["System"] if level == "System" else row
                container["Provider"] = {"Name": supplied} if shape == "object" else supplied
                before = copy.deepcopy(row)
                event = normalize(self.case, row, self.bound, True)
                self.assertEqual(event["classification"]["status"], "supported")
                self.assertEqual(event["provider"], supplied)
                self.assertEqual(row, before)
                identifiers.add(event["event_id"])
        self.assertEqual(len(identifiers), 1)
        self.assertNotIn(self.event()["event_id"], identifiers)

    def test_unknown_and_missing_imports_preserve_raw_bytes_references_and_ids(self):
        missing = self.row(provider=None)
        unknown = self.row(provider=UNKNOWN)
        raw = json.dumps([missing, unknown, missing], indent=2).encode("utf-8") + b"\r\n"
        entry = self.case.preserve(raw, LAB_CLIENT, "synthetic-provider-inputs", True)
        first = analyze(self.case)
        second = analyze(self.case)
        self.assertEqual(first["summary"]["events"], 2)
        self.assertEqual(first["summary"]["duplicate_rows"], 1)
        self.assertEqual(first["summary"]["unclassified_events"], 2)
        self.assertEqual(first["events"], second["events"])
        self.assertEqual(first["findings"], [])
        by_provider = {event["provider"]: event for event in first["events"]}
        self.assertEqual(len(by_provider[""]["references"]), 2)
        self.assertEqual(len(by_provider[UNKNOWN]["references"]), 1)
        for source in (missing, unknown):
            normalized = normalize(self.case, source, self.bound, True)
            self.assertEqual(normalized["event_id"], by_provider[normalized["provider"]]["event_id"])
        self.assertEqual(entry["sha256"], digest(raw))
        self.assertEqual((self.root / entry["path"]).read_bytes(), raw)
        self.assertEqual({reference["sha256"] for event in first["events"] for reference in event["references"]}, {digest(raw)})
        self.assertEqual(sorted(reference["row"] for event in first["events"] for reference in event["references"]), [1, 2, 3])
        self.assertEqual(self.case.verify(), 1)

    def test_legacy_providerless_fixture_keeps_bytes_ids_and_references(self):
        raw = data_path("windows.jsonl").read_bytes()
        self.assertEqual(digest(raw), LEGACY_SHA256)
        entry = self.case.preserve(raw, LAB_CLIENT, "legacy-synthetic-fixture", True)
        result = analyze(self.case)
        self.assertEqual(result["summary"], dict(events=21, findings=0, gaps=0, artifacts=1,
                         raw_event_rows=22, excluded_outside_window=0, duplicate_rows=1, unclassified_events=21))
        self.assertEqual({event["event_id"] for event in result["events"]}, LEGACY_EVENT_IDS)
        self.assertEqual(sum(len(event["references"]) for event in result["events"]), 22)
        self.assertTrue(all(event["provider"] == "" and event["classification"]["status"] == "missing-provider"
                            for event in result["events"]))
        self.assertEqual(result["session_view"]["summary"], dict(sessions=0, linked_events=0, unlinked_events=21,
                         ambiguous_events=0, unbounded_id_groups=0, events=21))
        self.assertEqual(result["session_view"]["boundaries"], [])
        write_report(self.case, result)
        self.assertEqual((self.root / entry["path"]).read_bytes(), raw)
        self.assertEqual(data_path("windows.jsonl").read_bytes(), raw)
        self.assertEqual(self.case.verify(), 1)

    def test_authored_positive_fixture_has_explicit_providers_and_new_identity(self):
        legacy = data_path("windows.jsonl").read_bytes()
        authored = data_path("windows-providers.jsonl").read_bytes()
        self.assertEqual(digest(legacy), LEGACY_SHA256)
        self.assertEqual(digest(authored), POSITIVE_SHA256)
        original_rows, authored_rows = records(legacy), records(authored)
        self.assertEqual(len(original_rows), len(authored_rows))
        for original, supplied in zip(original_rows, authored_rows):
            restored = copy.deepcopy(supplied)
            if supplied["CrumbTrailRowType"] == "event":
                self.assertNotIn("Provider", original["System"])
                self.assertTrue(restored["System"].pop("Provider")["Name"])
            self.assertEqual(restored, original)
        result = self.positive_result()
        self.assertEqual(result["summary"], dict(events=21, findings=4, gaps=0, artifacts=1,
                         raw_event_rows=22, excluded_outside_window=0, duplicate_rows=1, unclassified_events=0))
        self.assertEqual({event["event_id"] for event in result["events"]}, POSITIVE_EVENT_IDS)
        self.assertTrue(POSITIVE_EVENT_IDS.isdisjoint(LEGACY_EVENT_IDS))
        self.assertTrue(all(event["simulation"] and event["classification"]["status"] == "supported" for event in result["events"]))
        self.assertEqual(result["session_view"]["summary"], dict(sessions=1, linked_events=3, unlinked_events=18,
                         ambiguous_events=0, unbounded_id_groups=0, events=21))
        self.assertEqual(sum(len(event["references"]) for event in result["events"]), 22)
        self.assertEqual(self.case.verify(), 1)

    def test_unclassified_events_cannot_join_or_cut_off_supported_session(self):
        for provider in (None, UNKNOWN):
            for channel, code in ((SYSMON_CHANNEL, 1), ("Security", 4634), ("Security", 4608)):
                with self.subTest(provider=provider, channel=channel, code=code):
                    start = self.event()
                    excluded = self.event(channel=channel, provider=provider, code=code, record=2, minute=2)
                    process = self.event(channel=SYSMON_CHANNEL, provider=SYSMON, code=1, record=3, minute=3)
                    view = build_session_view([start, excluded, process])
                    member = next(item for item in view["events"] if item["event_id"] == excluded["event_id"])
                    self.assertEqual(member["status"], "unlinked")
                    self.assertEqual(member["reason_codes"], ["unclassified_event"])
                    self.assertEqual(member["source_logon_ids"], excluded["source_logon_ids"])
                    self.assertEqual(member["references"], excluded["references"])
                    self.assertEqual(member["logon_ids"], [])
                    self.assertEqual(member["candidate_session_ids"], [])
                    self.assertEqual(view["boundaries"], [])
                    self.assertEqual(view["unbounded_id_groups"], [])
                    self.assertIsNone(view["sessions"][0]["end_utc"])
                    self.assertEqual([finding["event_ids"] for finding in correlate([start, excluded, process])],
                                     [[start["event_id"], process["event_id"]]])

    def test_stale_classification_kind_and_cached_view_cannot_admit_unknown_tuple(self):
        known = [self.event(), self.event(channel=SYSMON_CHANNEL, provider=SYSMON, code=1, record=2, minute=2)]
        cached = build_session_view(known)
        self.assertEqual(len(correlate(copy.deepcopy(known))), 1)
        for changed in (0, 1):
            for provider in ("", UNKNOWN):
                with self.subTest(changed=changed, provider=provider):
                    stale = copy.deepcopy(known)
                    stale[changed]["provider"] = provider
                    self.assertEqual(stale[changed]["classification"]["status"], "supported")
                    view = build_session_view(stale)
                    member = next(item for item in view["events"] if item["event_id"] == stale[changed]["event_id"])
                    self.assertEqual(member["status"], "unlinked")
                    self.assertEqual(member["reason_codes"], ["unclassified_event"])
                    self.assertEqual(correlate(stale, session_view=cached), [])

    def test_cached_session_view_cannot_relink_across_a_supported_boundary(self):
        start = self.event()
        process = self.event(channel=SYSMON_CHANNEL, provider=SYSMON, code=1, record=3, minute=3)
        cached = build_session_view([start, process])
        self.assertEqual(len(correlate(copy.deepcopy([start, process]), session_view=cached)), 1)
        boundary = self.event(code=4634, record=2, minute=2)
        self.assertEqual(correlate([start, boundary, process], session_view=cached), [])

    def test_stale_positive_fixture_kinds_cannot_emit_unclassified_findings(self):
        result = self.positive_result()
        self.assertEqual(len(result["findings"]), 4)
        for provider in ("", UNKNOWN):
            with self.subTest(provider=provider):
                stale = copy.deepcopy(result["events"])
                for event in stale:
                    event["provider"] = provider
                    event["finding_ids"] = []
                self.assertIn("recovery", {event["kind"] for event in stale})
                self.assertIn("file", {event["kind"] for event in stale})
                self.assertEqual(correlate(stale, session_view=result["session_view"]), [])
                self.assertTrue(all(not event["finding_ids"] for event in stale))
                view = build_session_view(stale)
                self.assertEqual(view["summary"]["sessions"], 0)
                self.assertEqual(view["summary"]["unlinked_events"], 21)

    def test_unclassified_status_and_reason_are_visible_in_json_html_and_csv(self):
        source = [self.row(provider=None), self.row(provider=UNKNOWN, record=2, minute=2)]
        raw = encode(source)
        entry = self.case.preserve(raw, LAB_CLIENT, "synthetic-report-inputs", True)
        result = analyze(self.case)
        write_report(self.case, result)
        saved = json.loads((self.root / "timeline.json").read_text())
        self.assertEqual(saved["events"], result["events"])
        self.assertEqual(saved["summary"]["unclassified_events"], 2)
        html = (self.root / "report.html").read_text()
        self.assertIn("2 unclassified events", html)
        with (self.root / "timeline.csv").open(encoding="utf-8-sig", newline="") as stream:
            csv_events = {row["event_id"]: row for row in csv.DictReader(stream)}
        for event in result["events"]:
            self.assertIn("Unclassified", event["label"])
            self.assertTrue(event["classification"]["reason"])
            self.assertIn(event["classification"]["reason"], html)
            self.assertIn(event["label"], html)
            self.assertEqual(csv_events[event["event_id"]]["label"], event["label"])
            self.assertIn(event["classification"]["reason"], csv_events[event["event_id"]]["label"])
            self.assertTrue(event["references"])
        self.assertEqual((self.root / entry["path"]).read_bytes(), raw)
        self.assertEqual(self.case.verify(), 1)


if __name__ == "__main__":
    unittest.main()
