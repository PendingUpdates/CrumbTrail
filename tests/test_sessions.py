import contextlib
import copy
import io
import json
import random
import tempfile
import unittest
from pathlib import Path

from crumbtrail.cli import main
from crumbtrail.events import analyze, correlate, normalize
from crumbtrail.report import write_report
from crumbtrail.sessions import build_session_view
from crumbtrail.storage import Case, case_lock, encode


HOST_A = "C.1111111111111111"
HOST_B = "C.2222222222222222"
AUTHORED_PROVIDER = object()


class SessionViewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "case"
        self.case = Case.create(self.root, "2026-10-30T20:00:00Z", "2026-10-30T22:00:00Z", "CT-SESSIONS")
        self.case.bind(HOST_A, "host-a")
        self.case.bind(HOST_B, "host-b")

    def row(self, record, minute, fields, code=1, host=HOST_A, provider=AUTHORED_PROVIDER):
        channel = "Microsoft-Windows-Sysmon/Operational" if code == 1 else "Security"
        # These are authored mock events, not inferred providers for imports.
        if provider is AUTHORED_PROVIDER:
            provider = "Microsoft-Windows-Sysmon" if code == 1 else "Microsoft-Windows-Security-Auditing"
        system = {"Computer": self.case.binding(host)["hostname"]}
        if provider is not None:
            system["Provider"] = {"Name": provider}
        return {"TimeCreated": f"2026-10-30T20:{minute:02}:00Z", "Channel": channel,
                "EventID": code, "EventRecordID": record,
                "System": system,
                "EventData": fields}

    def event(self, record, minute, fields, code=1, host=HOST_A, simulation=False, provider=AUTHORED_PROVIDER):
        event = normalize(self.case, self.row(record, minute, fields, code, host, provider), self.case.binding(host), simulation)
        event["references"] = [{"artifact": "raw/" + str(record) + ".json", "sha256": str(record),
                                "row": 1, "provenance": {"client_id": host, "simulation": simulation}}]
        return event

    def start(self, record, minute, logon, host=HOST_A, simulation=False, provider=AUTHORED_PROVIDER, **fields):
        return self.event(record, minute, {"TargetLogonId": logon, "TargetUserName": "analyst", **fields},
                          4624, host, simulation, provider)

    def boundary(self, record, minute, code, host=HOST_A, logon="0x42", provider=AUTHORED_PROVIDER):
        row = self.row(record, minute, {"TargetLogonId": logon} if code == 4634 else {}, code, host, provider)
        event = normalize(self.case, row, self.case.binding(host), False)
        event["references"] = [{"artifact": "raw/boundary.json", "sha256": "boundary", "row": record}]
        return event

    def process(self, record, minute, provider=AUTHORED_PROVIDER, **fields):
        return self.event(record, minute, {
            "Image": r"C:\Windows\example.exe",
            "ProcessGuid": "11111111-1111-1111-1111-111111111111", **fields}, provider=provider)

    def logon_findings(self, events):
        return [finding for finding in correlate(events) if finding["rule"] == "logon-process"]

    def test_correlation_respects_logoff_and_startup_and_new_start(self):
        for code in (4634, 4608):
            with self.subTest(code=code):
                start = self.start(1, 1, "0x42")
                before = self.process(2, 2, LogonId="0x42")
                cutoff = self.boundary(3, 3, code)
                after = self.process(4, 4, LogonId="0x42")
                restart = self.start(5, 5, "0x42")
                renewed = self.process(6, 6, LogonId="0x42")
                events = [renewed, after, cutoff, start, restart, before]
                self.assertEqual([f["event_ids"] for f in self.logon_findings(events)],
                                 [[start["event_id"], before["event_id"]],
                                  [restart["event_id"], renewed["event_id"]]])

    def test_correlation_suppresses_repeated_starts_and_conflicting_roles(self):
        first, second = self.start(1, 1, "0x42"), self.start(3, 3, "0x42")
        process = self.process(2, 2, LogonId="0x42")
        self.assertEqual(self.logon_findings([first, process, second]), [])
        conflict = self.process(4, 4, SubjectLogonId="0x42", TargetLogonId="0x43")
        self.assertEqual(self.logon_findings([first, conflict]), [])

    def test_correlation_uses_start_target_not_subject_or_generic_id(self):
        start = self.start(1, 1, "0x42", SubjectLogonId="0x43", LogonId="0x44")
        correct = self.process(2, 2, LogonId="0x42")
        subject = self.process(3, 3, LogonId="0x43")
        generic = self.process(4, 4, LogonId="0x44")
        self.assertEqual([f["event_ids"] for f in self.logon_findings([start, correct, subject, generic])],
                         [[start["event_id"], correct["event_id"]]])

    def test_correlation_rejects_untrusted_start_provider(self):
        self.assertEqual(len(self.logon_findings([
            self.start(1, 1, "0x42"), self.process(2, 2, LogonId="0x42")])), 1)
        for provider in (None, "Untrusted-Provider"):
            with self.subTest(provider=provider):
                start = self.start(1, 1, "0x42", provider=provider)
                self.assertEqual(self.logon_findings([start, self.process(2, 2, LogonId="0x42")]), [])

    def test_correlation_keeps_30_minute_window_and_boundary_ties(self):
        start = self.start(1, 1, "0x42")
        at_limit = self.process(2, 31, LogonId="0x42")
        outside = self.process(3, 32, LogonId="0x42")
        self.assertEqual(len(self.logon_findings([start, at_limit, outside])), 1)
        cutoff = self.boundary(4, 31, 4634)
        self.assertEqual(self.logon_findings([start, at_limit, cutoff]), [])

    def test_two_sessions_on_each_of_two_hosts_reuse_ids_without_cross_linking(self):
        events = []
        for host, base in ((HOST_A, 100), (HOST_B, 200)):
            for offset, logon in ((0, "0x42"), (10, "0x43")):
                events += [self.start(base + offset, offset, logon, host),
                           self.event(base + offset + 1, offset + 1, {"LogonId": logon}, host=host)]
        view = build_session_view(events)
        self.assertEqual(view["summary"]["sessions"], 4)
        self.assertEqual(view["summary"]["linked_events"], 8)
        members = {event["event_id"]: event for event in view["events"]}
        for session in view["sessions"]:
            self.assertEqual(len(session["event_ids"]), 2)
            self.assertEqual({members[eid]["scope"]["client_id"] for eid in session["event_ids"]},
                             {session["scope"]["client_id"]})
            self.assertEqual({members[eid]["logon_ids"][0] for eid in session["event_ids"]}, {session["logon_id"]})

    def test_100ns_ordering_and_logoff_cutoff_do_not_collapse_to_microseconds(self):
        start = self.start(1, 1, "0x42")
        before = self.event(2, 1, {"LogonId": "0x42"})
        boundary = self.boundary(3, 1, 4634)
        after = self.event(4, 1, {"LogonId": "0x42"})
        for event, digit in zip((start, before, boundary, after), (1, 2, 3, 4)):
            event["timestamp_utc"] = f"2026-10-30T20:01:00.123456{digit}Z"
        result = build_session_view([after, boundary, before, start])
        self.assertEqual([item["event_id"] for item in result["events"]], [item["event_id"] for item in (start, before, boundary, after)])
        membership = {item["event_id"]: item for item in result["events"]}
        self.assertEqual(membership[before["event_id"]]["status"], "linked")
        self.assertEqual(membership[after["event_id"]]["status"], "unlinked")
        self.assertEqual(result["sessions"][0]["end_utc"], "2026-10-30T20:01:00.1234563Z")

    def test_repeated_start_does_not_assign_nearest_session(self):
        first, later = self.start(1, 1, "0x42"), self.start(3, 30, "0x42")
        between = self.event(2, 2, {"LogonId": "0x42"})
        after = self.event(4, 31, {"LogonId": "0x42"})
        view = build_session_view([first, between, later, after])
        self.assertEqual(len(view["sessions"]), 2)
        self.assertEqual({tuple(s["event_ids"]) for s in view["sessions"]},
                         {(first["event_id"],), (later["event_id"],)})
        for event in view["events"]:
            if event["event_id"] in (between["event_id"], after["event_id"]):
                self.assertEqual(event["status"], "ambiguous")
                self.assertEqual(event["reason_codes"], ["repeated_starts"])
                self.assertEqual(len(event["candidate_session_ids"]), 2)
                self.assertIsNone(event["session_id"])

    def test_shuffled_input_is_deterministic_and_input_is_unchanged(self):
        events = [self.start(1, 1, "0x42"), self.event(2, 2, {"LogonId": "0x42"}),
                  self.start(3, 3, "0x43", HOST_B), self.event(4, 4, {"LogonId": "0x99"}),
                  self.event(5, 5, {})]
        original = copy.deepcopy(events)
        expected = build_session_view(events)
        random.Random(7).shuffle(events)
        self.assertEqual(build_session_view(events), expected)
        self.assertEqual(sorted(events, key=lambda e: e["event_id"]), sorted(original, key=lambda e: e["event_id"]))

    def test_missing_boundaries_and_ids_remain_visible_without_process_inference(self):
        start = self.start(1, 1, "0x42")
        process = self.event(2, 2, {"LogonId": "0x42", "ProcessGuid": "{11111111-1111-1111-1111-111111111111}"})
        no_id = self.event(3, 2, {"User": "analyst", "ProcessGuid": "{11111111-1111-1111-1111-111111111111}"})
        no_start = self.event(4, 3, {"LogonId": "0x99"})
        view = build_session_view([start, process, no_id, no_start])
        self.assertEqual(view["summary"]["unlinked_events"], 2)
        self.assertEqual(view["summary"]["unbounded_id_groups"], 1)
        self.assertEqual(view["unbounded_id_groups"][0]["event_ids"], [no_start["event_id"]])
        self.assertIsNone(view["sessions"][0]["end_utc"])
        self.assertTrue(view["sessions"][0]["limitations"])
        self.assertEqual({m["event_id"] for m in view["events"]}, {e["event_id"] for e in [start, process, no_id, no_start]})

    def test_event_before_start_is_not_assigned_to_future_session(self):
        view = build_session_view([self.event(1, 1, {"LogonId": "0x42"}), self.start(2, 2, "0x42")])
        self.assertEqual(view["events"][0]["status"], "unlinked")
        self.assertEqual(view["events"][0]["reason_codes"], ["precedes_start"])

    def test_logoff_closes_only_its_host_and_id_without_relinking_later_event(self):
        later = self.event(4, 4, {"LogonId": "0x42"})
        other_host = self.event(6, 4, {"LogonId": "0x42"}, host=HOST_B)
        view = build_session_view([self.start(1, 1, "0x42"), self.start(5, 1, "0x42", HOST_B),
            self.event(2, 2, {"LogonId": "0x42"}), self.boundary(3, 3, 4634), later, other_host])
        sessions = {s["scope"]["client_id"]: s for s in view["sessions"]}
        self.assertEqual(sessions[HOST_A]["end_utc"], "2026-10-30T20:03:00Z")
        self.assertEqual(sessions[HOST_A]["boundary_status"], "logoff_observed")
        self.assertIsNone(sessions[HOST_B]["end_utc"])
        members = {m["event_id"]: m for m in view["events"]}
        self.assertEqual(members[later["event_id"]]["status"], "unlinked")
        self.assertEqual(members[later["event_id"]]["reason_codes"], ["missing_start"])
        self.assertEqual(members[other_host["event_id"]]["status"], "linked")

    def test_startup_cuts_off_earlier_id_without_inventing_logoff_time(self):
        marker = self.boundary(2, 2, 4608)
        later = self.event(3, 3, {"LogonId": "0x42"})
        view = build_session_view([self.start(1, 1, "0x42"), marker, later])
        session = view["sessions"][0]
        self.assertEqual(session["boundary_status"], "startup_cutoff")
        self.assertEqual(session["cutoff_event_id"], marker["event_id"])
        self.assertIsNone(session["end_utc"])
        self.assertEqual(view["events"][-1]["status"], "unlinked")
        self.assertEqual(view["boundaries"][0]["references"], marker["references"])

    def test_new_start_after_explicit_boundary_reuses_id_in_separate_context(self):
        events = [self.start(1, 1, "0x42"), self.event(2, 2, {"LogonId": "0x42"}),
                  self.boundary(3, 3, 4634), self.start(4, 4, "0x42"),
                  self.event(5, 5, {"LogonId": "0x42"})]
        view = build_session_view(events)
        self.assertEqual(view["summary"]["sessions"], 2)
        self.assertEqual(view["summary"]["ambiguous_events"], 0)
        self.assertEqual([len(s["event_ids"]) for s in view["sessions"]], [3, 2])
        self.assertNotEqual(view["sessions"][0]["session_id"], view["sessions"][1]["session_id"])

    def test_unrecognized_provider_does_not_establish_boundary(self):
        for provider in (None, "Unrelated-Provider"):
            with self.subTest(provider=provider):
                marker = self.boundary(2, 2, 4634, provider=provider)
                view = build_session_view([self.start(1, 1, "0x42"), marker])
                self.assertEqual(view["boundaries"], [])
                self.assertIsNone(view["sessions"][0]["end_utc"])
                self.assertEqual(view["events"][-1]["reason_codes"], ["unclassified_event"])

    def test_wrong_provider_success_record_does_not_establish_start(self):
        for provider in (None, "Unrelated-Provider"):
            with self.subTest(provider=provider):
                event = self.start(1, 1, "0x42", provider=provider)
                view = build_session_view([event])
                self.assertEqual(view["sessions"], [])
                self.assertEqual(view["events"][0]["reason_codes"], ["unclassified_event"])

    def test_provider_difference_is_not_deduplicated_away(self):
        row = self.row(1, 1, {"TargetLogonId": "0x42"}, code=4634)
        row["System"]["Provider"] = {"Name": "Microsoft-Windows-Security-Auditing"}
        other = copy.deepcopy(row)
        other["System"]["Provider"]["Name"] = "Unrelated-Provider"
        self.case.preserve(encode([row, other]), HOST_A, "test-export")
        result = analyze(self.case)
        self.assertEqual(result["summary"]["events"], 2)
        self.assertEqual(len(result["session_view"]["boundaries"]), 1)

    def test_equal_boundary_timestamp_is_not_ordered_by_event_id(self):
        tied = self.event(3, 2, {"LogonId": "0x42"})
        view = build_session_view([self.start(1, 1, "0x42"), self.boundary(2, 2, 4634), tied])
        member = next(m for m in view["events"] if m["event_id"] == tied["event_id"])
        self.assertEqual(member["status"], "ambiguous")
        self.assertEqual(member["reason_codes"], ["coincident_boundary"])

    def test_equivalent_time_offsets_produce_same_session_view(self):
        rows = [self.row(1, 1, {"TargetLogonId": "0x42"}, 4624), self.row(2, 2, {"LogonId": "0x42"})]
        offsets = copy.deepcopy(rows)
        offsets[0]["TimeCreated"] = "2026-10-30T16:01:00-04:00"
        offsets[1]["TimeCreated"] = "2026-10-30T21:02:00+01:00"
        expected = [normalize(self.case, row, self.case.binding(HOST_A), False) for row in rows]
        actual = [normalize(self.case, row, self.case.binding(HOST_A), False) for row in reversed(offsets)]
        self.assertEqual(build_session_view(expected), build_session_view(actual))

    def test_start_target_is_distinct_from_initiating_subject(self):
        event = self.start(1, 1, "0x42", SubjectLogonId="0x3e7")
        view = build_session_view([event])
        self.assertEqual([s["logon_id"] for s in view["sessions"]], ["66"])
        self.assertEqual(view["events"][0]["logon_ids"], ["66"])
        self.assertEqual({s["field"]: s["raw"] for s in view["events"][0]["source_logon_ids"]},
                         {"TargetLogonId": "0x42", "SubjectLogonId": "0x3e7"})

    def test_conflicting_subject_target_ids_are_ambiguous(self):
        event = self.event(3, 3, {"SubjectLogonId": "0x42", "TargetLogonId": "0x43"}, code=4688)
        view = build_session_view([self.start(1, 1, "0x42"), self.start(2, 2, "0x43"), event])
        member = next(m for m in view["events"] if m["event_id"] == event["event_id"])
        self.assertEqual(member["status"], "ambiguous")
        self.assertEqual(member["reason_codes"], ["conflicting_source_ids"])
        self.assertEqual(len(member["candidate_session_ids"]), 2)
        self.assertIsNone(member["session_id"])

    def test_subject_only_success_and_failure_do_not_create_new_session(self):
        events = [self.event(1, 1, {"SubjectLogonId": "0x42"}, code=4624),
                  self.event(2, 2, {"TargetLogonId": "0x43"}, code=4625)]
        view = build_session_view(events)
        self.assertEqual(view["sessions"], [])
        self.assertEqual(view["events"][0]["reason_codes"], ["missing_target_id"])
        self.assertEqual(view["summary"]["unlinked_events"], 2)

    def test_placeholder_ids_do_not_form_sessions(self):
        events = [self.start(1, 1, "0x0"), self.event(2, 2, {"LogonId": "-"}), self.event(3, 3, {})]
        view = build_session_view(events)
        self.assertEqual(view["summary"]["sessions"], 0)
        self.assertEqual(view["summary"]["unlinked_events"], 3)
        self.assertEqual(view["unbounded_id_groups"], [])

    def test_organization_and_simulation_are_separate_scopes(self):
        real = self.start(1, 1, "0x42")
        synthetic = self.start(2, 1, "0x42", simulation=True)
        other_org = copy.deepcopy(real)
        other_org.update(event_id="EVT-other-org", org_id="other")
        view = build_session_view([real, synthetic, other_org])
        self.assertEqual(view["summary"]["sessions"], 3)
        self.assertEqual(view["summary"]["ambiguous_events"], 0)

    def test_all_memberships_retain_raw_provenance_including_duplicate_and_unlinked(self):
        rows = [self.row(1, 1, {"TargetLogonId": "0x42"}, code=4624),
                self.row(2, 2, {}), self.row(2, 2, {})]
        self.case.preserve(encode(rows), HOST_A, "test-export")
        result = analyze(self.case)
        members = {m["event_id"]: m for m in result["session_view"]["events"]}
        for event in result["events"]:
            self.assertEqual(members[event["event_id"]]["references"], sorted(event["references"], key=encode))
        unlinked = next(m for m in members.values() if m["status"] == "unlinked")
        self.assertEqual(len(unlinked["references"]), 2)
        self.assertEqual(result["summary"]["duplicate_rows"], 1)

    def test_html_escapes_start_account_and_retains_event_links(self):
        row = self.row(1, 1, {"TargetLogonId": "0x42", "TargetUserName": '<script>alert("x")</script>'}, code=4624)
        self.case.preserve(encode([row]), HOST_A, "test-export")
        result = analyze(self.case)
        write_report(self.case, result)
        html = (self.root / "report.html").read_text(encoding="utf-8")
        self.assertIn('id="logon-sessions"', html)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn('href="#' + result["events"][0]["event_id"] + '"', html)
        self.assertEqual(json.loads((self.root / "sessions.json").read_text(encoding="utf-8")), result["session_view"])

    def test_cli_filter_keeps_full_saved_view_and_integrity_guard(self):
        for host in (HOST_A, HOST_B):
            self.case.preserve(encode([self.row(1, 1, {"TargetLogonId": "0x42"}, code=4624, host=host)]), host, "test-export")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(["sessions", "--root", str(self.root), "--client-id", HOST_A])
        self.assertEqual(status, 2)  # Missing coverage is still reported by the command status.
        view = json.loads(output.getvalue())
        self.assertEqual(view["summary"]["sessions"], 1)
        self.assertTrue(all(m["scope"]["client_id"] == HOST_A for m in view["events"]))
        self.assertEqual(json.loads((self.root / "sessions.json").read_text())["summary"]["sessions"], 2)
        before = (self.root / "sessions.json").read_bytes()
        entry = self.case.manifest()["artifacts"][0]
        (self.root / entry["path"]).write_bytes(b"tampered")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["sessions", "--root", str(self.root)]), 1)
        self.assertEqual((self.root / "sessions.json").read_bytes(), before)

    def test_session_command_obeys_case_lock(self):
        with case_lock(self.root), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["sessions", "--root", str(self.root)]), 1)


if __name__ == "__main__":
    unittest.main()
