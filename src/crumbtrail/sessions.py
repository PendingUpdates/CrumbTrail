"""Conservative, source-ID-backed views of observed Windows logon sessions."""
from bisect import bisect_left, bisect_right

from .storage import digest, encode, ticks as timestamp
from .providers import event_classification, supported_kind, unclassified_label


LIMITATIONS = [
    "Membership is an explicit logon-ID association, not proof of an actor or causality.",
    "Only supported provider, channel and event ID combinations participate; unclassified events remain unlinked.",
    "Only supplied Security 4634 logoff and 4608 startup records with the Microsoft-Windows-Security-Auditing provider establish boundaries. Other or missing boundaries remain unknown.",
    "A startup marker stops earlier ID associations; it does not supply an exact prior-session logoff time.",
    "A logon ID may be reused outside the collected window. Host identity does not establish a boot identity.",
    "Events without a usable source logon ID are not linked through time, account names, process IDs, or process GUIDs.",
]
REASONS = {
    "unclassified_event": "This event has no supported provider/channel/event interpretation and does not establish session associations.",
    "missing_source_id": "No usable explicit source logon ID is present.",
    "missing_target_id": "The successful-logon event has no usable TargetLogonId; its subject ID is not a new-session boundary.",
    "conflicting_source_ids": "Distinct subject/target/logon IDs are present; no single session is selected.",
    "missing_start": "No successful-logon start for this explicit ID is present in the current boundary context.",
    "precedes_start": "This event precedes the only observed start; it is not assigned to that later session.",
    "repeated_starts": "The ID has multiple successful-logon starts on this host; no nearest-start attribution is made.",
    "startup_boundary": "This host startup marker is a scope boundary, not membership in one user session.",
    "unvalidated_boundary": "This potential boundary has no validated provider or target ID and is not used to establish an end or startup.",
    "coincident_boundary": "A boundary has the same timestamp; event ordering across it is not inferred.",
}


def scope_of(event):
    return {key: event[key] for key in ("org_id", "client_id", "hostname", "simulation")}


def scope_key(scope):
    return (scope["org_id"], scope["client_id"], scope["hostname"], scope["simulation"])


def event_key(event):
    return timestamp(event["timestamp_utc"]), event["event_id"]


def source_selection(event):
    """Keep source roles visible; 4624 target identifies the newly observed logon."""
    sources = event.get("source_logon_ids", [])
    kind = supported_kind(event)
    if kind is None:
        return sources, [], False
    is_start = kind == "logon.success"
    target_only = event["channel"] == "Security" and event["event_code"] in (4624, 4634)
    eligible = [source for source in sources if source.get("value") and
                (not target_only or source["field"] == "TargetLogonId")]
    values = sorted({source["value"] for source in eligible})
    return sources, values, is_start


class BoundaryIndex:
    """Index explicit host startup and ID-specific logoff cutoffs without guessing order."""
    def __init__(self, events):
        self.startups, self.logoffs, self.by_event = {}, {}, {}
        for event in events:
            _, values, _ = source_selection(event)
            if event["channel"] != "Security" or supported_kind(event) is None:
                continue
            code = event["event_code"]
            if code != 4608 and not (code == 4634 and len(values) == 1):
                continue
            scope = scope_of(event)
            marker = dict(event_id=event["event_id"], timestamp_utc=event["timestamp_utc"], scope=scope,
                          kind="startup" if code == 4608 else "logoff",
                          logon_id=values[0] if code == 4634 else None,
                          references=sorted(event["references"], key=encode))
            self.by_event[event["event_id"]] = marker
            mapping = self.startups if code == 4608 else self.logoffs
            key = scope_key(scope) if code == 4608 else (*scope_key(scope), values[0])
            mapping.setdefault(key, []).append(marker)
        for mapping in (self.startups, self.logoffs):
            for key, markers in mapping.items():
                markers.sort(key=lambda item: (timestamp(item["timestamp_utc"]), item["event_id"]))
                mapping[key] = ([timestamp(item["timestamp_utc"]) for item in markers], markers)

    def neighbors(self, scope, logon, at):
        before, after, coincident = [], [], False
        for times, markers in (self.startups.get(scope_key(scope), ([], [])),
                               self.logoffs.get((*scope_key(scope), logon), ([], []))):
            left, right = bisect_left(times, at), bisect_right(times, at)
            if left:
                before.append(markers[left - 1])
            if right < len(times):
                after.append(markers[right])
            coincident = coincident or left != right
        order = lambda marker: (timestamp(marker["timestamp_utc"]), marker["event_id"])
        return (max(before, key=order) if before else None,
                min(after, key=order) if after else None, coincident)


def context_key(scope, logon, before):
    return (*scope_key(scope), logon, before["event_id"] if before else "")


def build_session_view(events):
    """Return deterministic membership without changing events or their references.

    Successful logons remain separate start anchors even when they share an ID.
    Other events with that reused ID remain ambiguous. IDs with no start are
    unbounded ID groups, never asserted to be one complete session.
    """
    ordered = sorted(events, key=event_key)
    boundaries = BoundaryIndex(ordered)
    anchors, selections = {}, {}
    for event in ordered:
        sources, values, is_start = source_selection(event)
        scope = scope_of(event)
        selections[event["event_id"]] = sources, values, is_start, scope
        if is_start and len(values) == 1:
            before, _, coincident = boundaries.neighbors(scope, values[0], timestamp(event["timestamp_utc"]))
            if not coincident:
                anchors.setdefault(context_key(scope, values[0], before), []).append(event)

    sessions, by_anchor = [], {}
    for key in sorted(anchors):
        for event in anchors[key]:
            scope = scope_of(event)
            before, after, _ = boundaries.neighbors(scope, key[-2], timestamp(event["timestamp_utc"]))
            limitations = ["An explicit ID association does not prove actor attribution or full source retention."]
            if not after:
                limitations.append("End boundary is unavailable.")
            elif after["kind"] == "startup":
                limitations.append("A startup cutoff is observed; the exact preceding logoff time remains unknown.")
            if not before or before["kind"] != "startup":
                limitations.append("A preceding startup marker for this ID context is unavailable.")
            if len(anchors[key]) > 1:
                limitations.append("This host/logon ID has multiple start records; nonboundary events remain ambiguous.")
            status = "logoff_observed" if after and after["kind"] == "logoff" else "startup_cutoff" if after else "start_observed_end_missing"
            session = dict(session_id="SESSION-" + digest(encode([scope, key[-2], event["event_id"]]))[:20],
                           scope=scope, logon_id=key[-2], start_event_id=event["event_id"],
                           start_utc=event["timestamp_utc"], start_account=event["account"],
                           end_utc=after["timestamp_utc"] if after and after["kind"] == "logoff" else None,
                           end_event_id=after["event_id"] if after and after["kind"] == "logoff" else None,
                           cutoff_utc=after["timestamp_utc"] if after else None,
                           cutoff_event_id=after["event_id"] if after else None,
                           context_after_event_id=before["event_id"] if before else None,
                           boundary_status="repeated_start_id" if len(anchors[key]) > 1 else status,
                           event_ids=[], limitations=limitations)
            sessions.append(session)
            by_anchor[event["event_id"]] = session

    memberships, unbounded = [], {}
    for event in ordered:
        sources, values, is_start, scope = selections[event["event_id"]]
        classification = event_classification(event)
        supported = classification["status"] == "supported"
        member = dict(event_id=event["event_id"], timestamp_utc=event["timestamp_utc"],
                      label=event["label"] if supported else unclassified_label(event["channel"], event["event_code"], classification),
                      kind=event["kind"] if supported else "event", classification=classification, scope=scope,
                      source_logon_ids=sources, logon_ids=values, status="unlinked",
                      session_id=None, candidate_session_ids=[], reason_codes=[],
                      references=sorted(event["references"], key=lambda ref: encode(ref)))
        marker = boundaries.by_event.get(event["event_id"])
        member["boundary_kind"] = marker["kind"] if marker else None
        possible_boundary = event["channel"] == "Security" and (event["event_code"] in (4608, 4634) or
            (event["event_code"] == 4624 and not is_start))
        if not supported:
            member["reason_codes"] = ["unclassified_event"]
        elif marker and marker["kind"] == "startup":
            member["reason_codes"] = ["startup_boundary"]
        elif possible_boundary and not marker:
            member["reason_codes"] = ["unvalidated_boundary"]
        elif not values:
            member["reason_codes"] = ["missing_target_id" if is_start else "missing_source_id"]
        elif len(values) > 1:
            member["status"] = "ambiguous"
            member["reason_codes"] = ["conflicting_source_ids"]
            member["candidate_session_ids"] = sorted({by_anchor[anchor["event_id"]]["session_id"]
                for value in values for anchor in anchors.get(context_key(scope, value,
                    boundaries.neighbors(scope, value, timestamp(event["timestamp_utc"]))[0]), [])})
        else:
            before, _, coincident = boundaries.neighbors(scope, values[0], timestamp(event["timestamp_utc"]))
            key = context_key(scope, values[0], before)
            starts = anchors.get(key, [])
            if coincident and not marker:
                member.update(status="ambiguous", reason_codes=["coincident_boundary"])
            elif is_start:
                session = by_anchor[event["event_id"]]
                member.update(status="linked", session_id=session["session_id"])
                session["event_ids"].append(event["event_id"])
            elif len(starts) > 1:
                member.update(status="ambiguous", reason_codes=["repeated_starts"],
                              candidate_session_ids=[by_anchor[start["event_id"]]["session_id"] for start in starts])
            elif starts and timestamp(event["timestamp_utc"]) >= timestamp(starts[0]["timestamp_utc"]):
                session = by_anchor[starts[0]["event_id"]]
                member.update(status="linked", session_id=session["session_id"])
                session["event_ids"].append(event["event_id"])
            else:
                reason = "precedes_start" if starts else "missing_start"
                member["reason_codes"] = [reason]
                group = unbounded.setdefault(key, dict(group_id="IDGROUP-" + digest(encode([scope, values[0], key[-1]]))[:20],
                    scope=scope, logon_id=values[0], context_after_event_id=key[-1] or None, event_ids=[], limitations=[]))
                group["event_ids"].append(event["event_id"])
                if REASONS[reason] not in group["limitations"]:
                    group["limitations"].append(REASONS[reason])
        memberships.append(member)
    sessions.sort(key=lambda item: (scope_key(item["scope"]), timestamp(item["start_utc"]), item["session_id"]))
    return dict(schema=1, policy="explicit-source-logon-ids", limitations=LIMITATIONS.copy(),
                reason_descriptions=REASONS.copy(), sessions=sessions,
                boundaries=sorted(boundaries.by_event.values(), key=lambda item: (timestamp(item["timestamp_utc"]), item["event_id"])),
                unbounded_id_groups=[unbounded[key] for key in sorted(unbounded)], events=memberships,
                summary=dict(sessions=len(sessions), linked_events=sum(m["status"] == "linked" for m in memberships),
                             unlinked_events=sum(m["status"] == "unlinked" for m in memberships),
                             ambiguous_events=sum(m["status"] == "ambiguous" for m in memberships),
                             unbounded_id_groups=len(unbounded), events=len(memberships)))
