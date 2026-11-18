"""Windows-only interpretation; adapted from the MIT BEC event rules."""
import re
from datetime import datetime, timedelta, timezone
from pathlib import PureWindowsPath

from .storage import CaseError, LOGS, digest, encode, iso, records, row_type, timestamp, ticks, iso_ticks, TICKS_PER_SECOND
from .providers import classify, supported_kind, unclassified_label


def guid(value):
    value = str(value or "").casefold().strip("{}")
    return value if re.fullmatch(r"[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", value) and value.replace("-", "").strip("0") else ""


def logon_id(value):
    try:
        value = str(value)
        number = int(value, 16 if value.lower().startswith("0x") else 10)
        return str(number) if number > 0 else ""
    except ValueError:
        return ""


def process_kind(image, command):
    if PureWindowsPath(image).name.casefold() in ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe") and re.search(r"delete\s+(shadows|shadowstorage|catalog)|shadowcopy.*delete|recoveryenabled\s+no", command, re.I):
        return "recovery"
    return "process"


def event_time(row, system):
    """Prefer the native event time over the artifact's formatted display time."""
    created = system.get("TimeCreated")
    native = created.get("SystemTime") if isinstance(created, dict) else created
    value = native if native is not None else row.get("TimeCreated")
    source = "System.TimeCreated.SystemTime" if native is not None and isinstance(created, dict) else "System.TimeCreated" if native is not None else "TimeCreated"
    if type(value) in (int, float):
        try:
            parsed = datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, OverflowError, OSError) as exc:
            raise CaseError("Invalid native event Unix timestamp.") from exc
    else:
        return value, iso_ticks(ticks(value)), source
    return value, iso(parsed), source


def normalize(case, row, bound, simulation, exact=None):
    system = row.get("System") or {}
    if not isinstance(system, dict):
        raise CaseError("Windows System must be an object.")
    host = str(system.get("Computer") or row.get("Computer") or "").casefold()
    if host != bound["hostname"]:
        raise CaseError("Event hostname differs from the bound endpoint.")
    channel = str(row.get("Channel") or system.get("Channel") or "")
    if channel not in LOGS:
        raise CaseError("Unsupported event channel: " + channel)
    provider = system.get("Provider") or row.get("Provider") or ""
    provider = str(provider.get("Name") or "") if isinstance(provider, dict) else str(provider)
    code = row.get("EventID", system.get("EventID"))
    if isinstance(code, dict):
        code = code.get("Value")
    try:
        code = int(code)
    except (ValueError, TypeError) as exc:
        raise CaseError("Event ID must be numeric.") from exc
    data = row.get("EventData") or row.get("UserData") or {}
    if isinstance(data, dict) and isinstance(data.get("LogFileCleared"), dict):
        data = data["LogFileCleared"]
    if not isinstance(data, dict):
        raise CaseError("Windows event data must be an object.")
    at, utc, time_source = event_time(row, system)
    if exact is not None:
        utc = iso_ticks(int(exact["filetime_ticks"]))
    image = str(data.get("Image") or data.get("NewProcessName") or "")
    command = str(data.get("CommandLine") or data.get("ProcessCommandLine") or "")
    target = str(data.get("TargetFilename") or data.get("ImagePath") or data.get("Path") or image or data.get("TaskName") or "")
    account = str(data.get("User") or data.get("TargetUserName") or data.get("SubjectUserName") or "")
    domain = data.get("TargetDomainName") or data.get("SubjectDomainName")
    if domain and account and "\\" not in account and "@" not in account:
        account = str(domain) + "\\" + account
    classification = classify(channel, provider, code)
    supported = classification["status"] == "supported"
    kind, label = "event", f"{channel} event {code}"
    if not supported:
        label = unclassified_label(channel, code, classification)
    elif channel == "Security" and code in (4624, 4625):
        kind = "logon.success" if code == 4624 else "logon.failure"
        label = "Windows logon " + ("succeeded" if code == 4624 else "failed")
    elif (channel == LOGS[2] and code == 1) or (channel == "Security" and code == 4688):
        kind, label = "process", "Process started: " + PureWindowsPath(image).name
    elif channel == LOGS[2] and code in (11, 15):
        kind, label = "file", "File created: " + PureWindowsPath(target).name
    elif channel == LOGS[2] and code == 3:
        kind, label = "network", "Process network connection"
    elif (channel == "System" and code == 7045) or (channel == "Security" and code == 4697):
        kind, label = "service", "Service installed: " + str(data.get("ServiceName", ""))
    elif channel == "Security" and code == 4698:
        kind, label = "task", "Scheduled task registered: " + str(data.get("TaskName", ""))
    elif (channel == "Security" and code == 1102) or (channel == "System" and code == 104):
        kind, label = "log.clear", "Windows event log cleared"
    elif channel == LOGS[3] and code == 4104:
        kind, label = "script", "PowerShell script block recorded"
    elif channel == LOGS[4] and code in (1116, 1117):
        kind, label = "detection", "Defender " + ("threat detection" if code == 1116 else "action recorded")
    if kind == "process" and process_kind(image, command) == "recovery":
        kind, label = "recovery", "Recovery suppression command observed"
    hashes = str(data.get("Hashes") or data.get("Hash") or "")
    match = re.search(r"(?:^|[,;\s])SHA256=([a-f0-9]{64})(?:$|[,;\s])", hashes, re.I)
    sha = match.group(1).lower() if match else hashes.lower() if re.fullmatch(r"[a-fA-F0-9]{64}", hashes) else None
    record_id = row.get("EventRecordID", system.get("EventRecordID"))
    identity = [case.meta["case_id"], bound, channel, code, record_id, utc, data, simulation]
    if provider:
        identity.append({"provider": provider})
    source_logon_ids = [dict(field=field, raw=str(data[field]), value=logon_id(data[field]))
                        for field in ("LogonId", "TargetLogonId", "SubjectLogonId") if field in data]
    if not supported:
        account = image = command = target = ""
        sha = None
    return dict(event_id="EVT-" + digest(encode(identity))[:24], timestamp_utc=utc,
                timestamp_original=at, client_id=bound["client_id"], org_id=bound["org_id"],
                timestamp_source=time_source,
                timestamp_precision="evtx-systemtime-100ns" if exact is not None else "native-float-microsecond" if type(at) in (int, float) else "iso-supplied",
                hostname=host, channel=channel, event_code=code, record_id=record_id,
                provider=provider, classification=classification,
                kind=kind, label=label, account=account.casefold(), image=image, command_line=command,
                target=target, process_guid=guid(data.get("ProcessGuid")) if supported else "",
                parent_process_guid=guid(data.get("ParentProcessGuid")) if supported else "",
                logon_id=logon_id(data.get("LogonId") or data.get("TargetLogonId") or data.get("SubjectLogonId")) if supported else "",
                source_logon_ids=source_logon_ids,
                sha256=sha, simulation=simulation, references=[], finding_ids=[])


def correlate(events, session_view=None):
    # Retain the optional argument for API compatibility, but rebuild context:
    # a cached view may predate provider validation or omit a current boundary.
    from .sessions import build_session_view
    return _correlate(events, build_session_view(events))


def _correlate(events, session_view):
    """Correlate against a session view freshly built from these complete events."""
    by_id = {event["event_id"]: event for event in events}
    starts = {session["session_id"]: by_id[session["start_event_id"]]
              for session in session_view["sessions"]
              if supported_kind(by_id[session["start_event_id"]]) == "logon.success"}
    linked_starts = {member["event_id"]: starts[member["session_id"]]
                     for member in session_view["events"]
                     if member["status"] == "linked" and member["session_id"] in starts}
    findings, processes, files, bursts = [], {}, {}, set()

    def emit(rule, title, chain, interpretation, suspicious=False):
        ids = [event["event_id"] for event in chain]
        finding_id = "F-" + digest(encode([rule, ids]))[:16]
        findings.append(dict(finding_id=finding_id, rule=rule, title=title,
                             event_ids=ids, interpretation=interpretation,
                             assessment="suspicious" if suspicious else "contextual"))
        for event in chain:
            event["finding_ids"].append(finding_id)

    for event in sorted(events, key=lambda item: (ticks(item["timestamp_utc"]), item["event_id"])):
        kind = supported_kind(event)
        if kind is None:
            continue
        if kind == "process":
            kind = process_kind(event["image"], event["command_line"])
        at = ticks(event["timestamp_utc"])
        host = (event["org_id"], event["client_id"], event["simulation"])
        key = (*host, event["process_guid"])
        if kind in ("process", "recovery") and event["process_guid"]:
            processes[key] = event
            login = linked_starts.get(event["event_id"])
            if login and 0 < at - ticks(login["timestamp_utc"]) <= 1800 * TICKS_PER_SECOND:
                emit("logon-process", "Logon followed by process execution", [login, event],
                     "The same endpoint and logon ID occur within 30 minutes; this is contextual association.")
        if kind == "recovery":
            parent = processes.get((*host, event["parent_process_guid"]))
            chain = [parent, event] if parent and 0 < at - ticks(parent["timestamp_utc"]) <= 1800 * TICKS_PER_SECOND else [event]
            emit("recovery-suppression", "Recovery suppression command observed", chain,
                 "Command-line telemetry records an attempt. Verify its effect; this does not prove recovery data was changed.", True)
        if kind == "file" and event["process_guid"]:
            recent = files.setdefault(key, [])
            recent[:] = [item for item in recent if at - ticks(item["timestamp_utc"]) <= 120 * TICKS_PER_SECOND]
            recent.append(event)
            paths = {item["target"].casefold() for item in recent}
            note = any(re.search(r"readme.*recover|how.*recover|ransom.*note", path, re.I) for path in paths)
            if note and len(paths) >= 6 and key not in bursts:
                parent = processes.get(key)
                chain = ([parent] if parent and 0 <= at - ticks(parent["timestamp_utc"]) <= 1800 * TICKS_PER_SECOND else []) + recent
                emit("file-burst", "Rapid file creation with a recovery-note filename", chain,
                     "At least six distinct paths share one process within two minutes. File contents must be examined to establish encryption.", True)
                bursts.add(key)
    return findings


def analyze(case):
    from .sessions import build_session_view
    from .precision import load_precision

    case.verify()
    unique, gaps, raw_events, excluded = {}, [], 0, 0
    manifest = case.manifest()
    if not case.meta["endpoints"]:
        gaps.append(dict(reason="No endpoint is bound."))
    sources = set()
    for entry in sorted(manifest["artifacts"], key=lambda e: e["sha256"]):
        provenance = entry["provenance"]
        bound = case.binding(provenance["client_id"])
        exact_rows = load_precision(case, entry)
        sources.add(bound["client_id"])
        coverage, counts = {}, {}
        for index, row in enumerate(records((case.root / entry["path"]).read_bytes()), 1):
            if row_type(row) == "coverage":
                coverage[row["LogChannel"]] = row
                continue
            exact = exact_rows.get(index)
            event = normalize(case, row, bound, provenance["simulation"], exact=exact)
            raw_events += 1
            counts[event["channel"]] = counts.get(event["channel"], 0) + 1
            if not ticks(case.meta["start"]) <= ticks(event["timestamp_utc"]) <= ticks(case.meta["end"]):
                excluded += 1
                continue
            target = unique.setdefault(event["event_id"], event)
            target["references"].append(dict(artifact=entry["path"], sha256=entry["sha256"], row=index,
                                             source_log=row.get("OSPath"), provenance=provenance,
                                             timestamp_source=event["timestamp_source"], timestamp_original=event["timestamp_original"]))
            if exact is not None:
                target["references"][-1]["exact_time"] = exact
        for channel in LOGS:
            row = coverage.get(channel)
            reason = None
            if not row or not row["Files"]:
                reason = channel + " coverage unavailable."
            elif row["AtLimit"]:
                reason = channel + " reached the collection row limit."
            elif row["Events"] != counts.get(channel, 0):
                reason = channel + " coverage count differs from supplied result rows."
            if reason:
                gaps.append(dict(client_id=bound["client_id"], artifact=entry["path"], reason=reason))
    for client_id in case.meta["endpoints"]:
        if client_id not in sources:
            gaps.append(dict(client_id=client_id, reason="No result source imported for this endpoint."))
    # ISO strings can have differing fractional precision; use actual UTC time.
    events = sorted(unique.values(), key=lambda e: (ticks(e["timestamp_utc"]), e["event_id"]))
    session_view = build_session_view(events)
    findings = _correlate(events, session_view)
    return dict(schema=1, tool="CrumbTrail", case=case.meta, events=events, findings=findings, gaps=gaps,
                session_view=session_view,
                summary=dict(events=len(events), findings=len(findings), gaps=len(gaps), artifacts=len(manifest["artifacts"]),
                             raw_event_rows=raw_events, excluded_outside_window=excluded,
                             duplicate_rows=raw_events - excluded - len(events),
                             unclassified_events=sum(event["classification"]["status"] != "supported" for event in events)))
