"""Portable, escaped offline HTML plus JSON and spreadsheet-safe CSV."""
import csv
import stat
from html import escape

from .storage import CaseError, atomic_writer, save

REPORT_FILENAMES = ("timeline.json", "sessions.json", "timeline.csv", "report.html")


def validate_report_destinations(root):
    """Reject unexpected existing entries before replacing any report outputs."""
    for name in REPORT_FILENAMES:
        try:
            status = (root / name).lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(status.st_mode) or status.st_nlink > 1
                or getattr(status, "st_file_attributes", 0) & 0x400):
            raise CaseError("Report destination must be a regular file without aliases: " + name)


def csv_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text


def session_section(view):
    esc = lambda value: escape(str(value), quote=True)
    members = {event["event_id"]: event for event in view["events"]}

    def event_list(ids):
        return "<ul>" + "".join('<li><a href="#' + esc(eid) + '">' + esc(members[eid]["timestamp_utc"]) + " — " +
            esc(members[eid]["label"]) + "</a><br><small>Source fields: " + esc(source_fields(members[eid])) + "</small></li>" for eid in ids) + "</ul>"

    def source_fields(event):
        return ", ".join(source["field"] + "=" + source["raw"] for source in event["source_logon_ids"]) or "none"

    summary = view["summary"]
    html = '<section id="logon-sessions"><h2>Logon-session views</h2><p>' + esc(summary["sessions"]) + " observed starts · " + esc(summary["linked_events"]) + " ID-linked events · " + esc(summary["unlinked_events"]) + " unlinked · " + esc(summary["ambiguous_events"]) + ' ambiguous. <a href="sessions.json">Session JSON with source references</a></p>'
    html += "<ul>" + "".join("<li>" + esc(limit) + "</li>" for limit in view["limitations"]) + "</ul>"
    for session in view["sessions"]:
        scope = session["scope"]
        html += '<details id="' + esc(session["session_id"]) + '"><summary>' + esc(scope["hostname"]) + " / " + esc(scope["client_id"]) + " · logon " + esc(session["logon_id"]) + " · start " + esc(session["start_utc"]) + (" [SYNTHETIC]" if scope["simulation"] else "") + "</summary>"
        html += "<p>Account recorded by the start event: " + esc(session["start_account"] or "unavailable") + ". Logoff: " + esc(session["end_utc"] or "unavailable") + ". Association cutoff: " + esc(session["cutoff_utc"] or "unavailable") + ".</p>"
        if session["cutoff_event_id"]:
            html += '<p><a href="#' + esc(session["cutoff_event_id"]) + '">Boundary source event</a></p>'
        html += "<ul>" + "".join("<li>" + esc(limit) + "</li>" for limit in session["limitations"]) + "</ul>" + event_list(session["event_ids"]) + "</details>"
    for group in view["unbounded_id_groups"]:
        html += "<details><summary>Unbounded ID group: " + esc(group["scope"]["hostname"]) + " · " + esc(group["logon_id"]) + "</summary><p>This group does not establish a complete session.</p>" + event_list(group["event_ids"]) + "</details>"
    for status, title in (("ambiguous", "Ambiguous events"), ("unlinked", "Unlinked events")):
        events = [event for event in view["events"] if event["status"] == status]
        html += "<details><summary>" + title + " (" + str(len(events)) + ")</summary><ul>"
        for event in events:
            html += '<li><a href="#' + esc(event["event_id"]) + '">' + esc(event["timestamp_utc"]) + " · " + esc(event["scope"]["hostname"]) + " · " + esc(event["label"]) + "</a> — " + esc(" ".join(view["reason_descriptions"][reason] for reason in event["reason_codes"]))
            html += "<br><small>Source fields: " + esc(source_fields(event)) + "</small>"
            if event["candidate_session_ids"]:
                html += "<p>Possible starts: " + ", ".join('<a href="#' + esc(candidate) + '">' + esc(candidate) + "</a>" for candidate in event["candidate_session_ids"]) + "</p>"
            html += "</li>"
        html += "</ul></details>"
    return html + "</section>"


def write_report(case, result):
    validate_report_destinations(case.root)
    save(case.root / "timeline.json", result)
    save(case.root / "sessions.json", result["session_view"])
    fields = ["event_id", "timestamp_utc", "hostname", "channel", "event_code", "kind", "label", "account", "image", "command_line", "target", "simulation"]
    with atomic_writer(case.root / "timeline.csv", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(fields)
        writer.writerows([csv_cell(event.get(field)) for field in fields] for event in result["events"])
    esc = lambda value: escape(str(value), quote=True)
    findings = "".join("<li><strong>" + esc(f["title"]) + "</strong> — " + esc(f["interpretation"]) +
                       "<br><small>" + esc(f["rule"]) + ": " + ", ".join('<a href="#' + esc(eid) + '">' + esc(eid) + "</a>" for eid in f["event_ids"]) + "</small></li>" for f in result["findings"])
    gaps = "".join("<li>" + esc(gap.get("client_id", "")) + " " + esc(gap["reason"]) + "</li>" for gap in result["gaps"])
    rows = []
    for event in result["events"]:
        refs = " ".join('<a href="' + esc(ref["artifact"]) + '">raw ' + esc(ref["sha256"][:12]) + " row " + str(ref["row"]) + "</a>" for ref in event["references"])
        rows.append('<tr id="' + esc(event["event_id"]) + '"><td>' + esc(event["timestamp_utc"]) + "</td><td>" + esc(event["hostname"]) +
                    "</td><td>" + esc(event["label"]) + (" <b>[SYNTHETIC]</b>" if event["simulation"] else "") +
                    "<details><summary>Details and original evidence</summary><p>" + esc(event["channel"]) + " / " + esc(event["event_code"]) +
                    "</p><pre>" + esc(event["command_line"] or event["target"]) + "</pre><p>" + refs + "</p></details></td></tr>")
    summary = result["summary"]
    page = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>CrumbTrail case report</title><style>
body{font:16px system-ui,sans-serif;line-height:1.55;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#15273b;background:#f5f7fa}
h1,h2{color:#163a54}a{color:#075985}table{width:100%;border-collapse:collapse;background:white}td,th{padding:.7rem;text-align:left;vertical-align:top;border-bottom:1px solid #cbd5e1}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{overflow-wrap:anywhere}li{margin:.6rem 0}.table{overflow-x:auto}b{color:#9a3412}@media print{body{background:white}details{display:block}a{color:inherit}}
</style></head><body><h1>CrumbTrail</h1>'''
    page += "<p>Case <strong>" + esc(case.meta["case_id"]) + "</strong> · " + esc(case.meta["start"]) + " to " + esc(case.meta["end"]) + "</p>"
    page += "<p>" + esc(summary["events"]) + " events · " + esc(summary["findings"]) + " findings · " + esc(summary["gaps"]) + " coverage gaps</p>"
    page += "<p>" + esc(summary["unclassified_events"]) + " unclassified events. These retained events have no supported provider/channel/event interpretation; this count is separate from collection coverage gaps.</p>"
    page += "<p>Findings describe telemetry associations, not proof of encryption or compromise. Original raw bytes remain linked below. The local manifest is unsigned.</p>"
    page += '<p><a href="timeline.json">JSON evidence timeline</a> · <a href="timeline.csv">CSV timeline</a> · <a href="manifest.json">SHA-256 manifest</a></p>'
    page += "<h2>Coverage</h2><ul>" + (gaps or "<li>No reported gaps in the supplied selected-channel coverage.</li>") + "</ul>"
    page += "<p>Excluded outside the case window: " + esc(summary["excluded_outside_window"]) + "; deduplicated rows: " + esc(summary["duplicate_rows"]) + ".</p>"
    page += "<h2>Findings</h2><ul>" + (findings or "<li>No configured rule matched; this is not a clean-host verdict.</li>") + "</ul>"
    page += session_section(result["session_view"])
    page += '<h2>Timeline (UTC)</h2><div class="table"><table><thead><tr><th>UTC</th><th>Endpoint</th><th>Observation</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div></body></html>"
    with atomic_writer(case.root / "report.html", encoding="utf-8", newline="") as stream:
        stream.write(page)
