# CrumbTrail

![CrumbTrail endpoint investigation banner](assets/CrumbTrail-Banner.gif)

Independent Windows event triage with original-byte preservation, a UTC timeline, logon-session views, and an offline report. CrumbTrail 0.3.0 reads supplied native Velociraptor JSON/JSONL event exports or parses an explicitly supplied directory of exported EVTX files with exact source timestamps. Use `import` and `local` for supplied real evidence, and `demo` and `lab` for synthetic fixtures. It needs no email account, cloud connector, sibling repository, or shared evidence engine.

The Python package is `crumbtrail`, the distribution is `crumbtrail-ir`, and the CLI is `crumbtrail`. Python 3.11 or newer is required. The base offline workflow uses only the standard library. `local` additionally requires the optional `evtx` extra, pinned to `python-evtx==0.8.1`; no parser dependency is required to verify or analyze a completed case. Velociraptor is required for `lab` and `local`.

CrumbTrail interprets only supported combinations of channel, explicit provider name and event ID. Provider names are matched case-insensitively while their supplied text remains preserved. Missing, unknown or unsupported combinations remain visible as **unclassified** events with a reason; they do not establish sessions, boundaries or findings. A recognized provider name selects a supported schema, not an authenticated publisher. Rebuilding an older providerless case can therefore remove previous derived associations without changing its original bytes, event IDs, timestamps or references.

## Permissions and access

CrumbTrail does not authenticate to Microsoft Graph, Exchange Online, Google Workspace/GAM or Active Directory. It needs no OAuth scopes, application consent, tenant roles, domain credentials or Domain Admin membership for its implemented workflows. A bound client ID, organization and hostname are provenance labels, not authentication.

| Operation | Required local access | External access/execution |
| --- | --- | --- |
| `create`, `demo` | Create/write permission in a new or empty case directory; read the installed package/fixture | None; `demo` analyzes synthetic data |
| `bind`, `import`, `analyze`, `sessions` | Read case metadata/evidence; write the case lock and relevant case files/reports; `import` also needs read access to the supplied JSON/JSONL export | No endpoint or cloud connection |
| `verify` | Read case metadata, registered raw files and precision sidecars; write access to the case lock file | Does not open recorded external source paths or invoke Velociraptor; it is not a strictly read-only filesystem operation because of locking |
| `lab` | Read/execute an approved Velociraptor binary and read the bundled fixture; create/write case and diagnostic files | Executes local VQL over synthetic data with the caller's token |
| `local` | Read/traverse the explicit exported-EVTX directory and selected files; read/execute the approved Velociraptor binary; write case/diagnostics; installed optional exact parser | Executes Velociraptor and a Python parser subprocess locally; no automatic elevation or remote API connection |

A normal account with these filesystem and execution permissions is sufficient for offline evidence analysis; administrator/root privileges are not inherently required. Keep originals separate and grant output access only to authorized investigators. The source is read for analysis, but case manifests, raw copies, reports, locks and diagnostics are written locally. Source preservation does not mean zero filesystem writes. See the implemented [CLI](src/crumbtrail/cli.py), [case locking/storage](src/crumbtrail/storage.py) and [native runner](src/crumbtrail/native.py).

### Obtaining Windows evidence is a separate permission boundary

CrumbTrail's `import` consumes an existing export; it does not obtain Windows channel access for you. Its `local` command parses supplied files, rather than exporting live event channels. An authorized evidence custodian must first obtain the evidence with an approved collection/export method.

For Windows Event Log API access, evaluate the operator/service token against each source channel's effective read permissions and policy. The channels used here are **Security**, **System**, **Microsoft-Windows-Sysmon/Operational**, **Microsoft-Windows-PowerShell/Operational**, and **Microsoft-Windows-Windows Defender/Operational**. Do not assume that membership in Event Log Readers grants every channel, or that one successful channel proves the other four are readable. Security-log access deserves separate verification; privilege requirements depend on the acquisition API and policy. Microsoft's legacy Event Logging API documents `SeSecurityPrivilege` for Security-log access, but this is not a blanket requirement for parsing an already-exported `Security.evtx`. Do not grant that broad privilege solely to run offline CrumbTrail. [Windows event-log access rights](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/set-event-log-security-locally-or-via-group-policy), [legacy Security-log privilege distinction](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging-security).

Reading an exported EVTX file instead requires access to that file and its containing directories; live channel access and exported-file ACLs are different checks. A custodian's export also needs an authorized writable destination. Missing files, denied access, disabled telemetry or incomplete retention are limitations to record, not reasons to clear logs, change channel ACLs, enable privileges or elevate automatically. Windows provides separate read/query, export and configuration operations; only use operations approved for the collection. [Microsoft wevtutil reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).

The packaged [WindowsTriage artifact](src/crumbtrail/data/Custom.CrumbTrail.WindowsTriage.yaml) is a Windows client artifact with an empty `LogDirectory` default and a nonblank-path precondition. It invokes `Artifact.Windows.EventLogs.Evtx` on the five explicitly named files under that directory. This is not a sandbox: an explicitly supplied live-log path would still be subject to that execution identity's access and must not be substituted for an authorized export. Direct artifact use in an existing Velociraptor deployment requires that deployment's separate artifact/collection authorization and the client's actual file permissions; CrumbTrail supplies neither server credentials nor deployment rights. Code inspection verifies these controls, not their runtime acceptance on every deployment. Review [validation limits](docs/validation.md) before native use.

## Install and try

See [prerequisites and platform-specific setup](docs/prerequisites.md) for isolated environments, optional EVTX dependencies and native Windows limitations.

From this repository:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m crumbtrail demo --root .\cases\demo
```

Open `cases/demo/report.html`. The CLI equivalent in an activated environment is `crumbtrail demo --root ./cases/demo`. Use a new directory for every demo/lab run; existing cases are never overwritten.

The original providerless fixture is unchanged. Its expected result is now **21 retained events, 21 unclassified events, zero findings, one duplicate row and zero collection-coverage gaps**. It contains 22 event rows and five coverage rows. Missing provider information is not a clean-host result. All derived events remain synthetic, and no command text is executed.

The legacy demo's session view has zero observed starts and 21 unlinked events. The separately authored `data/windows-providers.jsonl` synthetic fixture supplies documented provider names and retains positive regression coverage: 21 events, four findings from three rule types, one start, three linked events and 18 unlinked events. Its bytes and derived IDs differ from the legacy fixture by design; providers are never backfilled into imported evidence. A process GUID does not supply a missing logon ID.

## Native inert lab

Use an independently obtained Windows x64 Velociraptor executable:

```powershell
python -m crumbtrail lab --root .\cases\native-lab `
  --velociraptor C:\IRTools\velociraptor.exe
```

This executes the real VQL engine against the unchanged providerless JSONL fixture through `Custom.CrumbTrail.LabReplay`, then preserves its original stdout bytes. It does not load a driver, read live RAM/disks, or collect current-host logs. With the current provider policy, the expected interpretation is 21 unclassified events, zero findings and zero collection-coverage gaps; native replay has not been rerun under this provider policy. `collection/run-*/` retains the collector request, stdout, stderr, executable SHA-256, and result. The supplied executable runs with the caller's current token; no automatic elevation is requested.

## Bring real event evidence

Create a case and bind the exact endpoint hostname represented by the records. The client ID and organization are provenance supplied by the operator; an offline import cannot independently confirm them against a server.

```powershell
crumbtrail create --root D:\Cases\example --case-id CT-EXAMPLE `
  --start 2026-11-01T00:00:00Z --end 2026-11-02T00:00:00Z
crumbtrail bind --root D:\Cases\example --client-id C.0123456789abcdef `
  --hostname workstation.example.test --org root
crumbtrail import --root D:\Cases\example --client-id C.0123456789abcdef `
  --file D:\Exports\windows.jsonl
```

Import accepts UTF-8 JSON arrays or JSONL from the bundled `Custom.CrumbTrail.WindowsTriage` artifact, including its coverage rows. The original legacy `BECRowType` marker is accepted for compatible older exports; new artifacts use `CrumbTrailRowType`. Add `--simulation` only for synthetic exports. `import` does not directly accept binary EVTX, ZIP collectors, arbitrary vendor JSON, disk images, or RAM dumps.

For exported EVTX files, install the exact-parser extra from this checkout, then use local native parsing:

```powershell
python -m pip install ".[evtx]"
crumbtrail local --root D:\Cases\example --client-id C.0123456789abcdef `
  --velociraptor C:\IRTools\velociraptor.exe --log-directory D:\Exports\Logs
```

Expected filenames are `Security.evtx`, `System.evtx`, `Microsoft-Windows-Sysmon%4Operational.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx`, and `Microsoft-Windows-Windows Defender%4Operational.evtx`. Missing files remain coverage gaps. A log directory is mandatory; the CLI never silently falls back to current-host logs. Native results retain selected IDs from a slightly expanded candidate window; final timeline inclusion uses exact integer source time against the inclusive case window. The selected IDs are `1`, `3`, `11`, `15`, `104`, `1102`, `1116`, `1117`, `4104`, `4624`, `4625`, `4688`, `4697`, `4698`, and `7045`; interpretation also checks the channel.

The [bounded EVTX lab runner](docs/evtx-lab.md) compares this actual native path with independent Windows `Get-WinEvent -Path` using separate private copies. System and all 181 selected Security events now agree exactly at 100 ns resolution: **maximum timestamp difference 0 ns**, with the existing 1,000 ns acceptance gate unchanged. Real single-tick inclusive and adjacent exclusion tests pass. The wider W2 channel/OS/responder matrix remains open; no public EVTX data or private event records are bundled.

Exact local parsing reads the BinXML `Event/System/TimeCreated/@SystemTime` FILETIME substitution and binds its bytes to the source hash, record/field offsets, XML identity and original native result row. It does not substitute record-header time or Windows-oracle results. Ambiguous/missing matches, changed sources, unsupported parser versions and malformed nonzero chunks fail the operation. See [exact-time design and compatibility](docs/exact-time.md).

The WindowsTriage artifact now has an empty `LogDirectory` default and a nonblank-path precondition, including when run directly in Velociraptor. An omitted/blank path does not fall back to current-host logs. Operators must supply an authorized exported-log directory; this guard is not a filesystem sandbox and does not certify the provenance of a supplied directory. The local CLI rejects empty or whitespace-only directory text before converting it to a path, and checks that the supplied directory exists. An explicit `.` remains an intentional directory choice; nonblank path text is not stripped.

The Python native wrapper also rejects blank raw directory text. Callers must validate text before constructing a `Path`: Python has already converted `Path("")` into `Path(".")`, so the wrapper cannot recover whether that object originated from empty text.

The two artifact YAML files are packaged under `src/crumbtrail/data`. They may be installed in an existing Velociraptor deployment using its normal artifact management, then the full unnamed source can be exported for `import`. **Version 0.2 has no remote API client, artifact installer, server provisioning, remote scheduling, pagination, or collection resume command.** Do not treat a local lab pass as validation of a server deployment. [Velociraptor server API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/)

## Logon-session views

```powershell
crumbtrail sessions --root D:\Cases\example
crumbtrail sessions --root D:\Cases\example --client-id C.0123456789abcdef
```

The command verifies original evidence under the case lock, rebuilds the full report, and prints JSON for all hosts or the requested bound client. Filtering affects printed output only; saved case reports remain complete. `analyze`, `import`, `demo`, and `lab` also build the view automatically. Open **Logon-session views** in `report.html`, inspect `sessions.json`, or read `timeline.json`'s additive `session_view` field. The timeline CSV column schema remains unchanged.

Views use valid explicit `LogonId`, `TargetLogonId`, and `SubjectLogonId` fields from supported provider/channel/event combinations, scoped by organization, client ID, hostname, and simulation status. The raw field name/value and normalized numeric ID stay visible. A supported Security 4624 start uses its **TargetLogonId**; its initiating subject ID does not become the new session. Providerless and unsupported records remain unclassified and unlinked, with their references retained. Other supported events containing distinct usable IDs remain ambiguous; no account, process GUID, process ID, or nearby timestamp supplies a missing ID.

Repeated starts with the same ID in one boundary context remain separate observed-start views. Their other ID-matching events stay ambiguous; the tool does not choose the closest start. Events preceding the only observed start remain unlinked. An ID without a start forms an explicitly unbounded ID group, which is not asserted to be a single complete session. Every linked, unlinked, and ambiguous event retains its original raw references. Boundary/source limitations do not remove the event from the main timeline.

Supplied Security **4634** records close their `TargetLogonId` context only when the provider is `Microsoft-Windows-Security-Auditing`. Microsoft distinguishes completed session termination from a 4647 logoff request and notes that IDs can be reused after reboot. [Microsoft 4634 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)

Supplied Security **4608** records with that same provider establish a conservative startup cutoff for the host. A same-ID event after a logoff or startup cannot link to an earlier start without a new start record. A startup cutoff does not invent an exact preceding logoff time. Events sharing a boundary's exact timestamp remain ambiguous because ordering is unknown. [Microsoft 4608 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4608)

Missing/unrecognized providers do not establish these logoff/startup boundaries. Other markers, boot IDs, and inferred boundaries are not supported. **The bundled native artifact's selected IDs are unchanged and do not collect 4634 or 4608**; boundary handling applies when those records are already present in an imported native export. Where boundaries are absent, end time and boot context remain explicitly unknown. Views describe source-ID associations, not actor attribution or complete-session reconstruction.

## Evidence and interpretation

Each case contains:

| File | Purpose |
| --- | --- |
| `case.json` | Case ID, explicit incident window, immutable endpoint bindings |
| `raw/<sha256>.json` | Exact original imported bytes, including duplicates and out-of-window rows |
| `precision/<sha256>.json` | Verified native EVTX timestamp sidecar: exact FILETIME bytes, source/record hashes, byte offsets and raw-row bindings |
| `manifest.json` | Original hash, byte/row count, source, endpoint/organization, simulation flag, and provenance checksum |
| `timeline.json` | Normalized events, per-row raw references, findings, coverage gaps, and counts |
| `sessions.json` | Observed starts, explicit boundaries, source-ID membership, unbounded groups, and unlinked/ambiguous events with raw references |
| `timeline.csv` | Portable event table with spreadsheet-formula neutralization |
| `report.html` | Self-contained offline report with escaped evidence text and local raw links |
| `collection/run-*/` | Native execution request/stdout/stderr diagnostics, when applicable |

Report generation checks the four derived-output destinations before writing and accepts only absent paths or ordinary single-link files. Each JSON, CSV and HTML file is written to an exclusive temporary file, flushed, and replaced after that file is complete. A failed write before replacement retains the previous complete file. Replacement is per file, not a transaction across all four reports; after an interrupted regeneration, rerun analysis before handing off the report set.

Every retained raw event reference includes the original artifact hash and its one-based row number in the parsed result sequence. Duplicate events share one timeline event while retaining all references. Event IDs include the case and endpoint identities. Timestamp offsets normalize to UTC; timestamps without a timezone are rejected. Events outside the inclusive case window remain in raw evidence and are counted as excluded from the timeline.

Normalized events include a `classification` status and reason. `summary.unclassified_events` reports interpretation limitations separately from collection-coverage gaps; it does not change the coverage-based CLI exit status. JSON preserves classification details, and HTML/CSV labels identify unclassified observations. Unclassified account, process, command, path and hash convenience fields are deliberately empty; their original values remain in the linked raw evidence. Supplied source logon-ID fields remain visible without establishing membership. Rebuild all derived views together after adopting this policy; existing saved views are not silently migrated.

`System.TimeCreated.SystemTime` takes precedence over formatted top-level `TimeCreated`. The original imported value remains in `timestamp_original`, its field path in `timestamp_source`, and raw JSON bytes remain unchanged. Native exact cases add `timestamp_precision="evtx-systemtime-100ns"` and `references[].exact_time`; `timestamp_utc` is derived from the proven source bytes using integer arithmetic. Case-window selection, timeline ordering, correlations and session boundaries retain seven fractional digits when supplied. This is representation precision, not a guarantee of clock accuracy or causality.

Older JSON-only imports with numeric times retain their existing microsecond conversion and are labeled `native-float-microsecond`; lost source digits cannot be reconstructed without the EVTX. ISO imports preserve their supplied digits through 100 ns and are labeled `iso-supplied`; shorter fractions do not gain invented precision. Fractional timezone offsets and nonzero precision finer than 100 ns are rejected. Rebuild derived exports together after upgrading; accurate reparsing of an older local case requires its original EVTX and a new native run, not an oracle-time substitution.

Version 0.2 includes a supplied nonempty provider in derived event identity so otherwise identical trusted/unrecognized provider records cannot merge. Rebuilding an older case may therefore change derived event and finding IDs for records that contain a provider. Providerless fixture identities and original raw hashes remain unchanged; regenerate derived exports together.

Run full verification before handoff or rebuilding derived views:

```powershell
crumbtrail verify --root D:\Cases\example
crumbtrail analyze --root D:\Cases\example
```

`verify` checks registered raw and precision-sidecar hashes, sizes, rows, source/identity bindings, provenance checksums and endpoint binding. Missing, changed or unregistered sidecars stop verification. It never opens source paths recorded in an imported case, so a Windows case remains verifiable offline on another platform without the EVTX extra. Original EVTX files remain separately controlled evidence; the sidecar preserves their hashes and exact field bytes, not full EVTX copies. The manifest/checksums are unsigned and can be rewritten by someone controlling the whole case. Native diagnostics remain operational logs. Derived JSON/CSV/HTML can be regenerated after verification.

Rules correlate only within an endpoint, organization, and simulation status. Logon/process findings use the same full-scope source-ID membership as the session view: repeated starts, conflicting IDs, provider conflicts, logoff/startup cutoffs and coincident boundaries suppress an unsupported association. A uniquely linked observed start within 30 minutes gives context; a recovery-related command records an attempt; six distinct paths within two minutes plus a recovery-note-like filename creates a suspicious observation. None establishes that encryption occurred or that an account was compromised. Missing coverage, row-limit hits, and count mismatches are visible gaps. Absence of a finding is not a clean-host verdict.

Exit codes: `0` completed without reported gaps, `1` runtime/input/integrity error, `2` report generated with coverage gaps (also standard argparse usage errors), `130` interruption. `create`, `bind`, and `verify` report their own operation result, not a complete-coverage verdict.

## Python API

```python
from crumbtrail.storage import Case, case_lock
from crumbtrail.events import analyze
from crumbtrail.report import write_report

with case_lock("D:/Cases/example"):
    case = Case("D:/Cases/example")
    case.verify()
    result = analyze(case)
    write_report(case, result)
```

`Case.create(root, start, end, case_id=None)`, `case.bind(client_id, hostname, org="root")`, and `case.preserve(raw_bytes, client_id, source, simulation=False, details=None)` expose the same offline workflow. Supply complete native result objects, including coverage. The CLI rejects concurrent case operations using a nonblocking OS file lock. Direct API users must acquire `case_lock(root)` and then reopen `Case` before reading or changing an existing case, as above; methods do not nest their own locks. `Case.create` locks creation internally. There is no multiuser authorization layer.

`analyze(case)["session_view"]` supplies the session view. `crumbtrail.sessions.build_session_view(events)` also accepts current normalized events without modifying them; pass the complete selected scope so a filtered subset cannot hide starts or boundaries. Older normalized exports lacking source-field/provider metadata should be rebuilt from their preserved raw case evidence.

## Limits and development

Imports are bounded to 64 MiB per result/sidecar, 256 MiB of combined registered bytes per case, and 100,000 result rows per case. Exact local inputs are regular files without file reparse aliases: at most 64 MiB each, 256 MiB combined, five files and 100,000 physical records combined. Hashing checks byte bounds and file identity during reads. The exact parser runs in a separate process with a 120-second timeout. Native VQL retains its 655-second query/660-second process limits and 20,000 candidate rows per channel. Candidate overread can hit caps or cost more work; unchanged large-file throughput is not claimed. Native stdout streams to disk; the later 64 MiB check is not a hard disk quota. There is no resumable large-result import.

CrumbTrail provides event triage, not full filesystem or memory forensics. It does not acquire disks/RAM, extract credentials, alter protection settings, run ransomware, or contain email/cloud correlation. Original source attribution and MIT terms are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The fixture and event rules were selectively adapted; no legacy runtime package is required.

```powershell
python -m pip install -e ".[evtx]"
python -m unittest discover -s tests -v
```

See [validation and lab acceptance](docs/validation.md) for exactly what was exercised, and [the Windows triage agent role](agents/windows-triage.md) for scoped maintenance work.
