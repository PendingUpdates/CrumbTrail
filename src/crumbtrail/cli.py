"""Small standalone CLI; no provider credentials or neighboring packages."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .events import analyze
from .native import data_path, run_local
from .report import write_report
from .sessions import build_session_view
from .storage import Case, CaseError, MAX_BYTES, case_lock

LAB_CLIENT = "C.0123456789abcdef"


def _log_directory(value):
    if not value.strip():
        raise argparse.ArgumentTypeError("Supply a nonblank exported EVTX log directory explicitly.")
    return Path(value)


def parser():
    result = argparse.ArgumentParser(prog="crumbtrail", description="Preserve and triage Windows event evidence offline.")
    result.add_argument("--version", action="version", version="CrumbTrail " + __version__)
    commands = result.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("create", "Create an empty case with an explicit UTC window"),
        ("bind", "Bind an immutable endpoint identity"),
        ("import", "Preserve a native artifact JSON/JSONL export"),
        ("local", "Parse a supplied EVTX directory through local Velociraptor"),
        ("analyze", "Rebuild the offline report after integrity verification"),
        ("sessions", "Show source-ID-backed logon sessions, unlinked events, and ambiguity"),
        ("verify", "Verify raw bytes and source provenance"),
        ("demo", "Create an inert deterministic Windows fixture case"),
        ("lab", "Read the inert fixture through the actual local VQL engine"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--root", required=True, type=Path, help="Case directory; create/demo/lab require a new or empty directory")
        if name == "create":
            command.add_argument("--start", required=True)
            command.add_argument("--end", required=True)
            command.add_argument("--case-id")
        if name in ("bind", "import", "local"):
            command.add_argument("--client-id", required=True)
        if name == "sessions":
            command.add_argument("--client-id", help="Filter the printed view to one bound endpoint")
        if name == "bind":
            command.add_argument("--hostname", required=True)
            command.add_argument("--org", default="root")
        if name == "import":
            command.add_argument("--file", required=True, type=Path)
            command.add_argument("--simulation", action="store_true")
        if name in ("local", "lab"):
            command.add_argument("--velociraptor", required=True, type=Path)
        if name == "local":
            command.add_argument("--log-directory", required=True, type=_log_directory)
    return result


def execute(args):
    if args.command == "create":
        case = Case.create(args.root, args.start, args.end, args.case_id)
        print(json.dumps(case.meta, indent=2))
        return 0
    if args.command in ("demo", "lab"):
        Case.create(args.root, "2026-10-30T20:00:00Z", "2026-10-30T22:00:00Z", "CT-DEMO")
    with case_lock(args.root):
        # Re-open metadata only after acquiring the cross-process lock.
        case = Case(args.root)
        if args.command == "sessions" and args.client_id:
            case.binding(args.client_id)
        if args.command in ("demo", "lab"):
            case.bind(LAB_CLIENT, "LAB-WIN01")
            if args.command == "lab":
                run_local(case, LAB_CLIENT, args.velociraptor, fixture=True)
            else:
                case.preserve(data_path("windows.jsonl").read_bytes(), LAB_CLIENT, "bundled-fixture", True,
                              details={"filename": "windows.jsonl"})
        else:
            if args.command == "bind":
                print(json.dumps(case.bind(args.client_id, args.hostname, args.org), indent=2))
                return 0
            if args.command == "verify":
                print(json.dumps({"verified_artifacts": case.verify(), "case_id": case.meta["case_id"]}))
                return 0
            if args.command == "import":
                if not args.file.is_file() or args.file.stat().st_size > MAX_BYTES:
                    raise CaseError("Input file is missing or exceeds 64 MiB.")
                case.preserve(args.file.read_bytes(), args.client_id, "offline-export", args.simulation,
                              details={"filename": args.file.name})
            elif args.command == "local":
                run_local(case, args.client_id, args.velociraptor, log_directory=args.log_directory)
        result = analyze(case)
        write_report(case, result)
        if args.command == "sessions":
            view = result["session_view"] if not args.client_id else build_session_view(
                [event for event in result["events"] if event["client_id"] == args.client_id])
            print(json.dumps(view, indent=2))
            return 2 if result["gaps"] else 0
        print(json.dumps({**result["summary"], "root": str(case.root), "report": str(case.root / "report.html")}, indent=2))
        return 2 if result["gaps"] else 0


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return execute(args)
    except (CaseError, OSError, ValueError, KeyError, TypeError) as exc:
        print("crumbtrail: " + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("crumbtrail: interrupted; preserved case files remain on disk.", file=sys.stderr)
        return 130
