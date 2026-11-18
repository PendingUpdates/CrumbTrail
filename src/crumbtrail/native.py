"""Local Velociraptor execution over explicit files; no server or driver API."""
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from importlib.resources import files
from pathlib import Path

from .storage import CaseError, MAX_BYTES, save, ticks, iso_ticks, TICKS_PER_SECOND


def data_path(name):
    return Path(str(files("crumbtrail").joinpath("data", name)))


def run_local(case, client_id, executable, *, fixture=False, log_directory=None):
    """Parse an explicit export directory, or the bundled inert fixture.

    Raw blank directory text is rejected before Path can normalize it to ".".
    An already constructed Path("") is indistinguishable from explicit Path(".").
    """
    if not fixture and (log_directory is None or not os.fspath(log_directory).strip()):
        raise CaseError("Supply an existing exported EVTX log directory explicitly.")
    executable = Path(executable).resolve()
    if not executable.is_file():
        raise CaseError("Velociraptor executable is missing.")
    if not fixture and not Path(log_directory).is_dir():
        raise CaseError("Supply an existing exported EVTX log directory explicitly.")
    case.binding(client_id)
    sources = []
    if not fixture:
        from .precision import require_parser, file_hash
        require_parser()
        for filename in ("Security.evtx", "System.evtx", "Microsoft-Windows-Sysmon%4Operational.evtx",
                         "Microsoft-Windows-PowerShell%4Operational.evtx", "Microsoft-Windows-Windows Defender%4Operational.evtx"):
            candidate = Path(log_directory) / filename
            if candidate.exists() or candidate.is_symlink():
                if not candidate.is_file() or candidate.is_symlink() or getattr(candidate.lstat(), "st_file_attributes", 0) & 0x400:
                    raise CaseError("Exact EVTX inputs must be regular files without reparse aliases.")
                path = candidate.resolve()
                size = path.stat().st_size
                if not 0 < size <= MAX_BYTES:
                    raise CaseError("Exact EVTX inputs must be nonempty and at most 64 MiB each.")
                if sum(source["bytes"] for source in sources) + size > 256 * 1024 * 1024:
                    raise CaseError("Exact EVTX inputs exceed the 256 MiB aggregate budget.")
                sources.append(dict(path=str(path), bytes=size, sha256=file_hash(path, expected_size=size)))
        if sum(source["bytes"] for source in sources) > 256 * 1024 * 1024:
            raise CaseError("Exact EVTX inputs exceed the 256 MiB aggregate budget.")
    artifact = "Custom.CrumbTrail.LabReplay" if fixture else "Custom.CrumbTrail.WindowsTriage"
    variables = {"FixtureFile": str(data_path("windows.jsonl"))} if fixture else {
        # Candidate overread prevents upstream float rounding from losing an
        # event at an exact boundary. Final selection uses verified source ticks.
        "StartDate": iso_ticks((ticks(case.meta["start"]) // TICKS_PER_SECOND - 1) * TICKS_PER_SECOND),
        "EndDate": iso_ticks((ticks(case.meta["end"]) // TICKS_PER_SECOND + 2) * TICKS_PER_SECOND),
        "LogDirectory": str(Path(log_directory).resolve())}
    parameters = ",".join(key + "=" + key for key in variables)
    query = "SELECT * FROM Artifact." + artifact + "(" + parameters + ")"
    cmd = [str(executable), "--definitions", str(data_path("Custom.CrumbTrail.LabReplay.yaml").parent),
           "query", "--format", "jsonl", "--timeout", "655"]
    for key, value in variables.items():
        cmd.extend(["--env", key + "=" + value])
    cmd.append(query)
    fingerprint = hashlib.sha256()
    with executable.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            fingerprint.update(block)
    detail = dict(executable_sha256=fingerprint.hexdigest(), artifact=artifact, parameters=variables)
    if not fixture:
        detail["exact_window"] = {key: case.meta[key] for key in ("start", "end")}
    # Logs belong to the case, not the public source tree. Unique runs retain failures.
    run_dir = case.root / "collection" / ("run-" + uuid.uuid4().hex[:12])
    run_dir.mkdir(parents=True)
    save(run_dir / "request.json", detail)
    env = os.environ.copy()
    if os.name == "nt":
        env["__COMPAT_LAYER"] = "RunAsInvoker"
    output, errors = run_dir / "stdout.jsonl", run_dir / "stderr.log"
    try:
        with output.open("xb") as stdout, errors.open("xb") as stderr:
            result = subprocess.run(cmd, stdout=stdout, stderr=stderr, timeout=660, env=env,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise CaseError("Native parsing timed out; inspect " + str(run_dir)) from exc
    stderr = errors.read_bytes()
    if result.returncode or re.search(rb"(?im)^.*\[(error|fatal)\]|^.*: error:", stderr):
        raise CaseError("Native parsing failed; inspect " + str(errors))
    if output.stat().st_size > MAX_BYTES:
        raise CaseError("Native result exceeds the 64 MiB import budget; output retained at " + str(output))
    precision = None
    if not fixture:
        request, exact_output = run_dir / "precision-request.json", run_dir / "precision.json"
        save(request, dict(raw=str(output), sources=sources))
        try:
            with (run_dir / "precision.stderr.log").open("xb") as error_stream:
                precise = subprocess.run([sys.executable, "-I", "-m", "crumbtrail.precision", str(request), str(exact_output)],
                    stdout=subprocess.DEVNULL, stderr=error_stream, timeout=120,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired as exc:
            raise CaseError("Exact EVTX parsing timed out; inspect " + str(run_dir)) from exc
        if precise.returncode or not exact_output.is_file() or not 0 < exact_output.stat().st_size <= MAX_BYTES:
            raise CaseError("Exact EVTX parsing failed; inspect " + str(run_dir / "precision.stderr.log"))
        if any(file_hash(source["path"], expected_size=source["bytes"]) != source["sha256"] for source in sources):
            raise CaseError("EVTX source changed during native/exact parsing; inspect " + str(run_dir))
        precision = json.loads(exact_output.read_text(encoding="utf-8"))
    entry = case.preserve(output.read_bytes(), client_id, "native-fixture" if fixture else "native-evtx",
                          simulation=fixture, details=detail, precision=precision)
    save(run_dir / "result.json", dict(exit_code=result.returncode, artifact_sha256=entry["sha256"]))
    return entry
