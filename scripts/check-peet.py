"""Run current workspace checks and explicit peet TLS observations; save four report formats."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

CORE = Path(__file__).resolve().parents[1]
ENDPOINT = "https://tls.peet.ws/api/all"
PEET_CASES = ["TestCustomJA3Fingerprint", "TestJA3PointFormatsVariation/with_zero",
              "TestJA3PointFormatsVariation/empty", "TestGoStdlibFingerprint",
              "TestFastlsStdlibFingerprint"]
TEST_PATTERN = "^(TestCustomJA3Fingerprint|TestJA3PointFormatsVariation|TestGoStdlibFingerprint|TestFastlsStdlibFingerprint)$"


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def events(text):
    result = {}
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("Test") and item.get("Action") in ("pass", "fail", "skip"):
            result[item["Test"]] = item["Action"]
    return result


def peet_results(out, output, code, duration):
    states = events(output)
    result = []
    for name in PEET_CASES:
        evidence = Path("observations") / (name.replace("/", "-") + ".json")
        status = states.get(name, "error")
        message = ""
        observation = None
        if (out / evidence).is_file():
            try:
                observation = json.loads((out / evidence).read_text(encoding="utf-8"))
                if not isinstance(observation, dict):
                    observation = None
                    message = "observation must be a JSON object"
            except ValueError:
                message = "invalid observation JSON"
        if status == "pass" and (observation is None or observation.get("status") != "pass"
                                 or observation.get("endpoint") != ENDPOINT
                                 or observation.get("http_status") != 200
                                 or not observation.get("observed", {}).get("tls", {}).get("ja3")):
            status, message = "error", "test passed without successful response evidence"
        if status == "skip":
            status, message = "not_run", "network case skipped; not counted as passed"
        if status == "error" and not message:
            message = "test did not complete; see logs/peet.log"
        if observation and not message:
            seen = observation.get("observed", {})
            tls = seen.get("tls", {})
            message = (f"{observation.get('error')}; stage={observation.get('error_stage', 'unknown')}; "
                       f"protocol={observation.get('protocol', 'unavailable')}; "
                       f"bytes_read={observation.get('body_bytes', 'unknown')}; "
                       f"content_length={observation.get('content_length', 'unknown')}; "
                       f"auto_decompressed={observation.get('automatically_decompressed', 'unknown')}"
                       if observation.get("error") else (
                f"{ENDPOINT}; HTTP {observation.get('http_status')}; {seen.get('http_version')}; "
                f"TLS {tls.get('tls_version_negotiated')}; JA3={tls.get('ja3')}; "
                f"JA3 hash={tls.get('ja3_hash')}; JA4={tls.get('ja4')}; JA4R={tls.get('ja4_r')}; "
                f"Akamai={seen.get('http2', {}).get('akamai_fingerprint', '')}; "
                f"bytes_read={observation.get('body_bytes', 'unknown')}; "
                f"validation={'exact JA3 match' if observation.get('expected_ja3') else 'valid observation, no fixed JA3 baseline'}"))
        result.append({"step": {"id": "peet." + name.replace("/", "."), "task_id": "V04",
                                 "category": "network", "directory": ".", "required": True,
                                 "command": ["go", "test", "./_tests", "-run", TEST_PATTERN, "-count=1", "-timeout", "130s", "-json"]},
                       "status": status, "message": message, "duration_ms": observation.get("duration_ms", duration) if observation else duration,
                       "exit_code": code, "log": evidence.as_posix() if observation else "logs/peet.log"})
    # A package/build/cleanup error must not disappear behind successful leaf tests.
    if code != 0 and all(x["status"] == "pass" for x in result):
        result.append({"step": {"id": "peet.package", "task_id": "V04", "category": "network", "directory": ".", "command": ["go", "test", "./_tests"], "required": True},
                       "status": "fail", "message": "Go test process failed after case results", "duration_ms": duration, "exit_code": code, "log": "logs/peet.log"})
    return result


def command(args, directory, env, log, timeout=180):
    start = time.monotonic()
    try:
        p = subprocess.run(args, cwd=directory, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        code, output = p.returncode, p.stdout + p.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        code, output = 2, str(error)
    log.write_text(output, encoding="utf-8")
    return code, output, int((time.monotonic() - start) * 1000)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--output", type=Path, help="parent directory for a new immutable report")
    args = parser.parse_args()
    parent = (args.output or CORE.parent / "reports").resolve()
    parent.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    out = Path(tempfile.mkdtemp(prefix=started.strftime("%Y%m%dT%H%M%SZ") + "-peet-", dir=parent))
    (out / "logs").mkdir()
    env = dict(os.environ, GOWORK=str(CORE / "go.work"), FASTLS_PEET_NETWORK="1", FASTLS_PEET_OUTPUT=str(out / "observations"))
    # This suite intentionally tests the current workspace rather than stale unpublished module caches.
    checks = [("core.test", CORE, ["go", "test", "./...", "-count=1", "-timeout", "90s"]),
              ("core.build", CORE, ["go", "build", "./..."]),
              ("core.vet", CORE, ["go", "vet", "./..."]),
              ("profile.test", CORE / "profile", ["go", "test", "./...", "-count=1", "-timeout", "60s"]),
              ("reporter.test", CORE / "tools/fastls-check", ["go", "test", "./...", "-count=1", "-timeout", "60s"]),
              ("reporting.test", CORE, [sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py"]),
              ("configuration.test", CORE, ["go", "test", "./_tests", "-run", "^(TestH2|TestHTTP2|TestParseH2|TestNO_RFC|TestUnknown|TestJa4|TestOptions|TestPeetValidation)", "-count=1", "-timeout", "60s"])]
    manifest = {"schema_version": 1, "suite": "network", "endpoint": ENDPOINT,
                "started_at": started.isoformat(), "display_timezone": "Asia/Shanghai",
                "gowork": env["GOWORK"], "proxy": "direct; no environment proxy used by either client",
                "scope": "five external observations plus fresh local core/profile/configuration checks; no real-browser equivalence claim"}
    for key, cmd in [("go_version", ["go", "version"]), ("modules", ["go", "list", "-m", "-json", "all"])]:
        code, text, _ = command(cmd, CORE, env, out / "logs" / (key + ".log"))
        manifest[key] = text
        manifest[key + "_exit_code"] = code
    manifest["source_sha256"] = {}
    for module in (CORE, CORE / "profile", CORE.parent / "fhttp"):
        for p in sorted(module.rglob("*.go")):
            if any(x in p.relative_to(module).parts for x in (".git", "reports")):
                continue
            manifest["source_sha256"][str(p.relative_to(CORE.parent))] = hashlib.sha256(p.read_bytes()).hexdigest()
    save(out / "run-manifest.json", manifest)
    results = []
    for name, directory, cmd in checks:
        code, _, elapsed = command(cmd, directory, env, out / "logs" / (name + ".log"))
        results.append({"step": {"id": name, "task_id": "T01", "category": "local", "directory": str(directory), "command": cmd, "required": True},
                        "status": "pass" if code == 0 else "fail", "exit_code": code, "duration_ms": elapsed, "log": "logs/" + name + ".log"})
    peet_cmd = ["go", "test", "./_tests", "-run", TEST_PATTERN, "-count=1", "-timeout", "130s", "-json"]
    code, output, elapsed = command(peet_cmd, CORE, env, out / "logs/peet.log", timeout=150)
    results.extend(peet_results(out, output, code, elapsed))
    report = {"report_schema_version": 1, "run_id": out.name, "suite": "network", "started_at": started.isoformat(),
              "finished_at": datetime.now(timezone.utc).isoformat(), "results": results,
              "excluded": [{"path": "browser equivalence", "reason": "JA3 fixtures and standard-library observations; not proof of full real-browser fingerprint equivalence"},
                           {"path": "proxy/WS/H3/race/Linux", "reason": "not run by this network suite; local integration has its own report"}]}
    save(out / "results.json", report)
    reporter = out / ("fastls-check.exe" if os.name == "nt" else "fastls-check")
    code, _, _ = command(["go", "build", "-o", str(reporter), "."], CORE / "tools/fastls-check", dict(env, GOWORK="off"), out / "logs/reporter-build.log")
    if code:
        print("Report renderer build failed; raw results:", out / "results.json", file=sys.stderr)
        return 2
    rendered = subprocess.run([str(reporter), "-report-only", str(out / "results.json")], cwd=CORE, env=env)
    print("Peet report:", out / "report.html", flush=True)
    print("Required checks:", {s: sum(r["status"] == s for r in results) for s in ("pass", "fail", "error", "not_run")}, flush=True)
    return rendered.returncode


if __name__ == "__main__":
    raise SystemExit(main())
