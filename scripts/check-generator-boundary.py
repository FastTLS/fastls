"""Check the request core ships no browser generation code or frozen catalog."""
from pathlib import Path
import json
import re
import subprocess

core = Path(__file__).resolve().parents[1]
assert not (core / "internal/frozen").exists(), "browser catalog remains in core"
assert not (core / "imitate/ja4r").exists(), "old browser wrappers remain in core"
expected = {"provider.go", "use.go"}
actual = {p.name for p in (core / "imitate").glob("*.go") if not p.name.endswith("_test.go")}
assert actual == expected, f"review core application API files: {actual}"
for p in core.rglob("*.go"):
    if any(part in (".git", "reports") for part in p.relative_to(core).parts):
        continue
    source = p.read_text(encoding="utf-8")
    assert "github.com/FastTLS/imitate" not in source or "integration" in p.relative_to(core).parts, f"generator dependency leaked into core: {p}"
    assert not re.search(r"\bimitate\.(Chrome\w*|Firefox\w*|Chromium\w*|Edge\w*|Opera\w*|Safari\w*|Generate\w*)\b", source), f"removed browser API still referenced: {p}"
deps = subprocess.check_output(["go", "list", "-deps", "./..."], cwd=core, text=True).splitlines()
assert not any(p == "github.com/FastTLS/imitate" or p.startswith("github.com/FastTLS/imitate/") for p in deps)
print(json.dumps({"status": "pass", "application_files": sorted(actual), "core_generator_dependency": False}))
