"""Check first-party licenses and exact upstream notice copies; no network."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    manifest = json.loads((ROOT / "third_party/licenses/manifest.json").read_text(encoding="utf-8"))
    canonical = (ROOT / "LICENSE").read_bytes()
    # Git may normalize first-party text line endings on Windows.
    normalized = canonical.replace(b"\r\n", b"\n")
    assert hashlib.sha256(normalized).hexdigest() == manifest["apache_sha256"], "Apache text changed"
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    modules = sorted({Path(p).parent for p in tracked if p.endswith("go.mod")})
    assert modules, "no Go modules found"
    expected = []
    for module in modules:
        for name in ("LICENSE", "NOTICE"):
            relative = (module / name).as_posix()
            raw = (ROOT / relative).read_bytes()
            if name == "LICENSE":
                assert raw.replace(b"\r\n", b"\n") == normalized, relative
            else:
                assert b"FastTLS contributors" in raw and b"Third-party" in raw, relative
            expected.append(relative)
    for dependency in manifest["dependencies"]:
        assert dependency["files"], dependency["module"]
        for record in dependency["files"]:
            path = ROOT / record["path"]
            assert path.resolve().is_relative_to((ROOT / "third_party/licenses").resolve()), path
            assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"], path
            expected.append(record["path"])
    # Source archives must carry all licenses even for independent submodules.
    archive = subprocess.check_output(["git", "archive", "--format=zip", "HEAD"], cwd=ROOT)
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        for name in expected + ["THIRD_PARTY_NOTICES.md", "third_party/licenses/manifest.json", "third_party/fhttp-provenance.json"]:
            assert name in source.namelist(), "source archive lacks " + name
            assert source.read(name).replace(b"\r\n", b"\n") == (ROOT / name).read_bytes().replace(b"\r\n", b"\n"), name
    print(f"License materials passed: {len(modules)} Go modules, {len(manifest['dependencies'])} notice sources, source archive included.")
    print("Historical fhttp evidence is retained; the current production module graph and release source exclude fhttp.")


if __name__ == "__main__":
    main()
