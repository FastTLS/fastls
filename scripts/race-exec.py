"""Execute a Windows race test at its preferred PE base.

Zig's linker enables high-entropy ASLR, which maps the Go ThreadSanitizer image
outside its usable shadow range on this host. Only temporary instrumented test
executables are changed; application sources and production binaries are not.
"""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

exe = Path(sys.argv[1]).resolve()
if os.name == "nt":
    b = bytearray(exe.read_bytes())
    if b[:2] != b"MZ":
        raise SystemExit("expected a PE race test executable")
    pe = struct.unpack_from("<I", b, 0x3c)[0]
    if b[pe:pe + 4] != b"PE\x00\x00":
        raise SystemExit("invalid PE signature")
    opt = pe + 24
    flags = struct.unpack_from("<H", b, opt + 70)[0]
    struct.pack_into("<H", b, opt + 70, flags & ~0x60)
    exe.write_bytes(b)
    if "FASTLS_IMITATE_RUN" in os.environ:
        with (Path(os.environ["FASTLS_IMITATE_RUN"]) / "race-pe-layout.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"binary": str(exe), "original_dll_characteristics": flags, "test_dll_characteristics": flags & ~0x60, "reason": "Go ThreadSanitizer shadow mapping; temporary test executable only"}) + "\n")
raise SystemExit(subprocess.run([str(exe), *sys.argv[2:]]).returncode)
