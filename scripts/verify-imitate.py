"""Build local release candidates and verify the optional generator boundary.

No publication, global Go configuration changes, or module replace directives.
Run from the workspace: python fastls/scripts/verify-imitate.py --all
"""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
import xml.etree.ElementTree as ET

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent
VERSION = "v0.1.0-dev.20261023.8"
MODULES = {"fastls/profile": "github.com/FastTLS/fastls/profile", "fhttp": "github.com/FastTLS/fhttp", "fastls": "github.com/FastTLS/fastls", "imitate": "github.com/FastTLS/imitate"}
ACTIVE_OUT = None


def run(args, directory, env=None):
    p = subprocess.run(args, cwd=directory, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", timeout=300)
    if p.returncode:
        raise RuntimeError(f"{args} exited {p.returncode}\n{p.stdout}")
    return p.stdout


def files(source):
    for f in sorted(source.rglob("*")):
        if not f.is_file() or any(x in f.relative_to(source).parts for x in (".git", ".idea", "reports", "node_modules", "__pycache__")) or f.suffix in (".exe", ".zip", ".test") or f.name in ("go.work", "go.work.sum"):
            continue
        if any((p / "go.mod").exists() for p in f.parents if p != source and source in p.parents):
            continue
        yield f


def digest(source):
    h = hashlib.sha256()
    for f in files(source):
        h.update(f.relative_to(source).as_posix().encode()); h.update(b"\x00"); h.update(f.read_bytes())
    return h.hexdigest()


def pack(source, module, version, proxy):
    escaped = "".join("!" + c.lower() if c.isupper() else c for c in module)
    dest = proxy / escaped / "@v"; dest.mkdir(parents=True, exist_ok=True)
    (dest / (version + ".mod")).write_bytes((source / "go.mod").read_bytes())
    (dest / (version + ".info")).write_text(json.dumps({"Version": version, "Time": "2026-10-23T00:00:00Z"}), encoding="utf-8")
    with zipfile.ZipFile(dest / (version + ".zip"), "w", zipfile.ZIP_DEFLATED) as z:
        for f in files(source):
            z.write(f, module + "@" + version + "/" + f.relative_to(source).as_posix())
    (dest / "list").write_text("\n".join(sorted(f.stem for f in dest.glob("*.info"))) + "\n", encoding="utf-8")


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_failure(out, error):
    failure=Path(tempfile.mkdtemp(prefix="orchestrator-failure-",dir=out))
    detail={"status":"tool_error","exit_code":2,"message":str(error),"phase":"candidate preparation or boundary experiment"}
    save(failure / "results.json",detail)
    (failure / "report.html").write_text('<!doctype html><meta charset="utf-8"><title>Imitate verification stopped</title><h1>Verification stopped</h1><p>No complete acceptance claimed.</p><pre>'+html.escape(str(error))+'</pre>',encoding="utf-8")
    (failure / "summary.md").write_text("# Verification stopped\n\nExit code: 2. No complete acceptance claimed.\n\n"+str(error)+"\n",encoding="utf-8")
    suite=ET.Element("testsuite",name="imitate.orchestrator",tests="1",errors="1")
    ET.SubElement(ET.SubElement(suite,"testcase",name="preflight"),"error",message=str(error)).text=str(error)
    ET.ElementTree(suite).write(failure / "junit.xml",encoding="utf-8",xml_declaration=True)
    return failure


def prepare(out, network=False):
    shared_cache = Path(run(["go", "env", "GOMODCACHE"], CORE).strip())
    proxy = out / "proxy"
    snapshots = {}
    env = dict(os.environ, GOWORK="off", GOPROXY=proxy.as_uri() + "," + (shared_cache / "cache/download").as_uri() + (",https://proxy.golang.org,direct" if network else ",off"), GONOSUMDB="github.com/FastTLS/*", GOMODCACHE=str(out / "module-cache"), GOFLAGS="-mod=mod")
    env["FASTLS_IMITATE_RUN"] = str(out)
    # Publish only to the private file proxy, in dependency order. Populate
    # dependency sums before packing their dependents, so snapshots are fixed.
    for relative in ("fastls/profile", "fhttp"):
        run(["go", "mod", "download"], ROOT / relative, env)
        pack(ROOT / relative, MODULES[relative], VERSION, proxy)
    for relative in ("fastls", "imitate"):
        run(["go", "mod", "download"], ROOT / relative, env)
        run(["go","mod","download",MODULES["fastls/profile"]+"@"+VERSION],ROOT / relative,env)
        if relative=="fastls":run(["go","mod","download",MODULES["fhttp"]+"@"+VERSION],ROOT / relative,env)
        pack(ROOT / relative, MODULES[relative], VERSION, proxy)
    for relative,module in MODULES.items():
        source=ROOT / relative
        snapshots[module] = {"version": VERSION, "source_sha256": digest(source), "head": run(["git", "rev-parse", "HEAD"], source).strip() if relative != "imitate" else "uncommitted initial repository"}
    save(out / "candidates.json", {"published": False, "modules": snapshots, "proxy": proxy.as_uri(), "note": "Local immutable file-proxy candidates; GOWORK=off; not evidence of public availability."})
    save(out / "environment.json", {k: env[k] for k in ("GOWORK", "GOPROXY", "GOMODCACHE", "GONOSUMDB", "GOFLAGS")})
    return env


def graph_checks(out, env):
    # A physically separate cache must not acquire the generator at all.
    no_gen = out / "without-generator"; no_gen.mkdir(exist_ok=True)
    (no_gen / "go.mod").write_text(f"module no-generator\n\ngo 1.24\nrequire github.com/FastTLS/fastls {VERSION}\n", encoding="utf-8")
    (no_gen / "main.go").write_text('''package main
import ("errors";"fmt";"io";"os"; f "github.com/FastTLS/fastls"; "github.com/FastTLS/fastls/imitate"; "github.com/FastTLS/fastls/profile")
func main(){
 fps:=[]f.Fingerprint{nil,f.Ja3Fingerprint{FingerprintValue:"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-11-0-17613-5-45-23-65037-16-27-13-10-18-35-51-43-41,4588-29-23-24,0"},f.Ja4Fingerprint{FingerprintValue:"t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"}}
 for _,fp:=range fps{o:=f.Options{Fingerprint:fp,UserAgent:"custom-client/1.0",FingerprintUserAgent:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",Timeout:5};target:=os.Getenv("TEST_URL");if fp==nil{target=os.Getenv("TEST_URL_HTTP")};r,e:=f.NewClient().Do(target+"/inspect",o,"GET");if e!=nil{panic(e)};io.Copy(io.Discard,r.Body);r.Body.Close();r.Client.CloseIdleConnections();if r.Status!=200{panic(r.Status)}}
 _=profile.SchemaVersion;o:=f.Options{};_,err:=imitate.Use(&o,"chrome/155/windows");fmt.Println(errors.Is(err,profile.ErrInvalidOptions))
}
''', encoding="utf-8")
    isolated = dict(env, GOMODCACHE=str(out / "no-generator-cache"))
    isolated["GOPROXY"]=(Path(env["GOMODCACHE"]) / "cache/download").as_uri()+","+env["GOPROXY"]
    deps = [p for p in run(["go", "list", "-deps", "."], no_gen, isolated).splitlines() if p and " " not in p]
    assert "github.com/FastTLS/fastls" in deps and "github.com/FastTLS/fastls/profile" in deps
    assert not any(p == "github.com/FastTLS/imitate" or p.startswith("github.com/FastTLS/imitate/") for p in deps)
    lab_binary=out / ("lab-no-generator.exe" if os.name=="nt" else "lab-no-generator")
    run(["go","build","-o",str(lab_binary),"."],ROOT / "fastls-lab",env)
    lab_output=Path(tempfile.mkdtemp(prefix="no-generator-wire-",dir=out)) / "capture"
    lab_process=subprocess.Popen([str(lab_binary),"-output",str(lab_output)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8")
    try:
        lab_manifest=json.loads(lab_process.stdout.readline())
        transport_env=dict(isolated,TEST_URL=lab_manifest["https"].replace("127.0.0.1","localhost"),TEST_URL_HTTP=lab_manifest["http"])
        assert run(["go", "run", "."], no_gen, transport_env).splitlines()[-1] == "true"
    finally:
        lab_process.terminate();lab_process.wait(timeout=10)
    assert not list((out / "no-generator-cache/github.com/!fast!t!l!s").glob("imitate@*"))
    gen = out / "generator-alone"; gen.mkdir(exist_ok=True)
    (gen / "go.mod").write_text(f"module generator-alone\n\ngo 1.24\nrequire github.com/FastTLS/imitate {VERSION}\n", encoding="utf-8")
    (gen / "main.go").write_text('''package main
import("context";"encoding/json";"os";"github.com/FastTLS/imitate";"github.com/FastTLS/fastls/profile")
func main(){r,e:=imitate.New().Resolve(context.Background(),profile.ResolveRequest{Selector:"chrome/155/windows"});if e!=nil{panic(e)};json.NewEncoder(os.Stdout).Encode(r)}
''', encoding="utf-8")
    deps_gen = [p for p in run(["go", "list", "-deps", "."], gen, env).splitlines() if p and " " not in p]
    assert "github.com/FastTLS/imitate" in deps_gen and "github.com/FastTLS/fastls/profile" in deps_gen
    forbidden = ("github.com/FastTLS/fhttp", "github.com/refraction-networking/utls", "github.com/quic-go/")
    assert not any(p == "github.com/FastTLS/fastls" or p.startswith(forbidden) or p.startswith("github.com/FastTLS/fastls/imitate") for p in deps_gen)
    result = json.loads(run(["go", "run", "."], gen, env).splitlines()[-1])
    assert result["match"]["provider_id"] == "FastTLS/imitate"
    save(out / "dependency-boundaries.json", {"without_generator": {"status": "pass", "packages": deps, "generator_absent_from_isolated_cache": True, "actual_requests":["stdlib-empty-http","custom-ja3-https","custom-ja4r-https"],"lab":lab_manifest}, "generator_alone": {"status": "pass", "packages": deps_gen, "resolution": result}})
    print("optional dependency and standalone generator checks passed")


def upgrade_checks(out, env):
    before = {name: digest(ROOT / name) for name in ("fastls", "fastls/profile", "fhttp")}
    work = Path(tempfile.mkdtemp(prefix="upgrade-",dir=out))
    variant = work / "generator-candidate-B"
    shutil.copytree(ROOT / "imitate", variant, ignore=shutil.ignore_patterns(".git", "go.sum"))
    native = variant / "native.go"
    text = native.read_text(encoding="utf-8")
    marker = "switch r.Selector {"
    assert marker in text
    text = text.replace(marker, marker + '''
case "library/fastls/2/any/update-demo":
 s=library.FastlsPortable(false);s.ID=r.Selector;s.Metadata.Variant="update-demo"
case "library/fastls/2/any/unsupported-demo":
 s=library.FastlsPortable(false);s.ID=r.Selector;s.Metadata.Variant="unsupported-demo";s.Capabilities.RequiredFeatures=append(s.Capabilities.RequiredFeatures,"future.algorithm.v99")
''', 1)
    native.write_text(text, encoding="utf-8")
    provider = variant / "provider.go"; provider.write_text(provider.read_text(encoding="utf-8").replace('Version = "0.1.0-dev.20261023.8"', 'Version = "0.1.0-dev.20261023.8.1"'), encoding="utf-8")
    version_b = VERSION + ".1"
    pack(variant, "github.com/FastTLS/imitate", version_b, out / "proxy")
    probe = work / "upgrade-probe"; probe.mkdir(exist_ok=True)
    (probe / "main.go").write_text('''package main
import("encoding/json";"io";"os";"runtime/debug"; f "github.com/FastTLS/fastls";"github.com/FastTLS/fastls/imitate";g "github.com/FastTLS/imitate")
func main(){o:=f.Options{Timeout:5};m,e:=imitate.Use(&o,os.Getenv("TEST_SELECTOR"),imitate.WithProvider(g.New()));out:=map[string]any{"match":m};if e!=nil{out["error"]=e.Error()}else{target:=os.Getenv("TEST_URL");r,e:=f.NewClient().Do(target+"/inspect",o,"GET");if e!=nil{panic(e)};io.Copy(io.Discard,r.Body);r.Body.Close();r.Client.CloseIdleConnections();out["status"]=r.Status};b,_:=debug.ReadBuildInfo();out["build"]=b;json.NewEncoder(os.Stdout).Encode(out)}
''', encoding="utf-8")
    executable = work / ("lab-upgrade.exe" if os.name == "nt" else "lab-upgrade")
    run(["go", "build", "-o", str(executable), "."], ROOT / "fastls-lab", env)
    lab = subprocess.Popen([str(executable), "-output", str(work / "upgrade-lab")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        manifest = json.loads(lab.stdout.readline())
        test_env = dict(env, TEST_URL=manifest["https"].replace("127.0.0.1", "localhost"), TEST_SELECTOR="library/fastls/2/any/update-demo")
        def probe_version(version, selector):
            (probe / "go.mod").write_text(f"module upgrade-probe\n\ngo 1.24\nrequire (\ngithub.com/FastTLS/fastls {VERSION}\ngithub.com/FastTLS/imitate {version}\n)\n", encoding="utf-8")
            return json.loads(run(["go", "run", "."], probe, dict(test_env, TEST_SELECTOR=selector)).splitlines()[-1])
        a = probe_version(VERSION, test_env["TEST_SELECTOR"])
        b = probe_version(version_b, test_env["TEST_SELECTOR"])
        unsupported = probe_version(version_b, "library/fastls/2/any/unsupported-demo")
        assert "unknown profile" in a["error"] and b["status"] == 200 and "unsupported profile feature" in unsupported["error"]
        fixed_a={d["Path"]:(d["Version"],d.get("Sum")) for d in a["build"]["Deps"] if d["Path"]!="github.com/FastTLS/imitate"}
        fixed_b={d["Path"]:(d["Version"],d.get("Sum")) for d in b["build"]["Deps"] if d["Path"]!="github.com/FastTLS/imitate"}
        assert fixed_a==fixed_b
        after = {name: digest(ROOT / name) for name in before}
        assert before == after
        save(out / "generator-only-update.json", {"status": "pass", "fixed_sources_before": before, "fixed_sources_after": after, "generator_A": a, "generator_B": b, "unsupported": unsupported, "lab": manifest})
    finally:
        lab.terminate(); lab.wait(timeout=10)
    print("generator-only real module update and handshake passed")


def main():
    global ACTIVE_OUT
    p = argparse.ArgumentParser(__doc__); p.add_argument("--all", action="store_true"); p.add_argument("--network-bootstrap",action="store_true"); p.add_argument("--skip-consumer",action="store_true"); p.add_argument("--public-matrix",action="store_true"); p.add_argument("--cross-build",choices=["linux"]); p.add_argument("--graphs", action="store_true"); p.add_argument("--upgrade", action="store_true"); p.add_argument("--race"); p.add_argument("--race-canary",action="store_true"); p.add_argument("--output", type=Path)
    p.add_argument("--gost", type=Path, help="GOST executable: require real anonymous/authenticated proxy matrix in integration tests")
    a = p.parse_args()
    if a.gost:
        gost = a.gost.resolve()
        if not gost.is_file():
            p.error("--gost must point to an existing GOST executable")
        os.environ["GOST_BIN"] = str(gost)
    (ROOT / "reports").mkdir(exist_ok=True)
    out = a.output or (Path(os.environ["FASTLS_IMITATE_RUN"]) if "FASTLS_IMITATE_RUN" in os.environ else Path(tempfile.mkdtemp(prefix="imitate-acceptance-", dir=ROOT / "reports")))
    out = out.resolve(); out.mkdir(parents=True, exist_ok=True)
    ACTIVE_OUT=out
    if a.cross_build:
        env=dict(os.environ,GOWORK="off",GOOS=a.cross_build,GOARCH="amd64",CGO_ENABLED="0")
        evidence=[]
        for relative,pattern in [("fastls/profile","./..."),("imitate","./..."),("fastls","./..."),("fastls/integration/imitate","./..."),("fastls-lab","./..."),("fhttp","./http2")]:
            target=out / "cross-linux" / relative.replace("/","_");target.mkdir(parents=True,exist_ok=True)
            log=run(["go","test","-c","-o",str(target),pattern],ROOT / relative,env)
            evidence.append({"module":relative,"target":"linux/amd64","status":"compiled","executed":False,"log":log})
        save(out / "linux-cross-build.json",evidence);print("Linux test binaries compiled; no Linux execution claimed");return
    if a.race or a.race_canary:
        env = dict(os.environ, GOWORK="off", CGO_ENABLED="1")
        zig = ROOT / "reports/imitate-implementation/toolchain/zig-x86_64-windows-0.14.1/zig.exe"
        flags=[]
        if os.name == "nt" and zig.exists():
            env["CC"] = f"{zig.as_posix()} cc -target x86_64-windows.win10-gnu"
            env["CGO_LDFLAGS"] = "-lapi-ms-win-core-synch-l1-2-0"
        if os.name=="nt":
            wrapper=CORE / "scripts/race-exec.py"
            flags=['-exec="'+sys.executable.replace('\\','/')+'" "'+wrapper.as_posix()+'"']
        if a.race_canary:
            canary=out / "race-canary";canary.mkdir(exist_ok=True)
            (canary / "go.mod").write_text("module race-canary\n\ngo 1.24\n",encoding="utf-8")
            (canary / "main.go").write_text('package main;import "sync";func main(){var x int;var w sync.WaitGroup;w.Add(2);go func(){defer w.Done();x=1}();go func(){defer w.Done();x=2}();w.Wait();_=x}',encoding="utf-8")
            result=subprocess.run(["go","run","-race",*flags,"."],cwd=canary,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding="utf-8",errors="replace",timeout=180)
            assert result.returncode!=0 and "WARNING: DATA RACE" in result.stdout,result.stdout
            (out / "race-canary.log").write_text(result.stdout,encoding="utf-8")
            print("race detector canary correctly detected an intentional race");return
        print(run(["go", "test", "-race", "-count=1",*flags,"./..."], ROOT / a.race, env)); return
    if a.graphs or a.upgrade:
        env = dict(os.environ, GOWORK="off")
        if a.graphs: graph_checks(out, env)
        if a.upgrade: upgrade_checks(out, env)
        return
    env = prepare(out,a.network_bootstrap)
    if a.gost:
        save(out / "proxy-tool.json", {"binary": str(gost), "sha256": hashlib.sha256(gost.read_bytes()).hexdigest(), "version": run([str(gost), "-V"], ROOT).strip(), "scope": "local HTTP/HTTPS/SOCKS5/SOCKS5h; anonymous/correct/missing/wrong credentials"})
    if not a.all:
        print(out); return
    graph_checks(out, env); upgrade_checks(out, env)
    plan = json.loads((CORE / "scripts/check-imitate-plan.json").read_text(encoding="utf-8"))
    if a.public_matrix:
        prefixes=("core.","profile.","generator.","integration.","fhttp.","race.","fastls-lab.","legacy.","linux.")
        skipped=[step for step in plan["steps"] if not step["id"].startswith(prefixes) and step["command"] and not step["id"].startswith("consumer.")]
        plan["steps"]=[step for step in plan["steps"] if step not in skipped]
        plan["excluded"].extend({"path":step["directory"],"reason":"previous-stage service/tool outside the public imitate matrix"} for step in skipped)
        for step in plan["steps"]:
            if step["id"]=="linux.runtime" and sys.platform.startswith("linux"):step.update(command=["go","version"],required=True)
    if a.skip_consumer:
        for step in plan["steps"]:
            if step["id"].startswith("consumer."):step.update(command=[],required=False,reason="private consumer checkout unavailable on public CI; local acceptance is reported separately")
    save(out / "plan.json", plan)
    executable = out / ("fastls-check.exe" if os.name == "nt" else "fastls-check")
    run(["go", "build", "-o", str(executable), "."], CORE / "tools/fastls-check", env)
    result = subprocess.run([str(executable), "-root", str(CORE), "-plan", str(out / "plan.json"), "-output", str(out / "checks"), "-timeout", "5m", "-total-timeout", "45m"], cwd=CORE, env=env)
    print("acceptance evidence:", out)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        out=ACTIVE_OUT or ROOT / "reports"
        out.mkdir(parents=True,exist_ok=True)
        failure=write_failure(out,error)
        print(str(error),file=sys.stderr)
        print("Failure report:",failure / "report.html",file=sys.stderr)
        raise SystemExit(2)
