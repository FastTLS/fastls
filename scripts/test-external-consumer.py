"""Verify Fastls from immutable remote commits without a workspace or replace."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "scripts" / "external-consumer-dependencies.json"
SHA = re.compile(r"[0-9a-f]{40}")

CONSUMER_TEST = r'''package consumer

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fastls "github.com/FastTLS/fastls"
	fastlsimitate "github.com/FastTLS/fastls/imitate"
	generators "github.com/FastTLS/imitate"
)

func TestRemoteModulesPerformRequest(t *testing.T) {
    config := &fastls.HTTP3Config{MaxResponseHeaderBytes: 2048}
    session, err := fastls.NewSession(fastls.Options{HTTPVersion: fastls.HTTPVersion3, HTTP3: config})
    if err != nil { t.Fatal(err) }
    defer session.Close()
    config.MaxResponseHeaderBytes = 4096
    effective, ok := session.EffectiveHTTP3Config()
    if !ok || effective.MaxResponseHeaderBytes != 2048 || len(fastls.HTTP3Capabilities()) != 7 { t.Fatal("H3 API/snapshot contract failed") }

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "external-consumer/1" {
			t.Fatalf("unexpected user agent %q", r.Header.Get("User-Agent"))
		}
		w.Header().Add("X-Multi", "one")
		w.Header().Add("X-Multi", "two")
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	options := fastls.Options{
		FingerprintProvider: generators.New(),
		Headers:             map[string]string{"User-Agent": "external-consumer/1"},
		Timeout:             5,
		VerifyTLS:           true,
		TLSRootCAs:          roots,
	}
	match, err := fastlsimitate.Use(&options, "client/fastls-probe/1/any/portable-h1")
	if err != nil {
		t.Fatal(err)
	}
	if match.ProfileID == "" || options.Profile == nil {
		t.Fatal("profile was not applied")
	}
	response, err := fastls.NewClient().Do(server.URL, options, http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Client.CloseIdleConnections()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unexpected response: status=%d body=%q", response.Status, body)
	}
	if len(response.HeaderValues["X-Multi"]) != 2 {
		t.Fatalf("multi-value response header was not preserved: %#v", response.HeaderValues)
	}
}
'''


def run(args, directory, env):
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=directory, env=env, check=True)


def commit(value, label):
    if not SHA.fullmatch(value or ""):
        raise RuntimeError(f"{label} must be a full lowercase commit SHA")
    return value


def main():
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    parser = argparse.ArgumentParser()
    parser.add_argument("--fastls-ref", required=True)
    parser.add_argument("--imitate-ref", default=pins["imitate_ref"])
    parser.add_argument("--direct", action="store_true", help="bypass module proxies for repository commits")
    options = parser.parse_args()
    fastls_ref = commit(options.fastls_ref, "fastls ref")
    imitate_ref = commit(options.imitate_ref, "imitate ref")

    env = os.environ.copy()
    env["GOWORK"] = "off"
    env.pop("GOFLAGS", None)
    if options.direct:
        env["GOPROXY"] = "direct"
        # Direct mode validates GitHub's immutable refs rather than the public
        # proxy/sumdb view, which can retain a negative result after a new tag.
        env["GONOSUMDB"] = "github.com/FastTLS/*"

    with tempfile.TemporaryDirectory(prefix="fastls-external-consumer-") as temporary:
        root = Path(temporary)
        directory = root / "consumer"
        directory.mkdir()
        # Do not let a developer or runner's shared module/build caches make a
        # remote dependency look available when it is not.
        env["GOMODCACHE"] = str(root / "modcache")
        env["GOCACHE"] = str(root / "gocache")
        (directory / "consumer_test.go").write_text(CONSUMER_TEST, encoding="utf-8", newline="\n")
        run(["go", "mod", "init", "example.com/fastls-external-consumer"], directory, env)
        run(["go", "mod", "edit", "-go=1.26.0"], directory, env)
        run(["go", "get", f"github.com/FastTLS/fastls@{fastls_ref}"], directory, env)
        run(["go", "get", f"github.com/FastTLS/imitate@{imitate_ref}"], directory, env)
        run(["go", "mod", "tidy"], directory, env)
        run(["go", "mod", "verify"], directory, env)

        go_mod = (directory / "go.mod").read_text(encoding="utf-8")
        graph = subprocess.check_output(["go", "mod", "graph"], cwd=directory, env=env, text=True)
        modules = subprocess.check_output(["go", "list", "-m", "all"], cwd=directory, env=env, text=True)
        if "replace " in go_mod:
            raise RuntimeError("clean consumer unexpectedly contains a replace directive")
        if "github.com/FastTLS/fhttp" in graph:
            raise RuntimeError("retired fhttp dependency remains in the external graph")
        for module in ("github.com/FastTLS/fastls/profile", "github.com/FastTLS/ftransport", "github.com/FastTLS/imitate"):
            if module not in modules:
                raise RuntimeError(f"external graph is missing {module}")

        run(["go", "test", "-v", "./..."], directory, env)
        run(["go", "vet", "./..."], directory, env)
        print(json.dumps({
            "success": True,
            "workspace": env["GOWORK"],
            "proxy": env.get("GOPROXY", "go env default"),
            "fastls_ref": fastls_ref,
            "imitate_ref": imitate_ref,
        }, indent=2))


if __name__ == "__main__":
    main()
