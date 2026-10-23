package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/FastTLS/fastls/profile"
	generators "github.com/FastTLS/imitate"
	"github.com/FastTLS/imitate/library"
)

var lab struct{ HTTP, HTTPS, HTTPS2, Management string }
var workspace string

func TestMain(m *testing.M) {
	_, file, _, _ := runtime.Caller(0)
	workspace = filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
	dir, err := os.MkdirTemp(filepath.Join(workspace, "reports"), "imitate-wire-")
	if err != nil {
		panic(err)
	}
	exe := filepath.Join(dir, "lab")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	build := exec.Command("go", "build", "-o", exe, ".")
	build.Dir = filepath.Join(workspace, "fastls-lab")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintln(os.Stderr, string(out), err)
		os.Exit(2)
	}
	cmd := exec.Command(exe, "-output", filepath.Join(dir, "capture"))
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		panic(err)
	}
	done := make(chan error, 1)
	go func() { done <- json.NewDecoder(pipe).Decode(&lab) }()
	select {
	case err = <-done:
	case <-time.After(20 * time.Second):
		err = errors.New("lab startup timeout")
	}
	if err != nil {
		cmd.Process.Kill()
		panic(err)
	}
	fmt.Println("independent wire evidence:", dir)
	code := m.Run()
	cmd.Process.Kill()
	cmd.Wait()
	os.Exit(code)
}

type event struct {
	ConnectionID string          `json:"connection_id"`
	Type         string          `json:"type"`
	Data         json.RawMessage `json:"data"`
}

func events(t *testing.T) []event {
	t.Helper()
	c := http.Client{Timeout: 5 * time.Second}
	r, err := c.Get(lab.Management + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var e []event
	if err = json.NewDecoder(r.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	return e
}
func request(t *testing.T, o fastls.Options, url string) {
	t.Helper()
	o.Timeout = 5
	r, err := fastls.NewClient().Do(strings.Replace(url, "127.0.0.1", "localhost", 1)+"/inspect", o, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Client.CloseIdleConnections()
	defer r.Body.Close()
	io.Copy(io.Discard, r.Body)
	if r.Status != 200 {
		t.Fatal(r.Status)
	}
}
func TestNativeAndEditedSpecOnIndependentLab(t *testing.T) {
	for _, id := range []string{"library/fastls/2/any/portable-h1", "client/fastls-probe/1/any/portable-h1"} {
		o := fastls.Options{}
		m, err := imitate.Use(&o, id, imitate.WithProvider(generators.New()))
		if err != nil {
			t.Fatal(err)
		}
		if o.Profile == nil || o.Fingerprint != nil || m.Kind == "browser" {
			t.Fatal("native kind did not execute full Spec")
		}
		request(t, o, lab.HTTPS)
	}
	s := library.FastlsPortable(false)
	s.TLS.CipherSuites = []profile.Code{0x1303, 0x1301, 0xc02b}
	s.TLS.Extensions[1], s.TLS.Extensions[2] = s.TLS.Extensions[2], s.TLS.Extensions[1]
	s.Headers.Defaults = []profile.Header{{Name: "X-Second", Values: []string{"two", "again"}}, {Name: "X-First", Values: []string{"one"}}}
	s.Headers.Order = []string{"host", "x-second", "x-first", "user-agent"}
	before := len(events(t))
	o := fastls.Options{}
	if _, err := imitate.Apply(&o, s); err != nil {
		t.Fatal(err)
	}
	// Mutating the source after application cannot change the request.
	s.TLS.CipherSuites[0] = 0x1302
	s.Headers.Defaults[0].Values[0] = "changed"
	request(t, o, lab.HTTPS)
	e := events(t)[before:]
	helloFound, headersFound := false, false
	for _, ev := range e {
		switch ev.Type {
		case "tls.client_hello":
			var h struct {
				CipherSuites []uint16 `json:"cipher_suites"`
				Extensions   []struct {
					ID uint16 `json:"id"`
				} `json:"extensions"`
			}
			if err := json.Unmarshal(ev.Data, &h); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(h.CipherSuites, []uint16{0x1303, 0x1301, 0xc02b}) {
				t.Fatalf("edited suites not sent: %v", h.CipherSuites)
			}
			want := []uint16{0, 65281, 23, 10, 11, 13, 16, 43, 51, 45}
			ids := []uint16{}
			for _, x := range h.Extensions {
				ids = append(ids, x.ID)
			}
			if !slices.Equal(ids, want) {
				t.Fatalf("extension order not sent: %v", ids)
			}
			helloFound = true
		case "http1.headers":
			var h struct {
				Headers []struct{ Name, Value string }
			}
			if err := json.Unmarshal(ev.Data, &h); err != nil {
				t.Fatal(err)
			}
			filtered := []string{}
			for _, f := range h.Headers {
				if strings.HasPrefix(strings.ToLower(f.Name), "x-") {
					filtered = append(filtered, strings.ToLower(f.Name)+"="+f.Value)
				}
			}
			if !slices.Equal(filtered, []string{"x-second=two", "x-second=again", "x-first=one"}) {
				t.Fatalf("ordered repeated headers not sent: %v", filtered)
			}
			headersFound = true
		}
	}
	if !helloFound || !headersFound {
		t.Fatal("missing independent observations")
	}
}
func TestHTTP2OrderedSettingsAndHeaders(t *testing.T) {
	s := library.FastlsPortable(true)
	s.HTTP2.Settings = []profile.Setting{{ID: 4, Value: 524288}, {ID: 1, Value: 8192}, {ID: 2, Value: 0}, {ID: 6, Value: 131072}}
	s.HTTP2.ConnectionFlow = 2000000
	s.HTTP2.HeaderPriority = &profile.Priority{Dependency: 0, Weight: 42, Exclusive: true}
	s.HTTP2.PriorityFrames = []profile.Priority{{StreamID: 3, Dependency: 0, Weight: 100}}
	s.Headers.PseudoOrder = []string{":path", ":method", ":scheme", ":authority"}
	s.Headers.Defaults = append(s.Headers.Defaults, profile.Header{Name: "X-Wire", Values: []string{"first", "second"}})
	s.Headers.Order = []string{"x-wire", "accept", "user-agent"}
	before := len(events(t))
	request(t, fastls.Options{Profile: &s}, lab.HTTPS2)
	seen := map[string]bool{}
	for _, e := range events(t)[before:] {
		switch e.Type {
		case "http2.settings":
			var v []profile.Setting
			if err := json.Unmarshal(e.Data, &v); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(v, s.HTTP2.Settings) {
				t.Fatalf("settings changed: %s", e.Data)
			}
			seen[e.Type] = true
		case "http2.window_update":
			var v struct{ Increment uint32 }
			json.Unmarshal(e.Data, &v)
			if v.Increment != s.HTTP2.ConnectionFlow {
				t.Fatalf("flow changed: %s", e.Data)
			}
			seen[e.Type] = true
		case "http2.header_priority":
			var v struct{ Weight uint16 }
			json.Unmarshal(e.Data, &v)
			if v.Weight != 42 {
				t.Fatal("header priority changed")
			}
			seen[e.Type] = true
		case "http2.priority":
			seen[e.Type] = true
		case "http2.headers":
			var v struct {
				Headers []struct{ Name, Value string }
			}
			json.Unmarshal(e.Data, &v)
			names := []string{}
			for _, h := range v.Headers {
				names = append(names, h.Name)
			}
			if len(names) < 6 || !slices.Equal(names[:4], s.Headers.PseudoOrder) || names[4] != "x-wire" || names[5] != "x-wire" {
				t.Fatalf("H2 header order changed: %v", names)
			}
			seen[e.Type] = true
		}
	}
	for _, kind := range []string{"http2.settings", "http2.window_update", "http2.headers", "http2.header_priority", "http2.priority"} {
		if !seen[kind] {
			t.Fatalf("missing %s", kind)
		}
	}
}

type addedProvider struct {
	base        profile.Provider
	unsupported bool
}

func (p addedProvider) Resolve(ctx context.Context, r profile.ResolveRequest) (profile.Resolution, error) {
	if r.Selector != "library/extension-demo/1/any/portable-h1" {
		return p.base.Resolve(ctx, r)
	}
	s := library.FastlsPortable(false)
	s.ID = r.Selector
	s.Metadata.Product = "extension-demo"
	s.Metadata.ProductVersion = "1"
	if p.unsupported {
		s.Capabilities.RequiredFeatures = append(s.Capabilities.RequiredFeatures, "future.algorithm.v99")
	}
	return profile.Resolution{Spec: &s, Match: profile.Match{ProfileID: s.ID, ProviderID: "generator-update-experiment", ProviderVersion: "candidate-B", DataRevision: "B", ContractVersion: profile.ContractVersion}}, nil
}
func TestGeneratorOnlyUpdateAndUnsupported(t *testing.T) {
	const id = "library/extension-demo/1/any/portable-h1"
	o := fastls.Options{Headers: map[string]string{"X-Business": "preserved"}}
	if _, err := imitate.Use(&o, id, imitate.WithProvider(generators.New())); !errors.Is(err, profile.ErrUnknownProfile) {
		t.Fatal("candidate A unexpectedly supported", err)
	}
	if _, err := imitate.Use(&o, id, imitate.WithProvider(addedProvider{base: generators.New()})); err != nil {
		t.Fatal(err)
	}
	request(t, o, lab.HTTPS)
	before := o
	if _, err := imitate.Use(&o, id, imitate.WithProvider(addedProvider{base: generators.New(), unsupported: true})); !errors.Is(err, profile.ErrUnsupportedFeature) {
		t.Fatal("unsupported capability did not fail", err)
	}
	if !reflect.DeepEqual(o, before) {
		t.Fatal("unsupported capability mutated options")
	}
}
func TestGeneratorConcurrency(t *testing.T) {
	p := generators.New()
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := fastls.Options{}
			if _, err := imitate.Use(&o, "chrome/155/windows", imitate.WithProvider(p)); err != nil {
				t.Error(err)
			}
			o.Headers["X-Local"] = "owned"
		}()
	}
	wg.Wait()
}

func TestWebSocketAndWSSObserveTLS(t *testing.T) {
	for _, secure := range []bool{false, true} {
		s := library.FastlsPortable(false)
		s.Headers.Order = nil
		before := len(events(t))
		client := fastls.NewWebSocketClientWithOptions(fastls.Options{Profile: &s, Headers: map[string]string{"User-Agent": "custom-ws-agent", "X-Caller": "keep"}})
		target := lab.HTTP
		if secure {
			target = lab.HTTPS
		}
		target = strings.Replace(target, "127.0.0.1", "localhost", 1)
		conn, response, err := client.Connect(target + "/ws")
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 101 {
			t.Fatal(response.StatusCode)
		}
		if err = conn.WriteMessage(1, []byte("lab-only")); err != nil {
			t.Fatal(err)
		}
		_, message, err := conn.ReadMessage()
		if err != nil || string(message) != "lab-only" {
			t.Fatal(string(message), err)
		}
		conn.Close()
		observedUpgrade, observedTLS := false, false
		for _, ev := range events(t)[before:] {
			if ev.Type == "http1.headers" && strings.Contains(string(ev.Data), "Upgrade") {
				observedUpgrade = true
				if !strings.Contains(string(ev.Data), "custom-ws-agent") || !strings.Contains(string(ev.Data), "keep") {
					t.Fatal("WS override lost", string(ev.Data))
				}
			}
			if ev.Type == "tls.client_hello" {
				observedTLS = true
			}
		}
		if !observedUpgrade || secure && !observedTLS {
			t.Fatal("missing WS/WSS evidence")
		}
	}
	s := library.FastlsPortable(true)
	_, _, err := fastls.NewWebSocketClientWithOptions(fastls.Options{Profile: &s}).Connect(lab.HTTPS + "/ws")
	if !errors.Is(err, profile.ErrUnsupportedFeature) {
		t.Fatal("explicit unsupported WS order/ALPN ignored", err)
	}
}
func TestExplicitEmptyHTTP2DoesNotInventParameters(t *testing.T) {
	s := library.FastlsPortable(true)
	s.HTTP2 = profile.HTTP2Config{}
	before := len(events(t))
	request(t, fastls.Options{Profile: &s}, lab.HTTPS2)
	settings, headers := false, false
	for _, ev := range events(t)[before:] {
		switch ev.Type {
		case "http2.settings":
			if string(ev.Data) != "[]" {
				t.Fatalf("invented settings: %s", ev.Data)
			}
			settings = true
		case "http2.window_update", "http2.priority", "http2.header_priority":
			t.Fatalf("invented frame: %s", ev.Type)
		case "http2.headers":
			headers = true
		}
	}
	if !settings || !headers {
		t.Fatal("missing empty SETTINGS/request")
	}
}

func TestExportedBundleRunsWithoutGeneratorProvider(t *testing.T) {
	b, err := generators.New().Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := imitate.Register(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Aliases) != 0 {
		t.Fatalf("export omitted aliases: %d", len(b.Aliases))
	}
	for _, id := range []string{"chrome/155/windows", "chrome/156/windows", "client/fastls-probe/1/any/portable-h1"} {
		o := fastls.Options{}
		if _, err := imitate.Use(&o, id, imitate.WithProvider(p)); err != nil {
			t.Fatal(err)
		}
		request(t, o, lab.HTTPS)
	}
	a, err := generators.New().Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(b)
	second, _ := json.Marshal(a)
	if string(first) != string(second) {
		t.Fatal("export is not reproducible")
	}
}

func TestNativeLibraryDoesNotInventUserAgent(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		s := library.FastlsPortable(h2)
		before := len(events(t))
		target := lab.HTTPS
		if h2 {
			target = lab.HTTPS2
		}
		request(t, fastls.Options{Profile: &s}, target)
		count := 0
		for _, e := range events(t)[before:] {
			if e.Type != "http1.headers" && e.Type != "http2.headers" {
				continue
			}
			count++
			var data struct {
				Headers []struct{ Name, Value string }
			}
			if err := json.Unmarshal(e.Data, &data); err != nil {
				t.Fatal(err)
			}
			for _, h := range data.Headers {
				if strings.EqualFold(h.Name, "user-agent") {
					t.Fatal("absent identity was replaced with a User-Agent", h.Value)
				}
			}
		}
		if count != 1 {
			t.Fatal("missing HTTP identity observation")
		}
	}
}

func TestExplicitTLSVersionsExecuteOnLab(t *testing.T) {
	for _, version := range []profile.Code{0x0303, 0x0304} {
		s := library.FastlsPortable(false)
		s.TLS.MinVersion = version
		s.TLS.MaxVersion = version
		s.TLS.RecordVersion = 0x0301
		s.TLS.LegacyVersion = 0x0303
		if version == 0x0303 {
			s.TLS.CipherSuites = []profile.Code{0xc02b, 0xc02f}
		} else {
			s.TLS.CipherSuites = []profile.Code{0x1301, 0x1302}
		}
		for i := range s.TLS.Extensions {
			if s.TLS.Extensions[i].ID == 43 {
				s.TLS.Extensions[i].Versions = []profile.Code{version}
			}
		}
		before := len(events(t))
		request(t, fastls.Options{Profile: &s}, lab.HTTPS)
		found := false
		for _, e := range events(t)[before:] {
			if e.Type != "tls.negotiated" {
				continue
			}
			var data struct{ Version uint16 }
			if err := json.Unmarshal(e.Data, &data); err != nil {
				t.Fatal(err)
			}
			if data.Version != uint16(version) {
				t.Fatalf("TLS version ignored: got %x want %x", data.Version, version)
			}
			found = true
		}
		if !found {
			t.Fatal("missing negotiated TLS evidence")
		}
	}
}
