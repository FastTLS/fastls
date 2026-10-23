// fastls-check executes a versioned, explicit check plan and rebuilds offline reports.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Step struct {
	ID        string   `json:"id"`
	TaskID    string   `json:"task_id"`
	Category  string   `json:"category"`
	Directory string   `json:"directory"`
	Command   []string `json:"command"`
	Required  bool     `json:"required"`
	DependsOn []string `json:"depends_on,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}
type Plan struct {
	SchemaVersion int         `json:"schema_version"`
	Name          string      `json:"name"`
	Steps         []Step      `json:"steps"`
	Excluded      []Exclusion `json:"excluded"`
}
type Exclusion struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}
type Result struct {
	Step       Step   `json:"step"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code,omitempty"`
	Message    string `json:"message,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Log        string `json:"log,omitempty"`
}
type Report struct {
	SchemaVersion int         `json:"report_schema_version"`
	RunID         string      `json:"run_id"`
	Suite         string      `json:"suite"`
	StartedAt     time.Time   `json:"started_at"`
	FinishedAt    time.Time   `json:"finished_at"`
	Results       []Result    `json:"results"`
	Excluded      []Exclusion `json:"excluded"`
}
type Source struct {
	Directory string `json:"directory"`
	Head      string `json:"head"`
	Branch    string `json:"branch"`
	Status    string `json:"status"`
}
type Manifest struct {
	Filter            string    `json:"filter,omitempty"`
	PerCheckTimeoutMS int64     `json:"per_check_timeout_ms"`
	TotalTimeoutMS    int64     `json:"total_timeout_ms"`
	EffectiveModules  string    `json:"effective_modules"`
	SchemaVersion     int       `json:"schema_version"`
	RunID             string    `json:"run_id"`
	Suite             string    `json:"suite"`
	StartedAt         time.Time `json:"started_at"`
	DisplayTimezone   string    `json:"display_timezone"`
	Platform          string    `json:"platform"`
	GoVersion         string    `json:"go_version"`
	GoEnv             string    `json:"go_environment"`
	Plan              Plan      `json:"plan"`
	Sources           []Source  `json:"sources"`
}

func decode(path string, target any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(target); err != nil {
		return err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}
func validate(p Plan) error {
	if p.SchemaVersion != 1 {
		return errors.New("unsupported plan schema")
	}
	if len(p.Steps) == 0 {
		return errors.New("plan has no checks")
	}
	seen := map[string]bool{}
	for _, s := range p.Steps {
		if s.ID == "" || strings.ContainsAny(s.ID, "/\\:") || s.ID == ".." || seen[s.ID] {
			return fmt.Errorf("invalid or duplicate check ID %q", s.ID)
		}
		for _, dep := range s.DependsOn {
			if !seen[dep] {
				return fmt.Errorf("%s: dependency %s must precede check", s.ID, dep)
			}
		}
		if len(s.Command) == 0 && s.Reason == "" {
			return fmt.Errorf("%s: no command or explicit reason", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}
func atomicWrite(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".check-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(b, '\n'))
}
func environment() []string {
	result := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "GOWORK=") {
			result = append(result, v)
		}
	}
	return append(result, "GOWORK=off")
}
func metadata(ctx context.Context, dir string, args ...string) string {
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Dir = dir
	c.Env = environment()
	b, err := c.CombinedOutput()
	if err != nil {
		return "unavailable: " + err.Error() + "\n" + string(b)
	}
	return strings.TrimSpace(string(b))
}

func execute(ctx context.Context, root, out string, s Step, timeout time.Duration) Result {
	r := Result{Step: s, Status: "not_run"}
	if len(s.Command) == 0 {
		r.ReasonCode = "not_implemented"
		r.Message = s.Reason
		return r
	}
	if ctx.Err() != nil {
		r.ReasonCode = "cancelled"
		r.Message = ctx.Err().Error()
		return r
	}
	dir := s.Directory
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		r.Status = "error"
		r.ReasonCode = "blocked_environment"
		r.Message = "missing module directory: " + s.Directory
		return r
	}
	logName := filepath.Join("logs", s.ID+".log")
	logFile, err := os.Create(filepath.Join(out, logName))
	if err != nil {
		r.Status = "error"
		r.ReasonCode = "runner_error"
		r.Message = err.Error()
		return r
	}
	defer logFile.Close()
	r.Log = filepath.ToSlash(logName)
	childCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(childCtx, s.Command[0], s.Command[1:]...)
	c.Dir = dir
	c.Env = environment()
	c.Stdout = logFile
	c.Stderr = logFile
	configureProcess(c)
	start := time.Now()
	err = c.Run()
	r.DurationMS = time.Since(start).Milliseconds()
	if childCtx.Err() != nil {
		r.Status = "error"
		r.ReasonCode = "cancelled_or_timeout"
		r.Message = childCtx.Err().Error()
		return r
	}
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
			r.Status = "fail"
			r.ReasonCode = "command_failed"
		} else {
			r.Status = "error"
			r.ReasonCode = "blocked_environment"
			r.Message = err.Error()
			return r
		}
		r.Message = err.Error()
	} else {
		r.Status = "pass"
	}
	r.ExitCode = &code
	return r
}

func exitCode(results []Result) int {
	code := 0
	for _, r := range results {
		if !r.Step.Required {
			continue
		}
		switch r.Status {
		case "error":
			return 2
		case "fail":
			code = 1
		case "skip", "not_run":
			if code == 0 {
				code = 3
			}
		}
	}
	return code
}
func checkReport(r Report) error {
	if r.SchemaVersion != 1 {
		return errors.New("unsupported report schema")
	}
	if len(r.Results) == 0 {
		return errors.New("report has no results")
	}
	seen := map[string]bool{}
	for _, item := range r.Results {
		if seen[item.Step.ID] || item.Step.ID == "" {
			return errors.New("duplicate or empty result ID")
		}
		seen[item.Step.ID] = true
		switch item.Status {
		case "pass", "fail", "skip", "error", "not_run":
		default:
			return fmt.Errorf("invalid result status %s", item.Status)
		}
		if item.Log != "" && (filepath.IsAbs(item.Log) || strings.Contains(item.Log, "\\") || strings.Contains(item.Log, ":") || strings.Contains(item.Log, "..")) {
			return errors.New("invalid evidence path")
		}
	}
	return nil
}

func startupFailure(root, output, suite string, cause error) int {
	fmt.Fprintln(os.Stderr, cause)
	if !filepath.IsAbs(output) {
		output = filepath.Join(root, output)
	}
	if err := os.MkdirAll(output, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	started := time.Now().UTC()
	dir, err := os.MkdirTemp(output, started.Format("20060102T150405Z")+"-startup-error-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	r := Report{SchemaVersion: 1, RunID: filepath.Base(dir), Suite: suite, StartedAt: started, FinishedAt: time.Now().UTC(), Results: []Result{{Step: Step{ID: "runner.startup", TaskID: "T01", Category: "runner", Required: true}, Status: "error", ReasonCode: "invalid_plan", Message: cause.Error()}}}
	if err = saveJSON(filepath.Join(dir, "results.json"), r); err == nil {
		err = saveJSON(filepath.Join(dir, "run-manifest.json"), Manifest{SchemaVersion: 1, RunID: r.RunID, Suite: suite, StartedAt: started, DisplayTimezone: "Asia/Shanghai", Platform: runtime.GOOS + "/" + runtime.GOARCH})
	}
	if err == nil {
		err = render(dir, r)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		fmt.Println("Report:", filepath.Join(dir, "report.html"))
	}
	return 2
}

func run(args []string) int {
	flags := flag.NewFlagSet("fastls-check", flag.ContinueOnError)
	root := flags.String("root", ".", "core repository root")
	planPath := flags.String("plan", "scripts/check-plan.json", "versioned local plan (paths relative to root)")
	output := flags.String("output", "../reports", "output parent, relative to root")
	suite := flags.String("suite", "offline", "stage suite; offline is currently implemented")
	filter := flags.String("filter", "", "substring filter; required omitted checks remain incomplete")
	reportOnly := flags.String("report-only", "", "rebuild a saved results.json without executing checks")
	timeout := flags.Duration("timeout", 90*time.Second, "per-check deadline")
	total := flags.Duration("total-timeout", 15*time.Minute, "entire run deadline")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		return 2
	}
	if *reportOnly != "" {
		var r Report
		if err := decode(*reportOnly, &r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := checkReport(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := render(filepath.Dir(*reportOnly), r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return exitCode(r.Results)
	}
	if *suite != "offline" {
		fmt.Fprintln(os.Stderr, "suite not implemented:", *suite)
		return 2
	}
	if *timeout <= 0 || *total <= 0 {
		fmt.Fprintln(os.Stderr, "timeouts must be positive")
		return 2
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ppath := *planPath
	if !filepath.IsAbs(ppath) {
		ppath = filepath.Join(absRoot, ppath)
	}
	var plan Plan
	if err = decode(ppath, &plan); err != nil {
		return startupFailure(absRoot, *output, *suite, err)
	}
	if err = validate(plan); err != nil {
		return startupFailure(absRoot, *output, *suite, err)
	}
	out := *output
	if !filepath.IsAbs(out) {
		out = filepath.Join(absRoot, out)
	}
	// A random directory suffix prevents overwriting previous and concurrent runs.
	if err = os.MkdirAll(out, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	started := time.Now().UTC()
	out, err = os.MkdirTemp(out, started.Format("20060102T150405Z")+"-offline-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err = os.MkdirAll(filepath.Join(out, "logs"), 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	base, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(base, *total)
	defer cancel()
	m := Manifest{SchemaVersion: 1, RunID: filepath.Base(out), Suite: *suite, StartedAt: started, DisplayTimezone: "Asia/Shanghai", Platform: runtime.GOOS + "/" + runtime.GOARCH, Plan: plan}
	m.Filter = *filter
	m.PerCheckTimeoutMS = timeout.Milliseconds()
	m.TotalTimeoutMS = total.Milliseconds()
	metaCtx, metaCancel := context.WithTimeout(ctx, 15*time.Second)
	m.EffectiveModules = metadata(metaCtx, absRoot, "go", "list", "-m", "-json", "all")
	m.GoVersion = metadata(metaCtx, absRoot, "go", "version")
	m.GoEnv = metadata(metaCtx, absRoot, "go", "env", "CGO_ENABLED", "GOWORK", "GOTOOLCHAIN")
	dirs := map[string]bool{absRoot: true}
	for _, s := range plan.Steps {
		d := s.Directory
		if !filepath.IsAbs(d) {
			d = filepath.Join(absRoot, d)
		}
		dirs[d] = true
	}
	sorted := []string{}
	for d := range dirs {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)
	for _, d := range sorted {
		m.Sources = append(m.Sources, Source{Directory: d, Head: metadata(metaCtx, d, "git", "rev-parse", "HEAD"), Branch: metadata(metaCtx, d, "git", "branch", "--show-current"), Status: metadata(metaCtx, d, "git", "status", "--short")})
	}
	metaCancel()
	if err = saveJSON(filepath.Join(out, "run-manifest.json"), m); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	r := Report{SchemaVersion: 1, RunID: m.RunID, Suite: *suite, StartedAt: started, Excluded: plan.Excluded}
	states := map[string]string{}
	for _, s := range plan.Steps {
		item := Result{Step: s, Status: "not_run"}
		blocked := ""
		for _, dep := range s.DependsOn {
			if states[dep] != "pass" {
				blocked = dep
				break
			}
		}
		switch {
		case *filter != "" && !strings.Contains(s.ID, *filter):
			item.ReasonCode = "excluded_by_configuration"
			item.Message = "filtered out"
		case blocked != "":
			item.ReasonCode = "not_run_dependency"
			item.Message = blocked
		default:
			item = execute(ctx, absRoot, out, s, *timeout)
		}
		states[s.ID] = item.Status
		r.Results = append(r.Results, item)
		r.FinishedAt = time.Now().UTC()
		// Persist the unfinished plan too: interruption never silently drops pending checks.
		snapshot := r
		snapshot.Results = append([]Result(nil), r.Results...)
		for _, pending := range plan.Steps[len(r.Results):] {
			snapshot.Results = append(snapshot.Results, Result{Step: pending, Status: "not_run", ReasonCode: "pending"})
		}
		if err = saveJSON(filepath.Join(out, "results.json"), snapshot); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err = render(out, snapshot); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Printf("%s %s\n", item.Status, s.ID)
	}
	fmt.Println("Report:", filepath.Join(out, "report.html"))
	return exitCode(r.Results)
}
func main() { os.Exit(run(os.Args[1:])) }
