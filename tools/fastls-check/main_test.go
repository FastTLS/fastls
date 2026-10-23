package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("FASTLS_CHECK_HELPER") != "1" {
		return
	}
	switch os.Getenv("FASTLS_CHECK_HELPER_MODE") {
	case "failure":
		os.Exit(7)
	case "wait":
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func TestExecuteFailuresAndDeadline(t *testing.T) {
	t.Setenv("FASTLS_CHECK_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode, status, reason string
		deadline             time.Duration
	}{
		{"success", "pass", "", 5 * time.Second},
		{"failure", "fail", "command_failed", 5 * time.Second},
		{"wait", "error", "cancelled_or_timeout", 200 * time.Millisecond},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("FASTLS_CHECK_HELPER_MODE", tc.mode)
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "logs"), 0755); err != nil {
				t.Fatal(err)
			}
			r := execute(context.Background(), dir, dir, Step{ID: "helper", Command: []string{binary, "-test.run=^TestHelperProcess$"}, Directory: ".", Required: true}, tc.deadline)
			if r.Status != tc.status || r.ReasonCode != tc.reason {
				t.Fatalf("unexpected result: %+v", r)
			}
			if tc.mode == "failure" && (r.ExitCode == nil || *r.ExitCode != 7) {
				t.Fatalf("lost subprocess exit: %+v", r)
			}
			if tc.mode == "wait" && r.DurationMS > 5000 {
				t.Fatal("timeout did not terminate child promptly")
			}
		})
	}
	missing := execute(context.Background(), t.TempDir(), t.TempDir(), Step{ID: "missing", Directory: "does-not-exist", Command: []string{binary}, Required: true}, time.Second)
	if missing.Status != "error" || missing.ReasonCode != "blocked_environment" {
		t.Fatalf("missing directory: %+v", missing)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "logs"), 0755); err != nil {
		t.Fatal(err)
	}
	missing = execute(context.Background(), dir, dir, Step{ID: "missing-tool", Directory: ".", Command: []string{filepath.Join(dir, "nonexistent-program")}, Required: true}, time.Second)
	if missing.Status != "error" || missing.ExitCode != nil {
		t.Fatalf("startup failure invented exit code: %+v", missing)
	}
}

func TestPlanValidationAndExitPriority(t *testing.T) {
	for _, p := range []Plan{
		{SchemaVersion: 1},
		{SchemaVersion: 1, Steps: []Step{{ID: "same", Reason: "pending"}, {ID: "same", Reason: "pending"}}},
		{SchemaVersion: 1, Steps: []Step{{ID: "a", Reason: "pending", DependsOn: []string{"b"}}}},
		{SchemaVersion: 1, Steps: []Step{{ID: "../escape", Reason: "pending"}}},
	} {
		if err := validate(p); err == nil {
			t.Fatalf("accepted invalid plan: %+v", p)
		}
	}
	for _, tc := range []struct {
		statuses []string
		want     int
	}{
		{[]string{"pass"}, 0}, {[]string{"not_run"}, 3}, {[]string{"fail", "not_run"}, 1}, {[]string{"fail", "error"}, 2},
	} {
		results := []Result{}
		for _, s := range tc.statuses {
			results = append(results, Result{Step: Step{Required: true}, Status: s})
		}
		if got := exitCode(results); got != tc.want {
			t.Fatalf("%v: got %d want %d", tc.statuses, got, tc.want)
		}
	}
}

func TestReportRebuildIsOfflineAndEscapesInput(t *testing.T) {
	dir := t.TempDir()
	report := Report{SchemaVersion: 1, RunID: "fixture", Suite: "offline", Results: []Result{{Step: Step{ID: "x", Required: true, Command: []string{"this-program-must-not-execute"}}, Status: "fail", Message: "<script>alert(1)</script>"}}}
	path := filepath.Join(dir, "results.json")
	if err := saveJSON(path, report); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"-report-only", path}); got != 1 {
		t.Fatalf("report rebuild exit=%d", got)
	}
	rebuilt, _ := os.ReadFile(path)
	if string(original) != string(rebuilt) {
		t.Fatal("rebuild changed raw evidence")
	}
	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "<script>alert(1)</script>") || !strings.Contains(string(html), "&lt;script&gt;") {
		t.Fatal("unescaped HTML in report")
	}
	junit, _ := os.ReadFile(filepath.Join(dir, "junit.xml"))
	if !strings.Contains(string(junit), `failures="1"`) {
		t.Fatal("JUnit lost failure")
	}
	report.Results[0].Log = "../outside.txt"
	if err := checkReport(report); err == nil {
		t.Fatal("accepted evidence path escape")
	}
	report.SchemaVersion = 999
	if err := checkReport(report); err == nil {
		t.Fatal("accepted unsupported report version")
	}
}

func TestFilteredRunCannotPassWithNoExecutedChecks(t *testing.T) {
	dir := t.TempDir()
	plan := Plan{SchemaVersion: 1, Steps: []Step{{ID: "required", Required: true, Command: []string{"must-not-execute"}, Directory: "."}}}
	b, _ := json.Marshal(plan)
	path := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"-root", dir, "-plan", path, "-output", filepath.Join(dir, "reports"), "-filter", "absent"}); got != 3 {
		t.Fatalf("filtered run exit=%d", got)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "reports", "*", "results.json"))
	if len(files) != 1 {
		t.Fatalf("no partial results: %v", files)
	}
	var r Report
	if err := decode(files[0], &r); err != nil {
		t.Fatal(err)
	}
	if r.Results[0].Status != "not_run" {
		t.Fatal("filtered check incorrectly passed")
	}
}

func TestInvalidPlanProducesFailureReport(t *testing.T) {
	dir := t.TempDir()
	if got := run([]string{"-root", dir, "-plan", "missing.json", "-output", filepath.Join(dir, "reports")}); got != 2 {
		t.Fatalf("startup exit=%d", got)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "reports", "*", "results.json"))
	if len(files) != 1 {
		t.Fatalf("startup error lost report: %v", files)
	}
	var r Report
	if err := decode(files[0], &r); err != nil {
		t.Fatal(err)
	}
	if r.Results[0].Status != "error" || exitCode(r.Results) != 2 {
		t.Fatalf("wrong startup result: %+v", r)
	}
}
