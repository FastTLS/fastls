package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html/template"
	"path/filepath"
	"strings"
)

type junitCase struct {
	Name    string        `xml:"name,attr"`
	Class   string        `xml:"classname,attr"`
	Time    string        `xml:"time,attr"`
	Failure *junitMessage `xml:"failure,omitempty"`
	Error   *junitMessage `xml:"error,omitempty"`
	Skipped *junitMessage `xml:"skipped,omitempty"`
}
type junitMessage struct {
	Message string `xml:"message,attr"`
}
type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{"totals": resultTotals}).Parse(`<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Fastls checks · {{.RunID}}</title><style>
body{font:15px system-ui;background:#f3f5f8;color:#202b3d;margin:0;padding:32px}main{max-width:1200px;margin:auto}h1{font-size:28px}table{border-collapse:collapse;background:white;width:100%}td,th{text-align:left;padding:12px;border-bottom:1px solid #e0e6ed;vertical-align:top}code{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#145dc2}.pass{color:#176a3b}.fail,.error{color:#b42734}.not_run,.skip{color:#885500}small{color:#526176}
</style><main><h1>Fastls · 阶段检查报告</h1><p>{{.RunID}} · {{.Suite}} · {{.StartedAt.Format "2006-01-02T15:04:05Z07:00"}} UTC</p><p>结果来自所选执行计划；此报告不表示完整指纹或全部重构已通过。</p><p>{{totals .Results}}</p><p><input id="search" aria-label="搜索检查" placeholder="搜索检查或原因"><select id="status" aria-label="按状态筛选"><option value="">全部状态</option><option>pass</option><option>fail</option><option>error</option><option>not_run</option><option>skip</option></select></p>
<table><thead><tr><th>检查</th><th>状态</th><th>命令 / 原因</th><th>耗时</th><th>证据</th></tr></thead><tbody>{{range .Results}}<tr data-status="{{.Status}}"><td>{{.Step.ID}}<br><small>{{.Step.TaskID}} · {{if .Step.Required}}必需{{else}}非本阶段必需{{end}}</small></td><td class="{{.Status}}">{{.Status}}</td><td><code>{{range .Step.Command}}{{.}} {{end}}</code><br>{{.ReasonCode}} {{.Message}}</td><td>{{.DurationMS}} ms</td><td>{{if .Log}}<a href="{{.Log}}">执行证据</a>{{end}}</td></tr>{{end}}</tbody></table>
<h2>已知覆盖边界</h2><ul>{{range .Excluded}}<li><code>{{.Path}}</code>：{{.Reason}}</li>{{end}}</ul><p>原始结果：<a href="results.json">results.json</a> · <a href="run-manifest.json">运行清单</a> · <a href="junit.xml">JUnit</a></p></main><script>function filter(){const q=document.getElementById("search").value.toLowerCase(),s=document.getElementById("status").value;document.querySelectorAll("tbody tr").forEach(r=>r.hidden=(!r.textContent.toLowerCase().includes(q))||(s&&r.dataset.status!==s));}document.getElementById("search").addEventListener("input",filter);document.getElementById("status").addEventListener("change",filter);</script></html>`))

func resultTotals(results []Result) string {
	required, passed, failed, incomplete := 0, 0, 0, 0
	for _, r := range results {
		if !r.Step.Required {
			continue
		}
		required++
		switch r.Status {
		case "pass":
			passed++
		case "fail", "error":
			failed++
		default:
			incomplete++
		}
	}
	return fmt.Sprintf("必需检查 %d；通过 %d；失败/错误 %d；未完成 %d。", required, passed, failed, incomplete)
}

func render(dir string, r Report) error {
	if err := checkReport(r); err != nil {
		return err
	}
	var html bytes.Buffer
	if err := reportTemplate.Execute(&html, r); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, "report.html"), html.Bytes()); err != nil {
		return err
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Fastls 阶段检查报告\n\n运行：%s\n\n套件：%s；退出码：%d。仅证明本阶段所选计划结果。\n\n", r.RunID, r.Suite, exitCode(r.Results))
	suite := junitSuite{Name: "fastls." + r.Suite, Tests: len(r.Results)}
	for _, v := range r.Results {
		fmt.Fprintf(&md, "- %s: %s (%s)\n", v.Step.ID, v.Status, v.ReasonCode)
		if v.Message != "" {
			fmt.Fprintf(&md, "  - %s\n", strings.ReplaceAll(v.Message, "\n", " "))
		}
		if v.Log != "" {
			fmt.Fprintf(&md, "  - [执行证据](%s)\n", v.Log)
		}
		c := junitCase{Name: v.Step.ID, Class: v.Step.Category, Time: fmt.Sprintf("%.3f", float64(v.DurationMS)/1000)}
		msg := &junitMessage{Message: v.ReasonCode + ": " + v.Message}
		switch v.Status {
		case "fail":
			c.Failure = msg
			suite.Failures++
		case "error":
			c.Error = msg
			suite.Errors++
		case "skip", "not_run":
			c.Skipped = msg
			suite.Skipped++
		}
		suite.Cases = append(suite.Cases, c)
	}
	md.WriteString("\n覆盖边界：\n\n")
	for _, v := range r.Excluded {
		fmt.Fprintf(&md, "- %s: %s\n", v.Path, v.Reason)
	}
	if err := atomicWrite(filepath.Join(dir, "summary.md"), []byte(md.String())); err != nil {
		return err
	}
	b, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "junit.xml"), append([]byte(xml.Header), b...))
}
