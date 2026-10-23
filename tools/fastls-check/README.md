# fastls-check

统一执行显式阶段检查，保存逐项日志、JSON、独立 HTML、Markdown 和 JUnit。只使用 Go 标准库。

从核心目录运行 `./scripts/check.ps1`（Windows）或 `sh scripts/check.sh`（Linux/macOS）。默认计划为 `scripts/check-plan.json`，逐 module 使用 `GOWORK=off`；报告写入核心外层 `reports/<run-id>/`。不会执行公网或旧公网 WS 测试。

Windows：`./scripts/check.ps1 -ReportOnly <绝对路径>/results.json`。Linux：`sh scripts/check.sh -report-only <绝对路径>/results.json`。重建不运行计划中的任何命令，也不修改原始结果。

退出码：0 所选阶段必需项通过；1 检查失败；2 工具/环境错误；3 必需检查未完成。包装脚本先编译临时可执行文件，保留这些退出码。直接使用 `go run` 会将非零程序退出归并为 Go 工具自身的失败码，不适合 CI 判断。

可用 `-filter` 只执行匹配 ID 的检查，被过滤的必需项仍明确记为未完成，不能用于绕过完整验收。进程超时和取消终止进程树，结果逐项原子落盘。日志可能包含本地诊断信息，分享前核对；HTML 不嵌入日志正文。

默认 `scripts/check-plan.json` 是初始离线计划：包含核心、独立工具、lab和显式选择的 `_tests` 纯配置用例；未迁移的三个旧服务明确记为未执行。`scripts/legacy-test-inventory.json` 只保留现有测试清单。

完整生成器边界和发包验收通过 `python scripts/verify-imitate.py --all` 编排 `scripts/check-imitate-plan.json`；后者需要编排器准备的候选代理、缓存和环境，不能直接当成默认计划运行。GOST专项、race、Linux实际运行及发布须按各项实际结果判断。见 [开发说明](../../DEVELOPMENT.md)。
