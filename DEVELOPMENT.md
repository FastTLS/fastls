# 开发与测试

## 目录

- 根包：请求、代理、JA3/JA4R、HTTP2、HTTP3 与 WebSocket 执行。
- `imitate/`：Use、Apply、离线 Register；生成器在独立 FastTLS/imitate 仓库。
- `internal/compiler/`：中立 Spec 到后端参数的编译。
- `profile/`：独立 Go 规范模块，需要单独执行检查。
- `integration/imitate/`：独立联调模块，覆盖 Provider、发包、WS/WSS 和代理；包含 fastls-probe。
- `_tests/`：保留的协议配置及显式公网观测用例，根目录 `go test ./...` 不包含该目录。
- `scripts/`：验收计划与跨仓编排；`tools/`：独立工具模块；`services/`：独立服务链接。

## 本地核心检查

在核心目录执行；当前本地 go.work 连接并列 fhttp 和 profile 模块。不要在公共 go.mod 中加入本机绝对路径。

```sh
go test ./... -count=1 -timeout 90s
go build ./...
go vet ./...
```

进入 `profile/` 后单独运行 `go test ./... -count=1 -timeout 60s`。`_tests/` 的纯配置检查须使用显式选择，见其 [说明](./_tests/README.md)，避免误跑公网观测。

## 跨仓验收

在包含 fastls、fhttp、imitate 和 fastls-lab 的外层工作区执行：

```sh
python fastls/scripts/verify-imitate.py --all
```

编排器为未发布候选建立本地文件代理和隔离缓存。默认不联网；准备固定依赖的联网选项、GOST 专项与公开矩阵参数见 `--help`。该入口还检查生成器可选依赖边界和候选摘要，不可用单个核心测试代替。

通用报告工具使用 [fastls-check](tools/fastls-check/README.md)。不同计划覆盖范围不同；默认 check-plan 是初始离线计划，旧服务迁移、Linux 实际运行和发布状态必须分别查看，不能由报告全绿推断。

## 本地产物与维护

报告写入外层 `reports/`，`reports/`、Python缓存和二进制不属于发布源码。历史规划和清理备份保留在外层工作区；核心文档不依赖这些文件才能理解 API。当前 API 见 [imitate说明](imitate/README.md)，发布规则见 [RELEASE](RELEASE.md)。
