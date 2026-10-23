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

## peet 公网验证与完整报告

在核心目录运行：

```sh
python scripts/check-peet.py
```

该入口使用当前本地 go.work，重新执行核心 test/build/vet、profile、纯配置、报告工具与报告单元测试，再实际访问 `https://tls.peet.ws/api/all`。公网部分包括自定义 JA3、带0/空点格式、Go标准库和Fastls无指纹路径，共5个请求；每个请求限时20秒，无自动重试，不使用环境代理。

每次在外层 reports 下新建目录，保存 HTML、Markdown、JSON、JUnit、原始执行日志、逐请求响应和运行清单。观测记录包含输入/预期/实际JA3、JA3 hash、JA4/JA4R、协商协议、Akamai指纹与UA；自定义配置严格比较完整JA3，标准库只验证观测有效性，不固定随Go版本变化的指纹。报告中的原始响应包含服务返回的出口IP等信息。

读取失败时也保存已读字节、部分响应和错误阶段。原生 Go 响应额外记录 HTTP 协议、ContentLength、传输编码、自动解压标志和响应头；Fastls 旧 Response 接口只提供部分元信息，缺失项保持未知。自动解压后 ContentLength 可能为 -1，不能直接当作线上原始长度比较。

连接生命周期回归在 `connection_lifecycle_test.go`：覆盖同一指纹客户端连续请求、同站跳转、HTTP1/HTTP2关闭空闲后重连、保留活跃响应及并发访问。ALPN探测连接只交接一次，后续连接由HTTP传输层管理。GOST启动检查须完成真实代理请求，不使用只连接端口就关闭的探测。

普通离线计划不会请求公网。测试通过仅表示此次请求与所声明断言成功，不等于真实浏览器全部行为一致；代理、WS/H3、race和Linux实测沿用各自专门验收。

## 跨仓验收

在包含 fastls、fhttp、imitate 和 fastls-lab 的外层工作区执行：

```sh
python fastls/scripts/verify-imitate.py --all
```

编排器为未发布候选建立本地文件代理和隔离缓存。默认不联网；准备固定依赖的联网选项、GOST 专项与公开矩阵参数见 `--help`。该入口还检查生成器可选依赖边界和候选摘要，不可用单个核心测试代替。

通用报告工具使用 [fastls-check](tools/fastls-check/README.md)。不同计划覆盖范围不同；默认 check-plan 是初始离线计划，旧服务迁移、Linux 实际运行和发布状态必须分别查看，不能由报告全绿推断。

## 本地产物与维护

报告写入外层 `reports/`，`reports/`、Python缓存和二进制不属于发布源码。历史规划和清理备份保留在外层工作区；核心文档不依赖这些文件才能理解 API。当前 API 见 [imitate说明](imitate/README.md)，发布规则见 [RELEASE](RELEASE.md)。
