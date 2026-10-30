# profile 规范模块

## H2 流级配置

schema 1 增加可选 `http2.first_stream_id` 和 `http2.stream_window_increment`。前者 `0`/省略选择 `1`，非零值必须为合法客户端奇数编号；后者 `0`/省略不发送初始流更新，非零值在每个请求初始 HEADERS 后通告一次，并与 SETTINGS 的流接收窗口一起校验 31 位上限。字段为值类型，Clone 和 Bundle/Store 往返保留它们。

任一字段非零必须声明 `capabilities.required_features: ["http2.stream.v1"]`（与其它需要的能力合并）。旧严格 JSON 读取器拒绝未知字段，旧执行后端拒绝未知必需能力，不能无声退化。新增字段不改变 schema、Provider 接口或 C ABI 的版本。旧 profile/v0.1.0 标签不具备这些字段；请使用明确包含该变更的模块版本。

模块路径：`github.com/FastTLS/fastls/profile`。这是 Fastls 仓库中的独立小模块，只依赖 Go 标准库；没有产品目录、UA 算法或协议后端。

`Spec`、`Metadata`、`Match`、`Defaults` 和错误类型保留原导入路径。TLS ID 使用固定宽度 `0x0000` JSON 字符串；TLS 扩展、HTTP2 设置、头和伪头顺序使用有序数组。`Clone` 深拷贝；`Validate` 检查模型语义，执行支持由请求后端另外检查。

`Provider.Resolve(context.Context, ResolveRequest)` 返回恰好一个完整 `Spec` 或明确的 `LegacyDefinition`。Legacy 只有历史 JA3/JA4R 与中立 HTTP2 参数，不能借其标记伪装为完整 Spec。`HeaderPolicy` 描述默认、覆盖、按原值覆盖、删除及按名称前缀删除；多值保存在 Values，业务地址、代理、Body、Cookie、认证、超时不会传给 Provider。

2026-10-25：官方生成器全部输出完整 Spec。HeaderConfig 增加 `http1_defaults`、`http2_defaults`、`http1_order`；协议专属默认值不能与公共默认值重叠，HTTP/2 不接受连接专属头，头名大小写仅用于 HTTP/1。`shuffle-chrome` 固定 GREASE/padding 的位置并随机排列其他扩展。新行为通过 `http.headers.protocol.v1`、`tls.signature-advertised.v1`、`tls.shuffle-chrome.v1` 能力标记明确要求后端支持。

`capabilities.advertised_only` 显式区分线上声明与密码算法实现；缺少该标记的未实现声明仍被拒绝，后端不能验证的算法不会因标记而获得实现。LegacyDefinition 可额外携带 `signature_algorithms` 补足 JA3 未编码的字段；该兼容输入不用于官方目录的日常维护。

`DecodeCatalog` / `NewRegistry` 支持严格 JSON、单层基线、显式字段 presence 和不可变查询。`NewProvider` 将完整 Catalog 用作离线源。`DecodeBundle` 接收带版本的闭合导出快照；拒绝未知字段、重复键/ID、超限和非法响应，返回隔离的只读 Provider。固定 Bundle 不重新推导不同 UA 的 Client Hints。

先前未发布的产品查询函数 LookupLegacy、LegacyJA4R、LookupBuiltinSelection、LookupCompatibilitySelection 等已移入独立生成器 internal/catalog；它们不再属于共享规范。应用改用独立 imitate.New().Resolve/List/Export；核心已删除历史浏览器公开预设及冻结目录，Use 需要显式 Provider。产品数据变更不会触及本模块。

规范 schema 为1，接口版本为1，已发布 profile/v0.1.0；后续源码字段不代表旧标签自动具备。发布子目录时使用 `profile/v...` 标签。根库 `go test ./...` 不包含本模块，必须独立执行 `go test ./...`；跨仓验收入口为核心 scripts/verify-imitate.py。

2026-10-23 v2 规则更新：官方 Provider 不再读取 ResolveRequest.UserAgent 进行选择或校验，用户覆盖通过 Options 完成。Registry 不再自动生成旧平台/版本顺序别名。HeaderPolicy 是配置默认值，Fastls 最后应用用户请求头，因此任何生成规则都不能覆盖用户明确传入的值。LegacyUAFirst 已停用。自定义目录可显式登记自己的别名，但官方导出不携带历史别名。

## 许可证

本模块自有代码采用 [Apache-2.0](LICENSE)，版权声明见 [NOTICE](NOTICE)。子模块发行包直接随附完整许可文本。
