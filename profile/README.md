# profile 规范模块

模块路径：`github.com/FastTLS/fastls/profile`。这是 Fastls 仓库中的独立小模块，只依赖 Go 标准库；没有产品目录、UA 算法或协议后端。

`Spec`、`Metadata`、`Match`、`Defaults` 和错误类型保留原导入路径。TLS ID 使用固定宽度 `0x0000` JSON 字符串；TLS 扩展、HTTP2 设置、头和伪头顺序使用有序数组。`Clone` 深拷贝；`Validate` 检查模型语义，执行支持由请求后端另外检查。

`Provider.Resolve(context.Context, ResolveRequest)` 返回恰好一个完整 `Spec` 或明确的 `LegacyDefinition`。Legacy 只有历史 JA3/JA4R 与中立 HTTP2 参数，不能借其标记伪装为完整 Spec。`HeaderPolicy` 描述默认、覆盖、按原值覆盖、删除及按名称前缀删除；多值保存在 Values，业务地址、代理、Body、Cookie、认证、超时不会传给 Provider。

`DecodeCatalog` / `NewRegistry` 支持严格 JSON、单层基线、显式字段 presence 和不可变查询。`NewProvider` 将完整 Catalog 用作离线源。`DecodeBundle` 接收带版本的闭合导出快照；拒绝未知字段、重复键/ID、超限和非法响应，返回隔离的只读 Provider。固定 Bundle 不重新推导不同 UA 的 Client Hints。

先前未发布的产品查询函数 LookupLegacy、LegacyJA4R、LookupBuiltinSelection、LookupCompatibilitySelection 等已移入独立生成器 internal/catalog；它们不再属于共享规范。应用改用独立 imitate.New().Resolve/List/Export；核心已删除历史浏览器公开预设及冻结目录，Use 需要显式 Provider。产品数据变更不会触及本模块。

规范 schema 为1，接口版本为1，候选版本尚未公开发布。发布子目录时使用 `profile/v...` 标签。根库 `go test ./...` 不包含本模块，必须独立执行 `go test ./...`；跨仓验收入口为核心 scripts/verify-imitate.py。

2026-10-23 v2 规则更新：官方 Provider 不再读取 ResolveRequest.UserAgent 进行选择或校验，用户覆盖通过 Options 完成。Registry 不再自动生成旧平台/版本顺序别名。HeaderPolicy 是配置默认值，Fastls 最后应用用户请求头，因此任何生成规则都不能覆盖用户明确传入的值。LegacyUAFirst 已停用。自定义目录可显式登记自己的别名，但官方导出不携带历史别名。
