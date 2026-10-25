# imitate：Fastls v2 指纹应用入口

按规范 ID 加载协议配置和默认请求头。独立生成器为 github.com/FastTLS/imitate；Use 留在请求库。

```go
var provider = generators.New() // 可在请求间并发共用

options := fastls.Options{
    FingerprintProvider: provider,
    Headers: map[string]string{"User-Agent": "my-client/1.0"},
}
match, err := imitate.Use(&options, "chrome/156/windows")
if err != nil { return err }
options.Headers["Sec-Ch-Ua"] = "caller-defined-value"
// 使用 options 发送请求；Use 本身不发送请求。
```

用户头值始终优先，可在 Use 前或后覆盖；显式空值也保留。任意 UA 不会触发自动选指纹、Client Hints 重生成或身份冲突。原 TLS、HTTP2、头和伪头顺序不因修改头值而改变。Options.UserAgent 及 WithUserAgent 只是设置实际请求 UA 的方式。新增头按传输层规则排列，协议保留字段仍须满足格式要求。

只接受官方有限目录中的规范 ID，例如 chrome/156/windows；chrome156-win、旧平台/版本顺序、compat-v1、legacy-ua-first 均不再作为官方名称解析。旧名称和 UA 转规范名称属于下游。LegacyUAFirst 策略不再执行。RecordedOnly/AllowCompatible 只控制是否接受缺少真实浏览器验证的配置，不进行业务路由。

提供者优先级为 WithProvider → Options.FingerprintProvider。必须显式提供在线生成器或 Register 返回的离线 Provider；缺少 Provider 返回 ErrInvalidOptions，不再内置浏览器目录。显式源没有配置就返回错误。UseContext 支持取消；失败不修改 Options；非法请求头格式、不支持的协议能力仍明确报错。生成器可共用，每次请求单独创建 Options。

Apply(&options, spec)、Options.Profile、自定义 JA3/JA4R 都不要求独立生成器。Register(data) 返回隔离的离线 Provider，无全局注册。新离线包与在线源采用相同的用户头优先规则，标准 List/Export 不再包含旧别名或 compat-v1。

正式指纹目录现在统一使用完整 Spec，TLS 参数不再从 JA3 的缺失字段推导。`headers.http1_defaults` / `http2_defaults` 在 ALPN 确定后应用默认值，用户的显式值及空值优先；`http1_order` 同时指定 HTTP/1 顺序和头名大小写。带 `Connection: keep-alive` 默认值的配置允许 HTTP/1 持久连接，调用方仍应关闭响应体及不再使用的空闲连接。

自定义 JA3/JA4R 继续支持。冷连接不再生成假 PSK identity/binder，只有真正缓存的会话才能产生 PSK 扩展。JA3 缺少签名列表时仍使用历史默认值；需要完整覆盖可设置 `Options.FingerprintSignatureAlgorithms` 或调用 `StringToSpecWithSignatureAlgorithms`，更丰富的参数应使用完整 Spec。这些代码点声明不会自动增加后端的密码算法实现；ML-DSA 的声明必须与实际协商能力区分。

支持完整 Spec 的 TLS1.2/1.3 与已实现扩展、有序 HTTP1/HTTP2 参数。WS/WSS 允许覆盖头值，完整 Spec 的显式 Upgrade 头序及 H2/H3 ALPN 仍返回 UnsupportedFeature；不宣称 Gorilla 能复刻任意 Upgrade 顺序。H3 不属于完整 Spec 的当前支持范围。

协议解析身份与实际请求 UA 分离：FingerprintUserAgent 供后端固定解析使用，请不要将它当作业务 UA 修改。Match 产品/版本/平台描述选中的配置，Match.UserAgent 是 Use 当时的值。

开发与验收方式见 [开发说明](../DEVELOPMENT.md)。当前仅为尚未公开发布的本地候选。
