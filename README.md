# Fastls

[English](README_EN.md) · 中文

Go TLS 指纹请求库，支持自定义 JA3/JA4R、完整 profile.Spec、HTTP 请求头顺序及 HTTP/HTTPS/SOCKS5 代理。浏览器配置由独立 [FastTLS/imitate](https://github.com/FastTLS/imitate) 生成，Fastls 负责应用和发送请求。

Fastls v2 当前正式版为 [`v0.1.1`](https://github.com/FastTLS/fastls/releases/tag/v0.1.1)。Go 模块路径保持 `github.com/FastTLS/fastls`；正式源码和版本说明只在 GitHub 发布。

当前开发源码增加可选[目标地址策略](ADDRESS_POLICY.md)：HTTP1/HTTP2逐跳校验与DNS结果绑定拨号。Fetch/RPC及MITM开发源码已增加各自的可信启动配置及旧核心拒绝机制；能力尚未发布，FFI尚未接入。

## 使用

```go
import (
    "context"
    "io"

    fastls "github.com/FastTLS/fastls"
    "github.com/FastTLS/fastls/imitate"
    generators "github.com/FastTLS/imitate"
)

var fingerprints = generators.New() // 可以在请求间并发共用

func fetch(ctx context.Context, target string) ([]byte, error) {
    options := fastls.Options{
        FingerprintProvider: fingerprints,
        Headers: map[string]string{"User-Agent": "my-client/1.0"},
        Timeout: 15,
    }
    if _, err := imitate.Use(&options, "chrome/156/windows"); err != nil {
        return nil, err
    }
    resp, err := fastls.NewClient().DoContext(ctx, target, options, "GET")
    if err != nil {
        if resp.Body != nil {
            resp.Body.Close()
        }
        return nil, err
    }
    defer resp.Client.CloseIdleConnections()
    defer resp.Body.Close()
    return io.ReadAll(resp.Body)
}
```

`Use` 必须显式提供 Provider。用户请求头值优先于生成默认值；旧名称和 UA 转换由下游处理。自定义 JA3/JA4R、`imitate.Apply` 和 `Options.Profile` 不需要生成器。支持的规范名称与验证范围以 Provider 的 List、Match 和证据为准，不能将生成版本身份视为真实浏览器全指纹验证。

响应体由调用方关闭。无指纹请求在收到响应头后返回，取消、超时和读取错误可以在 Body.Read 时出现。完整 Spec 当前支持 HTTP1/HTTP2；一次性请求和 `Session` 均支持请求 Trailer，`Session` 还支持流式上传、H2 全双工、阶段超时和按需内容解码。响应 Trailer 在响应体读到 EOF 后完整可用，响应也会报告最终协议与跳转后的 URL。

H3 使用 `q` 前缀 JA4R 作为经校验的协议选择器，并支持 `VerifyTLS` 与 `TLSRootCAs`；标准 Go QUIC TLS 不能复刻任意 ClientHello 扩展顺序，因此不宣称完整 H3 浏览器指纹。H3 明确拒绝代理，避免静默直连。WS/WSS 使用 HTTP/1.1 Upgrade；任意 Upgrade 头序、压缩、重定向和 HTTP/2 Extended CONNECT 不在当前支持范围。会话关闭、拨号取消与当前开发源码的修复范围见[连接生命周期说明](SESSION_LIFECYCLE.md)。

## 文档与工具

- [指纹应用、离线注册与能力范围](imitate/README.md)
- [开发、测试与目录说明](DEVELOPMENT.md)
- [会话、取消和连接生命周期](SESSION_LIFECYCLE.md)
- [共享 profile 规范](profile/README.md)
- [命令行探针源码](integration/imitate/cmd/fastls-probe/main.go)
- [测试工具](tools/README.md)
- [独立服务与靶场](services/README.md)
- [发布与版本规则](RELEASE.md)

## 许可证

Fastls 自有代码采用 [Apache License 2.0](LICENSE)，版权声明见 [NOTICE](NOTICE)。独立 Go 子模块随附同一许可证。第三方代码和依赖保留原许可证，随附材料和历史来源审计见 [第三方声明](THIRD_PARTY_NOTICES.md)。
