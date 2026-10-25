# ftransport 迁移说明

本分支将 Fastls 的 HTTP/1.1 与 HTTP/2 后端从 `github.com/FastTLS/fhttp`
迁移到 `github.com/FastTLS/ftransport`，并把最低 Go 版本提升到 1.26。

## Go API 变化

- `Options.CookieJar`、`Response.Client` 以及内部请求/响应类型现在直接使用
  `net/http`。
- `Options.HTTP2Settings` 现在是 `*ftransport.HTTP2Config`。
- `ProfileHTTP2` 和 `ToHTTP2Settings` 返回 `*ftransport.HTTP2Config`；有序
  SETTINGS、连接窗口增量、PRIORITY 与 HEADERS priority 均保留显式零值。
- `HeaderOrderKeys` 与 `PHeaderOrderKeys` 仍是 Fastls 兼容入口，但不再写入
  伪造的 HTTP Header；它们在传输构造时转换为 ftransport 的线上编码配置。
- `RequestOptions.Trailers` 支持 H1/H2 请求 Trailer；`Response.Trailer` 在 Body
  读到 EOF 后完整可用，`Response.Protocol` 与 `Response.FinalURL` 暴露最终元信息。

## 保留行为

uTLS ClientHello、ALPN 探测、目标与代理证书根、HTTP/HTTPS CONNECT、SOCKS5、
阶段超时、CookieStore、连接复用、全双工、HTTP/3 和 WebSocket 继续由原有
Fastls 分层负责。HTTP/3 和 WebSocket 使用标准库类型，不进入 ftransport 的
HTTP/1.1/2 连接池。

H3 的 `q` JA4R 是经过语法校验的协议选择器，不代表标准 Go QUIC TLS 能复刻
任意 ClientHello。高层 H3 路径使用 `VerifyTLS`/`TLSRootCAs`，并在配置代理时
明确报错，禁止静默绕过代理直连。

## 依赖与构建

正式模块不包含本地 `replace`。发布 ftransport 后，应把 `go.mod` 中的候选
版本替换为该审阅提交对应的不可变版本。开发工作区通过被忽略的 `go.work`
绑定本地 ftransport、profile 与 imitate。以下检查必须保持不含 fhttp：

```shell
go list -deps ./...
go list -m all
```
