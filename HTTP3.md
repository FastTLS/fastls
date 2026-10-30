# HTTP/3 开发修复与支持范围

当前状态（2026-10-30）：显式 H3 已接入并交付 Python 0.2.0 / Node 0.11.0 及后续版本，平台验收见 [SDK 发布记录](https://github.com/FastTLS/fastls-ffi/releases)。浏览器 H3 指纹、UDP 代理与自动 Alt-Svc 尚属独立扩展。下文保留 2026-10-27 原始开发记录，其中“尚未接入/未验收”仅表示当时范围，不覆盖后续交付。

本工作区基于 `fc600f7`，分支 `codex/h3-improvements-20261027`。以下为未发布的 Go 核心改动，不代表正式版本、Python 或 Node SDK 已获得新能力。

## 当前入口与限制

新增 `Options.HTTPVersion = HTTPVersion3`：显式要求所有请求与重定向跳转使用 HTTPS/H3，不需要构造 JA4R 指纹，失败时不回退到 TCP。`HTTPVersionAuto` 是零值，保留现有 H1/H2 ALPN 与有效 q-JA4R 的历史选择方式，不会自动发现 H3/Alt-Svc。固定依赖仍为 quic-go v0.57.1。

显式 H3 在创建客户端/Session 时拒绝代理、H1/H2 profile.Spec、TCP TLS 指纹/扩展、H2 设置及自定义头部顺序，不会静默忽略这些配置。Go WebSocket 的两个 Options 入口也会拒绝显式 HTTPVersion，避免把强制 H3 偷换成 H1 Upgrade。SDK、UDP 代理和浏览器 H3 指纹配置尚未接入。

```go
func fetchH3(ctx context.Context, url string) error {
    session, err := fastls.NewSession(fastls.Options{
        HTTPVersion: fastls.HTTPVersion3,
        VerifyTLS: true,
    })
    if err != nil { return err }
    defer session.Close()
    response, err := session.DoContext(ctx, url, fastls.RequestOptions{}, "GET")
    if err != nil { return err }
    defer response.Body.Close()
    fmt.Println(response.Protocol) // HTTP/3.0 on success
    _, err = io.Copy(io.Discard, response.Body)
    return err
}
```

示例需要导入 context、fmt、io 和 github.com/FastTLS/fastls。调用方提供实际 H3 服务 URL，并通过 context 设置总时限。

配置代理时仍在进入 H3 前明确拒绝。JA4R 仅用于选择与校验；QUIC 使用 Go TLS，不承诺任意 ClientHello、QUIC 参数、H3 SETTINGS/QPACK 或头部顺序与真实浏览器一致。完整 profile.Spec 仍面向 H1/H2，H2 Duplex 不扩展到 H3。

Go 指纹路径的历史证书验证零值保持原样；使用时显式设置 VerifyTLS=true，需要本地 CA 时设置 TLSRootCAs。Session 的总时限由请求 context 控制，阶段预算使用 RequestOptions.Timeouts。

## 本批修复

- 保留请求显式 User-Agent，包括空字符串；H3 不再用固定默认 UA 覆盖请求值。
- 禁止底层自动添加 gzip 和隐式解压；由 Fastls 的 DecodeContent 与 MaxDecodedBytes 统一控制。DecodeContent=false 保留原始压缩字节，启用解码后沿用大小上限和错误处理。
- 活动响应计数持续到正文 EOF、失败或关闭，不能在只收到响应头时视为空闲。CloseIdleConnections 不再中断活动正文，最后一个响应结束后才回收待关闭传输。
- 传输拥有并完整关闭 QUIC 连接与 UDP socket；一次性请求在正文终止时释放，会话关闭也关闭其传输。空闲关闭后可重新建立连接。
- 使用上游默认的 context 感知 DNS、QUIC 拨号与 httptrace 路径，保留连接、写入、响应头和读取阶段预算。
- 服务器提前结束响应时，正文 EOF/关闭同时关闭未结束的上传源。请求取消也关闭源，避免生产者阻塞在 Read 中而仅 QUIC stream 已取消。
- 修复首次初始化和 Close 的数据竞态：在拨号前确认底层初始化已完成，关闭操作仅等待本地初始化，不等待网络握手。
- 修复响应 Trailer 在后端替换 map 后丢失的问题；预声明和未预声明 Trailer 均在 EOF 后可见。当前后端不能发送请求 Trailer，因此发送前明确拒绝，不再静默丢弃。
- Content-Length 正文提前结束返回 io.ErrUnexpectedEOF；HEAD、204、304 不错误地要求接收实体长度。

响应、上传源和 Session 仍须按契约管理。自定义上传源的 Close 必须能解除阻塞 Read；客户端无法强制中断忽略 Close 的任意用户代码。

## 本机验证

2026-10-27，Windows amd64 / Go 1.26.10，GOWORK=off，使用独立模块缓存及原有正式依赖。核心全包 test、vet、build 通过。

新增 12 个顶层 H3 测试，包含 UA、原始/解码响应、解码上限、活动响应空闲关闭、连接/头部/读/写超时、关闭及重连、未读正文的 Session 关闭、兄弟流取消隔离、一次性请求回收、早响应上传源回收和 64 MiB 双向传输。64 MiB 上传与下载分别计算 SHA-256，生成器和摘要器不缓存整份正文；这不是固定 RSS 或性能排名的证明。

其中 11 个生命周期/错误契约测试随机顺序重复 30 轮；大文件测试在全包套件中执行，未纳入重复负载。原有 H3 的私有 CA/不可信证书、代理拒绝、无效选择器和实际 HTTP/3.0 响应回归继续执行。

第一批的本机 race 曾因 gcc 缺失而构建失败。第二批使用官方 SHA-256 校验的 Zig 0.14.1 临时编译器及仓库已有 race-exec.py 测试包装，实际复现初始化/关闭竞态并修复；修复后全包 race 通过，首次使用与关闭专项 race 重复 20 轮通过。PE 包装仅影响临时测试程序，不修改生产二进制。

新增显式版本、禁止 TCP 回退/降级、WebSocket 入口约束、Trailer、截断和 HEAD 等回归。新增 `.github/workflows/http3.yml`，配置 Windows/Linux/macOS 双 Go 矩阵及 Linux H3 race；远端结果以该候选的实际运行记录为准。未运行公网、多实现协议互通、长时间 soak 或 Python/Node SDK 验收。

## 后续范围

按根工作区 G6 继续推进 SDK/ABI 接入、跨平台认证，再分别处理 H3 指纹、QUIC 参数及 UDP 代理。已有 P02/P03 开发分支的合并和地址策略集成仍属于独立整合工作，不能用本批基线冒充已包含它们。

## English summary

This core batch adds explicit HTTPVersion3 selection without TCP fallback, while preserving the existing zero-value behavior. It fixes initialization/close races, response trailers, truncated-body errors, request headers, decoding and resource ownership. Unsupported request trailers and H1/H2 configuration are rejected. Local Windows tests, vet, build and full race tests passed. Cross-platform certification and Python/Node H3 integration require their own evidence. Proxy and browser-fingerprint limitations remain.
