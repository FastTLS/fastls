# 会话、取消和连接生命周期

本页描述当前开发源码。P02 的修复尚未发布；现有正式基线仍为 `fastls v0.1.1` 与 `ftransport v0.1.0`。使用本轮 HTTP/2 初始化回收修复时，必须同时绑定这两个仓库的开发源码；只修改核心仓库不会升级其公开 `go.mod` 中的传输依赖。

## 请求取消

`Session.DoContext` 的 context 覆盖 DNS、TCP 拨号、代理握手、TLS 握手、HTTP/2 preface/初始帧、响应头和正文读取。`Timeouts.Connect` 包含取得连接所需的这些步骤；每跳阶段超时与调用者总截止时间各自生效。响应体读到 EOF 或关闭后释放请求 context。

HTTP/2 的初始化写入也可能阻塞。当前实现保留拨号 context 到初始化结束；取消会关闭尚未交付连接池的连接，并释放该 origin 的建连条目。等待同一拨号的其他有效请求可以重新建连。初始化成功后立即解除该取消回调，后续请求不会因最初请求结束而误关共享连接。

HTTP/HTTPS 代理 CONNECT、HTTPS 代理 TLS、SOCKS5 方法协商、认证和地址回复均受 context 控制。SOCKS5 本地解析使用同一个 context；SOCKS5h 发送目标域名给代理。以上承诺对应 `ValidateProxy` 接受的四种代理协议，不包含旧内部兼容拨号器或任意自定义的阻塞实现。自定义 `ContextDialer` 必须响应 context，上传 `BodyReader.Close` 必须能解除其阻塞读取。

## 关闭与错误

- `Session.CloseIdleConnections` 释放空闲连接，保持活动响应体可用。
- `Session.Close` 取消活动请求，拒绝新请求，并释放空闲连接；可重复调用。
- 会话关闭引发的请求错误和正文读取错误可以通过 `errors.Is(err, fastls.ErrSessionClosed)` 判断，并继续匹配 `context.Canceled`。
- 调用者自行取消仍匹配 `context.Canceled`；总截止时间匹配 `context.DeadlineExceeded`；阶段预算可以通过 `errors.As` 取得 `*fastls.TimeoutError` 和 `Phase`。
- 使用底层 `ftransport.Transport.Close` 时，错误匹配 `ftransport.ErrTransportClosed`，其 `OperationError` 仍保留原始错误链。

连接选择、协议校验或拨号失败时，请求传输层负责关闭已经接管的上传体。失败的 HTTP/2 连接获取必须同时结束上传与响应方向，才能将活动计数归零。成功的全双工响应仍按两个方向各自的生命周期回收。

## 连接池边界

会话固定代理、TLS/指纹和证书策略，按 origin 隔离传输实例，最多缓存128个 origin；每 origin 最多8条连接，空闲超时90秒。Cookie 和请求级头覆盖不改变固定传输身份。

自定义 HTTP/2 当前支持每 origin 最大连接数和空闲超时；独立的 `MaxIdleConnections` / `MaxIdlePerHost` 非零设置返回 `ftransport.ErrUnsupportedFeature`，在联网前拒绝。不能把未实现的独立空闲数量限制当作已生效。

## 验证范围

回归用例位于核心 `dial_cancellation_test.go`、`proxy_cancellation_test.go` 和 ftransport `dial_cancellation_test.go`。它们使用回环服务或可控内存连接，覆盖标准 TLS/uTLS 后续建连、阻塞 preface、有效等待者恢复、DNS、代理阶段、失败上传回收及会话关闭错误。现有连接池、H2兄弟流、慢消费者和全双工测试继续执行。

2026-10-26 本机 Windows amd64 已执行 Go1.26.10/1.27.3 全套测试、静态检查、race及代理URL模糊测试；下游和FFI验证记录见工作区的 P02 验收记录。新提交的远端平台矩阵须在提交推送后另行确认。
