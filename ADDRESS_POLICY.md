# 可选目标地址策略

可信 Session 地址策略已接入 Go 与 Python/Node。当前源码进一步支持显式 `HTTPVersion3` 与策略组合；SDK 须声明 `http3_address_policy_v1` 才能使用此组合，正式发行状态以 SDK 发行说明为准。旧 `fastls v0.1.1` 不包含这些 API。

## 启用

由可信应用代码使用`NewAddressPolicy(AddressPolicyConfig{...})`构造策略，并通过`Options.AddressPolicy`固定在一次性请求或`NewSession`的传输身份上。该字段标记`json:"-"`，不是远端请求可修改的DTO。nil保持原行为；非nil零值策略拒绝请求。构造时复制全部规则列表，之后没有修改规则的方法。

```go
policy, err := fastls.NewAddressPolicy(fastls.AddressPolicyConfig{
    AllowSchemes: []string{"https"},
    AllowHosts:   []string{"api.example.test"},
    AllowPorts:   []uint16{443},
    AllowCIDRs:   []string{"192.0.2.0/24"}, // 示例文档地址；替换为实际获准目标网段
})
if err != nil {
    return err
}
session, err := fastls.NewSession(fastls.Options{
    AddressPolicy: policy,
    VerifyTLS:     true,
})
if err != nil {
    return err
}
defer session.Close()
```

空允许列表表示该维度不限制，不会自动封禁私网、回环或元数据地址。各非空允许维度同时生效；`DenyCIDRs`优先于`AllowCIDRs`。建议优先使用明确的目标地址允许列表，而非把不完整的地址拒绝列表当作完整SSRF防护。

仅支持HTTP/HTTPS。域名为精确匹配，按IDNA Lookup、ASCII小写和单个结尾点规范化；不支持通配符或隐含的子域名匹配。非法UTF-8、无效/不稳定的IDNA A-label、空DNS标签和超长标签拒绝。IPv4-mapped IPv6按IPv4检查；相应映射CIDR须至少96位前缀并转换为IPv4前缀。IPv6 zone、URL用户信息和不同目标的Host覆盖拒绝。

## 请求、DNS和连接绑定

首次请求及每个实际发送的重定向请求，都在选择缓存传输前检查scheme、host和有效port；默认端口HTTP80、HTTPS443。Host覆盖必须与URL的规范化主机和有效端口一致。保留原有自动重定向次数上限及`DisableRedirect`行为；禁用跳转时返回原3xx，不主动访问Location。

每次新建TCP连接使用同一context解析DNS，要求1–256个有效结果，先检查全部结果，再尝试连接。任一结果不在允许CIDR或命中拒绝CIDR，整次尝试失败，不先连接“看起来安全”的部分答案。随后仅向`net.Dialer`传入该快照中的数值IP，不能再把原域名交给第二次解析；连接失败也只在这份已校验结果中重试。IPv4/IPv6族过滤在全部地址校验之后执行。DNS及TCP合计最多30秒，调用者更短的截止时间优先。

URL、Host、TLS SNI与证书名称验证仍使用原始目标，不替换为数值IP。标准TLS与uTLS、HTTP1与HTTP2均走同一受控拨号路径。已有连接只通向先前获准的IP，因此复用时不额外解析DNS；每个新连接仍重新解析并校验，不缓存以前的DNS许可。Session固定同一个不可变策略；不同策略不能通过单个Session按请求切换。

可通过可信`IPResolver`替换默认解析器；实现必须并发安全、响应取消，且不能在返回后并发修改结果。它不是远端客户端可注入的代码。

## 错误与拒绝路径

### 请求服务的增量能力协商

`Fastls.WithAddressPolicyJSON(data)`解析严格、最多1MiB的运维JSON并返回绑定不可变策略的客户端副本。允许字段仅为`allow_schemes`、`allow_hosts`、`allow_ports`、`allow_cidrs`及`deny_cidrs`，未知/重复键、null数组、错误类型、非法规则及尾随值拒绝。旧客户端副本不受影响，验证失败保留原客户端策略。客户端固定策略优先于每次请求的Options，不能通过DTO或传入nil/宽松策略清除。

下游可以对链接进二进制的客户端作该方法的接口能力检查，不需要静态引用新具体类型；没有方法的旧核心必须在收到启用要求时拒绝启动。新策略错误实现`AddressPolicyReason() string`，供兼容旧依赖的适配层通过错误链接口分类。该约定只用于可信服务配置，不是FFI ABI协议或远端请求JSON入口。

P03-B3新增`Fastls.CheckAddressPolicy(ctx, request, expectedOrigin)`无目标套接字预检：非空origin还绑定规范化scheme、host、有效port，供MITM检查CONNECT/SNI及解密请求。预检检查全部DNS答案，但不是允许任意拨号的凭据；真正出站仍须使用固定策略客户端重新解析及数值IP绑定，不能保存预检成功后调用未检查的拨号器。

使用`errors.Is(err, fastls.ErrAddressDenied)`识别策略拒绝；`errors.As`取得`*fastls.AddressPolicyError`及稳定`Reason`，例如`host_not_allowed`、`port_not_allowed`、`cidr_denied`、`cidr_not_allowed`、`host_override`。解析器和拨号器的取消/超时继续保留原错误链，不转换为普通策略拒绝。策略错误本身不包含URL或凭据；外围`net/url`包装及现有日志仍可能包含URL，不能视为已经实现脱敏审计。

启用策略时，HTTP/HTTPS/SOCKS 代理、HTTP3 的 q 指纹选择器与两类接收 Options 的 WebSocket 入口仍在联网前拒绝，原因分别为 `proxy_unsupported`、`http3_unsupported`、`websocket_unsupported`。显式 H3 不传指纹选择器时支持策略；拒绝前已接管的上传体会关闭。

这不是操作系统出站防火墙，不校验服务端后续代理行为、路由/NAT变换或目标应用的业务权限。不自动升级TLS验证开关：需要证书校验时仍显式设置`VerifyTLS:true`。

## 验证与剩余工作

`address_policy_test.go`覆盖规则复制、规范化、CIDR优先级、映射地址、混合DNS结果、固定IP重试、解析取消、逐跳重定向、DNS重绑定、后续新连接、Host覆盖、上传体回收、标准TLS/uTLS、H1/H2复用及并发。保留模糊测试发现的非法UTF-8样本。独立Action配置三个操作系统和两套Go工具链，Linux增加race/fuzz；提交推送之前不能宣称远端矩阵已通过。

Fetch/RPC的服务端配置与MITM独立安全拦截模式均已在开发源码接入，默认公开依赖构建仍因旧核心而不能启用。MITM策略模式有单请求正文限额；Fetch/RPC可配置请求大小、连接/隧道配额和审计接口仍未实现。本轮不改变下游公开依赖版本，不新增标签或Release。


## 显式 H3 的目标绑定

设置 `Options{HTTPVersion: HTTPVersion3, AddressPolicy: policy, VerifyTLS: true}`。每个新 QUIC 连接重新解析并校验全部地址，然后只向批准的数字 IP/端口创建 connected UDP socket；不会再次解析域名。原 URL authority、SNI 与证书名称保持一致。解析及全部连接尝试共享最多 30 秒预算，更短的请求/阶段截止时间优先。

socket 由内核固定远端；PacketConn 的 WriteTo 同时拒绝其它目标（`peer_change_unsupported`），不暴露可绕过校验的原始/OOB/批量写入接口。因此策略路径不启用 ECN/GSO、连接迁移或服务端首选地址切换，不启用 0-RTT。普通无策略 H3 路径保持原实现，不能由本路径推断浏览器指纹或性能等价。

会话内可复用同一 origin 已批准的物理连接，DNS 改变不会追溯撤销既有连接；新连接必须校验新快照。策略不可变且随传输固定；每个请求、重定向和缓存分派前仍校验逻辑目标。握手失败、取消、连接结束和会话关闭释放所拥有的 socket；CloseIdleConnections 保留活动正文的原契约。

实现接口依据固定版本 [quic-go v0.57.1 HTTP/3 transport](https://github.com/quic-go/quic-go/blob/v0.57.1/http3/transport.go) 与 [QUIC Dial](https://github.com/quic-go/quic-go/blob/v0.57.1/client.go)，不以其它版本的接口推断当前行为。
