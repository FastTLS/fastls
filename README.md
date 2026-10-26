# Fastls

[English documentation](https://fasttls.github.io/en/fastls/)

[English](README_EN.md) · [完整文档](https://fasttls.github.io/fastls/)

Go HTTP 客户端库，用于选择浏览器网络配置、自定义 JA3/JA4R 或完整 profile.Spec，发送具有指定 TLS/HTTP 参数及头部顺序的请求。Python、Node 用户请直接使用 [SDK](https://github.com/FastTLS/fastls-ffi)。

## 安装

需要 Go 1.26+。在自己的 Go 项目中执行：

```sh
go get github.com/FastTLS/fastls@v0.1.1
go get github.com/FastTLS/imitate@v0.1.0
```

当前稳定核心版本为 `v0.1.1`；v2 是源码分支/实现代际，导入路径没有 `/v2` 后缀。使用正式标签可避免把尚未发布的默认分支功能当作稳定版本。

## 快速开始

```go
package main

import (
    "context"
    "fmt"
    "io"
    "log"
    "time"

    fastls "github.com/FastTLS/fastls"
    "github.com/FastTLS/fastls/imitate"
    generators "github.com/FastTLS/imitate"
)

func main() {
    options := fastls.Options{
        FingerprintProvider: generators.New(),
        VerifyTLS: true,
    }
    if _, err := imitate.Use(&options, "chrome/156/windows"); err != nil {
        log.Fatal(err)
    }
    if err := fetch(options); err != nil {
        log.Fatal(err)
    }
}

func fetch(options fastls.Options) error {
    session, err := fastls.NewSession(options)
    if err != nil { return err }
    defer session.Close()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    response, err := session.DoContext(ctx, "https://example.com/", fastls.RequestOptions{}, "GET")
    if err != nil {
        if response.Body != nil { response.Body.Close() }
        return err
    }
    defer response.Body.Close()
    fmt.Println(response.Status, response.Protocol, response.FinalURL)
    _, err = io.Copy(io.Discard, response.Body)
    return err
}
```

`Use` 必须显式提供生成器或离线 Provider。配置名称以该版本 Provider 的 List 为准，未知名称报错。自定义 JA3/JA4R 和完整 Spec 不需要生成器。

## 支持什么

- HTTP/1.1、HTTP/2；有序请求头、Cookie、HTTP/HTTPS CONNECT 与 SOCKS5 代理。
- JA3、JA4R、完整 Spec；用户请求头值优先于生成默认值。
- 可并发复用的 Session、连接池、上下文取消、阶段超时、流式上传下载、请求/响应 Trailer、按需解压及 H2 全双工。
- WS/WSS 的 HTTP/1.1 Upgrade；受限的 HTTP/3 路径。

## 限制与重要行为

- Go 指纹 TCP TLS 的历史零值不启用证书验证，新项目应显式设置 `VerifyTLS: true`；SDK 的默认策略不同。
- `Options.Timeout` 用于一次性请求；Session 的总时限由每次 `DoContext` 的 context 决定，阶段预算在 `RequestOptions.Timeouts`。
- 必须关闭响应体及 Session；网络错误也可能在读取正文时出现。HTTP 错误状态需自行处理，Trailer 在 EOF 后完整。
- 完整 Spec 面向 H1/H2；H3 不保证任意 ClientHello 顺序，且拒绝代理，不会静默直连。
- WebSocket 不支持压缩、任意 Upgrade 头序、自动重定向或 H2/H3 Extended CONNECT。
- 不是浏览器运行时，不执行页面 JavaScript，不提供验证码处理、完整浏览器模拟或第三方服务成功率保证。
- 开发分支的地址策略、生命周期修复等须以实际标签说明为准，不能仅凭默认分支文档推断已发布。

## 仓库内文档

- [指纹、离线数据与能力范围](imitate/README.md)
- [profile 规范](profile/README.md)
- [独立服务](services/README.md) · [测试工具](tools/README.md)
- 维护者：[开发指南](DEVELOPMENT.md) · [发布流程](RELEASE.md)

## 详细文档与问题反馈

- [使用文档](https://fasttls.github.io/fastls/)：安装、功能、参数与排错。
- [版本与发布说明](https://github.com/FastTLS/fastls/releases)：正式版本、开发版本和产物边界。
- [问题反馈](https://github.com/FastTLS/fastls/issues)：请提供版本、系统架构、脱敏后的最小示例与错误；不要提交凭据、Cookie、私钥或个人数据。

## 开源协议与第三方声明

自有代码采用 [Apache-2.0](LICENSE)，版权和归属见 [NOTICE](NOTICE)。第三方代码保留原许可证，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 使用边界与免责声明

仅在拥有权限的系统、数据和网络上使用，并遵守适用法律、服务条款及隐私要求。软件按许可证约定以“现状”提供，不承诺可用性、特定用途适用性、第三方服务放行、匿名性或与真实浏览器完全一致。浏览器名称和版本用于描述配置，不表示获得相应厂商认证或背书。部署方负责访问控制、密钥和个人信息保护、请求限额及数据备份；担保排除与责任限制以随附许可证及适用法律为准。本说明不改变许可证授予的权利或新增许可限制。
