# Fastls

[English](README_EN.md) · 中文

Go TLS 指纹请求库，支持自定义 JA3/JA4R、完整 profile.Spec、HTTP 请求头顺序及 HTTP/HTTPS/SOCKS5 代理。浏览器配置由独立 [FastTLS/imitate](https://github.com/FastTLS/imitate) 生成，Fastls 负责应用和发送请求。

当前 v2 为尚未公开发布的开发候选。下列 API 适用于本地开发版本；公共模块安装结果不代表已包含这些修改。

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

响应体由调用方关闭。无指纹请求在收到响应头后返回，取消、超时和读取错误可以在 Body.Read 时出现。完整 Spec 当前支持 HTTP1/HTTP2；完整 Spec 的 H3、WS Upgrade 任意头序和 H2 后续拨号取消仍有能力边界，见接入说明。

## 文档与工具

- [指纹应用、离线注册与能力范围](imitate/README.md)
- [开发、测试与目录说明](DEVELOPMENT.md)
- [共享 profile 规范](profile/README.md)
- [命令行探针源码](integration/imitate/cmd/fastls-probe/main.go)
- [测试工具](tools/README.md)
- [独立服务与靶场](services/README.md)
- [发布前置条件](RELEASE.md)

## 许可证

当前仓库没有 LICENSE 文件，正式发布前需确认授权与许可证。
