# Fastls 服务与验证项目

这些项目在独立仓库维护，源码、使用说明、测试和版本发布请访问：

- [fastls-fetch：Fetch 服务](https://github.com/FastTLS/fastls-fetch)
- [fastls-mitm：MITM 代理](https://github.com/FastTLS/fastls-mitm)
- [fastls-rpc：JSON-RPC 与 gRPC 服务](https://github.com/FastTLS/fastls-rpc)
- [fastls-lab：请求指纹靶场，含 WS/WSS（建设中）](https://github.com/FastTLS/fastls-lab)

指纹生成逻辑由独立 [imitate](https://github.com/FastTLS/imitate) 维护；[fastls-fingerprints](https://github.com/FastTLS/fastls-fingerprints) 保存证据和固定导出物。

本目录仅提供访问入口，核心库无需初始化服务子模块。服务使用固定可获取的核心版本；本地联合开发在外层工作区引用并列仓库，不在服务 go.mod 中写维护者电脑路径。核心的 `scripts/check.ps1` / `scripts/check.sh` 按显式计划执行检查，可通过 `-plan` 指定自有仓库布局。
