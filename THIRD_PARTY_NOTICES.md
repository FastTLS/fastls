# 第三方许可与分发声明

FastTLS 自有代码采用根目录的 Apache-2.0；该选择也适用于本仓库独立 Go 子模块中由 FastTLS 授权的代码。根目录及各子模块的 `NOTICE` 保留项目版权信息。已有第三方版权头、许可证、专利和归属声明不因本项目选择 Apache-2.0 而改变。

## 随附的依赖材料

`third_party/licenses/manifest.json` 记录当前核心包在本机由 Go 实际选择的依赖版本、原始许可文件路径和 SHA-256；[许可目录](third_party/licenses/)按模块路径保留原始文件内容，包含子目录中的独立许可证及 PATENTS 等材料。Go 标准库/运行时的许可证另存于 `third_party/licenses/go/LICENSE`。

此快照包含：

- github.com/andybalholm/brotli v1.2.0
- github.com/gorilla/websocket v1.5.3
- github.com/klauspost/compress v1.18.1
- github.com/quic-go/qpack v0.6.0
- github.com/quic-go/quic-go v0.57.1
- github.com/refraction-networking/utls v1.8.1
- golang.org/x/crypto v0.41.0
- golang.org/x/net v0.43.0
- golang.org/x/sys v0.35.0
- golang.org/x/text v0.28.0
- h12.io/socks v1.0.3
- 构建工具链中的 Go 标准库和运行时许可。

目录中的副本用于保留上游原声明，不构成对整个依赖模块使用同一种许可证的断言。修改依赖版本时须重新检查原文件、嵌入的第三方来源和该版本的分发要求。该清单是当前核心依赖的材料快照，不是所有平台、工具、示例及测试依赖的完整清单。

## fhttp 的继承代码

`github.com/FastTLS/fhttp` 是独立依赖仓库。本次检查的提交为 `e027ce786984d3e7e831b0d10c54875dec746b35`。其 HTTP/HTTP2 等文件带有 Go Authors 的 BSD-style 许可头，但当前检出未提供对应的顶层 LICENSE。

本项目不把这些代码重新授权为 Apache-2.0，也不替独立仓库的其他贡献者作出授权。正式分发前，须在 fhttp 中核实并恢复其确切来源对应的许可和必要声明；仅附 Go 运行时的许可证不能代替完成 fhttp 来源核对。

## 下游二进制与独立模块

- 分发包含本项目代码的动态库、wheel、npm 包或程序时，随附本项目 LICENSE/NOTICE，以及实际打入产物的依赖所要求的许可和声明；仅有仓库链接不能替代要求随附的文本。
- 独立 Go 子模块分别携带完整 LICENSE/NOTICE。它们的依赖仍依各自原许可分发，不因模块目录中出现 Apache-2.0 而被重新授权。
- 本次只落实 fastls 仓库及其子模块的许可。独立的 imitate、FFI 和其他 SDK 仓库须分别处理自己的许可和打包元数据，不能仅因依赖 fastls 就宣称这些仓库已经完成许可配置。
- 在未完成依赖来源核对、版本发布和实际产物随附检查前，保持现有开发候选状态；本次不创建正式 Release 或发布模块标签。
