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

2026-10-24 已核对 `github.com/FastTLS/fhttp` 的 `v2` 提交 `e027ce786984d3e7e831b0d10c54875dec746b35`、完整非浅克隆历史及上游 GitHub 目录。可复核的提交、许可文本哈希和远端快照见 [来源证据](third_party/fhttp-provenance.json)。结论分为两部分：

- **Go 来源部分已有 BSD 证据。** 159 个被跟踪的 Go 文件中，150 个包含 Go Authors 声明。fhttp 的历史提交 `f2903183edbd3bcf43b6b2e89e0ebfb086216bf9` 曾在 `vendor/golang.org/x/net/LICENSE` 保存 BSD 文本；该文本与 Go 1.16 的官方 LICENSE 逐字节一致，现作为 [历史 Go BSD 声明](third_party/licenses/fhttp-go-origin/Go-BSD-3-Clause)随附。它的原始位置是 vendor 依赖目录，并不是覆盖全部 fhttp 新增代码的仓库级授权。
- **fhttp 自身新增及修改的授权范围仍未确认。** GitHub fork 元数据表明 FastTLS/fhttp 的直接上游是 Danny-Dasilva/fhttp，源头为 useflyent/fhttp；本地历史中的 `eeeb0b347ce1dd26f36a69b009ac654dcf75ee84` 是 FastTLS 改动前的直接上游祖先，原模块声明也是 `github.com/Danny-Dasilva/fhttp`。扫描 84 个可达提交，没有发现仓库级 LICENSE/COPYING/NOTICE/PATENTS 的历史记录，只有 vendor 依赖声明。

源头 useflyent、直接上游 Danny-Dasilva，以及相关的 Carcraftz、bogdanfinn、Noooste 分支，在本次固定提交快照的根目录均未发现上述许可材料，GitHub 许可识别为空。pkg.go.dev 对 [Danny-Dasilva/fhttp](https://pkg.go.dev/github.com/Danny-Dasilva/fhttp) 和 [useflyent/fhttp](https://pkg.go.dev/github.com/useflyent/fhttp) 也显示未识别到许可。自动识别结果仅为辅助证据：未识别不等于证明不存在授权；同样，保留 Go 文件头也不足以由本项目单方面确认所有后续贡献的许可范围。文件计数不是逐文件授权认证，带 Go 版权头的文件中也可能包含后续修改。

因此，本次没有把整个 fhttp 标为 BSD 或 Apache-2.0，也没有用其他下游项目的许可证替代其自身授权。正式分发前仍须取得涵盖继承贡献的上游明确许可确认，或替换授权范围未明的实现；仅补一份 LICENSE 文本不能消除这项不确定性。没有向上游作者发送消息或提交 issue。

## 下游二进制与独立模块

- 分发包含本项目代码的动态库、wheel、npm 包或程序时，随附本项目 LICENSE/NOTICE，以及实际打入产物的依赖所要求的许可和声明；仅有仓库链接不能替代要求随附的文本。
- 独立 Go 子模块分别携带完整 LICENSE/NOTICE。它们的依赖仍依各自原许可分发，不因模块目录中出现 Apache-2.0 而被重新授权。
- 本次只落实 fastls 仓库及其子模块的许可。独立的 imitate、FFI 和其他 SDK 仓库须分别处理自己的许可和打包元数据，不能仅因依赖 fastls 就宣称这些仓库已经完成许可配置。
- 在未完成依赖来源核对、版本发布和实际产物随附检查前，保持现有开发候选状态；本次不创建正式 Release 或发布模块标签。
