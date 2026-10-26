# 发布与版本规则

Fastls v2 使用 `v0.1.0` 起步，但模块路径保持 `github.com/FastTLS/fastls`，因为 Go 的主版本路径规则不允许在没有 `/v2` 后缀时使用 `v2.0.0` 标签。`profile` 是同仓库的独立模块，使用 `profile/v0.1.0` 形式的标签。

## 当前正式基线

2026-10-25 完成首轮 GitHub-only 正式发布。当前稳定组合为 `ftransport v0.1.0`、`profile/v0.1.0`、`imitate v0.1.0` 和 `fastls v0.1.1`。`fastls v0.1.1` 修复 Session 缓冲请求 Trailer，并隔离直接模块下载验证；不可变的 `v0.1.0` 保留为历史版本。

正式下游基线为 `fastls-fetch v0.1.0`、`fastls-rpc v0.1.0`、`fastls-mitm v0.1.0` 和 `fastls-ffi v0.1.2`。版本状态以各仓库 GitHub Release 为准；开发文档中的旧候选号和旧 Actions 运行只表示当时证据。

正式链路按 `ftransport → profile → imitate → fastls → 下游服务/SDK` 顺序发布。所有公共 `go.mod` 必须使用可从 GitHub/Go 模块代理获取的不可变版本，不得含本地 `replace`；生产模块图必须拒绝 `github.com/FastTLS/fhttp`。

发布前必须运行[开发检查](DEVELOPMENT.md)、独立消费者、许可证材料和下游矩阵。交叉编译不能替代目标平台实际运行。标签和 GitHub Release 保持不可变，修正使用新补丁版本。

正式发布仅使用 GitHub 标签、GitHub Releases 和 GitHub Actions 来源证明；不在 PyPI、npm、容器仓库或其他索引发布。`profile` 标签是 Go 子模块版本，不单独创建面向用户的 GitHub Release。
