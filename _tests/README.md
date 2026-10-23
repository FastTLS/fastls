# 协议配置与公网观测测试

根目录 `go test ./...` 不会自动进入本目录。

纯配置文件为 `h2settings_string_completeness_test.go`、`http2settings_string_test.go`、`no_rfc7540_priorities_test.go`、`unknown_setting_test.go` 和 `ja4_core_test.go`。在核心目录执行：

```sh
go test ./_tests -run '^(TestH2SettingsStringCompleteness|TestH2SettingsStringLimitations|TestHTTP2SettingsStringOverride|TestParseH2SettingsStringWithPHeaderOrder|TestNO_RFC7540_PRIORITIES|TestUnknownSettingID|TestJa4FingerprintType|TestJa4FingerprintValue|TestJa4FingerprintIsEmpty|TestOptionsIsJa4|TestOptionsGetFingerprintType|TestOptionsGetFingerprintValue|TestJa4FingerprintInterface|TestPeetValidation)$' -count=1 -timeout 60s
```

`peet_validation_test.go` 是纯本地响应校验回归。公网测试须从核心目录执行 `python scripts/check-peet.py`，其中包含 `ja3_custom_test.go` 和 `stdlib_fingerprint_test.go` 的5个请求。只有该入口显式设置 FASTLS_PEET_NETWORK=1 时才联网；未启用时记为 skip，不能算公网验证通过。入口生成HTML/Markdown/JSON/JUnit及逐请求响应证据，默认20秒请求超时，不自动重试。独立 Fetch 服务的旧接口测试已从核心移除，归属独立服务仓库。

当前浏览器数据回归在独立 imitate 仓库；Provider、HTTP1/HTTP2、请求头覆盖、WS/WSS 和代理发包检查见 [联调模块](../integration/imitate/integration_test.go)。跨仓执行方式见 [开发说明](../DEVELOPMENT.md)。`scripts/legacy-test-inventory.json` 只列当前保留测试，历史清单位于工作区清理备份。
