# 协议配置与公网观测测试

根目录 `go test ./...` 不会自动进入本目录。

纯配置文件为 `h2settings_string_completeness_test.go`、`http2settings_string_test.go`、`no_rfc7540_priorities_test.go`、`unknown_setting_test.go` 和 `ja4_core_test.go`。在核心目录执行：

```sh
go test ./_tests -run '^(TestH2SettingsStringCompleteness|TestH2SettingsStringLimitations|TestHTTP2SettingsStringOverride|TestParseH2SettingsStringWithPHeaderOrder|TestNO_RFC7540_PRIORITIES|TestUnknownSettingID|TestJa4FingerprintType|TestJa4FingerprintValue|TestJa4FingerprintIsEmpty|TestOptionsIsJa4|TestOptionsGetFingerprintType|TestOptionsGetFingerprintValue|TestJa4FingerprintInterface)$' -count=1 -timeout 60s
```

`ja3_custom_test.go` 和 `stdlib_fingerprint_test.go` 访问公网，仅显式选择后运行。独立 Fetch 服务的旧接口测试已从核心移除，归属独立服务仓库。

当前浏览器数据回归在独立 imitate 仓库；Provider、HTTP1/HTTP2、请求头覆盖、WS/WSS 和代理发包检查见 [联调模块](../integration/imitate/integration_test.go)。跨仓执行方式见 [开发说明](../DEVELOPMENT.md)。`scripts/legacy-test-inventory.json` 只列当前保留测试，历史清单位于工作区清理备份。
