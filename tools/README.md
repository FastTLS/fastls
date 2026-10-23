# 本地测试工具

工具各自为独立 Go module，均只依赖标准库：

- [fastls-target](fastls-target/README.md)：HTTP/HTTPS 靶场，回显请求并统计访问。
- [fastls-bench](fastls-bench/README.md)：HTTP 压测，统计吞吐、成功率和响应时间。
- [fastls-check](fastls-check/README.md)：按显式计划执行检查，生成 HTML/JSON/Markdown/JUnit 报告。

更完整的 TLS/HTTP2/WS/WSS 指纹采集使用独立 [fastls-lab](https://github.com/FastTLS/fastls-lab)。工具和服务不属于核心库运行依赖。
