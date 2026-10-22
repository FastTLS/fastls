# tools

本地测试工具，不属于 Fastls 库。

| 目录 | 作用 |
|------|------|
| `fastls-target` | HTTP/HTTPS 靶场，回显请求并统计访问 |
| `fastls-bench` | HTTP 压力测试客户端，统计 QPS、成功率和响应时间 |

两个工具各自是独立的 Go module，只依赖标准库。典型用法是先启动靶场，再用 bench 对它压测。详见各自目录下的 README。
