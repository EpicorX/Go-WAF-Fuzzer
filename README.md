# Go-WAF-Fuzzer

一个使用 Go 编写的并发式 WAF 规则回归测试工具

用于 WAF 规则验证、规则回归和样本回放。它会读取本地 payload 语料，对目标接口进行并发请求，根据 HTTP 状态码对结果进行分类，并在终端输出一份便于查看的统计表。

## 项目定位

- 贴近真实 WAF 研发工作：语料回放、规则回归、批量验证
- 能体现 Go 工程能力：并发、CLI、HTTP 客户端、结构化报告、单元测试

## 功能特性

- 可配置并发 worker 数量
- 支持 `query`、`form`、`json` 三种请求模式
- 按状态码分类为 `blocked`、`allowed`、`unexpected`、`error`
- 默认只允许本地或私网目标
- 支持导出 JSON 报告，方便后续分析或接 CI
- 自带本地 mock WAF 服务，开箱可演示

## 快速开始

先在一个终端启动本地 mock 服务：

```bash
go run ./examples/mock-server
```

再在另一个终端运行测试器：

```bash
go run ./cmd/go-waf-fuzzer -ack-authorized-testing
```

示例输出：

```text
WAF Regression Summary

Metric        Value
------------  ---------------------------------------
Target        http://127.0.0.1:8080/inspect
Method        GET
Mode          query
Payload file  examples/payloads.txt
Payloads      6
Blocked       4 (66.7%)
Allowed       2 (33.3%)
Unexpected    0
Errors        0
Avg latency   3ms
Fastest       1ms
Slowest       8ms
```

## 语料格式

`examples/payloads.txt` 支持两种格式：

```text
# label<TAB>payload
baseline-homepage	hello-world
xss-signal	xss-probe-string

# 或者只写 payload
normal-search-term
```

仓库中的示例语料是刻意做成无害形式的。实际使用时，你可以替换成自己在授权环境内维护的回归测试样本。

## 常用参数

```bash
go run ./cmd/go-waf-fuzzer \
  -ack-authorized-testing \
  -url http://127.0.0.1:8080/inspect \
  -payloads examples/payloads.txt \
  -workers 16 \
  -mode json \
  -method POST \
  -param input \
  -block-codes 403,406 \
  -allow-codes 200 \
  -json-out reports/latest.json
```

重点参数说明：

- `-ack-authorized-testing`：必须显式确认后才允许执行
- `-allow-remote`：如果目标不是本地或私网地址，需要额外开启
- `-mode`：请求模式，可选 `query`、`form`、`json`
- `-header`：可重复传入自定义请求头，例如 `-header "X-Env: staging"`
- `-json-out`：输出结构化 JSON 报告

## 开发方式

运行测试：

```bash
go test ./...
```

构建二进制：

```bash
go build ./cmd/go-waf-fuzzer
```

## 项目结构

```text
cmd/go-waf-fuzzer        CLI 入口
internal/fuzzer          配置、语料加载、并发执行、报告输出
examples/mock-server     本地演示服务
examples/payloads.txt    无害示例语料
```

## 安全说明

请只在你拥有或明确获得授权的系统上使用本项目。CLI 默认要求传入 `-ack-authorized-testing`，并且只允许本地或私网目标；如果你确实要对远程授权目标进行测试，需要额外传入 `-allow-remote`。
