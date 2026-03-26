# jinguiSSL Integration Gate

## Goal

确保 HTTP / SSH 集成方在接入 `jinguiSSL` 时，优先通过稳定 facade 完成校验、握手输入预检查与错误统一映射。

## Current Gate

- `P0-1`：主库在当前主开发平台可 `cjpm build`
- `P0-2`：公开的 contract facade 能力测试持续通过
- `P0-3`：失败路径与错误码可观测
- `P0-4`：HTTP TLS 配置输入可先经 contract precheck 再进入外部 TLS 配置构造
- `P0-5`：公开库能力已具备作为 HTTP / SSH 集成核心的最小闭环

## Recommended Pattern

1. 上层先调用 contract facade 做证书、私钥、协商参数与策略预检查
2. 通过 precheck 后，再进入各自框架或运行时的 TLS / SSH 配置构造
3. 统一使用 contract 返回面做错误分流，而不是自行解析底层异常

## Public Constraint

- 当前公开仓库提供的是**库能力与 facade**
- HTTP 服务框架接线、动态 bridge、私有集成脚本不在本次公开范围
