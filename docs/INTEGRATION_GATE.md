# jinguiSSL Integration Gate

## Goal

确保 HTTP / SSH 集成方在接入 `jinguiSSL` 时，优先通过稳定 facade 完成校验、握手输入预检查与错误统一映射。

## Naming Contract

- 品牌名：`jinguiSSL`
- `cjpm` 依赖名：`jinguissl`
- 稳定 import：
  - `jinguissl.contract.*`
- 当前构建产物前缀：
  - `libjinguissl*.a`

集成侧如果把品牌名 `jinguiSSL` 直接当作链接名使用，例如 `-ljinguiSSL.contract`，将无法命中实际产物。

当前公开仓库默认只把 `jinguissl.contract.*` 视为稳定依赖面；本地实验性 bridge 不属于当前公开契约。

## Current Gate

- `P0-1`：主库在当前主开发平台可 `cjpm build`
- `P0-2`：公开的 contract facade 能力测试持续通过
- `P0-3`：失败路径与错误码可观测
- `P0-4`：HTTP TLS 配置输入可先经 contract precheck 再进入外部 TLS 配置构造
- `P0-5`：公开库能力已具备作为 HTTP / SSH 集成核心的最小闭环
- `P0-6`：打包阶段可通过仓库内补完脚本产出可校验 `.cjp`

## Recommended Pattern

1. 上层先调用 contract facade 做证书、私钥、协商参数与策略预检查
2. 通过 precheck 后，再进入各自框架或运行时的 TLS / SSH 配置构造
3. 统一使用 contract 返回面做错误分流，而不是自行解析底层异常

## Packaging Gate

当前工具链下，原生 `cjpm bundle` 仍可能在已生成有效产物后，因 SHA256 相关索引阶段崩溃退出。

推荐发布路径：

```bash
./tools/cjpm_bundle_finish.sh
./tools/cjpm_bundle_audit.sh
```

发布前至少检查：

1. `cjpm build`
2. `cjpm test`
3. `./tools/cjpm_bundle_finish.sh`
4. `./tools/cjpm_bundle_audit.sh`

若第 3 步成功，说明当前仓库可产出有效 `.cjp`，即使原生命令退出码仍受上游工具链 bug 影响。

若第 4 步成功，说明：

- `.cjp` 制品可读；
- `.sha256` 与实际产物一致；
- bundle manifest 与制品、日志、已知上游崩溃语义保持一致。

## Public Constraint

- 当前公开仓库提供的是**库能力与 facade**
- HTTP 服务框架接线、动态 bridge、私有集成脚本不在本次公开范围
- `_helper/` 内的上下文备份、issue 留痕、参考仓库与本机路径文档不属于公开 API 文档
