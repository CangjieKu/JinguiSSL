# jinguiSSL Contract API Boundary

## Freeze Meta

- facade api version: `1.0.0`
- stability level: `L1`
- import rule: 默认仅 `import jinguissl.contract.*`

## Stable Domains

- `envelope`：AEAD envelope 与统一错误结果模型
- `x509`：证书解析、证书链校验、hostname / pinning 简化校验
- `tls12`：HTTP 场景需要的 TLS 1.2 握手与记录层入口
- `tls13`：HTTP 场景需要的 TLS 1.3 握手、ticket / cache、key-update、exporter
- `ssh`：SSH KEX、host verification、transport protection 所需 facade
- `hkdf`：HKDF extract / expand / derive 与场景化 key-set 导出
- `random`：CSPRNG 探测与随机字节生成

## Evolution Rule

- 允许：新增 facade API、扩展返回字段、增加新算法枚举值
- 不允许：未升级大版本前删除、重命名或改变既有 facade 语义
- 业务层与框架层应避免深度依赖 `jinguissl.crypto.*`

## Current Public Additions

- TLS 1.3 ticket 生命周期与会话缓存策略
- X.509 `try/outcome` 统一结果模型
- HKDF 的 HTTP / SSH key-set 导出入口
