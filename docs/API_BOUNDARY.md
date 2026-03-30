# jinguiSSL Contract API Boundary

## Freeze Meta

- release line: `0.6.0`
- facade api version: `1.0.0`
- stability level: `L1`
- import rule: 默认仅 `import jinguissl.contract.*`

## Stable Domains

- `envelope`：AEAD envelope 与统一错误结果模型
- `x509`：证书解析、证书链校验、hostname / pinning 简化校验
- `tls12`：HTTP 场景需要的 TLS 1.2 握手、证书握手校验、RSA / ECDHE 秘钥交换与记录层入口
- `tls13`：HTTP 场景需要的 TLS 1.3 握手、ticket / cache、PSK、0-RTT、key-update、exporter
- `ssh`：SSH KEX、host verification、host-signing material、transport protection 所需 facade
- `hkdf`：HKDF extract / expand / derive 与场景化 key-set 导出
- `random`：CSPRNG 探测与随机字节生成

## Stable Surface Notes

- HTTP / HTTPS 集成侧优先通过 request/result/outcome 风格 API 使用 facade
- TLS 服务端材料与客户端 trust 材料都提供了预检查 + material preparation 双层入口
- TLS 1.3 verified-session 结果已暴露后续 exporter、traffic secret rotation 与 session ticket 流程所需材料
- SSH facade 已覆盖 host key fingerprint、host-signing material、client/server initial-handshake、runtime bundle 与 required-host-verification 模式
- SSH runtime 已覆盖 current-session snapshot 与 X25519 rekey facade
- SSH request-style facade 已补到 transcript / negotiated algorithms / X25519 KEX helpers / session-state rekey
- SSH KEXINIT message build / encode / decode / negotiate / transcript builder 已进入稳定 contract 面
- SSH version banner build / codec、plaintext transport packet codec、decoded prelude -> transcript builder 已进入稳定 contract 面
- SSH `KEX_ECDH_INIT` / `KEX_ECDH_REPLY` message codec 已进入稳定 contract 面
- 当前不把 `jinguissl.crypto.*`、`bridges/`、`_helper/` 视为公开稳定契约的一部分

## Evolution Rule

- 允许：新增 facade API、扩展返回字段、增加新算法枚举值
- 不允许：未升级大版本前删除、重命名或改变既有 facade 语义
- 业务层与框架层应避免深度依赖 `jinguissl.crypto.*`

## Current Public Additions

- HTTP server TLS material preparation facade
- HTTP client trust material preparation facade
- TLS 1.3 ticket 生命周期、session cache、PSK、early-data replay gate
- TLS 1.3 session ticket / cache / PSK request-style facade
- TLS 1.3 early-data prepare / accept / HTTP accept request-style facade
- TLS 1.3 key-update / exporter / cipher-binding request-style facade
- TLS 1.3 verified-session runtime facade（cipher binding / exporter / record channel / key-update）
- TLS 1.3 verified-session state-advance facade（updated session + channel set）
- SSH host-signing material facade（RSA PKCS8 / ECDSA PKCS8 / Ed25519 seed）
- SSH client/server initial-handshake facade 与 required verify 模式
- SSH client/server runtime facade（transport convenience / sequence / session accessor）
- SSH runtime current-session / rekey facade（mutable session snapshot）
- SSH transcript / negotiated algorithms / X25519 KEX request facade
- SSH KEXINIT negotiation facade（default builder / codec / transcript helper）
- SSH version banner / plaintext transport packet / prelude transcript facade
- SSH KEX_ECDH init/reply codec facade
- X.509 `try/outcome` 统一结果模型与 PEM bundle normalization
- HKDF 的 HTTP / SSH key-set 导出入口
