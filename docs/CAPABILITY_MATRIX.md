# jinguiSSL HTTP / SSH Capability Matrix

## Scope

本清单仅覆盖 **库能力**，不包含 HTTP 服务框架、SSH daemon 或客户端应用层编排。

## HTTP / HTTPS

- TLS 1.2：ClientHello / ServerHello、RSA / ECDHE(P-256 / P-384)、AES-GCM / ChaCha20-Poly1305 记录层
- TLS 1.3：X25519 / ECDHE、PSK、0-RTT、ticket / cache、KeyUpdate、Exporter
- X.509：PEM / DER 解析、证书链校验、hostname 校验、pinning、简化 verify facade
- AEAD：AES-256-GCM、ChaCha20-Poly1305 Envelope API
- KDF / Random：HKDF、CSPRNG 可用性探测与随机字节生成

## SSH

- X25519 KEX、NEWKEYS gate、会话密钥派生、rekey
- host key / host signature 校验：RSA-SHA2、ECDSA、Ed25519
- known-host pinning（SHA-256）
- SSH packet protection：AES-CTR + HMAC、AEAD 路径

## Integrator Guidance

- 上层默认依赖 `jinguissl.contract.*`
- 仅在库内部实现中使用 `jinguissl.crypto.*`
- 当前公开仓库优先交付库核心，不包含动态 bridge 与应用层框架接线代码
