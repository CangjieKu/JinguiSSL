# jinguiSSL HTTP / SSH Capability Matrix

## Scope

本清单仅覆盖 **库能力**，不包含 HTTP 服务框架、SSH daemon 或客户端应用层编排。

当前版本快照：`0.6.0`

## HTTP / HTTPS

- TLS 配置与材料：
  - server TLS config validation
  - server TLS material preparation
  - client trust validation
  - client trust material preparation
- TLS 1.2：
  - ClientHello / ServerHello
  - RSA / ECDHE(P-256 / P-384) key exchange
  - certificate handshake build / verify
  - AES-GCM / ChaCha20-Poly1305 record channel
- TLS 1.3：
  - X25519 / ECDHE(P-256 / P-384) HTTP handshake facade
  - verified-session result
  - verified-session runtime helpers（cipher binding / exporter / record channel / key-update）
  - verified-session state advance（updated session / channel set）
  - PSK / session ticket / session cache
  - request-style session ticket / cache / PSK facade
  - request-style 0-RTT prepare / accept / HTTP accept facade
  - 0-RTT acceptance gate + replay cache
  - KeyUpdate / traffic secret rotation
  - Exporter / cipher-binding helpers
- X.509：
  - PEM / DER parse
  - certificate chain verify
  - hostname verify
  - leaf DER / SPKI pinning
  - RSA PKCS1 / PKCS8 and EC PKCS8 key parse
- AEAD：
  - AES-256-GCM
  - ChaCha20-Poly1305
  - Envelope JSON facade
- KDF / Random：
  - HKDF extract / expand / derive
  - HTTP / SSH key-set derivation
  - CSPRNG availability probe
  - random bytes / uint8 bytes

## SSH

- KEX / transport：
  - X25519 KEX
  - ECDH P-256 KEX
  - version banner build / decode / encode
  - decoded banner + KEXINIT prelude to transcript builder
  - KEX_ECDH_INIT / KEX_ECDH_REPLY encode / decode
  - NEWKEYS encode / decode
  - plaintext transport packet encode / decode
  - NEWKEYS gate
  - transport packet protection / rekey
- host verification：
  - RSA-SHA2 / ECDSA / Ed25519 host key and host signature verify
  - known-host pinning（SHA-256）
  - required-host-verification modes
- host-signing material facade：
  - RSA PKCS8 request
  - ECDSA PKCS8 request
  - Ed25519 seed request
- initial handshake facade：
  - client initial-handshake
  - server initial-handshake
  - result / outcome wrappers for request-style upper layers
  - client/server runtime bundle
  - transport convenience facade（session id / sequence / seal / open / reset counters）
  - current session snapshot
  - X25519 runtime rekey facade
  - request-style transcript / negotiated algorithms wrappers
  - X25519 KEX init/process helpers and session-state rekey entrypoints
  - KEXINIT default builder / codec / negotiation / transcript helper
  - version banner / prelude transcript request helpers
  - KEX_ECDH init/reply request helpers
  - NEWKEYS request helpers

## Integrator Guidance

- 上层默认依赖 `jinguissl.contract.*`
- 仅在库内部实现中使用 `jinguissl.crypto.*`
- 当前公开仓库优先交付库核心，不包含动态 bridge 与应用层框架接线代码
- HTTP / SSH 上层优先消费 contract 的 request/result/outcome 类型，而不是自己拼接底层 crypto 细节
