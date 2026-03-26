# jinguiSSL

`jinguiSSL` 是纯仓颉实现的 SSL/TLS 与密码学库，当前优先交付 **HTTP / SSH 所需的库能力**，对外推荐通过稳定 facade：

```cangjie
import jinguissl.contract.*
```

## 当前公开范围

- 库形态：`static` 仓颉库
- 公开源码：`src/`
- 公开测试：`src/jinguissl/tests/`
- 公开向量与夹具：`testdata/`
- 公开示例：`examples/phase1-demo/`
- 公开文档：`docs/`

## 能力概览

- 对称能力：AES-GCM、ChaCha20-Poly1305、HKDF、CSPRNG
- 非对称能力：RSA、ECDHE（P-256 / P-384）、X25519、ECDSA、Ed25519
- 证书能力：X.509 解析、证书链校验、hostname / pinning 简化校验
- 协议能力：TLS 1.2、TLS 1.3、SSH KEX / host verification 所需核心库接口

## 公开文档

- API 边界：`docs/API_BOUNDARY.md`
- HTTP / SSH 能力矩阵：`docs/CAPABILITY_MATRIX.md`
- SSH facade：`docs/SSH_FACADE.md`
- 集成门禁：`docs/INTEGRATION_GATE.md`

## 构建与验证

```bash
cjpm build
cjpm test
```

## 集成约定

- 业务层 / 框架层默认仅依赖 `jinguissl.contract.*`
- 不建议在外部模块中深度依赖 `jinguissl.crypto.*`
- 当前仓库优先提供**库能力**，不包含 HTTP 服务框架或 SSH 套件应用层实现

## 示例

- `examples/phase1-demo/`：基础大数、兼容层、合规策略的最小调用样例

## 许可证

- `Apache-2.0`
