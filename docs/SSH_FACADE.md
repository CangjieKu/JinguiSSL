# jinguiSSL SSH Facade

## Goal

为 SSH 集成方提供稳定的 `contract` 层，不直接暴露 `crypto.ssh` 内部实现细节。

## Stable Types

- `ContractSshKexExchangeTranscript`
- `ContractSshNegotiatedAlgorithms`
- `ContractSshHostVerificationPolicy`
- `ContractSshHostVerificationResult`
- `ContractSshSessionState`
- `ContractSshServerRuntimeBundle`
- `ContractSshClientRuntimeBundle`

## Stable APIs

- `contractSshBuildVersionBanner(...)`
- `contractSshBuildDefaultKexInit(...)`
- `contractSshBuildKexExchangeTranscriptFromPrelude(...)`
- `contractSshNegotiateKexInit(...)`
- `contractSshBuildKexEcdhInitX25519(...)`
- `contractSshCompleteServerInitialHandshakeX25519*Request(...)`
- `contractSshCompleteClientInitialHandshakeX25519Request(...)`
- `contractPrepareSshServerRuntimeRequest(...)`
- `contractPrepareSshClientRuntimeRequest(...)`
- `contractPrepareSshServerRuntimeRekeyFromSessionStateRequest(...)`
- `contractPrepareSshClientRuntimeRekeyFromSessionStateRequest(...)`
- `contractSshComputeHostKeySha256(...)`
- `contractSshVerifyHostIdentity(...)`
- `contractSshVerifyHostIdentityRequired(...)`

## Policy Model

- `expectedHostKeySha256`
- `requireKnownHost`
- `requireHostSignature`
- `allowLegacyRsaSha1`
- `requireVerifiedHost`

## Error Contract

- 非法输入、解析失败、不支持算法、签名不匹配，统一通过 contract 层错误模型返回
- 上层应消费 contract 结果，而不是直接拼接 `crypto.ssh` 细节

## Implementation Reference

- 若你要自己实现 SSH banner / KEXINIT / handshake / runtime / rekey 接线，优先看：
  - `HANDSHAKE_INTERFACE_GUIDE.md`
  - `examples/handshake-interface-demo/`
