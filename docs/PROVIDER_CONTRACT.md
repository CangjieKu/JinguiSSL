# jinguiSSL Provider Contract

## Goal

这份文档服务于 provider 选择层，而不是应用层。

当前定位固定为：

- `jinguissl` 是一个可被 `lisi` 吸收的 TLS / crypto provider 候选
- 当前已具备稳定的 precheck / material preparation / verify / error descriptor contract
- 当前**不是**默认 HTTPS listener 路径

## Stable Contract Helpers

当前公开稳定的 provider 侧 helper：

- `contractProviderCapabilityRecord()`
- `contractProviderAttachContractInfo()`
- `contractProviderServerAttachBoundary()`
- `ContractProviderSmokeFixtureCategory`
- `ContractProviderSmokeFixtureInfo`
- `ContractProviderSmokeExecutionMode`
- `ContractProviderSmokeBaselineRequest`
- `ContractProviderSmokeBaselineReport`
- `ContractProviderSmokeBaselineOutcome`
- `ContractProviderSmokeSuiteRequest`
- `ContractProviderSmokeSuiteReport`
- `ContractProviderSmokeSuiteOutcome`
- `ContractProviderSmokeSelfCheckPolicy`
- `ContractProviderSmokeSelfCheckReport`
- `ContractProviderSmokeSelfCheckOutcome`
- `contractProviderSmokeFixtureCatalog()`
- `contractRequireProviderSmokeFixture(...)`
- `contractDescribeProviderSmokeBaseline(...)`
- `contractDescribeProviderSmokeBaselineRequest(...)`
- `contractTryDescribeProviderSmokeBaselineRequest(...)`
- `contractDescribeProviderSmokeSuite()`
- `contractDescribeProviderSmokeSuiteRequest(...)`
- `contractTryDescribeProviderSmokeSuiteRequest(...)`
- `contractProviderSmokeSelfCheck(...)`
- `contractRequireProviderSmokeSelfCheck(...)`
- `contractTryProviderSmokeSelfCheck(...)`
- `contractTryRequireProviderSmokeSelfCheck(...)`
- `contractDescribeProviderErrorCode(...)`
- `contractDescribeProviderContractException(...)`
- `contractDescribeProviderCryptoException(...)`
- `contractRecommendProviderFallback(...)`

## Capability Record

当前 `0.6.16` provider 记录：

- `providerId`: `jinguissl`
- `providerVersion`: `0.6.16`
- `platformScope`: `primary darwin/aarch64; compile-target linux/ohos aarch64; x86_64 deferred to 0.7; loongarch64/riscv64 reserved skeletons`
- `cjScope`: `cjc >= 1.1.0`
- `supportsClientTls`: `true`
- `supportsServerTlsAttach`: `false`
- `supportsX509Verify`: `true`
- `supportsAlpnH2`: `true`
- `supportsMtls`: `false`
- `supportsSessionCache`: `true`
- `experimental`: `true`
- `defaultEligible`: `false`

当前 `unsupportedReasons`：

- 稳定的 server-side TLS attach contract 尚未公开
- 不提供直接 `stdx.net.tls.TlsServerConfig` bridge
- 当前发布线仍是 provider-candidate，不应表述为默认 HTTPS 路径

## Attach Contract

### TLS Precheck Inputs

当前稳定 precheck 侧建议字段：

- `serverName`
- `alpnProtocols`
- `certificatePem`
- `privateKeyPem`
- `trustAnchorsPem`
- `verifyMode`
- `handshakeTimeoutMs`

### TLS Attach Inputs

当前 attach 字段只作为 provider planning contract 保留：

- `serverName`
- `alpnProtocols`
- `certificatePem`
- `privateKeyPem`
- `clientAuthPolicy`
- `sessionTicketPolicy`
- `handshakeTimeoutMs`

结论：

- 这些字段已可用于上层 planning / 记录
- 但本仓不保证稳定的最终 attach 落点

### X.509 Verify Inputs

- `peerCertificatePem`
- `peerChainPem`
- `trustAnchorsPem`
- `expectedHost`
- `verifyMode`
- `pins`

### Failure Fields

provider 侧建议上层至少记录：

- `family`
- `phase`
- `retryable`
- `fallbackSuggested`
- `contractCode`
- `igniteCode`
- `message`

## Current Server Attach Boundary

`contractProviderServerAttachBoundary()` 当前固定返回：

- `status = PRECHECK_ONLY`
- `stableAttach = false`
- `blockingLayer = stdx contract / attach bridge`
- `recommendedFallback = fallback to stdx through lisi and keep jinguissl as provider-candidate only`

这意味着：

- `jinguissl` 目前可以稳定提供 precheck、material preparation、client TLS、X.509 verify
- `jinguissl` 目前不能在公开契约上承诺 server-side attach
- 真正的 attach、fallback 与记录应由 `lisi` 负责

## Error Model

### Family

当前 provider family 建议最少使用：

- `BAD_INPUT`
- `VERIFY_FAILED`
- `KEY_NOT_FOUND`
- `CRYPTO_UNAVAILABLE`
- `COMPLIANCE_REJECTED`
- `UNSUPPORTED`
- `INTERNAL_ERROR`
- `TLS_PRECHECK_ERROR`
- `TLS_HANDSHAKE_ERROR`
- `TLS_VERIFY_ERROR`
- `PROVIDER_UNAVAILABLE`

### Phase

当前 provider phase 建议使用：

- `PROVIDER_SELECTION`
- `TLS_PRECHECK`
- `TLS_HANDSHAKE`
- `TLS_VERIFY`
- `PROVIDER_RUNTIME`

### Mapping Intent

- `VERIFY_FAILED + TLS_PRECHECK` -> `TLS_PRECHECK_ERROR`
- `VERIFY_FAILED + TLS_HANDSHAKE` -> `TLS_HANDSHAKE_ERROR`
- `VERIFY_FAILED + TLS_VERIFY` -> `TLS_VERIFY_ERROR`
- `CRYPTO_UNAVAILABLE + PROVIDER_SELECTION / PROVIDER_RUNTIME` -> `PROVIDER_UNAVAILABLE`
- 其余错误优先保持原始 family，而不是全部压成一段 message

## Fallback Recommendation

`contractRecommendProviderFallback(...)` 当前建议：

- `PROVIDER_UNAVAILABLE` / `CRYPTO_UNAVAILABLE` / `UNSUPPORTED`
  - 建议回退到 `stdx`
- `TLS_HANDSHAKE_ERROR`
  - 可谨慎重试，或回退到 `stdx`
- `BAD_INPUT` / `COMPLIANCE_REJECTED` / `TLS_PRECHECK_ERROR` / `TLS_VERIFY_ERROR`
  - 不建议自动回退，应直接上抛

## Smoke Fixture Coverage

当前公开仓库现在通过 `contractProviderSmokeFixtureCatalog()` / `contractRequireProviderSmokeFixture(...)`
直接暴露一组稳定的 smoke / fault-baseline 元数据，供 provider 选择层消费。

当前固定 catalog：

- `success-x509-policy-chain`
  - category: `SUCCESS`
  - artifacts:
    - `testdata/x509/policy_root.pem`
    - `testdata/x509/policy_intermediate.pem`
    - `testdata/x509/policy_leaf.pem`
    - `testdata/x509/policy_leaf_key_pkcs8.pem`
- `precheck-cert-key-mismatch`
  - category: `PRECHECK_FAIL`
  - expected phase / family: `TLS_PRECHECK` / `TLS_PRECHECK_ERROR`
- `verify-hostname-mismatch`
  - category: `VERIFY_FAIL`
  - expected phase / family: `TLS_VERIFY` / `TLS_VERIFY_ERROR`
- `verify-pin-mismatch`
  - category: `VERIFY_FAIL`
  - expected phase / family: `TLS_VERIFY` / `TLS_VERIFY_ERROR`
- `handshake-server-hello-decode`
  - category: `HANDSHAKE_FAIL`
  - expected phase / family: `TLS_HANDSHAKE` / `TLS_HANDSHAKE_ERROR`
- `provider-not-linked`
  - category: `PROVIDER_UNAVAILABLE`
  - expected phase / family: `PROVIDER_SELECTION` / `PROVIDER_UNAVAILABLE`

建议上层至少区分：

- `precheck fail`
- `handshake fail`
- `verify fail`
- `provider unavailable`

如果上层要把 smoke suite 做成固定配置，而不是硬编码测试路径，建议：

- 通过 `fixtureId` 选定 smoke baseline
- 通过 `expectedPhase` / `expectedFamily` 统一错误桶
- 通过 `entrypoints` 决定调用哪一层 facade，而不是深挖 `crypto.*`

## Smoke Baseline Report

现在推荐 provider 选择层直接使用：

- `contractDescribeProviderSmokeBaseline(...)`
- `contractDescribeProviderSmokeBaselineRequest(...)`
- `contractTryDescribeProviderSmokeBaselineRequest(...)`

report 会把下面几层统一组装好：

- `fixture`：原始 smoke fixture metadata
- `executionMode`
  - `PRECHECK_PATH`
  - `VERIFY_PATH`
  - `PROVIDER_SELECTION_PATH`
  - `METADATA_ONLY`
- `expectedDescriptor`
- `expectedFallback`
- `capability`
- `attachBoundary`
- `warnings`

当前设计意图：

- 上层不必重复调用 `contractDescribeProviderErrorCode(...)` / `contractRecommendProviderFallback(...)`
- 上层可以直接按 `executionMode` 决定 smoke suite 应跑 precheck、verify、provider-selection，还是仅做 metadata assertion
- 当前 `HANDSHAKE_FAIL` baseline 会固定走 `METADATA_ONLY`，因为公开仓库尚未承诺稳定的 server-side attach / live provider handshake 入口

## Smoke Suite Report

如果上层不想逐个 fixture 查询，也可以直接用：

- `contractDescribeProviderSmokeSuite()`
- `contractDescribeProviderSmokeSuiteRequest(...)`
- `contractTryDescribeProviderSmokeSuiteRequest(...)`

suite report 会额外聚合：

- `baselines`
- `totalFixtureCount`
- `successFixtureCount`
- `failureFixtureCount`
- `precheckPathCount`
- `verifyPathCount`
- `providerSelectionPathCount`
- `metadataOnlyCount`
- `recommendedOrder`

这适合 provider 选择层在启动时拿一份“当前公开 smoke 计划总览”，再决定：

- 哪些项在 CI 中跑真实 precheck / verify
- 哪些项只做 metadata assertion
- 哪些项属于 provider-unavailable 预期路径，不应误报成运行故障

## Smoke Self-Check

如果上层希望把 smoke suite 再进一步收敛成一个“是否满足 provider 接入门槛”的 readiness 结论，可直接使用：

- `contractProviderSmokeSelfCheck(...)`
- `contractRequireProviderSmokeSelfCheck(...)`
- `contractTryProviderSmokeSelfCheck(...)`
- `contractTryRequireProviderSmokeSelfCheck(...)`

默认 policy 会要求：

- `client TLS`
- `X.509 verify`
- `TLS precheck`
- 至少一个 success baseline
- precheck / verify / provider-selection / handshake coverage
- 所有失败 baseline 都给出 fallback decision

默认 policy **不会**要求：

- stable server-side attach
- default HTTPS eligible
- live handshake coverage

这样做的原因是当前公开边界仍然是 `PRECHECK_ONLY`。因此默认 self-check 可以在“provider-candidate 可接入”层级返回 `overallReady = true`，同时通过 `warnings` 明确提示：

- 当前 release line 仍是 experimental / provider-candidate
- stable server attach 尚未发布
- handshake coverage 目前仍是 metadata-only

如果上层想收紧门槛，例如要求 stable attach 或 live handshake coverage，可以在 policy 中显式打开对应项；这时 `contractRequireProviderSmokeSelfCheck(...)` 会以 `UNSUPPORTED` 失败返回，便于 provider selector 或 CI gate 直接阻断。

## Non-Goals

当前这份 contract 不承诺：

- 直接替代默认 HTTPS listener
- 在 Ignite 主线暴露 provider backend 细节
- 让应用层自己承担 provider fallback 决策
