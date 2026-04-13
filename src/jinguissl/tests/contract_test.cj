package jinguissl.tests

import std.collection.{ArrayList, HashMap}
import std.fs.*
import jinguissl.contract.*
import jinguissl.crypto.bignum.BigNum
import jinguissl.crypto.digest.{HashAlgorithm, hkdf, hkdfExpand, hkdfExtract, sha256}
import jinguissl.crypto.ecc.{EcPrivateKey, NamedCurve, ecPublicFromPrivateKey}
import jinguissl.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl.crypto.ssh.*
import jinguissl.crypto.tls.*
import jinguissl.crypto.x25519.x25519PublicFromPrivate
import jinguissl.crypto.x509.{
    X509SelfSignedConfig,
    x509CreateSelfSignedRsaCertificate,
    x509ParseEcPrivateKeyPkcs8Pem,
    x509ParseRsaPrivateKeyPkcs8Pem
}

private let CONTRACT_TLS13_SUPPORTED_GROUPS_EXTENSION_TYPE: Int64 = 0x000a
private let CONTRACT_TLS13_GROUP_X25519_TEST: Int64 = 0x001d

@Test
public class ContractTestSuite {
    @TestCase
    public func testEnvelopeAesRoundTripJsonWithStoredAad(): Unit {
        let key = incrementalBytes(32, start: 1)
        let keyRing = HashMap<String, Array<Byte>>()
        keyRing.add("k1", key)

        let plaintext = "{\"hello\":\"ignite\"}".toArray()
        let aad = "http-request-aad".toArray()
        let envelopeJson = contractEncryptEnvelopeJsonV1(
            ContractAeadAlgorithm.Aes256Gcm,
            "k1",
            key,
            plaintext,
            aad: aad
        )

        let decrypted = contractDecryptEnvelopeJsonV1(envelopeJson, keyRing)
        @Assert(decrypted, plaintext)

        let parsed = ContractAeadEnvelopeV1.parseJson(envelopeJson)
        @Assert(parsed.ver, 1)
        @Assert(parsed.alg, "AES-256-GCM")
        @Assert(parsed.kid, "k1")

        try {
            _ = contractDecryptEnvelopeJsonV1(
                envelopeJson,
                keyRing,
                aadOverride: Some("wrong-aad".toArray())
            )
            @Fail("mismatched AAD override should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testEnvelopeChachaRoundTripAndTamperedTagReject(): Unit {
        let key = incrementalBytes(32, start: 41)
        let keyRing = HashMap<String, Array<Byte>>()
        keyRing.add("k2", key)

        let envelope = contractEncryptEnvelopeV1(
            ContractAeadAlgorithm.Chacha20Poly1305,
            "k2",
            key,
            "payload-for-chacha".toArray(),
            aad: "ws-frame".toArray()
        )

        let opened = contractDecryptEnvelopeV1(envelope, keyRing)
        @Assert(opened, "payload-for-chacha".toArray())

        let tampered = ContractAeadEnvelopeV1(
            envelope.ver,
            envelope.alg,
            envelope.kid,
            envelope.nonce,
            envelope.aad,
            envelope.ciphertext,
            tamperHeadAscii(envelope.tag)
        )
        try {
            _ = contractDecryptEnvelopeV1(tampered, keyRing)
            @Fail("tampered tag should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractAesHardwareFacade(): Unit {
        let mounts = contractAesListHardwareMountPoints()
        @Assert(mounts.size >= 5, true)

        let backends = ArrayList<String>()
        for (mount in mounts) {
            backends.add(mount.backend)
        }
        @Assert(containsString(backends.toArray(), "aesni"), true)
        @Assert(containsString(backends.toArray(), "armv8-ce"), true)
        @Assert(containsString(backends.toArray(), "shim"), true)
        @Assert(containsString(backends.toArray(), "loongarch64-reserved"), true)
        @Assert(containsString(backends.toArray(), "riscv64-reserved"), true)

        let hint = contractAesDefaultHardwareBackendHint().trimAscii()
        if (hint.size > 0) {
            @Assert(containsString(backends.toArray(), hint), true)
        }

        let shim = contractAesProbeHardware(backendHint: "shim")
        @Assert(shim.backend, "shim")
        @Assert(shim.available, true)
        @Assert(shim.accelerated, false)
        @Assert(shim.detail.trimAscii().size > 0, true)

        let loongarch = contractAesProbeHardware(backendHint: "loongarch64")
        @Assert(loongarch.backend, "loongarch64-reserved")
        @Assert(loongarch.available, false)
        @Assert(loongarch.accelerated, false)

        let riscv = contractAesProbeHardware(backendHint: "riscv64")
        @Assert(riscv.backend, "riscv64-reserved")
        @Assert(riscv.available, false)
        @Assert(riscv.accelerated, false)
    }

    @TestCase
    public func testContractAesHardwareRoadmapFacade(): Unit {
        let roadmap = contractAesHardwareRoadmap()
        @Assert(roadmap.size >= 4, true)

        var foundArm = false
        var foundX64 = false
        var foundLoong = false
        var foundRiscv = false
        for (entry in roadmap) {
            if (entry.architecture == "aarch64") {
                foundArm = true
                @Assert(entry.backend, "armv8-ce")
                @Assert(entry.status, "PRIMARY_ACTIVE")
                @Assert(entry.targetVersion, "0.6")
            }
            if (entry.architecture == "x86_64") {
                foundX64 = true
                @Assert(entry.backend, "aesni")
                @Assert(entry.status, "DEFERRED_0_7")
                @Assert(entry.targetVersion, "0.7")
            }
            if (entry.architecture == "loongarch64") {
                foundLoong = true
                @Assert(entry.status, "RESERVED_SKELETON")
            }
            if (entry.architecture == "riscv64") {
                foundRiscv = true
                @Assert(entry.status, "RESERVED_SKELETON")
            }
        }
        @Assert(foundArm, true)
        @Assert(foundX64, true)
        @Assert(foundLoong, true)
        @Assert(foundRiscv, true)
    }

    @TestCase
    public func testContractAesCurrentReleasePlanFacade(): Unit {
        let report = contractAesCurrentReleasePlan(backendHint: "shim")
        @Assert(report.currentReleaseSeries, "0.6")
        @Assert(report.primaryBackend, "armv8-ce")
        @Assert(containsString(report.primaryArchitectures, "aarch64"), true)
        @Assert(containsString(report.deferredBackends, "aesni"), true)
        @Assert(containsString(report.reservedBackends, "loongarch64-reserved"), true)
        @Assert(containsString(report.reservedBackends, "riscv64-reserved"), true)
        @Assert(report.usingPrimaryBackend, false)
        @Assert(
            containsString(report.warnings, "selected AES backend is not the current 0.6 primary backend"),
            true
        )

        try {
            _ = contractRequireAesCurrentReleasePrimaryBackend(backendHint: "shim")
            @Fail("shim backend should not satisfy current release primary backend requirement")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }
    }

    @TestCase
    public func testContractAesEngineFacade(): Unit {
        let resolvedShim = contractResolveAesEngine(backendHint: "shim")
        @Assert(resolvedShim.requested.toString(), "AUTO")
        @Assert(resolvedShim.active.toString(), "HARDWARE")
        @Assert(resolvedShim.backend, "shim")
        @Assert(resolvedShim.accelerated, false)

        let forcedSoftware = contractResolveAesEngine(
            requestedEngine: ContractAesEngineKind.Software,
            backendHint: "shim"
        )
        @Assert(forcedSoftware.requested.toString(), "SOFTWARE")
        @Assert(forcedSoftware.active.toString(), "SOFTWARE")
        @Assert(forcedSoftware.backend, "shim")

        let unavailable = contractTryResolveAesEngine(
            requestedEngine: ContractAesEngineKind.Hardware,
            backendHint: "none"
        )
        @Assert(unavailable.ok, false)
        match (unavailable.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("AES engine unavailable outcome should carry contract code")
        }
        match (unavailable.igniteCode) {
            case Some(value) =>
                @Assert(value.toString(), "CRYPTO_UNAVAILABLE")
            case None =>
                @Fail("AES engine unavailable outcome should carry ignite code")
        }

        try {
            _ = contractRequireAesAcceleratedBackend(backendHint: "shim")
            @Fail("shim backend should not satisfy accelerated backend requirement")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }
    }

    @TestCase
    public func testContractAesNativeBridgeDiagnosticsFacade(): Unit {
        let shimSpec = ContractAesNativeBridgeSpec("shim")
        let diagnostics = contractInspectAesNativeBridge(shimSpec)
        @Assert(diagnostics.spec.backend, "shim")
        @Assert(diagnostics.probe.backend, "shim")
        @Assert(diagnostics.probe.available, true)
        @Assert(diagnostics.probe.accelerated, false)
        @Assert(diagnostics.engine.active.toString(), "HARDWARE")
        @Assert(diagnostics.contract.backend, "shim")
        @Assert(diagnostics.contract.expandKeySymbol, "jinguissl_aes_expand_key")
        @Assert(diagnostics.contract.ghashMulSymbol, "jinguissl_aes_ghash_mul")

        let callShape = contractDescribeAesNativeBridgeCallShape(shimSpec, 16)
        @Assert(callShape.backend, "shim")
        @Assert(callShape.keyBytes, 16)
        @Assert(callShape.roundCount, 10)
        @Assert(callShape.roundKeyWordCount, 44)
        @Assert(callShape.expandedKeyBlobBytes, 188)
        @Assert(callShape.blockBytes, 16)
        @Assert(callShape.requiresBlockAlignedPayload, true)

        let invalid = contractTryInspectAesNativeBridge(ContractAesNativeBridgeSpec("bogus"))
        @Assert(invalid.ok, false)
        match (invalid.code) {
            case Some(value) =>
                @Assert(value.toString(), "BAD_INPUT")
            case None =>
                @Fail("AES native bridge diagnostics outcome should carry contract code")
        }
    }

    @TestCase
    public func testContractAesStartupSelfCheckFacade(): Unit {
        let recommendation = contractRecommendAesBackend()
        @Assert(recommendation.backendHint.size > 0, true)
        @Assert(recommendation.reason.size > 0, true)

        let report = contractAesStartupSelfCheck(backendHint: "shim")
        @Assert(report.effectiveBackendHint, "shim")
        @Assert(report.recommendation.backendHint.size > 0, true)
        @Assert(report.selectedEngine.backend, "shim")
        @Assert(report.selectedEngine.active.toString(), "HARDWARE")
        @Assert(report.acceleratedBackendReady, false)
        @Assert(report.mountPoints.size >= 3, true)
        match (report.diagnostics) {
            case Some(value) =>
                @Assert(value.spec.backend, "shim")
            case None =>
                @Fail("AES startup self-check should carry diagnostics for shim backend")
        }

        let softwareReport = contractAesStartupSelfCheck(
            requestedEngine: ContractAesEngineKind.Software,
            backendHint: "none"
        )
        @Assert(softwareReport.effectiveBackendHint, "none")
        @Assert(softwareReport.selectedEngine.active.toString(), "SOFTWARE")
        match (softwareReport.diagnostics) {
            case Some(_) =>
                @Fail("software-only AES startup self-check should not carry bridge diagnostics")
            case None => ()
        }
    }

    @TestCase
    public func testContractHttpSshStartupReadinessFacade(): Unit {
        let report = contractHttpSshStartupReadiness(aesBackendHint: "shim")
        @Assert(report.capability.stableDomains.size > 0, true)
        @Assert(report.httpTlsReady, true)
        @Assert(report.sshReady, true)
        @Assert(report.x509Ready, true)
        @Assert(report.overallReady, report.randomAvailable && report.httpTlsReady && report.sshReady && report.x509Ready)
        @Assert(report.productionAccelerationReady, false)
        @Assert(report.aes.effectiveBackendHint, "shim")
        @Assert(report.aesCurrentReleasePlan.currentReleaseSeries, "0.6")
        @Assert(report.aesCurrentReleasePlan.primaryBackend, "armv8-ce")
        @Assert(report.aesCurrentReleasePlan.usingPrimaryBackend, false)
        @Assert(containsString(report.warnings, "AES accelerated backend is not ready; software or shim path may be used"), true)
        @Assert(
            containsString(report.warnings, "selected AES backend is not the current 0.6 primary backend"),
            true
        )

        let outcome = contractTryHttpSshStartupReadiness(
            requestedAesEngine: ContractAesEngineKind.Hardware,
            aesBackendHint: "none"
        )
        @Assert(outcome.ok, false)
        match (outcome.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("HTTP/SSH startup readiness outcome should carry contract code")
        }
    }

    @TestCase
    public func testContractRequireHttpSshStartupReadinessFacade(): Unit {
        let relaxed = contractRequireHttpSshStartupReadiness(
            policy: ContractHttpSshStartupPolicy(
                requireRandom: true,
                requireHttpTls: true,
                requireSsh: false,
                requireX509: true,
                requireAcceleration: false
            ),
            aesBackendHint: "shim"
        )
        @Assert(relaxed.httpTlsReady, true)
        @Assert(relaxed.x509Ready, true)

        let accelerationRequired = contractTryRequireHttpSshStartupReadiness(
            policy: ContractHttpSshStartupPolicy(
                requireRandom: true,
                requireHttpTls: true,
                requireSsh: true,
                requireX509: true,
                requireAcceleration: true
            ),
            aesBackendHint: "shim"
        )
        @Assert(accelerationRequired.ok, false)
        match (accelerationRequired.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("HTTP/SSH startup policy failure should carry contract code")
        }
        @Assert(
            accelerationRequired.message.contains("accelerated AES backend is required but not ready"),
            true
        )

        let directBridgeRequired = contractTryRequireHttpSshStartupReadiness(
            policy: ContractHttpSshStartupPolicy(
                requireRandom: true,
                requireHttpTls: true,
                requireSsh: false,
                requireX509: true,
                requireDirectStdxTlsServerConfigBridge: true
            ),
            aesBackendHint: "shim"
        )
        @Assert(directBridgeRequired.ok, false)
        match (directBridgeRequired.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("direct bridge policy failure should carry contract code")
        }
        @Assert(
            directBridgeRequired.message.contains(
                "direct stdx.net.tls.TlsServerConfig bridge is required but unavailable"
            ),
            true
        )

        let releasePrimaryRequired = contractTryRequireHttpSshStartupReadiness(
            policy: ContractHttpSshStartupPolicy(
                requireRandom: true,
                requireHttpTls: true,
                requireSsh: true,
                requireX509: true,
                requireCurrentReleasePrimaryBackend: true
            ),
            aesBackendHint: "shim"
        )
        @Assert(releasePrimaryRequired.ok, false)
        match (releasePrimaryRequired.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("release primary backend policy failure should carry contract code")
        }
        @Assert(
            releasePrimaryRequired.message.contains(
                "current release requires primary AES backend armv8-ce, but startup resolved shim"
            ),
            true
        )
    }

    @TestCase
    public func testContractHttpSshStartupProfilesFacade(): Unit {
        let templates = contractListHttpSshStartupProfiles()
        @Assert(templates.size >= 6, true)

        let production = contractDescribeHttpSshStartupProfile(
            ContractHttpSshStartupProfile.ProductionAccelerated
        )
        @Assert(production.label, "production-accelerated")
        @Assert(production.defaultAesEngine.toString(), "HARDWARE")
        @Assert(production.policy.requireAcceleration, true)
        @Assert(production.policy.requireCurrentReleasePrimaryBackend, true)
        @Assert(production.defaultAesBackendHint, "armv8-ce")

        let sshClient = contractDescribeHttpSshStartupProfile(
            ContractHttpSshStartupProfile.SshClientLibrary
        )
        @Assert(sshClient.policy.requireHttpTls, false)
        @Assert(sshClient.policy.requireSsh, true)
        @Assert(sshClient.policy.requireX509, false)

        let httpClient = contractRequireHttpSshStartupProfile(
            ContractHttpSshStartupProfile.HttpClientLibrary,
            aesBackendHint: "shim"
        )
        @Assert(httpClient.httpTlsReady, true)
        @Assert(httpClient.x509Ready, true)

        let productionFailed = contractTryRequireHttpSshStartupProfile(
            ContractHttpSshStartupProfile.ProductionAccelerated,
            aesBackendHint: "shim"
        )
        @Assert(productionFailed.ok, false)
        match (productionFailed.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("startup profile failure should carry contract code")
        }
    }

    @TestCase
    public func testX509VerifyWithHostnameAndPinning(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let (derPin, spkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let verified = contractVerifyServerCertificatePem(
            leafPem,
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z",
            pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [spkiPin])
        )
        @Assert(verified.chainLength, 3)
        @Assert(verified.trustAnchorCommonName, "Policy Root")
        @Assert(verified.leafDerSha256, derPin)
        @Assert(verified.leafSpkiSha256, spkiPin)

        try {
            _ = contractVerifyServerCertificatePem(
                leafPem,
                rootPem,
                intermediatesPemBundle: intermediatePem,
                hostname: TEST_HOST_API,
                validationTime: "230101000000Z"
            )
            @Fail("hostname mismatch should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }

        let wrongPin = incrementalBytes(32, start: 200)
        try {
            _ = contractVerifyServerCertificatePem(
                leafPem,
                rootPem,
                intermediatesPemBundle: intermediatePem,
                hostname: TEST_HOST_WWW,
                validationTime: "230101000000Z",
                pinPolicy: ContractX509PinPolicy(allowedLeafDerSha256: [wrongPin])
            )
            @Fail("pin mismatch should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractX509ChainAndTryVerifyFacade(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let chainPem = "${leafPem}\n${intermediatePem}"

        let verified = contractVerifyServerCertificateChainPem(
            chainPem,
            rootPem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z"
        )
        @Assert(verified.chainLength, 3)
        @Assert(verified.trustAnchorCommonName, "Policy Root")

        let okOutcome = contractTryVerifyServerCertificateChainPem(
            chainPem,
            rootPem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z"
        )
        @Assert(okOutcome.ok, true)
        match (okOutcome.igniteCode) {
            case Some(_value) =>
                @Fail("x509 try verify success should not carry ignite code")
            case None =>
                ()
        }
        match (okOutcome.result) {
            case Some(value) =>
                @Assert(value.chainLength, 3)
            case None =>
                @Fail("try verify outcome should contain result for success path")
        }

        let failedOutcome = contractTryVerifyServerCertificateChainPem(
            chainPem,
            rootPem,
            hostname: TEST_HOST_API,
            validationTime: "230101000000Z"
        )
        @Assert(failedOutcome.ok, false)
        @Assert(failedOutcome.code.toString(), "VERIFY_FAILED")
        match (failedOutcome.igniteCode) {
            case Some(value) =>
                @Assert(value.toString(), "DECRYPT_FAILED")
            case None =>
                @Fail("x509 try verify failure should carry ignite code")
        }
        match (failedOutcome.result) {
            case Some(_value) =>
                @Fail("try verify outcome should not contain result on failure path")
            case None =>
                ()
        }
    }

    @TestCase
    public func testContractValidateHttpServerTlsConfigInput(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let certChainPem = "${leafPem}\n${intermediatePem}"
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")

        let result = contractValidateHttpServerTlsConfigInput(
            certChainPem,
            leafKeyPem,
            alpnProtocols: [" H2 ", "http/1.1", "h2"],
            requireHttp2Alpn: true
        )
        @Assert(result.certificateChainLength, 2)
        @Assert(result.normalizedAlpnProtocols, ["h2", "http/1.1"])
        @Assert(result.keyAlgorithm == "RSA" || result.keyAlgorithm == "EC", true)

        let http1Only = contractValidateHttpServerTlsConfigInput(
            certChainPem,
            leafKeyPem,
            alpnProtocols: ["http/1.1"],
            requireHttp2Alpn: false
        )
        @Assert(http1Only.normalizedAlpnProtocols, ["http/1.1"])

        try {
            _ = contractValidateHttpServerTlsConfigInput(
                certChainPem,
                leafKeyPem,
                alpnProtocols: ["http/1.1"],
                requireHttp2Alpn: true
            )
            @Fail("missing h2 ALPN should fail when requireHttp2Alpn is true")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }

        let wrongKeyPem = readText("testdata/x509/rsa_2048_pkcs8.pem")
        try {
            _ = contractValidateHttpServerTlsConfigInput(
                certChainPem,
                wrongKeyPem,
                alpnProtocols: ["h2", "http/1.1"],
                requireHttp2Alpn: true
            )
            @Fail("certificate and private key mismatch should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractTryValidateHttpServerTlsConfigInputOutcome(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let certChainPem = "${leafPem}\n${intermediatePem}"
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")

        let ok = contractTryValidateHttpServerTlsConfigInput(
            certChainPem,
            leafKeyPem,
            alpnProtocols: ["h2", "http/1.1"],
            requireHttp2Alpn: true
        )
        @Assert(ok.ok, true)
        match (ok.result) {
            case Some(value) =>
                @Assert(value.certificateChainLength, 2)
            case None =>
                @Fail("TLS config success outcome should carry result")
        }

        let failed = contractTryValidateHttpServerTlsConfigInput(
            certChainPem,
            leafKeyPem,
            alpnProtocols: ["http/1.1"],
            requireHttp2Alpn: true
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "BAD_INPUT")
            case None => @Fail("TLS config failed outcome should carry contract code")
        }
        match (failed.igniteCode) {
            case Some(value) => @Assert(value.toString(), "BAD_ENVELOPE")
            case None => @Fail("TLS config failed outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractPrepareHttpServerTlsMaterial(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let certChainPem = "${leafPem}\n${intermediatePem}"
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")

        let material = contractPrepareHttpServerTlsMaterial(
            certChainPem,
            leafKeyPem,
            alpnProtocols: [" H2 ", "http/1.1", "h2"],
            requireHttp2Alpn: true
        )
        @Assert(material.validation.certificateChainLength, 2)
        @Assert(material.validation.normalizedAlpnProtocols, ["h2", "http/1.1"])
        @Assert(material.certificateChainPemBlocks.size, 2)
        @Assert(material.certificateChainPemBundle().contains("BEGIN CERTIFICATE"), true)
        @Assert(material.leafCertificatePem().contains("BEGIN CERTIFICATE"), true)
        @Assert(material.privateKeyPem.contains("BEGIN PRIVATE KEY"), true)

        let failed = contractTryPrepareHttpServerTlsMaterial(
            certChainPem,
            leafKeyPem,
            alpnProtocols: ["http/1.1"],
            requireHttp2Alpn: true
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "BAD_INPUT")
            case None => @Fail("TLS server material failed outcome should carry contract code")
        }
    }

    @TestCase
    public func testContractHttpServerTlsRequestFacades(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let certChainPem = "${leafPem}\n${intermediatePem}"
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")

        let request = ContractHttpServerTlsConfigRequest(
            certChainPem,
            leafKeyPem,
            alpnProtocols: [" H2 ", "http/1.1", "h2"],
            requireHttp2Alpn: true
        )
        let validated = contractValidateHttpServerTlsConfigRequest(request)
        @Assert(validated.certificateChainLength, 2)
        @Assert(validated.normalizedAlpnProtocols, ["h2", "http/1.1"])

        let prepared = contractPrepareHttpServerTlsMaterialRequest(request)
        @Assert(prepared.validation.keyAlgorithm == "RSA" || prepared.validation.keyAlgorithm == "EC", true)
        @Assert(prepared.certificateChainPemBlocks.size, 2)

        let failed = contractTryPrepareHttpServerTlsMaterialRequest(
            ContractHttpServerTlsConfigRequest(
                certChainPem,
                leafKeyPem,
                alpnProtocols: ["http/1.1"],
                requireHttp2Alpn: true
            )
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "BAD_INPUT")
            case None => @Fail("request-style TLS server material failure should carry contract code")
        }
    }

    @TestCase
    public func testContractValidateHttpClientTlsConfigInput(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let (derPin, _spkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let result = contractValidateHttpClientTlsConfigInput(
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW_UPPER_PADDED,
            validationTime: "230101000000Z",
            pinPolicy: ContractX509PinPolicy(allowedLeafDerSha256: [derPin]),
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW_LOWER_PADDED, TEST_HOST_WWW_UPPER],
                alpnPreference: [" H2 ", "http/1.1"]
            )
        )
        @Assert(result.trustAnchorCount, 1)
        @Assert(result.intermediateCount, 1)
        @Assert(result.normalizedHostname, TEST_HOST_WWW)
        @Assert(result.hasValidationTimeOverride, true)
        @Assert(result.allowedLeafDerPinCount, 1)
        @Assert(result.allowedLeafSpkiPinCount, 0)
        @Assert(result.negotiationPolicy.normalizedAllowedServerNames, [TEST_HOST_WWW])
        @Assert(result.negotiationPolicy.normalizedAlpnPreference, ["h2", "http/1.1"])

        try {
            _ = contractValidateHttpClientTlsConfigInput(
                rootPem,
                hostname: TEST_HOST_WWW,
                policy: ContractTlsHttpNegotiationPolicy(
                    requireServerName: true,
                    allowedServerNames: [TEST_HOST_API]
                )
            )
            @Fail("hostname outside allowed server names should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testContractPrepareHttpClientTlsTrustMaterial(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let (derPin, _spkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let material = contractPrepareHttpClientTlsTrustMaterial(
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW_UPPER_PADDED,
            validationTime: "230101000000Z",
            pinPolicy: ContractX509PinPolicy(allowedLeafDerSha256: [derPin]),
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW_LOWER_PADDED, TEST_HOST_WWW_UPPER],
                alpnPreference: [" H2 ", "http/1.1"]
            )
        )
        @Assert(material.validation.trustAnchorCount, 1)
        @Assert(material.validation.intermediateCount, 1)
        @Assert(material.validation.normalizedHostname, TEST_HOST_WWW)
        @Assert(material.trustAnchorPemBlocks.size, 1)
        @Assert(material.intermediatePemBlocks.size, 1)
        @Assert(material.trustAnchorsPemBundle().contains("BEGIN CERTIFICATE"), true)
        @Assert(material.intermediatesPemBundle().contains("BEGIN CERTIFICATE"), true)
        @Assert(material.pinPolicy.allowedLeafDerSha256.size, 1)
        @Assert(material.validation.negotiationPolicy.normalizedAlpnPreference, ["h2", "http/1.1"])

        let failed = contractTryPrepareHttpClientTlsTrustMaterial(
            rootPem,
            hostname: TEST_HOST_WWW,
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_API]
            )
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "BAD_INPUT")
            case None => @Fail("TLS client material failed outcome should carry contract code")
        }
    }

    @TestCase
    public func testContractTryValidateHttpClientTlsConfigInputOutcome(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let (_derPin, spkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let ok = contractTryValidateHttpClientTlsConfigInput(
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z",
            pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [spkiPin]),
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2"]
            )
        )
        @Assert(ok.ok, true)
        match (ok.result) {
            case Some(value) =>
                @Assert(value.allowedLeafSpkiPinCount, 1)
            case None =>
                @Fail("TLS client config success outcome should carry result")
        }

        let failed = contractTryValidateHttpClientTlsConfigInput(
            rootPem,
            hostname: "",
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true
            )
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "BAD_INPUT")
            case None => @Fail("TLS client config failed outcome should carry contract code")
        }
        match (failed.igniteCode) {
            case Some(value) => @Assert(value.toString(), "BAD_ENVELOPE")
            case None => @Fail("TLS client config failed outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractHttpClientTlsRequestFacades(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let chainPem = "${leafPem}\n${intermediatePem}"
        let (_derPin, spkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let trustRequest = ContractHttpClientTlsTrustRequest(
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW_UPPER_PADDED,
            validationTime: "230101000000Z",
            pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [spkiPin]),
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW_LOWER_PADDED],
                alpnPreference: [" H2 ", "http/1.1"]
            )
        )

        let validated = contractValidateHttpClientTlsTrustRequest(trustRequest)
        @Assert(validated.normalizedHostname, TEST_HOST_WWW)
        @Assert(validated.negotiationPolicy.normalizedAlpnPreference, ["h2", "http/1.1"])

        let material = contractPrepareHttpClientTlsTrustMaterialRequest(trustRequest)
        @Assert(material.trustAnchorPemBlocks.size, 1)
        @Assert(material.intermediatePemBlocks.size, 1)
        @Assert(material.pinPolicy.allowedLeafSpkiSha256.size, 1)

        let verifiedLeaf = contractVerifyHttpClientPeerCertificatePemRequest(
            ContractHttpClientTlsPeerPemRequest(leafPem, trustRequest)
        )
        @Assert(verifiedLeaf.chainLength, 3)

        let verifiedChain = contractVerifyHttpClientPeerCertificateChainPemRequest(
            ContractHttpClientTlsPeerChainRequest(chainPem, trustRequest)
        )
        @Assert(verifiedChain.trustAnchorCommonName, "Policy Root")

        let failed = contractTryVerifyHttpClientPeerCertificateChainPemRequest(
            ContractHttpClientTlsPeerChainRequest(
                chainPem,
                ContractHttpClientTlsTrustRequest(
                    rootPem,
                    intermediatesPemBundle: intermediatePem,
                    hostname: TEST_HOST_API,
                    validationTime: "230101000000Z",
                    policy: ContractTlsHttpNegotiationPolicy(
                        requireServerName: true,
                        allowedServerNames: [TEST_HOST_API]
                    )
                )
            )
        )
        @Assert(failed.ok, false)
        @Assert(failed.code.toString(), "VERIFY_FAILED")
    }

    @TestCase
    public func testContractHttpLibraryStartupBundles(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let certChainPem = "${leafPem}\n${intermediatePem}"
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")
        let (_derPin, spkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let serverBundle = contractPrepareHttpServerLibraryStartupRequest(
            ContractHttpServerLibraryStartupRequest(
                ContractHttpServerTlsConfigRequest(
                    certChainPem,
                    leafKeyPem,
                    alpnProtocols: ["h2", "http/1.1"]
                ),
                profile: ContractHttpSshStartupProfile.HttpServerLibrary,
                aesBackendHint: "shim"
            )
        )
        @Assert(serverBundle.template.profile.toString(), "HTTP_SERVER_LIBRARY")
        @Assert(serverBundle.readiness.httpTlsReady, true)
        @Assert(serverBundle.readiness.aesCurrentReleasePlan.currentReleaseSeries, "0.6")
        @Assert(serverBundle.material.certificateChainPemBlocks.size, 2)

        let productionServer = contractTryPrepareHttpServerLibraryStartupRequest(
            ContractHttpServerLibraryStartupRequest(
                ContractHttpServerTlsConfigRequest(certChainPem, leafKeyPem),
                profile: ContractHttpSshStartupProfile.ProductionAccelerated,
                aesBackendHint: "shim"
            )
        )
        @Assert(productionServer.ok, false)
        match (productionServer.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("HTTP server startup production outcome should carry contract code")
        }

        let clientBundle = contractPrepareHttpClientLibraryStartupRequest(
            ContractHttpClientLibraryStartupRequest(
                ContractHttpClientTlsTrustRequest(
                    rootPem,
                    intermediatesPemBundle: intermediatePem,
                    hostname: TEST_HOST_WWW,
                    validationTime: "230101000000Z",
                    pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [spkiPin]),
                    policy: ContractTlsHttpNegotiationPolicy(
                        requireServerName: true,
                        allowedServerNames: [TEST_HOST_WWW],
                        alpnPreference: ["h2", "http/1.1"]
                    )
                ),
                profile: ContractHttpSshStartupProfile.HttpClientLibrary,
                aesBackendHint: "shim"
            )
        )
        @Assert(clientBundle.template.profile.toString(), "HTTP_CLIENT_LIBRARY")
        @Assert(clientBundle.readiness.httpTlsReady, true)
        @Assert(clientBundle.trust.validation.normalizedHostname, TEST_HOST_WWW)

        let invalidProfile = contractTryPrepareHttpClientLibraryStartupRequest(
            ContractHttpClientLibraryStartupRequest(
                ContractHttpClientTlsTrustRequest(rootPem, hostname: TEST_HOST_WWW),
                profile: ContractHttpSshStartupProfile.SshClientLibrary,
                aesBackendHint: "shim"
            )
        )
        @Assert(invalidProfile.ok, false)
        match (invalidProfile.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("HTTP client startup invalid profile outcome should carry contract code")
        }
    }

    @TestCase
    public func testContractSshLibraryStartupBundles(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let transcript = ContractSshKexExchangeTranscript(
            "SSH-2.0-contract-startup-client\r\n".toArray(),
            "SSH-2.0-contract-startup-server\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1820))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1860)))
        )
        let (encodedInit, _) = sshBuildKexEcdhInitX25519(clientPrivate)
        let negotiated = ContractSshNegotiatedAlgorithms(
            "curve25519-sha256",
            "rsa-sha2-256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            compressionAlgorithmClientToServer: "none",
            compressionAlgorithmServerToClient: "none"
        )
        let serverBundle = contractPrepareSshServerLibraryStartupX25519RsaPkcs8Request(
            ContractSshServerLibraryStartupX25519RsaPkcs8Request(
                transcript,
                serverPrivate,
                encodedInit,
                readText("testdata/x509/rsa_2048_pkcs8.pem"),
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                profile: ContractHttpSshStartupProfile.SshServerLibrary,
                aesBackendHint: "shim"
            )
        )
        @Assert(serverBundle.template.profile.toString(), "SSH_SERVER_LIBRARY")
        @Assert(serverBundle.readiness.sshReady, true)
        @Assert(serverBundle.handshake.hostSignatureAlgorithm, "rsa-sha2-256")
        @Assert(serverBundle.runtime.sessionId(), serverBundle.handshake.sessionId)

        let ecdsaBundle = contractPrepareSshServerLibraryStartupX25519EcdsaPkcs8Request(
            ContractSshServerLibraryStartupX25519EcdsaPkcs8Request(
                transcript,
                serverPrivate,
                encodedInit,
                readText("testdata/x509/policy_leaf_key_pkcs8.pem"),
                ContractSshNegotiatedAlgorithms(
                    "curve25519-sha256",
                    "ecdsa-sha2-nistp256",
                    "aes128-ctr",
                    "aes128-ctr",
                    "hmac-sha2-256",
                    "hmac-sha2-256",
                    compressionAlgorithmClientToServer: "none",
                    compressionAlgorithmServerToClient: "none"
                ),
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                profile: ContractHttpSshStartupProfile.SshServerLibrary,
                aesBackendHint: "shim"
            )
        )
        @Assert(ecdsaBundle.handshake.hostKeyAlgorithm, "ecdsa-sha2-nistp256")
        @Assert(ecdsaBundle.runtime.sessionId(), ecdsaBundle.handshake.sessionId)

        let ed25519Bundle = contractPrepareSshServerLibraryStartupX25519Ed25519SeedRequest(
            ContractSshServerLibraryStartupX25519Ed25519SeedRequest(
                transcript,
                serverPrivate,
                encodedInit,
                hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
                ContractSshNegotiatedAlgorithms(
                    "curve25519-sha256",
                    "ssh-ed25519",
                    "aes128-ctr",
                    "aes128-ctr",
                    "hmac-sha2-256",
                    "hmac-sha2-256",
                    compressionAlgorithmClientToServer: "none",
                    compressionAlgorithmServerToClient: "none"
                ),
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                profile: ContractHttpSshStartupProfile.SshServerLibrary,
                aesBackendHint: "shim"
            )
        )
        @Assert(ed25519Bundle.handshake.hostKeyAlgorithm, "ssh-ed25519")
        @Assert(ed25519Bundle.runtime.sessionId(), ed25519Bundle.handshake.sessionId)

        let clientBundle = contractPrepareSshClientLibraryStartupX25519Request(
            ContractSshClientLibraryStartupX25519Request(
                ContractSshClientInitialHandshakeX25519Request(
                    transcript,
                    clientPrivate,
                    encodedInit,
                    serverBundle.handshake.encodedReply,
                    negotiated,
                    sshEncodeNewKeys(),
                    sshEncodeNewKeys(),
                    policy: ContractSshHostVerificationPolicy(
                        negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                        expectedHostKeySha256: serverBundle.handshake.hostKeySha256,
                        requireKnownHost: true,
                        requireHostSignature: true,
                        requireVerifiedHost: true
                    )
                ),
                profile: ContractHttpSshStartupProfile.SshClientLibrary,
                aesBackendHint: "shim"
            )
        )
        @Assert(clientBundle.template.profile.toString(), "SSH_CLIENT_LIBRARY")
        @Assert(clientBundle.readiness.sshReady, true)
        @Assert(clientBundle.handshake.requireHostVerification().hostSignatureVerified, true)
        @Assert(clientBundle.runtime.sessionId(), clientBundle.handshake.sessionId)

        let productionServer = contractTryPrepareSshServerLibraryStartupX25519RsaPkcs8Request(
            ContractSshServerLibraryStartupX25519RsaPkcs8Request(
                transcript,
                serverPrivate,
                encodedInit,
                readText("testdata/x509/rsa_2048_pkcs8.pem"),
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                profile: ContractHttpSshStartupProfile.ProductionAccelerated,
                aesBackendHint: "shim"
            )
        )
        @Assert(productionServer.ok, false)
        match (productionServer.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("SSH server startup production outcome should carry contract code")
        }

        let invalidClientProfile = contractTryPrepareSshClientLibraryStartupX25519Request(
            ContractSshClientLibraryStartupX25519Request(
                ContractSshClientInitialHandshakeX25519Request(
                    transcript,
                    clientPrivate,
                    encodedInit,
                    serverBundle.handshake.encodedReply,
                    negotiated,
                    sshEncodeNewKeys(),
                    sshEncodeNewKeys()
                ),
                profile: ContractHttpSshStartupProfile.HttpClientLibrary,
                aesBackendHint: "shim"
            )
        )
        @Assert(invalidClientProfile.ok, false)
        match (invalidClientProfile.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("SSH client startup invalid profile outcome should carry contract code")
        }
    }

    @TestCase
    public func testContractVerifyHttpClientPeerCertificateFacades(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let chainPem = "${leafPem}\n${intermediatePem}"
        let (_derPin, spkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let verifiedLeaf = contractVerifyHttpClientPeerCertificatePem(
            leafPem,
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW_UPPER_PADDED,
            validationTime: "230101000000Z",
            pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [spkiPin]),
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )
        @Assert(verifiedLeaf.chainLength, 3)
        @Assert(verifiedLeaf.trustAnchorCommonName, "Policy Root")

        let verifiedChain = contractVerifyHttpClientPeerCertificateChainPem(
            chainPem,
            rootPem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z",
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW]
            )
        )
        @Assert(verifiedChain.chainLength, 3)
        @Assert(verifiedChain.leafSubjectCommonName, TEST_HOST_WWW)

        let failed = contractTryVerifyHttpClientPeerCertificateChainPem(
            chainPem,
            rootPem,
            hostname: TEST_HOST_API,
            validationTime: "230101000000Z",
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_API]
            )
        )
        @Assert(failed.ok, false)
        @Assert(failed.code.toString(), "VERIFY_FAILED")
        match (failed.igniteCode) {
            case Some(value) => @Assert(value.toString(), "DECRYPT_FAILED")
            case None => @Fail("HTTP client peer verify failure should carry ignite code")
        }
    }

    @TestCase
    public func testContractValidateTlsHttpNegotiationPolicy(): Unit {
        let result = contractValidateTlsHttpNegotiationPolicy(
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_API_UPPER_PADDED, TEST_HOST_API, TEST_HOST_WWW_UPPER],
                alpnPreference: [" H2 ", "http/1.1", "h2"]
            )
        )
        @Assert(result.requireServerName, true)
        @Assert(result.normalizedAllowedServerNames, [TEST_HOST_API, TEST_HOST_WWW])
        @Assert(result.normalizedAlpnPreference, ["h2", "http/1.1"])

        let defaults = contractValidateTlsHttpNegotiationPolicy(
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: false
            )
        )
        @Assert(defaults.requireServerName, false)
        @Assert(defaults.normalizedAllowedServerNames.size, 0)
        @Assert(defaults.normalizedAlpnPreference, ["h2", "http/1.1"])
    }

    @TestCase
    public func testContractTryValidateTlsHttpNegotiationPolicyOutcome(): Unit {
        let ok = contractTryValidateTlsHttpNegotiationPolicy(
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_API],
                alpnPreference: ["h2"]
            )
        )
        @Assert(ok.ok, true)
        match (ok.result) {
            case Some(value) =>
                @Assert(value.normalizedAllowedServerNames, [TEST_HOST_API])
            case None =>
                @Fail("TLS HTTP policy success outcome should carry result")
        }

        let failed = contractTryValidateTlsHttpNegotiationPolicy(
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: ["bad host name"],
                alpnPreference: ["h2"]
            )
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "BAD_INPUT")
            case None => @Fail("TLS HTTP policy failed outcome should carry contract code")
        }
        match (failed.igniteCode) {
            case Some(value) => @Assert(value.toString(), "BAD_ENVELOPE")
            case None => @Fail("TLS HTTP policy failed outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractTls13HttpX25519FlightFacadeRoundTrip(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")
        let (leafDerPin, leafSpkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let clientHello = contractTls13BuildHttpClientHelloX25519(
            TEST_HOST_WWW,
            alpnProtocols: ["h2", "http/1.1"],
            clientPrivateKey: Some(incrementalBytes(32, start: 91))
        )
        @Assert(clientHello.clientPrivateKey.size, 32)
        @Assert(clientHello.clientPublicKey.size, 32)

        let chainBundle = "${leafPem}\n${intermediatePem}"
        let flight = contractTls13BuildHttpServerFlightX25519(
            clientHello.encodedClientHello,
            incrementalBytes(32, start: 33),
            chainBundle,
            leafKeyPem,
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )
        @Assert(flight.selectedAlpn, "h2")
        @Assert(flight.requestedServerName, TEST_HOST_WWW)
        @Assert(flight.acknowledgedServerName, true)

        let verified = contractTls13VerifyHttpServerFlightX25519(
            clientHello,
            flight,
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z",
            pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [leafSpkiPin]),
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )
        @Assert(verified.selectedAlpn, "h2")
        @Assert(verified.requestedServerName, TEST_HOST_WWW)
        @Assert(verified.chainLength, 3)
        @Assert(verified.leafDerSha256, leafDerPin)
        @Assert(verified.leafSpkiSha256, leafSpkiPin)
        @Assert(verified.keyMaterial.clientWriteKey.size > 0, true)
        @Assert(verified.keyMaterial.serverWriteIv.size > 0, true)

        try {
            _ = contractTls13VerifyHttpServerFlightX25519(
                clientHello,
                flight,
                rootPem,
                intermediatesPemBundle: intermediatePem,
                hostname: TEST_HOST_API,
                validationTime: "230101000000Z",
                pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [leafSpkiPin]),
                policy: ContractTlsHttpNegotiationPolicy(
                    requireServerName: true,
                    allowedServerNames: [TEST_HOST_WWW],
                    alpnPreference: ["h2", "http/1.1"]
                )
            )
            @Fail("hostname mismatch should fail TLS1.3 HTTP contract verification")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractTls13HttpClientHelloCarriesInteropExtensions(): Unit {
        let clientHello = contractTls13BuildHttpClientHelloX25519(
            TEST_HOST_WWW,
            alpnProtocols: ["h2", "http/1.1"],
            clientPrivateKey: Some(incrementalBytes(32, start: 73))
        )
        let decoded = tlsDecodeClientHelloHandshake(clientHello.encodedClientHello)

        if (let Some(groupsExt) <- tlsFindExtension(decoded.extensions, CONTRACT_TLS13_SUPPORTED_GROUPS_EXTENSION_TYPE)) {
            @Assert(parseContractTls13UInt16VectorExtension(groupsExt.data), [CONTRACT_TLS13_GROUP_X25519_TEST])
        } else {
            @Fail("TLS1.3 contract ClientHello should carry supported_groups extension")
        }

        if (let Some(signatureExt) <- tlsFindExtension(decoded.extensions, TLS13_EXT_SIGNATURE_ALGORITHMS)) {
            @Assert(
                parseContractTls13UInt16VectorExtension(signatureExt.data),
                [
                    TLS13_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
                    TLS13_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
                    TLS13_SIG_SCHEME_RSA_PSS_RSAE_SHA256
                ]
            )
        } else {
            @Fail("TLS1.3 contract ClientHello should carry signature_algorithms extension")
        }
    }

    @TestCase
    public func testContractTls13HttpVerifiedSessionAndExporterFacade(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")

        let clientHello = contractTls13BuildHttpClientHelloX25519(
            TEST_HOST_WWW,
            alpnProtocols: ["h2", "http/1.1"],
            clientPrivateKey: Some(incrementalBytes(32, start: 121))
        )
        let flight = contractTls13BuildHttpServerFlightX25519(
            clientHello.encodedClientHello,
            incrementalBytes(32, start: 17),
            "${leafPem}\n${intermediatePem}",
            leafKeyPem,
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )
        let verifiedSession = contractTls13VerifyHttpServerFlightX25519WithSession(
            clientHello,
            flight,
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z",
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )

        @Assert(verifiedSession.result.selectedAlpn, "h2")
        @Assert(verifiedSession.result.chainLength, 3)
        @Assert(verifiedSession.clientAppTrafficSecret.size > 0, true)
        @Assert(verifiedSession.serverAppTrafficSecret.size > 0, true)
        @Assert(verifiedSession.masterSecret.size > 0, true)
        let binding = contractTls13ResolveCipherBindingFromVerifiedSession(verifiedSession)
        @Assert(binding.cipherSuiteName, "TLS_AES_128_GCM_SHA256")
        @Assert(binding.keyLen, verifiedSession.result.keyMaterial.clientWriteKey.size)

        let clientChannel = contractTls13CreateClientRecordChannelFromVerifiedSession(verifiedSession)
        let serverChannel = contractTls13CreateServerRecordChannelFromVerifiedSession(verifiedSession)
        @Assert(clientChannel.version.toString(), "TLS1.3")
        @Assert(clientChannel.algorithm.toString(), binding.algorithm.toString())
        @Assert(serverChannel.algorithm.toString(), binding.algorithm.toString())

        let runtime = contractTls13CreateVerifiedSessionChannelSet(verifiedSession)
        let runtimeCiphertext = runtime.clientChannel.sealApplicationData("verified-session-runtime".toArray())
        let runtimePlaintext = runtime.serverChannel.openApplicationData(runtimeCiphertext)
        @Assert(runtimePlaintext, "verified-session-runtime".toArray())

        let exporterMaster = contractTls13DeriveExporterMasterSecretFromVerifiedSession(
            verifiedSession
        )
        let exported = contractTls13ExportKeyingMaterialFromVerifiedSession(
            verifiedSession,
            "EXPORTER-jinkui/http",
            context: "http-ctx".toArray(),
            outputLen: 42
        )
        @Assert(exported.size, 42)

        let nextClientTraffic = contractTls13DeriveNextApplicationTrafficSecret(
            verifiedSession.clientAppTrafficSecret
        )
        let (nextClientWriteKey, nextClientWriteIv) = contractTls13DeriveApplicationTrafficKeyIv(
            nextClientTraffic,
            keyLen: verifiedSession.result.keyMaterial.clientWriteKey.size,
            ivLen: verifiedSession.result.keyMaterial.clientWriteIv.size
        )
        @Assert(nextClientWriteKey.size, verifiedSession.result.keyMaterial.clientWriteKey.size)
        @Assert(nextClientWriteIv.size, verifiedSession.result.keyMaterial.clientWriteIv.size)

        let exporterMasterByRequest = contractTls13DeriveExporterMasterSecretFromVerifiedSessionRequest(
            ContractTls13HttpVerifiedSessionRequest(verifiedSession)
        )
        @Assert(exporterMasterByRequest, exporterMaster)

        let exportedByRequest = contractTls13ExportKeyingMaterialFromVerifiedSessionRequest(
            ContractTls13HttpVerifiedSessionExportRequest(
                verifiedSession,
                "EXPORTER-jinkui/http",
                context: "http-ctx".toArray(),
                outputLen: 42
            )
        )
        @Assert(exportedByRequest, exported)

        let clientChannelByRequest = contractTls13CreateClientRecordChannelFromVerifiedSessionRequest(
            ContractTls13HttpVerifiedSessionRequest(verifiedSession)
        )
        @Assert(clientChannelByRequest.algorithm.toString(), clientChannel.algorithm.toString())

        let runtimeByRequest = contractTls13CreateVerifiedSessionChannelSetRequest(
            ContractTls13HttpVerifiedSessionRequest(verifiedSession)
        )
        let runtimeByRequestCiphertext = runtimeByRequest.serverChannel.sealApplicationData(
            "verified-session-runtime-request".toArray()
        )
        let runtimeByRequestPlaintext = runtimeByRequest.clientChannel.openApplicationData(
            runtimeByRequestCiphertext
        )
        @Assert(runtimeByRequestPlaintext, "verified-session-runtime-request".toArray())
    }

    @TestCase
    public func testContractTls13HttpRequestFacades(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")
        let (_leafDerPin, leafSpkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let clientHello = contractTls13BuildHttpClientHelloX25519Request(
            ContractTls13HttpClientHelloX25519Request(
                TEST_HOST_WWW,
                alpnProtocols: ["h2", "http/1.1"],
                clientPrivateKey: Some(incrementalBytes(32, start: 211))
            )
        )
        @Assert(clientHello.clientPrivateKey.size, 32)

        let flight = contractTls13BuildHttpServerFlightX25519Request(
            ContractTls13HttpServerFlightX25519Request(
                clientHello.encodedClientHello,
                incrementalBytes(32, start: 227),
                "${leafPem}\n${intermediatePem}",
                leafKeyPem,
                policy: ContractTlsHttpNegotiationPolicy(
                    requireServerName: true,
                    allowedServerNames: [TEST_HOST_WWW],
                    alpnPreference: ["h2", "http/1.1"]
                )
            )
        )
        @Assert(flight.selectedAlpn, "h2")

        let verifyRequest = ContractTls13HttpVerifyServerFlightX25519Request(
            clientHello,
            flight,
            ContractHttpClientTlsTrustRequest(
                rootPem,
                intermediatesPemBundle: intermediatePem,
                hostname: TEST_HOST_WWW,
                validationTime: "230101000000Z",
                pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [leafSpkiPin]),
                policy: ContractTlsHttpNegotiationPolicy(
                    requireServerName: true,
                    allowedServerNames: [TEST_HOST_WWW],
                    alpnPreference: ["h2", "http/1.1"]
                )
            )
        )

        let verified = contractTls13VerifyHttpServerFlightX25519Request(verifyRequest)
        @Assert(verified.selectedAlpn, "h2")
        @Assert(verified.chainLength, 3)

        let verifiedSession = contractTls13VerifyHttpServerFlightX25519WithSessionRequest(verifyRequest)
        @Assert(verifiedSession.result.selectedAlpn, "h2")
        @Assert(verifiedSession.masterSecret.size > 0, true)

        let failed = contractTryTls13VerifyHttpServerFlightX25519Request(
            ContractTls13HttpVerifyServerFlightX25519Request(
                clientHello,
                flight,
                ContractHttpClientTlsTrustRequest(
                    rootPem,
                    intermediatesPemBundle: intermediatePem,
                    hostname: TEST_HOST_API,
                    validationTime: "230101000000Z",
                    policy: ContractTlsHttpNegotiationPolicy(
                        requireServerName: true,
                        allowedServerNames: [TEST_HOST_API],
                        alpnPreference: ["h2", "http/1.1"]
                    )
                )
            )
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "VERIFY_FAILED")
            case None => @Fail("TLS1.3 request-style verify failure should carry contract code")
        }
    }

    @TestCase
    public func testContractTls12HttpRsaFacadeRoundTrip(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let rsaKeyPem = readText("testdata/x509/rsa_2048_pkcs8.pem")
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(rsaKeyPem)
        let rsaLeafPem = x509CreateSelfSignedRsaCertificate(
            X509SelfSignedConfig(
                "rsa.example.com",
                serialNumber: [UInt8(0x02)]
            ),
            rsaPrivateKey
        ).toPem()
        let (_leafDerPin, leafSpkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let clientHello = contractTls12BuildHttpClientHello(
            ContractTls12KeyExchange.Rsa,
            serverName: TEST_HOST_WWW,
            alpnProtocols: ["http/1.1"],
            requestOcspStapling: true
        )
        @Assert(clientHello.encodedClientHello.size > 0, true)
        @Assert(clientHello.clientRandom.size, 32)

        let serverHello = contractTls12BuildHttpServerHello(
            clientHello.encodedClientHello,
            ContractTls12KeyExchange.Rsa
        )
        @Assert(serverHello.encodedServerHello.size > 0, true)
        @Assert(serverHello.serverRandom.size, 32)

        let certHandshake = contractTls12BuildCertificateHandshakeFromPemChain(
            "${leafPem}\n${intermediatePem}"
        )
        let verified = contractTls12VerifyCertificateHandshakeForHttp(
            certHandshake,
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z",
            pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [leafSpkiPin])
        )
        @Assert(verified.chainLength, 3)
        @Assert(verified.leafSubjectCommonName, TEST_HOST_WWW)

        let clientKeyExchange = contractTls12BuildRsaClientKeyExchangeFromLeafPem(rsaLeafPem)
        @Assert(clientKeyExchange.preMasterSecret.size, 48)
        let serverPreMaster = contractTls12ProcessRsaClientKeyExchange(
            rsaKeyPem,
            clientKeyExchange.encodedClientKeyExchange
        )
        @Assert(serverPreMaster, clientKeyExchange.preMasterSecret)

        let clientSecrets = contractTls12DeriveSecretsFromPreMaster(
            clientKeyExchange.preMasterSecret,
            clientHello.clientRandom,
            serverHello.serverRandom
        )
        let serverSecrets = contractTls12DeriveSecretsFromPreMaster(
            serverPreMaster,
            clientHello.clientRandom,
            serverHello.serverRandom
        )
        @Assert(clientSecrets.masterSecret, serverSecrets.masterSecret)
        @Assert(clientSecrets.clientWriteKey, serverSecrets.clientWriteKey)
        @Assert(clientSecrets.serverWriteIv, serverSecrets.serverWriteIv)

        try {
            _ = contractTls12VerifyCertificateHandshakeForHttp(
                certHandshake,
                rootPem,
                intermediatesPemBundle: intermediatePem,
                hostname: TEST_HOST_API,
                validationTime: "230101000000Z",
                pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [leafSpkiPin])
            )
            @Fail("TLS1.2 certificate handshake verification should fail on hostname mismatch")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractTls12HttpEcdheP256FacadeRoundTrip(): Unit {
        let clientHello = contractTls12BuildHttpClientHello(
            ContractTls12KeyExchange.EcdheP256,
            serverName: TEST_HOST_WWW,
            alpnProtocols: ["h2", "http/1.1"],
            requestOcspStapling: true
        )
        let serverHello = contractTls12BuildHttpServerHello(
            clientHello.encodedClientHello,
            ContractTls12KeyExchange.EcdheP256
        )
        @Assert(clientHello.clientRandom.size, 32)
        @Assert(serverHello.serverRandom.size, 32)

        let serverExchange = contractTls12BuildEcdheServerKeyExchange(
            ContractTls12KeyExchange.EcdheP256,
            serverPrivateScalar: Some(incrementalBytes(32, start: 9))
        )
        let clientExchange = contractTls12BuildEcdheClientKeyExchange(
            ContractTls12KeyExchange.EcdheP256,
            clientPrivateScalar: Some(incrementalBytes(32, start: 27))
        )
        @Assert(serverExchange.encodedServerKeyExchange.size > 0, true)
        @Assert(clientExchange.encodedClientKeyExchange.size > 0, true)

        let clientSecrets = contractTls12DeriveClientSecretsFromEcdhe(
            ContractTls12KeyExchange.EcdheP256,
            clientExchange.clientPrivateScalar,
            serverExchange.encodedServerKeyExchange,
            clientHello.clientRandom,
            serverHello.serverRandom
        )
        let serverSecrets = contractTls12DeriveServerSecretsFromEcdhe(
            ContractTls12KeyExchange.EcdheP256,
            serverExchange.serverPrivateScalar,
            clientExchange.encodedClientKeyExchange,
            clientHello.clientRandom,
            serverHello.serverRandom
        )
        @Assert(clientSecrets.masterSecret, serverSecrets.masterSecret)
        @Assert(clientSecrets.clientWriteKey, serverSecrets.clientWriteKey)
        @Assert(clientSecrets.serverWriteIv, serverSecrets.serverWriteIv)

        try {
            _ = contractTls12BuildEcdheServerKeyExchange(ContractTls12KeyExchange.Rsa)
            @Fail("ECDHE server key exchange builder should reject RSA key exchange")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testContractTls12HttpEcdheP384FacadeRoundTrip(): Unit {
        let clientHello = contractTls12BuildHttpClientHello(
            ContractTls12KeyExchange.EcdheP384,
            serverName: TEST_HOST_WWW,
            alpnProtocols: ["h2", "http/1.1"],
            requestOcspStapling: true
        )
        let serverHello = contractTls12BuildHttpServerHello(
            clientHello.encodedClientHello,
            ContractTls12KeyExchange.EcdheP384
        )

        let serverExchange = contractTls12BuildEcdheServerKeyExchange(
            ContractTls12KeyExchange.EcdheP384,
            serverPrivateScalar: Some(incrementalBytes(48, start: 13))
        )
        let clientExchange = contractTls12BuildEcdheClientKeyExchange(
            ContractTls12KeyExchange.EcdheP384,
            clientPrivateScalar: Some(incrementalBytes(48, start: 77))
        )

        let clientSecrets = contractTls12DeriveClientSecretsFromEcdhe(
            ContractTls12KeyExchange.EcdheP384,
            clientExchange.clientPrivateScalar,
            serverExchange.encodedServerKeyExchange,
            clientHello.clientRandom,
            serverHello.serverRandom
        )
        let serverSecrets = contractTls12DeriveServerSecretsFromEcdhe(
            ContractTls12KeyExchange.EcdheP384,
            serverExchange.serverPrivateScalar,
            clientExchange.encodedClientKeyExchange,
            clientHello.clientRandom,
            serverHello.serverRandom
        )
        @Assert(clientSecrets.masterSecret, serverSecrets.masterSecret)
        @Assert(clientSecrets.clientWriteKey, serverSecrets.clientWriteKey)
        @Assert(clientSecrets.serverWriteIv, serverSecrets.serverWriteIv)
    }

    @TestCase
    public func testContractTls12HttpRequestFacades(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let rsaKeyPem = readText("testdata/x509/rsa_2048_pkcs8.pem")
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(rsaKeyPem)
        let rsaLeafPem = x509CreateSelfSignedRsaCertificate(
            X509SelfSignedConfig(
                "rsa.example.com",
                serialNumber: [UInt8(0x09)]
            ),
            rsaPrivateKey
        ).toPem()
        let (_leafDerPin, leafSpkiPin) = contractComputeLeafPinsFromPem(leafPem)

        let clientHello = contractTls12BuildHttpClientHelloRequest(
            ContractTls12HttpClientHelloRequest(
                ContractTls12KeyExchange.Rsa,
                serverName: TEST_HOST_WWW,
                alpnProtocols: ["http/1.1"],
                requestOcspStapling: true
            )
        )
        @Assert(clientHello.clientRandom.size, 32)

        let serverHello = contractTls12BuildHttpServerHelloRequest(
            ContractTls12HttpServerHelloRequest(
                clientHello.encodedClientHello,
                ContractTls12KeyExchange.Rsa
            )
        )
        @Assert(serverHello.serverRandom.size, 32)

        let certHandshake = contractTls12BuildCertificateHandshakeFromPemChainRequest(
            ContractTls12CertificateHandshakeFromPemChainRequest("${leafPem}\n${intermediatePem}")
        )
        let verified = contractTls12VerifyCertificateHandshakeForHttpRequest(
            ContractTls12VerifyCertificateHandshakeForHttpRequest(
                certHandshake,
                ContractHttpClientTlsTrustRequest(
                    rootPem,
                    intermediatesPemBundle: intermediatePem,
                    hostname: TEST_HOST_WWW,
                    validationTime: "230101000000Z",
                    pinPolicy: ContractX509PinPolicy(allowedLeafSpkiSha256: [leafSpkiPin])
                )
            )
        )
        @Assert(verified.chainLength, 3)

        let rsaExchange = contractTls12BuildRsaClientKeyExchangeFromLeafPemRequest(
            ContractTls12RsaClientKeyExchangeFromLeafPemRequest(rsaLeafPem)
        )
        let serverPreMaster = contractTls12ProcessRsaClientKeyExchangeRequest(
            ContractTls12ProcessRsaClientKeyExchangeRequest(
                rsaKeyPem,
                rsaExchange.encodedClientKeyExchange
            )
        )
        let clientSecrets = contractTls12DeriveSecretsFromPreMasterRequest(
            ContractTls12DeriveSecretsFromPreMasterRequest(
                rsaExchange.preMasterSecret,
                clientHello.clientRandom,
                serverHello.serverRandom
            )
        )
        let serverSecrets = contractTls12DeriveSecretsFromPreMasterRequest(
            ContractTls12DeriveSecretsFromPreMasterRequest(
                serverPreMaster,
                clientHello.clientRandom,
                serverHello.serverRandom
            )
        )
        @Assert(clientSecrets.masterSecret, serverSecrets.masterSecret)

        let ecdheClientHello = contractTls12BuildHttpClientHelloRequest(
            ContractTls12HttpClientHelloRequest(
                ContractTls12KeyExchange.EcdheP256,
                serverName: TEST_HOST_WWW,
                alpnProtocols: ["h2", "http/1.1"],
                requestOcspStapling: true
            )
        )
        let ecdheServerHello = contractTls12BuildHttpServerHelloRequest(
            ContractTls12HttpServerHelloRequest(
                ecdheClientHello.encodedClientHello,
                ContractTls12KeyExchange.EcdheP256
            )
        )
        let serverExchange = contractTls12BuildEcdheServerKeyExchangeRequest(
            ContractTls12EcdheServerKeyExchangeRequest(
                ContractTls12KeyExchange.EcdheP256,
                serverPrivateScalar: Some(incrementalBytes(32, start: 131))
            )
        )
        let clientExchange = contractTls12BuildEcdheClientKeyExchangeRequest(
            ContractTls12EcdheClientKeyExchangeRequest(
                ContractTls12KeyExchange.EcdheP256,
                clientPrivateScalar: Some(incrementalBytes(32, start: 163))
            )
        )
        let ecdheClientSecrets = contractTls12DeriveClientSecretsFromEcdheRequest(
            ContractTls12DeriveClientSecretsFromEcdheRequest(
                ContractTls12KeyExchange.EcdheP256,
                clientExchange.clientPrivateScalar,
                serverExchange.encodedServerKeyExchange,
                ecdheClientHello.clientRandom,
                ecdheServerHello.serverRandom
            )
        )
        let ecdheServerSecrets = contractTls12DeriveServerSecretsFromEcdheRequest(
            ContractTls12DeriveServerSecretsFromEcdheRequest(
                ContractTls12KeyExchange.EcdheP256,
                serverExchange.serverPrivateScalar,
                clientExchange.encodedClientKeyExchange,
                ecdheClientHello.clientRandom,
                ecdheServerHello.serverRandom
            )
        )
        @Assert(ecdheClientSecrets.masterSecret, ecdheServerSecrets.masterSecret)

        try {
            _ = contractTls12BuildHttpServerHelloRequest(
                ContractTls12HttpServerHelloRequest([], ContractTls12KeyExchange.Rsa)
            )
            @Fail("TLS1.2 HTTP ServerHello request should reject empty ClientHello")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testContractTls12RecordChannelAesRoundTrip(): Unit {
        let secrets = contractTls12DeriveSecretsFromPreMaster(
            incrementalBytes(48, start: 7),
            incrementalBytes(32, start: 51),
            incrementalBytes(32, start: 93)
        )
        let clientChannel = contractTls12CreateClientRecordChannel(
            secrets,
            algorithm: ContractAeadAlgorithm.Aes256Gcm
        )
        let serverChannel = contractTls12CreateServerRecordChannel(
            secrets,
            algorithm: ContractAeadAlgorithm.Aes256Gcm
        )
        @Assert(clientChannel.version.toString(), "TLS1.2")
        @Assert(serverChannel.version.toString(), "TLS1.2")

        let applicationData = "https-body-payload".toArray()
        let encodedApplicationRecord = clientChannel.sealApplicationData(applicationData)
        let openedApplicationData = serverChannel.openApplicationData(encodedApplicationRecord)
        @Assert(openedApplicationData, applicationData)

        let encodedHandshakeRecord = serverChannel.seal(
            ContractTlsRecordContentType.Handshake,
            [UInt8(0x01), UInt8(0x02), UInt8(0x03)]
        )
        let openedHandshake = clientChannel.open(encodedHandshakeRecord)
        @Assert(openedHandshake.version.toString(), "TLS1.2")
        @Assert(openedHandshake.contentType.toString(), "HANDSHAKE")
        @Assert(openedHandshake.fragment, [UInt8(0x01), UInt8(0x02), UInt8(0x03)])

        try {
            _ = clientChannel.openApplicationData(encodedHandshakeRecord)
            @Fail("openApplicationData must reject non-application-data records")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }

        let request = ContractTls12RecordChannelRequest(
            secrets,
            algorithm: ContractAeadAlgorithm.Aes256Gcm
        )
        let clientChannelByRequest = contractTls12CreateClientRecordChannelRequest(request)
        let serverChannelByRequest = contractTls12CreateServerRecordChannelRequest(request)
        let requestRecord = clientChannelByRequest.sealApplicationData("tls12-request-facade".toArray())
        let requestOpened = serverChannelByRequest.openApplicationData(requestRecord)
        @Assert(requestOpened, "tls12-request-facade".toArray())
    }

    @TestCase
    public func testContractTls13RecordChannelChachaFragmentsRoundTrip(): Unit {
        let keyMaterial = ContractTls13ApplicationKeyMaterial(
            incrementalBytes(32, start: 31),
            incrementalBytes(12, start: 101),
            incrementalBytes(32, start: 141),
            incrementalBytes(12, start: 211)
        )
        let clientChannel = contractTls13CreateClientRecordChannel(
            keyMaterial,
            algorithm: ContractAeadAlgorithm.Chacha20Poly1305
        )
        let serverChannel = contractTls13CreateServerRecordChannel(
            keyMaterial,
            algorithm: ContractAeadAlgorithm.Chacha20Poly1305
        )
        @Assert(clientChannel.version.toString(), "TLS1.3")
        @Assert(serverChannel.version.toString(), "TLS1.3")

        let payload = incrementalBytes(768, start: 23)
        let encodedRecords = clientChannel.sealFragments(
            ContractTlsRecordContentType.ApplicationData,
            payload,
            maxFragmentLen: 128
        )
        @Assert(encodedRecords.size > 1, true)
        let opened = serverChannel.openAndReassemble(encodedRecords)
        @Assert(opened, payload)
        @Assert(clientChannel.writeSequence > 0, true)

        clientChannel.resetSequences()
        serverChannel.resetSequences()
        @Assert(clientChannel.writeSequence, 0)
        @Assert(serverChannel.readSequence, 0)

        let request = ContractTls13RecordChannelRequest(
            keyMaterial,
            algorithm: ContractAeadAlgorithm.Chacha20Poly1305
        )
        let clientChannelByRequest = contractTls13CreateClientRecordChannelRequest(request)
        let serverChannelByRequest = contractTls13CreateServerRecordChannelRequest(request)
        let reqEncoded = clientChannelByRequest.sealApplicationData("req-round-trip".toArray())
        let reqOpened = serverChannelByRequest.openApplicationData(reqEncoded)
        @Assert(reqOpened, "req-round-trip".toArray())
    }

    @TestCase
    public func testContractTlsRecordAlertFacadeAndCloseNotify(): Unit {
        let clientHello = contractTls13BuildHttpClientHelloX25519(
            "localhost",
            alpnProtocols: ["http/1.1"],
            clientPrivateKey: Some(incrementalBytes(32, start: 13))
        )
        let wrappedClientHelloRecord = contractTlsEncodePlaintextRecordRequest(
            ContractTlsPlaintextRecordRequest(
                ContractTlsVersion.Tls12,
                ContractTlsRecordContentType.Handshake,
                clientHello.encodedClientHello
            )
        )
        let decodedWrappedClientHello = tlsDecodeRecord(wrappedClientHelloRecord)
        @Assert(decodedWrappedClientHello.header.contentType.toString(), "HANDSHAKE")
        @Assert(decodedWrappedClientHello.header.version.toString(), "TLS1.2")
        @Assert(decodedWrappedClientHello.fragment, clientHello.encodedClientHello)

        let alertPayloadRequest = ContractTlsAlertPayloadRequest(
            ContractTlsAlertLevel.AlertWarning,
            ContractTlsAlertDescription.AlertCloseNotify
        )
        let encodedAlertPayload = contractTlsEncodeAlertPayloadRequest(alertPayloadRequest)
        let decodedAlertPayload = contractTlsDecodeAlertPayloadRequest(
            ContractTlsAlertPayloadDecodeRequest(encodedAlertPayload)
        )
        @Assert(decodedAlertPayload.isCloseNotify, true)

        let plainAlertRecord = contractTlsEncodeAlertRecordRequest(
            ContractTlsAlertRecordRequest(
                ContractTlsVersion.Tls13,
                ContractTlsAlertLevel.AlertWarning,
                ContractTlsAlertDescription.AlertCloseNotify
            )
        )
        let decodedPlainAlert = contractTlsDecodeAlertRecord(plainAlertRecord)
        @Assert(decodedPlainAlert.level.toString(), "WARNING")
        @Assert(decodedPlainAlert.description.toString(), "CLOSE_NOTIFY")
        @Assert(decodedPlainAlert.isCloseNotify, true)
        @Assert(contractTlsIsCloseNotifyAlert(decodedPlainAlert), true)

        let alertRecordOutcome = contractTryTlsDecodeAlertRecordRequest(
            ContractTlsAlertRecordDecodeRequest(plainAlertRecord)
        )
        @Assert(alertRecordOutcome.ok, true)
        match (alertRecordOutcome.result) {
            case Some(value) => @Assert(value.isCloseNotify, true)
            case None => @Fail("successful TLS alert record outcome should carry result")
        }

        let keyMaterial = ContractTls13ApplicationKeyMaterial(
            incrementalBytes(32, start: 51),
            incrementalBytes(12, start: 71),
            incrementalBytes(32, start: 91),
            incrementalBytes(12, start: 111)
        )
        let clientChannel = contractTls13CreateClientRecordChannel(keyMaterial)
        let serverChannel = contractTls13CreateServerRecordChannel(keyMaterial)
        let encodedEncryptedCloseNotify = clientChannel.sendCloseNotify()
        let decodedEncryptedCloseNotify = serverChannel.openAlert(encodedEncryptedCloseNotify)
        @Assert(decodedEncryptedCloseNotify.isCloseNotify, true)

        try {
            _ = contractTlsDecodeAlertPayload([UInt8(0x03), UInt8(0x00)])
            @Fail("unsupported TLS alert level should surface as contract unsupported")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }

        let failedAlertPayloadOutcome = contractTryTlsDecodeAlertPayloadRequest(
            ContractTlsAlertPayloadDecodeRequest([UInt8(0x03), UInt8(0x00)])
        )
        @Assert(failedAlertPayloadOutcome.ok, false)
        match (failedAlertPayloadOutcome.code) {
            case Some(value) => @Assert(value.toString(), "UNSUPPORTED")
            case None => @Fail("failed TLS alert payload outcome should carry contract code")
        }
        match (failedAlertPayloadOutcome.igniteCode) {
            case Some(value) => @Assert(value.toString(), "CRYPTO_UNAVAILABLE")
            case None => @Fail("failed TLS alert payload outcome should carry ignite code")
        }

        try {
            _ = contractTlsDecodeAlertRecord([UInt8(0x99), UInt8(0x03), UInt8(0x03), UInt8(0x00), UInt8(0x00)])
            @Fail("unsupported TLS content type should surface as contract unsupported")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }

        let failedAlertRecordOutcome = contractTryTlsDecodeAlertRecord(
            [UInt8(0x99), UInt8(0x03), UInt8(0x03), UInt8(0x00), UInt8(0x00)]
        )
        @Assert(failedAlertRecordOutcome.ok, false)
        match (failedAlertRecordOutcome.code) {
            case Some(value) => @Assert(value.toString(), "UNSUPPORTED")
            case None => @Fail("failed TLS alert record outcome should carry contract code")
        }
        match (failedAlertRecordOutcome.igniteCode) {
            case Some(value) => @Assert(value.toString(), "CRYPTO_UNAVAILABLE")
            case None => @Fail("failed TLS alert record outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractTlsSessionTicketAndCacheFacade(): Unit {
        let identity = ContractTlsSessionIdentity(
            ContractTlsVersion.Tls13,
            incrementalBytes(16, start: 17),
            serverName: TEST_HOST_WWW_UPPER,
            alpnProtocol: "H2"
        )
        let ticket = contractTlsCreateSessionTicket(
            identity,
            incrementalBytes(48, start: 101),
            nonce: incrementalBytes(8, start: 3),
            nowUnixSeconds: 100,
            ttlSeconds: 600
        )
        @Assert(ticket.identity.serverName, TEST_HOST_WWW)
        @Assert(ticket.identity.alpnProtocol, "h2")
        @Assert(contractTlsIsSessionTicketExpired(ticket, nowUnixSeconds: 699), false)
        @Assert(contractTlsIsSessionTicketExpired(ticket, nowUnixSeconds: 700), true)

        let encoded = contractTlsEncodeSessionTicket(ticket)
        let decoded = contractTlsDecodeSessionTicket(encoded)
        @Assert(decoded.identity.resumptionId, identity.resumptionId)
        @Assert(decoded.secret, ticket.secret)
        @Assert(decoded.expiresAtUnixSeconds, 700)

        let cache = ContractTlsSessionCache(maxEntries: 2, defaultTtlSeconds: 60)
        _ = cache.store(decoded)
        let loaded = cache.load(identity, nowUnixSeconds: 200)
        match (loaded) {
            case Some(value) =>
                @Assert(value.secret, ticket.secret)
            case None =>
                @Fail("session cache should load stored ticket")
        }

        let statsAfterHit = cache.stats()
        @Assert(statsAfterHit.hits > 0, true)
        @Assert(cache.remove(identity), true)
        let statsAfterRemove = cache.stats()
        @Assert(statsAfterRemove.size, 0)
    }

    @TestCase
    public func testContractTls13NewSessionTicketBridgeFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(24, start: 91),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 201),
            nonce: incrementalBytes(12, start: 7),
            nowUnixSeconds: 1000,
            ttlSeconds: 720
        )
        let encodedNewSessionTicket = contractTls13BuildNewSessionTicketFromSessionTicket(
            ticket,
            ticketAgeAdd: 17
        )
        let decoded = contractTls13DecodeSessionTicketFromNewSessionTicket(encodedNewSessionTicket)
        @Assert(decoded.identity.serverName, "resume.example.com")
        @Assert(decoded.identity.alpnProtocol, "h2")
        @Assert(decoded.identity.resumptionId, ticket.identity.resumptionId)
        @Assert(decoded.secret, ticket.secret)
        @Assert(decoded.nonce, ticket.nonce)
    }

    @TestCase
    public func testContractTls13SessionCachePskClientHelloFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(24, start: 141),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 211),
            nonce: incrementalBytes(8, start: 27),
            nowUnixSeconds: 400,
            ttlSeconds: 900
        )
        let encodedNewSessionTicket = contractTls13BuildNewSessionTicketFromSessionTicket(ticket)
        let cache = ContractTlsSessionCache(maxEntries: 4, defaultTtlSeconds: 60)
        let stored = contractTls13StoreNewSessionTicketToCache(cache, encodedNewSessionTicket)
        @Assert(stored.identity.resumptionId, ticket.identity.resumptionId)
        @Assert(stored.secret, ticket.secret)

        let fromCache = contractTls13BuildHttpClientHelloPskFromSessionCache(
            cache,
            ticket.identity,
            nowUnixSeconds: 410,
            sessionId: incrementalBytes(8, start: 7)
        )
        @Assert(fromCache.ticket.secret, ticket.secret)
        let selectedTicket = contractTls13ExtractClientPskSessionTicket(fromCache.encodedClientHello)
        @Assert(selectedTicket.identity.resumptionId, ticket.identity.resumptionId)
        @Assert(selectedTicket.secret, ticket.secret)

        let missingIdentity = ContractTlsSessionIdentity(
            ContractTlsVersion.Tls13,
            incrementalBytes(24, start: 33),
            serverName: "resume.example.com",
            alpnProtocol: "h2"
        )
        let maybeMissing = contractTls13TryBuildHttpClientHelloPskFromSessionCache(
            cache,
            missingIdentity,
            nowUnixSeconds: 410
        )
        match (maybeMissing) {
            case Some(_value) =>
                @Fail("missing cached identity should return None")
            case None =>
                ()
        }

        try {
            _ = contractTls13BuildHttpClientHelloPskFromSessionCache(
                cache,
                missingIdentity,
                nowUnixSeconds: 410
            )
            @Fail("strict cached PSK ClientHello build should fail when ticket is absent")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "KEY_NOT_FOUND")
        }
    }

    @TestCase
    public func testContractTls13SessionCachePskClientHelloOutcomeFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(24, start: 61),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 91),
            nonce: incrementalBytes(8, start: 43),
            nowUnixSeconds: 400,
            ttlSeconds: 400
        )
        let cache = ContractTlsSessionCache(maxEntries: 4, defaultTtlSeconds: 60)
        _ = cache.store(ticket)

        let ok = contractTryBuildHttpClientHelloPskFromSessionCacheOutcome(
            cache,
            ticket.identity,
            nowUnixSeconds: 500,
            sessionId: incrementalBytes(8, start: 12)
        )
        @Assert(ok.ok, true)
        match (ok.result) {
            case Some(value) =>
                @Assert(value.ticket.secret, ticket.secret)
            case None =>
                @Fail("PSK cache success outcome should carry result")
        }

        let missingIdentity = ContractTlsSessionIdentity(
            ContractTlsVersion.Tls13,
            incrementalBytes(24, start: 62),
            serverName: "resume.example.com",
            alpnProtocol: "h2"
        )
        let missing = contractTryBuildHttpClientHelloPskFromSessionCacheOutcome(
            cache,
            missingIdentity,
            nowUnixSeconds: 500
        )
        @Assert(missing.ok, false)
        match (missing.code) {
            case Some(value) => @Assert(value.toString(), "KEY_NOT_FOUND")
            case None => @Fail("missing PSK cache outcome should carry contract code")
        }
        match (missing.igniteCode) {
            case Some(value) => @Assert(value.toString(), "KEY_NOT_FOUND")
            case None => @Fail("missing PSK cache outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractTls13SessionTicketLifecyclePolicyFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(24, start: 131),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 51),
            nonce: incrementalBytes(8, start: 77),
            nowUnixSeconds: 1000,
            ttlSeconds: 600
        )

        let strictPolicy = ContractTls13SessionTicketPolicy(
            minRemainingTtlSeconds: 120,
            renewBeforeExpirySeconds: 180,
            requiredServerName: "resume.example.com",
            requiredAlpnProtocol: "h2"
        )
        let nearExpiry = contractTls13EvaluateSessionTicketLifecycle(
            ticket,
            policy: strictPolicy,
            nowUnixSeconds: 1450
        )
        @Assert(nearExpiry.usable, true)
        @Assert(nearExpiry.shouldRenew, true)
        @Assert(nearExpiry.reason, "OK_RENEW_RECOMMENDED")
        @Assert(nearExpiry.remainingTtlSeconds, 150)

        let mismatchPolicy = ContractTls13SessionTicketPolicy(
            requiredServerName: TEST_HOST_API
        )
        let mismatch = contractTls13EvaluateSessionTicketLifecycle(
            ticket,
            policy: mismatchPolicy,
            nowUnixSeconds: 1200
        )
        @Assert(mismatch.usable, false)
        @Assert(mismatch.reason, "SERVER_NAME_MISMATCH")

        try {
            _ = contractTls13RequireUsableSessionTicket(
                ticket,
                policy: ContractTls13SessionTicketPolicy(
                    minRemainingTtlSeconds: 700
                ),
                nowUnixSeconds: 1200
            )
            @Fail("require usable session ticket should fail when remaining ttl is below policy")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractTls13SessionCachePskClientHelloPolicyFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(24, start: 181),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 111),
            nonce: incrementalBytes(8, start: 7),
            nowUnixSeconds: 800,
            ttlSeconds: 500
        )
        let cache = ContractTlsSessionCache(maxEntries: 4, defaultTtlSeconds: 60)
        _ = cache.store(ticket)

        let allowed = contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicy(
            cache,
            ticket.identity,
            policy: ContractTls13SessionTicketPolicy(
                minRemainingTtlSeconds: 100,
                requiredServerName: "resume.example.com",
                requiredAlpnProtocol: "h2"
            ),
            nowUnixSeconds: 1100
        )
        match (allowed) {
            case Some(value) =>
                @Assert(value.ticket.secret, ticket.secret)
            case None =>
                @Fail("cache ticket should pass lifecycle policy")
        }

        let blocked = contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicy(
            cache,
            ticket.identity,
            policy: ContractTls13SessionTicketPolicy(
                minRemainingTtlSeconds: 300
            ),
            nowUnixSeconds: 1100
        )
        match (blocked) {
            case Some(_value) =>
                @Fail("cache ticket should be rejected when lifecycle policy requires larger remaining ttl")
            case None =>
                ()
        }

        try {
            _ = contractTls13BuildHttpClientHelloPskFromSessionCacheWithPolicy(
                cache,
                ticket.identity,
                policy: ContractTls13SessionTicketPolicy(
                    minRemainingTtlSeconds: 300
                ),
                nowUnixSeconds: 1100
            )
            @Fail("strict cache->PSK helper should fail when no usable ticket is available")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "KEY_NOT_FOUND")
        }
    }

    @TestCase
    public func testContractTls13SessionCachePskClientHelloPolicyOutcomeFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(24, start: 211),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 121),
            nonce: incrementalBytes(8, start: 17),
            nowUnixSeconds: 800,
            ttlSeconds: 500
        )
        let cache = ContractTlsSessionCache(maxEntries: 4, defaultTtlSeconds: 60)
        _ = cache.store(ticket)

        let allowed = contractTryBuildHttpClientHelloPskFromSessionCacheWithPolicyOutcome(
            cache,
            ticket.identity,
            policy: ContractTls13SessionTicketPolicy(
                minRemainingTtlSeconds: 100,
                requiredServerName: "resume.example.com",
                requiredAlpnProtocol: "h2"
            ),
            nowUnixSeconds: 1100
        )
        @Assert(allowed.ok, true)
        match (allowed.lifecycle) {
            case Some(value) =>
                @Assert(value.reason, "OK_RENEW_RECOMMENDED")
                @Assert(value.shouldRenew, true)
            case None => @Fail("allowed PSK policy outcome should carry lifecycle")
        }

        let blocked = contractTryBuildHttpClientHelloPskFromSessionCacheWithPolicyOutcome(
            cache,
            ticket.identity,
            policy: ContractTls13SessionTicketPolicy(
                minRemainingTtlSeconds: 300
            ),
            nowUnixSeconds: 1100
        )
        @Assert(blocked.ok, false)
        match (blocked.code) {
            case Some(value) => @Assert(value.toString(), "VERIFY_FAILED")
            case None => @Fail("blocked PSK policy outcome should carry contract code")
        }
        match (blocked.lifecycle) {
            case Some(value) => @Assert(value.reason, "INSUFFICIENT_REMAINING_TTL")
            case None => @Fail("blocked PSK policy outcome should carry lifecycle")
        }
        match (blocked.igniteCode) {
            case Some(value) => @Assert(value.toString(), "DECRYPT_FAILED")
            case None => @Fail("blocked PSK policy outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractTls13SessionTicketRequestFacades(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(24, start: 231),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 141),
            nonce: incrementalBytes(8, start: 29),
            nowUnixSeconds: 900,
            ttlSeconds: 700
        )
        let lifecycleRequest = ContractTls13SessionTicketLifecycleRequest(
            ticket,
            policy: ContractTls13SessionTicketPolicy(
                minRemainingTtlSeconds: 150,
                renewBeforeExpirySeconds: 300,
                requiredServerName: "resume.example.com",
                requiredAlpnProtocol: "h2"
            ),
            nowUnixSeconds: 1300
        )
        let lifecycle = contractTls13EvaluateSessionTicketLifecycleRequest(lifecycleRequest)
        @Assert(lifecycle.usable, true)
        @Assert(lifecycle.shouldRenew, true)
        @Assert(lifecycle.reason, "OK_RENEW_RECOMMENDED")

        let required = contractTls13RequireUsableSessionTicketRequest(lifecycleRequest)
        @Assert(required.remainingTtlSeconds, 300)

        let rejectedRequest = ContractTls13SessionTicketLifecycleRequest(
            ticket,
            policy: ContractTls13SessionTicketPolicy(
                minRemainingTtlSeconds: 400
            ),
            nowUnixSeconds: 1300
        )
        try {
            _ = contractTls13RequireUsableSessionTicketRequest(rejectedRequest)
            @Fail("request-style usable session ticket helper should reject insufficient ttl")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }

        let encodedNewSessionTicket = contractTls13BuildNewSessionTicketFromSessionTicketRequest(
            ContractTls13NewSessionTicketRequest(ticket, ticketAgeAdd: 23)
        )
        let cache = ContractTlsSessionCache(maxEntries: 4, defaultTtlSeconds: 60)
        let stored = contractTls13StoreNewSessionTicketToCacheRequest(
            ContractTls13StoreNewSessionTicketRequest(cache, encodedNewSessionTicket)
        )
        @Assert(stored.identity.resumptionId, ticket.identity.resumptionId)
        @Assert(stored.secret, ticket.secret)
    }

    @TestCase
    public func testContractTls13SessionCachePskClientHelloRequestFacades(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(24, start: 17),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 181),
            nonce: incrementalBytes(8, start: 39),
            nowUnixSeconds: 1000,
            ttlSeconds: 500
        )
        let cache = ContractTlsSessionCache(maxEntries: 4, defaultTtlSeconds: 60)
        _ = cache.store(ticket)

        let request = ContractTls13PskClientHelloFromSessionCacheRequest(
            cache,
            ticket.identity,
            nowUnixSeconds: 1100,
            sessionId: incrementalBytes(8, start: 55)
        )
        let strictResult = contractTls13BuildHttpClientHelloPskFromSessionCacheRequest(request)
        @Assert(strictResult.ticket.secret, ticket.secret)

        let optionalResult = contractTls13TryBuildHttpClientHelloPskFromSessionCacheRequest(request)
        match (optionalResult) {
            case Some(value) =>
                @Assert(value.ticket.identity.resumptionId, ticket.identity.resumptionId)
            case None =>
                @Fail("request-style cache PSK helper should load stored ticket")
        }

        let outcome = contractTryBuildHttpClientHelloPskFromSessionCacheRequestOutcome(request)
        @Assert(outcome.ok, true)
        match (outcome.result) {
            case Some(value) =>
                let selectedTicket = contractTls13ExtractClientPskSessionTicket(value.encodedClientHello)
                @Assert(selectedTicket.secret, ticket.secret)
            case None =>
                @Fail("request-style cache PSK outcome should carry result")
        }

        let policyRequest = ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest(
            cache,
            ticket.identity,
            policy: ContractTls13SessionTicketPolicy(
                minRemainingTtlSeconds: 150,
                requiredServerName: "resume.example.com",
                requiredAlpnProtocol: "h2"
            ),
            nowUnixSeconds: 1300,
            sessionId: incrementalBytes(8, start: 87)
        )
        let allowed = contractTls13BuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(policyRequest)
        @Assert(allowed.ticket.identity.resumptionId, ticket.identity.resumptionId)

        let blockedOutcome = contractTryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequestOutcome(
            ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest(
                cache,
                ticket.identity,
                policy: ContractTls13SessionTicketPolicy(
                    minRemainingTtlSeconds: 300
                ),
                nowUnixSeconds: 1300
            )
        )
        @Assert(blockedOutcome.ok, false)
        match (blockedOutcome.lifecycle) {
            case Some(value) => @Assert(value.reason, "INSUFFICIENT_REMAINING_TTL")
            case None => @Fail("blocked request-style PSK outcome should carry lifecycle")
        }
    }

    @TestCase
    public func testContractTls13PskEarlyDataPlanFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 171),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 71),
            nonce: incrementalBytes(8, start: 59),
            nowUnixSeconds: 2000,
            ttlSeconds: 600
        )

        let clientPlan = contractTls13PreparePskEarlyDataFromSessionTicket(
            ticket,
            sessionId: incrementalBytes(8, start: 13)
        )
        @Assert(clientPlan.selectedIdentityIndex, 0)
        @Assert(clientPlan.ticket.secret, ticket.secret)
        @Assert(clientPlan.clientHelloHash, sha256(clientPlan.encodedClientHello))
        @Assert(clientPlan.clientEarlyWriteKey.size, 16)
        @Assert(clientPlan.clientEarlyWriteIv.size, 12)

        let serverPlan = contractTls13AcceptPskEarlyDataFromClientHello(
            clientPlan.encodedClientHello,
            nowUnixSeconds: 2100
        )
        @Assert(serverPlan.selectedIdentityIndex, 0)
        @Assert(serverPlan.ticket.identity.resumptionId, ticket.identity.resumptionId)
        @Assert(serverPlan.clientHelloHash, clientPlan.clientHelloHash)
        @Assert(serverPlan.clientEarlyTrafficSecret, clientPlan.clientEarlyTrafficSecret)
        @Assert(serverPlan.clientEarlyWriteKey, clientPlan.clientEarlyWriteKey)
        @Assert(serverPlan.clientEarlyWriteIv, clientPlan.clientEarlyWriteIv)

        let cache = ContractTlsSessionCache(maxEntries: 2, defaultTtlSeconds: 60)
        _ = cache.store(ticket)
        let fromCachePlan = contractTls13PreparePskEarlyDataFromSessionCache(
            cache,
            ticket.identity,
            nowUnixSeconds: 2100
        )
        let serverFromCachePlan = contractTls13AcceptPskEarlyDataFromClientHello(
            fromCachePlan.encodedClientHello,
            nowUnixSeconds: 2100,
            selectedIdentityIndex: fromCachePlan.selectedIdentityIndex
        )
        @Assert(serverFromCachePlan.clientEarlyTrafficSecret, fromCachePlan.clientEarlyTrafficSecret)
        @Assert(serverFromCachePlan.clientEarlyWriteKey, fromCachePlan.clientEarlyWriteKey)
        @Assert(serverFromCachePlan.clientEarlyWriteIv, fromCachePlan.clientEarlyWriteIv)

        let expiredTicket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 201),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 111),
            nonce: incrementalBytes(8, start: 91),
            nowUnixSeconds: 100,
            ttlSeconds: 5
        )
        let expiredPlan = contractTls13PreparePskEarlyDataFromSessionTicket(expiredTicket)
        try {
            _ = contractTls13AcceptPskEarlyDataFromClientHello(
                expiredPlan.encodedClientHello,
                nowUnixSeconds: 200
            )
            @Fail("expired session ticket early data plan should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractTls13PskEarlyDataReplayCacheFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 181),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 81),
            nonce: incrementalBytes(8, start: 63),
            nowUnixSeconds: 3000,
            ttlSeconds: 600
        )

        let clientPlan = contractTls13PreparePskEarlyDataFromSessionTicket(
            ticket,
            sessionId: incrementalBytes(8, start: 9)
        )
        let replayCache = ContractTls13EarlyDataReplayCache(maxEntries: 2, defaultWindowSeconds: 120)
        let serverPlan = contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCache(
            clientPlan.encodedClientHello,
            replayCache,
            nowUnixSeconds: 3100,
            replayTtlSeconds: 60
        )
        @Assert(serverPlan.clientEarlyTrafficSecret, clientPlan.clientEarlyTrafficSecret)
        @Assert(serverPlan.clientEarlyWriteKey, clientPlan.clientEarlyWriteKey)
        @Assert(serverPlan.clientEarlyWriteIv, clientPlan.clientEarlyWriteIv)

        let replayKey = contractTls13BuildPskEarlyDataReplayKey(serverPlan)
        @Assert(replayCache.contains(replayKey, nowUnixSeconds: 3100), true)

        try {
            _ = contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCache(
                clientPlan.encodedClientHello,
                replayCache,
                nowUnixSeconds: 3105,
                replayTtlSeconds: 60
            )
            @Fail("TLS1.3 early data replay should be rejected")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }

        @Assert(replayCache.purgeExpired(nowUnixSeconds: 3161), 1)
        @Assert(replayCache.contains(replayKey, nowUnixSeconds: 3161), false)
        let stats = replayCache.stats()
        @Assert(stats.hits > 0, true)
        @Assert(stats.rejects > 0, true)
    }

    @TestCase
    public func testContractTls13PskEarlyDataHttpBindingFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 191),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 91),
            nonce: incrementalBytes(8, start: 73),
            nowUnixSeconds: 4000,
            ttlSeconds: 600
        )

        let clientPlan = contractTls13PreparePskEarlyDataFromSessionTicket(
            ticket,
            sessionId: incrementalBytes(8, start: 17)
        )
        let accepted = contractTls13AcceptPskEarlyDataForHttp(
            clientPlan.encodedClientHello,
            expectedServerName: "RESUME.EXAMPLE.COM",
            expectedAlpnProtocol: "H2",
            nowUnixSeconds: 4100
        )
        @Assert(accepted.clientEarlyTrafficSecret, clientPlan.clientEarlyTrafficSecret)

        try {
            _ = contractTls13AcceptPskEarlyDataForHttp(
                clientPlan.encodedClientHello,
                expectedServerName: TEST_HOST_API,
                expectedAlpnProtocol: "h2",
                nowUnixSeconds: 4100
            )
            @Fail("mismatched expected server name should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }

        try {
            _ = contractTls13AcceptPskEarlyDataForHttp(
                clientPlan.encodedClientHello,
                expectedServerName: "resume.example.com",
                expectedAlpnProtocol: "http/1.1",
                nowUnixSeconds: 4100
            )
            @Fail("mismatched expected ALPN should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }

        let replayCache = ContractTls13EarlyDataReplayCache(maxEntries: 2, defaultWindowSeconds: 120)
        _ = contractTls13AcceptPskEarlyDataForHttpWithReplayCache(
            clientPlan.encodedClientHello,
            replayCache,
            expectedServerName: "resume.example.com",
            expectedAlpnProtocol: "h2",
            nowUnixSeconds: 4100,
            replayTtlSeconds: 60
        )
        try {
            _ = contractTls13AcceptPskEarlyDataForHttpWithReplayCache(
                clientPlan.encodedClientHello,
                replayCache,
                expectedServerName: "resume.example.com",
                expectedAlpnProtocol: "h2",
                nowUnixSeconds: 4105,
                replayTtlSeconds: 60
            )
            @Fail("replayed early data with HTTP binding should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractTls13PskEarlyDataRequestFacades(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 41),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 151),
            nonce: incrementalBytes(8, start: 99),
            nowUnixSeconds: 5000,
            ttlSeconds: 600
        )

        let prepareRequest = ContractTls13PskEarlyDataFromSessionTicketRequest(
            ticket,
            sessionId: incrementalBytes(8, start: 21)
        )
        let clientPlan = contractTls13PreparePskEarlyDataFromSessionTicketRequest(prepareRequest)
        let accepted = contractTls13AcceptPskEarlyDataFromClientHelloRequest(
            ContractTls13PskEarlyDataAcceptRequest(
                clientPlan.encodedClientHello,
                nowUnixSeconds: 5100
            )
        )
        @Assert(accepted.clientEarlyTrafficSecret, clientPlan.clientEarlyTrafficSecret)

        let cache = ContractTlsSessionCache(maxEntries: 2, defaultTtlSeconds: 60)
        _ = cache.store(ticket)
        let fromCachePlan = contractTls13PreparePskEarlyDataFromSessionCacheRequest(
            ContractTls13PskEarlyDataFromSessionCacheRequest(
                cache,
                ticket.identity,
                nowUnixSeconds: 5100,
                sessionId: incrementalBytes(8, start: 23)
            )
        )
        @Assert(fromCachePlan.ticket.identity.resumptionId, ticket.identity.resumptionId)

        let replayCache = ContractTls13EarlyDataReplayCache(maxEntries: 2, defaultWindowSeconds: 120)
        let replayAccepted = contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCacheRequest(
            ContractTls13PskEarlyDataAcceptWithReplayCacheRequest(
                fromCachePlan.encodedClientHello,
                replayCache,
                nowUnixSeconds: 5101,
                replayTtlSeconds: 60
            )
        )
        @Assert(replayAccepted.clientEarlyWriteKey, fromCachePlan.clientEarlyWriteKey)

        let httpAccepted = contractTls13AcceptPskEarlyDataForHttpRequest(
            ContractTls13PskEarlyDataHttpAcceptRequest(
                clientPlan.encodedClientHello,
                expectedServerName: "RESUME.EXAMPLE.COM",
                expectedAlpnProtocol: "H2",
                nowUnixSeconds: 5100
            )
        )
        @Assert(httpAccepted.clientEarlyWriteIv, clientPlan.clientEarlyWriteIv)

        let httpReplayCache = ContractTls13EarlyDataReplayCache(maxEntries: 2, defaultWindowSeconds: 120)
        let httpReplayRequest = ContractTls13PskEarlyDataHttpAcceptWithReplayCacheRequest(
            clientPlan.encodedClientHello,
            httpReplayCache,
            expectedServerName: "resume.example.com",
            expectedAlpnProtocol: "h2",
            nowUnixSeconds: 5102,
            replayTtlSeconds: 60
        )
        let httpReplayAccepted = contractTls13AcceptPskEarlyDataForHttpWithReplayCacheRequest(httpReplayRequest)
        @Assert(httpReplayAccepted.clientEarlyTrafficSecret, clientPlan.clientEarlyTrafficSecret)

        try {
            _ = contractTls13AcceptPskEarlyDataForHttpWithReplayCacheRequest(httpReplayRequest)
            @Fail("request-style HTTP early data replay should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractTls13KeyUpdateAndCipherBindingFacade(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")

        let clientHello = contractTls13BuildHttpClientHelloX25519(
            TEST_HOST_WWW,
            alpnProtocols: ["h2", "http/1.1"],
            clientPrivateKey: Some(incrementalBytes(32, start: 19))
        )
        let flight = contractTls13BuildHttpServerFlightX25519(
            clientHello.encodedClientHello,
            incrementalBytes(32, start: 201),
            "${leafPem}\n${intermediatePem}",
            leafKeyPem,
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )
        let verifiedSession = contractTls13VerifyHttpServerFlightX25519WithSession(
            clientHello,
            flight,
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z",
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )
        let binding = contractTls13ResolveCipherBindingFromVerifiedSession(verifiedSession)
        @Assert(binding.cipherSuiteName, "TLS_AES_128_GCM_SHA256")
        @Assert(binding.algorithm.toString(), "AES-256-GCM")
        @Assert(binding.keyLen, verifiedSession.result.keyMaterial.clientWriteKey.size)
        @Assert(binding.ivLen, verifiedSession.result.keyMaterial.clientWriteIv.size)

        let keyUpdate = contractTls13PrepareKeyUpdateFromVerifiedSession(
            verifiedSession,
            requestPeerUpdate: true
        )
        @Assert(contractTls13DecodeKeyUpdateHandshake(keyUpdate.encodedKeyUpdate), true)
        @Assert(keyUpdate.requestPeerUpdate, true)

        let applied = contractTls13ApplyPeerKeyUpdateFromVerifiedSession(
            verifiedSession,
            keyUpdate.encodedKeyUpdate
        )
        @Assert(applied.requestPeerUpdate, true)
        @Assert(applied.nextWriteKey.size, binding.keyLen)
        @Assert(applied.nextWriteIv.size, binding.ivLen)

        let keyUpdateByRequest = contractTls13PrepareKeyUpdateFromVerifiedSessionRequest(
            ContractTls13HttpVerifiedSessionKeyUpdateRequest(
                verifiedSession,
                requestPeerUpdate: true
            )
        )
        @Assert(contractTls13DecodeKeyUpdateHandshake(keyUpdateByRequest.encodedKeyUpdate), true)
        @Assert(keyUpdateByRequest.requestPeerUpdate, true)

        let appliedByRequest = contractTls13ApplyPeerKeyUpdateFromVerifiedSessionRequest(
            ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest(
                verifiedSession,
                keyUpdateByRequest.encodedKeyUpdate
            )
        )
        @Assert(appliedByRequest.requestPeerUpdate, true)
        @Assert(appliedByRequest.nextWriteKey.size, binding.keyLen)
        @Assert(appliedByRequest.nextWriteIv.size, binding.ivLen)

        let localTrafficUpdate = contractTls13RotateClientTrafficInVerifiedSession(
            verifiedSession,
            requestPeerUpdate: true
        )
        @Assert(localTrafficUpdate.requestPeerUpdate, true)
        @Assert(
            localTrafficUpdate.runtime.session.clientAppTrafficSecret == verifiedSession.clientAppTrafficSecret,
            false
        )
        @Assert(
            localTrafficUpdate.runtime.session.serverAppTrafficSecret,
            verifiedSession.serverAppTrafficSecret
        )
        let localCiphertext = localTrafficUpdate.runtime.clientChannel.sealApplicationData(
            "verified-session-local-update".toArray()
        )
        let localPlaintext = localTrafficUpdate.runtime.serverChannel.openApplicationData(localCiphertext)
        @Assert(localPlaintext, "verified-session-local-update".toArray())

        let localTrafficUpdateByRequest = contractTls13RotateClientTrafficInVerifiedSessionRequest(
            ContractTls13HttpVerifiedSessionKeyUpdateRequest(
                verifiedSession,
                requestPeerUpdate: true
            )
        )
        @Assert(
            localTrafficUpdateByRequest.runtime.session.clientAppTrafficSecret,
            localTrafficUpdate.runtime.session.clientAppTrafficSecret
        )

        let peerTrafficUpdate = contractTls13ApplyPeerTrafficUpdateToVerifiedSession(
            verifiedSession,
            keyUpdate.encodedKeyUpdate
        )
        @Assert(peerTrafficUpdate.requestPeerUpdate, true)
        @Assert(
            peerTrafficUpdate.runtime.session.clientAppTrafficSecret,
            verifiedSession.clientAppTrafficSecret
        )
        @Assert(
            peerTrafficUpdate.runtime.session.serverAppTrafficSecret == verifiedSession.serverAppTrafficSecret,
            false
        )
        let peerCiphertext = peerTrafficUpdate.runtime.serverChannel.sealApplicationData(
            "verified-session-peer-update".toArray()
        )
        let peerPlaintext = peerTrafficUpdate.runtime.clientChannel.openApplicationData(peerCiphertext)
        @Assert(peerPlaintext, "verified-session-peer-update".toArray())

        let peerTrafficUpdateByRequest = contractTls13ApplyPeerTrafficUpdateToVerifiedSessionRequest(
            ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest(
                verifiedSession,
                keyUpdateByRequest.encodedKeyUpdate
            )
        )
        @Assert(
            peerTrafficUpdateByRequest.runtime.session.serverAppTrafficSecret,
            peerTrafficUpdate.runtime.session.serverAppTrafficSecret
        )
    }

    @TestCase
    public func testContractTls13PskSessionResumptionFacade(): Unit {
        let expired = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 7),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 31),
            nonce: incrementalBytes(8, start: 3),
            nowUnixSeconds: 100,
            ttlSeconds: 10
        )
        let active = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 101),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 131),
            nonce: incrementalBytes(8, start: 11),
            nowUnixSeconds: 100,
            ttlSeconds: 600
        )

        let pskHello = contractTls13BuildHttpClientHelloPskFromSessionTickets(
            [expired, active],
            sessionId: incrementalBytes(8, start: 19)
        )
        let selected = contractTls13SelectPskIdentityFromSessionTickets(
            pskHello,
            nowUnixSeconds: 200
        )
        @Assert(selected, 1)

        let decodedSelectedTicket = contractTls13ExtractClientPskSessionTicket(
            pskHello,
            selectedIdentityIndex: selected
        )
        @Assert(decodedSelectedTicket.secret, active.secret)
        @Assert(decodedSelectedTicket.identity.resumptionId, active.identity.resumptionId)

        let serverHello = contractTls13BuildHttpServerHelloForPskBySessionTickets(
            pskHello,
            nowUnixSeconds: 200
        )
        @Assert(contractTls13ExtractServerSelectedPskIdentity(serverHello), 1)

        let singlePskHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(active)
        let serverHelloSingle = contractTls13BuildHttpServerHelloForPskFromSessionTicket(
            singlePskHello,
            selectedIdentityIndex: 0,
            nowUnixSeconds: 101
        )
        @Assert(contractTls13ExtractServerSelectedPskIdentity(serverHelloSingle), 0)
    }

    @TestCase
    public func testContractTls13PskX25519DerivedSecretsAndRecordChannelFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 17),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 129),
            nonce: incrementalBytes(8, start: 33),
            nowUnixSeconds: 1000,
            ttlSeconds: 600
        )
        let pskClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(ticket)
        let pskServerHello = contractTls13BuildHttpServerHelloForPskFromSessionTicket(
            pskClientHello,
            selectedIdentityIndex: 0,
            nowUnixSeconds: 1100
        )
        @Assert(contractTls13ExtractServerSelectedPskIdentity(pskServerHello), 0)

        let clientPrivate = incrementalBytes(32, start: 5)
        let serverPrivate = incrementalBytes(32, start: 77)
        let serverPublic = x25519PublicFromPrivate(serverPrivate)
        let transcriptHash = incrementalBytes(32, start: 201)

        let aesDerived = contractTls13DerivePskX25519SecretsFromSessionTicketAndServerHello(
            ticket,
            clientPrivate,
            serverPublic,
            transcriptHash,
            pskServerHello
        )
        @Assert(aesDerived.cipherBinding.cipherSuiteName, "TLS_AES_128_GCM_SHA256")
        @Assert(aesDerived.keyMaterial.clientWriteKey.size, aesDerived.cipherBinding.keyLen)
        @Assert(aesDerived.keyMaterial.clientWriteIv.size, aesDerived.cipherBinding.ivLen)

        let aesDerivedBySuite = contractTls13DerivePskX25519SecretsFromSessionTicketForCipherSuite(
            ticket,
            clientPrivate,
            serverPublic,
            transcriptHash,
            0x1301
        )
        @Assert(aesDerivedBySuite.masterSecret, aesDerived.masterSecret)
        @Assert(aesDerivedBySuite.keyMaterial.clientWriteKey, aesDerived.keyMaterial.clientWriteKey)

        let aesClientChannel = contractTls13CreateClientRecordChannelFromPskX25519Secrets(aesDerived)
        let aesServerChannel = contractTls13CreateServerRecordChannelFromPskX25519Secrets(aesDerived)
        let aesPayload = "tls13-psk-x25519-aes-payload".toArray()
        let aesEncrypted = aesClientChannel.sealApplicationData(aesPayload)
        let aesOpened = aesServerChannel.openApplicationData(aesEncrypted)
        @Assert(aesOpened, aesPayload)

        let chachaDerived = contractTls13DerivePskX25519SecretsFromSessionTicketForCipherSuite(
            ticket,
            clientPrivate,
            serverPublic,
            transcriptHash,
            0x1303
        )
        @Assert(chachaDerived.cipherBinding.cipherSuiteName, "TLS_CHACHA20_POLY1305_SHA256")
        @Assert(chachaDerived.cipherBinding.algorithm.toString(), "CHACHA20-POLY1305")
        @Assert(chachaDerived.keyMaterial.clientWriteKey.size, chachaDerived.cipherBinding.keyLen)

        let chachaClientChannel = contractTls13CreateClientRecordChannelFromPskX25519Secrets(chachaDerived)
        let chachaServerChannel = contractTls13CreateServerRecordChannelFromPskX25519Secrets(chachaDerived)
        let chachaPayload = "tls13-psk-x25519-chacha-payload".toArray()
        let chachaEncrypted = chachaClientChannel.sealApplicationData(chachaPayload)
        let chachaOpened = chachaServerChannel.openApplicationData(chachaEncrypted)
        @Assert(chachaOpened, chachaPayload)
    }

    @TestCase
    public func testContractTls13PskX25519ChannelSetAndTrafficRotationFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 41),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 101),
            nonce: incrementalBytes(8, start: 77),
            nowUnixSeconds: 2000,
            ttlSeconds: 900
        )
        let clientPrivate = incrementalBytes(32, start: 9)
        let serverPrivate = incrementalBytes(32, start: 63)
        let serverPublic = x25519PublicFromPrivate(serverPrivate)
        let transcriptHash = incrementalBytes(32, start: 171)

        let pskClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(ticket)
        let pskServerHello = contractTls13BuildHttpServerHelloForPskFromSessionTicket(
            pskClientHello,
            selectedIdentityIndex: 0,
            nowUnixSeconds: 2050
        )

        let initialChannels = contractTls13CreatePskX25519ChannelSetFromSessionTicketAndServerHello(
            ticket,
            clientPrivate,
            serverPublic,
            transcriptHash,
            pskServerHello
        )
        @Assert(initialChannels.secrets.cipherBinding.cipherSuiteName, "TLS_AES_128_GCM_SHA256")
        @Assert(initialChannels.clientChannel.algorithm.toString(), "AES-256-GCM")
        @Assert(initialChannels.serverChannel.algorithm.toString(), "AES-256-GCM")

        let rebuiltChannels = contractTls13CreatePskX25519ChannelSetFromSecrets(initialChannels.secrets)
        let initialPayload = "tls13-psk-x25519-initial-channelset".toArray()
        let initialCiphertext = rebuiltChannels.clientChannel.sealApplicationData(initialPayload)
        let initialOpened = rebuiltChannels.serverChannel.openApplicationData(initialCiphertext)
        @Assert(initialOpened, initialPayload)

        let clientUpdate = contractTls13RotatePskX25519ClientTraffic(
            initialChannels,
            requestPeerUpdate: true
        )
        @Assert(contractTls13DecodeKeyUpdateHandshake(clientUpdate.encodedKeyUpdate), true)
        @Assert(clientUpdate.requestPeerUpdate, true)
        @Assert(
            clientUpdate.channels.secrets.clientAppTrafficSecret == initialChannels.secrets.clientAppTrafficSecret,
            false
        )
        @Assert(
            clientUpdate.channels.secrets.serverAppTrafficSecret,
            initialChannels.secrets.serverAppTrafficSecret
        )

        let clientUpdatedPayload = "tls13-psk-x25519-client-update".toArray()
        let clientUpdatedCiphertext = clientUpdate.channels.clientChannel.sealApplicationData(clientUpdatedPayload)
        let clientUpdatedOpened = clientUpdate.channels.serverChannel.openApplicationData(clientUpdatedCiphertext)
        @Assert(clientUpdatedOpened, clientUpdatedPayload)

        let appliedClientUpdate = contractTls13ApplyPskX25519ClientTrafficUpdate(
            initialChannels,
            clientUpdate.encodedKeyUpdate
        )
        @Assert(appliedClientUpdate.requestPeerUpdate, true)
        @Assert(
            appliedClientUpdate.channels.secrets.clientAppTrafficSecret,
            clientUpdate.channels.secrets.clientAppTrafficSecret
        )
        @Assert(
            appliedClientUpdate.channels.secrets.serverAppTrafficSecret,
            clientUpdate.channels.secrets.serverAppTrafficSecret
        )
        let applyClientChannels = contractTls13CreatePskX25519ChannelSetFromSecrets(
            clientUpdate.channels.secrets
        )
        let appliedClientPayload = "tls13-psk-x25519-client-update-apply".toArray()
        let appliedClientCiphertext = applyClientChannels.clientChannel.sealApplicationData(appliedClientPayload)
        let appliedClientOpened = appliedClientUpdate.channels.serverChannel.openApplicationData(appliedClientCiphertext)
        @Assert(appliedClientOpened, appliedClientPayload)

        let serverUpdate = contractTls13RotatePskX25519ServerTraffic(clientUpdate.channels)
        @Assert(contractTls13DecodeKeyUpdateHandshake(serverUpdate.encodedKeyUpdate), false)
        @Assert(serverUpdate.requestPeerUpdate, false)
        @Assert(
            serverUpdate.channels.secrets.clientAppTrafficSecret,
            clientUpdate.channels.secrets.clientAppTrafficSecret
        )
        @Assert(
            serverUpdate.channels.secrets.serverAppTrafficSecret == clientUpdate.channels.secrets.serverAppTrafficSecret,
            false
        )

        let serverUpdatedPayload = "tls13-psk-x25519-server-update".toArray()
        let serverUpdatedCiphertext = serverUpdate.channels.serverChannel.sealApplicationData(serverUpdatedPayload)
        let serverUpdatedOpened = serverUpdate.channels.clientChannel.openApplicationData(serverUpdatedCiphertext)
        @Assert(serverUpdatedOpened, serverUpdatedPayload)

        let appliedServerUpdate = contractTls13ApplyPskX25519ServerTrafficUpdate(
            clientUpdate.channels,
            serverUpdate.encodedKeyUpdate
        )
        @Assert(appliedServerUpdate.requestPeerUpdate, false)
        @Assert(
            appliedServerUpdate.channels.secrets.clientAppTrafficSecret,
            serverUpdate.channels.secrets.clientAppTrafficSecret
        )
        @Assert(
            appliedServerUpdate.channels.secrets.serverAppTrafficSecret,
            serverUpdate.channels.secrets.serverAppTrafficSecret
        )
        let applyServerChannels = contractTls13CreatePskX25519ChannelSetFromSecrets(
            serverUpdate.channels.secrets
        )
        let appliedServerPayload = "tls13-psk-x25519-server-update-apply".toArray()
        let appliedServerCiphertext = applyServerChannels.serverChannel.sealApplicationData(appliedServerPayload)
        let appliedServerOpened = appliedServerUpdate.channels.clientChannel.openApplicationData(appliedServerCiphertext)
        @Assert(appliedServerOpened, appliedServerPayload)
    }

    @TestCase
    public func testContractTls13PskX25519PeerUpdateOrchestrationFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 143),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 201),
            nonce: incrementalBytes(8, start: 55),
            nowUnixSeconds: 3000,
            ttlSeconds: 600
        )
        let clientPrivate = incrementalBytes(32, start: 31)
        let serverPrivate = incrementalBytes(32, start: 91)
        let serverPublic = x25519PublicFromPrivate(serverPrivate)
        let transcriptHash = incrementalBytes(32, start: 29)

        let pskClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(ticket)
        let pskServerHello = contractTls13BuildHttpServerHelloForPskFromSessionTicket(
            pskClientHello,
            selectedIdentityIndex: 0,
            nowUnixSeconds: 3010
        )
        let channels = contractTls13CreatePskX25519ChannelSetFromSessionTicketAndServerHello(
            ticket,
            clientPrivate,
            serverPublic,
            transcriptHash,
            pskServerHello
        )

        let incomingClientUpdateWithRequest = contractTls13RotatePskX25519ClientTraffic(
            channels,
            requestPeerUpdate: true
        )
        let orchestratedClient = contractTls13ApplyPskX25519ClientTrafficUpdateAndMaybeRespond(
            channels,
            incomingClientUpdateWithRequest.encodedKeyUpdate
        )
        @Assert(orchestratedClient.incomingRequestPeerUpdate, true)
        @Assert(orchestratedClient.responseRequired, true)
        @Assert(contractTls13DecodeKeyUpdateHandshake(orchestratedClient.encodedResponseKeyUpdate), false)

        let manualApplyClient = contractTls13ApplyPskX25519ClientTrafficUpdate(
            channels,
            incomingClientUpdateWithRequest.encodedKeyUpdate
        )
        let manualResponseClient = contractTls13RotatePskX25519ServerTraffic(manualApplyClient.channels)
        @Assert(
            orchestratedClient.channels.secrets.clientAppTrafficSecret,
            manualResponseClient.channels.secrets.clientAppTrafficSecret
        )
        @Assert(
            orchestratedClient.channels.secrets.serverAppTrafficSecret,
            manualResponseClient.channels.secrets.serverAppTrafficSecret
        )
        @Assert(orchestratedClient.encodedResponseKeyUpdate, manualResponseClient.encodedKeyUpdate)

        let syncClientChannels = contractTls13CreatePskX25519ChannelSetFromSecrets(
            manualResponseClient.channels.secrets
        )
        let orchestratedClientPayload = "tls13-psk-x25519-orchestrated-client".toArray()
        let orchestratedClientCipher = syncClientChannels.clientChannel.sealApplicationData(orchestratedClientPayload)
        let orchestratedClientOpen = orchestratedClient.channels.serverChannel.openApplicationData(orchestratedClientCipher)
        @Assert(orchestratedClientOpen, orchestratedClientPayload)

        let incomingServerUpdateNoRequest = contractTls13RotatePskX25519ServerTraffic(channels)
        let orchestratedServerNoResp = contractTls13ApplyPskX25519ServerTrafficUpdateAndMaybeRespond(
            channels,
            incomingServerUpdateNoRequest.encodedKeyUpdate
        )
        @Assert(orchestratedServerNoResp.incomingRequestPeerUpdate, false)
        @Assert(orchestratedServerNoResp.responseRequired, false)
        @Assert(orchestratedServerNoResp.encodedResponseKeyUpdate.size, 0)

        let forcedServerResponse = contractTls13ApplyPskX25519ServerTrafficUpdateAndMaybeRespond(
            channels,
            incomingServerUpdateNoRequest.encodedKeyUpdate,
            forceResponse: true
        )
        @Assert(forcedServerResponse.incomingRequestPeerUpdate, false)
        @Assert(forcedServerResponse.responseRequired, true)
        @Assert(contractTls13DecodeKeyUpdateHandshake(forcedServerResponse.encodedResponseKeyUpdate), false)
    }

    @TestCase
    public func testContractTls13PskX25519RoleAwarePeerUpdateFacade(): Unit {
        let ticket = contractTlsCreateSessionTicket(
            ContractTlsSessionIdentity(
                ContractTlsVersion.Tls13,
                incrementalBytes(20, start: 221),
                serverName: "resume.example.com",
                alpnProtocol: "h2"
            ),
            incrementalBytes(48, start: 17),
            nonce: incrementalBytes(8, start: 113),
            nowUnixSeconds: 4000,
            ttlSeconds: 1200
        )
        let clientPrivate = incrementalBytes(32, start: 7)
        let serverPrivate = incrementalBytes(32, start: 139)
        let serverPublic = x25519PublicFromPrivate(serverPrivate)
        let transcriptHash = incrementalBytes(32, start: 211)
        let pskClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(ticket)
        let pskServerHello = contractTls13BuildHttpServerHelloForPskFromSessionTicket(
            pskClientHello,
            selectedIdentityIndex: 0,
            nowUnixSeconds: 4010
        )
        let channels = contractTls13CreatePskX25519ChannelSetFromSessionTicketAndServerHello(
            ticket,
            clientPrivate,
            serverPublic,
            transcriptHash,
            pskServerHello
        )

        let clientInitiated = contractTls13RotatePskX25519LocalTraffic(
            channels,
            ContractTlsEndpointRole.Client,
            requestPeerUpdate: true
        )
        let clientInitiatedExplicit = contractTls13RotatePskX25519ClientTraffic(
            channels,
            requestPeerUpdate: true
        )
        @Assert(clientInitiated.encodedKeyUpdate, clientInitiatedExplicit.encodedKeyUpdate)
        @Assert(
            clientInitiated.channels.secrets.clientAppTrafficSecret,
            clientInitiatedExplicit.channels.secrets.clientAppTrafficSecret
        )
        @Assert(
            clientInitiated.channels.secrets.serverAppTrafficSecret,
            clientInitiatedExplicit.channels.secrets.serverAppTrafficSecret
        )

        let serverApplyOnly = contractTls13ApplyPskX25519PeerTrafficUpdate(
            channels,
            clientInitiated.encodedKeyUpdate,
            ContractTlsEndpointRole.Server
        )
        @Assert(serverApplyOnly.requestPeerUpdate, true)
        @Assert(
            serverApplyOnly.channels.secrets.clientAppTrafficSecret,
            clientInitiated.channels.secrets.clientAppTrafficSecret
        )
        @Assert(
            serverApplyOnly.channels.secrets.serverAppTrafficSecret,
            channels.secrets.serverAppTrafficSecret
        )

        let serverOrchestrated = contractTls13ApplyPskX25519PeerTrafficUpdateAndMaybeRespond(
            channels,
            clientInitiated.encodedKeyUpdate,
            ContractTlsEndpointRole.Server
        )
        let explicitServerOrchestrated = contractTls13ApplyPskX25519ClientTrafficUpdateAndMaybeRespond(
            channels,
            clientInitiated.encodedKeyUpdate
        )
        @Assert(serverOrchestrated.incomingRequestPeerUpdate, true)
        @Assert(serverOrchestrated.responseRequired, true)
        @Assert(contractTls13DecodeKeyUpdateHandshake(serverOrchestrated.encodedResponseKeyUpdate), false)
        @Assert(
            serverOrchestrated.channels.secrets.clientAppTrafficSecret,
            explicitServerOrchestrated.channels.secrets.clientAppTrafficSecret
        )
        @Assert(
            serverOrchestrated.channels.secrets.serverAppTrafficSecret,
            explicitServerOrchestrated.channels.secrets.serverAppTrafficSecret
        )
        @Assert(serverOrchestrated.encodedResponseKeyUpdate, explicitServerOrchestrated.encodedResponseKeyUpdate)

        let serverInitiated = contractTls13RotatePskX25519LocalTraffic(
            channels,
            ContractTlsEndpointRole.Server
        )
        let clientOrchestrated = contractTls13ApplyPskX25519PeerTrafficUpdateAndMaybeRespond(
            channels,
            serverInitiated.encodedKeyUpdate,
            ContractTlsEndpointRole.Client
        )
        @Assert(clientOrchestrated.incomingRequestPeerUpdate, false)
        @Assert(clientOrchestrated.responseRequired, false)
        @Assert(clientOrchestrated.encodedResponseKeyUpdate.size, 0)

        let forcedClientResponse = contractTls13ApplyPskX25519PeerTrafficUpdateAndMaybeRespond(
            channels,
            serverInitiated.encodedKeyUpdate,
            ContractTlsEndpointRole.Client,
            forceResponse: true
        )
        @Assert(forcedClientResponse.incomingRequestPeerUpdate, false)
        @Assert(forcedClientResponse.responseRequired, true)
        @Assert(contractTls13DecodeKeyUpdateHandshake(forcedClientResponse.encodedResponseKeyUpdate), false)
    }

    @TestCase
    public func testContractRandomWrapperAndErrorMapping(): Unit {
        @Assert(contractMapCryptoErrorCode(CryptoErrorCode.InvalidArgument).toString(), "BAD_INPUT")
        @Assert(contractMapCryptoErrorCode(CryptoErrorCode.ParseError).toString(), "VERIFY_FAILED")
        @Assert(
            contractMapCryptoErrorCode(CryptoErrorCode.ComplianceRejected).toString(),
            "COMPLIANCE_REJECTED"
        )
        @Assert(contractMapCryptoErrorCode(CryptoErrorCode.Unsupported).toString(), "UNSUPPORTED")

        if (contractRandomAvailable()) {
            let randomBytes = contractRandomBytes(16)
            @Assert(randomBytes.size, 16)
        } else {
            try {
                _ = contractRandomBytes(16)
                @Fail("random call should fail when CSPRNG is unavailable")
            } catch (e: ContractException) {
                @Assert(e.code.toString(), "CRYPTO_UNAVAILABLE")
            }
        }
    }

    @TestCase
    public func testContractHkdfFacade(): Unit {
        let ikm = incrementalBytes(32, start: 9)
        let salt = incrementalBytes(16, start: 101)
        let info = "http-ssh-key-derivation".toArray()

        let expectedPrk = hkdfExtract(HashAlgorithm.SHA256, salt, ikm)
        let prk = contractHkdfExtract(ContractKdfHash.Sha256, salt, ikm)
        @Assert(prk, expectedPrk)

        let expectedOkm = hkdfExpand(HashAlgorithm.SHA256, expectedPrk, info, 42)
        let okmFromExpand = contractHkdfExpand(ContractKdfHash.Sha256, prk, info, 42)
        @Assert(okmFromExpand, expectedOkm)

        let okmFromOneShot = contractHkdf(
            ContractKdfHash.Sha256,
            ikm,
            info,
            42,
            salt: salt
        )
        let expectedOneShot = hkdf(HashAlgorithm.SHA256, ikm, info, 42, salt: salt)
        @Assert(okmFromOneShot, expectedOneShot)

        try {
            _ = contractHkdfExpand(ContractKdfHash.Sha256, prk, info, -1)
            @Fail("HKDF negative output length should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testContractHkdfHttpSshKeySetFacade(): Unit {
        let ikm = incrementalBytes(32, start: 37)
        let salt = incrementalBytes(16, start: 81)
        let keySet = contractHkdfDeriveHttpSshKeySet(
            ikm,
            contextId: "ingress-a",
            outputLen: 32,
            salt: salt
        )

        @Assert(keySet.httpRequestKey.size, 32)
        @Assert(keySet.httpResponseKey.size, 32)
        @Assert(keySet.sshClientToServerKey.size, 32)
        @Assert(keySet.sshServerToClientKey.size, 32)
        @Assert(keySet.httpRequestKey == keySet.httpResponseKey, false)
        @Assert(keySet.sshClientToServerKey == keySet.sshServerToClientKey, false)
        @Assert(keySet.httpRequestKey == keySet.sshClientToServerKey, false)
    }

    @TestCase
    public func testContractFacadeInfo(): Unit {
        let info = contractFacadeInfo()
        @Assert(info.apiVersion, CONTRACT_FACADE_API_VERSION)
        @Assert(info.stabilityLevel, "L1")
        @Assert(info.freezeDate, "2026-03-24")
        @Assert(info.stableDomains.size > 0, true)
        @Assert(containsString(info.stableDomains, "x509"), true)
        @Assert(containsString(info.stableDomains, "tls13"), true)
    }

    @TestCase
    public func testContractCapabilityInfo(): Unit {
        let info = contractCapabilityInfo()
        @Assert(containsString(info.stableDomains, "ssh"), true)
        @Assert(containsString(info.httpTlsFeatures, "tls13-x25519"), true)
        @Assert(containsString(info.httpTlsFeatures, "http-server-tls-config-validation"), true)
        @Assert(containsString(info.httpTlsFeatures, "http-server-tls-material-preparation"), true)
        @Assert(containsString(info.httpTlsFeatures, "http-client-tls-config-validation"), true)
        @Assert(containsString(info.httpTlsFeatures, "http-client-trust-material-preparation"), true)
        @Assert(containsString(info.sshFeatures, "ed25519-hostkey"), true)
        @Assert(containsString(info.sshFeatures, "session-runtime-snapshot-facade"), true)
        @Assert(containsString(info.x509Features, "hostname-policy"), true)
        @Assert(containsString(info.x509Features, "pem-bundle-normalization"), true)
        @Assert(containsString(info.x509Features, "http-client-peer-certificate-verify"), true)
        @Assert(info.directStdxTlsServerConfigBridge, false)
        @Assert(
            containsString(
                info.notes,
                "use contractValidateHttpServerTlsConfigInput before external TLS server config construction"
            ),
            true
        )
    }

    @TestCase
    public func testContractProviderCapabilityAndAttachBoundary(): Unit {
        let capability = contractProviderCapabilityRecord()
        @Assert(capability.providerId, "jinguissl")
        @Assert(capability.providerVersion, "0.6.21")
        @Assert(capability.supportsClientTls, true)
        @Assert(capability.supportsServerTlsAttach, false)
        @Assert(capability.supportsX509Verify, true)
        @Assert(capability.supportsAlpnH2, true)
        @Assert(capability.supportsMtls, false)
        @Assert(capability.supportsSessionCache, true)
        @Assert(capability.experimental, true)
        @Assert(capability.defaultEligible, false)
        @Assert(
            containsString(
                capability.unsupportedReasons,
                "stable server-side TLS attach contract is not exposed in this repo"
            ),
            true
        )

        let attach = contractProviderAttachContractInfo()
        @Assert(attach.providerId, "jinguissl")
        @Assert(attach.supportsTlsPrecheck, true)
        @Assert(attach.supportsServerTlsAttach, false)
        @Assert(containsString(attach.tlsPrecheckInputs, "serverName"), true)
        @Assert(containsString(attach.tlsAttachInputs, "handshakeTimeoutMs"), true)
        @Assert(containsString(attach.failureFields, "family"), true)
        @Assert(containsString(attach.failureFields, "fallbackSuggested"), true)

        let boundary = contractProviderServerAttachBoundary()
        @Assert(boundary.providerId, "jinguissl")
        @Assert(boundary.status.toString(), "PRECHECK_ONLY")
        @Assert(boundary.stableAttach, false)
        @Assert(boundary.recommendedFallback.contains("stdx"), true)
    }

    @TestCase
    public func testContractProviderSmokeFixtureCatalog(): Unit {
        let catalog = contractProviderSmokeFixtureCatalog()
        @Assert(catalog.size >= 9, true)

        var foundSuccess = false
        var foundPrecheck = false
        var foundVerify = false
        var foundHandshake = false
        var foundUnavailable = false
        var foundAttach = false
        var foundVerifyTrust = false
        var foundUnavailableGate = false
        for (fixture in catalog) {
            @Assert(fixture.providerId, "jinguissl")
            @Assert(fixture.artifacts.size > 0, true)
            @Assert(fixture.entrypoints.size > 0, true)
            if (fixture.fixtureId == "success-x509-policy-chain") {
                foundSuccess = true
                @Assert(fixture.category.toString(), "SUCCESS")
                match (fixture.expectedCode) {
                    case Some(_value) => @Fail("success fixture should not carry expected code")
                    case None => ()
                }
                match (fixture.expectedFamily) {
                    case Some(_value) => @Fail("success fixture should not carry expected family")
                    case None => ()
                }
            }
            if (fixture.fixtureId == "precheck-cert-key-mismatch") {
                foundPrecheck = true
                @Assert(fixture.category.toString(), "PRECHECK_FAIL")
                match (fixture.expectedPhase) {
                    case Some(value) => @Assert(value.toString(), "TLS_PRECHECK")
                    case None => @Fail("precheck fixture should carry expected phase")
                }
                match (fixture.expectedFamily) {
                    case Some(value) => @Assert(value.toString(), "TLS_PRECHECK_ERROR")
                    case None => @Fail("precheck fixture should carry expected family")
                }
            }
            if (
                fixture.fixtureId == "verify-hostname-mismatch" ||
                fixture.fixtureId == "verify-pin-mismatch" ||
                fixture.fixtureId == "verify-untrusted-chain"
            ) {
                foundVerify = true
                @Assert(fixture.category.toString(), "VERIFY_FAIL")
                match (fixture.expectedFamily) {
                    case Some(value) => @Assert(value.toString(), "TLS_VERIFY_ERROR")
                    case None => @Fail("verify fixture should carry expected family")
                }
                if (fixture.fixtureId == "verify-untrusted-chain") {
                    foundVerifyTrust = true
                }
            }
            if (fixture.fixtureId == "handshake-server-hello-decode") {
                foundHandshake = true
                @Assert(fixture.category.toString(), "HANDSHAKE_FAIL")
                match (fixture.expectedPhase) {
                    case Some(value) => @Assert(value.toString(), "TLS_HANDSHAKE")
                    case None => @Fail("handshake fixture should carry expected phase")
                }
                match (fixture.expectedFamily) {
                    case Some(value) => @Assert(value.toString(), "TLS_HANDSHAKE_ERROR")
                    case None => @Fail("handshake fixture should carry expected family")
                }
            }
            if (fixture.fixtureId == "attach-stable-listener-unpublished") {
                foundAttach = true
                @Assert(fixture.category.toString(), "HANDSHAKE_FAIL")
                match (fixture.expectedCode) {
                    case Some(value) => @Assert(value.toString(), "UNSUPPORTED")
                    case None => @Fail("attach fixture should carry expected code")
                }
                match (fixture.expectedPhase) {
                    case Some(value) => @Assert(value.toString(), "PROVIDER_RUNTIME")
                    case None => @Fail("attach fixture should carry expected phase")
                }
                match (fixture.expectedFamily) {
                    case Some(value) => @Assert(value.toString(), "UNSUPPORTED")
                    case None => @Fail("attach fixture should carry expected family")
                }
            }
            if (fixture.fixtureId == "provider-not-linked") {
                foundUnavailable = true
                @Assert(fixture.category.toString(), "PROVIDER_UNAVAILABLE")
                match (fixture.expectedCode) {
                    case Some(value) => @Assert(value.toString(), "CRYPTO_UNAVAILABLE")
                    case None => @Fail("provider unavailable fixture should carry expected code")
                }
                match (fixture.expectedFamily) {
                    case Some(value) => @Assert(value.toString(), "PROVIDER_UNAVAILABLE")
                    case None => @Fail("provider unavailable fixture should carry expected family")
                }
            }
            if (fixture.fixtureId == "provider-experimental-gated-off") {
                foundUnavailableGate = true
                @Assert(fixture.category.toString(), "PROVIDER_UNAVAILABLE")
                match (fixture.expectedPhase) {
                    case Some(value) => @Assert(value.toString(), "PROVIDER_SELECTION")
                    case None => @Fail("provider gated fixture should carry expected phase")
                }
                match (fixture.expectedFamily) {
                    case Some(value) => @Assert(value.toString(), "PROVIDER_UNAVAILABLE")
                    case None => @Fail("provider gated fixture should carry expected family")
                }
            }
        }
        @Assert(foundSuccess, true)
        @Assert(foundPrecheck, true)
        @Assert(foundVerify, true)
        @Assert(foundVerifyTrust, true)
        @Assert(foundHandshake, true)
        @Assert(foundAttach, true)
        @Assert(foundUnavailable, true)
        @Assert(foundUnavailableGate, true)

        let required = contractRequireProviderSmokeFixture("provider-not-linked")
        @Assert(required.fixtureId, "provider-not-linked")
        @Assert(required.category.toString(), "PROVIDER_UNAVAILABLE")

        try {
            _ = contractRequireProviderSmokeFixture("")
            @Fail("empty smoke fixture id should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }

        try {
            _ = contractRequireProviderSmokeFixture("missing-fixture")
            @Fail("unknown smoke fixture id should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testContractProviderSmokeBaselineReportFacade(): Unit {
        let success = contractDescribeProviderSmokeBaseline("success-x509-policy-chain")
        @Assert(success.providerId, "jinguissl")
        @Assert(success.executionMode.toString(), "VERIFY_PATH")
        @Assert(success.expectedSuccess, true)
        match (success.expectedDescriptor) {
            case Some(_value) =>
                @Fail("success baseline should not carry expected descriptor")
            case None => ()
        }
        match (success.expectedFallback) {
            case Some(_value) =>
                @Fail("success baseline should not carry expected fallback")
            case None => ()
        }

        let precheck = contractDescribeProviderSmokeBaselineRequest(
            ContractProviderSmokeBaselineRequest("precheck-cert-key-mismatch")
        )
        @Assert(precheck.executionMode.toString(), "PRECHECK_PATH")
        @Assert(precheck.expectedSuccess, false)
        match (precheck.expectedDescriptor) {
            case Some(value) =>
                @Assert(value.family.toString(), "TLS_PRECHECK_ERROR")
            case None =>
                @Fail("precheck baseline should carry expected descriptor")
        }
        match (precheck.expectedFallback) {
            case Some(value) =>
                @Assert(value.fallbackSuggested, false)
            case None =>
                @Fail("precheck baseline should carry fallback decision")
        }

        let handshake = contractDescribeProviderSmokeBaseline("handshake-server-hello-decode")
        @Assert(handshake.executionMode.toString(), "METADATA_ONLY")
        match (handshake.expectedDescriptor) {
            case Some(value) =>
                @Assert(value.family.toString(), "TLS_HANDSHAKE_ERROR")
            case None =>
                @Fail("handshake baseline should carry expected descriptor")
        }
        match (handshake.expectedFallback) {
            case Some(value) =>
                @Assert(value.fallbackSuggested, true)
                @Assert(value.fallbackTarget, "stdx")
            case None =>
                @Fail("handshake baseline should carry fallback decision")
        }
        @Assert(
            containsString(
                handshake.warnings,
                "this smoke baseline is modeled through provider error normalization metadata rather than a live network handshake"
            ),
            true
        )

        let unavailable = contractDescribeProviderSmokeBaseline("provider-not-linked")
        @Assert(unavailable.executionMode.toString(), "PROVIDER_SELECTION_PATH")
        match (unavailable.expectedDescriptor) {
            case Some(value) =>
                @Assert(value.family.toString(), "PROVIDER_UNAVAILABLE")
            case None =>
                @Fail("provider unavailable baseline should carry expected descriptor")
        }
        match (unavailable.expectedFallback) {
            case Some(value) =>
                @Assert(value.fallbackSuggested, true)
                @Assert(value.fallbackTarget, "stdx")
            case None =>
                @Fail("provider unavailable baseline should carry fallback decision")
        }

        let failed = contractTryDescribeProviderSmokeBaselineRequest(
            ContractProviderSmokeBaselineRequest("missing-fixture")
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) =>
                @Assert(value.toString(), "BAD_INPUT")
            case None =>
                @Fail("missing baseline outcome should carry contract code")
        }
        match (failed.igniteCode) {
            case Some(value) =>
                @Assert(value.toString(), "BAD_ENVELOPE")
            case None =>
                @Fail("missing baseline outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractProviderSmokeSuiteReportFacade(): Unit {
        let suite = contractDescribeProviderSmokeSuite()
        @Assert(suite.providerId, "jinguissl")
        @Assert(suite.totalFixtureCount >= 9, true)
        @Assert(suite.successFixtureCount, 1)
        @Assert(suite.failureFixtureCount, suite.totalFixtureCount - 1)
        @Assert(suite.precheckPathCount, 1)
        @Assert(suite.verifyPathCount, 4)
        @Assert(suite.providerSelectionPathCount, 2)
        @Assert(suite.metadataOnlyCount, 2)
        @Assert(suite.recommendedOrder[0], "success-x509-policy-chain")
        @Assert(
            containsString(
                suite.warnings,
                "metadata-only smoke baselines should be asserted through contract descriptors instead of being counted as live handshake regressions"
            ),
            true
        )

        let subset = contractDescribeProviderSmokeSuiteRequest(
            ContractProviderSmokeSuiteRequest(
                fixtureIds: [
                    "provider-not-linked",
                    "handshake-server-hello-decode"
                ]
            )
        )
        @Assert(subset.totalFixtureCount, 2)
        @Assert(subset.successFixtureCount, 0)
        @Assert(subset.failureFixtureCount, 2)
        @Assert(subset.providerSelectionPathCount, 1)
        @Assert(subset.metadataOnlyCount, 1)
        @Assert(subset.recommendedOrder, ["provider-not-linked", "handshake-server-hello-decode"])

        let failed = contractTryDescribeProviderSmokeSuiteRequest(
            ContractProviderSmokeSuiteRequest(
                fixtureIds: [
                    "provider-not-linked",
                    "missing-fixture"
                ]
            )
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) =>
                @Assert(value.toString(), "BAD_INPUT")
            case None =>
                @Fail("missing suite fixture should carry contract code")
        }
        match (failed.igniteCode) {
            case Some(value) =>
                @Assert(value.toString(), "BAD_ENVELOPE")
            case None =>
                @Fail("missing suite fixture should carry ignite code")
        }
    }

    @TestCase
    public func testContractProviderSmokeSelfCheckFacade(): Unit {
        let report = contractProviderSmokeSelfCheck()
        @Assert(report.overallReady, true)
        @Assert(report.supportsClientTls, true)
        @Assert(report.supportsX509Verify, true)
        @Assert(report.supportsTlsPrecheck, true)
        @Assert(report.hasSuccessBaseline, true)
        @Assert(report.hasPrecheckCoverage, true)
        @Assert(report.hasVerifyCoverage, true)
        @Assert(report.hasProviderSelectionCoverage, true)
        @Assert(report.hasHandshakeCoverage, true)
        @Assert(report.hasLiveHandshakeCoverage, false)
        @Assert(report.hasFallbackPlanCoverage, true)
        @Assert(report.stableServerAttach, false)
        @Assert(report.defaultEligible, false)
        @Assert(
            containsString(
                report.warnings,
                "provider smoke self-check handshake coverage is currently metadata-only; a stable live attach path is not published yet"
            ),
            true
        )

        let required = contractRequireProviderSmokeSelfCheck()
        @Assert(required.overallReady, true)

        let strictPolicy = ContractProviderSmokeSelfCheckPolicy(
            requireStableServerAttach: true
        )
        let strictReport = contractProviderSmokeSelfCheck(policy: strictPolicy)
        @Assert(strictReport.overallReady, false)
        @Assert(
            containsString(
                strictReport.warnings,
                "provider smoke self-check requires stable server attach coverage, but the public boundary remains precheck-only"
            ),
            true
        )

        let relaxedOutcome = contractTryProviderSmokeSelfCheck(policy: strictPolicy)
        @Assert(relaxedOutcome.ok, true)
        match (relaxedOutcome.result) {
            case Some(value) =>
                @Assert(value.overallReady, false)
            case None =>
                @Fail("provider smoke self-check outcome should carry report")
        }

        let strictOutcome = contractTryRequireProviderSmokeSelfCheck(policy: strictPolicy)
        @Assert(strictOutcome.ok, false)
        match (strictOutcome.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("strict provider smoke self-check should carry contract code")
        }
        match (strictOutcome.igniteCode) {
            case Some(value) =>
                @Assert(value.toString(), "CRYPTO_UNAVAILABLE")
            case None =>
                @Fail("strict provider smoke self-check should carry ignite code")
        }
        @Assert(strictOutcome.message.contains("stable server attach"), true)
    }

    @TestCase
    public func testContractProviderSmokeProfilesFacade(): Unit {
        let templates = contractListProviderSmokeProfiles()
        @Assert(templates.size, 5)

        let candidate = contractDescribeProviderSmokeProfile(
            ContractProviderSmokeProfile.ProviderCandidate
        )
        @Assert(candidate.label, "provider-candidate")
        @Assert(candidate.policy.requireStableServerAttach, false)
        @Assert(candidate.policy.requireDefaultEligible, false)
        @Assert(candidate.policy.requireLiveHandshakeCoverage, false)

        let planning = contractDescribeProviderSmokeProfile(
            ContractProviderSmokeProfile.AttachPlanning
        )
        @Assert(planning.label, "attach-planning")
        @Assert(planning.policy.requireProviderSelectionCoverage, false)
        @Assert(planning.policy.requireHandshakeCoverage, false)
        @Assert(planning.policy.requireFallbackPlan, true)

        let strict = contractDescribeProviderSmokeProfile(
            ContractProviderSmokeProfile.ProductionStrict
        )
        @Assert(strict.label, "production-strict")
        @Assert(strict.policy.requireStableServerAttach, true)
        @Assert(strict.policy.requireDefaultEligible, true)
        @Assert(strict.policy.requireLiveHandshakeCoverage, true)

        let required = contractRequireProviderSmokeProfile(
            ContractProviderSmokeProfile.ProviderCandidate
        )
        @Assert(required.overallReady, true)

        let strictOutcome = contractTryRequireProviderSmokeProfile(
            ContractProviderSmokeProfile.DefaultHttpsEligible
        )
        @Assert(strictOutcome.ok, false)
        match (strictOutcome.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("strict provider smoke profile should carry contract code")
        }
        match (strictOutcome.igniteCode) {
            case Some(value) =>
                @Assert(value.toString(), "CRYPTO_UNAVAILABLE")
            case None =>
                @Fail("strict provider smoke profile should carry ignite code")
        }
        @Assert(strictOutcome.message.contains("stable server attach"), true)

        let liveAttachOutcome = contractTryRequireProviderSmokeProfile(
            ContractProviderSmokeProfile.LiveAttachExperimental
        )
        @Assert(liveAttachOutcome.ok, false)
        @Assert(liveAttachOutcome.message.contains("stable server attach"), true)
    }

    @TestCase
    public func testContractProviderConsumptionPathGuidance(): Unit {
        let paths = contractListProviderConsumptionPaths()
        @Assert(paths.size, 5)

        let httpClient = contractDescribeProviderConsumptionPath(
            ContractProviderConsumptionPath.HttpClientTls
        )
        @Assert(httpClient.label, "http-client-tls")
        @Assert(httpClient.consumerKind, "provider-selection")
        @Assert(httpClient.attemptAllowed, true)
        @Assert(httpClient.useProviderSelection, true)
        @Assert(httpClient.requiresUpperLayerAttachGlue, false)
        @Assert(httpClient.publishedContractPath, true)
        @Assert(httpClient.suggestedFallbackTarget, "stdx-default")
        @Assert(httpClient.attachPlanMeaning.contains("buildTlsAttachPlan"), true)
        match (httpClient.suggestedSmokeProfile) {
            case Some(value) =>
                @Assert(value.toString(), "PROVIDER_CANDIDATE")
            case None =>
                @Fail("HTTP client path should suggest a provider smoke profile")
        }

        let httpPlanning = contractDescribeProviderConsumptionPath(
            ContractProviderConsumptionPath.HttpServerAttachPlanning
        )
        @Assert(httpPlanning.attemptAllowed, true)
        @Assert(httpPlanning.requiresUpperLayerAttachGlue, true)
        @Assert(httpPlanning.publishedContractPath, true)
        @Assert(httpPlanning.attachPlanMeaning.contains("planning metadata only"), true)
        match (httpPlanning.suggestedSmokeProfile) {
            case Some(value) =>
                @Assert(value.toString(), "ATTACH_PLANNING")
            case None =>
                @Fail("HTTP server planning path should suggest attach-planning profile")
        }

        let httpStable = contractDescribeProviderConsumptionPath(
            ContractProviderConsumptionPath.HttpServerStableAttach
        )
        @Assert(httpStable.attemptAllowed, false)
        @Assert(httpStable.publishedContractPath, false)
        @Assert(httpStable.attachPlanMeaning.contains("not a published jinguissl contract"), true)
        match (httpStable.suggestedSmokeProfile) {
            case Some(value) =>
                @Assert(value.toString(), "DEFAULT_HTTPS_ELIGIBLE")
            case None =>
                @Fail("HTTP stable attach path should suggest strict profile")
        }

        let sshClient = contractDescribeProviderConsumptionPath(
            ContractProviderConsumptionPath.SshClientLibrary
        )
        @Assert(sshClient.attemptAllowed, true)
        @Assert(sshClient.useProviderSelection, false)
        @Assert(sshClient.publishedContractPath, true)
        @Assert(sshClient.attachPlanMeaning.contains("does not apply to SSH client runtime"), true)
        match (sshClient.suggestedSmokeProfile) {
            case Some(_value) =>
                @Fail("SSH client path should not suggest a provider smoke profile")
            case None => ()
        }

        let sshServer = contractDescribeProviderConsumptionPath(
            ContractProviderConsumptionPath.SshServerLibrary
        )
        @Assert(sshServer.attemptAllowed, true)
        @Assert(sshServer.useProviderSelection, false)
        @Assert(sshServer.publishedContractPath, true)
        @Assert(sshServer.attachPlanMeaning.contains("does not apply to SSH server runtime"), true)
    }

    @TestCase
    public func testContractProviderFallbackOutcomeGuidance(): Unit {
        let guides = contractListProviderFallbackOutcomeGuides()
        @Assert(guides.size, 6)

        let unavailableGuide = contractDescribeProviderFallbackOutcomeGuide(
            ContractProviderFallbackCauseCode.ProviderUnavailable
        )
        @Assert(unavailableGuide.wireName, "provider_unavailable")
        @Assert(unavailableGuide.defaultOutcome.toString(), "SUGGESTED_ONLY")
        @Assert(unavailableGuide.stableDefaultOutcome.toString(), "NO_FALLBACK")
        @Assert(unavailableGuide.suggestedFallbackTarget, "stdx-default")

        let unavailableResolution = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.ProviderUnavailable
            )
        )
        @Assert(unavailableResolution.finalOutcome.toString(), "SUGGESTED_ONLY")
        @Assert(unavailableResolution.fallbackTarget, "stdx-default")

        let unavailableStableResolution = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.ProviderUnavailable,
                alreadyOnStableDefault: true
            )
        )
        @Assert(unavailableStableResolution.finalOutcome.toString(), "NO_FALLBACK")
        @Assert(unavailableStableResolution.fallbackTarget, "")

        let handshakeResolution = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.TlsHandshakeError,
                connectionConsumed: true
            )
        )
        @Assert(handshakeResolution.finalOutcome.toString(), "MANUAL_REVIEW")
        @Assert(handshakeResolution.fallbackTarget, "")

        let verifyResolution = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.TlsVerifyError
            )
        )
        @Assert(verifyResolution.finalOutcome.toString(), "NO_AUTO_FALLBACK")
        @Assert(verifyResolution.mustSurface, true)

        let precheckResolution = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.TlsPrecheckError
            )
        )
        @Assert(precheckResolution.finalOutcome.toString(), "NO_AUTO_FALLBACK")
        @Assert(precheckResolution.mustSurface, true)

        let cryptoStableResolution = contractResolveProviderFallbackOutcome(
            ContractProviderFallbackResolutionRequest(
                ContractProviderFallbackCauseCode.CryptoUnavailable,
                alreadyOnStableDefault: true
            )
        )
        @Assert(cryptoStableResolution.finalOutcome.toString(), "MANUAL_REVIEW")
    }

    @TestCase
    public func testContractProviderConsumptionGateFacade(): Unit {
        let gates = contractListProviderConsumptionGates()
        @Assert(gates.size, 5)

        let httpClient = contractDescribeProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpClientTls
        )
        @Assert(httpClient.status.toString(), "PROVIDER_CANDIDATE")
        @Assert(httpClient.providerId, "jinguissl")
        @Assert(httpClient.selectedEntryId, "jinguissl-provider-candidate")
        @Assert(httpClient.candidateOrder, ["jinguissl-provider-candidate", "stdx-default"])
        @Assert(httpClient.blockedCandidates.size, 0)
        @Assert(httpClient.publicPath, "provider-candidate")
        @Assert(httpClient.releasePath, "experimental-only")
        @Assert(httpClient.riskLevel, "medium")
        @Assert(httpClient.readyNow, true)
        @Assert(httpClient.fallbackTarget, "stdx-default")
        @Assert(httpClient.fallbackChain, ["stdx-default"])
        @Assert(httpClient.selectedReason.contains("provider-candidate route"), true)
        @Assert(containsString(httpClient.observabilityTags, "provider_id:jinguissl"), true)
        @Assert(
            containsString(httpClient.observabilityTags, "selected_entry:jinguissl-provider-candidate"),
            true
        )
        match (httpClient.smokeProfile) {
            case Some(value) =>
                @Assert(value.profile.toString(), "PROVIDER_CANDIDATE")
            case None =>
                @Fail("HTTP client provider gate should carry a smoke profile")
        }
        match (httpClient.smokeReadiness) {
            case Some(value) =>
                @Assert(value.overallReady, true)
            case None =>
                @Fail("HTTP client provider gate should carry a smoke readiness report")
        }

        let httpPlanning = contractDescribeProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpServerAttachPlanning
        )
        @Assert(httpPlanning.status.toString(), "PLANNING_ONLY")
        @Assert(httpPlanning.providerId, "jinguissl")
        @Assert(httpPlanning.selectedEntryId, "jinguissl-provider-candidate")
        @Assert(httpPlanning.candidateOrder, ["jinguissl-provider-candidate", "stdx-default"])
        @Assert(httpPlanning.blockedCandidates.size, 0)
        @Assert(httpPlanning.publicPath, "attach-planning")
        @Assert(httpPlanning.releasePath, "experimental-only")
        @Assert(httpPlanning.riskLevel, "medium")
        @Assert(httpPlanning.readyNow, true)
        @Assert(httpPlanning.selectedReason.contains("attach planning only"), true)
        @Assert(
            containsString(
                httpPlanning.warnings,
                "server attach still depends on upper-layer stdx integration glue"
            ),
            true
        )

        let httpStable = contractDescribeProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpServerStableAttach
        )
        @Assert(httpStable.status.toString(), "BLOCKED")
        @Assert(httpStable.providerId, "jinguissl")
        @Assert(httpStable.selectedEntryId, "")
        @Assert(httpStable.candidateOrder, ["jinguissl-provider-candidate", "stdx-default"])
        @Assert(httpStable.blockedCandidates, ["jinguissl-provider-candidate:stable_attach_unpublished"])
        @Assert(httpStable.publicPath, "blocked")
        @Assert(httpStable.releasePath, "unsupported")
        @Assert(httpStable.riskLevel, "high")
        @Assert(httpStable.readyNow, false)
        @Assert(httpStable.fallbackChain, ["stdx-default"])
        @Assert(httpStable.selectedReason.contains("stable HTTPS listener attach"), true)
        @Assert(containsString(httpStable.observabilityTags, "selected_entry:none"), true)
        @Assert(containsString(httpStable.observabilityTags, "ready_now:false"), true)
        match (httpStable.smokeProfile) {
            case Some(value) =>
                @Assert(value.profile.toString(), "DEFAULT_HTTPS_ELIGIBLE")
            case None =>
                @Fail("HTTP stable attach provider gate should carry a smoke profile")
        }
        match (httpStable.smokeReadiness) {
            case Some(value) =>
                @Assert(value.overallReady, false)
            case None =>
                @Fail("HTTP stable attach provider gate should carry a smoke readiness report")
        }

        let sshClient = contractDescribeProviderConsumptionGate(
            ContractProviderConsumptionPath.SshClientLibrary
        )
        @Assert(sshClient.status.toString(), "LIBRARY_CONTRACT")
        @Assert(sshClient.providerId, "jinguissl")
        @Assert(sshClient.selectedEntryId, "jinguissl-library-direct")
        @Assert(sshClient.candidateOrder, ["jinguissl-library-direct"])
        @Assert(sshClient.publicPath, "library-contract")
        @Assert(sshClient.releasePath, "library-direct")
        @Assert(sshClient.riskLevel, "low")
        @Assert(sshClient.readyNow, true)
        @Assert(sshClient.fallbackTarget, "")
        @Assert(sshClient.fallbackChain.size, 0)
        @Assert(containsString(sshClient.observabilityTags, "provider_entry:jinguissl-library-direct"), true)
        match (sshClient.smokeProfile) {
            case Some(_value) =>
                @Fail("SSH client provider gate should not require a smoke profile")
            case None => ()
        }
        @Assert(sshClient.selectedReason.contains("stable library contract"), true)

        let allowed = contractRequireProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpClientTls
        )
        @Assert(allowed.readyNow, true)

        let blocked = contractTryRequireProviderConsumptionGate(
            ContractProviderConsumptionPath.HttpServerStableAttach
        )
        @Assert(blocked.ok, false)
        match (blocked.code) {
            case Some(value) =>
                @Assert(value.toString(), "UNSUPPORTED")
            case None =>
                @Fail("blocked provider gate should carry contract code")
        }
        match (blocked.igniteCode) {
            case Some(value) =>
                @Assert(value.toString(), "CRYPTO_UNAVAILABLE")
            case None =>
                @Fail("blocked provider gate should carry ignite code")
        }
        @Assert(blocked.message.contains("stable HTTPS listener attach"), true)
    }

    @TestCase
    public func testContractIgniteCompatibilityFacade(): Unit {
        let key = incrementalBytes(32, start: 11)
        let plaintext = "ignite-contract-bridge".toArray()

        let keyRing = HashMap<String, Array<Byte>>()
        keyRing.add("bridge-k1", key)
        let legacyJson = contractEncryptEnvelopeJsonLegacyV1(
            ContractAeadAlgorithm.Aes256Gcm,
            "bridge-k1",
            key,
            plaintext
        )

        let parsed = contractParseEnvelopeJsonCompatV1(legacyJson)
        @Assert(parsed.ver, 1)
        @Assert(parsed.kid, "bridge-k1")
        let openedLegacy = contractDecryptEnvelopeJsonCompatV1(legacyJson, keyRing)
        @Assert(openedLegacy, plaintext)

        let keyU8 = toUInt8Array(key)
        let plainU8 = toUInt8Array(plaintext)
        let keyRingU8 = HashMap<String, Array<UInt8>>()
        keyRingU8.add("bridge-k2", keyU8)
        let modernJson = contractEncryptEnvelopeJsonV1UInt8(
            ContractAeadAlgorithm.Chacha20Poly1305,
            "bridge-k2",
            keyU8,
            plainU8
        )
        let openedModern = contractDecryptEnvelopeJsonV1UInt8(modernJson, keyRingU8)
        @Assert(openedModern, plainU8)
    }

    @TestCase
    public func testContractIgniteErrorMappingFacade(): Unit {
        @Assert(
            contractMapToIgniteCryptoErrorCode(ContractErrorCode.BadInput).toString(),
            "BAD_ENVELOPE"
        )
        @Assert(
            contractMapToIgniteCryptoErrorCode(ContractErrorCode.KeyNotFound).toString(),
            "KEY_NOT_FOUND"
        )
        @Assert(
            contractMapToIgniteCryptoErrorCode(ContractErrorCode.VerifyFailed).toString(),
            "DECRYPT_FAILED"
        )
        @Assert(
            contractMapToIgniteCryptoErrorCode(ContractErrorCode.CryptoUnavailable).toString(),
            "CRYPTO_UNAVAILABLE"
        )
        @Assert(
            contractMapToIgniteCryptoErrorCode(ContractErrorCode.ComplianceRejected).toString(),
            "CRYPTO_UNAVAILABLE"
        )
        @Assert(
            contractMapToIgniteCryptoErrorCode(ContractErrorCode.Unsupported).toString(),
            "CRYPTO_UNAVAILABLE"
        )
        @Assert(
            contractMapToIgniteCryptoErrorCode(ContractErrorCode.InternalError).toString(),
            "CRYPTO_UNAVAILABLE"
        )

        try {
            _ = contractRandomBytes(0)
            @Fail("invalid random size should fail")
        } catch (e: ContractException) {
            @Assert(
                contractMapExceptionToIgniteCryptoErrorCode(e).toString(),
                "BAD_ENVELOPE"
            )
        }

        let parseFailure = CryptoException(CryptoErrorCode.ParseError, "parse failed")
        @Assert(
            contractMapCryptoExceptionToErrorCode(parseFailure, operation: "x509").toString(),
            "VERIFY_FAILED"
        )
        @Assert(
            contractMapCryptoExceptionToIgniteCryptoErrorCode(parseFailure, operation: "x509").toString(),
            "DECRYPT_FAILED"
        )

        let verifyDescriptor = contractDescribeProviderErrorCode(
            ContractErrorCode.VerifyFailed,
            phase: ContractProviderErrorPhase.TlsVerify,
            detail: "certificate chain rejected"
        )
        @Assert(verifyDescriptor.family.toString(), "TLS_VERIFY_ERROR")
        @Assert(verifyDescriptor.retryable, false)
        @Assert(verifyDescriptor.fallbackSuggested, false)

        let unavailableDescriptor = contractDescribeProviderErrorCode(
            ContractErrorCode.CryptoUnavailable,
            phase: ContractProviderErrorPhase.ProviderSelection,
            detail: "provider not linked"
        )
        @Assert(unavailableDescriptor.family.toString(), "PROVIDER_UNAVAILABLE")
        @Assert(unavailableDescriptor.fallbackSuggested, true)

        let fallbackDecision = contractRecommendProviderFallback(unavailableDescriptor)
        @Assert(fallbackDecision.fallbackSuggested, true)
        @Assert(fallbackDecision.fallbackTarget, "stdx")
        @Assert(fallbackDecision.mustSurface, false)

        let handshakeDescriptor = contractDescribeProviderCryptoException(
            CryptoException(CryptoErrorCode.ParseError, "server hello decode failed"),
            phase: ContractProviderErrorPhase.TlsHandshake,
            operation: "tls"
        )
        @Assert(handshakeDescriptor.family.toString(), "TLS_HANDSHAKE_ERROR")
        @Assert(handshakeDescriptor.retryable, true)
        @Assert(handshakeDescriptor.fallbackSuggested, true)
    }

    @TestCase
    public func testContractEnvelopeTryOutcomeFacade(): Unit {
        let key = incrementalBytes(32, start: 201)
        let plaintext = "ignite-outcome-envelope".toArray()
        let keyRing = HashMap<String, Array<Byte>>()
        keyRing.add("outcome-k1", key)

        let envelopeJson = contractEncryptEnvelopeJsonV1(
            ContractAeadAlgorithm.Aes256Gcm,
            "outcome-k1",
            key,
            plaintext,
            aad: "ignite-aad".toArray()
        )

        let opened = contractTryDecryptEnvelopeJsonV1(envelopeJson, keyRing)
        @Assert(opened.ok, true)
        @Assert(opened.message, "OK")
        match (opened.code) {
            case Some(_) => @Fail("success envelope outcome should not carry contract code")
            case None => ()
        }
        match (opened.igniteCode) {
            case Some(_) => @Fail("success envelope outcome should not carry ignite code")
            case None => ()
        }
        match (opened.plaintext) {
            case Some(value) => @Assert(value, plaintext)
            case None => @Fail("success envelope outcome should carry plaintext")
        }

        let failed = contractTryDecryptEnvelopeJsonV1(
            envelopeJson,
            keyRing,
            aadOverride: Some("wrong-aad".toArray())
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "VERIFY_FAILED")
            case None => @Fail("failed envelope outcome should carry contract code")
        }
        match (failed.igniteCode) {
            case Some(value) => @Assert(value.toString(), "DECRYPT_FAILED")
            case None => @Fail("failed envelope outcome should carry ignite code")
        }
        match (failed.plaintext) {
            case Some(_) => @Fail("failed envelope outcome must not carry plaintext")
            case None => ()
        }
    }

    @TestCase
    public func testContractTls13TryOutcomeFacade(): Unit {
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let rootPem = readText("testdata/x509/policy_root.pem")
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")

        let clientHello = contractTls13BuildHttpClientHelloX25519(
            TEST_HOST_WWW,
            alpnProtocols: ["h2", "http/1.1"],
            clientPrivateKey: Some(incrementalBytes(32, start: 221))
        )
        let flight = contractTls13BuildHttpServerFlightX25519(
            clientHello.encodedClientHello,
            incrementalBytes(32, start: 229),
            "${leafPem}\n${intermediatePem}",
            leafKeyPem,
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )

        let verified = contractTryTls13VerifyHttpServerFlightX25519WithSession(
            clientHello,
            flight,
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_WWW,
            validationTime: "230101000000Z",
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )
        @Assert(verified.ok, true)
        match (verified.result) {
            case Some(value) =>
                @Assert(value.result.selectedAlpn, "h2")
            case None =>
                @Fail("TLS1.3 success outcome should carry verified session")
        }

        let failed = contractTryTls13VerifyHttpServerFlightX25519WithSession(
            clientHello,
            flight,
            rootPem,
            intermediatesPemBundle: intermediatePem,
            hostname: TEST_HOST_API,
            validationTime: "230101000000Z",
            policy: ContractTlsHttpNegotiationPolicy(
                requireServerName: true,
                allowedServerNames: [TEST_HOST_WWW],
                alpnPreference: ["h2", "http/1.1"]
            )
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "VERIFY_FAILED")
            case None => @Fail("TLS1.3 failed outcome should carry contract code")
        }
        match (failed.igniteCode) {
            case Some(value) => @Assert(value.toString(), "DECRYPT_FAILED")
            case None => @Fail("TLS1.3 failed outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractSshTryOutcomeFacade(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let transcript = SshKexExchangeTranscript(
            "SSH-2.0-contract-client-outcome\r\n".toArray(),
            "SSH-2.0-contract-server-outcome\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1660))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1700)))
        )
        let (encodedInit, _) = sshBuildKexEcdhInitX25519(clientPrivate)
        let negotiated = SshNegotiatedAlgorithms(
            "curve25519-sha256",
            "rsa-sha2-256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none"
        )
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(readText("testdata/x509/rsa_2048_pkcs8.pem"))
        let server = contractSshCompleteServerInitialHandshakeX25519Rsa(
            transcript,
            serverPrivate,
            encodedInit,
            rsaPrivateKey,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )

        let ok = contractTrySshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivate,
            encodedInit,
            server.encodedReply,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                expectedHostKeySha256: server.hostKeySha256,
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        @Assert(ok.ok, true)
        match (ok.result) {
            case Some(value) =>
                @Assert(value.requireHostVerification().hostSignatureVerified, true)
            case None =>
                @Fail("SSH success outcome should carry handshake result")
        }

        let failed = contractTrySshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivate,
            encodedInit,
            server.encodedReply,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                expectedHostKeySha256: incrementalBytes(32, start: 1900),
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        @Assert(failed.ok, false)
        match (failed.code) {
            case Some(value) => @Assert(value.toString(), "VERIFY_FAILED")
            case None => @Fail("SSH failed outcome should carry contract code")
        }
        match (failed.igniteCode) {
            case Some(value) => @Assert(value.toString(), "DECRYPT_FAILED")
            case None => @Fail("SSH failed outcome should carry ignite code")
        }

        let serverOk = contractTrySshCompleteServerInitialHandshakeX25519Rsa(
            transcript,
            serverPrivate,
            encodedInit,
            rsaPrivateKey,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        @Assert(serverOk.ok, true)
        match (serverOk.result) {
            case Some(value) =>
                @Assert(value.hostKeyAlgorithm, "ssh-rsa")
            case None =>
                @Fail("SSH server success outcome should carry handshake result")
        }

        let serverFailed = contractTrySshCompleteServerInitialHandshakeX25519Rsa(
            transcript,
            serverPrivate,
            [0],
            rsaPrivateKey,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        @Assert(serverFailed.ok, false)
        match (serverFailed.code) {
            case Some(value) => @Assert(value.toString(), "VERIFY_FAILED")
            case None => @Fail("SSH server failed outcome should carry contract code")
        }
        match (serverFailed.igniteCode) {
            case Some(value) => @Assert(value.toString(), "DECRYPT_FAILED")
            case None => @Fail("SSH server failed outcome should carry ignite code")
        }
    }

    @TestCase
    public func testContractSshHostVerificationFacadeModes(): Unit {
        let exchangeHash = incrementalBytes(32, start: 19)
        let serverHostKey = buildDummySshRsaHostKeyBlob()
        let hostSignature = buildDummySshHostSignatureBlob(
            "rsa-sha2-256",
            incrementalBytes(64, start: 81)
        )
        let requiredRequest = ContractSshVerifyHostIdentityRequest(
            exchangeHash,
            serverHostKey,
            hostSignature,
            policy: ContractSshHostVerificationPolicy(
                expectedHostKeySha256: contractSshComputeHostKeySha256(serverHostKey),
                requireKnownHost: true,
                requireHostSignature: false,
                requireVerifiedHost: true
            )
        )

        let knownFingerprint = contractSshComputeHostKeySha256(serverHostKey)
        let knownHostPolicy = ContractSshHostVerificationPolicy(
            expectedHostKeySha256: knownFingerprint,
            requireKnownHost: true,
            requireHostSignature: false,
            requireVerifiedHost: true
        )
        let knownHostResult = contractSshVerifyHostIdentityRequired(
            exchangeHash,
            serverHostKey,
            hostSignature,
            policy: knownHostPolicy
        )
        @Assert(knownHostResult.hostKeyAlgorithm, "ssh-rsa")
        @Assert(knownHostResult.hostSignatureAlgorithm, "rsa-sha2-256")
        @Assert(knownHostResult.hostSignatureVerified, false)
        @Assert(knownHostResult.hostKeySha256, knownFingerprint)
        let knownHostByRequest = contractSshVerifyHostIdentityRequiredRequest(requiredRequest)
        @Assert(knownHostByRequest.hostKeyAlgorithm, "ssh-rsa")
        let knownHostOutcome = contractTrySshVerifyHostIdentityRequiredRequest(requiredRequest)
        @Assert(knownHostOutcome.ok, true)
        match (knownHostOutcome.result) {
            case Some(value) => @Assert(value.hostKeySha256, knownFingerprint)
            case None => @Fail("SSH host verification request outcome should carry result")
        }

        let strictPolicy = ContractSshHostVerificationPolicy(
            requireHostSignature: true,
            requireVerifiedHost: true
        )
        try {
            _ = contractSshVerifyHostIdentity(
                exchangeHash,
                serverHostKey,
                hostSignature,
                policy: strictPolicy
            )
            @Fail("strict SSH host verification should fail on invalid signature")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }

        let optionalPolicy = ContractSshHostVerificationPolicy(
            requireHostSignature: true,
            requireVerifiedHost: false
        )
        let optionalResult = contractSshVerifyHostIdentityRequest(
            ContractSshVerifyHostIdentityRequest(
                exchangeHash,
                serverHostKey,
                hostSignature,
                policy: optionalPolicy
            )
        )
        match (optionalResult) {
            case Some(_value) =>
                @Fail("optional SSH host verification should return None on invalid signature")
            case None =>
                ()
        }

        let unsupportedSignature = buildDummySshHostSignatureBlob(
            "ssh-dss",
            incrementalBytes(40, start: 241)
        )
        try {
            _ = contractSshVerifyHostIdentityRequired(
                exchangeHash,
                serverHostKey,
                unsupportedSignature,
                policy: ContractSshHostVerificationPolicy(
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
            @Fail("unsupported SSH host signature algorithm should surface as Unsupported")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }

        let optionalUnsupported = contractSshVerifyHostIdentity(
            exchangeHash,
            serverHostKey,
            unsupportedSignature,
            policy: ContractSshHostVerificationPolicy(
                requireHostSignature: true,
                requireVerifiedHost: false
            )
        )
        match (optionalUnsupported) {
            case Some(_value) =>
                @Fail("optional SSH host verification should return None on unsupported algorithms")
            case None =>
                ()
        }

        let unsupportedOutcome = contractTrySshVerifyHostIdentityRequiredRequest(
            ContractSshVerifyHostIdentityRequest(
                exchangeHash,
                serverHostKey,
                unsupportedSignature,
                policy: ContractSshHostVerificationPolicy(
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )
        @Assert(unsupportedOutcome.ok, false)
        match (unsupportedOutcome.code) {
            case Some(value) => @Assert(value.toString(), "UNSUPPORTED")
            case None => @Fail("unsupported SSH host verification outcome should carry contract code")
        }
        match (unsupportedOutcome.igniteCode) {
            case Some(value) => @Assert(value.toString(), "CRYPTO_UNAVAILABLE")
            case None => @Fail("unsupported SSH host verification outcome should carry ignite code")
        }

        let ecdsaPrivateKey = EcPrivateKey(NamedCurve.P256, BigNum.one())
        let invalidCurveHostKey = contractSshEncodeEcdsaHostPublicKey(ecPublicFromPrivateKey(ecdsaPrivateKey))
        let invalidCurveName = "nistp999".toArray()
        var invalidCurveOffset = 4 + "ecdsa-sha2-nistp256".size + 4
        var invalidCurveIndex = 0
        while (invalidCurveIndex < invalidCurveName.size) {
            invalidCurveHostKey[invalidCurveOffset + invalidCurveIndex] = invalidCurveName[invalidCurveIndex]
            invalidCurveIndex += 1
        }
        let ecdsaSignature = contractSshSignExchangeHashEcdsa(ecdsaPrivateKey, exchangeHash)
        try {
            _ = contractSshVerifyHostIdentityRequired(
                exchangeHash,
                invalidCurveHostKey,
                ecdsaSignature,
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "ecdsa-sha2-nistp256",
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
            @Fail("unsupported SSH ECDSA host key curve should surface as Unsupported")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }
    }

    @TestCase
    public func testContractSshHostVerificationErrorConsistencyAcrossAlgorithms(): Unit {
        let exchangeHash = incrementalBytes(32, start: 33)
        let serverHostKey = buildDummySshRsaHostKeyBlob()

        assertSshHostVerificationVerifyFailed(
            exchangeHash,
            serverHostKey,
            buildDummySshHostSignatureBlob("rsa-sha2-256", incrementalBytes(64, start: 101))
        )
        assertSshHostVerificationVerifyFailed(
            exchangeHash,
            serverHostKey,
            buildDummySshHostSignatureBlob("rsa-sha2-512", incrementalBytes(64, start: 141))
        )
        assertSshHostVerificationVerifyFailed(
            exchangeHash,
            serverHostKey,
            buildDummySshHostSignatureBlob("ecdsa-sha2-nistp256", incrementalBytes(64, start: 181))
        )
        assertSshHostVerificationVerifyFailed(
            exchangeHash,
            serverHostKey,
            buildDummySshHostSignatureBlob("ssh-ed25519", incrementalBytes(64, start: 221))
        )
    }

    @TestCase
    public func testContractSshHostSigningFacadeHelpers(): Unit {
        let exchangeHash = sha256("contract-ssh-host-signing".toArray())

        let rsaPrivateKeyPem = readText("testdata/x509/rsa_2048_pkcs8.pem")
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(rsaPrivateKeyPem)
        let rsaHostKeyBlob = contractSshEncodeRsaHostPublicKey(rsaPrivateKey.publicKey)
        let rsaSignature = contractSshSignExchangeHashRsa(rsaPrivateKey, exchangeHash)
        let rsaVerified = contractSshVerifyHostIdentityRequired(
            exchangeHash,
            rsaHostKeyBlob,
            rsaSignature,
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        @Assert(rsaVerified.hostKeyAlgorithm, "ssh-rsa")
        @Assert(rsaVerified.hostSignatureAlgorithm, "rsa-sha2-256")
        @Assert(rsaVerified.hostSignatureVerified, true)

        let ecPrivateKey = EcPrivateKey(NamedCurve.P256, BigNum.one())
        let ecHostKeyBlob = contractSshEncodeEcdsaHostPublicKey(ecPublicFromPrivateKey(ecPrivateKey))
        let ecSignature = contractSshSignExchangeHashEcdsa(ecPrivateKey, exchangeHash)
        let ecVerified = contractSshVerifyHostIdentityRequired(
            exchangeHash,
            ecHostKeyBlob,
            ecSignature,
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "ecdsa-sha2-nistp256",
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        @Assert(ecVerified.hostKeyAlgorithm, "ecdsa-sha2-nistp256")
        @Assert(ecVerified.hostSignatureAlgorithm, "ecdsa-sha2-nistp256")
        @Assert(ecVerified.hostSignatureVerified, true)

        let ed25519Seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let ed25519HostKeyBlob = contractSshBuildEd25519HostKeyBlobFromSeed(ed25519Seed)
        let ed25519Signature = contractSshSignExchangeHashEd25519(ed25519Seed, exchangeHash)
        let ed25519Verified = contractSshVerifyHostIdentityRequired(
            exchangeHash,
            ed25519HostKeyBlob,
            ed25519Signature,
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "ssh-ed25519",
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        @Assert(ed25519Verified.hostKeyAlgorithm, "ssh-ed25519")
        @Assert(ed25519Verified.hostSignatureAlgorithm, "ssh-ed25519")
        @Assert(ed25519Verified.hostSignatureVerified, true)
    }

    @TestCase
    public func testContractSshHostSigningMaterialFacade(): Unit {
        let exchangeHash = sha256("contract-ssh-host-signing-material".toArray())

        let rsaPrivateKeyPem = readText("testdata/x509/rsa_2048_pkcs8.pem")
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(rsaPrivateKeyPem)
        let rsaResult = contractPrepareSshHostSigningRsa(rsaPrivateKey, exchangeHash)
        @Assert(rsaResult.hostKeyAlgorithm, "ssh-rsa")
        @Assert(rsaResult.hostSignatureAlgorithm, "rsa-sha2-256")
        @Assert(rsaResult.hostKeySha256, contractSshComputeHostKeySha256(rsaResult.serverHostKey))

        let rsaOutcome = contractTryPrepareSshHostSigningRsa(rsaPrivateKey, exchangeHash)
        @Assert(rsaOutcome.ok, true)
        match (rsaOutcome.result) {
            case Some(value) =>
                @Assert(value.hostKeyAlgorithm, "ssh-rsa")
            case None =>
                @Fail("RSA host signing outcome should carry result")
        }

        let rsaRequestResult = contractPrepareSshHostSigningRsaPkcs8Request(
            ContractSshHostSigningRsaPkcs8Request(rsaPrivateKeyPem, exchangeHash)
        )
        @Assert(rsaRequestResult.hostKeyAlgorithm, "ssh-rsa")
        let rsaRequestOutcome = contractTryPrepareSshHostSigningRsaPkcs8Request(
            ContractSshHostSigningRsaPkcs8Request("bad pem", exchangeHash)
        )
        @Assert(rsaRequestOutcome.ok, false)
        match (rsaRequestOutcome.code) {
            case Some(value) =>
                @Assert(value.toString(), "VERIFY_FAILED")
            case None =>
                @Fail("RSA host signing request outcome should carry contract code")
        }

        let ecdsaPrivateKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")
        let ecdsaPrivateKey = x509ParseEcPrivateKeyPkcs8Pem(ecdsaPrivateKeyPem)
        let ecdsaResult = contractPrepareSshHostSigningEcdsa(ecdsaPrivateKey, exchangeHash)
        @Assert(ecdsaResult.hostKeyAlgorithm, "ecdsa-sha2-nistp256")
        @Assert(ecdsaResult.hostSignatureAlgorithm, "ecdsa-sha2-nistp256")
        @Assert(ecdsaResult.hostKeySha256, contractSshComputeHostKeySha256(ecdsaResult.serverHostKey))

        let ecdsaOutcome = contractTryPrepareSshHostSigningEcdsa(ecdsaPrivateKey, exchangeHash)
        @Assert(ecdsaOutcome.ok, true)
        match (ecdsaOutcome.result) {
            case Some(value) =>
                @Assert(value.hostKeyAlgorithm, "ecdsa-sha2-nistp256")
            case None =>
                @Fail("ECDSA host signing outcome should carry result")
        }

        let ecdsaRequestResult = contractPrepareSshHostSigningEcdsaPkcs8Request(
            ContractSshHostSigningEcdsaPkcs8Request(ecdsaPrivateKeyPem, exchangeHash)
        )
        @Assert(ecdsaRequestResult.hostKeyAlgorithm, "ecdsa-sha2-nistp256")

        let ed25519Seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let ed25519Result = contractPrepareSshHostSigningEd25519(ed25519Seed, exchangeHash)
        @Assert(ed25519Result.hostKeyAlgorithm, "ssh-ed25519")
        @Assert(ed25519Result.hostSignatureAlgorithm, "ssh-ed25519")
        @Assert(ed25519Result.hostKeySha256, contractSshComputeHostKeySha256(ed25519Result.serverHostKey))

        let ed25519Outcome = contractTryPrepareSshHostSigningEd25519(ed25519Seed, exchangeHash)
        @Assert(ed25519Outcome.ok, true)
        match (ed25519Outcome.result) {
            case Some(value) =>
                @Assert(value.hostKeyAlgorithm, "ssh-ed25519")
            case None =>
                @Fail("Ed25519 host signing outcome should carry result")
        }

        let ed25519RequestResult = contractPrepareSshHostSigningEd25519SeedRequest(
            ContractSshHostSigningEd25519SeedRequest(ed25519Seed, exchangeHash)
        )
        @Assert(ed25519RequestResult.hostKeyAlgorithm, "ssh-ed25519")
    }

    @TestCase
    public func testContractSshVersionBannerAndTransportPacketFacadeHelpers(): Unit {
        let banner = contractSshBuildVersionBannerRequest(
            ContractSshBuildVersionBannerRequest(
                "jinkuiSSL_0.6.21",
                comments: "contract-test"
            )
        )
        let serverBanner = contractSshBuildVersionBanner("OpenSSH_9.8", comments: "server")
        let encodedBanner = contractSshEncodeVersionBannerRequest(
            ContractSshEncodeVersionBannerRequest(banner)
        )
        let decodedBanner = contractSshDecodeVersionBannerRequest(
            ContractSshDecodeVersionBannerRequest(encodedBanner)
        )

        @Assert(decodedBanner.protocolVersion, "2.0")
        @Assert(decodedBanner.softwareVersion, "jinkuiSSL_0.6.21")
        @Assert(decodedBanner.comments, "contract-test")
        @Assert(
            String.fromUtf8(encodedBanner),
            "SSH-2.0-jinkuiSSL_0.6.21 contract-test\r\n"
        )

        let payload = "abc".toArray()
        let randomPadding = incrementalBytes(4, start: 1456)
        let encodedPacket = contractSshEncodeTransportPacketRequest(
            ContractSshEncodeTransportPacketRequest(
                payload,
                blockSize: 8,
                randomPadding: randomPadding
            )
        )
        let decodedPacket = contractSshDecodeTransportPacketRequest(
            ContractSshDecodeTransportPacketRequest(encodedPacket, blockSize: 8)
        )

        @Assert(decodedPacket.packetLength, 8)
        @Assert(decodedPacket.payload, payload)
        @Assert(decodedPacket.padding, randomPadding)

        let clientKexInit = contractSshBuildDefaultKexInitRequest(
            ContractSshBuildDefaultKexInitRequest(cookie: incrementalBytes(16, start: 1504))
        )
        let serverKexInit = contractSshBuildDefaultKexInitRequest(
            ContractSshBuildDefaultKexInitRequest(cookie: incrementalBytes(16, start: 1520))
        )
        let transcript = contractSshBuildKexExchangeTranscriptFromPreludeRequest(
            ContractSshBuildTranscriptFromPreludeRequest(
                banner,
                serverBanner,
                clientKexInit,
                serverKexInit
            )
        )

        @Assert(transcript.clientBannerLine, encodedBanner)
        @Assert(
            transcript.serverBannerLine,
            contractSshEncodeVersionBanner(serverBanner)
        )
        @Assert(
            transcript.clientKexInitPayload,
            contractSshEncodeKexInit(clientKexInit)
        )
        @Assert(
            transcript.serverKexInitPayload,
            contractSshEncodeKexInit(serverKexInit)
        )
    }

    @TestCase
    public func testContractSshKexInitNegotiationFacadeHelpers(): Unit {
        let chachaCipher = SSH_CIPHER_CHACHA20_POLY1305_OPENSSH
        let clientMessage = ContractSshKexInitMessage(
            incrementalBytes(16, start: 1400),
            ["curve25519-sha256", "ecdh-sha2-nistp256"],
            ["rsa-sha2-256", "ssh-ed25519"],
            ["aes128-ctr", chachaCipher],
            ["aes128-ctr", chachaCipher],
            ["hmac-sha2-256"],
            ["hmac-sha2-256"],
            ["none"],
            ["none"]
        )
        let serverMessage = contractSshBuildDefaultKexInitRequest(
            ContractSshBuildDefaultKexInitRequest(cookie: incrementalBytes(16, start: 1432))
        )
        let encodedClient = contractSshEncodeKexInitRequest(ContractSshEncodeKexInitRequest(clientMessage))
        let decodedClient = contractSshDecodeKexInitRequest(ContractSshDecodeKexInitRequest(encodedClient))
        let negotiated = contractSshNegotiateKexInitRequest(
            ContractSshNegotiateKexInitRequest(decodedClient, serverMessage)
        )
        let transcript = contractSshBuildKexExchangeTranscriptRequest(
            ContractSshBuildTranscriptFromKexInitRequest(
                "SSH-2.0-contract-client-kexinit\r\n".toArray(),
                "SSH-2.0-contract-server-kexinit\r\n".toArray(),
                decodedClient,
                serverMessage
            )
        )

        @Assert(decodedClient.cookie, clientMessage.cookie)
        @Assert(decodedClient.kexAlgorithms, clientMessage.kexAlgorithms)
        @Assert(negotiated.kexAlgorithm, "curve25519-sha256")
        @Assert(negotiated.serverHostKeyAlgorithm, "ssh-ed25519")
        @Assert(negotiated.macAlgorithmClientToServer, "hmac-sha2-256")
        @Assert(transcript.clientKexInitPayload, encodedClient)
        @Assert(
            transcript.serverKexInitPayload,
            contractSshEncodeKexInit(serverMessage)
        )
    }

    @TestCase
    public func testContractSshKexEcdhCodecFacadeHelpers(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let clientPublic = x25519PublicFromPrivate(clientPrivate)
        let serverPublic = x25519PublicFromPrivate(serverPrivate)

        let initMessage = ContractSshKexEcdhInitMessage(clientPublic)
        let encodedInit = contractSshEncodeKexEcdhInitRequest(
            ContractSshEncodeKexEcdhInitRequest(initMessage)
        )
        let decodedInit = contractSshDecodeKexEcdhInitRequest(
            ContractSshDecodeKexEcdhInitRequest(encodedInit)
        )
        @Assert(decodedInit.clientEphemeralPublicKey, clientPublic)

        let replyMessage = ContractSshKexEcdhReplyMessage(
            "server-host-key".toArray(),
            serverPublic,
            "signature-blob".toArray()
        )
        let encodedReply = contractSshEncodeKexEcdhReplyRequest(
            ContractSshEncodeKexEcdhReplyRequest(replyMessage)
        )
        let decodedReply = contractSshDecodeKexEcdhReplyRequest(
            ContractSshDecodeKexEcdhReplyRequest(encodedReply)
        )
        @Assert(decodedReply.serverHostKey, "server-host-key".toArray())
        @Assert(decodedReply.serverEphemeralPublicKey, serverPublic)
        @Assert(decodedReply.signature, "signature-blob".toArray())

        let encodedNewKeys = contractSshEncodeNewKeysRequest(ContractSshEncodeNewKeysRequest())
        @Assert(encodedNewKeys, sshEncodeNewKeys())
        contractSshDecodeNewKeysRequest(ContractSshDecodeNewKeysRequest(encodedNewKeys))

        try {
            contractSshDecodeNewKeys([UInt8(1), UInt8(2)])
            @Fail("invalid NEWKEYS payload should fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testContractSshRequestStyleHandshakeAndKexHelpers(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let clientKexInit = contractSshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1600))
        let serverKexInit = contractSshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1632))
        let transcript = contractSshBuildKexExchangeTranscript(
            "SSH-2.0-contract-client-request\r\n".toArray(),
            "SSH-2.0-contract-server-request\r\n".toArray(),
            clientKexInit,
            serverKexInit
        )
        let negotiated = contractSshNegotiateKexInit(clientKexInit, serverKexInit)
        let initResult = contractSshBuildKexEcdhInitX25519Request(
            ContractSshBuildKexEcdhInitX25519Request(clientPrivate)
        )
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(readText("testdata/x509/rsa_2048_pkcs8.pem"))
        let serverHandshake = contractSshCompleteServerInitialHandshakeX25519RsaRequest(
            ContractSshServerInitialHandshakeX25519RsaRequest(
                transcript,
                serverPrivate,
                initResult.encodedInit,
                rsaPrivateKey,
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys()
            )
        )
        let lowLevelServer = contractSshServerProcessKexEcdhInitX25519Request(
            ContractSshServerProcessKexEcdhInitX25519Request(
                transcript,
                serverPrivate,
                initResult.encodedInit,
                ContractSshHostSigningResult(
                    serverHandshake.serverHostKey,
                    serverHandshake.hostSignature,
                    serverHandshake.hostKeyAlgorithm,
                    serverHandshake.hostSignatureAlgorithm,
                    serverHandshake.hostKeySha256
                )
            )
        )
        let clientKexSession = contractSshClientProcessKexEcdhReplyX25519Request(
            ContractSshClientProcessKexEcdhReplyX25519Request(
                transcript,
                clientPrivate,
                initResult.encodedInit,
                lowLevelServer.encodedReply,
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: serverHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )
        let clientHandshake = contractSshCompleteClientInitialHandshakeX25519Request(
            ContractSshClientInitialHandshakeX25519Request(
                transcript,
                clientPrivate,
                initResult.encodedInit,
                serverHandshake.encodedReply,
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: serverHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )

        @Assert(lowLevelServer.encodedReply, serverHandshake.encodedReply)
        @Assert(lowLevelServer.session.sharedSecret, serverHandshake.sharedSecret)
        @Assert(lowLevelServer.session.exchangeHash, serverHandshake.exchangeHash)
        @Assert(clientKexSession.sharedSecret, serverHandshake.sharedSecret)
        @Assert(clientKexSession.exchangeHash, serverHandshake.exchangeHash)
        @Assert(clientKexSession.hostKeySha256, serverHandshake.hostKeySha256)
        @Assert(clientHandshake.sharedSecret, clientKexSession.sharedSecret)
        @Assert(clientHandshake.exchangeHash, clientKexSession.exchangeHash)
        @Assert(clientHandshake.requireHostVerification().hostSignatureVerified, true)
        @Assert(clientKexSession.requireHostVerification().hostSignatureVerified, true)
    }

    @TestCase
    public func testContractSshServerInitialHandshakeFacadeHelpers(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let transcript = SshKexExchangeTranscript(
            "SSH-2.0-contract-client\r\n".toArray(),
            "SSH-2.0-contract-server\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1500))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1540)))
        )
        let (encodedInit, _) = sshBuildKexEcdhInitX25519(clientPrivate)
        let negotiated = SshNegotiatedAlgorithms(
            "curve25519-sha256",
            "rsa-sha2-256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none"
        )

        let rsaPrivateKeyPem = readText("testdata/x509/rsa_2048_pkcs8.pem")
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(rsaPrivateKeyPem)
        let rsaServer = contractSshCompleteServerInitialHandshakeX25519Rsa(
            transcript,
            serverPrivate,
            encodedInit,
            rsaPrivateKey,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        @Assert(rsaServer.hostKeyAlgorithm, "ssh-rsa")
        @Assert(rsaServer.hostSignatureAlgorithm, "rsa-sha2-256")
        @Assert(rsaServer.hostKeySha256, contractSshComputeHostKeySha256(rsaServer.serverHostKey))

        let rsaClient = sshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivate,
            encodedInit,
            rsaServer.encodedReply,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        @Assert(rsaClient.kexResult.exchangeHash, rsaServer.exchangeHash)
        @Assert(rsaClient.kexResult.sessionId, rsaServer.sessionId)

        let ed25519Seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let ed25519Server = contractSshCompleteServerInitialHandshakeX25519Ed25519(
            transcript,
            serverPrivate,
            encodedInit,
            ed25519Seed,
            SshNegotiatedAlgorithms(
                "curve25519-sha256",
                "ssh-ed25519",
                "aes128-ctr",
                "aes128-ctr",
                "hmac-sha2-256",
                "hmac-sha2-256",
                "none",
                "none"
            ),
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        @Assert(ed25519Server.hostKeyAlgorithm, "ssh-ed25519")
        @Assert(ed25519Server.hostSignatureAlgorithm, "ssh-ed25519")

        let ed25519Client = sshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivate,
            encodedInit,
            ed25519Server.encodedReply,
            SshNegotiatedAlgorithms(
                "curve25519-sha256",
                "ssh-ed25519",
                "aes128-ctr",
                "aes128-ctr",
                "hmac-sha2-256",
                "hmac-sha2-256",
                "none",
                "none"
            ),
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        @Assert(ed25519Client.kexResult.exchangeHash, ed25519Server.exchangeHash)
        @Assert(ed25519Client.kexResult.sessionId, ed25519Server.sessionId)
    }

    @TestCase
    public func testContractSshClientInitialHandshakeFacadeModes(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let transcript = SshKexExchangeTranscript(
            "SSH-2.0-contract-client-verify\r\n".toArray(),
            "SSH-2.0-contract-server-verify\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1580))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1620)))
        )
        let (encodedInit, _) = sshBuildKexEcdhInitX25519(clientPrivate)
        let rsaNegotiated = SshNegotiatedAlgorithms(
            "curve25519-sha256",
            "rsa-sha2-256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none"
        )
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(readText("testdata/x509/rsa_2048_pkcs8.pem"))
        let rsaServer = contractSshCompleteServerInitialHandshakeX25519Rsa(
            transcript,
            serverPrivate,
            encodedInit,
            rsaPrivateKey,
            rsaNegotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        let rsaClient = contractSshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivate,
            encodedInit,
            rsaServer.encodedReply,
            rsaNegotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                expectedHostKeySha256: rsaServer.hostKeySha256,
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        @Assert(rsaClient.exchangeHash, rsaServer.exchangeHash)
        @Assert(rsaClient.sessionId, rsaServer.sessionId)
        @Assert(rsaClient.hostKeyAlgorithm, "ssh-rsa")
        @Assert(rsaClient.hostSignatureAlgorithm, "rsa-sha2-256")
        @Assert(rsaClient.requireHostVerification().hostSignatureVerified, true)
        let clientTransport = rsaClient.transport()
        let serverTransport = rsaServer.transport()
        @Assert(clientTransport.sessionId(), rsaClient.sessionId)
        let clientPacket = clientTransport.seal(
            "contract-client->server".toArray(),
            randomPadding: incrementalBytes(64, start: 1720)
        )
        let serverOpened = serverTransport.open(clientPacket)
        @Assert(serverOpened.payload, "contract-client->server".toArray())
        @Assert(clientTransport.writeSequence, 1)
        @Assert(serverTransport.readSequence, 1)
        let serverPacket = serverTransport.seal(
            "contract-server->client".toArray(),
            randomPadding: incrementalBytes(64, start: 1784)
        )
        let clientOpened = clientTransport.open(serverPacket)
        @Assert(clientOpened.payload, "contract-server->client".toArray())

        let rsaOptional = contractSshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivate,
            encodedInit,
            rsaServer.encodedReply,
            rsaNegotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                expectedHostKeySha256: incrementalBytes(32, start: 1700),
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: false
            )
        )
        match (rsaOptional.hostVerification) {
            case Some(_) => @Fail("optional SSH client facade should return None when host verification is not required")
            case None => ()
        }

        let ecdsaNegotiated = SshNegotiatedAlgorithms(
            "curve25519-sha256",
            "ecdsa-sha2-nistp256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none"
        )
        let ecdsaPrivateKey = x509ParseEcPrivateKeyPkcs8Pem(readText("testdata/x509/policy_leaf_key_pkcs8.pem"))
        let ecdsaServer = contractSshCompleteServerInitialHandshakeX25519Ecdsa(
            transcript,
            serverPrivate,
            encodedInit,
            ecdsaPrivateKey,
            ecdsaNegotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        let ecdsaClient = contractSshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivate,
            encodedInit,
            ecdsaServer.encodedReply,
            ecdsaNegotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "ecdsa-sha2-nistp256",
                expectedHostKeySha256: ecdsaServer.hostKeySha256,
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        @Assert(ecdsaClient.exchangeHash, ecdsaServer.exchangeHash)
        @Assert(ecdsaClient.hostKeyAlgorithm, "ecdsa-sha2-nistp256")
        @Assert(ecdsaClient.requireHostVerification().hostKeyAlgorithm, "ecdsa-sha2-nistp256")
    }

    @TestCase
    public func testContractSshRuntimeFacadeHelpers(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let transcript = SshKexExchangeTranscript(
            "SSH-2.0-contract-client-runtime\r\n".toArray(),
            "SSH-2.0-contract-server-runtime\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1660))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1700)))
        )
        let (encodedInit, _) = sshBuildKexEcdhInitX25519(clientPrivate)
        let negotiated = SshNegotiatedAlgorithms(
            "curve25519-sha256",
            "rsa-sha2-256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none"
        )
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(readText("testdata/x509/rsa_2048_pkcs8.pem"))
        let serverHandshake = contractSshCompleteServerInitialHandshakeX25519Rsa(
            transcript,
            serverPrivate,
            encodedInit,
            rsaPrivateKey,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        let clientHandshake = contractSshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivate,
            encodedInit,
            serverHandshake.encodedReply,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                expectedHostKeySha256: serverHandshake.hostKeySha256,
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )

        let clientRuntime = contractSshCreateClientRuntime(clientHandshake)
        let serverRuntime = contractSshCreateServerRuntimeRequest(
            ContractSshServerRuntimeRequest(serverHandshake)
        )
        let knownHostSummary = clientHandshake.requireHostVerification().hostIdentity()
        @Assert(knownHostSummary.hostKeyAlgorithm, "ssh-rsa")
        match (knownHostSummary.signatureVerified) {
            case Some(value) => @Assert(value, true)
            case None => @Fail("SSH verified host identity summary should carry verification flag")
        }
        let serverHandshakeSnapshot = serverHandshake.sessionSnapshot()
        @Assert(serverHandshakeSnapshot.sessionId, serverHandshake.sessionId)
        @Assert(serverHandshakeSnapshot.hostIdentity.hostKeyAlgorithm, "ssh-rsa")
        match (serverHandshakeSnapshot.hostIdentity.signatureVerified) {
            case None => @Assert(true, true)
            case Some(_) => @Fail("SSH server handshake snapshot should not synthesize verification flag")
        }
        let clientHandshakeSnapshot = clientHandshake.sessionSnapshot()
        @Assert(clientHandshakeSnapshot.sessionId, clientHandshake.sessionId)
        @Assert(clientHandshakeSnapshot.hostIdentity.hostSignatureAlgorithm, "rsa-sha2-256")
        match (clientHandshakeSnapshot.hostIdentity.signatureVerified) {
            case Some(value) => @Assert(value, true)
            case None => @Fail("SSH client handshake snapshot should preserve verification flag")
        }
        let initialClientRuntimeSnapshot = clientRuntime.snapshot()
        @Assert(initialClientRuntimeSnapshot.sessionId(), clientHandshake.sessionId)
        @Assert(initialClientRuntimeSnapshot.hostIdentity().hostKeySha256, serverHandshake.hostKeySha256)
        @Assert(initialClientRuntimeSnapshot.writeSequence, 0)
        @Assert(initialClientRuntimeSnapshot.readSequence, 0)
        match (initialClientRuntimeSnapshot.hostVerification()) {
            case Some(value) => @Assert(value.hostSignatureVerified, true)
            case None => @Fail("SSH client runtime snapshot should preserve host verification")
        }
        let initialServerRuntimeSnapshot = serverRuntime.snapshot()
        @Assert(initialServerRuntimeSnapshot.session.sessionId, serverHandshake.sessionId)
        @Assert(initialServerRuntimeSnapshot.hostIdentity().hostKeyAlgorithm, "ssh-rsa")
        match (initialServerRuntimeSnapshot.hostVerification()) {
            case None => @Assert(true, true)
            case Some(_) => @Fail("SSH server runtime snapshot should not report host verification")
        }
        @Assert(clientRuntime.sessionId(), clientHandshake.sessionId)
        @Assert(serverRuntime.sessionId(), serverHandshake.sessionId)
        @Assert(clientRuntime.requireHostVerification().hostSignatureVerified, true)
        match (clientRuntime.hostVerification()) {
            case Some(value) =>
                @Assert(value.hostKeySha256, serverHandshake.hostKeySha256)
            case None =>
                @Fail("SSH client runtime should preserve host verification")
        }

        let clientPacket = clientRuntime.seal(
            "contract-runtime-client".toArray(),
            randomPadding: incrementalBytes(64, start: 1764)
        )
        let serverOpened = serverRuntime.open(clientPacket)
        @Assert(serverOpened.payload, "contract-runtime-client".toArray())
        @Assert(clientRuntime.writeSequence, 1)
        @Assert(serverRuntime.readSequence, 1)
        let updatedClientRuntimeSnapshot = clientRuntime.snapshot()
        @Assert(updatedClientRuntimeSnapshot.writeSequence, 1)
        @Assert(updatedClientRuntimeSnapshot.readSequence, 0)
        let updatedServerRuntimeSnapshot = serverRuntime.snapshot()
        @Assert(updatedServerRuntimeSnapshot.writeSequence, 0)
        @Assert(updatedServerRuntimeSnapshot.readSequence, 1)

        let serverPacket = serverRuntime.seal(
            "contract-runtime-server".toArray(),
            randomPadding: incrementalBytes(64, start: 1828)
        )
        let clientOpened = clientRuntime.open(serverPacket)
        @Assert(clientOpened.payload, "contract-runtime-server".toArray())
        @Assert(serverRuntime.writeSequence, 1)
        @Assert(clientRuntime.readSequence, 1)

        clientRuntime.resetTransportCounters()
        serverRuntime.resetTransportCounters()
        @Assert(clientRuntime.writeSequence, 0)
        @Assert(clientRuntime.readSequence, 0)
        @Assert(serverRuntime.writeSequence, 0)
        @Assert(serverRuntime.readSequence, 0)

        let clientRuntimeByRequest = contractSshCreateClientRuntimeRequest(
            ContractSshClientRuntimeRequest(clientHandshake)
        )
        @Assert(clientRuntimeByRequest.transport().sessionId(), clientHandshake.sessionId)
    }

    @TestCase
    public func testContractSshRuntimeBundleFacades(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let negotiated = ContractSshNegotiatedAlgorithms(
            "curve25519-sha256",
            "rsa-sha2-256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256"
        )
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(readText("testdata/x509/rsa_2048_pkcs8.pem"))

        let initialTranscript = ContractSshKexExchangeTranscript(
            "SSH-2.0-contract-client-runtime-bundle0\r\n".toArray(),
            "SSH-2.0-contract-server-runtime-bundle0\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 2200))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 2232)))
        )
        let initialInit = contractSshBuildKexEcdhInitX25519Request(
            ContractSshBuildKexEcdhInitX25519Request(clientPrivate)
        )
        let serverHandshake = contractSshCompleteServerInitialHandshakeX25519RsaRequest(
            ContractSshServerInitialHandshakeX25519RsaRequest(
                initialTranscript,
                serverPrivate,
                initialInit.encodedInit,
                rsaPrivateKey,
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys()
            )
        )
        let clientHandshake = contractSshCompleteClientInitialHandshakeX25519Request(
            ContractSshClientInitialHandshakeX25519Request(
                initialTranscript,
                clientPrivate,
                initialInit.encodedInit,
                serverHandshake.encodedReply,
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: serverHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )

        let serverRuntimeBundle = contractPrepareSshServerRuntimeRequest(
            ContractSshServerRuntimeRequest(serverHandshake)
        )
        let clientRuntimeBundle = contractPrepareSshClientRuntimeRequest(
            ContractSshClientRuntimeRequest(clientHandshake)
        )
        @Assert(serverRuntimeBundle.session.sessionId, serverHandshake.sessionId)
        @Assert(serverRuntimeBundle.snapshot.sessionId(), serverHandshake.sessionId)
        @Assert(clientRuntimeBundle.session.sessionId, clientHandshake.sessionId)
        @Assert(clientRuntimeBundle.snapshot.sessionId(), clientHandshake.sessionId)
        match (clientRuntimeBundle.snapshot.hostVerification()) {
            case Some(value) => @Assert(value.hostSignatureVerified, true)
            case None => @Fail("SSH client runtime bundle snapshot should preserve host verification")
        }

        let rekeyTranscript = ContractSshKexExchangeTranscript(
            "SSH-2.0-contract-client-runtime-bundle1\r\n".toArray(),
            "SSH-2.0-contract-server-runtime-bundle1\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 2264))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 2296)))
        )
        let rekeyClientPrivate = hexToBytes("5c3a3d02825f2a5f6905aef0d8c8d3f0a4f8df94d153c5e8e91c1f1f9a8e6f71")
        let rekeyServerPrivate = hexToBytes("4f2f6c59b0d4f52b8c0db0ce1d77c4f1e1dcb3ea65b31f8f5a6c6e7f8899aabb")
        let rekeyInit = contractSshBuildKexEcdhInitX25519Request(
            ContractSshBuildKexEcdhInitX25519Request(rekeyClientPrivate)
        )
        let rekeyServerHandshake = contractSshCompleteServerInitialHandshakeX25519RsaRequest(
            ContractSshServerInitialHandshakeX25519RsaRequest(
                rekeyTranscript,
                rekeyServerPrivate,
                rekeyInit.encodedInit,
                rsaPrivateKey,
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys()
            )
        )
        let rekeyServerSession = contractSshServerProcessKexEcdhInitX25519Request(
            ContractSshServerProcessKexEcdhInitX25519Request(
                rekeyTranscript,
                rekeyServerPrivate,
                rekeyInit.encodedInit,
                ContractSshHostSigningResult(
                    rekeyServerHandshake.serverHostKey,
                    rekeyServerHandshake.hostSignature,
                    rekeyServerHandshake.hostKeyAlgorithm,
                    rekeyServerHandshake.hostSignatureAlgorithm,
                    rekeyServerHandshake.hostKeySha256
                )
            )
        )
        let rekeyClientSession = contractSshClientProcessKexEcdhReplyX25519Request(
            ContractSshClientProcessKexEcdhReplyX25519Request(
                rekeyTranscript,
                rekeyClientPrivate,
                rekeyInit.encodedInit,
                rekeyServerSession.encodedReply,
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: serverHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )

        let serverRekeyBundle = contractPrepareSshServerRuntimeRekeyFromSessionStateRequest(
            ContractSshServerRuntimeSessionRekeyRequest(
                serverRuntimeBundle.runtime,
                rekeyServerSession.session,
                sshEncodeNewKeys(),
                sshEncodeNewKeys()
            )
        )
        let clientRekeyBundle = contractPrepareSshClientRuntimeRekeyFromSessionStateRequest(
            ContractSshClientRuntimeSessionRekeyRequest(
                clientRuntimeBundle.runtime,
                rekeyClientSession,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: serverHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )
        @Assert(serverRekeyBundle.session.sessionId, serverRuntimeBundle.session.sessionId)
        @Assert(clientRekeyBundle.session.sessionId, clientRuntimeBundle.session.sessionId)
        @Assert(serverRekeyBundle.snapshot.sessionId(), serverRuntimeBundle.session.sessionId)
        @Assert(clientRekeyBundle.snapshot.sessionId(), clientRuntimeBundle.session.sessionId)
        @Assert(serverRekeyBundle.runtime.currentSession().exchangeHash, rekeyServerSession.session.exchangeHash)
        @Assert(clientRekeyBundle.runtime.currentSession().exchangeHash, rekeyClientSession.exchangeHash)
        match (clientRekeyBundle.snapshot.hostVerification()) {
            case Some(value) => @Assert(value.hostSignatureVerified, true)
            case None => @Fail("SSH client rekey bundle snapshot should preserve host verification")
        }

        let failedClientRekey = contractTryPrepareSshClientRuntimeRekeyFromSessionStateRequest(
            ContractSshClientRuntimeSessionRekeyRequest(
                clientRuntimeBundle.runtime,
                rekeyClientSession,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: incrementalBytes(32, start: 2330),
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )
        @Assert(failedClientRekey.ok, false)
        match (failedClientRekey.code) {
            case Some(value) => @Assert(value.toString(), "VERIFY_FAILED")
            case None => @Fail("SSH client runtime rekey bundle outcome should carry contract code")
        }
    }

    @TestCase
    public func testContractSshRuntimeSessionRekeyRequestHelpers(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let negotiated = ContractSshNegotiatedAlgorithms(
            "curve25519-sha256",
            "rsa-sha2-256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256"
        )
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(readText("testdata/x509/rsa_2048_pkcs8.pem"))

        let initialTranscript = ContractSshKexExchangeTranscript(
            "SSH-2.0-contract-client-session-rekey0\r\n".toArray(),
            "SSH-2.0-contract-server-session-rekey0\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 2056))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 2088)))
        )
        let initialInit = contractSshBuildKexEcdhInitX25519(clientPrivate)
        let initialServerHandshake = contractSshCompleteServerInitialHandshakeX25519RsaRequest(
            ContractSshServerInitialHandshakeX25519RsaRequest(
                initialTranscript,
                serverPrivate,
                initialInit.encodedInit,
                rsaPrivateKey,
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys()
            )
        )
        let initialClientHandshake = contractSshCompleteClientInitialHandshakeX25519Request(
            ContractSshClientInitialHandshakeX25519Request(
                initialTranscript,
                clientPrivate,
                initialInit.encodedInit,
                initialServerHandshake.encodedReply,
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: initialServerHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )
        let clientRuntime = contractSshCreateClientRuntime(initialClientHandshake)
        let serverRuntime = contractSshCreateServerRuntime(initialServerHandshake)
        let initialSessionId = clientRuntime.sessionId()

        let rekeyTranscript = ContractSshKexExchangeTranscript(
            "SSH-2.0-contract-client-session-rekey1\r\n".toArray(),
            "SSH-2.0-contract-server-session-rekey1\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 2120))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 2152)))
        )
        let rekeyClientPrivate = hexToBytes("5c3a3d02825f2a5f6905aef0d8c8d3f0a4f8df94d153c5e8e91c1f1f9a8e6f71")
        let rekeyServerPrivate = hexToBytes("4f2f6c59b0d4f52b8c0db0ce1d77c4f1e1dcb3ea65b31f8f5a6c6e7f8899aabb")
        let rekeyInit = contractSshBuildKexEcdhInitX25519(rekeyClientPrivate)
        let rekeyServerHandshake = contractSshCompleteServerInitialHandshakeX25519RsaRequest(
            ContractSshServerInitialHandshakeX25519RsaRequest(
                rekeyTranscript,
                rekeyServerPrivate,
                rekeyInit.encodedInit,
                rsaPrivateKey,
                negotiated,
                sshEncodeNewKeys(),
                sshEncodeNewKeys()
            )
        )
        let rekeyServerSession = contractSshServerProcessKexEcdhInitX25519Request(
            ContractSshServerProcessKexEcdhInitX25519Request(
                rekeyTranscript,
                rekeyServerPrivate,
                rekeyInit.encodedInit,
                ContractSshHostSigningResult(
                    rekeyServerHandshake.serverHostKey,
                    rekeyServerHandshake.hostSignature,
                    rekeyServerHandshake.hostKeyAlgorithm,
                    rekeyServerHandshake.hostSignatureAlgorithm,
                    rekeyServerHandshake.hostKeySha256
                )
            )
        )
        let rekeyClientSession = contractSshClientProcessKexEcdhReplyX25519Request(
            ContractSshClientProcessKexEcdhReplyX25519Request(
                rekeyTranscript,
                rekeyClientPrivate,
                rekeyInit.encodedInit,
                rekeyServerSession.encodedReply,
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: initialServerHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )

        let serverRekey = contractSshRekeyServerRuntimeFromSessionStateRequest(
            ContractSshServerRuntimeSessionRekeyRequest(
                serverRuntime,
                rekeyServerSession.session,
                sshEncodeNewKeys(),
                sshEncodeNewKeys()
            )
        )
        let clientRekey = contractSshRekeyClientRuntimeFromSessionStateRequest(
            ContractSshClientRuntimeSessionRekeyRequest(
                clientRuntime,
                rekeyClientSession,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: initialServerHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )

        @Assert(serverRekey.session.sessionId, initialSessionId)
        @Assert(clientRekey.session.sessionId, initialSessionId)
        @Assert(serverRekey.runtime.currentSession().exchangeHash, rekeyServerSession.session.exchangeHash)
        @Assert(clientRekey.runtime.currentSession().exchangeHash, rekeyClientSession.exchangeHash)
        @Assert(clientRekey.runtime.requireHostVerification().hostSignatureVerified, true)

        let sealed = clientRekey.runtime.seal(
            "contract-runtime-session-rekey".toArray(),
            randomPadding: incrementalBytes(64, start: 2184)
        )
        let opened = serverRekey.runtime.open(sealed)
        @Assert(opened.payload, "contract-runtime-session-rekey".toArray())
    }

    @TestCase
    public func testContractSshRuntimeRekeyFacadeHelpers(): Unit {
        let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let negotiated = SshNegotiatedAlgorithms(
            "curve25519-sha256",
            "rsa-sha2-256",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none"
        )
        let rsaPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(readText("testdata/x509/rsa_2048_pkcs8.pem"))

        let initialTranscript = SshKexExchangeTranscript(
            "SSH-2.0-contract-client-rekey0\r\n".toArray(),
            "SSH-2.0-contract-server-rekey0\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1880))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1912)))
        )
        let (initialEncodedInit, _) = sshBuildKexEcdhInitX25519(clientPrivate)
        let initialServerHandshake = contractSshCompleteServerInitialHandshakeX25519Rsa(
            initialTranscript,
            serverPrivate,
            initialEncodedInit,
            rsaPrivateKey,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        let initialClientHandshake = contractSshCompleteClientInitialHandshakeX25519(
            initialTranscript,
            clientPrivate,
            initialEncodedInit,
            initialServerHandshake.encodedReply,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                expectedHostKeySha256: initialServerHandshake.hostKeySha256,
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        let clientRuntime = contractSshCreateClientRuntime(initialClientHandshake)
        let serverRuntime = contractSshCreateServerRuntime(initialServerHandshake)
        let initialSessionId = clientRuntime.sessionId()
        let initialExchangeHash = clientRuntime.currentSession().exchangeHash

        let rekeyTranscript = SshKexExchangeTranscript(
            "SSH-2.0-contract-client-rekey1\r\n".toArray(),
            "SSH-2.0-contract-server-rekey1\r\n".toArray(),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1944))),
            sshEncodeKexInit(sshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 1976)))
        )
        let (rekeyEncodedInit, _) = sshBuildKexEcdhInitX25519(hexToBytes("5c3a3d02825f2a5f6905aef0d8c8d3f0a4f8df94d153c5e8e91c1f1f9a8e6f71"))
        let rekeyServerHandshake = sshCompleteServerInitialHandshakeX25519Rsa(
            rekeyTranscript,
            hexToBytes("4f2f6c59b0d4f52b8c0db0ce1d77c4f1e1dcb3ea65b31f8f5a6c6e7f8899aabb"),
            rekeyEncodedInit,
            rsaPrivateKey,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )
        let rekeyClientHandshake = sshCompleteClientInitialHandshakeX25519(
            rekeyTranscript,
            hexToBytes("5c3a3d02825f2a5f6905aef0d8c8d3f0a4f8df94d153c5e8e91c1f1f9a8e6f71"),
            rekeyEncodedInit,
            rekeyServerHandshake.encodedReply,
            negotiated,
            sshEncodeNewKeys(),
            sshEncodeNewKeys()
        )

        let serverRekey = contractSshRekeyServerRuntimeX25519Request(
            ContractSshServerRuntimeRekeyRequest(
                serverRuntime,
                rekeyServerHandshake.kexResult,
                sshEncodeNewKeys(),
                sshEncodeNewKeys()
            )
        )
        let clientRekey = contractSshRekeyClientRuntimeX25519Request(
            ContractSshClientRuntimeRekeyRequest(
                clientRuntime,
                rekeyClientHandshake.kexResult,
                sshEncodeNewKeys(),
                sshEncodeNewKeys(),
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: initialServerHandshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )

        @Assert(serverRekey.session.sessionId, initialSessionId)
        @Assert(clientRekey.session.sessionId, initialSessionId)
        @Assert(serverRekey.runtime.currentSession().sessionId, initialSessionId)
        @Assert(clientRekey.runtime.currentSession().sessionId, initialSessionId)
        @Assert(clientRekey.runtime.currentSession().exchangeHash, rekeyClientHandshake.kexResult.exchangeHash)
        @Assert(serverRekey.runtime.currentSession().exchangeHash, rekeyServerHandshake.kexResult.exchangeHash)
        @Assert(clientRekey.runtime.currentSession().exchangeHash == initialExchangeHash, false)
        @Assert(clientRekey.runtime.requireHostVerification().hostSignatureVerified, true)

        let rekeyPacket = clientRekey.runtime.seal(
            "contract-runtime-rekey".toArray(),
            randomPadding: incrementalBytes(64, start: 2008)
        )
        let rekeyOpened = serverRekey.runtime.open(rekeyPacket)
        @Assert(rekeyOpened.payload, "contract-runtime-rekey".toArray())

        let optionalClientRekey = contractSshRekeyClientRuntimeX25519(
            clientRuntime,
            rekeyClientHandshake.kexResult,
            sshEncodeNewKeys(),
            sshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                expectedHostKeySha256: incrementalBytes(32, start: 2040),
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: false
            )
        )
        match (optionalClientRekey.session.hostVerification) {
            case Some(_) => @Fail("optional SSH runtime rekey should tolerate verification miss")
            case None => ()
        }
    }
}

private func readText(path: String): String {
    String.fromUtf8(File.readFrom(path))
}

private func incrementalBytes(size: Int64, start!: Int64 = 0): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    var i = 0
    while (i < size) {
        out[i] = UInt8((start + i) & 0xff)
        i += 1
    }
    out
}

private func toUInt8Array(bytes: Array<Byte>): Array<UInt8> {
    let out = Array<UInt8>(bytes.size, repeat: 0)
    var i = 0
    while (i < bytes.size) {
        out[i] = UInt8(bytes[i])
        i += 1
    }
    out
}

private func buildDummySshRsaHostKeyBlob(): Array<Byte> {
    let exponent = [UInt8(0x01), UInt8(0x00), UInt8(0x01)]
    let modulus = Array<Byte>(128, repeat: 0)
    modulus[0] = UInt8(0x7f)
    var i = 1
    while (i < modulus.size) {
        modulus[i] = UInt8((0x11 + i) & 0xff)
        i += 1
    }
    concatByteParts([
        encodeSshString("ssh-rsa".toArray()),
        encodeSshString(exponent),
        encodeSshString(modulus)
    ])
}

private func buildDummySshHostSignatureBlob(algorithm: String, signatureBytes: Array<Byte>): Array<Byte> {
    concatByteParts([
        encodeSshString(algorithm.toArray()),
        encodeSshString(signatureBytes)
    ])
}

private func encodeSshString(data: Array<Byte>): Array<Byte> {
    let out = Array<Byte>(4 + data.size, repeat: 0)
    out[0] = UInt8((data.size >> 24) & 0xff)
    out[1] = UInt8((data.size >> 16) & 0xff)
    out[2] = UInt8((data.size >> 8) & 0xff)
    out[3] = UInt8(data.size & 0xff)
    var i = 0
    while (i < data.size) {
        out[4 + i] = data[i]
        i += 1
    }
    out
}

private func concatByteParts(parts: Array<Array<Byte>>): Array<Byte> {
    var total = 0
    for (part in parts) {
        total += part.size
    }
    let out = Array<Byte>(total, repeat: 0)
    var offset = 0
    for (part in parts) {
        var i = 0
        while (i < part.size) {
            out[offset + i] = part[i]
            i += 1
        }
        offset += part.size
    }
    out
}

private func assertSshHostVerificationVerifyFailed(
    exchangeHash: Array<Byte>,
    serverHostKey: Array<Byte>,
    hostSignature: Array<Byte>
): Unit {
    try {
        _ = contractSshVerifyHostIdentityRequired(
            exchangeHash,
            serverHostKey,
            hostSignature,
            policy: ContractSshHostVerificationPolicy(
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
        @Fail("SSH host verification should fail for invalid/tampered signature")
    } catch (e: ContractException) {
        @Assert(e.code.toString(), "VERIFY_FAILED")
    }
}

private func containsString(values: Array<String>, expected: String): Bool {
    for (value in values) {
        if (value == expected) {
            return true
        }
    }
    false
}

private func parseContractTls13UInt16VectorExtension(data: Array<Byte>): Array<Int64> {
    if (data.size < 2) {
        throw Exception("TLS1.3 extension vector is truncated")
    }
    let encodedLen = readContractUInt16Be(data, 0)
    if (encodedLen == 0 || (encodedLen % 2) != 0 || encodedLen + 2 != data.size) {
        throw Exception("TLS1.3 extension vector length is invalid")
    }

    let values = ArrayList<Int64>()
    var offset = 2
    while (offset < data.size) {
        values.add(readContractUInt16Be(data, offset))
        offset += 2
    }
    values.toArray()
}

private func readContractUInt16Be(data: Array<Byte>, offset: Int64): Int64 {
    if (offset + 2 > data.size) {
        throw Exception("uint16 read exceeds buffer")
    }
    (Int64(UInt8(data[offset])) << 8) | Int64(UInt8(data[offset + 1]))
}

private func tamperHeadAscii(text: String): String {
    if (text.size == 0) {
        return text
    }
    let bytes = text.toArray()
    let head = bytes[0]
    bytes[0] = if (head == b'A') { b'B' } else { b'A' }
    String.fromUtf8(bytes)
}

private func hexToBytes(hex: String): Array<Byte> {
    let normalized = hex.trimAscii()
    if ((normalized.size % 2) != 0) {
        throw Exception("hex string length must be even")
    }
    let bytes = normalized.toArray()
    let out = ArrayList<Byte>()
    var i = 0
    while (i < normalized.size) {
        out.add(UInt8(parseHexByte(UInt8(bytes[i]), UInt8(bytes[i + 1]))))
        i += 2
    }
    out.toArray()
}

private func parseHexByte(high: UInt8, low: UInt8): Int64 {
    (parseHexNibble(high) << 4) | parseHexNibble(low)
}

private func parseHexNibble(ch: UInt8): Int64 {
    if (ch >= b'0' && ch <= b'9') {
        return Int64(ch) - Int64(b'0')
    }
    if (ch >= b'a' && ch <= b'f') {
        return 10 + Int64(ch) - Int64(b'a')
    }
    if (ch >= b'A' && ch <= b'F') {
        return 10 + Int64(ch) - Int64(b'A')
    }
    throw Exception("invalid hex digit")
}
