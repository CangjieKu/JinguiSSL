package jinguissl.tests

import std.collection.{ArrayList, HashMap}
import std.fs.*
import jinguissl.contract.*
import jinguissl.crypto.bignum.BigNum
import jinguissl.crypto.digest.{HashAlgorithm, hkdf, hkdfExpand, hkdfExtract, sha256}
import jinguissl.crypto.ecc.{EcPrivateKey, NamedCurve, ecPublicFromPrivateKey}
import jinguissl.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl.crypto.ssh.*
import jinguissl.crypto.x25519.x25519PublicFromPrivate
import jinguissl.crypto.x509.{
    X509SelfSignedConfig,
    x509CreateSelfSignedRsaCertificate,
    x509ParseEcPrivateKeyPkcs8Pem,
    x509ParseRsaPrivateKeyPkcs8Pem
}

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

        let exporterMaster = contractTls13DeriveExporterMasterSecret(
            verifiedSession.masterSecret,
            verifiedSession.transcriptHash
        )
        let exported = contractTls13ExportKeyingMaterial(
            exporterMaster,
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

        let exporterMasterByRequest = contractTls13DeriveExporterMasterSecretRequest(
            ContractTls13ExporterMasterSecretRequest(
                verifiedSession.masterSecret,
                verifiedSession.transcriptHash
            )
        )
        @Assert(exporterMasterByRequest, exporterMaster)

        let exportedByRequest = contractTls13ExportKeyingMaterialRequest(
            ContractTls13ExportKeyingMaterialRequest(
                exporterMasterByRequest,
                "EXPORTER-jinkui/http",
                context: "http-ctx".toArray(),
                outputLen: 42
            )
        )
        @Assert(exportedByRequest, exported)
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
        let plainAlertRecord = contractTlsEncodeAlertRecord(
            ContractTlsVersion.Tls13,
            ContractTlsAlertLevel.AlertWarning,
            ContractTlsAlertDescription.AlertCloseNotify
        )
        let decodedPlainAlert = contractTlsDecodeAlertRecord(plainAlertRecord)
        @Assert(decodedPlainAlert.level.toString(), "WARNING")
        @Assert(decodedPlainAlert.description.toString(), "CLOSE_NOTIFY")
        @Assert(decodedPlainAlert.isCloseNotify, true)
        @Assert(contractTlsIsCloseNotifyAlert(decodedPlainAlert), true)

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
        let binding = contractTls13ResolveCipherBindingFromServerFlight(flight)
        @Assert(binding.cipherSuiteName, "TLS_AES_128_GCM_SHA256")
        @Assert(binding.algorithm.toString(), "AES-256-GCM")
        @Assert(binding.keyLen, verifiedSession.result.keyMaterial.clientWriteKey.size)
        @Assert(binding.ivLen, verifiedSession.result.keyMaterial.clientWriteIv.size)

        let keyUpdate = contractTls13PrepareKeyUpdate(
            verifiedSession.clientAppTrafficSecret,
            requestPeerUpdate: true,
            keyLen: binding.keyLen,
            ivLen: binding.ivLen
        )
        @Assert(contractTls13DecodeKeyUpdateHandshake(keyUpdate.encodedKeyUpdate), true)
        @Assert(keyUpdate.requestPeerUpdate, true)

        let applied = contractTls13ApplyPeerKeyUpdate(
            verifiedSession.serverAppTrafficSecret,
            keyUpdate.encodedKeyUpdate,
            keyLen: binding.keyLen,
            ivLen: binding.ivLen
        )
        @Assert(applied.requestPeerUpdate, true)
        @Assert(applied.nextWriteKey.size, binding.keyLen)
        @Assert(applied.nextWriteIv.size, binding.ivLen)

        let keyUpdateByRequest = contractTls13PrepareKeyUpdateRequest(
            ContractTls13KeyUpdateRequest(
                verifiedSession.clientAppTrafficSecret,
                requestPeerUpdate: true,
                keyLen: binding.keyLen,
                ivLen: binding.ivLen
            )
        )
        @Assert(contractTls13DecodeKeyUpdateHandshake(keyUpdateByRequest.encodedKeyUpdate), true)
        @Assert(keyUpdateByRequest.requestPeerUpdate, true)

        let appliedByRequest = contractTls13ApplyPeerKeyUpdateRequest(
            ContractTls13PeerKeyUpdateRequest(
                verifiedSession.serverAppTrafficSecret,
                keyUpdateByRequest.encodedKeyUpdate,
                keyLen: binding.keyLen,
                ivLen: binding.ivLen
            )
        )
        @Assert(appliedByRequest.requestPeerUpdate, true)
        @Assert(appliedByRequest.nextWriteKey.size, binding.keyLen)
        @Assert(appliedByRequest.nextWriteIv.size, binding.ivLen)
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
        let optionalResult = contractSshVerifyHostIdentity(
            exchangeHash,
            serverHostKey,
            hostSignature,
            policy: optionalPolicy
        )
        match (optionalResult) {
            case Some(_value) =>
                @Fail("optional SSH host verification should return None on invalid signature")
            case None =>
                ()
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
