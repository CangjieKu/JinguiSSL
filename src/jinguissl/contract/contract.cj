package jinguissl.contract

import std.collection.{ArrayList, HashMap}
import jinguissl.crypto.aes.{AesGcmContext, aesGcmDecryptWithContext, aesGcmEncryptWithContext, aesNewGcmContext}
import jinguissl.crypto.bignum.BigNum
import jinguissl.crypto.chacha20.{chacha20Poly1305Decrypt, chacha20Poly1305Encrypt}
import jinguissl.crypto.compliance.{TLS_VERSION_1_2, TLS_VERSION_1_3, TlsVersion}
import jinguissl.crypto.digest.{HashAlgorithm, hkdf, hkdfExpand, hkdfExtract, sha256}
import jinguissl.crypto.ecc.{EcPrivateKey, EcPublicKey, NamedCurve, ecPublicFromPrivateKey}
import jinguissl.crypto.error.*
import jinguissl.crypto.rsa.{RsaPrivateKey, RsaPublicKey}
import jinguissl.crypto.ssh.{
    SshClientInitialHandshakeResult,
    SshHandshakeCoordinator,
    SshHostVerificationPolicy,
    SshHostVerificationResult,
    SshKexExchangeTranscript,
    SshKexInitMessage,
    SshNegotiatedAlgorithms,
    SshServerInitialHandshakeResult,
    SshTransportPacket,
    SshX25519KexResult,
    sshBuildKexEcdhInitX25519,
    sshBuildDefaultKexInit,
    sshClientProcessKexEcdhReplyX25519,
    sshBuildEd25519HostKeyBlobFromSeed,
    sshCompleteClientInitialHandshakeX25519WithHostVerificationRequirement,
    sshCompleteServerInitialHandshakeX25519Ecdsa,
    sshCompleteServerInitialHandshakeX25519Ed25519,
    sshCompleteServerInitialHandshakeX25519Rsa,
    sshComputeHostKeySha256,
    sshDecodeKexInit,
    sshEncodeEcdsaHostPublicKey,
    sshEncodeKexInit,
    sshEncodeRsaHostPublicKey,
    sshExtractHostKeyAlgorithm,
    sshExtractHostSignatureAlgorithm,
    sshNegotiateKexInit,
    sshServerProcessKexEcdhInitX25519,
    sshSignExchangeHashEcdsa,
    sshSignExchangeHashEd25519,
    sshSignExchangeHashRsa,
    sshVerifyServerHostSignature
}
import jinguissl.crypto.tls.{
    TLS_SESSION_DEFAULT_TTL_SECONDS,
    TlsAeadRecordLayer,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsChacha20Poly1305RecordLayer,
    TlsSessionCache,
    TlsSessionCacheStats,
    TlsSessionIdentity,
    TlsSessionTicket,
    Tls12HandshakeSecrets,
    Tls12KeyExchange,
    TlsAeadAlgorithm,
    TlsContentType,
    tlsCreateSessionTicket,
    tlsDecodeAlert,
    tlsDecodeAlertRecord,
    tlsDecodeServerHelloHandshake,
    tlsDecodeSessionTicket,
    tlsEncodeAlert,
    tlsEncodeAlertRecord,
    tlsEncodeSessionTicket,
    tlsIsCloseNotifyAlert,
    tlsIsSessionTicketExpired,
    Tls13AuthFlight,
    Tls13AuthFlightRole,
    Tls13HandshakeSecrets,
    TlsHttpNegotiationPolicy,
    Tls13ServerHandshakeFlight,
    tls12BuildCertificateHandshakeFromDerChain,
    tls12BuildClientHello,
    tls12CreateClientRecordLayer,
    tls12CreateClientRecordLayerChacha20Poly1305,
    tls12CreateServerRecordLayer,
    tls12CreateServerRecordLayerChacha20Poly1305,
    tls12BuildEcdheClientKeyExchange,
    tls12BuildEcdheServerKeyExchange,
    tls12BuildRsaClientKeyExchange,
    tls12BuildServerHello,
    tls12DeriveSecretsFromEcdhe,
    tls12DeriveSecretsFromPreMaster,
    tls12ExtractClientRandom,
    tls12ExtractServerRandom,
    tls12ParseEcdheClientKeyExchange,
    tls12ParseEcdheServerKeyExchange,
    tls12ProcessRsaClientKeyExchange,
    tls12VerifyCertificateChainFromHandshake,
    tls13BuildHttpClientHelloX25519,
    tls13BuildClientHelloPskFromSessionTicket,
    tls13BuildClientHelloPskFromSessionTickets,
    tls13BuildKeyUpdateHandshake,
    tls13BuildNewSessionTicketFromSessionTicket,
    tls13BuildServerHelloForPskBySessionTickets,
    tls13BuildServerHelloForPskFromSessionTicket,
    tls13CipherSuiteAeadAlgorithm,
    tls13CipherSuiteIvLen,
    tls13CipherSuiteKeyLen,
    TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
    TLS13_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    tls13DecodeKeyUpdateHandshake,
    tls13ExtractClientPskIdentity,
    tls13ExtractServerSelectedPskIdentity,
    tls13DecodeSessionTicketFromNewSessionTicket,
    tls13DeriveEarlyDataSecrets,
    tls13DeriveApplicationTrafficKeyIv,
    tls13DeriveExporterMasterSecret,
    tls13DeriveNextApplicationTrafficSecret,
    tls13DeriveSecretsFromPskAndX25519ForCipherSuite,
    tls13ExportKeyingMaterial,
    tls13SelectPskIdentityFromSessionTickets,
    tls13VerifyClientPskBinder,
    tls13BuildHttpServerHandshakeContextX25519,
    tls13ProcessServerHandshakeFlightX25519,
    tls13ValidateHttpClientResult
}
import jinguissl.crypto.utils.{constantTimeEquals, csprngBytes, csprngIsAvailable}
import jinguissl.crypto.x25519.{x25519GeneratePrivateKey, x25519PublicFromPrivate}
import jinguissl.crypto.x509.{
    X509Certificate,
    X509VerificationPolicy,
    x509ExtractEcPublicKey,
    x509ParsePem,
    x509ParsePemChain,
    x509ParseEcPrivateKeyPkcs8Pem,
    x509ParseRsaPrivateKeyPkcs1Pem,
    x509ParseRsaPrivateKeyPkcs8Pem,
    x509ExtractRsaPublicKey,
    x509VerifyCertificateChain
}

private let CONTRACT_AES_GCM_CONTEXT_CACHE_MAX: Int64 = 16
private let _contractAesGcmContextCache = ArrayList<ContractAesGcmContextCacheEntry>()

private class ContractAesGcmContextCacheEntry {
    let key: Array<Byte>
    let context: AesGcmContext

    init(key: Array<Byte>, context: AesGcmContext) {
        this.key = key
        this.context = context
    }
}

public enum ContractErrorCode <: Equatable<ContractErrorCode> & ToString {
    | BadInput
    | KeyNotFound
    | VerifyFailed
    | CryptoUnavailable
    | ComplianceRejected
    | Unsupported
    | InternalError

    public operator func ==(right: ContractErrorCode): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractErrorCode): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case BadInput => 0
            case KeyNotFound => 1
            case VerifyFailed => 2
            case CryptoUnavailable => 3
            case ComplianceRejected => 4
            case Unsupported => 5
            case InternalError => 6
        }
    }

    public func toString(): String {
        match (this) {
            case BadInput => "BAD_INPUT"
            case KeyNotFound => "KEY_NOT_FOUND"
            case VerifyFailed => "VERIFY_FAILED"
            case CryptoUnavailable => "CRYPTO_UNAVAILABLE"
            case ComplianceRejected => "COMPLIANCE_REJECTED"
            case Unsupported => "UNSUPPORTED"
            case InternalError => "INTERNAL_ERROR"
        }
    }
}

public class ContractException <: Exception {
    public let code: ContractErrorCode

    public init(code: ContractErrorCode, message: String) {
        super(message)
        this.code = code
    }
}

public enum ContractIgniteCryptoErrorCode <: Equatable<ContractIgniteCryptoErrorCode> & ToString {
    | BadEnvelope
    | KeyNotFound
    | DecryptFailed
    | CryptoUnavailable

    public operator func ==(right: ContractIgniteCryptoErrorCode): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractIgniteCryptoErrorCode): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case BadEnvelope => 0
            case KeyNotFound => 1
            case DecryptFailed => 2
            case CryptoUnavailable => 3
        }
    }

    public func toString(): String {
        match (this) {
            case BadEnvelope => "BAD_ENVELOPE"
            case KeyNotFound => "KEY_NOT_FOUND"
            case DecryptFailed => "DECRYPT_FAILED"
            case CryptoUnavailable => "CRYPTO_UNAVAILABLE"
        }
    }
}

public enum ContractAeadAlgorithm <: Equatable<ContractAeadAlgorithm> & ToString {
    | Aes256Gcm
    | Chacha20Poly1305

    public operator func ==(right: ContractAeadAlgorithm): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractAeadAlgorithm): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Aes256Gcm => 0
            case Chacha20Poly1305 => 1
        }
    }

    public func toString(): String {
        match (this) {
            case Aes256Gcm => "AES-256-GCM"
            case Chacha20Poly1305 => "CHACHA20-POLY1305"
        }
    }
}

public enum ContractKdfHash <: Equatable<ContractKdfHash> & ToString {
    | Sha1
    | Sha256
    | Sha384
    | Sha512

    public operator func ==(right: ContractKdfHash): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractKdfHash): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Sha1 => 0
            case Sha256 => 1
            case Sha384 => 2
            case Sha512 => 3
        }
    }

    public func toString(): String {
        match (this) {
            case Sha1 => "HKDF-SHA1"
            case Sha256 => "HKDF-SHA256"
            case Sha384 => "HKDF-SHA384"
            case Sha512 => "HKDF-SHA512"
        }
    }
}

public let CONTRACT_FACADE_API_VERSION: String = "1.0.0"
public let CONTRACT_FACADE_STABILITY_LEVEL: String = "L1"
public let CONTRACT_FACADE_FREEZE_DATE: String = "2026-03-24"

public class ContractFacadeInfo {
    public let apiVersion: String
    public let stabilityLevel: String
    public let freezeDate: String
    public let stableDomains: Array<String>
    public let importRule: String

    public init(
        apiVersion: String,
        stabilityLevel: String,
        freezeDate: String,
        stableDomains: Array<String>,
        importRule: String
    ) {
        if (apiVersion.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract facade api version must not be empty")
        }
        if (stabilityLevel.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract facade stability level must not be empty")
        }
        if (freezeDate.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract facade freeze date must not be empty")
        }
        if (stableDomains.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract facade stable domains must not be empty")
        }
        this.apiVersion = apiVersion.trimAscii()
        this.stabilityLevel = stabilityLevel.trimAscii()
        this.freezeDate = freezeDate.trimAscii()
        this.stableDomains = stableDomains.clone()
        this.importRule = importRule.trimAscii()
    }
}

public func contractFacadeInfo(): ContractFacadeInfo {
    ContractFacadeInfo(
        CONTRACT_FACADE_API_VERSION,
        CONTRACT_FACADE_STABILITY_LEVEL,
        CONTRACT_FACADE_FREEZE_DATE,
        [
            "envelope",
            "x509",
            "tls12",
            "tls13",
            "ssh",
            "hkdf",
            "random"
        ],
        "import jinguissl.contract.* only; avoid deep import from jinguissl.crypto.* in app/framework layers"
    )
}

public class ContractCapabilityInfo {
    public let stableDomains: Array<String>
    public let httpTlsFeatures: Array<String>
    public let sshFeatures: Array<String>
    public let x509Features: Array<String>
    public let directStdxTlsServerConfigBridge: Bool
    public let notes: Array<String>

    public init(
        stableDomains: Array<String>,
        httpTlsFeatures: Array<String>,
        sshFeatures: Array<String>,
        x509Features: Array<String>,
        directStdxTlsServerConfigBridge: Bool,
        notes: Array<String>
    ) {
        if (stableDomains.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract capability stable domains must not be empty")
        }
        if (httpTlsFeatures.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract capability HTTP/TLS feature list must not be empty")
        }
        if (sshFeatures.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract capability SSH feature list must not be empty")
        }
        if (x509Features.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract capability X.509 feature list must not be empty")
        }
        if (notes.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "contract capability notes must not be empty")
        }
        this.stableDomains = stableDomains.clone()
        this.httpTlsFeatures = httpTlsFeatures.clone()
        this.sshFeatures = sshFeatures.clone()
        this.x509Features = x509Features.clone()
        this.directStdxTlsServerConfigBridge = directStdxTlsServerConfigBridge
        this.notes = notes.clone()
    }
}

public func contractCapabilityInfo(): ContractCapabilityInfo {
    ContractCapabilityInfo(
        [
            "envelope",
            "x509",
            "tls12",
            "tls13",
            "ssh",
            "hkdf",
            "random"
        ],
        [
            "tls12-rsa",
            "tls12-ecdhe-p256",
            "tls12-ecdhe-p384",
            "tls13-x25519",
            "tls13-p256",
            "tls13-p384",
            "tls13-client-auth",
            "tls13-session-ticket-psk",
            "tls13-key-update",
            "http-server-tls-config-validation",
            "http-server-tls-material-preparation",
            "http-client-tls-config-validation",
            "http-client-trust-material-preparation",
            "alpn-normalization"
        ],
        [
            "transport-packet-protection",
            "x25519-kex",
            "ecdh-p256-kex",
            "rsa-sha2-hostkey",
            "ecdsa-p256-hostkey",
            "ecdsa-p384-hostkey",
            "ed25519-hostkey",
            "host-signing-material-facade",
            "client-initial-handshake-facade",
            "server-initial-handshake-facade",
            "host-verification-required-modes"
        ],
        [
            "pem-der-parse",
            "pem-bundle-normalization",
            "certificate-chain-verify",
            "http-client-peer-certificate-verify",
            "hostname-policy",
            "leaf-pin-der-sha256",
            "leaf-pin-spki-sha256",
            "private-key-parse-rsa-pkcs1-pkcs8",
            "private-key-parse-ec-pkcs8"
        ],
        false,
        [
            "apps/frameworks should import jinguissl.contract.* only",
            "direct stdx.net.tls.TlsServerConfig bridge is not provided in this repo",
            "use contractValidateHttpServerTlsConfigInput before external TLS server config construction",
            "HTTP/SSH-facing contract surface is prioritized over deep crypto internals"
        ]
    )
}

public class ContractAeadEnvelopeV1 {
    public let ver: Int64
    public let alg: String
    public let kid: String
    public let nonce: String
    public let aad: String
    public let ciphertext: String
    public let tag: String

    public init(
        ver: Int64,
        alg: String,
        kid: String,
        nonce: String,
        aad: String,
        ciphertext: String,
        tag: String
    ) {
        if (ver != 1) {
            throw ContractException(ContractErrorCode.BadInput, "envelope version must be 1")
        }

        let normalizedAlg = contractNormalizeAlgorithmToken(alg)
        let normalizedKid = kid.trimAscii()
        requireTokenAscii(normalizedKid, "kid")
        requireTokenAscii(nonce, "nonce")
        requireTokenAscii(aad, "aad", allowEmpty: true)
        requireTokenAscii(ciphertext, "ciphertext")
        requireTokenAscii(tag, "tag")

        if (nonce.size == 0 || ciphertext.size == 0 || tag.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "envelope fields must not be empty")
        }

        this.ver = ver
        this.alg = normalizedAlg
        this.kid = normalizedKid
        this.nonce = nonce
        this.aad = aad
        this.ciphertext = ciphertext
        this.tag = tag
    }

    public func algorithm(): ContractAeadAlgorithm {
        contractParseAlgorithmToken(alg)
    }

    public func toJsonString(): String {
        "{\"ver\":1,\"alg\":\"${alg}\",\"kid\":\"${kid}\",\"nonce\":\"${nonce}\",\"aad\":\"${aad}\",\"ciphertext\":\"${ciphertext}\",\"tag\":\"${tag}\"}"
    }

    public static func parseJson(text: String): ContractAeadEnvelopeV1 {
        let compact = removeAsciiSpaces(text)
        if (compact.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "envelope json must not be empty")
        }

        let ver = extractIntField(compact, "ver")
        let alg = extractStringField(compact, "alg")
        let kid = extractStringField(compact, "kid")
        let nonce = extractStringField(compact, "nonce")
        let aad = extractStringField(compact, "aad")
        let ciphertext = extractStringField(compact, "ciphertext")
        let tag = extractStringField(compact, "tag")
        ContractAeadEnvelopeV1(ver, alg, kid, nonce, aad, ciphertext, tag)
    }
}

public func contractParseEnvelopeJsonCompatV1(envelopeJson: String): ContractAeadEnvelopeV1 {
    let compact = removeAsciiSpaces(envelopeJson)
    if (compact.size == 0) {
        throw ContractException(ContractErrorCode.BadInput, "envelope json must not be empty")
    }

    if (indexOfString(compact, "\"ver\":") >= 0) {
        return ContractAeadEnvelopeV1.parseJson(compact)
    }

    let ver = extractIntField(compact, "v")
    let alg = extractStringField(compact, "alg")
    let kid = extractStringField(compact, "kid")
    let nonce = extractStringField(compact, "nonce")
    let aad = extractOptionalStringField(compact, "aad", "")
    let ciphertext = extractStringField(compact, "ct")
    let tag = extractStringField(compact, "tag")
    ContractAeadEnvelopeV1(ver, alg, kid, nonce, aad, ciphertext, tag)
}

public func contractEnvelopeToLegacyJsonV1(envelope: ContractAeadEnvelopeV1): String {
    "{\"v\":1,\"alg\":\"${envelope.alg}\",\"kid\":\"${envelope.kid}\",\"nonce\":\"${envelope.nonce}\",\"aad\":\"${envelope.aad}\",\"ct\":\"${envelope.ciphertext}\",\"tag\":\"${envelope.tag}\"}"
}

public class ContractX509PinPolicy {
    public let allowedLeafDerSha256: Array<Array<Byte>>
    public let allowedLeafSpkiSha256: Array<Array<Byte>>

    public init(
        allowedLeafDerSha256!: Array<Array<Byte>> = [],
        allowedLeafSpkiSha256!: Array<Array<Byte>> = []
    ) {
        this.allowedLeafDerSha256 = clonePinList(allowedLeafDerSha256, "leaf DER")
        this.allowedLeafSpkiSha256 = clonePinList(allowedLeafSpkiSha256, "leaf SPKI")
    }
}

public class ContractX509VerifyResult {
    public let chainLength: Int64
    public let leafSubjectCommonName: String
    public let leafIssuerCommonName: String
    public let trustAnchorCommonName: String
    public let leafDerSha256: Array<Byte>
    public let leafSpkiSha256: Array<Byte>

    public init(
        chainLength: Int64,
        leafSubjectCommonName: String,
        leafIssuerCommonName: String,
        trustAnchorCommonName: String,
        leafDerSha256: Array<Byte>,
        leafSpkiSha256: Array<Byte>
    ) {
        if (chainLength <= 0) {
            throw ContractException(ContractErrorCode.BadInput, "verified certificate chain length must be > 0")
        }
        requireSha256Pin(leafDerSha256, "leafDerSha256")
        requireSha256Pin(leafSpkiSha256, "leafSpkiSha256")
        this.chainLength = chainLength
        this.leafSubjectCommonName = leafSubjectCommonName
        this.leafIssuerCommonName = leafIssuerCommonName
        this.trustAnchorCommonName = trustAnchorCommonName
        this.leafDerSha256 = leafDerSha256.clone()
        this.leafSpkiSha256 = leafSpkiSha256.clone()
    }
}

public class ContractX509VerifyOutcome {
    public let ok: Bool
    public let code: ContractErrorCode
    public let message: String
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractX509VerifyResult

    public init(
        ok: Bool,
        code: ContractErrorCode,
        message: String,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractX509VerifyResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "x509 verify outcome message must not be empty")
        }
        if (ok) {
            match (igniteCode) {
                case Some(_) =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "x509 verify outcome ignite code must be empty when ok is true"
                    )
                case None => ()
            }
            match (result) {
                case Some(_value) =>
                    ()
                case None =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "x509 verify outcome result must exist when ok is true"
                    )
            }
        } else {
            match (igniteCode) {
                case Some(_value) => ()
                case None =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "x509 verify outcome ignite code must exist when ok is false"
                    )
            }
        }
        this.ok = ok
        this.code = code
        this.message = message.trimAscii()
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractEnvelopeOpenOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let plaintext: ?Array<Byte>

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        plaintext!: ?Array<Byte> = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "envelope outcome message must not be empty")
        }
        if (ok) {
            match (code) {
                case Some(_) =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "envelope outcome code must be empty when ok is true"
                    )
                case None => ()
            }
            match (igniteCode) {
                case Some(_) =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "envelope outcome ignite code must be empty when ok is true"
                    )
                case None => ()
            }
            match (plaintext) {
                case Some(_value) => ()
                case None =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "envelope outcome plaintext must exist when ok is true"
                    )
            }
        } else {
            match (code) {
                case Some(_value) => ()
                case None =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "envelope outcome code must exist when ok is false"
                    )
            }
            match (igniteCode) {
                case Some(_value) => ()
                case None =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "envelope outcome ignite code must exist when ok is false"
                    )
            }
            match (plaintext) {
                case Some(_) =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "envelope outcome plaintext must be empty when ok is false"
                    )
                case None => ()
            }
        }
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.plaintext = contractCloneOptionalBytes(plaintext)
    }
}

public class ContractHttpServerTlsConfigValidationResult {
    public let certificateChainLength: Int64
    public let leafSubjectCommonName: String
    public let leafIssuerCommonName: String
    public let keyAlgorithm: String
    public let normalizedAlpnProtocols: Array<String>

    public init(
        certificateChainLength: Int64,
        leafSubjectCommonName: String,
        leafIssuerCommonName: String,
        keyAlgorithm: String,
        normalizedAlpnProtocols: Array<String>
    ) {
        if (certificateChainLength <= 0) {
            throw ContractException(ContractErrorCode.BadInput, "certificate chain must contain at least one certificate")
        }
        let normalizedKeyAlgorithm = keyAlgorithm.trimAscii().toAsciiUpper()
        if (normalizedKeyAlgorithm != "RSA" && normalizedKeyAlgorithm != "EC") {
            throw ContractException(ContractErrorCode.BadInput, "TLS server key algorithm must be RSA or EC")
        }
        if (normalizedAlpnProtocols.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS ALPN protocol list must not be empty")
        }
        this.certificateChainLength = certificateChainLength
        this.leafSubjectCommonName = leafSubjectCommonName
        this.leafIssuerCommonName = leafIssuerCommonName
        this.keyAlgorithm = normalizedKeyAlgorithm
        this.normalizedAlpnProtocols = normalizedAlpnProtocols.clone()
    }
}

public class ContractHttpServerTlsConfigValidationOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractHttpServerTlsConfigValidationResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractHttpServerTlsConfigValidationResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS config validation outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "TLS config validation outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractHttpServerTlsMaterial {
    public let validation: ContractHttpServerTlsConfigValidationResult
    public let certificateChainPemBlocks: Array<String>
    public let privateKeyPem: String

    public init(
        validation: ContractHttpServerTlsConfigValidationResult,
        certificateChainPemBlocks: Array<String>,
        privateKeyPem: String
    ) {
        if (certificateChainPemBlocks.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS server certificate PEM blocks must not be empty")
        }
        if (Int64(certificateChainPemBlocks.size) != validation.certificateChainLength) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS server certificate PEM block count must match validation result"
            )
        }
        let normalizedPrivateKeyPem = privateKeyPem.trimAscii()
        if (normalizedPrivateKeyPem.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS server private key PEM must not be empty")
        }
        this.validation = validation
        this.certificateChainPemBlocks = contractCloneTrimmedPemBlocks(
            certificateChainPemBlocks,
            "TLS server certificate PEM"
        )
        this.privateKeyPem = normalizedPrivateKeyPem
    }

    public func leafCertificatePem(): String {
        certificateChainPemBlocks[0]
    }

    public func certificateChainPemBundle(): String {
        contractJoinPemBlocks(certificateChainPemBlocks)
    }
}

public class ContractHttpServerTlsMaterialOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractHttpServerTlsMaterial

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractHttpServerTlsMaterial = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS server material outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "TLS server material outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractHttpClientTlsConfigValidationResult {
    public let trustAnchorCount: Int64
    public let intermediateCount: Int64
    public let normalizedHostname: String
    public let hasValidationTimeOverride: Bool
    public let allowedLeafDerPinCount: Int64
    public let allowedLeafSpkiPinCount: Int64
    public let negotiationPolicy: ContractTlsHttpNegotiationPolicyValidationResult

    public init(
        trustAnchorCount: Int64,
        intermediateCount: Int64,
        normalizedHostname: String,
        hasValidationTimeOverride: Bool,
        allowedLeafDerPinCount: Int64,
        allowedLeafSpkiPinCount: Int64,
        negotiationPolicy: ContractTlsHttpNegotiationPolicyValidationResult
    ) {
        if (trustAnchorCount <= 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS client trust anchors must not be empty")
        }
        if (intermediateCount < 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS client intermediate count must not be negative")
        }
        if (allowedLeafDerPinCount < 0 || allowedLeafSpkiPinCount < 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS client pin counts must not be negative")
        }
        if (negotiationPolicy.requireServerName && normalizedHostname.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS client hostname must not be empty when negotiation policy requires server name"
            )
        }
        this.trustAnchorCount = trustAnchorCount
        this.intermediateCount = intermediateCount
        this.normalizedHostname = normalizedHostname.trimAscii().toAsciiLower()
        this.hasValidationTimeOverride = hasValidationTimeOverride
        this.allowedLeafDerPinCount = allowedLeafDerPinCount
        this.allowedLeafSpkiPinCount = allowedLeafSpkiPinCount
        this.negotiationPolicy = negotiationPolicy
    }
}

public class ContractHttpClientTlsTrustMaterial {
    public let validation: ContractHttpClientTlsConfigValidationResult
    public let trustAnchorPemBlocks: Array<String>
    public let intermediatePemBlocks: Array<String>
    public let validationTime: String
    public let pinPolicy: ContractX509PinPolicy

    public init(
        validation: ContractHttpClientTlsConfigValidationResult,
        trustAnchorPemBlocks: Array<String>,
        intermediatePemBlocks!: Array<String> = [],
        validationTime!: String = "",
        pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy()
    ) {
        if (trustAnchorPemBlocks.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS client trust anchor PEM blocks must not be empty")
        }
        if (Int64(trustAnchorPemBlocks.size) != validation.trustAnchorCount) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS client trust anchor PEM block count must match validation result"
            )
        }
        if (Int64(intermediatePemBlocks.size) != validation.intermediateCount) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS client intermediate PEM block count must match validation result"
            )
        }
        this.validation = validation
        this.trustAnchorPemBlocks = contractCloneTrimmedPemBlocks(
            trustAnchorPemBlocks,
            "TLS client trust anchor PEM"
        )
        this.intermediatePemBlocks = contractCloneTrimmedPemBlocks(
            intermediatePemBlocks,
            "TLS client intermediate PEM"
        )
        this.validationTime = validationTime.trimAscii()
        this.pinPolicy = ContractX509PinPolicy(
            allowedLeafDerSha256: pinPolicy.allowedLeafDerSha256,
            allowedLeafSpkiSha256: pinPolicy.allowedLeafSpkiSha256
        )
    }

    public func trustAnchorsPemBundle(): String {
        contractJoinPemBlocks(trustAnchorPemBlocks)
    }

    public func intermediatesPemBundle(): String {
        contractJoinPemBlocks(intermediatePemBlocks)
    }
}

public class ContractHttpClientTlsTrustMaterialOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractHttpClientTlsTrustMaterial

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractHttpClientTlsTrustMaterial = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS client material outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "TLS client material outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractHttpClientTlsConfigValidationOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractHttpClientTlsConfigValidationResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractHttpClientTlsConfigValidationResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS client config validation outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "TLS client config validation outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractHttpServerTlsConfigRequest {
    public let certificateChainPem: String
    public let privateKeyPem: String
    public let alpnProtocols: Array<String>
    public let requireHttp2Alpn: Bool

    public init(
        certificateChainPem: String,
        privateKeyPem: String,
        alpnProtocols!: Array<String> = ["h2", "http/1.1"],
        requireHttp2Alpn!: Bool = true
    ) {
        if (certificateChainPem.trimAscii().size == 0 || privateKeyPem.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "HTTP server TLS config request fields are invalid"
            )
        }
        this.certificateChainPem = certificateChainPem
        this.privateKeyPem = privateKeyPem
        this.alpnProtocols = alpnProtocols.clone()
        this.requireHttp2Alpn = requireHttp2Alpn
    }
}

public class ContractHttpClientTlsTrustRequest {
    public let trustAnchorsPemBundle: String
    public let intermediatesPemBundle: String
    public let hostname: String
    public let validationTime: String
    public let pinPolicy: ContractX509PinPolicy
    public let policy: ContractTlsHttpNegotiationPolicy

    public init(
        trustAnchorsPemBundle: String,
        intermediatesPemBundle!: String = "",
        hostname!: String = "",
        validationTime!: String = "",
        pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
        policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
    ) {
        if (trustAnchorsPemBundle.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "HTTP client TLS trust request trust anchors must not be empty"
            )
        }
        this.trustAnchorsPemBundle = trustAnchorsPemBundle
        this.intermediatesPemBundle = intermediatesPemBundle
        this.hostname = hostname
        this.validationTime = validationTime
        this.pinPolicy = ContractX509PinPolicy(
            allowedLeafDerSha256: pinPolicy.allowedLeafDerSha256,
            allowedLeafSpkiSha256: pinPolicy.allowedLeafSpkiSha256
        )
        this.policy = ContractTlsHttpNegotiationPolicy(
            requireServerName: policy.requireServerName,
            allowedServerNames: policy.allowedServerNames,
            alpnPreference: policy.alpnPreference
        )
    }
}

public class ContractHttpClientTlsPeerPemRequest {
    public let leafPem: String
    public let trust: ContractHttpClientTlsTrustRequest

    public init(
        leafPem: String,
        trust: ContractHttpClientTlsTrustRequest
    ) {
        if (leafPem.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "HTTP client TLS peer PEM request leaf certificate must not be empty"
            )
        }
        this.leafPem = leafPem
        this.trust = trust
    }
}

public class ContractHttpClientTlsPeerChainRequest {
    public let certificateChainPemBundle: String
    public let trust: ContractHttpClientTlsTrustRequest

    public init(
        certificateChainPemBundle: String,
        trust: ContractHttpClientTlsTrustRequest
    ) {
        if (certificateChainPemBundle.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "HTTP client TLS peer chain request certificate chain must not be empty"
            )
        }
        this.certificateChainPemBundle = certificateChainPemBundle
        this.trust = trust
    }
}

public class ContractTlsHttpNegotiationPolicyValidationResult {
    public let requireServerName: Bool
    public let normalizedAllowedServerNames: Array<String>
    public let normalizedAlpnPreference: Array<String>

    public init(
        requireServerName: Bool,
        normalizedAllowedServerNames: Array<String>,
        normalizedAlpnPreference: Array<String>
    ) {
        if (normalizedAlpnPreference.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS HTTP negotiation ALPN preference must not be empty")
        }
        this.requireServerName = requireServerName
        this.normalizedAllowedServerNames = normalizedAllowedServerNames.clone()
        this.normalizedAlpnPreference = normalizedAlpnPreference.clone()
    }
}

public class ContractTlsHttpNegotiationPolicyValidationOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractTlsHttpNegotiationPolicyValidationResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractTlsHttpNegotiationPolicyValidationResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS HTTP negotiation policy validation outcome message must not be empty"
            )
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "TLS HTTP negotiation policy validation outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractSshNegotiatedAlgorithms {
    public let kexAlgorithm: String
    public let serverHostKeyAlgorithm: String
    public let encryptionAlgorithmClientToServer: String
    public let encryptionAlgorithmServerToClient: String
    public let macAlgorithmClientToServer: String
    public let macAlgorithmServerToClient: String
    public let compressionAlgorithmClientToServer: String
    public let compressionAlgorithmServerToClient: String

    public init(
        kexAlgorithm: String,
        serverHostKeyAlgorithm: String,
        encryptionAlgorithmClientToServer: String,
        encryptionAlgorithmServerToClient: String,
        macAlgorithmClientToServer: String,
        macAlgorithmServerToClient: String,
        compressionAlgorithmClientToServer!: String = "none",
        compressionAlgorithmServerToClient!: String = "none"
    ) {
        if (
            kexAlgorithm.trimAscii().size == 0 ||
            serverHostKeyAlgorithm.trimAscii().size == 0 ||
            encryptionAlgorithmClientToServer.trimAscii().size == 0 ||
            encryptionAlgorithmServerToClient.trimAscii().size == 0 ||
            macAlgorithmClientToServer.trimAscii().size == 0 ||
            macAlgorithmServerToClient.trimAscii().size == 0 ||
            compressionAlgorithmClientToServer.trimAscii().size == 0 ||
            compressionAlgorithmServerToClient.trimAscii().size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH negotiated algorithms must not contain empty fields"
            )
        }
        this.kexAlgorithm = kexAlgorithm.trimAscii()
        this.serverHostKeyAlgorithm = serverHostKeyAlgorithm.trimAscii()
        this.encryptionAlgorithmClientToServer = encryptionAlgorithmClientToServer.trimAscii()
        this.encryptionAlgorithmServerToClient = encryptionAlgorithmServerToClient.trimAscii()
        this.macAlgorithmClientToServer = macAlgorithmClientToServer.trimAscii()
        this.macAlgorithmServerToClient = macAlgorithmServerToClient.trimAscii()
        this.compressionAlgorithmClientToServer = compressionAlgorithmClientToServer.trimAscii()
        this.compressionAlgorithmServerToClient = compressionAlgorithmServerToClient.trimAscii()
    }
}

public class ContractSshKexExchangeTranscript {
    public let clientBannerLine: Array<Byte>
    public let serverBannerLine: Array<Byte>
    public let clientKexInitPayload: Array<Byte>
    public let serverKexInitPayload: Array<Byte>

    public init(
        clientBannerLine: Array<Byte>,
        serverBannerLine: Array<Byte>,
        clientKexInitPayload: Array<Byte>,
        serverKexInitPayload: Array<Byte>
    ) {
        _ = contractToSshKexExchangeTranscript(
            clientBannerLine,
            serverBannerLine,
            clientKexInitPayload,
            serverKexInitPayload
        )
        this.clientBannerLine = clientBannerLine.clone()
        this.serverBannerLine = serverBannerLine.clone()
        this.clientKexInitPayload = clientKexInitPayload.clone()
        this.serverKexInitPayload = serverKexInitPayload.clone()
    }
}

public class ContractSshKexInitMessage {
    public let cookie: Array<Byte>
    public let kexAlgorithms: Array<String>
    public let serverHostKeyAlgorithms: Array<String>
    public let encryptionAlgorithmsClientToServer: Array<String>
    public let encryptionAlgorithmsServerToClient: Array<String>
    public let macAlgorithmsClientToServer: Array<String>
    public let macAlgorithmsServerToClient: Array<String>
    public let compressionAlgorithmsClientToServer: Array<String>
    public let compressionAlgorithmsServerToClient: Array<String>
    public let languagesClientToServer: Array<String>
    public let languagesServerToClient: Array<String>
    public let firstKexPacketFollows: Bool
    public let reserved: Int64

    public init(
        cookie: Array<Byte>,
        kexAlgorithms: Array<String>,
        serverHostKeyAlgorithms: Array<String>,
        encryptionAlgorithmsClientToServer: Array<String>,
        encryptionAlgorithmsServerToClient: Array<String>,
        macAlgorithmsClientToServer: Array<String>,
        macAlgorithmsServerToClient: Array<String>,
        compressionAlgorithmsClientToServer: Array<String>,
        compressionAlgorithmsServerToClient: Array<String>,
        languagesClientToServer!: Array<String> = [],
        languagesServerToClient!: Array<String> = [],
        firstKexPacketFollows!: Bool = false,
        reserved!: Int64 = 0
    ) {
        _ = contractToSshKexInitMessage(
            cookie,
            kexAlgorithms,
            serverHostKeyAlgorithms,
            encryptionAlgorithmsClientToServer,
            encryptionAlgorithmsServerToClient,
            macAlgorithmsClientToServer,
            macAlgorithmsServerToClient,
            compressionAlgorithmsClientToServer,
            compressionAlgorithmsServerToClient,
            languagesClientToServer: languagesClientToServer,
            languagesServerToClient: languagesServerToClient,
            firstKexPacketFollows: firstKexPacketFollows,
            reserved: reserved
        )
        this.cookie = cookie.clone()
        this.kexAlgorithms = contractCloneStringArray(kexAlgorithms)
        this.serverHostKeyAlgorithms = contractCloneStringArray(serverHostKeyAlgorithms)
        this.encryptionAlgorithmsClientToServer = contractCloneStringArray(encryptionAlgorithmsClientToServer)
        this.encryptionAlgorithmsServerToClient = contractCloneStringArray(encryptionAlgorithmsServerToClient)
        this.macAlgorithmsClientToServer = contractCloneStringArray(macAlgorithmsClientToServer)
        this.macAlgorithmsServerToClient = contractCloneStringArray(macAlgorithmsServerToClient)
        this.compressionAlgorithmsClientToServer = contractCloneStringArray(compressionAlgorithmsClientToServer)
        this.compressionAlgorithmsServerToClient = contractCloneStringArray(compressionAlgorithmsServerToClient)
        this.languagesClientToServer = contractCloneStringArray(languagesClientToServer)
        this.languagesServerToClient = contractCloneStringArray(languagesServerToClient)
        this.firstKexPacketFollows = firstKexPacketFollows
        this.reserved = reserved
    }
}

public class ContractSshBuildDefaultKexInitRequest {
    public let cookie: Array<Byte>

    public init(cookie!: Array<Byte> = []) {
        if (cookie.size != 0 && cookie.size != 16) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH default KEXINIT cookie must be empty or 16 bytes"
            )
        }
        this.cookie = cookie.clone()
    }
}

public class ContractSshEncodeKexInitRequest {
    public let message: ContractSshKexInitMessage

    public init(message: ContractSshKexInitMessage) {
        this.message = message
    }
}

public class ContractSshDecodeKexInitRequest {
    public let encoded: Array<Byte>

    public init(encoded: Array<Byte>) {
        if (encoded.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH encoded KEXINIT payload must not be empty"
            )
        }
        this.encoded = encoded.clone()
    }
}

public class ContractSshNegotiateKexInitRequest {
    public let client: ContractSshKexInitMessage
    public let server: ContractSshKexInitMessage

    public init(client: ContractSshKexInitMessage, server: ContractSshKexInitMessage) {
        this.client = client
        this.server = server
    }
}

public class ContractSshBuildTranscriptFromKexInitRequest {
    public let clientBannerLine: Array<Byte>
    public let serverBannerLine: Array<Byte>
    public let clientKexInit: ContractSshKexInitMessage
    public let serverKexInit: ContractSshKexInitMessage

    public init(
        clientBannerLine: Array<Byte>,
        serverBannerLine: Array<Byte>,
        clientKexInit: ContractSshKexInitMessage,
        serverKexInit: ContractSshKexInitMessage
    ) {
        if (clientBannerLine.size == 0 || serverBannerLine.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH transcript banners must not be empty"
            )
        }
        this.clientBannerLine = clientBannerLine.clone()
        this.serverBannerLine = serverBannerLine.clone()
        this.clientKexInit = clientKexInit
        this.serverKexInit = serverKexInit
    }
}

public class ContractSshX25519InitResult {
    public let encodedInit: Array<Byte>
    public let clientPublicKey: Array<Byte>

    public init(encodedInit: Array<Byte>, clientPublicKey: Array<Byte>) {
        if (encodedInit.size == 0 || clientPublicKey.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH X25519 init result fields must not be empty"
            )
        }
        this.encodedInit = encodedInit.clone()
        this.clientPublicKey = clientPublicKey.clone()
    }
}

public class ContractSshBuildKexEcdhInitX25519Request {
    public let clientPrivateKey: Array<Byte>

    public init(clientPrivateKey: Array<Byte>) {
        if (clientPrivateKey.size != 32) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH X25519 client private key must be 32 bytes"
            )
        }
        this.clientPrivateKey = clientPrivateKey.clone()
    }
}

public class ContractSshServerProcessKexEcdhInitX25519Result {
    public let encodedReply: Array<Byte>
    public let session: ContractSshSessionState

    public init(encodedReply: Array<Byte>, session: ContractSshSessionState) {
        if (encodedReply.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH server KEX reply must not be empty"
            )
        }
        this.encodedReply = encodedReply.clone()
        this.session = session
    }
}

public class ContractSshServerProcessKexEcdhInitX25519Request {
    public let transcript: ContractSshKexExchangeTranscript
    public let serverPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let hostSigning: ContractSshHostSigningResult
    public let serverPublicKey: Array<Byte>

    public init(
        transcript: ContractSshKexExchangeTranscript,
        serverPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        hostSigning: ContractSshHostSigningResult,
        serverPublicKey!: Array<Byte> = []
    ) {
        if (serverPrivateKey.size != 32 || encodedClientInit.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH server KEX request fields are invalid"
            )
        }
        this.transcript = transcript
        this.serverPrivateKey = serverPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.hostSigning = hostSigning
        this.serverPublicKey = serverPublicKey.clone()
    }
}

public class ContractSshClientProcessKexEcdhReplyX25519Request {
    public let transcript: ContractSshKexExchangeTranscript
    public let clientPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let encodedServerReply: Array<Byte>
    public let policy: ContractSshHostVerificationPolicy

    public init(
        transcript: ContractSshKexExchangeTranscript,
        clientPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        encodedServerReply: Array<Byte>,
        policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
    ) {
        if (
            clientPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            encodedServerReply.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH client KEX request fields are invalid"
            )
        }
        this.transcript = transcript
        this.clientPrivateKey = clientPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.encodedServerReply = encodedServerReply.clone()
        this.policy = policy
    }
}

public class ContractSshHostVerificationPolicy {
    public let negotiatedHostKeyAlgorithm: String
    public let expectedHostKeySha256: Array<Byte>
    public let requireKnownHost: Bool
    public let requireHostSignature: Bool
    public let allowLegacyRsaSha1: Bool
    public let requireVerifiedHost: Bool

    public init(
        negotiatedHostKeyAlgorithm!: String = "",
        expectedHostKeySha256!: Array<Byte> = [],
        requireKnownHost!: Bool = false,
        requireHostSignature!: Bool = true,
        allowLegacyRsaSha1!: Bool = false,
        requireVerifiedHost!: Bool = true
    ) {
        let normalizedNegotiated = negotiatedHostKeyAlgorithm.trimAscii().toAsciiLower()
        if (expectedHostKeySha256.size != 0 && expectedHostKeySha256.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "SSH expected host key fingerprint must be SHA-256 sized")
        }
        if (requireKnownHost && expectedHostKeySha256.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH known-host verification requires expected host key fingerprint"
            )
        }

        this.negotiatedHostKeyAlgorithm = normalizedNegotiated
        this.expectedHostKeySha256 = expectedHostKeySha256.clone()
        this.requireKnownHost = requireKnownHost
        this.requireHostSignature = requireHostSignature
        this.allowLegacyRsaSha1 = allowLegacyRsaSha1
        this.requireVerifiedHost = requireVerifiedHost
    }
}

public class ContractSshHostVerificationResult {
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>
    public let hostSignatureVerified: Bool

    public init(
        hostKeyAlgorithm: String,
        hostSignatureAlgorithm: String,
        hostKeySha256: Array<Byte>,
        hostSignatureVerified: Bool
    ) {
        if (hostKeyAlgorithm.size == 0 || hostSignatureAlgorithm.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH host verification algorithms must not be empty")
        }
        if (hostKeySha256.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "SSH host key fingerprint must be SHA-256 sized")
        }
        this.hostKeyAlgorithm = hostKeyAlgorithm
        this.hostSignatureAlgorithm = hostSignatureAlgorithm
        this.hostKeySha256 = hostKeySha256.clone()
        this.hostSignatureVerified = hostSignatureVerified
    }
}

public class ContractSshHostVerificationOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractSshHostVerificationResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractSshHostVerificationResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH host verification outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "SSH host verification outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractSshHostSigningResult {
    public let serverHostKey: Array<Byte>
    public let hostSignature: Array<Byte>
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>

    public init(
        serverHostKey: Array<Byte>,
        hostSignature: Array<Byte>,
        hostKeyAlgorithm: String,
        hostSignatureAlgorithm: String,
        hostKeySha256: Array<Byte>
    ) {
        if (serverHostKey.size == 0 || hostSignature.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH host signing result fields must not be empty")
        }
        if (hostKeyAlgorithm.size == 0 || hostSignatureAlgorithm.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH host signing algorithms must not be empty")
        }
        if (hostKeySha256.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "SSH host signing fingerprint must be SHA-256 sized")
        }
        this.serverHostKey = serverHostKey.clone()
        this.hostSignature = hostSignature.clone()
        this.hostKeyAlgorithm = hostKeyAlgorithm
        this.hostSignatureAlgorithm = hostSignatureAlgorithm
        this.hostKeySha256 = hostKeySha256.clone()
    }
}

public class ContractSshHostSigningOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractSshHostSigningResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractSshHostSigningResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH host signing outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "SSH host signing outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractSshHostSigningRsaPkcs8Request {
    public let hostPrivateKeyPkcs8Pem: String
    public let exchangeHash: Array<Byte>
    public let signatureAlgorithm: String

    public init(
        hostPrivateKeyPkcs8Pem: String,
        exchangeHash: Array<Byte>,
        signatureAlgorithm!: String = "rsa-sha2-256"
    ) {
        if (
            hostPrivateKeyPkcs8Pem.trimAscii().size == 0 ||
            exchangeHash.size == 0 ||
            signatureAlgorithm.trimAscii().size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH RSA host signing request fields are invalid"
            )
        }
        this.hostPrivateKeyPkcs8Pem = hostPrivateKeyPkcs8Pem
        this.exchangeHash = exchangeHash.clone()
        this.signatureAlgorithm = signatureAlgorithm.trimAscii()
    }
}

public class ContractSshHostSigningEcdsaPkcs8Request {
    public let hostPrivateKeyPkcs8Pem: String
    public let exchangeHash: Array<Byte>

    public init(
        hostPrivateKeyPkcs8Pem: String,
        exchangeHash: Array<Byte>
    ) {
        if (
            hostPrivateKeyPkcs8Pem.trimAscii().size == 0 ||
            exchangeHash.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH ECDSA host signing request fields are invalid"
            )
        }
        this.hostPrivateKeyPkcs8Pem = hostPrivateKeyPkcs8Pem
        this.exchangeHash = exchangeHash.clone()
    }
}

public class ContractSshHostSigningEd25519SeedRequest {
    public let hostPrivateKeySeed: Array<Byte>
    public let exchangeHash: Array<Byte>

    public init(
        hostPrivateKeySeed: Array<Byte>,
        exchangeHash: Array<Byte>
    ) {
        if (
            hostPrivateKeySeed.size != 32 ||
            exchangeHash.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH Ed25519 host signing request fields are invalid"
            )
        }
        this.hostPrivateKeySeed = hostPrivateKeySeed.clone()
        this.exchangeHash = exchangeHash.clone()
    }
}

public class ContractSshServerInitialHandshakeX25519RsaRequest {
    public let transcript: ContractSshKexExchangeTranscript
    public let serverPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let hostPrivateKey: RsaPrivateKey
    public let negotiated: ContractSshNegotiatedAlgorithms
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let signatureAlgorithm: String
    public let serverPublicKey: Array<Byte>

    public init(
        transcript: ContractSshKexExchangeTranscript,
        serverPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        hostPrivateKey: RsaPrivateKey,
        negotiated: ContractSshNegotiatedAlgorithms,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        signatureAlgorithm!: String = "rsa-sha2-256",
        serverPublicKey!: Array<Byte> = []
    ) {
        if (
            serverPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            encodedClientNewKeys.size == 0 ||
            encodedServerNewKeys.size == 0 ||
            signatureAlgorithm.trimAscii().size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH RSA server handshake request fields are invalid"
            )
        }
        this.transcript = transcript
        this.serverPrivateKey = serverPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.hostPrivateKey = hostPrivateKey
        this.negotiated = negotiated
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.signatureAlgorithm = signatureAlgorithm.trimAscii()
        this.serverPublicKey = serverPublicKey.clone()
    }
}

public class ContractSshServerInitialHandshakeX25519EcdsaRequest {
    public let transcript: ContractSshKexExchangeTranscript
    public let serverPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let hostPrivateKey: EcPrivateKey
    public let negotiated: ContractSshNegotiatedAlgorithms
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let serverPublicKey: Array<Byte>

    public init(
        transcript: ContractSshKexExchangeTranscript,
        serverPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        hostPrivateKey: EcPrivateKey,
        negotiated: ContractSshNegotiatedAlgorithms,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        serverPublicKey!: Array<Byte> = []
    ) {
        if (
            serverPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            encodedClientNewKeys.size == 0 ||
            encodedServerNewKeys.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH ECDSA server handshake request fields are invalid"
            )
        }
        this.transcript = transcript
        this.serverPrivateKey = serverPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.hostPrivateKey = hostPrivateKey
        this.negotiated = negotiated
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.serverPublicKey = serverPublicKey.clone()
    }
}

public class ContractSshServerInitialHandshakeX25519Ed25519Request {
    public let transcript: ContractSshKexExchangeTranscript
    public let serverPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let hostPrivateKeySeed: Array<Byte>
    public let negotiated: ContractSshNegotiatedAlgorithms
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let serverPublicKey: Array<Byte>

    public init(
        transcript: ContractSshKexExchangeTranscript,
        serverPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        hostPrivateKeySeed: Array<Byte>,
        negotiated: ContractSshNegotiatedAlgorithms,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        serverPublicKey!: Array<Byte> = []
    ) {
        if (
            serverPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            hostPrivateKeySeed.size != 32 ||
            encodedClientNewKeys.size == 0 ||
            encodedServerNewKeys.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH Ed25519 server handshake request fields are invalid"
            )
        }
        this.transcript = transcript
        this.serverPrivateKey = serverPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.hostPrivateKeySeed = hostPrivateKeySeed.clone()
        this.negotiated = negotiated
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.serverPublicKey = serverPublicKey.clone()
    }
}

public class ContractSshClientInitialHandshakeX25519Request {
    public let transcript: ContractSshKexExchangeTranscript
    public let clientPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let encodedServerReply: Array<Byte>
    public let negotiated: ContractSshNegotiatedAlgorithms
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let policy: ContractSshHostVerificationPolicy

    public init(
        transcript: ContractSshKexExchangeTranscript,
        clientPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        encodedServerReply: Array<Byte>,
        negotiated: ContractSshNegotiatedAlgorithms,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
    ) {
        if (
            clientPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            encodedServerReply.size == 0 ||
            encodedClientNewKeys.size == 0 ||
            encodedServerNewKeys.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH client handshake request fields are invalid"
            )
        }
        this.transcript = transcript
        this.clientPrivateKey = clientPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.encodedServerReply = encodedServerReply.clone()
        this.negotiated = negotiated
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.policy = policy
    }
}

public class ContractSshServerInitialHandshakeResult {
    public let encodedReply: Array<Byte>
    public let sharedSecret: Array<Byte>
    public let exchangeHash: Array<Byte>
    public let sessionId: Array<Byte>
    public let clientEphemeralPublicKey: Array<Byte>
    public let serverEphemeralPublicKey: Array<Byte>
    public let serverHostKey: Array<Byte>
    public let hostSignature: Array<Byte>
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>
    let _transport: ContractSshTransportChannel

    public init(
        encodedReply: Array<Byte>,
        sharedSecret: Array<Byte>,
        exchangeHash: Array<Byte>,
        sessionId: Array<Byte>,
        clientEphemeralPublicKey: Array<Byte>,
        serverEphemeralPublicKey: Array<Byte>,
        serverHostKey: Array<Byte>,
        hostSignature: Array<Byte>,
        hostKeyAlgorithm: String,
        hostSignatureAlgorithm: String,
        hostKeySha256: Array<Byte>,
        transport: ContractSshTransportChannel
    ) {
        if (
            encodedReply.size == 0 ||
            sharedSecret.size == 0 ||
            exchangeHash.size == 0 ||
            sessionId.size == 0 ||
            clientEphemeralPublicKey.size == 0 ||
            serverEphemeralPublicKey.size == 0 ||
            serverHostKey.size == 0 ||
            hostSignature.size == 0
        ) {
            throw ContractException(ContractErrorCode.BadInput, "SSH server handshake result fields must not be empty")
        }
        if (hostKeyAlgorithm.size == 0 || hostSignatureAlgorithm.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH server handshake algorithms must not be empty")
        }
        if (hostKeySha256.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "SSH server handshake fingerprint must be SHA-256 sized")
        }
        this.encodedReply = encodedReply.clone()
        this.sharedSecret = sharedSecret.clone()
        this.exchangeHash = exchangeHash.clone()
        this.sessionId = sessionId.clone()
        this.clientEphemeralPublicKey = clientEphemeralPublicKey.clone()
        this.serverEphemeralPublicKey = serverEphemeralPublicKey.clone()
        this.serverHostKey = serverHostKey.clone()
        this.hostSignature = hostSignature.clone()
        this.hostKeyAlgorithm = hostKeyAlgorithm
        this.hostSignatureAlgorithm = hostSignatureAlgorithm
        this.hostKeySha256 = hostKeySha256.clone()
        this._transport = transport
    }

    public func transport(): ContractSshTransportChannel {
        _transport
    }
}

public class ContractSshClientInitialHandshakeResult {
    public let sharedSecret: Array<Byte>
    public let exchangeHash: Array<Byte>
    public let sessionId: Array<Byte>
    public let clientEphemeralPublicKey: Array<Byte>
    public let serverEphemeralPublicKey: Array<Byte>
    public let serverHostKey: Array<Byte>
    public let hostSignature: Array<Byte>
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>
    public let hostVerification: ?ContractSshHostVerificationResult
    let _transport: ContractSshTransportChannel

    public init(
        sharedSecret: Array<Byte>,
        exchangeHash: Array<Byte>,
        sessionId: Array<Byte>,
        clientEphemeralPublicKey: Array<Byte>,
        serverEphemeralPublicKey: Array<Byte>,
        serverHostKey: Array<Byte>,
        hostSignature: Array<Byte>,
        hostKeyAlgorithm: String,
        hostSignatureAlgorithm: String,
        hostKeySha256: Array<Byte>,
        transport: ContractSshTransportChannel,
        hostVerification!: ?ContractSshHostVerificationResult = None
    ) {
        if (
            sharedSecret.size == 0 ||
            exchangeHash.size == 0 ||
            sessionId.size == 0 ||
            clientEphemeralPublicKey.size == 0 ||
            serverEphemeralPublicKey.size == 0 ||
            serverHostKey.size == 0 ||
            hostSignature.size == 0
        ) {
            throw ContractException(ContractErrorCode.BadInput, "SSH client handshake result fields must not be empty")
        }
        if (hostKeyAlgorithm.size == 0 || hostSignatureAlgorithm.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH client handshake algorithms must not be empty")
        }
        if (hostKeySha256.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "SSH client handshake fingerprint must be SHA-256 sized")
        }
        this.sharedSecret = sharedSecret.clone()
        this.exchangeHash = exchangeHash.clone()
        this.sessionId = sessionId.clone()
        this.clientEphemeralPublicKey = clientEphemeralPublicKey.clone()
        this.serverEphemeralPublicKey = serverEphemeralPublicKey.clone()
        this.serverHostKey = serverHostKey.clone()
        this.hostSignature = hostSignature.clone()
        this.hostKeyAlgorithm = hostKeyAlgorithm
        this.hostSignatureAlgorithm = hostSignatureAlgorithm
        this.hostKeySha256 = hostKeySha256.clone()
        this._transport = transport
        this.hostVerification = hostVerification
    }

    public func requireHostVerification(): ContractSshHostVerificationResult {
        match (hostVerification) {
            case Some(value) => value
            case None =>
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "SSH host identity verification is unavailable"
                )
        }
    }

    public func transport(): ContractSshTransportChannel {
        _transport
    }
}

public class ContractSshServerInitialHandshakeOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractSshServerInitialHandshakeResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractSshServerInitialHandshakeResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH server handshake outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "SSH server handshake outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractSshClientInitialHandshakeOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractSshClientInitialHandshakeResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractSshClientInitialHandshakeResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH client handshake outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "SSH client handshake outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractSshSessionState {
    public let sharedSecret: Array<Byte>
    public let exchangeHash: Array<Byte>
    public let sessionId: Array<Byte>
    public let clientEphemeralPublicKey: Array<Byte>
    public let serverEphemeralPublicKey: Array<Byte>
    public let serverHostKey: Array<Byte>
    public let hostSignature: Array<Byte>
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>
    public let hostVerification: ?ContractSshHostVerificationResult

    public init(
        sharedSecret: Array<Byte>,
        exchangeHash: Array<Byte>,
        sessionId: Array<Byte>,
        clientEphemeralPublicKey: Array<Byte>,
        serverEphemeralPublicKey: Array<Byte>,
        serverHostKey: Array<Byte>,
        hostSignature: Array<Byte>,
        hostKeyAlgorithm: String,
        hostSignatureAlgorithm: String,
        hostKeySha256: Array<Byte>,
        hostVerification!: ?ContractSshHostVerificationResult = None
    ) {
        if (
            sharedSecret.size == 0 ||
            exchangeHash.size == 0 ||
            sessionId.size == 0 ||
            clientEphemeralPublicKey.size == 0 ||
            serverEphemeralPublicKey.size == 0 ||
            serverHostKey.size == 0 ||
            hostSignature.size == 0
        ) {
            throw ContractException(ContractErrorCode.BadInput, "SSH session state fields must not be empty")
        }
        if (hostKeyAlgorithm.size == 0 || hostSignatureAlgorithm.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH session state algorithms must not be empty")
        }
        if (hostKeySha256.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "SSH session state fingerprint must be SHA-256 sized")
        }
        this.sharedSecret = sharedSecret.clone()
        this.exchangeHash = exchangeHash.clone()
        this.sessionId = sessionId.clone()
        this.clientEphemeralPublicKey = clientEphemeralPublicKey.clone()
        this.serverEphemeralPublicKey = serverEphemeralPublicKey.clone()
        this.serverHostKey = serverHostKey.clone()
        this.hostSignature = hostSignature.clone()
        this.hostKeyAlgorithm = hostKeyAlgorithm
        this.hostSignatureAlgorithm = hostSignatureAlgorithm
        this.hostKeySha256 = hostKeySha256.clone()
        this.hostVerification = hostVerification
    }

    public func requireHostVerification(): ContractSshHostVerificationResult {
        match (hostVerification) {
            case Some(value) => value
            case None =>
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "SSH host identity verification is unavailable"
                )
        }
    }
}

public class ContractSshServerRuntime {
    public let initialHandshake: ContractSshServerInitialHandshakeResult
    let _currentSession: ContractSshSessionState

    public init(
        initialHandshake: ContractSshServerInitialHandshakeResult,
        currentSession!: ?ContractSshSessionState = None
    ) {
        this.initialHandshake = initialHandshake
        this._currentSession = contractResolveSshServerRuntimeSessionState(
            initialHandshake,
            currentSession
        )
    }

    public prop writeSequence: Int64 {
        get() {
            initialHandshake.transport().writeSequence
        }
    }

    public prop readSequence: Int64 {
        get() {
            initialHandshake.transport().readSequence
        }
    }

    public func sessionId(): Array<Byte> {
        initialHandshake.transport().sessionId()
    }

    public func currentSession(): ContractSshSessionState {
        _currentSession
    }

    public func transport(): ContractSshTransportChannel {
        initialHandshake.transport()
    }

    public func resetTransportCounters(): Unit {
        initialHandshake.transport().resetTransportCounters()
    }

    public func seal(payload: Array<Byte>, randomPadding!: Array<Byte> = []): Array<Byte> {
        initialHandshake.transport().seal(payload, randomPadding: randomPadding)
    }

    public func open(encodedPacket: Array<Byte>): ContractSshTransportPacket {
        initialHandshake.transport().open(encodedPacket)
    }
}

public class ContractSshClientRuntime {
    public let initialHandshake: ContractSshClientInitialHandshakeResult
    let _currentSession: ContractSshSessionState

    public init(
        initialHandshake: ContractSshClientInitialHandshakeResult,
        currentSession!: ?ContractSshSessionState = None
    ) {
        this.initialHandshake = initialHandshake
        this._currentSession = contractResolveSshClientRuntimeSessionState(
            initialHandshake,
            currentSession
        )
    }

    public prop writeSequence: Int64 {
        get() {
            initialHandshake.transport().writeSequence
        }
    }

    public prop readSequence: Int64 {
        get() {
            initialHandshake.transport().readSequence
        }
    }

    public func sessionId(): Array<Byte> {
        initialHandshake.transport().sessionId()
    }

    public func currentSession(): ContractSshSessionState {
        _currentSession
    }

    public func transport(): ContractSshTransportChannel {
        initialHandshake.transport()
    }

    public func hostVerification(): ?ContractSshHostVerificationResult {
        _currentSession.hostVerification
    }

    public func requireHostVerification(): ContractSshHostVerificationResult {
        _currentSession.requireHostVerification()
    }

    public func resetTransportCounters(): Unit {
        initialHandshake.transport().resetTransportCounters()
    }

    public func seal(payload: Array<Byte>, randomPadding!: Array<Byte> = []): Array<Byte> {
        initialHandshake.transport().seal(payload, randomPadding: randomPadding)
    }

    public func open(encodedPacket: Array<Byte>): ContractSshTransportPacket {
        initialHandshake.transport().open(encodedPacket)
    }
}

public class ContractSshServerRuntimeRequest {
    public let result: ContractSshServerInitialHandshakeResult

    public init(result: ContractSshServerInitialHandshakeResult) {
        this.result = result
    }
}

public class ContractSshClientRuntimeRequest {
    public let result: ContractSshClientInitialHandshakeResult

    public init(result: ContractSshClientInitialHandshakeResult) {
        this.result = result
    }
}

public class ContractSshServerRuntimeRekeyRequest {
    public let runtime: ContractSshServerRuntime
    public let kexResult: SshX25519KexResult
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>

    public init(
        runtime: ContractSshServerRuntime,
        kexResult: SshX25519KexResult,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>
    ) {
        if (encodedClientNewKeys.size == 0 || encodedServerNewKeys.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH server runtime rekey NEWKEYS frames must not be empty"
            )
        }
        this.runtime = runtime
        this.kexResult = kexResult
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
    }
}

public class ContractSshClientRuntimeRekeyRequest {
    public let runtime: ContractSshClientRuntime
    public let kexResult: SshX25519KexResult
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let policy: ContractSshHostVerificationPolicy

    public init(
        runtime: ContractSshClientRuntime,
        kexResult: SshX25519KexResult,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
    ) {
        if (encodedClientNewKeys.size == 0 || encodedServerNewKeys.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH client runtime rekey NEWKEYS frames must not be empty"
            )
        }
        this.runtime = runtime
        this.kexResult = kexResult
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.policy = policy
    }
}

public class ContractSshServerRuntimeSessionRekeyRequest {
    public let runtime: ContractSshServerRuntime
    public let session: ContractSshSessionState
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>

    public init(
        runtime: ContractSshServerRuntime,
        session: ContractSshSessionState,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>
    ) {
        if (encodedClientNewKeys.size == 0 || encodedServerNewKeys.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH server runtime session rekey NEWKEYS frames must not be empty"
            )
        }
        this.runtime = runtime
        this.session = session
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
    }
}

public class ContractSshClientRuntimeSessionRekeyRequest {
    public let runtime: ContractSshClientRuntime
    public let session: ContractSshSessionState
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let policy: ContractSshHostVerificationPolicy

    public init(
        runtime: ContractSshClientRuntime,
        session: ContractSshSessionState,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
    ) {
        if (encodedClientNewKeys.size == 0 || encodedServerNewKeys.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH client runtime session rekey NEWKEYS frames must not be empty"
            )
        }
        this.runtime = runtime
        this.session = session
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.policy = policy
    }
}

public class ContractSshServerRuntimeRekeyResult {
    public let runtime: ContractSshServerRuntime
    public let session: ContractSshSessionState

    public init(
        runtime: ContractSshServerRuntime,
        session: ContractSshSessionState
    ) {
        this.runtime = runtime
        this.session = session
    }
}

public class ContractSshClientRuntimeRekeyResult {
    public let runtime: ContractSshClientRuntime
    public let session: ContractSshSessionState

    public init(
        runtime: ContractSshClientRuntime,
        session: ContractSshSessionState
    ) {
        this.runtime = runtime
        this.session = session
    }
}

public class ContractSshTransportPacket {
    public let packetLength: Int64
    public let payload: Array<Byte>
    public let padding: Array<Byte>

    public init(packetLength: Int64, payload: Array<Byte>, padding: Array<Byte>) {
        if (packetLength <= 0) {
            throw ContractException(ContractErrorCode.BadInput, "SSH packet length must be positive")
        }
        this.packetLength = packetLength
        this.payload = payload.clone()
        this.padding = padding.clone()
    }
}

public class ContractSshTransportChannel {
    let _coordinator: SshHandshakeCoordinator

    public init(coordinator: SshHandshakeCoordinator) {
        if (!coordinator.isActive) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH transport channel requires an active handshake coordinator"
            )
        }
        this._coordinator = coordinator
    }

    public prop writeSequence: Int64 {
        get() {
            try {
                _coordinator.writeSequence
            } catch (e: CryptoException) {
                throw ContractException(
                    mapCryptoErrorForOperation(e, "ssh"),
                    "SSH write sequence is unavailable: ${e.message}"
                )
            }
        }
    }

    public prop readSequence: Int64 {
        get() {
            try {
                _coordinator.readSequence
            } catch (e: CryptoException) {
                throw ContractException(
                    mapCryptoErrorForOperation(e, "ssh"),
                    "SSH read sequence is unavailable: ${e.message}"
                )
            }
        }
    }

    public func sessionId(): Array<Byte> {
        try {
            _coordinator.sessionId()
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "ssh"),
                "SSH session id is unavailable: ${e.message}"
            )
        }
    }

    public func resetTransportCounters(): Unit {
        try {
            _coordinator.resetTransportCounters()
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "ssh"),
                "SSH transport counter reset failed: ${e.message}"
            )
        }
    }

    public func seal(payload: Array<Byte>, randomPadding!: Array<Byte> = []): Array<Byte> {
        try {
            _coordinator.seal(payload, randomPadding: randomPadding)
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "ssh"),
                "SSH packet seal failed: ${e.message}"
            )
        }
    }

    public func open(encodedPacket: Array<Byte>): ContractSshTransportPacket {
        try {
            contractFromSshTransportPacket(_coordinator.open(encodedPacket))
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "ssh"),
                "SSH packet open failed: ${e.message}"
            )
        }
    }
}

public class ContractTlsHttpNegotiationPolicy {
    public let requireServerName: Bool
    public let allowedServerNames: Array<String>
    public let alpnPreference: Array<String>

    public init(
        requireServerName!: Bool = true,
        allowedServerNames!: Array<String> = [],
        alpnPreference!: Array<String> = []
    ) {
        this.requireServerName = requireServerName
        this.allowedServerNames = allowedServerNames.clone()
        this.alpnPreference = alpnPreference.clone()
    }
}

public func contractValidateTlsHttpNegotiationPolicy(
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTlsHttpNegotiationPolicyValidationResult {
    try {
        let normalized = contractToTlsHttpNegotiationPolicy(policy)
        ContractTlsHttpNegotiationPolicyValidationResult(
            normalized.requireServerName,
            normalized.allowedServerNames,
            normalized.alpnPreference
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS HTTP negotiation policy validation failed: ${e.message}"
        )
    }
}

public func contractTryValidateTlsHttpNegotiationPolicy(
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTlsHttpNegotiationPolicyValidationOutcome {
    try {
        let result = contractValidateTlsHttpNegotiationPolicy(policy: policy)
        ContractTlsHttpNegotiationPolicyValidationOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractTlsHttpNegotiationPolicyValidationOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public enum ContractTls12KeyExchange <: Equatable<ContractTls12KeyExchange> & ToString {
    | Rsa
    | EcdheP256
    | EcdheP384

    public operator func ==(right: ContractTls12KeyExchange): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractTls12KeyExchange): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Rsa => 0
            case EcdheP256 => 1
            case EcdheP384 => 2
        }
    }

    public func toString(): String {
        match (this) {
            case Rsa => "TLS12-RSA"
            case EcdheP256 => "TLS12-ECDHE-P256"
            case EcdheP384 => "TLS12-ECDHE-P384"
        }
    }
}

public class ContractTls12ClientHello {
    public let encodedClientHello: Array<Byte>
    public let clientRandom: Array<Byte>

    public init(encodedClientHello: Array<Byte>, clientRandom: Array<Byte>) {
        if (encodedClientHello.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 ClientHello must not be empty")
        }
        if (clientRandom.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 client random must be 32 bytes")
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.clientRandom = clientRandom.clone()
    }
}

public class ContractTls12ServerHello {
    public let encodedServerHello: Array<Byte>
    public let serverRandom: Array<Byte>

    public init(encodedServerHello: Array<Byte>, serverRandom: Array<Byte>) {
        if (encodedServerHello.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 ServerHello must not be empty")
        }
        if (serverRandom.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 server random must be 32 bytes")
        }
        this.encodedServerHello = encodedServerHello.clone()
        this.serverRandom = serverRandom.clone()
    }
}

public class ContractTls12RsaClientKeyExchange {
    public let encodedClientKeyExchange: Array<Byte>
    public let preMasterSecret: Array<Byte>

    public init(encodedClientKeyExchange: Array<Byte>, preMasterSecret: Array<Byte>) {
        if (encodedClientKeyExchange.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 RSA ClientKeyExchange must not be empty")
        }
        if (preMasterSecret.size != 48) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 RSA pre-master secret must be 48 bytes")
        }
        this.encodedClientKeyExchange = encodedClientKeyExchange.clone()
        this.preMasterSecret = preMasterSecret.clone()
    }
}

public class ContractTls12EcdheServerKeyExchange {
    public let encodedServerKeyExchange: Array<Byte>
    public let serverPrivateScalar: Array<Byte>

    public init(encodedServerKeyExchange: Array<Byte>, serverPrivateScalar: Array<Byte>) {
        if (encodedServerKeyExchange.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 ECDHE ServerKeyExchange must not be empty")
        }
        if (serverPrivateScalar.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 ECDHE server private scalar must not be empty")
        }
        this.encodedServerKeyExchange = encodedServerKeyExchange.clone()
        this.serverPrivateScalar = serverPrivateScalar.clone()
    }
}

public class ContractTls12EcdheClientKeyExchange {
    public let encodedClientKeyExchange: Array<Byte>
    public let clientPrivateScalar: Array<Byte>

    public init(encodedClientKeyExchange: Array<Byte>, clientPrivateScalar: Array<Byte>) {
        if (encodedClientKeyExchange.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 ECDHE ClientKeyExchange must not be empty")
        }
        if (clientPrivateScalar.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 ECDHE client private scalar must not be empty")
        }
        this.encodedClientKeyExchange = encodedClientKeyExchange.clone()
        this.clientPrivateScalar = clientPrivateScalar.clone()
    }
}

public class ContractTls12HandshakeSecrets {
    public let masterSecret: Array<Byte>
    public let clientWriteKey: Array<Byte>
    public let clientWriteIv: Array<Byte>
    public let serverWriteKey: Array<Byte>
    public let serverWriteIv: Array<Byte>

    public init(
        masterSecret: Array<Byte>,
        clientWriteKey: Array<Byte>,
        clientWriteIv: Array<Byte>,
        serverWriteKey: Array<Byte>,
        serverWriteIv: Array<Byte>
    ) {
        if (
            masterSecret.size == 0 ||
            clientWriteKey.size == 0 ||
            clientWriteIv.size == 0 ||
            serverWriteKey.size == 0 ||
            serverWriteIv.size == 0
        ) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 handshake secrets must not be empty")
        }
        this.masterSecret = masterSecret.clone()
        this.clientWriteKey = clientWriteKey.clone()
        this.clientWriteIv = clientWriteIv.clone()
        this.serverWriteKey = serverWriteKey.clone()
        this.serverWriteIv = serverWriteIv.clone()
    }
}

public class ContractTls12HttpClientHelloRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let sessionId: Array<Byte>
    public let serverName: String
    public let alpnProtocols: Array<String>
    public let requestOcspStapling: Bool

    public init(
        keyExchange: ContractTls12KeyExchange,
        sessionId!: Array<Byte> = [],
        serverName!: String = "",
        alpnProtocols!: Array<String> = [],
        requestOcspStapling!: Bool = false
    ) {
        this.keyExchange = keyExchange
        this.sessionId = sessionId.clone()
        this.serverName = serverName
        this.alpnProtocols = alpnProtocols.clone()
        this.requestOcspStapling = requestOcspStapling
    }
}

public class ContractTls12HttpServerHelloRequest {
    public let encodedClientHello: Array<Byte>
    public let keyExchange: ContractTls12KeyExchange

    public init(
        encodedClientHello: Array<Byte>,
        keyExchange: ContractTls12KeyExchange
    ) {
        if (encodedClientHello.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 HTTP ServerHello request encoded ClientHello must not be empty"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.keyExchange = keyExchange
    }
}

public class ContractTls12CertificateHandshakeFromPemChainRequest {
    public let certChainPemBundle: String

    public init(certChainPemBundle: String) {
        if (certChainPemBundle.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 certificate handshake request PEM bundle must not be empty"
            )
        }
        this.certChainPemBundle = certChainPemBundle
    }
}

public class ContractTls12VerifyCertificateHandshakeForHttpRequest {
    public let encodedCertificateHandshake: Array<Byte>
    public let trust: ContractHttpClientTlsTrustRequest

    public init(
        encodedCertificateHandshake: Array<Byte>,
        trust: ContractHttpClientTlsTrustRequest
    ) {
        if (encodedCertificateHandshake.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 certificate verify request handshake must not be empty"
            )
        }
        this.encodedCertificateHandshake = encodedCertificateHandshake.clone()
        this.trust = trust
    }
}

public class ContractTls12RsaClientKeyExchangeFromLeafPemRequest {
    public let serverLeafPem: String

    public init(serverLeafPem: String) {
        if (serverLeafPem.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 RSA ClientKeyExchange request server leaf certificate must not be empty"
            )
        }
        this.serverLeafPem = serverLeafPem
    }
}

public class ContractTls12ProcessRsaClientKeyExchangeRequest {
    public let serverPrivateKeyPkcs8Pem: String
    public let encodedClientKeyExchange: Array<Byte>

    public init(
        serverPrivateKeyPkcs8Pem: String,
        encodedClientKeyExchange: Array<Byte>
    ) {
        if (
            serverPrivateKeyPkcs8Pem.trimAscii().size == 0 ||
            encodedClientKeyExchange.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 RSA ClientKeyExchange process request fields are invalid"
            )
        }
        this.serverPrivateKeyPkcs8Pem = serverPrivateKeyPkcs8Pem
        this.encodedClientKeyExchange = encodedClientKeyExchange.clone()
    }
}

public class ContractTls12DeriveSecretsFromPreMasterRequest {
    public let preMasterSecret: Array<Byte>
    public let clientRandom: Array<Byte>
    public let serverRandom: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        preMasterSecret: Array<Byte>,
        clientRandom: Array<Byte>,
        serverRandom: Array<Byte>,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (
            preMasterSecret.size == 0 ||
            clientRandom.size != 32 ||
            serverRandom.size != 32 ||
            keyLen <= 0 ||
            ivLen <= 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 pre-master secret derivation request fields are invalid"
            )
        }
        this.preMasterSecret = preMasterSecret.clone()
        this.clientRandom = clientRandom.clone()
        this.serverRandom = serverRandom.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls12EcdheServerKeyExchangeRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let serverPrivateScalar: ?Array<Byte>

    public init(
        keyExchange: ContractTls12KeyExchange,
        serverPrivateScalar!: ?Array<Byte> = None
    ) {
        if (let Some(value) <- serverPrivateScalar) {
            if (value.size == 0) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "TLS1.2 ECDHE server key exchange request scalar must not be empty"
                )
            }
            this.serverPrivateScalar = Some(value.clone())
        } else {
            this.serverPrivateScalar = None
        }
        this.keyExchange = keyExchange
    }
}

public class ContractTls12EcdheClientKeyExchangeRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let clientPrivateScalar: ?Array<Byte>

    public init(
        keyExchange: ContractTls12KeyExchange,
        clientPrivateScalar!: ?Array<Byte> = None
    ) {
        if (let Some(value) <- clientPrivateScalar) {
            if (value.size == 0) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "TLS1.2 ECDHE client key exchange request scalar must not be empty"
                )
            }
            this.clientPrivateScalar = Some(value.clone())
        } else {
            this.clientPrivateScalar = None
        }
        this.keyExchange = keyExchange
    }
}

public class ContractTls12DeriveClientSecretsFromEcdheRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let clientPrivateScalar: Array<Byte>
    public let encodedServerKeyExchange: Array<Byte>
    public let clientRandom: Array<Byte>
    public let serverRandom: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        keyExchange: ContractTls12KeyExchange,
        clientPrivateScalar: Array<Byte>,
        encodedServerKeyExchange: Array<Byte>,
        clientRandom: Array<Byte>,
        serverRandom: Array<Byte>,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (
            clientPrivateScalar.size == 0 ||
            encodedServerKeyExchange.size == 0 ||
            clientRandom.size != 32 ||
            serverRandom.size != 32 ||
            keyLen <= 0 ||
            ivLen <= 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 ECDHE client secret derivation request fields are invalid"
            )
        }
        this.keyExchange = keyExchange
        this.clientPrivateScalar = clientPrivateScalar.clone()
        this.encodedServerKeyExchange = encodedServerKeyExchange.clone()
        this.clientRandom = clientRandom.clone()
        this.serverRandom = serverRandom.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls12DeriveServerSecretsFromEcdheRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let serverPrivateScalar: Array<Byte>
    public let encodedClientKeyExchange: Array<Byte>
    public let clientRandom: Array<Byte>
    public let serverRandom: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        keyExchange: ContractTls12KeyExchange,
        serverPrivateScalar: Array<Byte>,
        encodedClientKeyExchange: Array<Byte>,
        clientRandom: Array<Byte>,
        serverRandom: Array<Byte>,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (
            serverPrivateScalar.size == 0 ||
            encodedClientKeyExchange.size == 0 ||
            clientRandom.size != 32 ||
            serverRandom.size != 32 ||
            keyLen <= 0 ||
            ivLen <= 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 ECDHE server secret derivation request fields are invalid"
            )
        }
        this.keyExchange = keyExchange
        this.serverPrivateScalar = serverPrivateScalar.clone()
        this.encodedClientKeyExchange = encodedClientKeyExchange.clone()
        this.clientRandom = clientRandom.clone()
        this.serverRandom = serverRandom.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls13HttpClientHelloX25519Request {
    public let serverName: String
    public let alpnProtocols: Array<String>
    public let clientPrivateKey: ?Array<Byte>

    public init(
        serverName: String,
        alpnProtocols!: Array<String> = [],
        clientPrivateKey!: ?Array<Byte> = None
    ) {
        if (serverName.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 HTTP ClientHello request server name must not be empty"
            )
        }
        if (let Some(value) <- clientPrivateKey) {
            if (value.size != 32) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "TLS1.3 HTTP ClientHello request private key must be 32 bytes"
                )
            }
            this.clientPrivateKey = Some(value.clone())
        } else {
            this.clientPrivateKey = None
        }
        this.serverName = serverName.trimAscii()
        this.alpnProtocols = alpnProtocols.clone()
    }
}

public class ContractTls13HttpClientHelloX25519 {
    public let encodedClientHello: Array<Byte>
    public let clientPrivateKey: Array<Byte>
    public let clientPublicKey: Array<Byte>

    public init(
        encodedClientHello: Array<Byte>,
        clientPrivateKey: Array<Byte>,
        clientPublicKey: Array<Byte>
    ) {
        if (encodedClientHello.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 encoded ClientHello must not be empty")
        }
        if (clientPrivateKey.size != 32 || clientPublicKey.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 X25519 private/public key must be 32 bytes")
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.clientPrivateKey = clientPrivateKey.clone()
        this.clientPublicKey = clientPublicKey.clone()
    }
}

public class ContractTls13HttpServerFlightX25519Request {
    public let encodedClientHello: Array<Byte>
    public let serverKeyExchangePrivate: Array<Byte>
    public let certChainPemBundle: String
    public let certificatePrivateKeyPkcs8Pem: String
    public let policy: ContractTlsHttpNegotiationPolicy

    public init(
        encodedClientHello: Array<Byte>,
        serverKeyExchangePrivate: Array<Byte>,
        certChainPemBundle: String,
        certificatePrivateKeyPkcs8Pem: String,
        policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
    ) {
        if (
            encodedClientHello.size == 0 ||
            serverKeyExchangePrivate.size != 32 ||
            certChainPemBundle.trimAscii().size == 0 ||
            certificatePrivateKeyPkcs8Pem.trimAscii().size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 HTTP server flight request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.serverKeyExchangePrivate = serverKeyExchangePrivate.clone()
        this.certChainPemBundle = certChainPemBundle
        this.certificatePrivateKeyPkcs8Pem = certificatePrivateKeyPkcs8Pem
        this.policy = ContractTlsHttpNegotiationPolicy(
            requireServerName: policy.requireServerName,
            allowedServerNames: policy.allowedServerNames,
            alpnPreference: policy.alpnPreference
        )
    }
}

public class ContractTls13HttpServerFlight {
    public let serverHello: Array<Byte>
    public let encryptedExtensions: Array<Byte>
    public let certificateHandshake: Array<Byte>
    public let certificateVerifyHandshake: Array<Byte>
    public let finishedHandshake: Array<Byte>
    public let transcriptHash: Array<Byte>
    public let selectedAlpn: String
    public let requestedServerName: String
    public let acknowledgedServerName: Bool

    public init(
        serverHello: Array<Byte>,
        encryptedExtensions: Array<Byte>,
        certificateHandshake: Array<Byte>,
        certificateVerifyHandshake: Array<Byte>,
        finishedHandshake: Array<Byte>,
        transcriptHash: Array<Byte>,
        selectedAlpn!: String = "",
        requestedServerName!: String = "",
        acknowledgedServerName!: Bool = false
    ) {
        if (
            serverHello.size == 0 ||
            encryptedExtensions.size == 0 ||
            certificateHandshake.size == 0 ||
            certificateVerifyHandshake.size == 0 ||
            finishedHandshake.size == 0
        ) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 HTTP server flight messages must not be empty")
        }
        if (transcriptHash.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 transcript hash must be SHA-256 sized")
        }

        this.serverHello = serverHello.clone()
        this.encryptedExtensions = encryptedExtensions.clone()
        this.certificateHandshake = certificateHandshake.clone()
        this.certificateVerifyHandshake = certificateVerifyHandshake.clone()
        this.finishedHandshake = finishedHandshake.clone()
        this.transcriptHash = transcriptHash.clone()
        this.selectedAlpn = selectedAlpn.trimAscii()
        this.requestedServerName = requestedServerName.trimAscii().toAsciiLower()
        this.acknowledgedServerName = acknowledgedServerName
    }
}

public class ContractTls13HttpVerifyServerFlightX25519Request {
    public let clientHello: ContractTls13HttpClientHelloX25519
    public let serverFlight: ContractTls13HttpServerFlight
    public let trust: ContractHttpClientTlsTrustRequest

    public init(
        clientHello: ContractTls13HttpClientHelloX25519,
        serverFlight: ContractTls13HttpServerFlight,
        trust: ContractHttpClientTlsTrustRequest
    ) {
        this.clientHello = clientHello
        this.serverFlight = serverFlight
        this.trust = trust
    }
}

public class ContractTls13ApplicationKeyMaterial {
    public let clientWriteKey: Array<Byte>
    public let clientWriteIv: Array<Byte>
    public let serverWriteKey: Array<Byte>
    public let serverWriteIv: Array<Byte>

    public init(
        clientWriteKey: Array<Byte>,
        clientWriteIv: Array<Byte>,
        serverWriteKey: Array<Byte>,
        serverWriteIv: Array<Byte>
    ) {
        if (
            clientWriteKey.size == 0 ||
            clientWriteIv.size == 0 ||
            serverWriteKey.size == 0 ||
            serverWriteIv.size == 0
        ) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 key material must not be empty")
        }
        this.clientWriteKey = clientWriteKey.clone()
        this.clientWriteIv = clientWriteIv.clone()
        this.serverWriteKey = serverWriteKey.clone()
        this.serverWriteIv = serverWriteIv.clone()
    }
}

public class ContractTls13CipherBinding {
    public let cipherSuite: Int64
    public let cipherSuiteName: String
    public let algorithm: ContractAeadAlgorithm
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        cipherSuite: Int64,
        cipherSuiteName: String,
        algorithm: ContractAeadAlgorithm,
        keyLen: Int64,
        ivLen: Int64
    ) {
        if (cipherSuite < 0 || cipherSuite > 65535) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 cipher suite must be uint16")
        }
        if (cipherSuiteName.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 cipher suite name must not be empty")
        }
        if (keyLen <= 0 || ivLen <= 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 cipher binding key/iv lengths must be > 0")
        }
        this.cipherSuite = cipherSuite
        this.cipherSuiteName = cipherSuiteName.trimAscii()
        this.algorithm = algorithm
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls13KeyUpdatePlan {
    public let encodedKeyUpdate: Array<Byte>
    public let requestPeerUpdate: Bool
    public let nextTrafficSecret: Array<Byte>
    public let nextWriteKey: Array<Byte>
    public let nextWriteIv: Array<Byte>

    public init(
        encodedKeyUpdate: Array<Byte>,
        requestPeerUpdate: Bool,
        nextTrafficSecret: Array<Byte>,
        nextWriteKey: Array<Byte>,
        nextWriteIv: Array<Byte>
    ) {
        if (encodedKeyUpdate.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 KeyUpdate handshake must not be empty")
        }
        if (nextTrafficSecret.size == 0 || nextWriteKey.size == 0 || nextWriteIv.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 key update plan traffic secret and key material must not be empty"
            )
        }
        this.encodedKeyUpdate = encodedKeyUpdate.clone()
        this.requestPeerUpdate = requestPeerUpdate
        this.nextTrafficSecret = nextTrafficSecret.clone()
        this.nextWriteKey = nextWriteKey.clone()
        this.nextWriteIv = nextWriteIv.clone()
    }
}

public class ContractTls13ExporterMasterSecretRequest {
    public let masterSecret: Array<Byte>
    public let transcriptHash: Array<Byte>

    public init(masterSecret: Array<Byte>, transcriptHash: Array<Byte>) {
        if (masterSecret.size == 0 || transcriptHash.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 exporter master secret request fields must not be empty"
            )
        }
        this.masterSecret = masterSecret.clone()
        this.transcriptHash = transcriptHash.clone()
    }
}

public class ContractTls13ExportKeyingMaterialRequest {
    public let exporterMasterSecret: Array<Byte>
    public let exporterLabel: String
    public let context: Array<Byte>
    public let outputLen: Int64

    public init(
        exporterMasterSecret: Array<Byte>,
        exporterLabel: String,
        context!: Array<Byte> = [],
        outputLen!: Int64 = 32
    ) {
        if (exporterMasterSecret.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 export keying material request exporter master secret must not be empty"
            )
        }
        if (exporterLabel.trimAscii().size == 0 || outputLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 export keying material request fields are invalid"
            )
        }
        this.exporterMasterSecret = exporterMasterSecret.clone()
        this.exporterLabel = exporterLabel.trimAscii()
        this.context = context.clone()
        this.outputLen = outputLen
    }
}

public class ContractTls13KeyUpdateRequest {
    public let currentTrafficSecret: Array<Byte>
    public let requestPeerUpdate: Bool
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        currentTrafficSecret: Array<Byte>,
        requestPeerUpdate!: Bool = false,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (currentTrafficSecret.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 key update request fields are invalid"
            )
        }
        this.currentTrafficSecret = currentTrafficSecret.clone()
        this.requestPeerUpdate = requestPeerUpdate
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls13PeerKeyUpdateRequest {
    public let currentTrafficSecret: Array<Byte>
    public let encodedKeyUpdate: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        currentTrafficSecret: Array<Byte>,
        encodedKeyUpdate: Array<Byte>,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (currentTrafficSecret.size == 0 || encodedKeyUpdate.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 peer key update request fields are invalid"
            )
        }
        this.currentTrafficSecret = currentTrafficSecret.clone()
        this.encodedKeyUpdate = encodedKeyUpdate.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls13PskX25519DerivedSecrets {
    public let cipherBinding: ContractTls13CipherBinding
    public let keyMaterial: ContractTls13ApplicationKeyMaterial
    public let clientAppTrafficSecret: Array<Byte>
    public let serverAppTrafficSecret: Array<Byte>
    public let masterSecret: Array<Byte>

    public init(
        cipherBinding: ContractTls13CipherBinding,
        keyMaterial: ContractTls13ApplicationKeyMaterial,
        clientAppTrafficSecret: Array<Byte>,
        serverAppTrafficSecret: Array<Byte>,
        masterSecret: Array<Byte>
    ) {
        if (clientAppTrafficSecret.size == 0 || serverAppTrafficSecret.size == 0 || masterSecret.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK+X25519 derived secrets must not contain empty traffic/master secret"
            )
        }
        this.cipherBinding = cipherBinding
        this.keyMaterial = keyMaterial
        this.clientAppTrafficSecret = clientAppTrafficSecret.clone()
        this.serverAppTrafficSecret = serverAppTrafficSecret.clone()
        this.masterSecret = masterSecret.clone()
    }
}

public class ContractTls13PskX25519ChannelSet {
    public let secrets: ContractTls13PskX25519DerivedSecrets
    public let clientChannel: ContractTlsRecordChannel
    public let serverChannel: ContractTlsRecordChannel

    public init(
        secrets: ContractTls13PskX25519DerivedSecrets,
        clientChannel: ContractTlsRecordChannel,
        serverChannel: ContractTlsRecordChannel
    ) {
        if (clientChannel.version != ContractTlsVersion.Tls13 || serverChannel.version != ContractTlsVersion.Tls13) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK+X25519 channel set requires TLS1.3 record channels"
            )
        }
        if (clientChannel.algorithm != secrets.cipherBinding.algorithm) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK+X25519 client channel algorithm must match cipher binding"
            )
        }
        if (serverChannel.algorithm != secrets.cipherBinding.algorithm) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK+X25519 server channel algorithm must match cipher binding"
            )
        }
        this.secrets = secrets
        this.clientChannel = clientChannel
        this.serverChannel = serverChannel
    }
}

public class ContractTls13PskX25519TrafficUpdateResult {
    public let encodedKeyUpdate: Array<Byte>
    public let requestPeerUpdate: Bool
    public let channels: ContractTls13PskX25519ChannelSet

    public init(
        encodedKeyUpdate: Array<Byte>,
        requestPeerUpdate: Bool,
        channels: ContractTls13PskX25519ChannelSet
    ) {
        if (encodedKeyUpdate.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK+X25519 KeyUpdate handshake must not be empty"
            )
        }
        this.encodedKeyUpdate = encodedKeyUpdate.clone()
        this.requestPeerUpdate = requestPeerUpdate
        this.channels = channels
    }
}

public class ContractTls13PskX25519PeerUpdateOrchestrationResult {
    public let incomingRequestPeerUpdate: Bool
    public let responseRequired: Bool
    public let encodedResponseKeyUpdate: Array<Byte>
    public let channels: ContractTls13PskX25519ChannelSet

    public init(
        incomingRequestPeerUpdate: Bool,
        responseRequired: Bool,
        encodedResponseKeyUpdate: Array<Byte>,
        channels: ContractTls13PskX25519ChannelSet
    ) {
        if (responseRequired && encodedResponseKeyUpdate.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK+X25519 peer update orchestration requires non-empty response KeyUpdate"
            )
        }
        if (!responseRequired && encodedResponseKeyUpdate.size != 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK+X25519 peer update orchestration response must be empty when not required"
            )
        }
        this.incomingRequestPeerUpdate = incomingRequestPeerUpdate
        this.responseRequired = responseRequired
        this.encodedResponseKeyUpdate = encodedResponseKeyUpdate.clone()
        this.channels = channels
    }
}

public enum ContractTlsVersion <: Equatable<ContractTlsVersion> & ToString {
    | Tls12
    | Tls13

    public operator func ==(right: ContractTlsVersion): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractTlsVersion): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Tls12 => 0
            case Tls13 => 1
        }
    }

    public func toString(): String {
        match (this) {
            case Tls12 => "TLS1.2"
            case Tls13 => "TLS1.3"
        }
    }
}

public enum ContractTlsEndpointRole <: Equatable<ContractTlsEndpointRole> & ToString {
    | Client
    | Server

    public operator func ==(right: ContractTlsEndpointRole): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractTlsEndpointRole): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Client => 0
            case Server => 1
        }
    }

    public func toString(): String {
        match (this) {
            case Client => "CLIENT"
            case Server => "SERVER"
        }
    }
}

public enum ContractTlsRecordContentType <: Equatable<ContractTlsRecordContentType> & ToString {
    | ChangeCipherSpec
    | Alert
    | Handshake
    | ApplicationData

    public operator func ==(right: ContractTlsRecordContentType): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractTlsRecordContentType): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case ChangeCipherSpec => 0
            case Alert => 1
            case Handshake => 2
            case ApplicationData => 3
        }
    }

    public func toString(): String {
        match (this) {
            case ChangeCipherSpec => "CHANGE_CIPHER_SPEC"
            case Alert => "ALERT"
            case Handshake => "HANDSHAKE"
            case ApplicationData => "APPLICATION_DATA"
        }
    }
}

public class ContractTlsRecordPlaintext {
    public let version: ContractTlsVersion
    public let contentType: ContractTlsRecordContentType
    public let fragment: Array<Byte>

    public init(
        version: ContractTlsVersion,
        contentType: ContractTlsRecordContentType,
        fragment: Array<Byte>
    ) {
        this.version = version
        this.contentType = contentType
        this.fragment = fragment.clone()
    }
}

public class ContractTlsRecordChannel {
    public let version: ContractTlsVersion
    public let algorithm: ContractAeadAlgorithm

    let _aesLayer: ?TlsAeadRecordLayer
    let _chachaLayer: ?TlsChacha20Poly1305RecordLayer

    public init(
        version: ContractTlsVersion,
        algorithm: ContractAeadAlgorithm,
        aesLayer!: ?TlsAeadRecordLayer = None,
        chachaLayer!: ?TlsChacha20Poly1305RecordLayer = None
    ) {
        match (algorithm) {
            case ContractAeadAlgorithm.Aes256Gcm =>
                if (let Some(_layer) <- aesLayer) {
                    if (let Some(_unexpected) <- chachaLayer) {
                        throw ContractException(
                            ContractErrorCode.BadInput,
                            "TLS record channel for AES must not carry ChaCha layer"
                        )
                    }
                } else {
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "TLS record channel for AES requires AES layer"
                    )
                }
            case ContractAeadAlgorithm.Chacha20Poly1305 =>
                if (let Some(_layer) <- chachaLayer) {
                    if (let Some(_unexpected) <- aesLayer) {
                        throw ContractException(
                            ContractErrorCode.BadInput,
                            "TLS record channel for ChaCha20-Poly1305 must not carry AES layer"
                        )
                    }
                } else {
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "TLS record channel for ChaCha20-Poly1305 requires ChaCha layer"
                    )
                }
        }

        this.version = version
        this.algorithm = algorithm
        this._aesLayer = aesLayer
        this._chachaLayer = chachaLayer
    }

    public prop writeSequence: Int64 {
        get() {
            match (algorithm) {
                case ContractAeadAlgorithm.Aes256Gcm =>
                    if (let Some(layer) <- _aesLayer) {
                        return layer.writeSequence
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS AES record layer is unavailable")
                case ContractAeadAlgorithm.Chacha20Poly1305 =>
                    if (let Some(layer) <- _chachaLayer) {
                        return layer.writeSequence
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS ChaCha20 record layer is unavailable")
            }
        }
    }

    public prop readSequence: Int64 {
        get() {
            match (algorithm) {
                case ContractAeadAlgorithm.Aes256Gcm =>
                    if (let Some(layer) <- _aesLayer) {
                        return layer.readSequence
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS AES record layer is unavailable")
                case ContractAeadAlgorithm.Chacha20Poly1305 =>
                    if (let Some(layer) <- _chachaLayer) {
                        return layer.readSequence
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS ChaCha20 record layer is unavailable")
            }
        }
    }

    public func resetSequences(): Unit {
        match (algorithm) {
            case ContractAeadAlgorithm.Aes256Gcm =>
                if (let Some(layer) <- _aesLayer) {
                    layer.resetSequences()
                    return
                }
                throw ContractException(ContractErrorCode.InternalError, "TLS AES record layer is unavailable")
            case ContractAeadAlgorithm.Chacha20Poly1305 =>
                if (let Some(layer) <- _chachaLayer) {
                    layer.resetSequences()
                    return
                }
                throw ContractException(ContractErrorCode.InternalError, "TLS ChaCha20 record layer is unavailable")
        }
    }

    public func seal(
        contentType: ContractTlsRecordContentType,
        plaintext: Array<Byte>
    ): Array<Byte> {
        try {
            match (algorithm) {
                case ContractAeadAlgorithm.Aes256Gcm =>
                    if (let Some(layer) <- _aesLayer) {
                        return layer.seal(contractToTlsContentType(contentType), plaintext)
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS AES record layer is unavailable")
                case ContractAeadAlgorithm.Chacha20Poly1305 =>
                    if (let Some(layer) <- _chachaLayer) {
                        return layer.seal(contractToTlsContentType(contentType), plaintext)
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS ChaCha20 record layer is unavailable")
            }
        } catch (e: ContractException) {
            throw e
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS record seal failed: ${e.message}"
            )
        }
    }

    public func open(encodedRecord: Array<Byte>): ContractTlsRecordPlaintext {
        try {
            let plain = match (algorithm) {
                case ContractAeadAlgorithm.Aes256Gcm =>
                    if (let Some(layer) <- _aesLayer) {
                        layer.open(encodedRecord)
                    } else {
                        throw ContractException(ContractErrorCode.InternalError, "TLS AES record layer is unavailable")
                    }
                case ContractAeadAlgorithm.Chacha20Poly1305 =>
                    if (let Some(layer) <- _chachaLayer) {
                        layer.open(encodedRecord)
                    } else {
                        throw ContractException(ContractErrorCode.InternalError, "TLS ChaCha20 record layer is unavailable")
                    }
            }
            ContractTlsRecordPlaintext(
                contractFromTlsVersion(plain.version),
                contractFromTlsContentType(plain.contentType),
                plain.fragment
            )
        } catch (e: ContractException) {
            throw e
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS record open failed: ${e.message}"
            )
        }
    }

    public func sealApplicationData(plaintext: Array<Byte>): Array<Byte> {
        seal(ContractTlsRecordContentType.ApplicationData, plaintext)
    }

    public func openApplicationData(encodedRecord: Array<Byte>): Array<Byte> {
        let plain = open(encodedRecord)
        if (plain.contentType != ContractTlsRecordContentType.ApplicationData) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS record content type is not APPLICATION_DATA"
            )
        }
        plain.fragment
    }

    public func sealFragments(
        contentType: ContractTlsRecordContentType,
        plaintext: Array<Byte>,
        maxFragmentLen!: Int64 = 16384
    ): Array<Array<Byte>> {
        try {
            match (algorithm) {
                case ContractAeadAlgorithm.Aes256Gcm =>
                    if (let Some(layer) <- _aesLayer) {
                        return layer.sealFragments(
                            contractToTlsContentType(contentType),
                            plaintext,
                            maxFragmentLen: maxFragmentLen
                        )
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS AES record layer is unavailable")
                case ContractAeadAlgorithm.Chacha20Poly1305 =>
                    if (let Some(layer) <- _chachaLayer) {
                        return layer.sealFragments(
                            contractToTlsContentType(contentType),
                            plaintext,
                            maxFragmentLen: maxFragmentLen
                        )
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS ChaCha20 record layer is unavailable")
            }
        } catch (e: ContractException) {
            throw e
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS record fragment sealing failed: ${e.message}"
            )
        }
    }

    public func openAndReassemble(
        encodedRecords: Array<Array<Byte>>,
        expectedContentType!: ContractTlsRecordContentType = ContractTlsRecordContentType.ApplicationData
    ): Array<Byte> {
        try {
            match (algorithm) {
                case ContractAeadAlgorithm.Aes256Gcm =>
                    if (let Some(layer) <- _aesLayer) {
                        return layer.openAndReassemble(
                            encodedRecords,
                            expectedContentType: contractToTlsContentType(expectedContentType)
                        )
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS AES record layer is unavailable")
                case ContractAeadAlgorithm.Chacha20Poly1305 =>
                    if (let Some(layer) <- _chachaLayer) {
                        return layer.openAndReassemble(
                            encodedRecords,
                            expectedContentType: contractToTlsContentType(expectedContentType)
                        )
                    }
                    throw ContractException(ContractErrorCode.InternalError, "TLS ChaCha20 record layer is unavailable")
            }
        } catch (e: ContractException) {
            throw e
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS record fragment open failed: ${e.message}"
            )
        }
    }

    public func sendCloseNotify(): Array<Byte> {
        seal(
            ContractTlsRecordContentType.Alert,
            contractTlsEncodeAlertPayload(
                ContractTlsAlertLevel.AlertWarning,
                ContractTlsAlertDescription.AlertCloseNotify
            )
        )
    }

    public func openAlert(encodedRecord: Array<Byte>): ContractTlsAlertMessage {
        let plain = open(encodedRecord)
        if (plain.contentType != ContractTlsRecordContentType.Alert) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS record content type is not ALERT"
            )
        }
        contractTlsDecodeAlertPayload(plain.fragment)
    }
}

public class ContractTls12RecordChannelRequest {
    public let secrets: ContractTls12HandshakeSecrets
    public let algorithm: ContractAeadAlgorithm

    public init(
        secrets: ContractTls12HandshakeSecrets,
        algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
    ) {
        this.secrets = secrets
        this.algorithm = algorithm
    }
}

public class ContractTls13RecordChannelRequest {
    public let keyMaterial: ContractTls13ApplicationKeyMaterial
    public let algorithm: ContractAeadAlgorithm

    public init(
        keyMaterial: ContractTls13ApplicationKeyMaterial,
        algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
    ) {
        this.keyMaterial = keyMaterial
        this.algorithm = algorithm
    }
}

public class ContractTls13PskClientHelloFromSessionCacheRequest {
    public let cache: ContractTlsSessionCache
    public let identity: ContractTlsSessionIdentity
    public let nowUnixSeconds: Int64
    public let sessionId: Array<Byte>

    public init(
        cache: ContractTlsSessionCache,
        identity: ContractTlsSessionIdentity,
        nowUnixSeconds!: Int64 = 0,
        sessionId!: Array<Byte> = []
    ) {
        this.cache = cache
        this.identity = identity
        this.nowUnixSeconds = nowUnixSeconds
        this.sessionId = sessionId.clone()
    }
}

public class ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest {
    public let cache: ContractTlsSessionCache
    public let identity: ContractTlsSessionIdentity
    public let policy: ContractTls13SessionTicketPolicy
    public let nowUnixSeconds: Int64
    public let sessionId: Array<Byte>

    public init(
        cache: ContractTlsSessionCache,
        identity: ContractTlsSessionIdentity,
        policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
        nowUnixSeconds!: Int64 = 0,
        sessionId!: Array<Byte> = []
    ) {
        this.cache = cache
        this.identity = identity
        this.policy = ContractTls13SessionTicketPolicy(
            minRemainingTtlSeconds: policy.minRemainingTtlSeconds,
            renewBeforeExpirySeconds: policy.renewBeforeExpirySeconds,
            requiredServerName: policy.requiredServerName,
            requiredAlpnProtocol: policy.requiredAlpnProtocol
        )
        this.nowUnixSeconds = nowUnixSeconds
        this.sessionId = sessionId.clone()
    }
}

public enum ContractTlsAlertLevel <: Equatable<ContractTlsAlertLevel> & ToString {
    | AlertWarning
    | AlertFatal

    public operator func ==(right: ContractTlsAlertLevel): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractTlsAlertLevel): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case AlertWarning => 0
            case AlertFatal => 1
        }
    }

    public func toString(): String {
        match (this) {
            case AlertWarning => "WARNING"
            case AlertFatal => "FATAL"
        }
    }
}

public enum ContractTlsAlertDescription <: Equatable<ContractTlsAlertDescription> & ToString {
    | AlertCloseNotify
    | AlertUnexpectedMessage
    | AlertBadRecordMac
    | AlertDecryptionFailedReserved
    | AlertRecordOverflow
    | AlertHandshakeFailure
    | AlertBadCertificate
    | AlertUnsupportedCertificate
    | AlertCertificateRevoked
    | AlertCertificateExpired
    | AlertCertificateUnknown
    | AlertIllegalParameter
    | AlertUnknownCa
    | AlertAccessDenied
    | AlertDecodeError
    | AlertDecryptError
    | AlertProtocolVersion
    | AlertInsufficientSecurity
    | AlertInternalError
    | AlertUserCanceled
    | AlertMissingExtension
    | AlertUnsupportedExtension
    | AlertUnrecognizedName
    | AlertBadCertificateStatusResponse
    | AlertUnknownPskIdentity
    | AlertCertificateRequired
    | AlertNoApplicationProtocol

    public operator func ==(right: ContractTlsAlertDescription): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: ContractTlsAlertDescription): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case AlertCloseNotify => 0
            case AlertUnexpectedMessage => 1
            case AlertBadRecordMac => 2
            case AlertDecryptionFailedReserved => 3
            case AlertRecordOverflow => 4
            case AlertHandshakeFailure => 5
            case AlertBadCertificate => 6
            case AlertUnsupportedCertificate => 7
            case AlertCertificateRevoked => 8
            case AlertCertificateExpired => 9
            case AlertCertificateUnknown => 10
            case AlertIllegalParameter => 11
            case AlertUnknownCa => 12
            case AlertAccessDenied => 13
            case AlertDecodeError => 14
            case AlertDecryptError => 15
            case AlertProtocolVersion => 16
            case AlertInsufficientSecurity => 17
            case AlertInternalError => 18
            case AlertUserCanceled => 19
            case AlertMissingExtension => 20
            case AlertUnsupportedExtension => 21
            case AlertUnrecognizedName => 22
            case AlertBadCertificateStatusResponse => 23
            case AlertUnknownPskIdentity => 24
            case AlertCertificateRequired => 25
            case AlertNoApplicationProtocol => 26
        }
    }

    public func toString(): String {
        match (this) {
            case AlertCloseNotify => "CLOSE_NOTIFY"
            case AlertUnexpectedMessage => "UNEXPECTED_MESSAGE"
            case AlertBadRecordMac => "BAD_RECORD_MAC"
            case AlertDecryptionFailedReserved => "DECRYPTION_FAILED_RESERVED"
            case AlertRecordOverflow => "RECORD_OVERFLOW"
            case AlertHandshakeFailure => "HANDSHAKE_FAILURE"
            case AlertBadCertificate => "BAD_CERTIFICATE"
            case AlertUnsupportedCertificate => "UNSUPPORTED_CERTIFICATE"
            case AlertCertificateRevoked => "CERTIFICATE_REVOKED"
            case AlertCertificateExpired => "CERTIFICATE_EXPIRED"
            case AlertCertificateUnknown => "CERTIFICATE_UNKNOWN"
            case AlertIllegalParameter => "ILLEGAL_PARAMETER"
            case AlertUnknownCa => "UNKNOWN_CA"
            case AlertAccessDenied => "ACCESS_DENIED"
            case AlertDecodeError => "DECODE_ERROR"
            case AlertDecryptError => "DECRYPT_ERROR"
            case AlertProtocolVersion => "PROTOCOL_VERSION"
            case AlertInsufficientSecurity => "INSUFFICIENT_SECURITY"
            case AlertInternalError => "INTERNAL_ERROR"
            case AlertUserCanceled => "USER_CANCELED"
            case AlertMissingExtension => "MISSING_EXTENSION"
            case AlertUnsupportedExtension => "UNSUPPORTED_EXTENSION"
            case AlertUnrecognizedName => "UNRECOGNIZED_NAME"
            case AlertBadCertificateStatusResponse => "BAD_CERTIFICATE_STATUS_RESPONSE"
            case AlertUnknownPskIdentity => "UNKNOWN_PSK_IDENTITY"
            case AlertCertificateRequired => "CERTIFICATE_REQUIRED"
            case AlertNoApplicationProtocol => "NO_APPLICATION_PROTOCOL"
        }
    }
}

public class ContractTlsAlertMessage {
    public let level: ContractTlsAlertLevel
    public let description: ContractTlsAlertDescription

    public init(level: ContractTlsAlertLevel, description: ContractTlsAlertDescription) {
        this.level = level
        this.description = description
    }

    public prop isCloseNotify: Bool {
        get() {
            description == ContractTlsAlertDescription.AlertCloseNotify
        }
    }
}

public class ContractTlsSessionIdentity {
    public let version: ContractTlsVersion
    public let resumptionId: Array<Byte>
    public let serverName: String
    public let alpnProtocol: String

    public init(
        version: ContractTlsVersion,
        resumptionId: Array<Byte>,
        serverName!: String = "",
        alpnProtocol!: String = ""
    ) {
        if (resumptionId.size == 0 || resumptionId.size > 65535) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session resumption id length is invalid")
        }
        this.version = version
        this.resumptionId = resumptionId.clone()
        this.serverName = serverName.trimAscii().toAsciiLower()
        this.alpnProtocol = alpnProtocol.trimAscii().toAsciiLower()
    }
}

public class ContractTlsSessionTicket {
    public let version: Int64
    public let identity: ContractTlsSessionIdentity
    public let secret: Array<Byte>
    public let nonce: Array<Byte>
    public let issuedAtUnixSeconds: Int64
    public let expiresAtUnixSeconds: Int64

    public init(
        version: Int64,
        identity: ContractTlsSessionIdentity,
        secret: Array<Byte>,
        nonce: Array<Byte>,
        issuedAtUnixSeconds: Int64,
        expiresAtUnixSeconds: Int64
    ) {
        if (version <= 0 || version > 255) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session ticket version is invalid")
        }
        if (secret.size == 0 || secret.size > 65535) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session ticket secret length is invalid")
        }
        if (issuedAtUnixSeconds <= 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds) {
            throw ContractException(ContractErrorCode.BadInput, "TLS session ticket validity window is invalid")
        }
        this.version = version
        this.identity = identity
        this.secret = secret.clone()
        this.nonce = nonce.clone()
        this.issuedAtUnixSeconds = issuedAtUnixSeconds
        this.expiresAtUnixSeconds = expiresAtUnixSeconds
    }
}

public class ContractTls13SessionTicketPolicy {
    public let minRemainingTtlSeconds: Int64
    public let renewBeforeExpirySeconds: Int64
    public let requiredServerName: String
    public let requiredAlpnProtocol: String

    public init(
        minRemainingTtlSeconds!: Int64 = 1,
        renewBeforeExpirySeconds!: Int64 = 300,
        requiredServerName!: String = "",
        requiredAlpnProtocol!: String = ""
    ) {
        if (minRemainingTtlSeconds < 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 ticket min remaining ttl must be >= 0"
            )
        }
        if (renewBeforeExpirySeconds < 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 ticket renew-before-expiry seconds must be >= 0"
            )
        }
        this.minRemainingTtlSeconds = minRemainingTtlSeconds
        this.renewBeforeExpirySeconds = renewBeforeExpirySeconds
        this.requiredServerName = requiredServerName.trimAscii().toAsciiLower()
        this.requiredAlpnProtocol = requiredAlpnProtocol.trimAscii().toAsciiLower()
    }
}

public class ContractTls13SessionTicketLifecycleResult {
    public let usable: Bool
    public let shouldRenew: Bool
    public let reason: String
    public let nowUnixSeconds: Int64
    public let remainingTtlSeconds: Int64

    public init(
        usable: Bool,
        shouldRenew: Bool,
        reason: String,
        nowUnixSeconds: Int64,
        remainingTtlSeconds: Int64
    ) {
        if (reason.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 ticket lifecycle reason must not be empty")
        }
        if (nowUnixSeconds <= 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 ticket lifecycle nowUnixSeconds must be > 0")
        }
        this.usable = usable
        this.shouldRenew = shouldRenew
        this.reason = reason.trimAscii()
        this.nowUnixSeconds = nowUnixSeconds
        this.remainingTtlSeconds = remainingTtlSeconds
    }
}

public class ContractTls13NewSessionTicketRequest {
    public let ticket: ContractTlsSessionTicket
    public let ticketAgeAdd: Int64

    public init(
        ticket: ContractTlsSessionTicket,
        ticketAgeAdd!: Int64 = 0
    ) {
        this.ticket = ticket
        this.ticketAgeAdd = ticketAgeAdd
    }
}

public class ContractTls13StoreNewSessionTicketRequest {
    public let cache: ContractTlsSessionCache
    public let encodedNewSessionTicket: Array<Byte>

    public init(
        cache: ContractTlsSessionCache,
        encodedNewSessionTicket: Array<Byte>
    ) {
        if (encodedNewSessionTicket.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 store NewSessionTicket request payload must not be empty"
            )
        }
        this.cache = cache
        this.encodedNewSessionTicket = encodedNewSessionTicket.clone()
    }
}

public class ContractTls13SessionTicketLifecycleRequest {
    public let ticket: ContractTlsSessionTicket
    public let policy: ContractTls13SessionTicketPolicy
    public let nowUnixSeconds: Int64

    public init(
        ticket: ContractTlsSessionTicket,
        policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
        nowUnixSeconds!: Int64 = 0
    ) {
        this.ticket = ticket
        this.policy = ContractTls13SessionTicketPolicy(
            minRemainingTtlSeconds: policy.minRemainingTtlSeconds,
            renewBeforeExpirySeconds: policy.renewBeforeExpirySeconds,
            requiredServerName: policy.requiredServerName,
            requiredAlpnProtocol: policy.requiredAlpnProtocol
        )
        this.nowUnixSeconds = nowUnixSeconds
    }
}

public class ContractTlsSessionCacheStats {
    public let size: Int64
    public let hits: Int64
    public let misses: Int64
    public let evictions: Int64
    public let expiredRemovals: Int64

    public init(size: Int64, hits: Int64, misses: Int64, evictions: Int64, expiredRemovals: Int64) {
        this.size = size
        this.hits = hits
        this.misses = misses
        this.evictions = evictions
        this.expiredRemovals = expiredRemovals
    }
}

public class ContractTlsSessionCache {
    let _inner: TlsSessionCache

    public init(maxEntries!: Int64 = 1024, defaultTtlSeconds!: Int64 = TLS_SESSION_DEFAULT_TTL_SECONDS) {
        try {
            this._inner = TlsSessionCache(maxEntries: maxEntries, defaultTtlSeconds: defaultTtlSeconds)
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS session cache initialization failed: ${e.message}"
            )
        }
    }

    public prop size: Int64 {
        get() {
            _inner.size
        }
    }

    public func stats(): ContractTlsSessionCacheStats {
        contractFromTlsSessionCacheStats(_inner.stats())
    }

    public func store(ticket: ContractTlsSessionTicket): ContractTlsSessionTicket {
        try {
            let stored = _inner.store(contractToTlsSessionTicket(ticket))
            contractFromTlsSessionTicket(stored)
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS session ticket store failed: ${e.message}"
            )
        }
    }

    public func storeFromSecret(
        identity: ContractTlsSessionIdentity,
        secret: Array<Byte>,
        nonce!: Array<Byte> = [],
        nowUnixSeconds!: Int64 = 0,
        ttlSeconds!: Int64 = 0
    ): ContractTlsSessionTicket {
        try {
            let stored = _inner.storeFromSecret(
                contractToTlsSessionIdentity(identity),
                secret,
                nonce: nonce,
                nowUnixSeconds: nowUnixSeconds,
                ttlSeconds: ttlSeconds
            )
            contractFromTlsSessionTicket(stored)
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS session ticket store-from-secret failed: ${e.message}"
            )
        }
    }

    public func load(
        identity: ContractTlsSessionIdentity,
        nowUnixSeconds!: Int64 = 0
    ): ?ContractTlsSessionTicket {
        try {
            let loaded = _inner.load(
                contractToTlsSessionIdentity(identity),
                nowUnixSeconds: nowUnixSeconds
            )
            if (let Some(ticket) <- loaded) {
                return Some(contractFromTlsSessionTicket(ticket))
            }
            None
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS session ticket load failed: ${e.message}"
            )
        }
    }

    public func remove(identity: ContractTlsSessionIdentity): Bool {
        try {
            _inner.remove(contractToTlsSessionIdentity(identity))
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS session ticket remove failed: ${e.message}"
            )
        }
    }

    public func purgeExpired(nowUnixSeconds!: Int64 = 0): Int64 {
        try {
            _inner.purgeExpired(nowUnixSeconds: nowUnixSeconds)
        } catch (e: CryptoException) {
            throw ContractException(
                mapCryptoErrorForOperation(e, "tls"),
                "TLS session cache purge failed: ${e.message}"
            )
        }
    }

    public func clear(): Unit {
        _inner.clear()
    }
}

public class ContractTls13EarlyDataReplayStats {
    public let size: Int64
    public let hits: Int64
    public let misses: Int64
    public let evictions: Int64
    public let expiredRemovals: Int64
    public let rejects: Int64

    public init(
        size: Int64,
        hits: Int64,
        misses: Int64,
        evictions: Int64,
        expiredRemovals: Int64,
        rejects: Int64
    ) {
        this.size = size
        this.hits = hits
        this.misses = misses
        this.evictions = evictions
        this.expiredRemovals = expiredRemovals
        this.rejects = rejects
    }
}

public class ContractTls13EarlyDataReplayCache {
    let _maxEntries: Int64
    let _defaultWindowSeconds: Int64
    let _entries = ArrayList<ContractTls13EarlyDataReplayEntry>()

    var _hits: Int64 = 0
    var _misses: Int64 = 0
    var _evictions: Int64 = 0
    var _expiredRemovals: Int64 = 0
    var _rejects: Int64 = 0

    public init(maxEntries!: Int64 = 2048, defaultWindowSeconds!: Int64 = 600) {
        if (maxEntries <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 early data replay cache maxEntries must be positive"
            )
        }
        if (defaultWindowSeconds <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 early data replay cache default window must be positive"
            )
        }
        this._maxEntries = maxEntries
        this._defaultWindowSeconds = defaultWindowSeconds
    }

    public prop size: Int64 {
        get() {
            _entries.size
        }
    }

    public func stats(): ContractTls13EarlyDataReplayStats {
        ContractTls13EarlyDataReplayStats(
            _entries.size,
            _hits,
            _misses,
            _evictions,
            _expiredRemovals,
            _rejects
        )
    }

    public func contains(replayKey: String, nowUnixSeconds!: Int64 = 0): Bool {
        let normalizedKey = contractNormalizeReplayKey(replayKey)
        let now = contractResolveReplayUnixSeconds(nowUnixSeconds)
        purgeExpiredInternal(now)
        let (index, found) = findEntryByKey(normalizedKey)
        if (index < 0) {
            _misses += 1
            return false
        }
        match (found) {
            case Some(entry) =>
                if (entry.isExpired(now)) {
                    _entries.remove(at: index)
                    _expiredRemovals += 1
                    _misses += 1
                    return false
                }
                _hits += 1
                true
            case None =>
                _misses += 1
                false
        }
    }

    public func remember(
        replayKey: String,
        nowUnixSeconds!: Int64 = 0,
        ttlSeconds!: Int64 = 0
    ): Bool {
        let normalizedKey = contractNormalizeReplayKey(replayKey)
        let now = contractResolveReplayUnixSeconds(nowUnixSeconds)
        purgeExpiredInternal(now)
        let (index, found) = findEntryByKey(normalizedKey)
        if (index >= 0) {
            match (found) {
                case Some(entry) =>
                    if (!entry.isExpired(now)) {
                        _hits += 1
                        _rejects += 1
                        return false
                    }
                    _entries.remove(at: index)
                    _expiredRemovals += 1
                case None =>
                    ()
            }
        }

        let effectiveTtl = if (ttlSeconds > 0) {
            ttlSeconds
        } else {
            _defaultWindowSeconds
        }
        let expiresAt = now + effectiveTtl
        _entries.add(
            ContractTls13EarlyDataReplayEntry(
                normalizedKey,
                now,
                expiresAt
            )
        )
        trimToCapacity()
        _misses += 1
        true
    }

    public func purgeExpired(nowUnixSeconds!: Int64 = 0): Int64 {
        let now = contractResolveReplayUnixSeconds(nowUnixSeconds)
        purgeExpiredInternal(now)
    }

    public func clear(): Unit {
        while (_entries.size > 0) {
            _entries.remove(at: _entries.size - 1)
        }
    }

    private func purgeExpiredInternal(nowUnixSeconds: Int64): Int64 {
        var removed: Int64 = 0
        var i = _entries.size - 1
        while (i >= 0) {
            if (_entries[i].isExpired(nowUnixSeconds)) {
                _entries.remove(at: i)
                removed += 1
            }
            i -= 1
        }
        _expiredRemovals += removed
        removed
    }

    private func trimToCapacity(): Unit {
        while (_entries.size > _maxEntries) {
            _entries.remove(at: 0)
            _evictions += 1
        }
    }

    private func findEntryByKey(replayKey: String): (Int64, ?ContractTls13EarlyDataReplayEntry) {
        var idx: Int64 = 0
        for (entry in _entries) {
            if (entry.replayKey == replayKey) {
                return (idx, Some(entry))
            }
            idx += 1
        }
        (-1, None)
    }
}

class ContractTls13EarlyDataReplayEntry {
    public let replayKey: String
    public let acceptedAtUnixSeconds: Int64
    public let expiresAtUnixSeconds: Int64

    public init(replayKey: String, acceptedAtUnixSeconds: Int64, expiresAtUnixSeconds: Int64) {
        if (replayKey.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 early data replay key must not be empty")
        }
        if (acceptedAtUnixSeconds <= 0 || expiresAtUnixSeconds <= acceptedAtUnixSeconds) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 early data replay entry lifetime is invalid"
            )
        }
        this.replayKey = replayKey
        this.acceptedAtUnixSeconds = acceptedAtUnixSeconds
        this.expiresAtUnixSeconds = expiresAtUnixSeconds
    }

    public func isExpired(nowUnixSeconds: Int64): Bool {
        nowUnixSeconds >= expiresAtUnixSeconds
    }
}

private func contractNormalizeReplayKey(replayKey: String): String {
    let normalized = replayKey.trimAscii()
    if (normalized.size == 0) {
        throw ContractException(ContractErrorCode.BadInput, "TLS1.3 early data replay key must not be empty")
    }
    normalized
}

private func contractResolveReplayUnixSeconds(nowUnixSeconds: Int64): Int64 {
    if (nowUnixSeconds > 0) {
        return nowUnixSeconds
    }
    1
}

public func contractTlsCreateSessionTicket(
    identity: ContractTlsSessionIdentity,
    secret: Array<Byte>,
    nonce!: Array<Byte> = [],
    nowUnixSeconds!: Int64 = 0,
    ttlSeconds!: Int64 = TLS_SESSION_DEFAULT_TTL_SECONDS
): ContractTlsSessionTicket {
    try {
        let ticket = tlsCreateSessionTicket(
            contractToTlsSessionIdentity(identity),
            secret,
            nonce: nonce,
            nowUnixSeconds: nowUnixSeconds,
            ttlSeconds: ttlSeconds
        )
        contractFromTlsSessionTicket(ticket)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS session ticket creation failed: ${e.message}"
        )
    }
}

public func contractTlsEncodeSessionTicket(ticket: ContractTlsSessionTicket): Array<Byte> {
    try {
        tlsEncodeSessionTicket(contractToTlsSessionTicket(ticket))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS session ticket encoding failed: ${e.message}"
        )
    }
}

public func contractTlsDecodeSessionTicket(encoded: Array<Byte>): ContractTlsSessionTicket {
    try {
        contractFromTlsSessionTicket(tlsDecodeSessionTicket(encoded))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS session ticket decoding failed: ${e.message}"
        )
    }
}

public func contractTlsIsSessionTicketExpired(
    ticket: ContractTlsSessionTicket,
    nowUnixSeconds!: Int64 = 0
): Bool {
    try {
        tlsIsSessionTicketExpired(contractToTlsSessionTicket(ticket), nowUnixSeconds: nowUnixSeconds)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS session ticket expiry check failed: ${e.message}"
        )
    }
}

public func contractTlsEncodeAlertPayload(
    level: ContractTlsAlertLevel,
    description: ContractTlsAlertDescription
): Array<Byte> {
    try {
        tlsEncodeAlert(contractToTlsAlertLevel(level), contractToTlsAlertDescription(description))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS alert payload encoding failed: ${e.message}"
        )
    }
}

public func contractTlsDecodeAlertPayload(
    encodedAlert: Array<Byte>
): ContractTlsAlertMessage {
    try {
        contractFromTlsAlertMessage(tlsDecodeAlert(encodedAlert))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS alert payload decoding failed: ${e.message}"
        )
    }
}

public func contractTlsEncodeAlertRecord(
    version: ContractTlsVersion,
    level: ContractTlsAlertLevel,
    description: ContractTlsAlertDescription
): Array<Byte> {
    try {
        tlsEncodeAlertRecord(
            contractToTlsVersion(version),
            contractToTlsAlertLevel(level),
            contractToTlsAlertDescription(description)
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS alert record encoding failed: ${e.message}"
        )
    }
}

public func contractTlsDecodeAlertRecord(encodedRecord: Array<Byte>): ContractTlsAlertMessage {
    try {
        contractFromTlsAlertMessage(tlsDecodeAlertRecord(encodedRecord))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS alert record decoding failed: ${e.message}"
        )
    }
}

public func contractTlsIsCloseNotifyAlert(alert: ContractTlsAlertMessage): Bool {
    tlsIsCloseNotifyAlert(
        TlsAlertMessage(
            contractToTlsAlertLevel(alert.level),
            contractToTlsAlertDescription(alert.description)
        )
    )
}

public func contractTls13DeriveExporterMasterSecret(
    masterSecret: Array<Byte>,
    transcriptHash: Array<Byte>
): Array<Byte> {
    try {
        tls13DeriveExporterMasterSecret(masterSecret, transcriptHash)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 exporter master secret derivation failed: ${e.message}"
        )
    }
}

public func contractTls13DeriveExporterMasterSecretRequest(
    request: ContractTls13ExporterMasterSecretRequest
): Array<Byte> {
    contractTls13DeriveExporterMasterSecret(
        request.masterSecret,
        request.transcriptHash
    )
}

public func contractTls13ExportKeyingMaterial(
    exporterMasterSecret: Array<Byte>,
    exporterLabel: String,
    context!: Array<Byte> = [],
    outputLen!: Int64 = 32
): Array<Byte> {
    try {
        tls13ExportKeyingMaterial(
            exporterMasterSecret,
            exporterLabel,
            context: context,
            outputLen: outputLen
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 keying material export failed: ${e.message}"
        )
    }
}

public func contractTls13ExportKeyingMaterialRequest(
    request: ContractTls13ExportKeyingMaterialRequest
): Array<Byte> {
    contractTls13ExportKeyingMaterial(
        request.exporterMasterSecret,
        request.exporterLabel,
        context: request.context,
        outputLen: request.outputLen
    )
}

public func contractTls13DeriveNextApplicationTrafficSecret(
    currentTrafficSecret: Array<Byte>
): Array<Byte> {
    try {
        tls13DeriveNextApplicationTrafficSecret(currentTrafficSecret)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 next application traffic secret derivation failed: ${e.message}"
        )
    }
}

public func contractTls13DeriveApplicationTrafficKeyIv(
    applicationTrafficSecret: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): (Array<Byte>, Array<Byte>) {
    try {
        tls13DeriveApplicationTrafficKeyIv(applicationTrafficSecret, keyLen: keyLen, ivLen: ivLen)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 application traffic key/iv derivation failed: ${e.message}"
        )
    }
}

public func contractTls13ResolveCipherBinding(cipherSuite: Int64): ContractTls13CipherBinding {
    try {
        let algorithm = contractFromTlsAeadAlgorithm(tls13CipherSuiteAeadAlgorithm(cipherSuite))
        ContractTls13CipherBinding(
            cipherSuite,
            contractTls13CipherSuiteName(cipherSuite),
            algorithm,
            tls13CipherSuiteKeyLen(cipherSuite),
            tls13CipherSuiteIvLen(cipherSuite)
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 cipher binding resolve failed: ${e.message}"
        )
    }
}

public func contractTls13ResolveCipherBindingFromServerHello(
    encodedServerHello: Array<Byte>
): ContractTls13CipherBinding {
    try {
        let serverHello = tlsDecodeServerHelloHandshake(encodedServerHello)
        contractTls13ResolveCipherBinding(serverHello.cipherSuite)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 cipher binding resolve from ServerHello failed: ${e.message}"
        )
    }
}

public func contractTls13ResolveCipherBindingFromServerFlight(
    serverFlight: ContractTls13HttpServerFlight
): ContractTls13CipherBinding {
    contractTls13ResolveCipherBindingFromServerHello(serverFlight.serverHello)
}

public func contractTls13DerivePskX25519SecretsForCipherSuite(
    psk: Array<Byte>,
    clientPrivateKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    cipherSuite: Int64
): ContractTls13PskX25519DerivedSecrets {
    try {
        let binding = contractTls13ResolveCipherBinding(cipherSuite)
        let tlsSecrets = tls13DeriveSecretsFromPskAndX25519ForCipherSuite(
            psk,
            clientPrivateKey,
            serverPublicKey,
            transcriptHash,
            cipherSuite
        )
        contractFromTls13PskX25519DerivedSecrets(binding, tlsSecrets)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK+X25519 secret derivation failed: ${e.message}"
        )
    }
}

public func contractTls13DerivePskX25519SecretsFromSessionTicketForCipherSuite(
    ticket: ContractTlsSessionTicket,
    clientPrivateKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    cipherSuite: Int64
): ContractTls13PskX25519DerivedSecrets {
    contractTls13DerivePskX25519SecretsForCipherSuite(
        ticket.secret,
        clientPrivateKey,
        serverPublicKey,
        transcriptHash,
        cipherSuite
    )
}

public func contractTls13DerivePskX25519SecretsFromSessionTicketAndServerHello(
    ticket: ContractTlsSessionTicket,
    clientPrivateKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    encodedServerHello: Array<Byte>
): ContractTls13PskX25519DerivedSecrets {
    let binding = contractTls13ResolveCipherBindingFromServerHello(encodedServerHello)
    contractTls13DerivePskX25519SecretsFromSessionTicketForCipherSuite(
        ticket,
        clientPrivateKey,
        serverPublicKey,
        transcriptHash,
        binding.cipherSuite
    )
}

public func contractTls13CreateClientRecordChannelFromPskX25519Secrets(
    secrets: ContractTls13PskX25519DerivedSecrets
): ContractTlsRecordChannel {
    contractTls13CreateClientRecordChannel(secrets.keyMaterial, algorithm: secrets.cipherBinding.algorithm)
}

public func contractTls13CreateServerRecordChannelFromPskX25519Secrets(
    secrets: ContractTls13PskX25519DerivedSecrets
): ContractTlsRecordChannel {
    contractTls13CreateServerRecordChannel(secrets.keyMaterial, algorithm: secrets.cipherBinding.algorithm)
}

public func contractTls13CreatePskX25519ChannelSetFromSecrets(
    secrets: ContractTls13PskX25519DerivedSecrets
): ContractTls13PskX25519ChannelSet {
    ContractTls13PskX25519ChannelSet(
        secrets,
        contractTls13CreateClientRecordChannelFromPskX25519Secrets(secrets),
        contractTls13CreateServerRecordChannelFromPskX25519Secrets(secrets)
    )
}

public func contractTls13CreatePskX25519ChannelSetFromSessionTicketAndServerHello(
    ticket: ContractTlsSessionTicket,
    clientPrivateKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    encodedServerHello: Array<Byte>
): ContractTls13PskX25519ChannelSet {
    let secrets = contractTls13DerivePskX25519SecretsFromSessionTicketAndServerHello(
        ticket,
        clientPrivateKey,
        serverPublicKey,
        transcriptHash,
        encodedServerHello
    )
    contractTls13CreatePskX25519ChannelSetFromSecrets(secrets)
}

public func contractTls13RotatePskX25519ClientTraffic(
    channels: ContractTls13PskX25519ChannelSet,
    requestPeerUpdate!: Bool = false
): ContractTls13PskX25519TrafficUpdateResult {
    let encodedKeyUpdate = contractTls13BuildKeyUpdateHandshake(requestPeerUpdate: requestPeerUpdate)
    let rotatedSecrets = contractTls13RotatePskX25519ClientSecrets(channels.secrets)
    let rotatedChannels = contractTls13CreatePskX25519ChannelSetFromSecrets(rotatedSecrets)
    ContractTls13PskX25519TrafficUpdateResult(
        encodedKeyUpdate,
        requestPeerUpdate,
        rotatedChannels
    )
}

public func contractTls13RotatePskX25519ServerTraffic(
    channels: ContractTls13PskX25519ChannelSet,
    requestPeerUpdate!: Bool = false
): ContractTls13PskX25519TrafficUpdateResult {
    let encodedKeyUpdate = contractTls13BuildKeyUpdateHandshake(requestPeerUpdate: requestPeerUpdate)
    let rotatedSecrets = contractTls13RotatePskX25519ServerSecrets(channels.secrets)
    let rotatedChannels = contractTls13CreatePskX25519ChannelSetFromSecrets(rotatedSecrets)
    ContractTls13PskX25519TrafficUpdateResult(
        encodedKeyUpdate,
        requestPeerUpdate,
        rotatedChannels
    )
}

public func contractTls13ApplyPskX25519ClientTrafficUpdate(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>
): ContractTls13PskX25519TrafficUpdateResult {
    let requestPeerUpdate = contractTls13DecodeKeyUpdateHandshake(encodedKeyUpdate)
    let rotatedSecrets = contractTls13RotatePskX25519ClientSecrets(channels.secrets)
    let rotatedChannels = contractTls13CreatePskX25519ChannelSetFromSecrets(rotatedSecrets)
    ContractTls13PskX25519TrafficUpdateResult(
        encodedKeyUpdate,
        requestPeerUpdate,
        rotatedChannels
    )
}

public func contractTls13ApplyPskX25519ServerTrafficUpdate(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>
): ContractTls13PskX25519TrafficUpdateResult {
    let requestPeerUpdate = contractTls13DecodeKeyUpdateHandshake(encodedKeyUpdate)
    let rotatedSecrets = contractTls13RotatePskX25519ServerSecrets(channels.secrets)
    let rotatedChannels = contractTls13CreatePskX25519ChannelSetFromSecrets(rotatedSecrets)
    ContractTls13PskX25519TrafficUpdateResult(
        encodedKeyUpdate,
        requestPeerUpdate,
        rotatedChannels
    )
}

public func contractTls13ApplyPskX25519ClientTrafficUpdateAndMaybeRespond(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>,
    forceResponse!: Bool = false
): ContractTls13PskX25519PeerUpdateOrchestrationResult {
    let applied = contractTls13ApplyPskX25519ClientTrafficUpdate(channels, encodedKeyUpdate)
    if (applied.requestPeerUpdate || forceResponse) {
        let response = contractTls13RotatePskX25519ServerTraffic(applied.channels)
        return ContractTls13PskX25519PeerUpdateOrchestrationResult(
            applied.requestPeerUpdate,
            true,
            response.encodedKeyUpdate,
            response.channels
        )
    }
    ContractTls13PskX25519PeerUpdateOrchestrationResult(
        applied.requestPeerUpdate,
        false,
        [],
        applied.channels
    )
}

public func contractTls13ApplyPskX25519ServerTrafficUpdateAndMaybeRespond(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>,
    forceResponse!: Bool = false
): ContractTls13PskX25519PeerUpdateOrchestrationResult {
    let applied = contractTls13ApplyPskX25519ServerTrafficUpdate(channels, encodedKeyUpdate)
    if (applied.requestPeerUpdate || forceResponse) {
        let response = contractTls13RotatePskX25519ClientTraffic(applied.channels)
        return ContractTls13PskX25519PeerUpdateOrchestrationResult(
            applied.requestPeerUpdate,
            true,
            response.encodedKeyUpdate,
            response.channels
        )
    }
    ContractTls13PskX25519PeerUpdateOrchestrationResult(
        applied.requestPeerUpdate,
        false,
        [],
        applied.channels
    )
}

public func contractTls13RotatePskX25519LocalTraffic(
    channels: ContractTls13PskX25519ChannelSet,
    localEndpointRole: ContractTlsEndpointRole,
    requestPeerUpdate!: Bool = false
): ContractTls13PskX25519TrafficUpdateResult {
    match (localEndpointRole) {
        case ContractTlsEndpointRole.Client =>
            contractTls13RotatePskX25519ClientTraffic(channels, requestPeerUpdate: requestPeerUpdate)
        case ContractTlsEndpointRole.Server =>
            contractTls13RotatePskX25519ServerTraffic(channels, requestPeerUpdate: requestPeerUpdate)
    }
}

public func contractTls13ApplyPskX25519PeerTrafficUpdate(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>,
    localEndpointRole: ContractTlsEndpointRole
): ContractTls13PskX25519TrafficUpdateResult {
    match (localEndpointRole) {
        case ContractTlsEndpointRole.Client =>
            contractTls13ApplyPskX25519ServerTrafficUpdate(channels, encodedKeyUpdate)
        case ContractTlsEndpointRole.Server =>
            contractTls13ApplyPskX25519ClientTrafficUpdate(channels, encodedKeyUpdate)
    }
}

public func contractTls13ApplyPskX25519PeerTrafficUpdateAndMaybeRespond(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>,
    localEndpointRole: ContractTlsEndpointRole,
    forceResponse!: Bool = false
): ContractTls13PskX25519PeerUpdateOrchestrationResult {
    match (localEndpointRole) {
        case ContractTlsEndpointRole.Client =>
            contractTls13ApplyPskX25519ServerTrafficUpdateAndMaybeRespond(
                channels,
                encodedKeyUpdate,
                forceResponse: forceResponse
            )
        case ContractTlsEndpointRole.Server =>
            contractTls13ApplyPskX25519ClientTrafficUpdateAndMaybeRespond(
                channels,
                encodedKeyUpdate,
                forceResponse: forceResponse
            )
    }
}

public func contractTls13BuildKeyUpdateHandshake(
    requestPeerUpdate!: Bool = false
): Array<Byte> {
    try {
        tls13BuildKeyUpdateHandshake(requestPeerUpdate: requestPeerUpdate)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 KeyUpdate build failed: ${e.message}"
        )
    }
}

public func contractTls13DecodeKeyUpdateHandshake(encodedKeyUpdate: Array<Byte>): Bool {
    try {
        tls13DecodeKeyUpdateHandshake(encodedKeyUpdate)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 KeyUpdate decode failed: ${e.message}"
        )
    }
}

public func contractTls13PrepareKeyUpdate(
    currentTrafficSecret: Array<Byte>,
    requestPeerUpdate!: Bool = false,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13KeyUpdatePlan {
    let encodedKeyUpdate = contractTls13BuildKeyUpdateHandshake(requestPeerUpdate: requestPeerUpdate)
    contractTls13BuildKeyUpdatePlan(
        currentTrafficSecret,
        encodedKeyUpdate,
        keyLen,
        ivLen
    )
}

public func contractTls13PrepareKeyUpdateRequest(
    request: ContractTls13KeyUpdateRequest
): ContractTls13KeyUpdatePlan {
    contractTls13PrepareKeyUpdate(
        request.currentTrafficSecret,
        requestPeerUpdate: request.requestPeerUpdate,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls13ApplyPeerKeyUpdate(
    currentTrafficSecret: Array<Byte>,
    encodedKeyUpdate: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13KeyUpdatePlan {
    contractTls13BuildKeyUpdatePlan(
        currentTrafficSecret,
        encodedKeyUpdate,
        keyLen,
        ivLen
    )
}

public func contractTls13ApplyPeerKeyUpdateRequest(
    request: ContractTls13PeerKeyUpdateRequest
): ContractTls13KeyUpdatePlan {
    contractTls13ApplyPeerKeyUpdate(
        request.currentTrafficSecret,
        request.encodedKeyUpdate,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls13ResolveCipherBindingFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession
): ContractTls13CipherBinding {
    match (session.result.cipherBinding) {
        case Some(binding) => binding
        case None =>
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 verified session does not carry cipher binding"
            )
    }
}

public func contractTls13CreateClientRecordChannelFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession
): ContractTlsRecordChannel {
    let binding = contractTls13ResolveCipherBindingFromVerifiedSession(session)
    contractTls13CreateClientRecordChannel(
        session.result.keyMaterial,
        algorithm: binding.algorithm
    )
}

public func contractTls13CreateClientRecordChannelFromVerifiedSessionRequest(
    request: ContractTls13HttpVerifiedSessionRequest
): ContractTlsRecordChannel {
    contractTls13CreateClientRecordChannelFromVerifiedSession(request.session)
}

public func contractTls13CreateServerRecordChannelFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession
): ContractTlsRecordChannel {
    let binding = contractTls13ResolveCipherBindingFromVerifiedSession(session)
    contractTls13CreateServerRecordChannel(
        session.result.keyMaterial,
        algorithm: binding.algorithm
    )
}

public func contractTls13CreateServerRecordChannelFromVerifiedSessionRequest(
    request: ContractTls13HttpVerifiedSessionRequest
): ContractTlsRecordChannel {
    contractTls13CreateServerRecordChannelFromVerifiedSession(request.session)
}

public func contractTls13CreateVerifiedSessionChannelSet(
    session: ContractTls13HttpClientVerifiedSession
): ContractTls13HttpVerifiedSessionChannelSet {
    ContractTls13HttpVerifiedSessionChannelSet(
        session,
        contractTls13CreateClientRecordChannelFromVerifiedSession(session),
        contractTls13CreateServerRecordChannelFromVerifiedSession(session)
    )
}

public func contractTls13CreateVerifiedSessionChannelSetRequest(
    request: ContractTls13HttpVerifiedSessionRequest
): ContractTls13HttpVerifiedSessionChannelSet {
    contractTls13CreateVerifiedSessionChannelSet(request.session)
}

public func contractTls13DeriveExporterMasterSecretFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession
): Array<Byte> {
    contractTls13DeriveExporterMasterSecret(
        session.masterSecret,
        session.transcriptHash
    )
}

public func contractTls13DeriveExporterMasterSecretFromVerifiedSessionRequest(
    request: ContractTls13HttpVerifiedSessionRequest
): Array<Byte> {
    contractTls13DeriveExporterMasterSecretFromVerifiedSession(request.session)
}

public func contractTls13ExportKeyingMaterialFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    exporterLabel: String,
    context!: Array<Byte> = [],
    outputLen!: Int64 = 32
): Array<Byte> {
    let exporterMasterSecret = contractTls13DeriveExporterMasterSecretFromVerifiedSession(session)
    contractTls13ExportKeyingMaterial(
        exporterMasterSecret,
        exporterLabel,
        context: context,
        outputLen: outputLen
    )
}

public func contractTls13ExportKeyingMaterialFromVerifiedSessionRequest(
    request: ContractTls13HttpVerifiedSessionExportRequest
): Array<Byte> {
    contractTls13ExportKeyingMaterialFromVerifiedSession(
        request.session,
        request.exporterLabel,
        context: request.context,
        outputLen: request.outputLen
    )
}

public func contractTls13PrepareKeyUpdateFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    requestPeerUpdate!: Bool = false
): ContractTls13KeyUpdatePlan {
    let binding = contractTls13ResolveCipherBindingFromVerifiedSession(session)
    contractTls13PrepareKeyUpdate(
        session.clientAppTrafficSecret,
        requestPeerUpdate: requestPeerUpdate,
        keyLen: binding.keyLen,
        ivLen: binding.ivLen
    )
}

public func contractTls13PrepareKeyUpdateFromVerifiedSessionRequest(
    request: ContractTls13HttpVerifiedSessionKeyUpdateRequest
): ContractTls13KeyUpdatePlan {
    contractTls13PrepareKeyUpdateFromVerifiedSession(
        request.session,
        requestPeerUpdate: request.requestPeerUpdate
    )
}

public func contractTls13ApplyPeerKeyUpdateFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    encodedKeyUpdate: Array<Byte>
): ContractTls13KeyUpdatePlan {
    let binding = contractTls13ResolveCipherBindingFromVerifiedSession(session)
    contractTls13ApplyPeerKeyUpdate(
        session.serverAppTrafficSecret,
        encodedKeyUpdate,
        keyLen: binding.keyLen,
        ivLen: binding.ivLen
    )
}

public func contractTls13ApplyPeerKeyUpdateFromVerifiedSessionRequest(
    request: ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest
): ContractTls13KeyUpdatePlan {
    contractTls13ApplyPeerKeyUpdateFromVerifiedSession(
        request.session,
        request.encodedKeyUpdate
    )
}

public func contractTls13RotateClientTrafficInVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    requestPeerUpdate!: Bool = false
): ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    let plan = contractTls13PrepareKeyUpdateFromVerifiedSession(
        session,
        requestPeerUpdate: requestPeerUpdate
    )
    let updatedSession = contractTls13RebuildVerifiedSession(
        session,
        session.result.keyMaterial.serverWriteKey,
        session.result.keyMaterial.serverWriteIv,
        plan.nextTrafficSecret,
        session.serverAppTrafficSecret,
        plan.nextWriteKey,
        plan.nextWriteIv
    )
    ContractTls13HttpVerifiedSessionTrafficUpdateResult(
        plan.encodedKeyUpdate,
        plan.requestPeerUpdate,
        contractTls13CreateVerifiedSessionChannelSet(updatedSession)
    )
}

public func contractTls13RotateClientTrafficInVerifiedSessionRequest(
    request: ContractTls13HttpVerifiedSessionKeyUpdateRequest
): ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    contractTls13RotateClientTrafficInVerifiedSession(
        request.session,
        requestPeerUpdate: request.requestPeerUpdate
    )
}

public func contractTls13ApplyPeerTrafficUpdateToVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    encodedKeyUpdate: Array<Byte>
): ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    let plan = contractTls13ApplyPeerKeyUpdateFromVerifiedSession(
        session,
        encodedKeyUpdate
    )
    let updatedSession = contractTls13RebuildVerifiedSession(
        session,
        plan.nextWriteKey,
        plan.nextWriteIv,
        session.clientAppTrafficSecret,
        plan.nextTrafficSecret,
        session.result.keyMaterial.clientWriteKey,
        session.result.keyMaterial.clientWriteIv
    )
    ContractTls13HttpVerifiedSessionTrafficUpdateResult(
        plan.encodedKeyUpdate,
        plan.requestPeerUpdate,
        contractTls13CreateVerifiedSessionChannelSet(updatedSession)
    )
}

public func contractTls13ApplyPeerTrafficUpdateToVerifiedSessionRequest(
    request: ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest
): ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    contractTls13ApplyPeerTrafficUpdateToVerifiedSession(
        request.session,
        request.encodedKeyUpdate
    )
}

public func contractTls13BuildNewSessionTicketFromSessionTicket(
    ticket: ContractTlsSessionTicket,
    ticketAgeAdd!: Int64 = 0
): Array<Byte> {
    try {
        let tlsTicket = contractToTlsSessionTicket(ticket)
        tls13BuildNewSessionTicketFromSessionTicket(tlsTicket, ticketAgeAdd: ticketAgeAdd)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 NewSessionTicket build from session ticket failed: ${e.message}"
        )
    }
}

public func contractTls13BuildNewSessionTicketFromSessionTicketRequest(
    request: ContractTls13NewSessionTicketRequest
): Array<Byte> {
    contractTls13BuildNewSessionTicketFromSessionTicket(
        request.ticket,
        ticketAgeAdd: request.ticketAgeAdd
    )
}

public func contractTls13DecodeSessionTicketFromNewSessionTicket(
    encodedNewSessionTicket: Array<Byte>
): ContractTlsSessionTicket {
    try {
        contractFromTlsSessionTicket(tls13DecodeSessionTicketFromNewSessionTicket(encodedNewSessionTicket))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 session ticket decode from NewSessionTicket failed: ${e.message}"
        )
    }
}

public func contractTls13StoreNewSessionTicketToCache(
    cache: ContractTlsSessionCache,
    encodedNewSessionTicket: Array<Byte>
): ContractTlsSessionTicket {
    let ticket = contractTls13DecodeSessionTicketFromNewSessionTicket(encodedNewSessionTicket)
    cache.store(ticket)
}

public func contractTls13StoreNewSessionTicketToCacheRequest(
    request: ContractTls13StoreNewSessionTicketRequest
): ContractTlsSessionTicket {
    contractTls13StoreNewSessionTicketToCache(
        request.cache,
        request.encodedNewSessionTicket
    )
}

public func contractTls13TryBuildHttpClientHelloPskFromSessionCache(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ?ContractTls13PskClientHelloFromCacheResult {
    match (cache.load(identity, nowUnixSeconds: nowUnixSeconds)) {
        case Some(ticket) =>
            let encodedClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(
                ticket,
                sessionId: sessionId
            )
            Some(ContractTls13PskClientHelloFromCacheResult(ticket, encodedClientHello))
        case None =>
            None
    }
}

public func contractTls13TryBuildHttpClientHelloPskFromSessionCacheRequest(
    request: ContractTls13PskClientHelloFromSessionCacheRequest
): ?ContractTls13PskClientHelloFromCacheResult {
    contractTls13TryBuildHttpClientHelloPskFromSessionCache(
        request.cache,
        request.identity,
        nowUnixSeconds: request.nowUnixSeconds,
        sessionId: request.sessionId
    )
}

public func contractTryBuildHttpClientHelloPskFromSessionCacheOutcome(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ContractTls13PskClientHelloFromCacheOutcome {
    match (cache.load(identity, nowUnixSeconds: nowUnixSeconds)) {
        case Some(ticket) =>
            let encodedClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(
                ticket,
                sessionId: sessionId
            )
            ContractTls13PskClientHelloFromCacheOutcome(
                true,
                "OK",
                result: Some(ContractTls13PskClientHelloFromCacheResult(ticket, encodedClientHello))
            )
        case None =>
            ContractTls13PskClientHelloFromCacheOutcome(
                false,
                "TLS1.3 PSK session ticket is not found in cache",
                code: Some(ContractErrorCode.KeyNotFound),
                igniteCode: Some(contractMapToIgniteCryptoErrorCode(ContractErrorCode.KeyNotFound))
            )
    }
}

public func contractTryBuildHttpClientHelloPskFromSessionCacheRequestOutcome(
    request: ContractTls13PskClientHelloFromSessionCacheRequest
): ContractTls13PskClientHelloFromCacheOutcome {
    contractTryBuildHttpClientHelloPskFromSessionCacheOutcome(
        request.cache,
        request.identity,
        nowUnixSeconds: request.nowUnixSeconds,
        sessionId: request.sessionId
    )
}

public func contractTls13EvaluateSessionTicketLifecycle(
    ticket: ContractTlsSessionTicket,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0
): ContractTls13SessionTicketLifecycleResult {
    let now = if (nowUnixSeconds > 0) {
        nowUnixSeconds
    } else {
        ticket.issuedAtUnixSeconds
    }
    if (now <= 0) {
        throw ContractException(ContractErrorCode.BadInput, "TLS1.3 session ticket lifecycle nowUnixSeconds must be > 0")
    }

    if (ticket.identity.version != ContractTlsVersion.Tls13) {
        return ContractTls13SessionTicketLifecycleResult(
            false,
            false,
            "UNSUPPORTED_VERSION",
            now,
            ticket.expiresAtUnixSeconds - now
        )
    }
    if (now < ticket.issuedAtUnixSeconds) {
        return ContractTls13SessionTicketLifecycleResult(
            false,
            false,
            "NOT_YET_ACTIVE",
            now,
            ticket.expiresAtUnixSeconds - now
        )
    }
    if (
        policy.requiredServerName.size > 0 &&
        ticket.identity.serverName != policy.requiredServerName
    ) {
        return ContractTls13SessionTicketLifecycleResult(
            false,
            false,
            "SERVER_NAME_MISMATCH",
            now,
            ticket.expiresAtUnixSeconds - now
        )
    }
    if (
        policy.requiredAlpnProtocol.size > 0 &&
        ticket.identity.alpnProtocol != policy.requiredAlpnProtocol
    ) {
        return ContractTls13SessionTicketLifecycleResult(
            false,
            false,
            "ALPN_MISMATCH",
            now,
            ticket.expiresAtUnixSeconds - now
        )
    }

    let remaining = ticket.expiresAtUnixSeconds - now
    if (remaining <= 0) {
        return ContractTls13SessionTicketLifecycleResult(false, false, "EXPIRED", now, remaining)
    }
    if (remaining < policy.minRemainingTtlSeconds) {
        return ContractTls13SessionTicketLifecycleResult(
            false,
            false,
            "INSUFFICIENT_REMAINING_TTL",
            now,
            remaining
        )
    }

    let shouldRenew = if (policy.renewBeforeExpirySeconds > 0) {
        remaining <= policy.renewBeforeExpirySeconds
    } else {
        false
    }
    let reason = if (shouldRenew) {
        "OK_RENEW_RECOMMENDED"
    } else {
        "OK"
    }
    ContractTls13SessionTicketLifecycleResult(true, shouldRenew, reason, now, remaining)
}

public func contractTls13EvaluateSessionTicketLifecycleRequest(
    request: ContractTls13SessionTicketLifecycleRequest
): ContractTls13SessionTicketLifecycleResult {
    contractTls13EvaluateSessionTicketLifecycle(
        request.ticket,
        policy: request.policy,
        nowUnixSeconds: request.nowUnixSeconds
    )
}

public func contractTls13RequireUsableSessionTicket(
    ticket: ContractTlsSessionTicket,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0
): ContractTls13SessionTicketLifecycleResult {
    let lifecycle = contractTls13EvaluateSessionTicketLifecycle(
        ticket,
        policy: policy,
        nowUnixSeconds: nowUnixSeconds
    )
    if (!lifecycle.usable) {
        throw ContractException(
            ContractErrorCode.VerifyFailed,
            "TLS1.3 session ticket lifecycle rejected: ${lifecycle.reason}"
        )
    }
    lifecycle
}

public func contractTls13RequireUsableSessionTicketRequest(
    request: ContractTls13SessionTicketLifecycleRequest
): ContractTls13SessionTicketLifecycleResult {
    contractTls13RequireUsableSessionTicket(
        request.ticket,
        policy: request.policy,
        nowUnixSeconds: request.nowUnixSeconds
    )
}

public func contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicy(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ?ContractTls13PskClientHelloFromCacheResult {
    match (cache.load(identity, nowUnixSeconds: nowUnixSeconds)) {
        case Some(ticket) =>
            let lifecycle = contractTls13EvaluateSessionTicketLifecycle(
                ticket,
                policy: policy,
                nowUnixSeconds: nowUnixSeconds
            )
            if (!lifecycle.usable) {
                return None
            }
            let encodedClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(
                ticket,
                sessionId: sessionId
            )
            Some(ContractTls13PskClientHelloFromCacheResult(ticket, encodedClientHello))
        case None =>
            None
    }
}

public func contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(
    request: ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest
): ?ContractTls13PskClientHelloFromCacheResult {
    contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicy(
        request.cache,
        request.identity,
        policy: request.policy,
        nowUnixSeconds: request.nowUnixSeconds,
        sessionId: request.sessionId
    )
}

public func contractTryBuildHttpClientHelloPskFromSessionCacheWithPolicyOutcome(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ContractTls13PskClientHelloFromCacheOutcome {
    match (cache.load(identity, nowUnixSeconds: nowUnixSeconds)) {
        case Some(ticket) =>
            let lifecycle = contractTls13EvaluateSessionTicketLifecycle(
                ticket,
                policy: policy,
                nowUnixSeconds: nowUnixSeconds
            )
            if (!lifecycle.usable) {
                return ContractTls13PskClientHelloFromCacheOutcome(
                    false,
                    "TLS1.3 session ticket lifecycle rejected: ${lifecycle.reason}",
                    code: Some(ContractErrorCode.VerifyFailed),
                    igniteCode: Some(contractMapToIgniteCryptoErrorCode(ContractErrorCode.VerifyFailed)),
                    lifecycle: Some(lifecycle)
                )
            }
            let encodedClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(
                ticket,
                sessionId: sessionId
            )
            ContractTls13PskClientHelloFromCacheOutcome(
                true,
                "OK",
                result: Some(ContractTls13PskClientHelloFromCacheResult(ticket, encodedClientHello)),
                lifecycle: Some(lifecycle)
            )
        case None =>
            ContractTls13PskClientHelloFromCacheOutcome(
                false,
                "TLS1.3 usable PSK session ticket is not found in cache",
                code: Some(ContractErrorCode.KeyNotFound),
                igniteCode: Some(contractMapToIgniteCryptoErrorCode(ContractErrorCode.KeyNotFound))
            )
    }
}

public func contractTryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequestOutcome(
    request: ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest
): ContractTls13PskClientHelloFromCacheOutcome {
    contractTryBuildHttpClientHelloPskFromSessionCacheWithPolicyOutcome(
        request.cache,
        request.identity,
        policy: request.policy,
        nowUnixSeconds: request.nowUnixSeconds,
        sessionId: request.sessionId
    )
}

public func contractTls13BuildHttpClientHelloPskFromSessionCacheWithPolicy(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ContractTls13PskClientHelloFromCacheResult {
    match (
        contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicy(
            cache,
            identity,
            policy: policy,
            nowUnixSeconds: nowUnixSeconds,
            sessionId: sessionId
        )
    ) {
        case Some(result) =>
            result
        case None =>
            throw ContractException(
                ContractErrorCode.KeyNotFound,
                "TLS1.3 usable PSK session ticket is not found in cache"
            )
    }
}

public func contractTls13BuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(
    request: ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest
): ContractTls13PskClientHelloFromCacheResult {
    contractTls13BuildHttpClientHelloPskFromSessionCacheWithPolicy(
        request.cache,
        request.identity,
        policy: request.policy,
        nowUnixSeconds: request.nowUnixSeconds,
        sessionId: request.sessionId
    )
}

public func contractTls13BuildHttpClientHelloPskFromSessionCache(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ContractTls13PskClientHelloFromCacheResult {
    match (
        contractTls13TryBuildHttpClientHelloPskFromSessionCache(
            cache,
            identity,
            nowUnixSeconds: nowUnixSeconds,
            sessionId: sessionId
        )
    ) {
        case Some(result) =>
            result
        case None =>
            throw ContractException(
                ContractErrorCode.KeyNotFound,
                "TLS1.3 PSK session ticket is not found in cache"
            )
    }
}

public func contractTls13BuildHttpClientHelloPskFromSessionCacheRequest(
    request: ContractTls13PskClientHelloFromSessionCacheRequest
): ContractTls13PskClientHelloFromCacheResult {
    contractTls13BuildHttpClientHelloPskFromSessionCache(
        request.cache,
        request.identity,
        nowUnixSeconds: request.nowUnixSeconds,
        sessionId: request.sessionId
    )
}

public func contractTls13PreparePskEarlyDataFromSessionTicket(
    ticket: ContractTlsSessionTicket,
    sessionId!: Array<Byte> = [],
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13PskEarlyDataPlan {
    let encodedClientHello = contractTls13BuildHttpClientHelloPskFromSessionTicket(
        ticket,
        sessionId: sessionId
    )
    contractTls13BuildPskEarlyDataPlan(
        ticket,
        encodedClientHello,
        0,
        keyLen,
        ivLen
    )
}

public func contractTls13PreparePskEarlyDataFromSessionTicketRequest(
    request: ContractTls13PskEarlyDataFromSessionTicketRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13PreparePskEarlyDataFromSessionTicket(
        request.ticket,
        sessionId: request.sessionId,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls13PreparePskEarlyDataFromSessionCache(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = [],
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13PskEarlyDataPlan {
    let fromCache = contractTls13BuildHttpClientHelloPskFromSessionCache(
        cache,
        identity,
        nowUnixSeconds: nowUnixSeconds,
        sessionId: sessionId
    )
    contractTls13BuildPskEarlyDataPlan(
        fromCache.ticket,
        fromCache.encodedClientHello,
        0,
        keyLen,
        ivLen
    )
}

public func contractTls13PreparePskEarlyDataFromSessionCacheRequest(
    request: ContractTls13PskEarlyDataFromSessionCacheRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13PreparePskEarlyDataFromSessionCache(
        request.cache,
        request.identity,
        nowUnixSeconds: request.nowUnixSeconds,
        sessionId: request.sessionId,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls13AcceptPskEarlyDataFromClientHello(
    encodedClientHello: Array<Byte>,
    nowUnixSeconds!: Int64 = 0,
    selectedIdentityIndex!: Int64 = -1,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13PskEarlyDataPlan {
    let resolvedIdentityIndex = if (selectedIdentityIndex >= 0) {
        selectedIdentityIndex
    } else {
        contractTls13SelectPskIdentityFromSessionTickets(
            encodedClientHello,
            nowUnixSeconds: nowUnixSeconds
        )
    }
    if (resolvedIdentityIndex < 0 || resolvedIdentityIndex > 65535) {
        throw ContractException(ContractErrorCode.BadInput, "TLS1.3 selected identity index must be uint16")
    }

    let ticket = contractTls13ExtractClientPskSessionTicket(
        encodedClientHello,
        selectedIdentityIndex: resolvedIdentityIndex
    )
    if (nowUnixSeconds > 0 && contractTlsIsSessionTicketExpired(ticket, nowUnixSeconds: nowUnixSeconds)) {
        throw ContractException(ContractErrorCode.VerifyFailed, "TLS1.3 PSK session ticket is expired")
    }

    try {
        let binderOk = tls13VerifyClientPskBinder(
            encodedClientHello,
            ticket.secret,
            selectedIdentityIndex: resolvedIdentityIndex
        )
        if (!binderOk) {
            throw ContractException(ContractErrorCode.VerifyFailed, "TLS1.3 PSK binder verification failed")
        }
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK binder verification failed: ${e.message}"
        )
    }

    contractTls13BuildPskEarlyDataPlan(
        ticket,
        encodedClientHello,
        resolvedIdentityIndex,
        keyLen,
        ivLen
    )
}

public func contractTls13AcceptPskEarlyDataFromClientHelloRequest(
    request: ContractTls13PskEarlyDataAcceptRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataFromClientHello(
        request.encodedClientHello,
        nowUnixSeconds: request.nowUnixSeconds,
        selectedIdentityIndex: request.selectedIdentityIndex,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls13BuildPskEarlyDataReplayKey(
    plan: ContractTls13PskEarlyDataPlan
): String {
    contractTls13BuildPskEarlyDataReplayKeyFromFields(
        plan.ticket.identity,
        plan.clientHelloHash
    )
}

public func contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCache(
    encodedClientHello: Array<Byte>,
    replayCache: ContractTls13EarlyDataReplayCache,
    nowUnixSeconds!: Int64 = 0,
    selectedIdentityIndex!: Int64 = -1,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12,
    replayTtlSeconds!: Int64 = 0
): ContractTls13PskEarlyDataPlan {
    let plan = contractTls13AcceptPskEarlyDataFromClientHello(
        encodedClientHello,
        nowUnixSeconds: nowUnixSeconds,
        selectedIdentityIndex: selectedIdentityIndex,
        keyLen: keyLen,
        ivLen: ivLen
    )
    contractTls13RememberEarlyDataReplayOrThrow(
        plan,
        replayCache,
        nowUnixSeconds,
        replayTtlSeconds
    )
    plan
}

public func contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCacheRequest(
    request: ContractTls13PskEarlyDataAcceptWithReplayCacheRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCache(
        request.encodedClientHello,
        request.replayCache,
        nowUnixSeconds: request.nowUnixSeconds,
        selectedIdentityIndex: request.selectedIdentityIndex,
        keyLen: request.keyLen,
        ivLen: request.ivLen,
        replayTtlSeconds: request.replayTtlSeconds
    )
}

public func contractTls13AcceptPskEarlyDataForHttp(
    encodedClientHello: Array<Byte>,
    expectedServerName!: String = "",
    expectedAlpnProtocol!: String = "",
    nowUnixSeconds!: Int64 = 0,
    selectedIdentityIndex!: Int64 = -1,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13PskEarlyDataPlan {
    let plan = contractTls13AcceptPskEarlyDataFromClientHello(
        encodedClientHello,
        nowUnixSeconds: nowUnixSeconds,
        selectedIdentityIndex: selectedIdentityIndex,
        keyLen: keyLen,
        ivLen: ivLen
    )
    contractTls13ValidatePskEarlyDataHttpBinding(
        plan.ticket.identity,
        expectedServerName,
        expectedAlpnProtocol
    )
    plan
}

public func contractTls13AcceptPskEarlyDataForHttpRequest(
    request: ContractTls13PskEarlyDataHttpAcceptRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataForHttp(
        request.encodedClientHello,
        expectedServerName: request.expectedServerName,
        expectedAlpnProtocol: request.expectedAlpnProtocol,
        nowUnixSeconds: request.nowUnixSeconds,
        selectedIdentityIndex: request.selectedIdentityIndex,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls13AcceptPskEarlyDataForHttpWithReplayCache(
    encodedClientHello: Array<Byte>,
    replayCache: ContractTls13EarlyDataReplayCache,
    expectedServerName!: String = "",
    expectedAlpnProtocol!: String = "",
    nowUnixSeconds!: Int64 = 0,
    selectedIdentityIndex!: Int64 = -1,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12,
    replayTtlSeconds!: Int64 = 0
): ContractTls13PskEarlyDataPlan {
    let plan = contractTls13AcceptPskEarlyDataForHttp(
        encodedClientHello,
        expectedServerName: expectedServerName,
        expectedAlpnProtocol: expectedAlpnProtocol,
        nowUnixSeconds: nowUnixSeconds,
        selectedIdentityIndex: selectedIdentityIndex,
        keyLen: keyLen,
        ivLen: ivLen
    )
    contractTls13RememberEarlyDataReplayOrThrow(
        plan,
        replayCache,
        nowUnixSeconds,
        replayTtlSeconds
    )
    plan
}

public func contractTls13AcceptPskEarlyDataForHttpWithReplayCacheRequest(
    request: ContractTls13PskEarlyDataHttpAcceptWithReplayCacheRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataForHttpWithReplayCache(
        request.encodedClientHello,
        request.replayCache,
        expectedServerName: request.expectedServerName,
        expectedAlpnProtocol: request.expectedAlpnProtocol,
        nowUnixSeconds: request.nowUnixSeconds,
        selectedIdentityIndex: request.selectedIdentityIndex,
        keyLen: request.keyLen,
        ivLen: request.ivLen,
        replayTtlSeconds: request.replayTtlSeconds
    )
}

private func contractTls13RememberEarlyDataReplayOrThrow(
    plan: ContractTls13PskEarlyDataPlan,
    replayCache: ContractTls13EarlyDataReplayCache,
    nowUnixSeconds: Int64,
    replayTtlSeconds: Int64
): Unit {
    let replayKey = contractTls13BuildPskEarlyDataReplayKey(plan)
    let replayNow = if (nowUnixSeconds > 0) {
        nowUnixSeconds
    } else {
        plan.ticket.issuedAtUnixSeconds
    }

    var effectiveReplayTtl = replayTtlSeconds
    if (effectiveReplayTtl <= 0) {
        let remainingLifetime = plan.ticket.expiresAtUnixSeconds - replayNow
        if (remainingLifetime > 0) {
            effectiveReplayTtl = remainingLifetime
        }
    }
    let accepted = replayCache.remember(
        replayKey,
        nowUnixSeconds: replayNow,
        ttlSeconds: effectiveReplayTtl
    )
    if (!accepted) {
        throw ContractException(ContractErrorCode.VerifyFailed, "TLS1.3 PSK early data replay detected")
    }
}

public func contractTls13BuildHttpClientHelloPskFromSessionTicket(
    ticket: ContractTlsSessionTicket,
    sessionId!: Array<Byte> = []
): Array<Byte> {
    try {
        tls13BuildClientHelloPskFromSessionTicket(contractToTlsSessionTicket(ticket), sessionId: sessionId)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK ClientHello build from session ticket failed: ${e.message}"
        )
    }
}

public func contractTls13BuildHttpClientHelloPskFromSessionTickets(
    tickets: Array<ContractTlsSessionTicket>,
    sessionId!: Array<Byte> = []
): Array<Byte> {
    if (tickets.size == 0) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "TLS1.3 PSK ClientHello build from session ticket list requires at least one ticket"
        )
    }
    try {
        let tlsTickets = ArrayList<TlsSessionTicket>()
        for (ticket in tickets) {
            tlsTickets.add(contractToTlsSessionTicket(ticket))
        }
        tls13BuildClientHelloPskFromSessionTickets(tlsTickets.toArray(), sessionId: sessionId)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK ClientHello build from session ticket list failed: ${e.message}"
        )
    }
}

public func contractTls13SelectPskIdentityFromSessionTickets(
    encodedClientHello: Array<Byte>,
    nowUnixSeconds!: Int64 = 0
): Int64 {
    try {
        tls13SelectPskIdentityFromSessionTickets(encodedClientHello, nowUnixSeconds: nowUnixSeconds)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK session ticket identity selection failed: ${e.message}"
        )
    }
}

public func contractTls13BuildHttpServerHelloForPskFromSessionTicket(
    encodedClientHello: Array<Byte>,
    selectedIdentityIndex!: Int64 = 0,
    nowUnixSeconds!: Int64 = 0
): Array<Byte> {
    try {
        tls13BuildServerHelloForPskFromSessionTicket(
            encodedClientHello,
            selectedIdentityIndex: selectedIdentityIndex,
            nowUnixSeconds: nowUnixSeconds
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK ServerHello build from session ticket failed: ${e.message}"
        )
    }
}

public func contractTls13BuildHttpServerHelloForPskBySessionTickets(
    encodedClientHello: Array<Byte>,
    nowUnixSeconds!: Int64 = 0
): Array<Byte> {
    try {
        tls13BuildServerHelloForPskBySessionTickets(encodedClientHello, nowUnixSeconds: nowUnixSeconds)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK ServerHello build from session ticket list failed: ${e.message}"
        )
    }
}

public func contractTls13ExtractClientPskSessionTicket(
    encodedClientHello: Array<Byte>,
    selectedIdentityIndex!: Int64 = 0
): ContractTlsSessionTicket {
    try {
        let encodedTicket = tls13ExtractClientPskIdentity(
            encodedClientHello,
            selectedIdentityIndex: selectedIdentityIndex
        )
        contractFromTlsSessionTicket(tlsDecodeSessionTicket(encodedTicket))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK session ticket extract failed: ${e.message}"
        )
    }
}

public func contractTls13ExtractServerSelectedPskIdentity(
    encodedServerHello: Array<Byte>
): Int64 {
    try {
        tls13ExtractServerSelectedPskIdentity(encodedServerHello)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK selected identity extract failed: ${e.message}"
        )
    }
}

public class ContractTls13HttpClientResult {
    public let selectedAlpn: String
    public let requestedServerName: String
    public let acknowledgedServerName: Bool
    public let chainLength: Int64
    public let leafSubjectCommonName: String
    public let trustAnchorCommonName: String
    public let leafDerSha256: Array<Byte>
    public let leafSpkiSha256: Array<Byte>
    public let keyMaterial: ContractTls13ApplicationKeyMaterial
    public let cipherBinding: ?ContractTls13CipherBinding

    public init(
        selectedAlpn: String,
        requestedServerName: String,
        acknowledgedServerName: Bool,
        chainLength: Int64,
        leafSubjectCommonName: String,
        trustAnchorCommonName: String,
        leafDerSha256: Array<Byte>,
        leafSpkiSha256: Array<Byte>,
        keyMaterial: ContractTls13ApplicationKeyMaterial,
        cipherBinding!: ?ContractTls13CipherBinding = None
    ) {
        if (chainLength <= 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 verified chain length must be > 0")
        }
        requireSha256Pin(leafDerSha256, "leafDerSha256")
        requireSha256Pin(leafSpkiSha256, "leafSpkiSha256")
        this.selectedAlpn = selectedAlpn.trimAscii()
        this.requestedServerName = requestedServerName.trimAscii().toAsciiLower()
        this.acknowledgedServerName = acknowledgedServerName
        this.chainLength = chainLength
        this.leafSubjectCommonName = leafSubjectCommonName
        this.trustAnchorCommonName = trustAnchorCommonName
        this.leafDerSha256 = leafDerSha256.clone()
        this.leafSpkiSha256 = leafSpkiSha256.clone()
        this.keyMaterial = keyMaterial
        this.cipherBinding = cipherBinding
    }
}

public class ContractTls13HttpClientVerifiedSession {
    public let result: ContractTls13HttpClientResult
    public let clientAppTrafficSecret: Array<Byte>
    public let serverAppTrafficSecret: Array<Byte>
    public let masterSecret: Array<Byte>
    public let transcriptHash: Array<Byte>

    public init(
        result: ContractTls13HttpClientResult,
        clientAppTrafficSecret: Array<Byte>,
        serverAppTrafficSecret: Array<Byte>,
        masterSecret: Array<Byte>,
        transcriptHash: Array<Byte>
    ) {
        if (
            clientAppTrafficSecret.size == 0 ||
            serverAppTrafficSecret.size == 0 ||
            masterSecret.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 verified session traffic/master secrets must not be empty"
            )
        }
        if (transcriptHash.size != 32) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 verified session transcript hash must be SHA-256 sized"
            )
        }
        this.result = result
        this.clientAppTrafficSecret = clientAppTrafficSecret.clone()
        this.serverAppTrafficSecret = serverAppTrafficSecret.clone()
        this.masterSecret = masterSecret.clone()
        this.transcriptHash = transcriptHash.clone()
    }
}

public class ContractTls13HttpClientVerifyOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractTls13HttpClientResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractTls13HttpClientResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 HTTP verify outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "TLS1.3 HTTP verify outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractTls13HttpClientVerifiedSessionOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractTls13HttpClientVerifiedSession

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractTls13HttpClientVerifiedSession = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 HTTP verified session outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "TLS1.3 HTTP verified session outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractTls13HttpVerifiedSessionRequest {
    public let session: ContractTls13HttpClientVerifiedSession

    public init(session: ContractTls13HttpClientVerifiedSession) {
        this.session = session
    }
}

public class ContractTls13HttpVerifiedSessionExportRequest {
    public let session: ContractTls13HttpClientVerifiedSession
    public let exporterLabel: String
    public let context: Array<Byte>
    public let outputLen: Int64

    public init(
        session: ContractTls13HttpClientVerifiedSession,
        exporterLabel: String,
        context!: Array<Byte> = [],
        outputLen!: Int64 = 32
    ) {
        if (exporterLabel.trimAscii().size == 0 || outputLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 verified session export request fields are invalid"
            )
        }
        this.session = session
        this.exporterLabel = exporterLabel.trimAscii()
        this.context = context.clone()
        this.outputLen = outputLen
    }
}

public class ContractTls13HttpVerifiedSessionKeyUpdateRequest {
    public let session: ContractTls13HttpClientVerifiedSession
    public let requestPeerUpdate: Bool

    public init(
        session: ContractTls13HttpClientVerifiedSession,
        requestPeerUpdate!: Bool = false
    ) {
        this.session = session
        this.requestPeerUpdate = requestPeerUpdate
    }
}

public class ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest {
    public let session: ContractTls13HttpClientVerifiedSession
    public let encodedKeyUpdate: Array<Byte>

    public init(
        session: ContractTls13HttpClientVerifiedSession,
        encodedKeyUpdate: Array<Byte>
    ) {
        if (encodedKeyUpdate.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 verified session peer key update request must not be empty"
            )
        }
        this.session = session
        this.encodedKeyUpdate = encodedKeyUpdate.clone()
    }
}

public class ContractTls13HttpVerifiedSessionChannelSet {
    public let session: ContractTls13HttpClientVerifiedSession
    public let clientChannel: ContractTlsRecordChannel
    public let serverChannel: ContractTlsRecordChannel

    public init(
        session: ContractTls13HttpClientVerifiedSession,
        clientChannel: ContractTlsRecordChannel,
        serverChannel: ContractTlsRecordChannel
    ) {
        let binding = contractTls13ResolveCipherBindingFromVerifiedSession(session)
        if (clientChannel.version != ContractTlsVersion.Tls13 || serverChannel.version != ContractTlsVersion.Tls13) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 verified session channel set requires TLS1.3 record channels"
            )
        }
        if (clientChannel.algorithm != binding.algorithm || serverChannel.algorithm != binding.algorithm) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 verified session channel algorithms must match cipher binding"
            )
        }
        this.session = session
        this.clientChannel = clientChannel
        this.serverChannel = serverChannel
    }
}

public class ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    public let encodedKeyUpdate: Array<Byte>
    public let requestPeerUpdate: Bool
    public let runtime: ContractTls13HttpVerifiedSessionChannelSet

    public init(
        encodedKeyUpdate: Array<Byte>,
        requestPeerUpdate: Bool,
        runtime: ContractTls13HttpVerifiedSessionChannelSet
    ) {
        if (encodedKeyUpdate.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 verified session traffic update handshake must not be empty"
            )
        }
        this.encodedKeyUpdate = encodedKeyUpdate.clone()
        this.requestPeerUpdate = requestPeerUpdate
        this.runtime = runtime
    }
}

public class ContractTls13PskClientHelloFromCacheResult {
    public let ticket: ContractTlsSessionTicket
    public let encodedClientHello: Array<Byte>

    public init(ticket: ContractTlsSessionTicket, encodedClientHello: Array<Byte>) {
        if (encodedClientHello.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK ClientHello from cache must not be empty"
            )
        }
        this.ticket = ticket
        this.encodedClientHello = encodedClientHello.clone()
    }
}

public class ContractTls13PskClientHelloFromCacheOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractTls13PskClientHelloFromCacheResult
    public let lifecycle: ?ContractTls13SessionTicketLifecycleResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractTls13PskClientHelloFromCacheResult = None,
        lifecycle!: ?ContractTls13SessionTicketLifecycleResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 PSK cache outcome message must not be empty")
        }
        contractValidateOutcomeState(
            ok,
            code,
            igniteCode,
            result,
            "TLS1.3 PSK cache outcome result"
        )
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
        this.lifecycle = lifecycle
    }
}

public class ContractTls13PskEarlyDataPlan {
    public let selectedIdentityIndex: Int64
    public let ticket: ContractTlsSessionTicket
    public let encodedClientHello: Array<Byte>
    public let clientHelloHash: Array<Byte>
    public let clientEarlyTrafficSecret: Array<Byte>
    public let clientEarlyWriteKey: Array<Byte>
    public let clientEarlyWriteIv: Array<Byte>

    public init(
        selectedIdentityIndex: Int64,
        ticket: ContractTlsSessionTicket,
        encodedClientHello: Array<Byte>,
        clientHelloHash: Array<Byte>,
        clientEarlyTrafficSecret: Array<Byte>,
        clientEarlyWriteKey: Array<Byte>,
        clientEarlyWriteIv: Array<Byte>
    ) {
        if (selectedIdentityIndex < 0 || selectedIdentityIndex > 65535) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 selected identity index must be uint16")
        }
        if (encodedClientHello.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 PSK early data ClientHello must not be empty")
        }
        if (clientHelloHash.size != 32) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK early data ClientHello hash must be SHA-256 sized"
            )
        }
        if (
            clientEarlyTrafficSecret.size == 0 ||
            clientEarlyWriteKey.size == 0 ||
            clientEarlyWriteIv.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK early data traffic secret and key material must not be empty"
            )
        }
        this.selectedIdentityIndex = selectedIdentityIndex
        this.ticket = ticket
        this.encodedClientHello = encodedClientHello.clone()
        this.clientHelloHash = clientHelloHash.clone()
        this.clientEarlyTrafficSecret = clientEarlyTrafficSecret.clone()
        this.clientEarlyWriteKey = clientEarlyWriteKey.clone()
        this.clientEarlyWriteIv = clientEarlyWriteIv.clone()
    }
}

public class ContractTls13PskEarlyDataFromSessionTicketRequest {
    public let ticket: ContractTlsSessionTicket
    public let sessionId: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        ticket: ContractTlsSessionTicket,
        sessionId!: Array<Byte> = [],
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK early data request key/iv lengths must be > 0"
            )
        }
        this.ticket = ticket
        this.sessionId = sessionId.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls13PskEarlyDataFromSessionCacheRequest {
    public let cache: ContractTlsSessionCache
    public let identity: ContractTlsSessionIdentity
    public let nowUnixSeconds: Int64
    public let sessionId: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        cache: ContractTlsSessionCache,
        identity: ContractTlsSessionIdentity,
        nowUnixSeconds!: Int64 = 0,
        sessionId!: Array<Byte> = [],
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK early data cache request key/iv lengths must be > 0"
            )
        }
        this.cache = cache
        this.identity = identity
        this.nowUnixSeconds = nowUnixSeconds
        this.sessionId = sessionId.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls13PskEarlyDataAcceptRequest {
    public let encodedClientHello: Array<Byte>
    public let nowUnixSeconds: Int64
    public let selectedIdentityIndex: Int64
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        encodedClientHello: Array<Byte>,
        nowUnixSeconds!: Int64 = 0,
        selectedIdentityIndex!: Int64 = -1,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (encodedClientHello.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK early data accept request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.nowUnixSeconds = nowUnixSeconds
        this.selectedIdentityIndex = selectedIdentityIndex
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls13PskEarlyDataAcceptWithReplayCacheRequest {
    public let encodedClientHello: Array<Byte>
    public let replayCache: ContractTls13EarlyDataReplayCache
    public let nowUnixSeconds: Int64
    public let selectedIdentityIndex: Int64
    public let keyLen: Int64
    public let ivLen: Int64
    public let replayTtlSeconds: Int64

    public init(
        encodedClientHello: Array<Byte>,
        replayCache: ContractTls13EarlyDataReplayCache,
        nowUnixSeconds!: Int64 = 0,
        selectedIdentityIndex!: Int64 = -1,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12,
        replayTtlSeconds!: Int64 = 0
    ) {
        if (encodedClientHello.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 PSK early data replay-cache request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.replayCache = replayCache
        this.nowUnixSeconds = nowUnixSeconds
        this.selectedIdentityIndex = selectedIdentityIndex
        this.keyLen = keyLen
        this.ivLen = ivLen
        this.replayTtlSeconds = replayTtlSeconds
    }
}

public class ContractTls13PskEarlyDataHttpAcceptRequest {
    public let encodedClientHello: Array<Byte>
    public let expectedServerName: String
    public let expectedAlpnProtocol: String
    public let nowUnixSeconds: Int64
    public let selectedIdentityIndex: Int64
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        encodedClientHello: Array<Byte>,
        expectedServerName!: String = "",
        expectedAlpnProtocol!: String = "",
        nowUnixSeconds!: Int64 = 0,
        selectedIdentityIndex!: Int64 = -1,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (encodedClientHello.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 HTTP early data accept request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.expectedServerName = expectedServerName.trimAscii().toAsciiLower()
        this.expectedAlpnProtocol = expectedAlpnProtocol.trimAscii().toAsciiLower()
        this.nowUnixSeconds = nowUnixSeconds
        this.selectedIdentityIndex = selectedIdentityIndex
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class ContractTls13PskEarlyDataHttpAcceptWithReplayCacheRequest {
    public let encodedClientHello: Array<Byte>
    public let replayCache: ContractTls13EarlyDataReplayCache
    public let expectedServerName: String
    public let expectedAlpnProtocol: String
    public let nowUnixSeconds: Int64
    public let selectedIdentityIndex: Int64
    public let keyLen: Int64
    public let ivLen: Int64
    public let replayTtlSeconds: Int64

    public init(
        encodedClientHello: Array<Byte>,
        replayCache: ContractTls13EarlyDataReplayCache,
        expectedServerName!: String = "",
        expectedAlpnProtocol!: String = "",
        nowUnixSeconds!: Int64 = 0,
        selectedIdentityIndex!: Int64 = -1,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12,
        replayTtlSeconds!: Int64 = 0
    ) {
        if (encodedClientHello.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 HTTP early data replay-cache request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.replayCache = replayCache
        this.expectedServerName = expectedServerName.trimAscii().toAsciiLower()
        this.expectedAlpnProtocol = expectedAlpnProtocol.trimAscii().toAsciiLower()
        this.nowUnixSeconds = nowUnixSeconds
        this.selectedIdentityIndex = selectedIdentityIndex
        this.keyLen = keyLen
        this.ivLen = ivLen
        this.replayTtlSeconds = replayTtlSeconds
    }
}

public func contractMapCryptoErrorCode(code: CryptoErrorCode): ContractErrorCode {
    match (code) {
        case InvalidArgument => ContractErrorCode.BadInput
        case OutOfBounds => ContractErrorCode.BadInput
        case ParseError => ContractErrorCode.VerifyFailed
        case ComplianceRejected => ContractErrorCode.ComplianceRejected
        case Unsupported => ContractErrorCode.Unsupported
        case InternalError => ContractErrorCode.InternalError
        case _ => ContractErrorCode.InternalError
    }
}

public func contractMapToIgniteCryptoErrorCode(code: ContractErrorCode): ContractIgniteCryptoErrorCode {
    match (code) {
        case BadInput => ContractIgniteCryptoErrorCode.BadEnvelope
        case KeyNotFound => ContractIgniteCryptoErrorCode.KeyNotFound
        case VerifyFailed => ContractIgniteCryptoErrorCode.DecryptFailed
        case CryptoUnavailable => ContractIgniteCryptoErrorCode.CryptoUnavailable
        case ComplianceRejected => ContractIgniteCryptoErrorCode.CryptoUnavailable
        case Unsupported => ContractIgniteCryptoErrorCode.CryptoUnavailable
        case InternalError => ContractIgniteCryptoErrorCode.CryptoUnavailable
    }
}

public func contractMapExceptionToIgniteCryptoErrorCode(
    exception: ContractException
): ContractIgniteCryptoErrorCode {
    contractMapToIgniteCryptoErrorCode(exception.code)
}

public func contractMapCryptoExceptionToErrorCode(
    exception: CryptoException,
    operation!: String = ""
): ContractErrorCode {
    mapCryptoErrorForOperation(exception, operation)
}

public func contractMapCryptoExceptionToIgniteCryptoErrorCode(
    exception: CryptoException,
    operation!: String = ""
): ContractIgniteCryptoErrorCode {
    contractMapToIgniteCryptoErrorCode(contractMapCryptoExceptionToErrorCode(exception, operation: operation))
}

public func contractRandomAvailable(): Bool {
    csprngIsAvailable()
}

public func contractRandomBytes(size: Int64): Array<Byte> {
    if (size <= 0) {
        throw ContractException(ContractErrorCode.BadInput, "random byte size must be > 0")
    }
    if (!csprngIsAvailable()) {
        throw ContractException(ContractErrorCode.CryptoUnavailable, "system CSPRNG is unavailable")
    }
    try {
        csprngBytes(size)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "random"),
            "random generation failed: ${e.message}"
        )
    }
}

public func contractRandomUInt8Bytes(size: Int64): Array<UInt8> {
    toUInt8Array(contractRandomBytes(size))
}

public func contractHkdfExtract(
    hash: ContractKdfHash,
    salt: Array<Byte>,
    ikm: Array<Byte>
): Array<Byte> {
    try {
        hkdfExtract(contractToHashAlgorithm(hash), salt, ikm)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "kdf"),
            "HKDF extract failed: ${e.message}"
        )
    }
}

public func contractHkdfExpand(
    hash: ContractKdfHash,
    prk: Array<Byte>,
    info: Array<Byte>,
    outputLen: Int64
): Array<Byte> {
    try {
        hkdfExpand(contractToHashAlgorithm(hash), prk, info, outputLen)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "kdf"),
            "HKDF expand failed: ${e.message}"
        )
    }
}

public func contractHkdf(
    hash: ContractKdfHash,
    ikm: Array<Byte>,
    info: Array<Byte>,
    outputLen: Int64,
    salt!: Array<Byte> = []
): Array<Byte> {
    try {
        hkdf(contractToHashAlgorithm(hash), ikm, info, outputLen, salt: salt)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "kdf"),
            "HKDF derive failed: ${e.message}"
        )
    }
}

public class ContractHkdfHttpSshKeySet {
    public let httpRequestKey: Array<Byte>
    public let httpResponseKey: Array<Byte>
    public let sshClientToServerKey: Array<Byte>
    public let sshServerToClientKey: Array<Byte>

    public init(
        httpRequestKey: Array<Byte>,
        httpResponseKey: Array<Byte>,
        sshClientToServerKey: Array<Byte>,
        sshServerToClientKey: Array<Byte>
    ) {
        if (
            httpRequestKey.size == 0 ||
            httpResponseKey.size == 0 ||
            sshClientToServerKey.size == 0 ||
            sshServerToClientKey.size == 0
        ) {
            throw ContractException(ContractErrorCode.BadInput, "HKDF key set entries must not be empty")
        }
        this.httpRequestKey = httpRequestKey.clone()
        this.httpResponseKey = httpResponseKey.clone()
        this.sshClientToServerKey = sshClientToServerKey.clone()
        this.sshServerToClientKey = sshServerToClientKey.clone()
    }
}

public func contractHkdfDeriveHttpSshKeySet(
    ikm: Array<Byte>,
    contextId!: String = "",
    outputLen!: Int64 = 32,
    salt!: Array<Byte> = []
): ContractHkdfHttpSshKeySet {
    let normalizedContextId = contextId.trimAscii().toAsciiLower()
    let suffix = if (normalizedContextId.size > 0) {
        "|${normalizedContextId}"
    } else {
        ""
    }
    ContractHkdfHttpSshKeySet(
        contractHkdf(ContractKdfHash.Sha256, ikm, "jinkui/http/request${suffix}".toArray(), outputLen, salt: salt),
        contractHkdf(ContractKdfHash.Sha256, ikm, "jinkui/http/response${suffix}".toArray(), outputLen, salt: salt),
        contractHkdf(ContractKdfHash.Sha256, ikm, "jinkui/ssh/c2s${suffix}".toArray(), outputLen, salt: salt),
        contractHkdf(ContractKdfHash.Sha256, ikm, "jinkui/ssh/s2c${suffix}".toArray(), outputLen, salt: salt)
    )
}

public func contractEncryptEnvelopeV1(
    algorithm: ContractAeadAlgorithm,
    kid: String,
    key: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = []
): ContractAeadEnvelopeV1 {
    let normalizedKid = kid.trimAscii()
    requireTokenAscii(normalizedKid, "kid")
    if (plaintext.size == 0) {
        throw ContractException(ContractErrorCode.BadInput, "plaintext must not be empty")
    }

    let nonce = contractRandomBytes(12)
    let (ciphertext, tag) = contractEncryptAead(algorithm, key, nonce, plaintext, aad)
    ContractAeadEnvelopeV1(
        1,
        algorithm.toString(),
        normalizedKid,
        base64UrlEncode(nonce),
        base64UrlEncode(aad),
        base64UrlEncode(ciphertext),
        base64UrlEncode(tag)
    )
}

public func contractEncryptEnvelopeJsonV1(
    algorithm: ContractAeadAlgorithm,
    kid: String,
    key: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = []
): String {
    contractEncryptEnvelopeV1(algorithm, kid, key, plaintext, aad: aad).toJsonString()
}

public func contractEncryptEnvelopeJsonLegacyV1(
    algorithm: ContractAeadAlgorithm,
    kid: String,
    key: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = []
): String {
    let envelope = contractEncryptEnvelopeV1(algorithm, kid, key, plaintext, aad: aad)
    contractEnvelopeToLegacyJsonV1(envelope)
}

public func contractDecryptEnvelopeV1(
    envelope: ContractAeadEnvelopeV1,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): Array<Byte> {
    match (keyRing.get(envelope.kid)) {
        case Some(key) =>
            let nonce = decodeEnvelopeField(envelope.nonce, "nonce")
            let ciphertext = decodeEnvelopeField(envelope.ciphertext, "ciphertext")
            let tag = decodeEnvelopeField(envelope.tag, "tag")
            let aad = if (let Some(override) <- aadOverride) {
                override
            } else {
                decodeEnvelopeField(envelope.aad, "aad")
            }
            contractDecryptAead(envelope.algorithm(), key, nonce, ciphertext, tag, aad)
        case None =>
            throw ContractException(ContractErrorCode.KeyNotFound, "envelope key id is not found: ${envelope.kid}")
    }
}

public func contractDecryptEnvelopeJsonV1(
    envelopeJson: String,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): Array<Byte> {
    let envelope = ContractAeadEnvelopeV1.parseJson(envelopeJson)
    contractDecryptEnvelopeV1(envelope, keyRing, aadOverride: aadOverride)
}

public func contractDecryptEnvelopeJsonCompatV1(
    envelopeJson: String,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): Array<Byte> {
    let envelope = contractParseEnvelopeJsonCompatV1(envelopeJson)
    contractDecryptEnvelopeV1(envelope, keyRing, aadOverride: aadOverride)
}

public func contractTryDecryptEnvelopeV1(
    envelope: ContractAeadEnvelopeV1,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): ContractEnvelopeOpenOutcome {
    try {
        let plaintext = contractDecryptEnvelopeV1(envelope, keyRing, aadOverride: aadOverride)
        ContractEnvelopeOpenOutcome(true, "OK", plaintext: Some(plaintext))
    } catch (e: ContractException) {
        ContractEnvelopeOpenOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryDecryptEnvelopeJsonV1(
    envelopeJson: String,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): ContractEnvelopeOpenOutcome {
    try {
        let plaintext = contractDecryptEnvelopeJsonV1(envelopeJson, keyRing, aadOverride: aadOverride)
        ContractEnvelopeOpenOutcome(true, "OK", plaintext: Some(plaintext))
    } catch (e: ContractException) {
        ContractEnvelopeOpenOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryDecryptEnvelopeJsonCompatV1(
    envelopeJson: String,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): ContractEnvelopeOpenOutcome {
    try {
        let plaintext = contractDecryptEnvelopeJsonCompatV1(envelopeJson, keyRing, aadOverride: aadOverride)
        ContractEnvelopeOpenOutcome(true, "OK", plaintext: Some(plaintext))
    } catch (e: ContractException) {
        ContractEnvelopeOpenOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractEncryptEnvelopeJsonV1UInt8(
    algorithm: ContractAeadAlgorithm,
    kid: String,
    key: Array<UInt8>,
    plaintext: Array<UInt8>,
    aad!: Array<UInt8> = []
): String {
    contractEncryptEnvelopeJsonV1(
        algorithm,
        kid,
        toByteArray(key),
        toByteArray(plaintext),
        aad: toByteArray(aad)
    )
}

public func contractDecryptEnvelopeJsonV1UInt8(
    envelopeJson: String,
    keyRing: HashMap<String, Array<UInt8>>,
    aadOverride!: ?Array<UInt8> = None
): Array<UInt8> {
    let byteKeyRing = HashMap<String, Array<Byte>>()
    for ((kid, key) in keyRing) {
        byteKeyRing.add(kid, toByteArray(key))
    }

    let byteAadOverride: ?Array<Byte> = if (let Some(value) <- aadOverride) {
        Some(toByteArray(value))
    } else {
        None
    }
    toUInt8Array(contractDecryptEnvelopeJsonV1(envelopeJson, byteKeyRing, aadOverride: byteAadOverride))
}

public func contractDecryptEnvelopeJsonCompatV1UInt8(
    envelopeJson: String,
    keyRing: HashMap<String, Array<UInt8>>,
    aadOverride!: ?Array<UInt8> = None
): Array<UInt8> {
    let byteKeyRing = HashMap<String, Array<Byte>>()
    for ((kid, key) in keyRing) {
        byteKeyRing.add(kid, toByteArray(key))
    }

    let byteAadOverride: ?Array<Byte> = if (let Some(value) <- aadOverride) {
        Some(toByteArray(value))
    } else {
        None
    }
    toUInt8Array(contractDecryptEnvelopeJsonCompatV1(envelopeJson, byteKeyRing, aadOverride: byteAadOverride))
}

public func contractComputeLeafPinsFromPem(leafPem: String): (Array<Byte>, Array<Byte>) {
    try {
        let leaf = x509ParsePem(leafPem)
        (sha256(leaf.der), sha256(leaf.subjectPublicKeyInfoDer))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "x509"),
            "failed to compute certificate pins: ${e.message}"
        )
    }
}

public func contractVerifyServerCertificatePem(
    leafPem: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy()
): ContractX509VerifyResult {
    try {
        let leaf = x509ParsePem(leafPem)
        let intermediates: Array<X509Certificate> = if (intermediatesPemBundle.trimAscii().size == 0) {
            []
        } else {
            x509ParsePemChain(intermediatesPemBundle)
        }
        contractVerifyServerCertificateParsed(
            leaf,
            trustAnchorsPemBundle,
            intermediates,
            hostname,
            validationTime,
            pinPolicy
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "x509"),
            "certificate verification failed: ${e.message}"
        )
    }
}

public func contractTryVerifyServerCertificatePem(
    leafPem: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy()
): ContractX509VerifyOutcome {
    try {
        let result = contractVerifyServerCertificatePem(
            leafPem,
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy
        )
        ContractX509VerifyOutcome(
            true,
            ContractErrorCode.VerifyFailed,
            "OK",
            result: Some(result)
        )
    } catch (e: ContractException) {
        ContractX509VerifyOutcome(
            false,
            e.code,
            e.message,
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code)),
            result: None
        )
    }
}

public func contractVerifyServerCertificateChainPem(
    certificateChainPemBundle: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy()
): ContractX509VerifyResult {
    try {
        let chain = x509ParsePemChain(certificateChainPemBundle)
        if (chain.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "certificate chain PEM bundle must not be empty")
        }

        let leaf = chain[0]
        let mergedIntermediates = ArrayList<X509Certificate>()
        var index = 1
        while (index < chain.size) {
            mergedIntermediates.add(chain[index])
            index += 1
        }
        if (intermediatesPemBundle.trimAscii().size > 0) {
            let extraIntermediates = x509ParsePemChain(intermediatesPemBundle)
            for (certificate in extraIntermediates) {
                mergedIntermediates.add(certificate)
            }
        }

        contractVerifyServerCertificateParsed(
            leaf,
            trustAnchorsPemBundle,
            mergedIntermediates.toArray(),
            hostname,
            validationTime,
            pinPolicy
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "x509"),
            "certificate chain verification failed: ${e.message}"
        )
    }
}

public func contractTryVerifyServerCertificateChainPem(
    certificateChainPemBundle: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy()
): ContractX509VerifyOutcome {
    try {
        let result = contractVerifyServerCertificateChainPem(
            certificateChainPemBundle,
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy
        )
        ContractX509VerifyOutcome(
            true,
            ContractErrorCode.VerifyFailed,
            "OK",
            result: Some(result)
        )
    } catch (e: ContractException) {
        ContractX509VerifyOutcome(
            false,
            e.code,
            e.message,
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code)),
            result: None
        )
    }
}

public func contractValidateHttpServerTlsConfigInput(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true
): ContractHttpServerTlsConfigValidationResult {
    try {
        let certChain = x509ParsePemChain(certificateChainPem)
        if (certChain.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS certificate chain PEM must not be empty")
        }
        let normalizedAlpn = contractNormalizeAlpnProtocols(alpnProtocols)
        if (requireHttp2Alpn && !contractContainsString(normalizedAlpn, "h2")) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS ALPN protocols must include h2 when requireHttp2Alpn is true"
            )
        }
        let keyAlgorithm = contractValidateLeafCertificateAndPrivateKeyMatch(certChain[0], privateKeyPem)
        ContractHttpServerTlsConfigValidationResult(
            certChain.size,
            certChain[0].subject.commonName(),
            certChain[0].issuer.commonName(),
            keyAlgorithm,
            normalizedAlpn
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "x509"),
            "TLS server config input validation failed: ${e.message}"
        )
    }
}

public func contractValidateHttpServerTlsConfigRequest(
    request: ContractHttpServerTlsConfigRequest
): ContractHttpServerTlsConfigValidationResult {
    contractValidateHttpServerTlsConfigInput(
        request.certificateChainPem,
        request.privateKeyPem,
        alpnProtocols: request.alpnProtocols,
        requireHttp2Alpn: request.requireHttp2Alpn
    )
}

public func contractTryValidateHttpServerTlsConfigInput(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true
): ContractHttpServerTlsConfigValidationOutcome {
    try {
        let result = contractValidateHttpServerTlsConfigInput(
            certificateChainPem,
            privateKeyPem,
            alpnProtocols: alpnProtocols,
            requireHttp2Alpn: requireHttp2Alpn
        )
        ContractHttpServerTlsConfigValidationOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractHttpServerTlsConfigValidationOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryValidateHttpServerTlsConfigRequest(
    request: ContractHttpServerTlsConfigRequest
): ContractHttpServerTlsConfigValidationOutcome {
    try {
        let result = contractValidateHttpServerTlsConfigRequest(request)
        ContractHttpServerTlsConfigValidationOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractHttpServerTlsConfigValidationOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractPrepareHttpServerTlsMaterial(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true
): ContractHttpServerTlsMaterial {
    try {
        let validation = contractValidateHttpServerTlsConfigInput(
            certificateChainPem,
            privateKeyPem,
            alpnProtocols: alpnProtocols,
            requireHttp2Alpn: requireHttp2Alpn
        )
        let certChain = x509ParsePemChain(certificateChainPem)
        ContractHttpServerTlsMaterial(
            validation,
            contractCertificatesToPemBlocks(certChain),
            privateKeyPem
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "x509"),
            "TLS server material preparation failed: ${e.message}"
        )
    }
}

public func contractPrepareHttpServerTlsMaterialRequest(
    request: ContractHttpServerTlsConfigRequest
): ContractHttpServerTlsMaterial {
    contractPrepareHttpServerTlsMaterial(
        request.certificateChainPem,
        request.privateKeyPem,
        alpnProtocols: request.alpnProtocols,
        requireHttp2Alpn: request.requireHttp2Alpn
    )
}

public func contractTryPrepareHttpServerTlsMaterial(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true
): ContractHttpServerTlsMaterialOutcome {
    try {
        let result = contractPrepareHttpServerTlsMaterial(
            certificateChainPem,
            privateKeyPem,
            alpnProtocols: alpnProtocols,
            requireHttp2Alpn: requireHttp2Alpn
        )
        ContractHttpServerTlsMaterialOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractHttpServerTlsMaterialOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryPrepareHttpServerTlsMaterialRequest(
    request: ContractHttpServerTlsConfigRequest
): ContractHttpServerTlsMaterialOutcome {
    try {
        let result = contractPrepareHttpServerTlsMaterialRequest(request)
        ContractHttpServerTlsMaterialOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractHttpServerTlsMaterialOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractValidateHttpClientTlsConfigInput(
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractHttpClientTlsConfigValidationResult {
    try {
        let anchors = x509ParsePemChain(trustAnchorsPemBundle)
        if (anchors.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS client trust anchors PEM bundle must not be empty")
        }
        let intermediates: Array<X509Certificate> = if (intermediatesPemBundle.trimAscii().size == 0) {
            []
        } else {
            x509ParsePemChain(intermediatesPemBundle)
        }
        let x509Policy = X509VerificationPolicy(
            anchors,
            intermediates: intermediates,
            requiredLeafDnsName: hostname,
            validationTime: validationTime
        )
        let validatedPolicy = contractValidateTlsHttpNegotiationPolicy(policy: policy)
        if (
            x509Policy.requiredLeafDnsName.size > 0 &&
            validatedPolicy.normalizedAllowedServerNames.size > 0 &&
            !contractContainsString(
                validatedPolicy.normalizedAllowedServerNames,
                x509Policy.requiredLeafDnsName
            )
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS client hostname must be included in allowed server names when both are configured"
            )
        }
        ContractHttpClientTlsConfigValidationResult(
            anchors.size,
            intermediates.size,
            x509Policy.requiredLeafDnsName,
            x509Policy.validationTime.size > 0,
            pinPolicy.allowedLeafDerSha256.size,
            pinPolicy.allowedLeafSpkiSha256.size,
            validatedPolicy
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS client config validation failed: ${e.message}"
        )
    }
}

public func contractValidateHttpClientTlsTrustRequest(
    request: ContractHttpClientTlsTrustRequest
): ContractHttpClientTlsConfigValidationResult {
    contractValidateHttpClientTlsConfigInput(
        request.trustAnchorsPemBundle,
        intermediatesPemBundle: request.intermediatesPemBundle,
        hostname: request.hostname,
        validationTime: request.validationTime,
        pinPolicy: request.pinPolicy,
        policy: request.policy
    )
}

public func contractPrepareHttpClientTlsTrustMaterial(
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractHttpClientTlsTrustMaterial {
    try {
        let validation = contractValidateHttpClientTlsConfigInput(
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy,
            policy: policy
        )
        let anchors = x509ParsePemChain(trustAnchorsPemBundle)
        let intermediates: Array<X509Certificate> = if (intermediatesPemBundle.trimAscii().size == 0) {
            []
        } else {
            x509ParsePemChain(intermediatesPemBundle)
        }
        ContractHttpClientTlsTrustMaterial(
            validation,
            contractCertificatesToPemBlocks(anchors),
            intermediatePemBlocks: contractCertificatesToPemBlocks(intermediates),
            validationTime: validationTime,
            pinPolicy: pinPolicy
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "x509"),
            "TLS client trust material preparation failed: ${e.message}"
        )
    }
}

public func contractPrepareHttpClientTlsTrustMaterialRequest(
    request: ContractHttpClientTlsTrustRequest
): ContractHttpClientTlsTrustMaterial {
    contractPrepareHttpClientTlsTrustMaterial(
        request.trustAnchorsPemBundle,
        intermediatesPemBundle: request.intermediatesPemBundle,
        hostname: request.hostname,
        validationTime: request.validationTime,
        pinPolicy: request.pinPolicy,
        policy: request.policy
    )
}

public func contractTryPrepareHttpClientTlsTrustMaterial(
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractHttpClientTlsTrustMaterialOutcome {
    try {
        let result = contractPrepareHttpClientTlsTrustMaterial(
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy,
            policy: policy
        )
        ContractHttpClientTlsTrustMaterialOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractHttpClientTlsTrustMaterialOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryPrepareHttpClientTlsTrustMaterialRequest(
    request: ContractHttpClientTlsTrustRequest
): ContractHttpClientTlsTrustMaterialOutcome {
    try {
        let result = contractPrepareHttpClientTlsTrustMaterialRequest(request)
        ContractHttpClientTlsTrustMaterialOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractHttpClientTlsTrustMaterialOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryValidateHttpClientTlsConfigInput(
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractHttpClientTlsConfigValidationOutcome {
    try {
        let result = contractValidateHttpClientTlsConfigInput(
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy,
            policy: policy
        )
        ContractHttpClientTlsConfigValidationOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractHttpClientTlsConfigValidationOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryValidateHttpClientTlsTrustRequest(
    request: ContractHttpClientTlsTrustRequest
): ContractHttpClientTlsConfigValidationOutcome {
    try {
        let result = contractValidateHttpClientTlsTrustRequest(request)
        ContractHttpClientTlsConfigValidationOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractHttpClientTlsConfigValidationOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractVerifyHttpClientPeerCertificatePem(
    leafPem: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractX509VerifyResult {
    let validated = contractValidateHttpClientTlsConfigInput(
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
    contractVerifyServerCertificatePem(
        leafPem,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: validated.normalizedHostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy
    )
}

public func contractVerifyHttpClientPeerCertificatePemRequest(
    request: ContractHttpClientTlsPeerPemRequest
): ContractX509VerifyResult {
    contractVerifyHttpClientPeerCertificatePem(
        request.leafPem,
        request.trust.trustAnchorsPemBundle,
        intermediatesPemBundle: request.trust.intermediatesPemBundle,
        hostname: request.trust.hostname,
        validationTime: request.trust.validationTime,
        pinPolicy: request.trust.pinPolicy,
        policy: request.trust.policy
    )
}

public func contractTryVerifyHttpClientPeerCertificatePem(
    leafPem: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractX509VerifyOutcome {
    try {
        let result = contractVerifyHttpClientPeerCertificatePem(
            leafPem,
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy,
            policy: policy
        )
        ContractX509VerifyOutcome(
            true,
            ContractErrorCode.VerifyFailed,
            "OK",
            result: Some(result)
        )
    } catch (e: ContractException) {
        ContractX509VerifyOutcome(
            false,
            e.code,
            e.message,
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code)),
            result: None
        )
    }
}

public func contractTryVerifyHttpClientPeerCertificatePemRequest(
    request: ContractHttpClientTlsPeerPemRequest
): ContractX509VerifyOutcome {
    try {
        let result = contractVerifyHttpClientPeerCertificatePemRequest(request)
        ContractX509VerifyOutcome(
            true,
            ContractErrorCode.VerifyFailed,
            "OK",
            result: Some(result)
        )
    } catch (e: ContractException) {
        ContractX509VerifyOutcome(
            false,
            e.code,
            e.message,
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code)),
            result: None
        )
    }
}

public func contractVerifyHttpClientPeerCertificateChainPem(
    certificateChainPemBundle: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractX509VerifyResult {
    let validated = contractValidateHttpClientTlsConfigInput(
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
    contractVerifyServerCertificateChainPem(
        certificateChainPemBundle,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: validated.normalizedHostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy
    )
}

public func contractVerifyHttpClientPeerCertificateChainPemRequest(
    request: ContractHttpClientTlsPeerChainRequest
): ContractX509VerifyResult {
    contractVerifyHttpClientPeerCertificateChainPem(
        request.certificateChainPemBundle,
        request.trust.trustAnchorsPemBundle,
        intermediatesPemBundle: request.trust.intermediatesPemBundle,
        hostname: request.trust.hostname,
        validationTime: request.trust.validationTime,
        pinPolicy: request.trust.pinPolicy,
        policy: request.trust.policy
    )
}

public func contractTryVerifyHttpClientPeerCertificateChainPem(
    certificateChainPemBundle: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractX509VerifyOutcome {
    try {
        let result = contractVerifyHttpClientPeerCertificateChainPem(
            certificateChainPemBundle,
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy,
            policy: policy
        )
        ContractX509VerifyOutcome(
            true,
            ContractErrorCode.VerifyFailed,
            "OK",
            result: Some(result)
        )
    } catch (e: ContractException) {
        ContractX509VerifyOutcome(
            false,
            e.code,
            e.message,
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code)),
            result: None
        )
    }
}

public func contractTryVerifyHttpClientPeerCertificateChainPemRequest(
    request: ContractHttpClientTlsPeerChainRequest
): ContractX509VerifyOutcome {
    try {
        let result = contractVerifyHttpClientPeerCertificateChainPemRequest(request)
        ContractX509VerifyOutcome(
            true,
            ContractErrorCode.VerifyFailed,
            "OK",
            result: Some(result)
        )
    } catch (e: ContractException) {
        ContractX509VerifyOutcome(
            false,
            e.code,
            e.message,
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code)),
            result: None
        )
    }
}

public func contractTls12BuildHttpClientHello(
    keyExchange: ContractTls12KeyExchange,
    sessionId!: Array<Byte> = [],
    serverName!: String = "",
    alpnProtocols!: Array<String> = [],
    requestOcspStapling!: Bool = false
): ContractTls12ClientHello {
    try {
        let encoded = tls12BuildClientHello(
            contractToTls12KeyExchange(keyExchange),
            sessionId: sessionId,
            serverName: serverName,
            alpnProtocols: alpnProtocols,
            requestOcspStapling: requestOcspStapling
        )
        let clientRandom = tls12ExtractClientRandom(encoded)
        ContractTls12ClientHello(encoded, clientRandom)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 HTTP ClientHello build failed: ${e.message}"
        )
    }
}

public func contractTls12BuildHttpClientHelloRequest(
    request: ContractTls12HttpClientHelloRequest
): ContractTls12ClientHello {
    contractTls12BuildHttpClientHello(
        request.keyExchange,
        sessionId: request.sessionId,
        serverName: request.serverName,
        alpnProtocols: request.alpnProtocols,
        requestOcspStapling: request.requestOcspStapling
    )
}

public func contractTls12BuildHttpServerHello(
    encodedClientHello: Array<Byte>,
    keyExchange: ContractTls12KeyExchange
): ContractTls12ServerHello {
    try {
        let encoded = tls12BuildServerHello(
            encodedClientHello,
            contractToTls12KeyExchange(keyExchange)
        )
        let serverRandom = tls12ExtractServerRandom(encoded)
        ContractTls12ServerHello(encoded, serverRandom)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 HTTP ServerHello build failed: ${e.message}"
        )
    }
}

public func contractTls12BuildHttpServerHelloRequest(
    request: ContractTls12HttpServerHelloRequest
): ContractTls12ServerHello {
    contractTls12BuildHttpServerHello(
        request.encodedClientHello,
        request.keyExchange
    )
}

public func contractTls12BuildCertificateHandshakeFromPemChain(
    certChainPemBundle: String
): Array<Byte> {
    try {
        let certChain = x509ParsePemChain(certChainPemBundle)
        if (certChain.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 certificate chain PEM bundle must not be empty")
        }
        let certChainDer = contractDerChainFromCertificates(certChain)
        tls12BuildCertificateHandshakeFromDerChain(certChainDer)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 certificate handshake build failed: ${e.message}"
        )
    }
}

public func contractTls12BuildCertificateHandshakeFromPemChainRequest(
    request: ContractTls12CertificateHandshakeFromPemChainRequest
): Array<Byte> {
    contractTls12BuildCertificateHandshakeFromPemChain(request.certChainPemBundle)
}

public func contractTls12VerifyCertificateHandshakeForHttp(
    encodedCertificateHandshake: Array<Byte>,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy()
): ContractX509VerifyResult {
    try {
        let anchors = x509ParsePemChain(trustAnchorsPemBundle)
        let intermediates: Array<X509Certificate> = if (intermediatesPemBundle.trimAscii().size == 0) {
            []
        } else {
            x509ParsePemChain(intermediatesPemBundle)
        }
        let policy = X509VerificationPolicy(
            anchors,
            intermediates: intermediates,
            requiredLeafDnsName: hostname,
            validationTime: validationTime
        )
        let verified = tls12VerifyCertificateChainFromHandshake(encodedCertificateHandshake, policy)
        let leaf = verified.chain[0]
        let leafDerSha = sha256(leaf.der)
        let leafSpkiSha = sha256(leaf.subjectPublicKeyInfoDer)
        contractRequirePinPolicy(pinPolicy, leafDerSha, leafSpkiSha)

        ContractX509VerifyResult(
            verified.chain.size,
            leaf.subject.commonName(),
            leaf.issuer.commonName(),
            verified.trustAnchor.subject.commonName(),
            leafDerSha,
            leafSpkiSha
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 certificate handshake verification failed: ${e.message}"
        )
    }
}

public func contractTls12VerifyCertificateHandshakeForHttpRequest(
    request: ContractTls12VerifyCertificateHandshakeForHttpRequest
): ContractX509VerifyResult {
    contractTls12VerifyCertificateHandshakeForHttp(
        request.encodedCertificateHandshake,
        request.trust.trustAnchorsPemBundle,
        intermediatesPemBundle: request.trust.intermediatesPemBundle,
        hostname: request.trust.hostname,
        validationTime: request.trust.validationTime,
        pinPolicy: request.trust.pinPolicy
    )
}

public func contractTls12BuildRsaClientKeyExchangeFromLeafPem(
    serverLeafPem: String
): ContractTls12RsaClientKeyExchange {
    try {
        let leaf = x509ParsePem(serverLeafPem)
        let rsaPublicKey = x509ExtractRsaPublicKey(leaf)
        let (encodedClientKeyExchange, preMasterSecret) = tls12BuildRsaClientKeyExchange(rsaPublicKey)
        ContractTls12RsaClientKeyExchange(encodedClientKeyExchange, preMasterSecret)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 RSA ClientKeyExchange build failed: ${e.message}"
        )
    }
}

public func contractTls12BuildRsaClientKeyExchangeFromLeafPemRequest(
    request: ContractTls12RsaClientKeyExchangeFromLeafPemRequest
): ContractTls12RsaClientKeyExchange {
    contractTls12BuildRsaClientKeyExchangeFromLeafPem(request.serverLeafPem)
}

public func contractTls12ProcessRsaClientKeyExchange(
    serverPrivateKeyPkcs8Pem: String,
    encodedClientKeyExchange: Array<Byte>
): Array<Byte> {
    try {
        let privateKey = x509ParseRsaPrivateKeyPkcs8Pem(serverPrivateKeyPkcs8Pem)
        tls12ProcessRsaClientKeyExchange(privateKey, encodedClientKeyExchange)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 RSA ClientKeyExchange process failed: ${e.message}"
        )
    }
}

public func contractTls12ProcessRsaClientKeyExchangeRequest(
    request: ContractTls12ProcessRsaClientKeyExchangeRequest
): Array<Byte> {
    contractTls12ProcessRsaClientKeyExchange(
        request.serverPrivateKeyPkcs8Pem,
        request.encodedClientKeyExchange
    )
}

public func contractTls12DeriveSecretsFromPreMaster(
    preMasterSecret: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls12HandshakeSecrets {
    try {
        let secrets = tls12DeriveSecretsFromPreMaster(
            preMasterSecret,
            clientRandom,
            serverRandom,
            keyLen: keyLen,
            ivLen: ivLen
        )
        contractFromTls12HandshakeSecrets(secrets)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 handshake secret derivation failed: ${e.message}"
        )
    }
}

public func contractTls12DeriveSecretsFromPreMasterRequest(
    request: ContractTls12DeriveSecretsFromPreMasterRequest
): ContractTls12HandshakeSecrets {
    contractTls12DeriveSecretsFromPreMaster(
        request.preMasterSecret,
        request.clientRandom,
        request.serverRandom,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls12BuildEcdheServerKeyExchange(
    keyExchange: ContractTls12KeyExchange,
    serverPrivateScalar!: ?Array<Byte> = None
): ContractTls12EcdheServerKeyExchange {
    let (curve, fieldBytes) = contractTls12ResolveEcdheCurveSpec(keyExchange)
    try {
        let scalar = if (let Some(value) <- serverPrivateScalar) {
            value.clone()
        } else {
            contractRandomBytes(fieldBytes)
        }
        let privateKey = contractTls12EcPrivateKeyFromScalar(curve, scalar, fieldBytes, "server")
        let publicKey = ecPublicFromPrivateKey(privateKey)
        let encodedServerKeyExchange = tls12BuildEcdheServerKeyExchange(publicKey)
        ContractTls12EcdheServerKeyExchange(encodedServerKeyExchange, scalar)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 ECDHE ServerKeyExchange build failed: ${e.message}"
        )
    }
}

public func contractTls12BuildEcdheServerKeyExchangeRequest(
    request: ContractTls12EcdheServerKeyExchangeRequest
): ContractTls12EcdheServerKeyExchange {
    contractTls12BuildEcdheServerKeyExchange(
        request.keyExchange,
        serverPrivateScalar: request.serverPrivateScalar
    )
}

public func contractTls12BuildEcdheClientKeyExchange(
    keyExchange: ContractTls12KeyExchange,
    clientPrivateScalar!: ?Array<Byte> = None
): ContractTls12EcdheClientKeyExchange {
    let (curve, fieldBytes) = contractTls12ResolveEcdheCurveSpec(keyExchange)
    try {
        let scalar = if (let Some(value) <- clientPrivateScalar) {
            value.clone()
        } else {
            contractRandomBytes(fieldBytes)
        }
        let privateKey = contractTls12EcPrivateKeyFromScalar(curve, scalar, fieldBytes, "client")
        let publicKey = ecPublicFromPrivateKey(privateKey)
        let encodedClientKeyExchange = tls12BuildEcdheClientKeyExchange(publicKey)
        ContractTls12EcdheClientKeyExchange(encodedClientKeyExchange, scalar)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 ECDHE ClientKeyExchange build failed: ${e.message}"
        )
    }
}

public func contractTls12BuildEcdheClientKeyExchangeRequest(
    request: ContractTls12EcdheClientKeyExchangeRequest
): ContractTls12EcdheClientKeyExchange {
    contractTls12BuildEcdheClientKeyExchange(
        request.keyExchange,
        clientPrivateScalar: request.clientPrivateScalar
    )
}

public func contractTls12DeriveClientSecretsFromEcdhe(
    keyExchange: ContractTls12KeyExchange,
    clientPrivateScalar: Array<Byte>,
    encodedServerKeyExchange: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls12HandshakeSecrets {
    let (curve, fieldBytes) = contractTls12ResolveEcdheCurveSpec(keyExchange)
    try {
        let privateKey = contractTls12EcPrivateKeyFromScalar(curve, clientPrivateScalar, fieldBytes, "client")
        let serverPublicKey = tls12ParseEcdheServerKeyExchange(encodedServerKeyExchange)
        if (serverPublicKey.curve != curve) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 ECDHE server key exchange curve mismatch")
        }
        let secrets = tls12DeriveSecretsFromEcdhe(
            privateKey,
            serverPublicKey,
            clientRandom,
            serverRandom,
            keyLen: keyLen,
            ivLen: ivLen
        )
        contractFromTls12HandshakeSecrets(secrets)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 ECDHE client secret derivation failed: ${e.message}"
        )
    }
}

public func contractTls12DeriveClientSecretsFromEcdheRequest(
    request: ContractTls12DeriveClientSecretsFromEcdheRequest
): ContractTls12HandshakeSecrets {
    contractTls12DeriveClientSecretsFromEcdhe(
        request.keyExchange,
        request.clientPrivateScalar,
        request.encodedServerKeyExchange,
        request.clientRandom,
        request.serverRandom,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls12DeriveServerSecretsFromEcdhe(
    keyExchange: ContractTls12KeyExchange,
    serverPrivateScalar: Array<Byte>,
    encodedClientKeyExchange: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls12HandshakeSecrets {
    let (curve, fieldBytes) = contractTls12ResolveEcdheCurveSpec(keyExchange)
    try {
        let privateKey = contractTls12EcPrivateKeyFromScalar(curve, serverPrivateScalar, fieldBytes, "server")
        let clientPublicKey = tls12ParseEcdheClientKeyExchange(encodedClientKeyExchange)
        if (clientPublicKey.curve != curve) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.2 ECDHE client key exchange curve mismatch")
        }
        let secrets = tls12DeriveSecretsFromEcdhe(
            privateKey,
            clientPublicKey,
            clientRandom,
            serverRandom,
            keyLen: keyLen,
            ivLen: ivLen
        )
        contractFromTls12HandshakeSecrets(secrets)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 ECDHE server secret derivation failed: ${e.message}"
        )
    }
}

public func contractTls12DeriveServerSecretsFromEcdheRequest(
    request: ContractTls12DeriveServerSecretsFromEcdheRequest
): ContractTls12HandshakeSecrets {
    contractTls12DeriveServerSecretsFromEcdhe(
        request.keyExchange,
        request.serverPrivateScalar,
        request.encodedClientKeyExchange,
        request.clientRandom,
        request.serverRandom,
        keyLen: request.keyLen,
        ivLen: request.ivLen
    )
}

public func contractTls12CreateClientRecordChannel(
    secrets: ContractTls12HandshakeSecrets,
    algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
): ContractTlsRecordChannel {
    try {
        let tlsSecrets = contractToTls12HandshakeSecrets(secrets)
        match (algorithm) {
            case ContractAeadAlgorithm.Aes256Gcm =>
                let layer = tls12CreateClientRecordLayer(tlsSecrets)
                return ContractTlsRecordChannel(
                    ContractTlsVersion.Tls12,
                    ContractAeadAlgorithm.Aes256Gcm,
                    aesLayer: Some(layer)
                )
            case ContractAeadAlgorithm.Chacha20Poly1305 =>
                let layer = tls12CreateClientRecordLayerChacha20Poly1305(tlsSecrets)
                return ContractTlsRecordChannel(
                    ContractTlsVersion.Tls12,
                    ContractAeadAlgorithm.Chacha20Poly1305,
                    chachaLayer: Some(layer)
                )
        }
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 client record channel creation failed: ${e.message}"
        )
    }
}

public func contractTls12CreateClientRecordChannelRequest(
    request: ContractTls12RecordChannelRequest
): ContractTlsRecordChannel {
    contractTls12CreateClientRecordChannel(
        request.secrets,
        algorithm: request.algorithm
    )
}

public func contractTls12CreateServerRecordChannel(
    secrets: ContractTls12HandshakeSecrets,
    algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
): ContractTlsRecordChannel {
    try {
        let tlsSecrets = contractToTls12HandshakeSecrets(secrets)
        match (algorithm) {
            case ContractAeadAlgorithm.Aes256Gcm =>
                let layer = tls12CreateServerRecordLayer(tlsSecrets)
                return ContractTlsRecordChannel(
                    ContractTlsVersion.Tls12,
                    ContractAeadAlgorithm.Aes256Gcm,
                    aesLayer: Some(layer)
                )
            case ContractAeadAlgorithm.Chacha20Poly1305 =>
                let layer = tls12CreateServerRecordLayerChacha20Poly1305(tlsSecrets)
                return ContractTlsRecordChannel(
                    ContractTlsVersion.Tls12,
                    ContractAeadAlgorithm.Chacha20Poly1305,
                    chachaLayer: Some(layer)
                )
        }
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.2 server record channel creation failed: ${e.message}"
        )
    }
}

public func contractTls12CreateServerRecordChannelRequest(
    request: ContractTls12RecordChannelRequest
): ContractTlsRecordChannel {
    contractTls12CreateServerRecordChannel(
        request.secrets,
        algorithm: request.algorithm
    )
}

public func contractTls13CreateClientRecordChannel(
    keyMaterial: ContractTls13ApplicationKeyMaterial,
    algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
): ContractTlsRecordChannel {
    try {
        match (algorithm) {
            case ContractAeadAlgorithm.Aes256Gcm =>
                let layer = TlsAeadRecordLayer(
                    keyMaterial.clientWriteKey,
                    keyMaterial.clientWriteIv,
                    readKey: keyMaterial.serverWriteKey,
                    readIv: keyMaterial.serverWriteIv,
                    version: TLS_VERSION_1_3
                )
                return ContractTlsRecordChannel(
                    ContractTlsVersion.Tls13,
                    ContractAeadAlgorithm.Aes256Gcm,
                    aesLayer: Some(layer)
                )
            case ContractAeadAlgorithm.Chacha20Poly1305 =>
                let layer = TlsChacha20Poly1305RecordLayer(
                    keyMaterial.clientWriteKey,
                    keyMaterial.clientWriteIv,
                    readKey: keyMaterial.serverWriteKey,
                    readIv: keyMaterial.serverWriteIv,
                    version: TLS_VERSION_1_3
                )
                return ContractTlsRecordChannel(
                    ContractTlsVersion.Tls13,
                    ContractAeadAlgorithm.Chacha20Poly1305,
                    chachaLayer: Some(layer)
                )
        }
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 client record channel creation failed: ${e.message}"
        )
    }
}

public func contractTls13CreateClientRecordChannelRequest(
    request: ContractTls13RecordChannelRequest
): ContractTlsRecordChannel {
    contractTls13CreateClientRecordChannel(
        request.keyMaterial,
        algorithm: request.algorithm
    )
}

public func contractTls13CreateServerRecordChannel(
    keyMaterial: ContractTls13ApplicationKeyMaterial,
    algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
): ContractTlsRecordChannel {
    try {
        match (algorithm) {
            case ContractAeadAlgorithm.Aes256Gcm =>
                let layer = TlsAeadRecordLayer(
                    keyMaterial.serverWriteKey,
                    keyMaterial.serverWriteIv,
                    readKey: keyMaterial.clientWriteKey,
                    readIv: keyMaterial.clientWriteIv,
                    version: TLS_VERSION_1_3
                )
                return ContractTlsRecordChannel(
                    ContractTlsVersion.Tls13,
                    ContractAeadAlgorithm.Aes256Gcm,
                    aesLayer: Some(layer)
                )
            case ContractAeadAlgorithm.Chacha20Poly1305 =>
                let layer = TlsChacha20Poly1305RecordLayer(
                    keyMaterial.serverWriteKey,
                    keyMaterial.serverWriteIv,
                    readKey: keyMaterial.clientWriteKey,
                    readIv: keyMaterial.clientWriteIv,
                    version: TLS_VERSION_1_3
                )
                return ContractTlsRecordChannel(
                    ContractTlsVersion.Tls13,
                    ContractAeadAlgorithm.Chacha20Poly1305,
                    chachaLayer: Some(layer)
                )
        }
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 server record channel creation failed: ${e.message}"
        )
    }
}

public func contractTls13CreateServerRecordChannelRequest(
    request: ContractTls13RecordChannelRequest
): ContractTlsRecordChannel {
    contractTls13CreateServerRecordChannel(
        request.keyMaterial,
        algorithm: request.algorithm
    )
}

public func contractTls13BuildHttpClientHelloX25519(
    serverName: String,
    alpnProtocols!: Array<String> = [],
    clientPrivateKey!: ?Array<Byte> = None
): ContractTls13HttpClientHelloX25519 {
    try {
        let privateKey = if (let Some(value) <- clientPrivateKey) {
            value.clone()
        } else {
            x25519GeneratePrivateKey()
        }
        let publicKey = x25519PublicFromPrivate(privateKey)
        let encodedClientHello = tls13BuildHttpClientHelloX25519(
            publicKey,
            serverName,
            alpnProtocols: alpnProtocols
        )
        ContractTls13HttpClientHelloX25519(encodedClientHello, privateKey, publicKey)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 HTTP ClientHello build failed: ${e.message}"
        )
    }
}

public func contractTls13BuildHttpClientHelloX25519Request(
    request: ContractTls13HttpClientHelloX25519Request
): ContractTls13HttpClientHelloX25519 {
    contractTls13BuildHttpClientHelloX25519(
        request.serverName,
        alpnProtocols: request.alpnProtocols,
        clientPrivateKey: request.clientPrivateKey
    )
}

public func contractTls13BuildHttpServerFlightX25519(
    encodedClientHello: Array<Byte>,
    serverKeyExchangePrivate: Array<Byte>,
    certChainPemBundle: String,
    certificatePrivateKeyPkcs8Pem: String,
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpServerFlight {
    try {
        let certChain = x509ParsePemChain(certChainPemBundle)
        if (certChain.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "TLS1.3 certificate chain PEM bundle must not be empty")
        }
        let certChainDer = contractDerChainFromCertificates(certChain)
        let certificatePrivateKeyRsa: ?RsaPrivateKey = contractTryParseRsaPrivateKeyPkcs8Pem(certificatePrivateKeyPkcs8Pem)
        let certificatePrivateKeyEcdsa: ?EcPrivateKey = if (let Some(_value) <- certificatePrivateKeyRsa) {
            None
        } else {
            contractTryParseEcPrivateKeyPkcs8Pem(certificatePrivateKeyPkcs8Pem)
        }
        if (
            !contractIsSomeRsaPrivateKey(certificatePrivateKeyRsa) &&
            !contractIsSomeEcPrivateKey(certificatePrivateKeyEcdsa)
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.3 certificate private key must be PKCS8 RSA or EC"
            )
        }
        let serverKeyShare = x25519PublicFromPrivate(serverKeyExchangePrivate)
        let context = tls13BuildHttpServerHandshakeContextX25519(
            encodedClientHello,
            serverKeyExchangePrivate,
            serverKeyShare,
            certChainDer,
            certificatePrivateKeyEcdsa: certificatePrivateKeyEcdsa,
            certificatePrivateKeyRsa: certificatePrivateKeyRsa,
            policy: contractToTlsHttpNegotiationPolicy(policy)
        )
        contractFromTls13ServerHandshakeFlight(context.flight)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 HTTP server flight build failed: ${e.message}"
        )
    }
}

public func contractTls13BuildHttpServerFlightX25519Request(
    request: ContractTls13HttpServerFlightX25519Request
): ContractTls13HttpServerFlight {
    contractTls13BuildHttpServerFlightX25519(
        request.encodedClientHello,
        request.serverKeyExchangePrivate,
        request.certChainPemBundle,
        request.certificatePrivateKeyPkcs8Pem,
        policy: request.policy
    )
}

public func contractTls13BuildHttpServerFlightX25519Rsa(
    encodedClientHello: Array<Byte>,
    serverKeyExchangePrivate: Array<Byte>,
    certChainPemBundle: String,
    certificatePrivateKeyPkcs8Pem: String,
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpServerFlight {
    contractTls13BuildHttpServerFlightX25519(
        encodedClientHello,
        serverKeyExchangePrivate,
        certChainPemBundle,
        certificatePrivateKeyPkcs8Pem,
        policy: policy
    )
}

public func contractTls13VerifyHttpServerFlightX25519(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverFlight: ContractTls13HttpServerFlight,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpClientResult {
    contractTls13VerifyHttpServerFlightX25519WithSession(
        clientHello,
        serverFlight,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    ).result
}

public func contractTls13VerifyHttpServerFlightX25519Request(
    request: ContractTls13HttpVerifyServerFlightX25519Request
): ContractTls13HttpClientResult {
    contractTls13VerifyHttpServerFlightX25519(
        request.clientHello,
        request.serverFlight,
        request.trust.trustAnchorsPemBundle,
        intermediatesPemBundle: request.trust.intermediatesPemBundle,
        hostname: request.trust.hostname,
        validationTime: request.trust.validationTime,
        pinPolicy: request.trust.pinPolicy,
        policy: request.trust.policy
    )
}

public func contractTls13VerifyHttpServerFlightX25519WithSession(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverFlight: ContractTls13HttpServerFlight,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpClientVerifiedSession {
    try {
        let anchors = x509ParsePemChain(trustAnchorsPemBundle)
        let intermediates: Array<X509Certificate> = if (intermediatesPemBundle.trimAscii().size == 0) {
            []
        } else {
            x509ParsePemChain(intermediatesPemBundle)
        }
        let x509Policy = X509VerificationPolicy(
            anchors,
            intermediates: intermediates,
            requiredLeafDnsName: hostname,
            validationTime: validationTime
        )
        let flight = contractToTls13ServerHandshakeFlight(serverFlight)
        let result = tls13ProcessServerHandshakeFlightX25519(
            clientHello.encodedClientHello,
            clientHello.clientPrivateKey,
            flight,
            x509Policy
        )
        tls13ValidateHttpClientResult(result, policy: contractToTlsHttpNegotiationPolicy(policy))

        let leaf = result.verification.chain[0]
        let leafDerSha = sha256(leaf.der)
        let leafSpkiSha = sha256(leaf.subjectPublicKeyInfoDer)
        contractRequirePinPolicy(pinPolicy, leafDerSha, leafSpkiSha)
        let binding = contractTls13ResolveCipherBindingFromServerFlight(serverFlight)
        let clientResult = ContractTls13HttpClientResult(
            result.selectedAlpn,
            result.requestedServerName,
            result.acknowledgedServerName,
            result.verification.chain.size,
            leaf.subject.commonName(),
            result.verification.trustAnchor.subject.commonName(),
            leafDerSha,
            leafSpkiSha,
            ContractTls13ApplicationKeyMaterial(
                result.secrets.clientWriteKey,
                result.secrets.clientWriteIv,
                result.secrets.serverWriteKey,
                result.secrets.serverWriteIv
            ),
            cipherBinding: Some(binding)
        )
        ContractTls13HttpClientVerifiedSession(
            clientResult,
            result.secrets.clientAppTrafficSecret,
            result.secrets.serverAppTrafficSecret,
            result.secrets.masterSecret,
            serverFlight.transcriptHash
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 HTTP server flight verification with session failed: ${e.message}"
        )
    }
}

public func contractTls13VerifyHttpServerFlightX25519WithSessionRequest(
    request: ContractTls13HttpVerifyServerFlightX25519Request
): ContractTls13HttpClientVerifiedSession {
    contractTls13VerifyHttpServerFlightX25519WithSession(
        request.clientHello,
        request.serverFlight,
        request.trust.trustAnchorsPemBundle,
        intermediatesPemBundle: request.trust.intermediatesPemBundle,
        hostname: request.trust.hostname,
        validationTime: request.trust.validationTime,
        pinPolicy: request.trust.pinPolicy,
        policy: request.trust.policy
    )
}

public func contractTryTls13VerifyHttpServerFlightX25519(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverFlight: ContractTls13HttpServerFlight,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpClientVerifyOutcome {
    try {
        let result = contractTls13VerifyHttpServerFlightX25519(
            clientHello,
            serverFlight,
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy,
            policy: policy
        )
        ContractTls13HttpClientVerifyOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractTls13HttpClientVerifyOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryTls13VerifyHttpServerFlightX25519Request(
    request: ContractTls13HttpVerifyServerFlightX25519Request
): ContractTls13HttpClientVerifyOutcome {
    try {
        let result = contractTls13VerifyHttpServerFlightX25519Request(request)
        ContractTls13HttpClientVerifyOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractTls13HttpClientVerifyOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryTls13VerifyHttpServerFlightX25519WithSession(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverFlight: ContractTls13HttpServerFlight,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpClientVerifiedSessionOutcome {
    try {
        let result = contractTls13VerifyHttpServerFlightX25519WithSession(
            clientHello,
            serverFlight,
            trustAnchorsPemBundle,
            intermediatesPemBundle: intermediatesPemBundle,
            hostname: hostname,
            validationTime: validationTime,
            pinPolicy: pinPolicy,
            policy: policy
        )
        ContractTls13HttpClientVerifiedSessionOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractTls13HttpClientVerifiedSessionOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTryTls13VerifyHttpServerFlightX25519WithSessionRequest(
    request: ContractTls13HttpVerifyServerFlightX25519Request
): ContractTls13HttpClientVerifiedSessionOutcome {
    try {
        let result = contractTls13VerifyHttpServerFlightX25519WithSessionRequest(request)
        ContractTls13HttpClientVerifiedSessionOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractTls13HttpClientVerifiedSessionOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractSshComputeHostKeySha256(serverHostKey: Array<Byte>): Array<Byte> {
    try {
        sshComputeHostKeySha256(serverHostKey)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH host key fingerprint computation failed: ${e.message}"
        )
    }
}

public func contractSshEncodeRsaHostPublicKey(publicKey: RsaPublicKey): Array<Byte> {
    try {
        sshEncodeRsaHostPublicKey(publicKey)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH RSA host key encoding failed: ${e.message}"
        )
    }
}

public func contractSshSignExchangeHashRsa(
    privateKey: RsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): Array<Byte> {
    try {
        sshSignExchangeHashRsa(privateKey, exchangeHash, signatureAlgorithm: signatureAlgorithm)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH RSA exchange-hash signing failed: ${e.message}"
        )
    }
}

public func contractSshEncodeEcdsaHostPublicKey(publicKey: EcPublicKey): Array<Byte> {
    try {
        sshEncodeEcdsaHostPublicKey(publicKey)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH ECDSA host key encoding failed: ${e.message}"
        )
    }
}

public func contractSshSignExchangeHashEcdsa(privateKey: EcPrivateKey, exchangeHash: Array<Byte>): Array<Byte> {
    try {
        sshSignExchangeHashEcdsa(privateKey, exchangeHash)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH ECDSA exchange-hash signing failed: ${e.message}"
        )
    }
}

public func contractSshBuildEd25519HostKeyBlobFromSeed(privateKeySeed: Array<Byte>): Array<Byte> {
    try {
        sshBuildEd25519HostKeyBlobFromSeed(privateKeySeed)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH Ed25519 host key encoding failed: ${e.message}"
        )
    }
}

public func contractPrepareSshHostSigningRsa(
    privateKey: RsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): ContractSshHostSigningResult {
    let serverHostKey = contractSshEncodeRsaHostPublicKey(privateKey.publicKey)
    let hostSignature = contractSshSignExchangeHashRsa(
        privateKey,
        exchangeHash,
        signatureAlgorithm: signatureAlgorithm
    )
    contractBuildSshHostSigningResult(serverHostKey, hostSignature)
}

public func contractTryPrepareSshHostSigningRsa(
    privateKey: RsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): ContractSshHostSigningOutcome {
    try {
        let result = contractPrepareSshHostSigningRsa(
            privateKey,
            exchangeHash,
            signatureAlgorithm: signatureAlgorithm
        )
        ContractSshHostSigningOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshHostSigningOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractPrepareSshHostSigningRsaPkcs8Request(
    request: ContractSshHostSigningRsaPkcs8Request
): ContractSshHostSigningResult {
    let privateKey = contractParseRsaPrivateKeyPkcs8PemForSshHostSigning(request.hostPrivateKeyPkcs8Pem)
    contractPrepareSshHostSigningRsa(
        privateKey,
        request.exchangeHash,
        signatureAlgorithm: request.signatureAlgorithm
    )
}

public func contractTryPrepareSshHostSigningRsaPkcs8Request(
    request: ContractSshHostSigningRsaPkcs8Request
): ContractSshHostSigningOutcome {
    try {
        let result = contractPrepareSshHostSigningRsaPkcs8Request(request)
        ContractSshHostSigningOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshHostSigningOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractPrepareSshHostSigningEcdsa(
    privateKey: EcPrivateKey,
    exchangeHash: Array<Byte>
): ContractSshHostSigningResult {
    let serverHostKey = contractSshEncodeEcdsaHostPublicKey(ecPublicFromPrivateKey(privateKey))
    let hostSignature = contractSshSignExchangeHashEcdsa(privateKey, exchangeHash)
    contractBuildSshHostSigningResult(serverHostKey, hostSignature)
}

public func contractTryPrepareSshHostSigningEcdsa(
    privateKey: EcPrivateKey,
    exchangeHash: Array<Byte>
): ContractSshHostSigningOutcome {
    try {
        let result = contractPrepareSshHostSigningEcdsa(privateKey, exchangeHash)
        ContractSshHostSigningOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshHostSigningOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractPrepareSshHostSigningEcdsaPkcs8Request(
    request: ContractSshHostSigningEcdsaPkcs8Request
): ContractSshHostSigningResult {
    let privateKey = contractParseEcPrivateKeyPkcs8PemForSshHostSigning(request.hostPrivateKeyPkcs8Pem)
    contractPrepareSshHostSigningEcdsa(privateKey, request.exchangeHash)
}

public func contractTryPrepareSshHostSigningEcdsaPkcs8Request(
    request: ContractSshHostSigningEcdsaPkcs8Request
): ContractSshHostSigningOutcome {
    try {
        let result = contractPrepareSshHostSigningEcdsaPkcs8Request(request)
        ContractSshHostSigningOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshHostSigningOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractPrepareSshHostSigningEd25519(
    privateKeySeed: Array<Byte>,
    exchangeHash: Array<Byte>
): ContractSshHostSigningResult {
    let serverHostKey = contractSshBuildEd25519HostKeyBlobFromSeed(privateKeySeed)
    let hostSignature = contractSshSignExchangeHashEd25519(privateKeySeed, exchangeHash)
    contractBuildSshHostSigningResult(serverHostKey, hostSignature)
}

public func contractTryPrepareSshHostSigningEd25519(
    privateKeySeed: Array<Byte>,
    exchangeHash: Array<Byte>
): ContractSshHostSigningOutcome {
    try {
        let result = contractPrepareSshHostSigningEd25519(privateKeySeed, exchangeHash)
        ContractSshHostSigningOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshHostSigningOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractPrepareSshHostSigningEd25519SeedRequest(
    request: ContractSshHostSigningEd25519SeedRequest
): ContractSshHostSigningResult {
    contractPrepareSshHostSigningEd25519(request.hostPrivateKeySeed, request.exchangeHash)
}

public func contractTryPrepareSshHostSigningEd25519SeedRequest(
    request: ContractSshHostSigningEd25519SeedRequest
): ContractSshHostSigningOutcome {
    try {
        let result = contractPrepareSshHostSigningEd25519SeedRequest(request)
        ContractSshHostSigningOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshHostSigningOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractSshSignExchangeHashEd25519(privateKeySeed: Array<Byte>, exchangeHash: Array<Byte>): Array<Byte> {
    try {
        sshSignExchangeHashEd25519(privateKeySeed, exchangeHash)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH Ed25519 exchange-hash signing failed: ${e.message}"
        )
    }
}

public func contractSshBuildDefaultKexInit(
    cookie!: Array<Byte> = []
): ContractSshKexInitMessage {
    try {
        contractFromSshKexInitMessage(sshBuildDefaultKexInit(cookie: cookie))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH default KEXINIT build failed: ${e.message}"
        )
    }
}

public func contractSshBuildDefaultKexInitRequest(
    request: ContractSshBuildDefaultKexInitRequest
): ContractSshKexInitMessage {
    contractSshBuildDefaultKexInit(cookie: request.cookie)
}

public func contractSshEncodeKexInit(
    message: ContractSshKexInitMessage
): Array<Byte> {
    try {
        sshEncodeKexInit(contractToSshKexInitMessage(message))
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH KEXINIT encode failed: ${e.message}"
        )
    }
}

public func contractSshEncodeKexInitRequest(
    request: ContractSshEncodeKexInitRequest
): Array<Byte> {
    contractSshEncodeKexInit(request.message)
}

public func contractSshDecodeKexInit(
    encoded: Array<Byte>
): ContractSshKexInitMessage {
    try {
        contractFromSshKexInitMessage(sshDecodeKexInit(encoded))
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH KEXINIT decode failed: ${e.message}"
        )
    }
}

public func contractSshDecodeKexInitRequest(
    request: ContractSshDecodeKexInitRequest
): ContractSshKexInitMessage {
    contractSshDecodeKexInit(request.encoded)
}

public func contractSshNegotiateKexInit(
    client: ContractSshKexInitMessage,
    server: ContractSshKexInitMessage
): ContractSshNegotiatedAlgorithms {
    try {
        contractFromSshNegotiatedAlgorithms(
            sshNegotiateKexInit(
                contractToSshKexInitMessage(client),
                contractToSshKexInitMessage(server)
            )
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH KEXINIT negotiation failed: ${e.message}"
        )
    }
}

public func contractSshNegotiateKexInitRequest(
    request: ContractSshNegotiateKexInitRequest
): ContractSshNegotiatedAlgorithms {
    contractSshNegotiateKexInit(request.client, request.server)
}

public func contractSshBuildKexExchangeTranscript(
    clientBannerLine: Array<Byte>,
    serverBannerLine: Array<Byte>,
    clientKexInit: ContractSshKexInitMessage,
    serverKexInit: ContractSshKexInitMessage
): ContractSshKexExchangeTranscript {
    ContractSshKexExchangeTranscript(
        clientBannerLine,
        serverBannerLine,
        contractSshEncodeKexInit(clientKexInit),
        contractSshEncodeKexInit(serverKexInit)
    )
}

public func contractSshBuildKexExchangeTranscriptRequest(
    request: ContractSshBuildTranscriptFromKexInitRequest
): ContractSshKexExchangeTranscript {
    contractSshBuildKexExchangeTranscript(
        request.clientBannerLine,
        request.serverBannerLine,
        request.clientKexInit,
        request.serverKexInit
    )
}

public func contractSshBuildKexEcdhInitX25519(clientPrivateKey: Array<Byte>): ContractSshX25519InitResult {
    try {
        let (encodedInit, clientPublicKey) = sshBuildKexEcdhInitX25519(clientPrivateKey)
        ContractSshX25519InitResult(encodedInit, clientPublicKey)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH X25519 KEX init build failed: ${e.message}"
        )
    }
}

public func contractSshBuildKexEcdhInitX25519Request(
    request: ContractSshBuildKexEcdhInitX25519Request
): ContractSshX25519InitResult {
    contractSshBuildKexEcdhInitX25519(request.clientPrivateKey)
}

public func contractSshServerProcessKexEcdhInitX25519(
    transcript: ContractSshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostSigning: ContractSshHostSigningResult,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerProcessKexEcdhInitX25519Result {
    try {
        let (encodedReply, kexResult) = sshServerProcessKexEcdhInitX25519(
            contractToSshKexExchangeTranscript(transcript),
            serverPrivateKey,
            encodedClientInit,
            hostSigning.serverHostKey,
            hostSigning.hostSignature,
            serverPublicKey: serverPublicKey
        )
        ContractSshServerProcessKexEcdhInitX25519Result(
            encodedReply,
            contractBuildSshSessionStateFromKexResult(kexResult, kexResult.sessionId)
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH server KEX process failed: ${e.message}"
        )
    }
}

public func contractSshServerProcessKexEcdhInitX25519Request(
    request: ContractSshServerProcessKexEcdhInitX25519Request
): ContractSshServerProcessKexEcdhInitX25519Result {
    contractSshServerProcessKexEcdhInitX25519(
        request.transcript,
        request.serverPrivateKey,
        request.encodedClientInit,
        request.hostSigning,
        serverPublicKey: request.serverPublicKey
    )
}

public func contractSshClientProcessKexEcdhReplyX25519(
    transcript: ContractSshKexExchangeTranscript,
    clientPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    encodedServerReply: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshSessionState {
    try {
        let kexResult = sshClientProcessKexEcdhReplyX25519(
            contractToSshKexExchangeTranscript(transcript),
            clientPrivateKey,
            encodedClientInit,
            encodedServerReply
        )
        let verification = contractSshVerifyHostIdentity(
            kexResult.exchangeHash,
            kexResult.serverHostKey,
            kexResult.hostSignature,
            policy: policy
        )
        contractBuildSshSessionStateFromKexResult(
            kexResult,
            kexResult.sessionId,
            hostVerification: verification
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH client KEX process failed: ${e.message}"
        )
    }
}

public func contractSshClientProcessKexEcdhReplyX25519Request(
    request: ContractSshClientProcessKexEcdhReplyX25519Request
): ContractSshSessionState {
    contractSshClientProcessKexEcdhReplyX25519(
        request.transcript,
        request.clientPrivateKey,
        request.encodedClientInit,
        request.encodedServerReply,
        policy: request.policy
    )
}

public func contractSshCompleteServerInitialHandshakeX25519Rsa(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: RsaPrivateKey,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256",
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeResult {
    try {
        contractFromSshServerInitialHandshakeResult(
            sshCompleteServerInitialHandshakeX25519Rsa(
                transcript,
                serverPrivateKey,
                encodedClientInit,
                hostPrivateKey,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                signatureAlgorithm: signatureAlgorithm,
                serverPublicKey: serverPublicKey
            )
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH RSA server initial handshake failed: ${e.message}"
        )
    }
}

public func contractSshCompleteServerInitialHandshakeX25519RsaRequest(
    request: ContractSshServerInitialHandshakeX25519RsaRequest
): ContractSshServerInitialHandshakeResult {
    contractSshCompleteServerInitialHandshakeX25519Rsa(
        contractToSshKexExchangeTranscript(request.transcript),
        request.serverPrivateKey,
        request.encodedClientInit,
        request.hostPrivateKey,
        contractToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        signatureAlgorithm: request.signatureAlgorithm,
        serverPublicKey: request.serverPublicKey
    )
}

public func contractTrySshCompleteServerInitialHandshakeX25519Rsa(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: RsaPrivateKey,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256",
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeOutcome {
    try {
        let result = contractSshCompleteServerInitialHandshakeX25519Rsa(
            transcript,
            serverPrivateKey,
            encodedClientInit,
            hostPrivateKey,
            negotiated,
            encodedClientNewKeys,
            encodedServerNewKeys,
            signatureAlgorithm: signatureAlgorithm,
            serverPublicKey: serverPublicKey
        )
        ContractSshServerInitialHandshakeOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshServerInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTrySshCompleteServerInitialHandshakeX25519RsaRequest(
    request: ContractSshServerInitialHandshakeX25519RsaRequest
): ContractSshServerInitialHandshakeOutcome {
    try {
        let result = contractSshCompleteServerInitialHandshakeX25519RsaRequest(request)
        ContractSshServerInitialHandshakeOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshServerInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractSshCompleteServerInitialHandshakeX25519Ecdsa(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: EcPrivateKey,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeResult {
    try {
        contractFromSshServerInitialHandshakeResult(
            sshCompleteServerInitialHandshakeX25519Ecdsa(
                transcript,
                serverPrivateKey,
                encodedClientInit,
                hostPrivateKey,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                serverPublicKey: serverPublicKey
            )
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH ECDSA server initial handshake failed: ${e.message}"
        )
    }
}

public func contractSshCompleteServerInitialHandshakeX25519EcdsaRequest(
    request: ContractSshServerInitialHandshakeX25519EcdsaRequest
): ContractSshServerInitialHandshakeResult {
    contractSshCompleteServerInitialHandshakeX25519Ecdsa(
        contractToSshKexExchangeTranscript(request.transcript),
        request.serverPrivateKey,
        request.encodedClientInit,
        request.hostPrivateKey,
        contractToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        serverPublicKey: request.serverPublicKey
    )
}

public func contractTrySshCompleteServerInitialHandshakeX25519Ecdsa(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: EcPrivateKey,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeOutcome {
    try {
        let result = contractSshCompleteServerInitialHandshakeX25519Ecdsa(
            transcript,
            serverPrivateKey,
            encodedClientInit,
            hostPrivateKey,
            negotiated,
            encodedClientNewKeys,
            encodedServerNewKeys,
            serverPublicKey: serverPublicKey
        )
        ContractSshServerInitialHandshakeOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshServerInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTrySshCompleteServerInitialHandshakeX25519EcdsaRequest(
    request: ContractSshServerInitialHandshakeX25519EcdsaRequest
): ContractSshServerInitialHandshakeOutcome {
    try {
        let result = contractSshCompleteServerInitialHandshakeX25519EcdsaRequest(request)
        ContractSshServerInitialHandshakeOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshServerInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractSshCompleteServerInitialHandshakeX25519Ed25519(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKeySeed: Array<Byte>,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeResult {
    try {
        contractFromSshServerInitialHandshakeResult(
            sshCompleteServerInitialHandshakeX25519Ed25519(
                transcript,
                serverPrivateKey,
                encodedClientInit,
                hostPrivateKeySeed,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                serverPublicKey: serverPublicKey
            )
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH Ed25519 server initial handshake failed: ${e.message}"
        )
    }
}

public func contractSshCompleteServerInitialHandshakeX25519Ed25519Request(
    request: ContractSshServerInitialHandshakeX25519Ed25519Request
): ContractSshServerInitialHandshakeResult {
    contractSshCompleteServerInitialHandshakeX25519Ed25519(
        contractToSshKexExchangeTranscript(request.transcript),
        request.serverPrivateKey,
        request.encodedClientInit,
        request.hostPrivateKeySeed,
        contractToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        serverPublicKey: request.serverPublicKey
    )
}

public func contractTrySshCompleteServerInitialHandshakeX25519Ed25519(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKeySeed: Array<Byte>,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeOutcome {
    try {
        let result = contractSshCompleteServerInitialHandshakeX25519Ed25519(
            transcript,
            serverPrivateKey,
            encodedClientInit,
            hostPrivateKeySeed,
            negotiated,
            encodedClientNewKeys,
            encodedServerNewKeys,
            serverPublicKey: serverPublicKey
        )
        ContractSshServerInitialHandshakeOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshServerInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTrySshCompleteServerInitialHandshakeX25519Ed25519Request(
    request: ContractSshServerInitialHandshakeX25519Ed25519Request
): ContractSshServerInitialHandshakeOutcome {
    try {
        let result = contractSshCompleteServerInitialHandshakeX25519Ed25519Request(request)
        ContractSshServerInitialHandshakeOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshServerInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractSshCompleteClientInitialHandshakeX25519(
    transcript: SshKexExchangeTranscript,
    clientPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    encodedServerReply: Array<Byte>,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshClientInitialHandshakeResult {
    try {
        contractFromSshClientInitialHandshakeResult(
            sshCompleteClientInitialHandshakeX25519WithHostVerificationRequirement(
                transcript,
                clientPrivateKey,
                encodedClientInit,
                encodedServerReply,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                policy: contractToSshHostVerificationPolicy(policy),
                requireVerifiedHost: policy.requireVerifiedHost
            )
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH client initial handshake failed: ${e.message}"
        )
    }
}

public func contractSshCompleteClientInitialHandshakeX25519Request(
    request: ContractSshClientInitialHandshakeX25519Request
): ContractSshClientInitialHandshakeResult {
    contractSshCompleteClientInitialHandshakeX25519(
        contractToSshKexExchangeTranscript(request.transcript),
        request.clientPrivateKey,
        request.encodedClientInit,
        request.encodedServerReply,
        contractToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        policy: request.policy
    )
}

public func contractTrySshCompleteClientInitialHandshakeX25519(
    transcript: SshKexExchangeTranscript,
    clientPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    encodedServerReply: Array<Byte>,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshClientInitialHandshakeOutcome {
    try {
        let result = contractSshCompleteClientInitialHandshakeX25519(
            transcript,
            clientPrivateKey,
            encodedClientInit,
            encodedServerReply,
            negotiated,
            encodedClientNewKeys,
            encodedServerNewKeys,
            policy: policy
        )
        ContractSshClientInitialHandshakeOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshClientInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractTrySshCompleteClientInitialHandshakeX25519Request(
    request: ContractSshClientInitialHandshakeX25519Request
): ContractSshClientInitialHandshakeOutcome {
    try {
        let result = contractSshCompleteClientInitialHandshakeX25519Request(request)
        ContractSshClientInitialHandshakeOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshClientInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func contractSshCreateServerRuntime(
    result: ContractSshServerInitialHandshakeResult
): ContractSshServerRuntime {
    ContractSshServerRuntime(result)
}

public func contractSshCreateServerRuntimeRequest(
    request: ContractSshServerRuntimeRequest
): ContractSshServerRuntime {
    contractSshCreateServerRuntime(request.result)
}

public func contractSshCreateClientRuntime(
    result: ContractSshClientInitialHandshakeResult
): ContractSshClientRuntime {
    ContractSshClientRuntime(result)
}

public func contractSshCreateClientRuntimeRequest(
    request: ContractSshClientRuntimeRequest
): ContractSshClientRuntime {
    contractSshCreateClientRuntime(request.result)
}

public func contractSshRekeyServerRuntimeX25519(
    runtime: ContractSshServerRuntime,
    kexResult: SshX25519KexResult,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>
): ContractSshServerRuntimeRekeyResult {
    try {
        _ = runtime.transport()._coordinator.rekeyWithX25519(
            kexResult,
            encodedClientNewKeys,
            encodedServerNewKeys
        )
        let session = contractBuildSshSessionStateFromKexResult(
            kexResult,
            runtime.transport().sessionId()
        )
        let updatedRuntime = ContractSshServerRuntime(
            runtime.initialHandshake,
            currentSession: Some(session)
        )
        ContractSshServerRuntimeRekeyResult(updatedRuntime, session)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH server runtime rekey failed: ${e.message}"
        )
    }
}

public func contractSshRekeyServerRuntimeX25519Request(
    request: ContractSshServerRuntimeRekeyRequest
): ContractSshServerRuntimeRekeyResult {
    contractSshRekeyServerRuntimeX25519(
        request.runtime,
        request.kexResult,
        request.encodedClientNewKeys,
        request.encodedServerNewKeys
    )
}

public func contractSshRekeyClientRuntimeX25519(
    runtime: ContractSshClientRuntime,
    kexResult: SshX25519KexResult,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshClientRuntimeRekeyResult {
    try {
        let verification = if (policy.requireVerifiedHost) {
            _ = runtime.transport()._coordinator.rekeyWithX25519Verified(
                kexResult,
                encodedClientNewKeys,
                encodedServerNewKeys,
                policy: contractToSshHostVerificationPolicy(policy)
            )
            Some(
                contractSshVerifyHostIdentityRequired(
                    kexResult.exchangeHash,
                    kexResult.serverHostKey,
                    kexResult.hostSignature,
                    policy: policy
                )
            )
        } else {
            _ = runtime.transport()._coordinator.rekeyWithX25519(
                kexResult,
                encodedClientNewKeys,
                encodedServerNewKeys
            )
            contractSshVerifyHostIdentity(
                kexResult.exchangeHash,
                kexResult.serverHostKey,
                kexResult.hostSignature,
                policy: policy
            )
        }
        let session = contractBuildSshSessionStateFromKexResult(
            kexResult,
            runtime.transport().sessionId(),
            hostVerification: verification
        )
        let updatedRuntime = ContractSshClientRuntime(
            runtime.initialHandshake,
            currentSession: Some(session)
        )
        ContractSshClientRuntimeRekeyResult(updatedRuntime, session)
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH client runtime rekey failed: ${e.message}"
        )
    }
}

public func contractSshRekeyClientRuntimeX25519Request(
    request: ContractSshClientRuntimeRekeyRequest
): ContractSshClientRuntimeRekeyResult {
    contractSshRekeyClientRuntimeX25519(
        request.runtime,
        request.kexResult,
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        policy: request.policy
    )
}

public func contractSshRekeyServerRuntimeFromSessionState(
    runtime: ContractSshServerRuntime,
    session: ContractSshSessionState,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>
): ContractSshServerRuntimeRekeyResult {
    contractSshRekeyServerRuntimeX25519(
        runtime,
        contractToSshX25519KexResult(session),
        encodedClientNewKeys,
        encodedServerNewKeys
    )
}

public func contractSshRekeyServerRuntimeFromSessionStateRequest(
    request: ContractSshServerRuntimeSessionRekeyRequest
): ContractSshServerRuntimeRekeyResult {
    contractSshRekeyServerRuntimeFromSessionState(
        request.runtime,
        request.session,
        request.encodedClientNewKeys,
        request.encodedServerNewKeys
    )
}

public func contractSshRekeyClientRuntimeFromSessionState(
    runtime: ContractSshClientRuntime,
    session: ContractSshSessionState,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshClientRuntimeRekeyResult {
    contractSshRekeyClientRuntimeX25519(
        runtime,
        contractToSshX25519KexResult(session),
        encodedClientNewKeys,
        encodedServerNewKeys,
        policy: policy
    )
}

public func contractSshRekeyClientRuntimeFromSessionStateRequest(
    request: ContractSshClientRuntimeSessionRekeyRequest
): ContractSshClientRuntimeRekeyResult {
    contractSshRekeyClientRuntimeFromSessionState(
        request.runtime,
        request.session,
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        policy: request.policy
    )
}

public func contractSshVerifyHostIdentity(
    exchangeHash: Array<Byte>,
    serverHostKey: Array<Byte>,
    hostSignature: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ?ContractSshHostVerificationResult {
    if (policy.requireVerifiedHost) {
        return Some(
            contractSshVerifyHostIdentityRequired(
                exchangeHash,
                serverHostKey,
                hostSignature,
                policy: policy
            )
        )
    }

    try {
        return Some(
            contractSshVerifyHostIdentityRequired(
                exchangeHash,
                serverHostKey,
                hostSignature,
                policy: policy
            )
        )
    } catch (e: ContractException) {
        if (e.code == ContractErrorCode.VerifyFailed || e.code == ContractErrorCode.Unsupported) {
            return None
        }
        throw e
    }
}

public func contractSshVerifyHostIdentityRequired(
    exchangeHash: Array<Byte>,
    serverHostKey: Array<Byte>,
    hostSignature: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshHostVerificationResult {
    try {
        let hostKeyAlgorithm = sshExtractHostKeyAlgorithm(serverHostKey)
        let hostSignatureAlgorithm = sshExtractHostSignatureAlgorithm(hostSignature)
        let hostKeySha256 = sshComputeHostKeySha256(serverHostKey)

        if (policy.expectedHostKeySha256.size != 0) {
            if (!constantTimeEquals(policy.expectedHostKeySha256, hostKeySha256)) {
                if (policy.requireKnownHost) {
                    throw ContractException(ContractErrorCode.VerifyFailed, "SSH known-host fingerprint verification failed")
                }
            }
        }

        var signatureVerified = false
        if (policy.requireHostSignature) {
            signatureVerified = sshVerifyServerHostSignature(
                exchangeHash,
                serverHostKey,
                hostSignature,
                negotiatedHostKeyAlgorithm: policy.negotiatedHostKeyAlgorithm,
                allowLegacyRsaSha1: policy.allowLegacyRsaSha1
            )
            if (!signatureVerified) {
                throw ContractException(ContractErrorCode.VerifyFailed, "SSH server host signature verification failed")
            }
        }

        ContractSshHostVerificationResult(
            hostKeyAlgorithm,
            hostSignatureAlgorithm,
            hostKeySha256,
            signatureVerified
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH host verification failed: ${e.message}"
        )
    }
}

public func contractTrySshVerifyHostIdentityRequired(
    exchangeHash: Array<Byte>,
    serverHostKey: Array<Byte>,
    hostSignature: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshHostVerificationOutcome {
    try {
        let result = contractSshVerifyHostIdentityRequired(
            exchangeHash,
            serverHostKey,
            hostSignature,
            policy: policy
        )
        ContractSshHostVerificationOutcome(true, "OK", result: Some(result))
    } catch (e: ContractException) {
        ContractSshHostVerificationOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

private func contractFromSshServerInitialHandshakeResult(
    result: SshServerInitialHandshakeResult
): ContractSshServerInitialHandshakeResult {
    let kex = result.kexResult
    let hostKeyAlgorithm = sshExtractHostKeyAlgorithm(kex.serverHostKey)
    let hostSignatureAlgorithm = sshExtractHostSignatureAlgorithm(kex.hostSignature)
    let hostKeySha256 = sshComputeHostKeySha256(kex.serverHostKey)
    ContractSshServerInitialHandshakeResult(
        result.encodedReply,
        kex.sharedSecret,
        kex.exchangeHash,
        kex.sessionId,
        kex.clientEphemeralPublicKey,
        kex.serverEphemeralPublicKey,
        kex.serverHostKey,
        kex.hostSignature,
        hostKeyAlgorithm,
        hostSignatureAlgorithm,
        hostKeySha256,
        ContractSshTransportChannel(result.coordinator)
    )
}

private func contractResolveSshServerRuntimeSessionState(
    initialHandshake: ContractSshServerInitialHandshakeResult,
    currentSession: ?ContractSshSessionState
): ContractSshSessionState {
    match (currentSession) {
        case Some(value) => value
        case None => contractBuildSshSessionStateFromServerInitialHandshake(initialHandshake)
    }
}

private func contractResolveSshClientRuntimeSessionState(
    initialHandshake: ContractSshClientInitialHandshakeResult,
    currentSession: ?ContractSshSessionState
): ContractSshSessionState {
    match (currentSession) {
        case Some(value) => value
        case None => contractBuildSshSessionStateFromClientInitialHandshake(initialHandshake)
    }
}

private func contractBuildSshSessionStateFromServerInitialHandshake(
    result: ContractSshServerInitialHandshakeResult
): ContractSshSessionState {
    ContractSshSessionState(
        result.sharedSecret,
        result.exchangeHash,
        result.sessionId,
        result.clientEphemeralPublicKey,
        result.serverEphemeralPublicKey,
        result.serverHostKey,
        result.hostSignature,
        result.hostKeyAlgorithm,
        result.hostSignatureAlgorithm,
        result.hostKeySha256
    )
}

private func contractBuildSshSessionStateFromClientInitialHandshake(
    result: ContractSshClientInitialHandshakeResult
): ContractSshSessionState {
    ContractSshSessionState(
        result.sharedSecret,
        result.exchangeHash,
        result.sessionId,
        result.clientEphemeralPublicKey,
        result.serverEphemeralPublicKey,
        result.serverHostKey,
        result.hostSignature,
        result.hostKeyAlgorithm,
        result.hostSignatureAlgorithm,
        result.hostKeySha256,
        hostVerification: result.hostVerification
    )
}

private func contractBuildSshSessionStateFromKexResult(
    kexResult: SshX25519KexResult,
    sessionId: Array<Byte>,
    hostVerification!: ?ContractSshHostVerificationResult = None
): ContractSshSessionState {
    let hostKeyAlgorithm = sshExtractHostKeyAlgorithm(kexResult.serverHostKey)
    let hostSignatureAlgorithm = sshExtractHostSignatureAlgorithm(kexResult.hostSignature)
    let hostKeySha256 = sshComputeHostKeySha256(kexResult.serverHostKey)
    ContractSshSessionState(
        kexResult.sharedSecret,
        kexResult.exchangeHash,
        sessionId,
        kexResult.clientEphemeralPublicKey,
        kexResult.serverEphemeralPublicKey,
        kexResult.serverHostKey,
        kexResult.hostSignature,
        hostKeyAlgorithm,
        hostSignatureAlgorithm,
        hostKeySha256,
        hostVerification: hostVerification
    )
}

private func contractFromSshClientInitialHandshakeResult(
    result: SshClientInitialHandshakeResult
): ContractSshClientInitialHandshakeResult {
    let kex = result.kexResult
    let hostKeyAlgorithm = sshExtractHostKeyAlgorithm(kex.serverHostKey)
    let hostSignatureAlgorithm = sshExtractHostSignatureAlgorithm(kex.hostSignature)
    let hostKeySha256 = sshComputeHostKeySha256(kex.serverHostKey)
    ContractSshClientInitialHandshakeResult(
        kex.sharedSecret,
        kex.exchangeHash,
        kex.sessionId,
        kex.clientEphemeralPublicKey,
        kex.serverEphemeralPublicKey,
        kex.serverHostKey,
        kex.hostSignature,
        hostKeyAlgorithm,
        hostSignatureAlgorithm,
        hostKeySha256,
        ContractSshTransportChannel(result.coordinator),
        hostVerification: contractTryFromSshHostVerificationResult(result.hostVerification)
    )
}

private func contractFromSshTransportPacket(packet: SshTransportPacket): ContractSshTransportPacket {
    ContractSshTransportPacket(packet.packetLength, packet.payload, packet.padding)
}

private func contractTryFromSshHostVerificationResult(
    result: ?SshHostVerificationResult
): ?ContractSshHostVerificationResult {
    match (result) {
        case Some(value) => Some(contractFromSshHostVerificationResult(value))
        case None => None
    }
}

private func contractFromSshHostVerificationResult(
    result: SshHostVerificationResult
): ContractSshHostVerificationResult {
    ContractSshHostVerificationResult(
        result.hostKeyAlgorithm,
        result.hostSignatureAlgorithm,
        result.hostKeySha256,
        result.hostSignatureVerified
    )
}

private func contractFromSshKexInitMessage(
    message: SshKexInitMessage
): ContractSshKexInitMessage {
    ContractSshKexInitMessage(
        message.cookie,
        message.kexAlgorithms,
        message.serverHostKeyAlgorithms,
        message.encryptionAlgorithmsClientToServer,
        message.encryptionAlgorithmsServerToClient,
        message.macAlgorithmsClientToServer,
        message.macAlgorithmsServerToClient,
        message.compressionAlgorithmsClientToServer,
        message.compressionAlgorithmsServerToClient,
        languagesClientToServer: message.languagesClientToServer,
        languagesServerToClient: message.languagesServerToClient,
        firstKexPacketFollows: message.firstKexPacketFollows,
        reserved: message.reserved
    )
}

private func contractFromSshNegotiatedAlgorithms(
    negotiated: SshNegotiatedAlgorithms
): ContractSshNegotiatedAlgorithms {
    ContractSshNegotiatedAlgorithms(
        negotiated.kexAlgorithm,
        negotiated.serverHostKeyAlgorithm,
        negotiated.encryptionAlgorithmClientToServer,
        negotiated.encryptionAlgorithmServerToClient,
        negotiated.macAlgorithmClientToServer,
        negotiated.macAlgorithmServerToClient,
        compressionAlgorithmClientToServer: negotiated.compressionAlgorithmClientToServer,
        compressionAlgorithmServerToClient: negotiated.compressionAlgorithmServerToClient
    )
}

private func contractToSshNegotiatedAlgorithms(
    negotiated: ContractSshNegotiatedAlgorithms
): SshNegotiatedAlgorithms {
    SshNegotiatedAlgorithms(
        negotiated.kexAlgorithm,
        negotiated.serverHostKeyAlgorithm,
        negotiated.encryptionAlgorithmClientToServer,
        negotiated.encryptionAlgorithmServerToClient,
        negotiated.macAlgorithmClientToServer,
        negotiated.macAlgorithmServerToClient,
        negotiated.compressionAlgorithmClientToServer,
        negotiated.compressionAlgorithmServerToClient
    )
}

private func contractToSshKexInitMessage(
    message: ContractSshKexInitMessage
): SshKexInitMessage {
    contractToSshKexInitMessage(
        message.cookie,
        message.kexAlgorithms,
        message.serverHostKeyAlgorithms,
        message.encryptionAlgorithmsClientToServer,
        message.encryptionAlgorithmsServerToClient,
        message.macAlgorithmsClientToServer,
        message.macAlgorithmsServerToClient,
        message.compressionAlgorithmsClientToServer,
        message.compressionAlgorithmsServerToClient,
        languagesClientToServer: message.languagesClientToServer,
        languagesServerToClient: message.languagesServerToClient,
        firstKexPacketFollows: message.firstKexPacketFollows,
        reserved: message.reserved
    )
}

private func contractToSshKexInitMessage(
    cookie: Array<Byte>,
    kexAlgorithms: Array<String>,
    serverHostKeyAlgorithms: Array<String>,
    encryptionAlgorithmsClientToServer: Array<String>,
    encryptionAlgorithmsServerToClient: Array<String>,
    macAlgorithmsClientToServer: Array<String>,
    macAlgorithmsServerToClient: Array<String>,
    compressionAlgorithmsClientToServer: Array<String>,
    compressionAlgorithmsServerToClient: Array<String>,
    languagesClientToServer!: Array<String> = [],
    languagesServerToClient!: Array<String> = [],
    firstKexPacketFollows!: Bool = false,
    reserved!: Int64 = 0
): SshKexInitMessage {
    try {
        SshKexInitMessage(
            cookie,
            kexAlgorithms,
            serverHostKeyAlgorithms,
            encryptionAlgorithmsClientToServer,
            encryptionAlgorithmsServerToClient,
            macAlgorithmsClientToServer,
            macAlgorithmsServerToClient,
            compressionAlgorithmsClientToServer,
            compressionAlgorithmsServerToClient,
            languagesClientToServer: languagesClientToServer,
            languagesServerToClient: languagesServerToClient,
            firstKexPacketFollows: firstKexPacketFollows,
            reserved: reserved
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH KEXINIT message is invalid: ${e.message}"
        )
    }
}

private func contractToSshKexExchangeTranscript(
    transcript: ContractSshKexExchangeTranscript
): SshKexExchangeTranscript {
    contractToSshKexExchangeTranscript(
        transcript.clientBannerLine,
        transcript.serverBannerLine,
        transcript.clientKexInitPayload,
        transcript.serverKexInitPayload
    )
}

private func contractToSshKexExchangeTranscript(
    clientBannerLine: Array<Byte>,
    serverBannerLine: Array<Byte>,
    clientKexInitPayload: Array<Byte>,
    serverKexInitPayload: Array<Byte>
): SshKexExchangeTranscript {
    try {
        SshKexExchangeTranscript(
            clientBannerLine,
            serverBannerLine,
            clientKexInitPayload,
            serverKexInitPayload
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH KEX transcript is invalid: ${e.message}"
        )
    }
}

private func contractCloneStringArray(values: Array<String>): Array<String> {
    let out = ArrayList<String>()
    for (value in values) {
        out.add(value)
    }
    out.toArray()
}

private func contractToSshX25519KexResult(
    session: ContractSshSessionState
): SshX25519KexResult {
    SshX25519KexResult(
        session.sharedSecret,
        session.exchangeHash,
        session.sessionId,
        session.clientEphemeralPublicKey,
        session.serverEphemeralPublicKey,
        session.serverHostKey,
        session.hostSignature
    )
}

private func contractToSshHostVerificationPolicy(
    policy: ContractSshHostVerificationPolicy
): SshHostVerificationPolicy {
    SshHostVerificationPolicy(
        negotiatedHostKeyAlgorithm: policy.negotiatedHostKeyAlgorithm,
        expectedHostKeySha256: policy.expectedHostKeySha256,
        requireKnownHost: policy.requireKnownHost,
        requireHostSignature: policy.requireHostSignature,
        allowLegacyRsaSha1: policy.allowLegacyRsaSha1
    )
}

private func contractDerChainFromCertificates(certChain: Array<X509Certificate>): Array<Array<Byte>> {
    let out = ArrayList<Array<Byte>>()
    for (cert in certChain) {
        out.add(cert.der.clone())
    }
    out.toArray()
}

private func contractTryParseRsaPrivateKeyPkcs8Pem(pkcs8Pem: String): ?RsaPrivateKey {
    try {
        Some(x509ParseRsaPrivateKeyPkcs8Pem(pkcs8Pem))
    } catch (e: CryptoException) {
        if (e.code == ParseError) {
            return None
        }
        throw e
    }
}

private func contractTryParseEcPrivateKeyPkcs8Pem(pkcs8Pem: String): ?EcPrivateKey {
    try {
        Some(x509ParseEcPrivateKeyPkcs8Pem(pkcs8Pem))
    } catch (e: CryptoException) {
        if (e.code == ParseError) {
            return None
        }
        throw e
    }
}

private func contractParseRsaPrivateKeyPkcs8PemForSshHostSigning(pkcs8Pem: String): RsaPrivateKey {
    try {
        x509ParseRsaPrivateKeyPkcs8Pem(pkcs8Pem)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH RSA host signing request failed: ${e.message}"
        )
    }
}

private func contractParseEcPrivateKeyPkcs8PemForSshHostSigning(pkcs8Pem: String): EcPrivateKey {
    try {
        x509ParseEcPrivateKeyPkcs8Pem(pkcs8Pem)
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH ECDSA host signing request failed: ${e.message}"
        )
    }
}

private func contractBuildSshHostSigningResult(
    serverHostKey: Array<Byte>,
    hostSignature: Array<Byte>
): ContractSshHostSigningResult {
    try {
        let hostKeyAlgorithm = sshExtractHostKeyAlgorithm(serverHostKey)
        let hostSignatureAlgorithm = sshExtractHostSignatureAlgorithm(hostSignature)
        let hostKeySha256 = contractSshComputeHostKeySha256(serverHostKey)
        ContractSshHostSigningResult(
            serverHostKey,
            hostSignature,
            hostKeyAlgorithm,
            hostSignatureAlgorithm,
            hostKeySha256
        )
    } catch (e: ContractException) {
        throw e
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "ssh"),
            "SSH host signing result construction failed: ${e.message}"
        )
    }
}

private func contractIsSomeRsaPrivateKey(value: ?RsaPrivateKey): Bool {
    if (let Some(_inner) <- value) {
        return true
    }
    false
}

private func contractIsSomeEcPrivateKey(value: ?EcPrivateKey): Bool {
    if (let Some(_inner) <- value) {
        return true
    }
    false
}

private func contractToTls12KeyExchange(
    keyExchange: ContractTls12KeyExchange
): Tls12KeyExchange {
    match (keyExchange) {
        case ContractTls12KeyExchange.Rsa => Tls12KeyExchange.RSA
        case ContractTls12KeyExchange.EcdheP256 => Tls12KeyExchange.ECDHE_P256
        case ContractTls12KeyExchange.EcdheP384 => Tls12KeyExchange.ECDHE_P384
    }
}

private func contractFromTls12HandshakeSecrets(
    secrets: Tls12HandshakeSecrets
): ContractTls12HandshakeSecrets {
    ContractTls12HandshakeSecrets(
        secrets.masterSecret,
        secrets.clientWriteKey,
        secrets.clientWriteIv,
        secrets.serverWriteKey,
        secrets.serverWriteIv
    )
}

private func contractToTls12HandshakeSecrets(
    secrets: ContractTls12HandshakeSecrets
): Tls12HandshakeSecrets {
    Tls12HandshakeSecrets(
        secrets.masterSecret,
        secrets.clientWriteKey,
        secrets.serverWriteKey,
        secrets.clientWriteIv,
        secrets.serverWriteIv
    )
}

private func contractToTlsContentType(
    contentType: ContractTlsRecordContentType
): TlsContentType {
    match (contentType) {
        case ContractTlsRecordContentType.ChangeCipherSpec => TlsContentType.ChangeCipherSpec
        case ContractTlsRecordContentType.Alert => TlsContentType.Alert
        case ContractTlsRecordContentType.Handshake => TlsContentType.Handshake
        case ContractTlsRecordContentType.ApplicationData => TlsContentType.ApplicationData
    }
}

private func contractFromTlsContentType(
    contentType: TlsContentType
): ContractTlsRecordContentType {
    match (contentType) {
        case TlsContentType.ChangeCipherSpec => ContractTlsRecordContentType.ChangeCipherSpec
        case TlsContentType.Alert => ContractTlsRecordContentType.Alert
        case TlsContentType.Handshake => ContractTlsRecordContentType.Handshake
        case TlsContentType.ApplicationData => ContractTlsRecordContentType.ApplicationData
    }
}

private func contractFromTlsAeadAlgorithm(algorithm: TlsAeadAlgorithm): ContractAeadAlgorithm {
    match (algorithm) {
        case TlsAeadAlgorithm.AES_GCM => ContractAeadAlgorithm.Aes256Gcm
        case TlsAeadAlgorithm.CHACHA20_POLY1305 => ContractAeadAlgorithm.Chacha20Poly1305
    }
}

private func contractFromTlsVersion(version: TlsVersion): ContractTlsVersion {
    if (version == TLS_VERSION_1_2) {
        return ContractTlsVersion.Tls12
    }
    if (version == TLS_VERSION_1_3) {
        return ContractTlsVersion.Tls13
    }
    throw ContractException(
        ContractErrorCode.Unsupported,
        "unsupported TLS version in contract record channel: ${version.toString()}"
    )
}

private func contractToTlsVersion(version: ContractTlsVersion): TlsVersion {
    match (version) {
        case ContractTlsVersion.Tls12 => TLS_VERSION_1_2
        case ContractTlsVersion.Tls13 => TLS_VERSION_1_3
    }
}

private func contractToTlsAlertLevel(level: ContractTlsAlertLevel): TlsAlertLevel {
    match (level) {
        case ContractTlsAlertLevel.AlertWarning => TlsAlertLevel.Warning
        case ContractTlsAlertLevel.AlertFatal => TlsAlertLevel.Fatal
    }
}

private func contractFromTlsAlertLevel(level: TlsAlertLevel): ContractTlsAlertLevel {
    match (level) {
        case TlsAlertLevel.Warning => ContractTlsAlertLevel.AlertWarning
        case TlsAlertLevel.Fatal => ContractTlsAlertLevel.AlertFatal
    }
}

private func contractToTlsAlertDescription(
    description: ContractTlsAlertDescription
): TlsAlertDescription {
    match (description) {
        case ContractTlsAlertDescription.AlertCloseNotify => TlsAlertDescription.CloseNotify
        case ContractTlsAlertDescription.AlertUnexpectedMessage => TlsAlertDescription.UnexpectedMessage
        case ContractTlsAlertDescription.AlertBadRecordMac => TlsAlertDescription.BadRecordMac
        case ContractTlsAlertDescription.AlertDecryptionFailedReserved => TlsAlertDescription.DecryptionFailedReserved
        case ContractTlsAlertDescription.AlertRecordOverflow => TlsAlertDescription.RecordOverflow
        case ContractTlsAlertDescription.AlertHandshakeFailure => TlsAlertDescription.HandshakeFailure
        case ContractTlsAlertDescription.AlertBadCertificate => TlsAlertDescription.BadCertificate
        case ContractTlsAlertDescription.AlertUnsupportedCertificate => TlsAlertDescription.UnsupportedCertificate
        case ContractTlsAlertDescription.AlertCertificateRevoked => TlsAlertDescription.CertificateRevoked
        case ContractTlsAlertDescription.AlertCertificateExpired => TlsAlertDescription.CertificateExpired
        case ContractTlsAlertDescription.AlertCertificateUnknown => TlsAlertDescription.CertificateUnknown
        case ContractTlsAlertDescription.AlertIllegalParameter => TlsAlertDescription.IllegalParameter
        case ContractTlsAlertDescription.AlertUnknownCa => TlsAlertDescription.UnknownCa
        case ContractTlsAlertDescription.AlertAccessDenied => TlsAlertDescription.AccessDenied
        case ContractTlsAlertDescription.AlertDecodeError => TlsAlertDescription.DecodeError
        case ContractTlsAlertDescription.AlertDecryptError => TlsAlertDescription.DecryptError
        case ContractTlsAlertDescription.AlertProtocolVersion => TlsAlertDescription.ProtocolVersion
        case ContractTlsAlertDescription.AlertInsufficientSecurity => TlsAlertDescription.InsufficientSecurity
        case ContractTlsAlertDescription.AlertInternalError => TlsAlertDescription.InternalError
        case ContractTlsAlertDescription.AlertUserCanceled => TlsAlertDescription.UserCanceled
        case ContractTlsAlertDescription.AlertMissingExtension => TlsAlertDescription.MissingExtension
        case ContractTlsAlertDescription.AlertUnsupportedExtension => TlsAlertDescription.UnsupportedExtension
        case ContractTlsAlertDescription.AlertUnrecognizedName => TlsAlertDescription.UnrecognizedName
        case ContractTlsAlertDescription.AlertBadCertificateStatusResponse => TlsAlertDescription.BadCertificateStatusResponse
        case ContractTlsAlertDescription.AlertUnknownPskIdentity => TlsAlertDescription.UnknownPskIdentity
        case ContractTlsAlertDescription.AlertCertificateRequired => TlsAlertDescription.CertificateRequired
        case ContractTlsAlertDescription.AlertNoApplicationProtocol => TlsAlertDescription.NoApplicationProtocol
    }
}

private func contractFromTlsAlertDescription(
    description: TlsAlertDescription
): ContractTlsAlertDescription {
    match (description) {
        case TlsAlertDescription.CloseNotify => ContractTlsAlertDescription.AlertCloseNotify
        case TlsAlertDescription.UnexpectedMessage => ContractTlsAlertDescription.AlertUnexpectedMessage
        case TlsAlertDescription.BadRecordMac => ContractTlsAlertDescription.AlertBadRecordMac
        case TlsAlertDescription.DecryptionFailedReserved => ContractTlsAlertDescription.AlertDecryptionFailedReserved
        case TlsAlertDescription.RecordOverflow => ContractTlsAlertDescription.AlertRecordOverflow
        case TlsAlertDescription.HandshakeFailure => ContractTlsAlertDescription.AlertHandshakeFailure
        case TlsAlertDescription.BadCertificate => ContractTlsAlertDescription.AlertBadCertificate
        case TlsAlertDescription.UnsupportedCertificate => ContractTlsAlertDescription.AlertUnsupportedCertificate
        case TlsAlertDescription.CertificateRevoked => ContractTlsAlertDescription.AlertCertificateRevoked
        case TlsAlertDescription.CertificateExpired => ContractTlsAlertDescription.AlertCertificateExpired
        case TlsAlertDescription.CertificateUnknown => ContractTlsAlertDescription.AlertCertificateUnknown
        case TlsAlertDescription.IllegalParameter => ContractTlsAlertDescription.AlertIllegalParameter
        case TlsAlertDescription.UnknownCa => ContractTlsAlertDescription.AlertUnknownCa
        case TlsAlertDescription.AccessDenied => ContractTlsAlertDescription.AlertAccessDenied
        case TlsAlertDescription.DecodeError => ContractTlsAlertDescription.AlertDecodeError
        case TlsAlertDescription.DecryptError => ContractTlsAlertDescription.AlertDecryptError
        case TlsAlertDescription.ProtocolVersion => ContractTlsAlertDescription.AlertProtocolVersion
        case TlsAlertDescription.InsufficientSecurity => ContractTlsAlertDescription.AlertInsufficientSecurity
        case TlsAlertDescription.InternalError => ContractTlsAlertDescription.AlertInternalError
        case TlsAlertDescription.UserCanceled => ContractTlsAlertDescription.AlertUserCanceled
        case TlsAlertDescription.MissingExtension => ContractTlsAlertDescription.AlertMissingExtension
        case TlsAlertDescription.UnsupportedExtension => ContractTlsAlertDescription.AlertUnsupportedExtension
        case TlsAlertDescription.UnrecognizedName => ContractTlsAlertDescription.AlertUnrecognizedName
        case TlsAlertDescription.BadCertificateStatusResponse => ContractTlsAlertDescription.AlertBadCertificateStatusResponse
        case TlsAlertDescription.UnknownPskIdentity => ContractTlsAlertDescription.AlertUnknownPskIdentity
        case TlsAlertDescription.CertificateRequired => ContractTlsAlertDescription.AlertCertificateRequired
        case TlsAlertDescription.NoApplicationProtocol => ContractTlsAlertDescription.AlertNoApplicationProtocol
    }
}

private func contractFromTlsAlertMessage(alert: TlsAlertMessage): ContractTlsAlertMessage {
    ContractTlsAlertMessage(
        contractFromTlsAlertLevel(alert.level),
        contractFromTlsAlertDescription(alert.description)
    )
}

private func contractToTlsSessionIdentity(identity: ContractTlsSessionIdentity): TlsSessionIdentity {
    TlsSessionIdentity(
        contractToTlsVersion(identity.version),
        identity.resumptionId,
        serverName: identity.serverName,
        alpnProtocol: identity.alpnProtocol
    )
}

private func contractFromTlsSessionIdentity(identity: TlsSessionIdentity): ContractTlsSessionIdentity {
    ContractTlsSessionIdentity(
        contractFromTlsVersion(identity.version),
        identity.resumptionId,
        serverName: identity.serverName,
        alpnProtocol: identity.alpnProtocol
    )
}

private func contractToTlsSessionTicket(ticket: ContractTlsSessionTicket): TlsSessionTicket {
    TlsSessionTicket(
        contractToTlsSessionIdentity(ticket.identity),
        ticket.secret,
        ticket.nonce,
        ticket.issuedAtUnixSeconds,
        ticket.expiresAtUnixSeconds,
        version: ticket.version
    )
}

private func contractFromTlsSessionTicket(ticket: TlsSessionTicket): ContractTlsSessionTicket {
    ContractTlsSessionTicket(
        ticket.version,
        contractFromTlsSessionIdentity(ticket.identity),
        ticket.secret,
        ticket.nonce,
        ticket.issuedAtUnixSeconds,
        ticket.expiresAtUnixSeconds
    )
}

private func contractFromTlsSessionCacheStats(stats: TlsSessionCacheStats): ContractTlsSessionCacheStats {
    ContractTlsSessionCacheStats(
        stats.size,
        stats.hits,
        stats.misses,
        stats.evictions,
        stats.expiredRemovals
    )
}

private func contractTls12ResolveEcdheCurveSpec(
    keyExchange: ContractTls12KeyExchange
): (NamedCurve, Int64) {
    match (keyExchange) {
        case ContractTls12KeyExchange.EcdheP256 => (P256, 32)
        case ContractTls12KeyExchange.EcdheP384 => (P384, 48)
        case ContractTls12KeyExchange.Rsa =>
            throw ContractException(
                ContractErrorCode.BadInput,
                "TLS1.2 ECDHE contract API requires ECDHE_P256 or ECDHE_P384 key exchange"
            )
    }
}

private func contractTls12EcPrivateKeyFromScalar(
    curve: NamedCurve,
    scalar: Array<Byte>,
    fieldBytes: Int64,
    roleLabel: String
): EcPrivateKey {
    if (scalar.size != fieldBytes) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "TLS1.2 ECDHE ${roleLabel} private scalar must be ${fieldBytes} bytes"
        )
    }
    if (isZeroBytes(scalar)) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "TLS1.2 ECDHE ${roleLabel} private scalar must not be zero"
        )
    }
    EcPrivateKey(curve, BigNum.fromBytesBE(scalar))
}

private func contractToTlsHttpNegotiationPolicy(
    policy: ContractTlsHttpNegotiationPolicy
): TlsHttpNegotiationPolicy {
    TlsHttpNegotiationPolicy(
        requireServerName: policy.requireServerName,
        allowedServerNames: policy.allowedServerNames,
        alpnPreference: policy.alpnPreference
    )
}

private func contractTls13CipherSuiteName(cipherSuite: Int64): String {
    if (cipherSuite == TLS13_CIPHER_SUITE_AES_128_GCM_SHA256) {
        return "TLS_AES_128_GCM_SHA256"
    }
    if (cipherSuite == TLS13_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) {
        return "TLS_CHACHA20_POLY1305_SHA256"
    }
    "TLS_UNKNOWN_${cipherSuite}"
}

private func contractToHashAlgorithm(hash: ContractKdfHash): HashAlgorithm {
    match (hash) {
        case ContractKdfHash.Sha1 => HashAlgorithm.SHA1
        case ContractKdfHash.Sha256 => HashAlgorithm.SHA256
        case ContractKdfHash.Sha384 => HashAlgorithm.SHA384
        case ContractKdfHash.Sha512 => HashAlgorithm.SHA512
    }
}

private func contractFromTls13PskX25519DerivedSecrets(
    binding: ContractTls13CipherBinding,
    tlsSecrets: Tls13HandshakeSecrets
): ContractTls13PskX25519DerivedSecrets {
    ContractTls13PskX25519DerivedSecrets(
        binding,
        ContractTls13ApplicationKeyMaterial(
            tlsSecrets.clientWriteKey,
            tlsSecrets.clientWriteIv,
            tlsSecrets.serverWriteKey,
            tlsSecrets.serverWriteIv
        ),
        tlsSecrets.clientAppTrafficSecret,
        tlsSecrets.serverAppTrafficSecret,
        tlsSecrets.masterSecret
    )
}

private func contractTls13BuildKeyUpdatePlan(
    currentTrafficSecret: Array<Byte>,
    encodedKeyUpdate: Array<Byte>,
    keyLen: Int64,
    ivLen: Int64
): ContractTls13KeyUpdatePlan {
    let requestPeerUpdate = contractTls13DecodeKeyUpdateHandshake(encodedKeyUpdate)
    let nextTrafficSecret = contractTls13DeriveNextApplicationTrafficSecret(currentTrafficSecret)
    let (nextWriteKey, nextWriteIv) = contractTls13DeriveApplicationTrafficKeyIv(
        nextTrafficSecret,
        keyLen: keyLen,
        ivLen: ivLen
    )
    ContractTls13KeyUpdatePlan(
        encodedKeyUpdate,
        requestPeerUpdate,
        nextTrafficSecret,
        nextWriteKey,
        nextWriteIv
    )
}

private func contractTls13BuildPskEarlyDataPlan(
    ticket: ContractTlsSessionTicket,
    encodedClientHello: Array<Byte>,
    selectedIdentityIndex: Int64,
    keyLen: Int64,
    ivLen: Int64
): ContractTls13PskEarlyDataPlan {
    let clientHelloHash = sha256(encodedClientHello)
    try {
        let earlyDataSecrets = tls13DeriveEarlyDataSecrets(
            ticket.secret,
            clientHelloHash,
            keyLen: keyLen,
            ivLen: ivLen
        )
        ContractTls13PskEarlyDataPlan(
            selectedIdentityIndex,
            ticket,
            encodedClientHello,
            clientHelloHash,
            earlyDataSecrets.clientEarlyTrafficSecret,
            earlyDataSecrets.clientEarlyWriteKey,
            earlyDataSecrets.clientEarlyWriteIv
        )
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "tls"),
            "TLS1.3 PSK early data secret derivation failed: ${e.message}"
        )
    }
}

private func contractTls13BuildPskEarlyDataReplayKeyFromFields(
    identity: ContractTlsSessionIdentity,
    clientHelloHash: Array<Byte>
): String {
    if (clientHelloHash.size != 32) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "TLS1.3 PSK early data replay hash must be SHA-256 sized"
        )
    }
    let versionTag = identity.version.toString()
    let resumptionId = base64UrlEncode(identity.resumptionId)
    let hash = base64UrlEncode(clientHelloHash)
    "${versionTag}:${resumptionId}:${hash}"
}

private func contractTls13RebuildVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    serverWriteKey: Array<Byte>,
    serverWriteIv: Array<Byte>,
    clientAppTrafficSecret: Array<Byte>,
    serverAppTrafficSecret: Array<Byte>,
    clientWriteKey: Array<Byte>,
    clientWriteIv: Array<Byte>
): ContractTls13HttpClientVerifiedSession {
    let previous = session.result
    let keyMaterial = ContractTls13ApplicationKeyMaterial(
        clientWriteKey,
        clientWriteIv,
        serverWriteKey,
        serverWriteIv
    )
    let result = ContractTls13HttpClientResult(
        previous.selectedAlpn,
        previous.requestedServerName,
        previous.acknowledgedServerName,
        previous.chainLength,
        previous.leafSubjectCommonName,
        previous.trustAnchorCommonName,
        previous.leafDerSha256,
        previous.leafSpkiSha256,
        keyMaterial,
        cipherBinding: previous.cipherBinding
    )
    ContractTls13HttpClientVerifiedSession(
        result,
        clientAppTrafficSecret,
        serverAppTrafficSecret,
        session.masterSecret,
        session.transcriptHash
    )
}

private func contractTls13ValidatePskEarlyDataHttpBinding(
    identity: ContractTlsSessionIdentity,
    expectedServerName: String,
    expectedAlpnProtocol: String
): Unit {
    let normalizedServerName = expectedServerName.trimAscii().toAsciiLower()
    if (normalizedServerName.size > 0) {
        if (identity.serverName.size == 0 || identity.serverName != normalizedServerName) {
            throw ContractException(
                ContractErrorCode.VerifyFailed,
                "TLS1.3 PSK early data ticket server_name does not match expected endpoint"
            )
        }
    }

    let normalizedAlpn = expectedAlpnProtocol.trimAscii().toAsciiLower()
    if (normalizedAlpn.size > 0) {
        if (identity.alpnProtocol.size == 0 || identity.alpnProtocol != normalizedAlpn) {
            throw ContractException(
                ContractErrorCode.VerifyFailed,
                "TLS1.3 PSK early data ticket ALPN does not match expected endpoint"
            )
        }
    }
}

private func contractTls13RotatePskX25519ClientSecrets(
    secrets: ContractTls13PskX25519DerivedSecrets
): ContractTls13PskX25519DerivedSecrets {
    let nextClientAppTrafficSecret = contractTls13DeriveNextApplicationTrafficSecret(
        secrets.clientAppTrafficSecret
    )
    let (nextClientWriteKey, nextClientWriteIv) = contractTls13DeriveApplicationTrafficKeyIv(
        nextClientAppTrafficSecret,
        keyLen: secrets.cipherBinding.keyLen,
        ivLen: secrets.cipherBinding.ivLen
    )
    contractTls13BuildPskX25519DerivedSecrets(
        secrets,
        nextClientAppTrafficSecret,
        secrets.serverAppTrafficSecret,
        nextClientWriteKey,
        nextClientWriteIv,
        secrets.keyMaterial.serverWriteKey,
        secrets.keyMaterial.serverWriteIv
    )
}

private func contractTls13RotatePskX25519ServerSecrets(
    secrets: ContractTls13PskX25519DerivedSecrets
): ContractTls13PskX25519DerivedSecrets {
    let nextServerAppTrafficSecret = contractTls13DeriveNextApplicationTrafficSecret(
        secrets.serverAppTrafficSecret
    )
    let (nextServerWriteKey, nextServerWriteIv) = contractTls13DeriveApplicationTrafficKeyIv(
        nextServerAppTrafficSecret,
        keyLen: secrets.cipherBinding.keyLen,
        ivLen: secrets.cipherBinding.ivLen
    )
    contractTls13BuildPskX25519DerivedSecrets(
        secrets,
        secrets.clientAppTrafficSecret,
        nextServerAppTrafficSecret,
        secrets.keyMaterial.clientWriteKey,
        secrets.keyMaterial.clientWriteIv,
        nextServerWriteKey,
        nextServerWriteIv
    )
}

private func contractTls13BuildPskX25519DerivedSecrets(
    current: ContractTls13PskX25519DerivedSecrets,
    clientAppTrafficSecret: Array<Byte>,
    serverAppTrafficSecret: Array<Byte>,
    clientWriteKey: Array<Byte>,
    clientWriteIv: Array<Byte>,
    serverWriteKey: Array<Byte>,
    serverWriteIv: Array<Byte>
): ContractTls13PskX25519DerivedSecrets {
    ContractTls13PskX25519DerivedSecrets(
        current.cipherBinding,
        ContractTls13ApplicationKeyMaterial(
            clientWriteKey,
            clientWriteIv,
            serverWriteKey,
            serverWriteIv
        ),
        clientAppTrafficSecret,
        serverAppTrafficSecret,
        current.masterSecret
    )
}

private func contractFromTls13ServerHandshakeFlight(
    flight: Tls13ServerHandshakeFlight
): ContractTls13HttpServerFlight {
    ContractTls13HttpServerFlight(
        flight.serverHello,
        flight.encryptedExtensions,
        flight.authFlight.certificateHandshake,
        flight.authFlight.certificateVerifyHandshake,
        flight.authFlight.finishedHandshake,
        flight.transcriptHash,
        selectedAlpn: flight.selectedAlpn,
        requestedServerName: flight.requestedServerName,
        acknowledgedServerName: flight.acknowledgedServerName
    )
}

private func contractToTls13ServerHandshakeFlight(
    flight: ContractTls13HttpServerFlight
): Tls13ServerHandshakeFlight {
    let authFlight = Tls13AuthFlight(
        Tls13AuthFlightRole.SERVER,
        flight.certificateHandshake,
        flight.certificateVerifyHandshake,
        flight.finishedHandshake
    )
    Tls13ServerHandshakeFlight(
        flight.serverHello,
        flight.encryptedExtensions,
        authFlight,
        flight.transcriptHash,
        selectedAlpn: flight.selectedAlpn,
        requestedServerName: flight.requestedServerName,
        acknowledgedServerName: flight.acknowledgedServerName
    )
}

private func contractEncryptAead(
    algorithm: ContractAeadAlgorithm,
    key: Array<Byte>,
    nonce: Array<Byte>,
    plaintext: Array<Byte>,
    aad: Array<Byte>
): (Array<Byte>, Array<Byte>) {
    try {
        match (algorithm) {
            case ContractAeadAlgorithm.Aes256Gcm =>
                aesGcmEncryptWithContext(contractResolveAesGcmContext(key), nonce, plaintext, aad: aad, tagLen: 16)
            case ContractAeadAlgorithm.Chacha20Poly1305 =>
                chacha20Poly1305Encrypt(key, nonce, plaintext, aad: aad)
        }
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "encrypt"),
            "AEAD encryption failed: ${e.message}"
        )
    }
}

private func contractResolveAesGcmContext(key: Array<Byte>): AesGcmContext {
    var index = 0
    while (index < _contractAesGcmContextCache.size) {
        let entry = _contractAesGcmContextCache[index]
        if (constantTimeEquals(entry.key, key)) {
            return entry.context
        }
        index += 1
    }

    let context = aesNewGcmContext(key)
    let keyCopy = key.clone()

    if (_contractAesGcmContextCache.size >= CONTRACT_AES_GCM_CONTEXT_CACHE_MAX) {
        _contractAesGcmContextCache.remove(at: 0)
    }
    _contractAesGcmContextCache.add(ContractAesGcmContextCacheEntry(keyCopy, context))
    context
}

private func contractDecryptAead(
    algorithm: ContractAeadAlgorithm,
    key: Array<Byte>,
    nonce: Array<Byte>,
    ciphertext: Array<Byte>,
    tag: Array<Byte>,
    aad: Array<Byte>
): Array<Byte> {
    try {
        match (algorithm) {
            case ContractAeadAlgorithm.Aes256Gcm =>
                aesGcmDecryptWithContext(contractResolveAesGcmContext(key), nonce, ciphertext, tag, aad: aad)
            case ContractAeadAlgorithm.Chacha20Poly1305 =>
                chacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad: aad)
        }
    } catch (e: CryptoException) {
        throw ContractException(
            mapCryptoErrorForOperation(e, "decrypt"),
            "AEAD decryption failed: ${e.message}"
        )
    }
}

private func contractRequirePinPolicy(
    pinPolicy: ContractX509PinPolicy,
    leafDerSha: Array<Byte>,
    leafSpkiSha: Array<Byte>
): Unit {
    if (pinPolicy.allowedLeafDerSha256.size > 0) {
        var found = false
        for (pin in pinPolicy.allowedLeafDerSha256) {
            if (constantTimeEquals(pin, leafDerSha)) {
                found = true
                break
            }
        }
        if (!found) {
            throw ContractException(ContractErrorCode.VerifyFailed, "leaf certificate DER pin mismatch")
        }
    }

    if (pinPolicy.allowedLeafSpkiSha256.size > 0) {
        var found = false
        for (pin in pinPolicy.allowedLeafSpkiSha256) {
            if (constantTimeEquals(pin, leafSpkiSha)) {
                found = true
                break
            }
        }
        if (!found) {
            throw ContractException(ContractErrorCode.VerifyFailed, "leaf certificate SPKI pin mismatch")
        }
    }
}

private func contractVerifyServerCertificateParsed(
    leaf: X509Certificate,
    trustAnchorsPemBundle: String,
    intermediates: Array<X509Certificate>,
    hostname: String,
    validationTime: String,
    pinPolicy: ContractX509PinPolicy
): ContractX509VerifyResult {
    let anchors = x509ParsePemChain(trustAnchorsPemBundle)
    let policy = X509VerificationPolicy(
        anchors,
        intermediates: intermediates,
        requiredLeafDnsName: hostname,
        validationTime: validationTime
    )
    let verified = x509VerifyCertificateChain(leaf, policy)
    let leafDerSha = sha256(leaf.der)
    let leafSpkiSha = sha256(leaf.subjectPublicKeyInfoDer)
    contractRequirePinPolicy(pinPolicy, leafDerSha, leafSpkiSha)

    ContractX509VerifyResult(
        verified.chain.size,
        leaf.subject.commonName(),
        leaf.issuer.commonName(),
        verified.trustAnchor.subject.commonName(),
        leafDerSha,
        leafSpkiSha
    )
}

private func contractNormalizeAlpnProtocols(alpnProtocols: Array<String>): Array<String> {
    let normalized = ArrayList<String>()
    for (protocol in alpnProtocols) {
        let value = protocol.trimAscii().toAsciiLower()
        if (value.size == 0) {
            continue
        }
        var exists = false
        for (item in normalized) {
            if (item == value) {
                exists = true
                break
            }
        }
        if (!exists) {
            normalized.add(value)
        }
    }
    if (normalized.size == 0) {
        throw ContractException(ContractErrorCode.BadInput, "TLS ALPN protocol list must not be empty")
    }
    normalized.toArray()
}

private func contractContainsString(values: Array<String>, expected: String): Bool {
    for (value in values) {
        if (value == expected) {
            return true
        }
    }
    false
}

private func contractValidateLeafCertificateAndPrivateKeyMatch(
    leaf: X509Certificate,
    privateKeyPem: String
): String {
    match (contractTryParseRsaPrivateKeyPem(privateKeyPem)) {
        case Some(rsaPrivateKey) =>
            let leafPublicKey = try {
                x509ExtractRsaPublicKey(leaf)
            } catch (_: CryptoException) {
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "TLS certificate public key is not RSA but private key is RSA"
                )
            }
            if (
                leafPublicKey.modulus.cmp(rsaPrivateKey.publicKey.modulus) != 0 ||
                leafPublicKey.exponent.cmp(rsaPrivateKey.publicKey.exponent) != 0
            ) {
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "TLS certificate public key does not match RSA private key"
                )
            }
            return "RSA"
        case None =>
            ()
    }

    match (contractTryParseEcPrivateKeyPem(privateKeyPem)) {
        case Some(ecPrivateKey) =>
            let leafPublicKey = try {
                x509ExtractEcPublicKey(leaf)
            } catch (_: CryptoException) {
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "TLS certificate public key is not EC but private key is EC"
                )
            }
            let derivedPublicKey = ecPublicFromPrivateKey(ecPrivateKey)
            if (
                leafPublicKey.curve != derivedPublicKey.curve ||
                leafPublicKey.x.cmp(derivedPublicKey.x) != 0 ||
                leafPublicKey.y.cmp(derivedPublicKey.y) != 0
            ) {
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "TLS certificate public key does not match EC private key"
                )
            }
            return "EC"
        case None =>
            ()
    }

    throw ContractException(
        ContractErrorCode.BadInput,
        "unsupported TLS private key PEM format (expected RSA PKCS#1/PKCS#8 or EC PKCS#8)"
    )
}

private func contractTryParseRsaPrivateKeyPem(privateKeyPem: String): ?RsaPrivateKey {
    try {
        return Some(x509ParseRsaPrivateKeyPkcs8Pem(privateKeyPem))
    } catch (_: CryptoException) {
        ()
    }
    try {
        return Some(x509ParseRsaPrivateKeyPkcs1Pem(privateKeyPem))
    } catch (_: CryptoException) {
        ()
    }
    None
}

private func contractTryParseEcPrivateKeyPem(privateKeyPem: String): ?EcPrivateKey {
    try {
        Some(x509ParseEcPrivateKeyPkcs8Pem(privateKeyPem))
    } catch (_: CryptoException) {
        None
    }
}

private func contractCertificatesToPemBlocks(certificates: Array<X509Certificate>): Array<String> {
    let blocks = ArrayList<String>()
    for (certificate in certificates) {
        blocks.add(certificate.toPem())
    }
    blocks.toArray()
}

private func contractCloneTrimmedPemBlocks(pemBlocks: Array<String>, fieldName: String): Array<String> {
    let normalized = ArrayList<String>()
    for (pemBlock in pemBlocks) {
        let trimmed = pemBlock.trimAscii()
        if (trimmed.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "${fieldName} block must not be empty")
        }
        normalized.add(trimmed)
    }
    normalized.toArray()
}

private func contractJoinPemBlocks(pemBlocks: Array<String>): String {
    if (pemBlocks.size == 0) {
        return ""
    }
    var out = ""
    var first = true
    for (pemBlock in pemBlocks) {
        let trimmed = pemBlock.trimAscii()
        if (trimmed.size == 0) {
            continue
        }
        if (!first) {
            out += "\n"
        }
        out += trimmed
        first = false
    }
    out
}

private func decodeEnvelopeField(text: String, fieldName: String): Array<Byte> {
    try {
        base64UrlDecode(text)
    } catch (e: ContractException) {
        throw ContractException(ContractErrorCode.BadInput, "invalid envelope ${fieldName}: ${e.message}")
    }
}

private func contractNormalizeAlgorithmToken(raw: String): String {
    let normalized = raw.trimAscii().toAsciiUpper()
    _ = contractParseAlgorithmToken(normalized)
    normalized
}

private func contractCloneOptionalBytes(bytes: ?Array<Byte>): ?Array<Byte> {
    match (bytes) {
        case Some(value) => Some(value.clone())
        case None => None
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractTlsHttpNegotiationPolicyValidationResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractHttpClientTlsConfigValidationResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractHttpServerTlsMaterial,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractHttpClientTlsTrustMaterial,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractHttpServerTlsConfigValidationResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractSshHostVerificationResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractSshHostSigningResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractSshServerInitialHandshakeResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractSshClientInitialHandshakeResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractTls13HttpClientResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractTls13PskClientHelloFromCacheResult,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractValidateOutcomeState(
    ok: Bool,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    result: ?ContractTls13HttpClientVerifiedSession,
    resultLabel: String
): Unit {
    if (ok) {
        match (code) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must be empty when ok is true"
                )
            case None => ()
        }
        match (igniteCode) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must be empty when ok is true"
                )
            case None => ()
        }
        match (result) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must exist when ok is true"
                )
        }
    } else {
        match (code) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} code must exist when ok is false"
                )
        }
        match (igniteCode) {
            case Some(_) => ()
            case None =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} ignite code must exist when ok is false"
                )
        }
        match (result) {
            case Some(_) =>
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "${resultLabel} must be empty when ok is false"
                )
            case None => ()
        }
    }
}

private func contractParseAlgorithmToken(raw: String): ContractAeadAlgorithm {
    let normalized = raw.trimAscii().toAsciiUpper()
    if (normalized == "AES-256-GCM") {
        return ContractAeadAlgorithm.Aes256Gcm
    }
    if (normalized == "CHACHA20-POLY1305") {
        return ContractAeadAlgorithm.Chacha20Poly1305
    }
    throw ContractException(ContractErrorCode.Unsupported, "unsupported AEAD algorithm: ${raw}")
}

private func requireTokenAscii(value: String, fieldName: String, allowEmpty!: Bool = false): Unit {
    if (!allowEmpty && value.size == 0) {
        throw ContractException(ContractErrorCode.BadInput, "${fieldName} must not be empty")
    }
    for (ch in value.toArray()) {
        if (
            (ch >= b'a' && ch <= b'z') ||
            (ch >= b'A' && ch <= b'Z') ||
            (ch >= b'0' && ch <= b'9') ||
            ch == b'-' ||
            ch == b'_' ||
            ch == b'.'
        ) {
            continue
        }
        throw ContractException(ContractErrorCode.BadInput, "${fieldName} contains invalid token character")
    }
}

private func mapCryptoErrorForOperation(e: CryptoException, operation: String): ContractErrorCode {
    if (operation == "random" && e.code == Unsupported) {
        return ContractErrorCode.CryptoUnavailable
    }
    if (operation == "decrypt") {
        if (e.code == InvalidArgument || e.code == ParseError) {
            return ContractErrorCode.VerifyFailed
        }
    }
    if (operation == "x509" && e.code == ParseError) {
        return ContractErrorCode.VerifyFailed
    }
    if (operation == "tls") {
        if (e.code == ParseError) {
            return ContractErrorCode.VerifyFailed
        }
        if (e.code == Unsupported) {
            return ContractErrorCode.Unsupported
        }
    }
    if (operation == "ssh" && (e.code == ParseError || e.code == Unsupported)) {
        return ContractErrorCode.VerifyFailed
    }
    contractMapCryptoErrorCode(e.code)
}

private func clonePinList(pins: Array<Array<Byte>>, label: String): Array<Array<Byte>> {
    let out = ArrayList<Array<Byte>>()
    for (pin in pins) {
        requireSha256Pin(pin, "${label} pin")
        out.add(pin.clone())
    }
    out.toArray()
}

private func requireSha256Pin(pin: Array<Byte>, fieldName: String): Unit {
    if (pin.size != 32) {
        throw ContractException(ContractErrorCode.BadInput, "${fieldName} must be 32 bytes (SHA-256)")
    }
}

private func removeAsciiSpaces(text: String): String {
    var out = ""
    for (ch in text.toRuneArray()) {
        if (ch == r' ' || ch == r'\n' || ch == r'\r' || ch == r'\t') {
            continue
        }
        out += ch.toString()
    }
    out
}

private func extractStringField(json: String, key: String): String {
    let pattern = "\"${key}\":\""
    let start = indexOfString(json, pattern)
    if (start < 0) {
        throw ContractException(ContractErrorCode.BadInput, "missing envelope field: ${key}")
    }
    let valueStart = start + pattern.size
    let valueEnd = indexOfRuneFrom(json, r'\"', valueStart)
    if (valueEnd < 0) {
        throw ContractException(ContractErrorCode.BadInput, "invalid envelope string field: ${key}")
    }
    substringRange(json, valueStart, valueEnd)
}

private func extractOptionalStringField(json: String, key: String, defaultValue: String): String {
    let pattern = "\"${key}\":\""
    let start = indexOfString(json, pattern)
    if (start < 0) {
        return defaultValue
    }
    let valueStart = start + pattern.size
    let valueEnd = indexOfRuneFrom(json, r'\"', valueStart)
    if (valueEnd < 0) {
        throw ContractException(ContractErrorCode.BadInput, "invalid envelope string field: ${key}")
    }
    substringRange(json, valueStart, valueEnd)
}

private func extractIntField(json: String, key: String): Int64 {
    let pattern = "\"${key}\":"
    let start = indexOfString(json, pattern)
    if (start < 0) {
        throw ContractException(ContractErrorCode.BadInput, "missing envelope field: ${key}")
    }
    let runes = json.toRuneArray()
    var i = start + pattern.size
    var digits = ""
    while (i < runes.size) {
        let ch = runes[i]
        if (ch >= r'0' && ch <= r'9') {
            digits += ch.toString()
            i += 1
            continue
        }
        break
    }
    if (digits.size == 0) {
        throw ContractException(ContractErrorCode.BadInput, "invalid envelope integer field: ${key}")
    }
    parseInt64Ascii(digits)
}

private func parseInt64Ascii(text: String): Int64 {
    var out: Int64 = 0
    for (ch in text.toRuneArray()) {
        out = (out * 10) + digitOfRune(ch)
    }
    out
}

private func digitOfRune(ch: Rune): Int64 {
    match (ch) {
        case r'0' => 0
        case r'1' => 1
        case r'2' => 2
        case r'3' => 3
        case r'4' => 4
        case r'5' => 5
        case r'6' => 6
        case r'7' => 7
        case r'8' => 8
        case r'9' => 9
        case _ => throw ContractException(ContractErrorCode.BadInput, "invalid numeric field")
    }
}

private func indexOfString(text: String, needle: String): Int64 {
    let hay = text.toRuneArray()
    let target = needle.toRuneArray()
    if (target.size == 0) {
        return 0
    }
    if (hay.size < target.size) {
        return -1
    }

    var i = 0
    while (i <= hay.size - target.size) {
        var matched = true
        var j = 0
        while (j < target.size) {
            if (hay[i + j] != target[j]) {
                matched = false
                break
            }
            j += 1
        }
        if (matched) {
            return i
        }
        i += 1
    }
    -1
}

private func indexOfRuneFrom(text: String, target: Rune, start: Int64): Int64 {
    let chars = text.toRuneArray()
    var i = start
    while (i < chars.size) {
        if (chars[i] == target) {
            return i
        }
        i += 1
    }
    -1
}

private func substringRange(text: String, start: Int64, endExclusive: Int64): String {
    let chars = text.toRuneArray()
    if (start < 0 || endExclusive < start || endExclusive > chars.size) {
        throw ContractException(ContractErrorCode.BadInput, "invalid envelope string range")
    }
    var out = ""
    var i = start
    while (i < endExclusive) {
        out += chars[i].toString()
        i += 1
    }
    out
}

private func base64UrlEncode(input: Array<Byte>): String {
    let data = toUInt8Array(input)
    if (data.size == 0) {
        return ""
    }

    let table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toRuneArray()
    var out = ""
    var i = 0
    while (i < data.size) {
        let b0 = Int64(data[i])
        let b1 = if (i + 1 < data.size) { Int64(data[i + 1]) } else { -1 }
        let b2 = if (i + 2 < data.size) { Int64(data[i + 2]) } else { -1 }

        let x0 = b0 >> 2
        let x1 = ((b0 & 0x03) << 4) | (if (b1 >= 0) { (b1 >> 4) & 0x0f } else { 0 })
        out += table[x0].toString()
        out += table[x1].toString()

        if (b1 >= 0) {
            let x2 = ((b1 & 0x0f) << 2) | (if (b2 >= 0) { (b2 >> 6) & 0x03 } else { 0 })
            out += table[x2].toString()
        }
        if (b2 >= 0) {
            let x3 = b2 & 0x3f
            out += table[x3].toString()
        }
        i += 3
    }
    out
}

private func base64UrlDecode(input: String): Array<Byte> {
    let text = input.trimAscii()
    if (text.size == 0) {
        return []
    }

    let out = ArrayList<UInt8>()
    var buffer: Int64 = 0
    var bits: Int64 = 0
    for (ch in text.toRuneArray()) {
        let value = base64UrlIndex(ch)
        if (value < 0) {
            throw ContractException(ContractErrorCode.BadInput, "invalid base64url character")
        }
        buffer = (buffer << 6) | value
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.add(UInt8((buffer >> bits) & 0xFF))
        }
    }
    toByteArray(out.toArray())
}

private func base64UrlIndex(ch: Rune): Int64 {
    let table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toRuneArray()
    var i = 0
    while (i < table.size) {
        if (table[i] == ch) {
            return i
        }
        i += 1
    }
    -1
}

private func isZeroBytes(bytes: Array<Byte>): Bool {
    for (value in bytes) {
        if (UInt8(value) != UInt8(0)) {
            return false
        }
    }
    true
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

private func toByteArray(bytes: Array<UInt8>): Array<Byte> {
    let out = Array<Byte>(bytes.size, repeat: 0)
    var i = 0
    while (i < bytes.size) {
        out[i] = UInt8(bytes[i])
        i += 1
    }
    out
}
