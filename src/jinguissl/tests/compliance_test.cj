package jinguissl.tests

import jinguissl.crypto.compliance.*
import jinguissl.crypto.error.CryptoException

@Test
public class ComplianceTestSuite {
    @TestCase
    public func testDefaultProfileAllowAndReject(): Unit {
        let profile = FipsProfile.phase1Default()
        @Assert(profile.isAllowed("AES-GCM"), true)
        @Assert(profile.isAllowed("md5"), false)

        profile.requireAllowed("TLS1.3")

        try {
            profile.requireAllowed("AES-ECB")
            @Fail("AES-ECB should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "COMPLIANCE_REJECTED")
        }
    }

    @TestCase
    public func testProfileFromText(): Unit {
        let raw = """
# phase1 profile
sha-256, hmac-sha-256
TLS1.3
"""
        let profile = FipsProfile.fromText(raw)
        @Assert(profile.isAllowed("SHA-256"), true)
        @Assert(profile.isAllowed("HMAC-SHA-256"), true)
        @Assert(profile.isAllowed("TLS1.3"), true)
        @Assert(profile.isAllowed("MD5"), false)
    }

    @TestCase
    public func testTlsConstants(): Unit {
        @Assert(TLS_VERSION_1_2.toString(), "TLS1.2")
        @Assert(TLS_VERSION_1_3.toString(), "TLS1.3")
    }

    @TestCase
    public func testProfileValidationAndNormalization(): Unit {
        try {
            _ = FipsProfile([])
            @Fail("empty allow list should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            _ = FipsProfile(["  ", "\t"])
            @Fail("blank allow list should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        let profile = FipsProfile([" aes-gcm ", " tls1.3 "])
        @Assert(profile.isAllowed("AES-GCM"), true)
        @Assert(profile.isAllowed("tls1.3"), true)
        @Assert(profile.isAllowed("AES-ECB"), false)

        try {
            profile.requireAllowed(" AES-ECB ")
            @Fail("blocked algorithm should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "COMPLIANCE_REJECTED")
        }
    }
}
