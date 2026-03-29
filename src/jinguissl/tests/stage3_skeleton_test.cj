package jinguissl.tests

import std.fs.*
import std.collection.{ArrayList, HashMap}
import jinguissl.crypto.bignum.BigNum
import jinguissl.crypto.compliance.FipsProfile
import jinguissl.crypto.ecc.*
import jinguissl.crypto.error.CryptoException
import jinguissl.crypto.rsa.*

type KeyValueVector = HashMap<String, String>

@Test
public class Stage3SkeletonTestSuite {
    @TestCase
    public func testStage3VectorFilesLoad(): Unit {
        let signVectors = parseVectorFile("testdata/stage3/ecdsa_sign_sample.txt")
        let verifyVectors = parseVectorFile("testdata/stage3/ecdsa_verify_sample.txt")
        let verifyP256Vectors = parseVectorFile("testdata/stage3/ecdsa_verify_p256_sample.txt")
        let rsaVectors = parseVectorFile("testdata/stage3/rsa_params_sample.txt")

        @Assert(signVectors.size > 0, true)
        @Assert(verifyVectors.size > 0, true)
        @Assert(verifyP256Vectors.size > 0, true)
        @Assert(rsaVectors.size > 0, true)

        for (item in signVectors) {
            _ = requireValue(item, "Curve")
            _ = requireValue(item, "Digest")
            _ = requireValue(item, "R")
            _ = requireValue(item, "S")
        }

        for (item in verifyVectors) {
            _ = requireValue(item, "Curve")
            _ = requireValue(item, "Digest")
            _ = requireValue(item, "R")
            _ = requireValue(item, "S")
        }
    }

    @TestCase
    public func testRsaStage3SkeletonAndValidation(): Unit {
        let profile = FipsProfile.phase1Default()
        rsaRequireAllowed(profile)
        rsaValidateKeyParameters(2048, BigNum.fromHex("010001"))

        try {
            rsaValidateKeyParameters(1024, BigNum.fromHex("010001"))
            @Fail("RSA-1024 should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "COMPLIANCE_REJECTED")
        }

        try {
            rsaValidateKeyParameters(2048, BigNum.fromHex("100"))
            @Fail("even RSA exponent should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        let sk = RsaPrivateKey(
            BigNum.fromHex("d5"),
            BigNum.fromHex("03"),
            BigNum.fromHex("13")
        )
        @Assert(sk.publicKey.bits() > 0, true)

        let generated = rsaGenerateKey(2048)
        @Assert(generated.publicKey.bits(), 2048)
        let digest = hexToBytes(TEST_HEX_32_00112233445566778899AABBCCDDEEFF_00112233445566778899AABBCCDDEEFF)
        let signature = rsaSignPkcs1v15(generated, digest)
        @Assert(rsaVerifyPkcs1v15(generated.publicKey, digest, signature), true)
    }

    @TestCase
    public func testRsaPkcs1v15SignVerifyWithVectorKey(): Unit {
        let vectors = parseVectorFile("testdata/stage3/rsa_params_sample.txt")
        var selected = HashMap<String, String>()
        for (item in vectors) {
            if (requireValueOrEmpty(item, "Vector") == "RSA-2048") {
                selected = item
                break
            }
        }
        if (selected.size == 0) {
            @Fail("RSA-2048 vector not found")
        }

        let privateKey = rsaPrivateKeyFromHex(
            requireValue(selected, "N"),
            requireValue(selected, "E"),
            requireValue(selected, "D")
        )
        let publicKey = privateKey.publicKey

        let digest = hexToBytes(TEST_HEX_32_00112233445566778899AABBCCDDEEFF_00112233445566778899AABBCCDDEEFF)
        let signature = rsaSignPkcs1v15(privateKey, digest)
        @Assert(signature.size, 256)
        @Assert(rsaVerifyPkcs1v15(publicKey, digest, signature), true)

        let bad = signature.clone()
        bad[0] = UInt8(bad[0]) ^ UInt8(0x01)
        @Assert(rsaVerifyPkcs1v15(publicKey, digest, bad), false)
    }

    @TestCase
    public func testRsaPssSignVerifyWithVectorKey(): Unit {
        let vectors = parseVectorFile("testdata/stage3/rsa_params_sample.txt")
        var selected = HashMap<String, String>()
        for (item in vectors) {
            if (requireValueOrEmpty(item, "Vector") == "RSA-2048") {
                selected = item
                break
            }
        }
        if (selected.size == 0) {
            @Fail("RSA-2048 vector not found")
        }

        let privateKey = rsaPrivateKeyFromHex(
            requireValue(selected, "N"),
            requireValue(selected, "E"),
            requireValue(selected, "D")
        )
        let publicKey = privateKey.publicKey

        let d256 = hexToBytes("f3f4f5f60102030405060708090a0b0c1112131415161718191a1b1c1d1e1f20")
        let s256 = rsaSignPssWithHash(privateKey, d256, RsaHashAlgorithm.SHA256)
        @Assert(s256.size, 256)
        @Assert(rsaVerifyPssWithHash(publicKey, d256, s256, RsaHashAlgorithm.SHA256), true)
        let sDefault = rsaSignPss(privateKey, d256)
        @Assert(rsaVerifyPss(publicKey, d256, sDefault), true)
        let s256Fixed = rsaSignPssWithHash(privateKey, d256, RsaHashAlgorithm.SHA256, saltLen: 20)
        @Assert(rsaVerifyPssWithHash(publicKey, d256, s256Fixed, RsaHashAlgorithm.SHA256, saltLen: 20), true)
        @Assert(rsaVerifyPssWithHash(publicKey, d256, s256Fixed, RsaHashAlgorithm.SHA256, saltLen: 16), false)

        let d384 = hexToBytes(
            "000102030405060708090a0b0c0d0e0f" +
            "101112131415161718191a1b1c1d1e1f" +
            "202122232425262728292a2b2c2d2e2f"
        )
        let s384 = rsaSignPssWithHash(privateKey, d384, RsaHashAlgorithm.SHA384)
        @Assert(rsaVerifyPssWithHash(publicKey, d384, s384, RsaHashAlgorithm.SHA384), true)

        let d512 = hexToBytes(
            "000102030405060708090a0b0c0d0e0f" +
            "101112131415161718191a1b1c1d1e1f" +
            "202122232425262728292a2b2c2d2e2f" +
            TEST_HEX_ASCII_303132333435363738393A3B3C3D3E3F
        )
        let s512 = rsaSignPssWithHash(privateKey, d512, RsaHashAlgorithm.SHA512)
        @Assert(rsaVerifyPssWithHash(publicKey, d512, s512, RsaHashAlgorithm.SHA512), true)

        let bad = s256.clone()
        bad[10] = UInt8(bad[10]) ^ UInt8(0x80)
        @Assert(rsaVerifyPssWithHash(publicKey, d256, bad, RsaHashAlgorithm.SHA256), false)
    }

    @TestCase
    public func testEccStage3SkeletonAndValidation(): Unit {
        let profile = FipsProfile.phase1Default()
        ecdsaRequireAllowed(profile)
        ecdhRequireAllowed(profile)

        let p256 = namedCurveFromText("secp256r1")
        @Assert(p256.toString(), "P-256")
        @Assert(isFipsCurve(SECP256K1), false)

        requireFipsCurve(P256)

        try {
            requireFipsCurve(SECP256K1)
            @Fail("secp256k1 should be blocked in FIPS curve policy")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "COMPLIANCE_REJECTED")
        }

        let privateKey = EcPrivateKey(P256, BigNum.one())
        let publicKey = EcPublicKey(
            P256,
            BigNum.fromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
            BigNum.fromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
        )

        let digest = hexToBytes(TEST_HEX_32_00112233445566778899AABBCCDDEEFF_00112233445566778899AABBCCDDEEFF)
        let (r, s) = ecdsaSign(privateKey, digest)
        @Assert(ecdsaVerify(publicKey, digest, r, s), true)

        let p384Public = EcPublicKey(
            P384,
            BigNum.fromHex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
            BigNum.fromHex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F")
        )
        let p384Private = EcPrivateKey(P384, BigNum.one())
        let p384Digest = hexToBytes(
            "000102030405060708090a0b0c0d0e0f" +
            "101112131415161718191a1b1c1d1e1f" +
            "202122232425262728292a2b2c2d2e2f"
        )
        let (r384, s384) = ecdsaSign(p384Private, p384Digest)
        @Assert(ecdsaVerify(p384Public, p384Digest, r384, s384), true)
        let sharedP384 = ecdhDeriveSharedSecret(p384Private, p384Public)
        @Assert(sharedP384.size, 48)
        @Assert(sharedP384, p384Public.x.toBytesBE(paddedLen: 48))
    }

    @TestCase
    public func testEcdsaP256VerifyVectors(): Unit {
        let vectors = parseVectorFile("testdata/stage3/ecdsa_verify_p256_sample.txt")
        for (item in vectors) {
            let publicKey = EcPublicKey(
                namedCurveFromText(requireValue(item, "Curve")),
                BigNum.fromHex(requireValue(item, "X")),
                BigNum.fromHex(requireValue(item, "Y"))
            )
            let digest = hexToBytes(requireValue(item, "Digest"))
            let r = BigNum.fromHex(requireValue(item, "R"))
            let s = BigNum.fromHex(requireValue(item, "S"))
            let invalid = hasKey(item, "Invalid")
            let ok = ecdsaVerify(publicKey, digest, r, s)
            if (invalid) {
                @Assert(ok, false)
            } else {
                @Assert(ok, true)
            }
        }
    }

    @TestCase
    public func testEcdhP256Minimal(): Unit {
        let gx = BigNum.fromHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
        let gy = BigNum.fromHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
        let publicKey = EcPublicKey(P256, gx, gy)
        let privateKey = EcPrivateKey(P256, BigNum.one())
        let shared = ecdhDeriveSharedSecret(privateKey, publicKey)
        @Assert(shared, hexToBytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"))
    }

    @TestCase
    public func testRsaVectorValidationEntry(): Unit {
        let vectors = parseVectorFile("testdata/stage3/rsa_params_sample.txt")
        for (item in vectors) {
            let bits = parseInt(requireValue(item, "Bits"))
            let exponent = BigNum.fromHex(requireValue(item, "E"))
            if (requireValueOrEmpty(item, "Invalid").size > 0) {
                try {
                    rsaValidateKeyParameters(bits, exponent)
                    @Fail("invalid RSA vector should fail validation")
                } catch (e: CryptoException) {
                    @Assert(e.code.toString(), "COMPLIANCE_REJECTED")
                }
            } else {
                rsaValidateKeyParameters(bits, exponent)
            }
        }
    }
}

private func parseVectorFile(path: String): Array<KeyValueVector> {
    if (!exists(path)) {
        throw Exception("vector file not found: ${path}")
    }

    let content = String.fromUtf8(File.readFrom(path))
    let lines = content.replace("\r", "\n").split('\n')

    let result = ArrayList<KeyValueVector>()
    var current = HashMap<String, String>()

    for (rawLine in lines) {
        let line = rawLine.trimAscii()
        if (line.size == 0) {
            if (current.size > 0) {
                result.add(copyMap(current))
                current = HashMap<String, String>()
            }
            continue
        }
        if (line.startsWith("#")) {
            continue
        }

        if (let Some(pos) <- line.indexOf("=")) {
            let key = line[..pos].trimAscii()
            let value = line[(pos + 1)..].trimAscii()
            current.add(key, value)
        }
    }

    if (current.size > 0) {
        result.add(copyMap(current))
    }

    result.toArray()
}

private func copyMap(origin: HashMap<String, String>): HashMap<String, String> {
    let target = HashMap<String, String>()
    let iter = origin.iterator()
    while (let Some((k, v)) <- iter.next()) {
        target.add(k, v)
    }
    target
}

private func requireValue(values: HashMap<String, String>, key: String): String {
    values.get(key) ?? throw Exception("missing key: ${key}")
}

private func requireValueOrEmpty(values: HashMap<String, String>, key: String): String {
    values.get(key) ?? ""
}

private func hasKey(values: HashMap<String, String>, key: String): Bool {
    if (let Some(_) <- values.get(key)) {
        return true
    }
    false
}

private func parseInt(raw: String): Int64 {
    let text = raw.trimAscii()
    if (text.size == 0) {
        throw Exception("invalid integer: ${raw}")
    }

    var value: Int64 = 0
    for (ch in text.toArray()) {
        if (ch < b'0' || ch > b'9') {
            throw Exception("invalid integer: ${raw}")
        }
        value = value * 10 + Int64(ch - b'0')
    }
    value
}

private func hexToBytes(hex: String): Array<Byte> {
    let clean = hex.trimAscii().replace(" ", "").replace("\n", "").replace("\t", "")
    if ((clean.size % 2) != 0) {
        throw Exception("invalid hex length")
    }

    let out = Array<Byte>(clean.size / 2, repeat: 0)
    var i = 0
    while (i < clean.size) {
        let hi = hexNibble(clean[i])
        let lo = hexNibble(clean[i + 1])
        out[i / 2] = UInt8((hi << 4) | lo)
        i += 2
    }
    out
}

private func hexNibble(ch: Byte): UInt8 {
    if (ch >= b'0' && ch <= b'9') {
        return UInt8(ch - b'0')
    }

    let lower = if (ch >= b'A' && ch <= b'F') {
        ch + 32
    } else {
        ch
    }

    if (lower >= b'a' && lower <= b'f') {
        return UInt8(lower - b'a' + 10)
    }
    throw Exception("invalid hex char")
}
