package jinguissl.tests

import jinguissl.crypto.digest.*
import jinguissl.crypto.error.CryptoException

@Test
public class DigestTestSuite {
    @TestCase
    public func testMd5Vectors(): Unit {
        assertDigestHex(md5("".toArray()), "d41d8cd98f00b204e9800998ecf8427e")
        assertDigestHex(md5("abc".toArray()), "900150983cd24fb0d6963f7d28e17f72")
        assertDigestHex(md5("message digest".toArray()), "f96b697d7cb7938d525a2f31aaf161d0")
        assertDigestHex(md5("abcdefghijklmnopqrstuvwxyz".toArray()), "c3fcd3d76192e4007dfb496cca67e13b")

        let fromDispatch = hash(MD5, "abc".toArray())
        assertDigestHex(fromDispatch, "900150983cd24fb0d6963f7d28e17f72")
    }

    @TestCase
    public func testSha2Vectors(): Unit {
        assertDigestHex(
            sha1("".toArray()),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )
        assertDigestHex(
            sha1("abc".toArray()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        )

        assertDigestHex(
            sha256("".toArray()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assertDigestHex(
            sha256("abc".toArray()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assertDigestHex(
            sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toArray()),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )

        assertDigestHex(
            sha384("".toArray()),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da" +
            "274edebfe76f65fbd51ad2f14898b95b"
        )
        assertDigestHex(
            sha384("abc".toArray()),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163" +
            "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )

        assertDigestHex(
            sha512("".toArray()),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc" +
            "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f" +
            "63b931bd47417a81a538327af927da3e"
        )
        assertDigestHex(
            sha512("abc".toArray()),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2" +
            "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd" +
            "454d4423643ce80e2a9ac94fa54ca49f"
        )

        let fromDispatch = hash(HashAlgorithm.SHA256, "abc".toArray())
        assertDigestHex(fromDispatch, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        assertDigestHex(hash(HashAlgorithm.SHA1, "abc".toArray()), "a9993e364706816aba3e25717850c26c9cd0d89d")
    }

    @TestCase
    public func testHmacVectors(): Unit {
        let key1 = Array<Byte>(20, repeat: UInt8(0x0b))
        let data1 = "Hi There".toArray()

        assertDigestHex(
            hmac(HashAlgorithm.SHA1, key1, data1),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        )
        assertDigestHex(
            hmac(HashAlgorithm.SHA256, key1, data1),
            "b0344c61d8db38535ca8afceaf0bf12b" +
            "881dc200c9833da726e9376c2e32cff7"
        )
        assertDigestHex(
            hmac(HashAlgorithm.SHA384, key1, data1),
            "afd03944d84895626b0825f4ab46907f" +
            "15f9dadbe4101ec682aa034c7cebc59c" +
            "faea9ea9076ede7f4af152e8b2fa9cb6"
        )
        assertDigestHex(
            hmac(HashAlgorithm.SHA512, key1, data1),
            "87aa7cdea5ef619d4ff0b4241a1d6cb0" +
            "2379f4e2ce4ec2787ad0b30545e17cde" +
            "daa833b7d6b8a702038b274eaea3f4e4" +
            "be9d914eeb61f1702e696c203a126854"
        )

        let key2 = "Jefe".toArray()
        let data2 = "what do ya want for nothing?".toArray()

        assertDigestHex(
            hmac(HashAlgorithm.SHA256, key2, data2),
            "5bdcc146bf60754e6a042426089575c7" +
            "5a003f089d2739839dec58b964ec3843"
        )
        assertDigestHex(
            hmac(HashAlgorithm.SHA384, key2, data2),
            "af45d2e376484031617f78d2b58a6b1b" +
            "9c7ef464f5a01b47e42ec3736322445e" +
            "8e2240ca5e69e2c78b3239ecfab21649"
        )
        assertDigestHex(
            hmac(HashAlgorithm.SHA512, key2, data2),
            "164b7a7bfcf819e2e395fbe73b56e0a3" +
            "87bd64222e831fd610270cd7ea250554" +
            "9758bf75c05a994a6d034f65f8f0e6fd" +
            "caeab1a34d4a6b4b636e070a38bce737"
        )

        let md5Key = Array<Byte>(16, repeat: UInt8(0x0b))
        assertDigestHex(
            hmac(MD5, md5Key, data1),
            "9294727a3638bb1c13f48ef8158bfc9d"
        )
    }

    @TestCase
    public func testHkdfVectorsAndBounds(): Unit {
        let ikm = Array<Byte>(22, repeat: UInt8(0x0b))
        let salt = hexToBytes("000102030405060708090a0b0c")
        let info = hexToBytes("f0f1f2f3f4f5f6f7f8f9")

        let prk = hkdfExtract(HashAlgorithm.SHA256, salt, ikm)
        assertDigestHex(
            prk,
            "077709362c2e32df0ddc3f0dc47bba63" +
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        )

        let okmFromExpand = hkdfExpand(HashAlgorithm.SHA256, prk, info, 42)
        assertDigestHex(
            okmFromExpand,
            "3cb25f25faacd57a90434f64d0362f2a" +
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865"
        )

        let okmFromOneShot = hkdf(HashAlgorithm.SHA256, ikm, info, 42, salt: salt)
        @Assert(okmFromOneShot, okmFromExpand)

        try {
            _ = hkdfExpand(HashAlgorithm.SHA256, prk, info, 8161)
            @Fail("HKDF expand length overflow should fail")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "OUT_OF_BOUNDS")
        }
    }
}

private func assertDigestHex(actual: Array<Byte>, expectedHex: String): Unit {
    let expected = expectedHex.toAsciiLower().replace(" ", "")
    @Assert(bytesToHexLower(actual), expected)
}

private func hexToBytes(hex: String): Array<Byte> {
    let normalized = hex.trimAscii().toAsciiLower().replace(" ", "")
    if (normalized.size % 2 != 0) {
        @Fail("hex string length must be even")
    }
    let out = Array<Byte>(normalized.size / 2, repeat: 0)
    var i: Int64 = 0
    while (i < normalized.size) {
        let hi = hexNibble(normalized[i])
        let lo = hexNibble(normalized[i + 1])
        out[i / 2] = UInt8((hi << 4) | lo)
        i += 2
    }
    out
}

private func hexNibble(ch: UInt8): Int64 {
    if (ch >= UInt8(0x30) && ch <= UInt8(0x39)) {
        return Int64(ch - UInt8(0x30))
    }
    if (ch >= UInt8(0x61) && ch <= UInt8(0x66)) {
        return Int64(ch - UInt8(0x61) + 10)
    }
    @Fail("invalid hex character")
    0
}
