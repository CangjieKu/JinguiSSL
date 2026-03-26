package jinguissl.tests

import std.collection.ArrayList
import std.fs.*
import jinguissl.crypto.chacha20.*
import jinguissl.crypto.compliance.FipsProfile
import jinguissl.crypto.digest.bytesToHexLower
import jinguissl.crypto.error.CryptoException

type Chacha20Poly1305Vector = (Array<Byte>, Array<Byte>, Array<Byte>, Array<Byte>, Array<Byte>, Array<Byte>)
type Poly1305Vector = (Array<Byte>, Array<Byte>, Array<Byte>)

@Test
public class Chacha20TestSuite {
    @TestCase
    public func testChacha20BlockRfc8439Vector() {
        let key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let nonce = hexToBytes("000000090000004a00000000")
        let expected = "10f1e7e4d13b5915500fdd1fa32071c4" +
            "c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2" +
            "b5129cd1de164eb9cbd083e8a2503c4e"

        let block = chacha20Block(key, 1, nonce)
        @Assert(bytesToHexLower(block), expected)
    }

    @TestCase
    public func testChacha20StreamRfc8439Vector() {
        let key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let nonce = hexToBytes("000000000000004a00000000")
        let plaintext = (
            "Ladies and Gentlemen of the class of '99: " +
            "If I could offer you only one tip for the future, sunscreen would be it."
        ).toArray()
        let expectedCipher = "6e2e359a2568f98041ba0728dd0d6981" +
            "e97e7aec1d4360c20a27afccfd9fae0b" +
            "f91b65c5524733ab8f593dabcd62b357" +
            "1639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e" +
            "52bc514d16ccf806818ce91ab7793736" +
            "5af90bbf74a35be6b40b8eedf2785e42" +
            "874d"

        let ciphertext = chacha20Xor(key, nonce, plaintext, initialCounter: 1)
        @Assert(bytesToHexLower(ciphertext), expectedCipher)
        @Assert(chacha20Xor(key, nonce, ciphertext, initialCounter: 1), plaintext)
    }

    @TestCase
    public func testPoly1305RfcVector() {
        let key = hexToBytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        let input = "Cryptographic Forum Research Group".toArray()
        let tag = poly1305Mac(key, input)
        @Assert(bytesToHexLower(tag), "a8061dc1305136c6c22b8baf0c0127a9")
    }

    @TestCase
    public func testBoringSslPoly1305Vectors() {
        let vectors = parsePoly1305Vectors("testdata/chacha20/poly1305_tests.txt")
        @Assert(vectors.size >= 30, true)

        for ((key, input, mac) in vectors) {
            let got = poly1305Mac(key, input)
            @Assert(got, mac)
        }
    }

    @TestCase
    public func testBoringSslChacha20Poly1305Vectors() {
        let vectors = parseChacha20Poly1305Vectors("testdata/chacha20/chacha20_poly1305_tests.txt")
        @Assert(vectors.size >= 80, true)

        for ((key, nonce, input, aad, expectedCipher, expectedTag) in vectors) {
            if (expectedTag.size != CHACHA20_POLY1305_TAG_LEN) {
                continue
            }
            let context = chacha20Poly1305NewContext(key)
            let (ciphertext, tag) = chacha20Poly1305EncryptWithContext(context, nonce, input, aad: aad)
            @Assert(ciphertext, expectedCipher)
            @Assert(tag, expectedTag)

            let plain = chacha20Poly1305DecryptWithContext(context, nonce, ciphertext, tag, aad: aad)
            @Assert(plain, input)

            let badTag = tag.clone()
            badTag[0] = UInt8(badTag[0]) ^ UInt8(0x01)
            try {
                _ = chacha20Poly1305DecryptWithContext(context, nonce, ciphertext, badTag, aad: aad)
                @Fail("tag mismatch should be rejected")
            } catch (e: CryptoException) {
                @Assert(e.code.toString(), "INVALID_ARGUMENT")
            }
        }
    }

    @TestCase
    public func testChacha20Poly1305ComplianceGate() {
        let key = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let nonce = hexToBytes("000000000000004a00000000")
        let plain = "hello-chacha20-poly1305".toArray()
        let aad = "tls-record-aad".toArray()

        let blocked = FipsProfile.phase1Default()
        try {
            _ = chacha20Poly1305EncryptChecked(blocked, key, nonce, plain, aad: aad)
            @Fail("default phase profile should block CHACHA20-POLY1305")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "COMPLIANCE_REJECTED")
        }

        let allowed = FipsProfile.fromText("TLS1.2\nCHACHA20-POLY1305")
        let context = chacha20Poly1305NewContext(key)
        let (ciphertext, tag) = chacha20Poly1305EncryptWithContextChecked(allowed, context, nonce, plain, aad: aad)
        let opened = chacha20Poly1305DecryptWithContextChecked(allowed, context, nonce, ciphertext, tag, aad: aad)
        @Assert(opened, plain)
    }
}

private func parseChacha20Poly1305Vectors(path: String): Array<Chacha20Poly1305Vector> {
    if (!exists(path)) {
        throw Exception("missing vector file: ${path}")
    }

    let lines = String.fromUtf8(File.readFrom(path)).replace("\r", "\n").split('\n')
    let out = ArrayList<Chacha20Poly1305Vector>()

    var key = ""
    var nonce = ""
    var input = ""
    var aad = ""
    var ciphertext = ""
    var tag = ""

    for (rawLine in lines) {
        let line = rawLine.trimAscii()
        if (line.size == 0) {
            if (hasChachaVectorData(key, nonce, input, aad, ciphertext, tag)) {
                out.add(buildChachaVector(path, key, nonce, input, aad, ciphertext, tag))
                key = ""
                nonce = ""
                input = ""
                aad = ""
                ciphertext = ""
                tag = ""
            }
            continue
        }
        if (line.startsWith("#")) {
            continue
        }

        if (let Some(pos) <- line.indexOf(":")) {
            let field = line[..pos].trimAscii()
            let value = line[(pos + 1)..].trimAscii()
            if (field == "KEY") {
                key = value
            } else if (field == "NONCE") {
                nonce = value
            } else if (field == "IN") {
                input = value
            } else if (field == "AD") {
                aad = value
            } else if (field == "CT") {
                ciphertext = value
            } else if (field == "TAG") {
                tag = value
            }
        }
    }

    if (hasChachaVectorData(key, nonce, input, aad, ciphertext, tag)) {
        out.add(buildChachaVector(path, key, nonce, input, aad, ciphertext, tag))
    }

    out.toArray()
}

private func hasChachaVectorData(
    key: String,
    nonce: String,
    input: String,
    aad: String,
    ciphertext: String,
    tag: String
): Bool {
    key.size > 0 || nonce.size > 0 || input.size > 0 || aad.size > 0 || ciphertext.size > 0 || tag.size > 0
}

private func buildChachaVector(
    path: String,
    key: String,
    nonce: String,
    input: String,
    aad: String,
    ciphertext: String,
    tag: String
): Chacha20Poly1305Vector {
    if (key.size == 0 || nonce.size == 0 || input.size == 0 || aad.size == 0 || ciphertext.size == 0 || tag.size == 0) {
        throw Exception("malformed CHACHA20-POLY1305 vector in ${path}")
    }

    (
        decodeVectorBytes(key),
        decodeVectorBytes(nonce),
        decodeVectorBytes(input),
        decodeVectorBytes(aad),
        decodeVectorBytes(ciphertext),
        decodeVectorBytes(tag)
    )
}

private func parsePoly1305Vectors(path: String): Array<Poly1305Vector> {
    if (!exists(path)) {
        throw Exception("missing vector file: ${path}")
    }

    let lines = String.fromUtf8(File.readFrom(path)).replace("\r", "\n").split('\n')
    let out = ArrayList<Poly1305Vector>()

    var key = ""
    var input = ""
    var mac = ""

    for (rawLine in lines) {
        let line = rawLine.trimAscii()
        if (line.size == 0) {
            if (key.size > 0 || input.size > 0 || mac.size > 0) {
                out.add(buildPoly1305Vector(path, key, input, mac))
                key = ""
                input = ""
                mac = ""
            }
            continue
        }
        if (line.startsWith("#")) {
            continue
        }

        if (let Some(pos) <- line.indexOf("=")) {
            let field = line[..pos].trimAscii()
            let value = line[(pos + 1)..].trimAscii()
            if (field == "Key") {
                key = value
            } else if (field == "Input") {
                input = value
            } else if (field == "MAC") {
                mac = value
            }
        }
    }

    if (key.size > 0 || input.size > 0 || mac.size > 0) {
        out.add(buildPoly1305Vector(path, key, input, mac))
    }

    out.toArray()
}

private func buildPoly1305Vector(path: String, key: String, input: String, mac: String): Poly1305Vector {
    if (key.size == 0 || input.size == 0 || mac.size == 0) {
        throw Exception("malformed Poly1305 vector in ${path}")
    }

    (
        decodeVectorBytes(key),
        decodeVectorBytes(input),
        decodeVectorBytes(mac)
    )
}

private func decodeVectorBytes(raw: String): Array<Byte> {
    let value = raw.trimAscii()
    if (value.size == 0) {
        return []
    }

    if (value.startsWith("\"") && value.endsWith("\"")) {
        if (value.size == 2) {
            return []
        }
        return value[1..(value.size - 1)].toArray()
    }

    hexToBytes(value)
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
