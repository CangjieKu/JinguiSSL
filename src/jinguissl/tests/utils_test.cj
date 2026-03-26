package jinguissl.tests

import jinguissl.crypto.utils.*
import jinguissl.crypto.error.CryptoException

@Test
public class UtilsTestSuite {
    @TestCase
    public func testEndianConversion() {
        let bytesBE: Array<Byte> = [0x12, 0x34, 0x56, 0x78]
        let bytesLE: Array<Byte> = [0x78, 0x56, 0x34, 0x12]

        @Assert(bytesToUInt32BE(bytesBE), UInt32(0x12345678))
        @Assert(bytesToUInt32LE(bytesLE), UInt32(0x12345678))
        @Assert(uInt32ToBytesBE(0x12345678), bytesBE)
        @Assert(uInt32ToBytesLE(0x12345678), bytesLE)
    }

    @TestCase
    public func testSecureCopyAndZero() {
        let source: Array<Byte> = [1, 2, 3, 4]
        let copied = secureCopy(source)
        @Assert(copied, source)

        source[0] = 9
        @Assert(copied[0], UInt8(1))

        let dst: Array<Byte> = [0, 0, 0, 0, 0, 0]
        secureCopyInto(copied, dst, dstOffset: 2)
        let expectedAfterCopy: Array<Byte> = [0, 0, 1, 2, 3, 4]
        @Assert(dst, expectedAfterCopy)

        secureZero(dst)
        let expectedAfterZero: Array<Byte> = [0, 0, 0, 0, 0, 0]
        @Assert(dst, expectedAfterZero)
    }

    @TestCase
    public func testConstantTimeEquals() {
        @Assert(constantTimeEquals([1, 2, 3], [1, 2, 3]), true)
        @Assert(constantTimeEquals([1, 2, 3], [1, 2, 4]), false)
        @Assert(constantTimeEquals([1, 2, 3], [1, 2]), false)
    }

    @TestCase
    public func testRandomSeedSize() {
        let seed = randomSeed(size: 16)
        @Assert(seed.size, 16)

        try {
            _ = randomSeed(size: 0)
            @Fail("randomSeed(size: 0) should throw")
        } catch (_: CryptoException) {
            @Assert(true)
        }
    }

    @TestCase
    public func testCsprngApis() {
        let available = csprngIsAvailable()
        if (available) {
            let out = csprngBytes(32)
            @Assert(out.size, 32)
        } else {
            try {
                _ = csprngBytes(32)
                @Fail("csprngBytes should fail when backend is unavailable")
            } catch (_: CryptoException) {
                @Assert(true)
            }
        }
    }

    @TestCase
    public func testBoundsChecks() {
        try {
            _ = bytesToUInt32BE([1, 2, 3], offset: 0)
            @Fail("bytesToUInt32BE should throw on short input")
        } catch (_: CryptoException) {
            @Assert(true)
        }

        try {
            let dst: Array<Byte> = [0, 0]
            secureCopyInto([1, 2, 3], dst)
            @Fail("secureCopyInto should throw when destination is too small")
        } catch (_: CryptoException) {
            @Assert(true)
        }
    }
}
