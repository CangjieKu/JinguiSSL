package jinguissl.tests

import jinguissl.crypto.base.{ByteBuffer, SecureBytes}
import jinguissl.crypto.error.CryptoException

@Test
public class BaseTestSuite {
    @TestCase
    public func testSecureBytesCloneClearAndDestroyLifecycle() {
        let source: Array<Byte> = [1, 2, 3, 4]
        let secure = SecureBytes(source)
        source[0] = 9

        let expectedInit: Array<Byte> = [1, 2, 3, 4]
        @Assert(secure.bytes(), expectedInit)
        @Assert(secure.size, 4)
        @Assert(secure.isDestroyed, false)

        secure.clear()
        let expectedCleared: Array<Byte> = [0, 0, 0, 0]
        @Assert(secure.bytes(), expectedCleared)
        @Assert(secure.isDestroyed, false)

        secure.destroy()
        @Assert(secure.isDestroyed, true)
        secure.destroy()

        try {
            _ = secure.bytes()
            @Fail("SecureBytes.bytes should fail after destroy")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            secure.setAt(0, 1)
            @Fail("SecureBytes.setAt should fail after destroy")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }
    }

    @TestCase
    public func testSecureBytesBoundsAndFactoryValidation() {
        let secure = SecureBytes.withSize(3)
        let expectedZeros: Array<Byte> = [0, 0, 0]
        @Assert(secure.bytes(), expectedZeros)

        try {
            _ = SecureBytes.withSize(-1)
            @Fail("SecureBytes.withSize should reject negative size")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            secure.setAt(3, 7)
            @Fail("SecureBytes.setAt should reject out-of-range index")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "OUT_OF_BOUNDS")
        }
    }

    @TestCase
    public func testByteBufferAppendAndClear() {
        let buffer = ByteBuffer([1, 2])
        buffer.append(UInt8(3))
        buffer.append([4, 5])
        @Assert(buffer.size, 5)
        let expected: Array<Byte> = [1, 2, 3, 4, 5]
        @Assert(buffer.toArray(), expected)

        buffer.clear()
        @Assert(buffer.size, 0)
        @Assert(buffer.toArray().size, 0)
    }
}
