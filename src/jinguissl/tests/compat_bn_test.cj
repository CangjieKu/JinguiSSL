package jinguissl.tests

import jinguissl.compat.bn.*
import jinguissl.crypto.bignum.BigNum
import jinguissl.crypto.error.CryptoException

@Test
public class CompatBnTestSuite {
    @TestCase
    public func testCompatAndNativeConsistency() {
        let a = BN(BigNum.fromHex("1234567890abcdef"))
        let b = BN(BigNum.fromHex("fedcba987654321"))

        let add = BN_add(a, b)
        @Assert(add.value.toHex(), a.value.add(b.value).toHex())

        let sub = BN_sub(a, b)
        @Assert(sub.value.toHex(), a.value.sub(b.value).toHex())

        let mul = BN_mul(a, b)
        @Assert(mul.value.toHex(), a.value.mul(b.value).toHex())

        let (q, r) = BN_div(a, b)
        let (eq, er) = a.value.divMod(b.value)
        @Assert(q.value.toHex(), eq.toHex())
        @Assert(r.value.toHex(), er.toHex())
    }

    @TestCase
    public func testCompatModExpAndInverse() {
        let a = BN(BigNum.fromHex("2"))
        let e = BN(BigNum.fromHex("10"))
        let m = BN(BigNum.fromHex("10001"))

        let modExp = BN_mod_exp(a, e, m)
        @Assert(modExp.value.toHex(), a.value.modExp(e.value, m.value).toHex())

        let invA = BN(BigNum.fromHex("11"))
        let invM = BN(BigNum.fromHex("100"))
        let inv = BN_mod_inverse(invA, invM)
        @Assert(inv.value.toHex(), invA.value.modInverse(invM.value).toHex())
    }

    @TestCase
    public func testCompatErrorSurface() {
        try {
            let a = BN(BigNum.fromHex("1234"))
            _ = BN_div(a, BN(BigNum.zero()))
            @Fail("BN_div should throw on divide by zero")
        } catch (_: CryptoException) {
            @Assert(true)
        }

        try {
            let a = BN(BigNum.fromHex("2"))
            _ = BN_mod_inverse(a, BN(BigNum.fromHex("4")))
            @Fail("BN_mod_inverse should throw if inverse does not exist")
        } catch (_: CryptoException) {
            @Assert(true)
        }
    }

    @TestCase
    public func testBin2BnAndBn2Bin() {
        let raw: Array<Byte> = [0x00, 0x12, 0x34, 0x56]
        let bn = BN_bin2bn(raw)
        let expected: Array<Byte> = [0x12, 0x34, 0x56]
        @Assert(BN_bn2bin(bn), expected)

        let reused = BN_new()
        _ = BN_bin2bn([0x7f], out: reused)
        @Assert(reused.value.toHex(), "7f")
    }
}
