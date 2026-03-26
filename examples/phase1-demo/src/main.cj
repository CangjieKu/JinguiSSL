package jinguissl_phase1_demo

import jinguissl.crypto.bignum.BigNum
import jinguissl.compat.bn.*
import jinguissl.crypto.compliance.*
import jinguissl.crypto.error.CryptoException

main(): Int64 {
    println("[jinguiSSL] phase-1 demo")

    let a = BigNum.fromHex("123456789abcdef")
    let b = BigNum.fromHex("ff")

    let add = a.add(b)
    let mul = a.mul(b)
    let modExp = a.modExp(BigNum.fromHex("10"), BigNum.fromHex("10001"))

    println("a + b = ${add.toHex()}")
    println("a * b = ${mul.toHex()}")
    println("a ^ 0x10 mod 0x10001 = ${modExp.toHex()}")

    let compatAdd = BN_add(BN(a), BN(b))
    println("BN_add(a,b) = ${compatAdd.value.toHex()}")

    let profile = FipsProfile.phase1Default()
    println("AES-GCM allowed = ${profile.isAllowed("AES-GCM")}")

    try {
        profile.requireAllowed("AES-ECB")
    } catch (e: CryptoException) {
        println("AES-ECB blocked with code=${e.code.toString()}")
    }

    0
}
