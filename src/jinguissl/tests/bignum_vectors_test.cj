package jinguissl.tests

import std.fs.*
import std.collection.{ArrayList, HashMap}
import jinguissl.crypto.bignum.BigNum

type VectorCase = (String, HashMap<String, String>)

@Test
public class BigNumVectorTestSuite {
    @TestCase
    public func testSumVectors() {
        runVectorFile("testdata/bn/sum_tests.txt", "Sum") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let b = BigNum.fromHex(requireValue(values, "B"))
            assertBigNumEq(a.add(b), requireValue(values, "Sum"), "Sum")
        }
    }

    @TestCase
    public func testProductVectors() {
        runVectorFile("testdata/bn/product_tests.txt", "Product") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let b = BigNum.fromHex(requireValue(values, "B"))
            assertBigNumEq(a.mul(b), requireValue(values, "Product"), "Product")
        }
    }

    @TestCase
    public func testQuotientVectors() {
        runVectorFile("testdata/bn/quotient_tests.txt", "Quotient") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let b = BigNum.fromHex(requireValue(values, "B"))
            let (q, r) = a.divMod(b)
            assertBigNumEq(q, requireValue(values, "Quotient"), "Quotient")
            assertBigNumEq(r, requireValue(values, "Remainder"), "Remainder")
        }
    }

    @TestCase
    public func testShiftVectors() {
        let vectors = parseVectorFile("testdata/bn/shift_tests.txt")
        for ((kind, values) in vectors) {
            let a = BigNum.fromHex(requireValue(values, "A"))
            match (kind) {
                case "LShift1" =>
                    assertBigNumEq(a.lshift(1), requireValue(values, "LShift1"), "LShift1")
                case "LShift" =>
                    let nHex = requireValue(values, "N")
                    let n = BigNum.fromHex(nHex).toBigInt().toInt64()
                    assertBigNumEq(a.lshift(n), requireValue(values, "LShift"), "LShift")
                case "RShift" =>
                    let nHex = requireValue(values, "N")
                    let n = BigNum.fromHex(nHex).toBigInt().toInt64()
                    assertBigNumEq(a.rshift(n), requireValue(values, "RShift"), "RShift")
                case _ =>
                    @Fail("unknown shift vector type: ${kind}")
            }
        }
    }

    @TestCase
    public func testModMulVectors() {
        runVectorFile("testdata/bn/mod_mul_tests.txt", "ModMul") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let b = BigNum.fromHex(requireValue(values, "B"))
            let m = BigNum.fromHex(requireValue(values, "M"))
            let got = a.mul(b).mod(m)
            assertBigNumEq(got, requireValue(values, "ModMul"), "ModMul")
        }
    }

    @TestCase
    public func testModExpVectors() {
        runVectorFile("testdata/bn/mod_exp_tests.txt", "ModExp") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let e = BigNum.fromHex(requireValue(values, "E"))
            let m = BigNum.fromHex(requireValue(values, "M"))
            let got = a.modExp(e, m)
            assertBigNumEq(got, requireValue(values, "ModExp"), "ModExp")
        }
    }

    @TestCase
    public func testModInvVectors() {
        runVectorFile("testdata/bn/mod_inv_tests.txt", "ModInv") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let m = BigNum.fromHex(requireValue(values, "M"))
            let got = a.modInverse(m)
            assertBigNumEq(got, requireValue(values, "ModInv"), "ModInv")
        }
    }

    @TestCase
    public func testExpVectors() {
        runVectorFile("testdata/bn/exp_tests.txt", "Exp") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let e = BigNum.fromHex(requireValue(values, "E"))
            let got = a.exp(e)
            assertBigNumEq(got, requireValue(values, "Exp"), "Exp")
        }
    }

    @TestCase
    public func testGcdVectors() {
        runVectorFile("testdata/bn/gcd_tests.txt", "GCD") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let b = BigNum.fromHex(requireValue(values, "B"))
            let got = BigNum.gcd(a, b)
            assertBigNumEq(got, requireValue(values, "GCD"), "GCD")
        }
    }

    @TestCase
    public func testModSqrtVectors() {
        runVectorFile("testdata/bn/mod_sqrt_tests.txt", "ModSqrt") { values =>
            let a = BigNum.fromHex(requireValue(values, "A"))
            let p = BigNum.fromHex(requireValue(values, "P"))
            let got = BigNum.modSqrt(a, p)
            let expected = BigNum.fromHex(requireValue(values, "ModSqrt"))
            if (got.cmp(expected) == 0) {
                return
            }

            let other = p.sub(expected).mod(p)
            if (got.cmp(other) != 0) {
                @Fail("ModSqrt mismatch, got=${got.toHex()}, expected=${expected.toHex()}, expected_alt=${other.toHex()}")
            }
        }
    }
}

private func runVectorFile(path: String, expectedType: String, body: (HashMap<String, String>) -> Unit): Unit {
    let vectors = parseVectorFile(path)
    for ((kind, values) in vectors) {
        if (kind != expectedType) {
            continue
        }
        body(values)
    }
}

private func parseVectorFile(path: String): Array<VectorCase> {
    if (!exists(path)) {
        throw Exception("vector file not found: ${path}")
    }

    let content = String.fromUtf8(File.readFrom(path))
    let lines = content.replace("\r", "\n").split('\n')
    let result = ArrayList<VectorCase>()

    var currentType = ""
    var current = HashMap<String, String>()

    for (rawLine in lines) {
        let line = rawLine.trimAscii()
        if (line.size == 0) {
            if (currentType.size > 0) {
                result.add((currentType, copyMap(current)))
                currentType = ""
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
            if (currentType.size == 0) {
                currentType = key
            }
            current.add(key, value)
        }
    }

    if (currentType.size > 0) {
        result.add((currentType, copyMap(current)))
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

private func assertBigNumEq(actual: BigNum, expectedHex: String, label: String): Unit {
    let expected = BigNum.fromHex(expectedHex)
    if (actual.cmp(expected) != 0) {
        @Fail("${label} mismatch, got=${actual.toHex()}, expected=${expected.toHex()}")
    }
}
