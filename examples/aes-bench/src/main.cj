package jinguissl_aes_bench

import std.env.getVariable
import jinguissl.crypto.aes.*
import jinguissl.crypto.compliance.FipsProfile
import jinguissl.crypto.perf.*

main(): Int64 {
    println("[jinguiSSL] AES-256-GCM benchmark (software)")
    println("report=median/min/max/mean/trimmed_mean/spread_ratio with stability retries")
    println("backend_hint_default=${aesDefaultHardwareBackendHint()}")
    let stability = resolveBenchStabilityConfig()
    println(
        "bench_stability max_spread_ratio=${stability.maxSpreadRatio} " +
        "max_retries=${stability.maxRetries} sample_step=${stability.sampleStep}"
    )
    let pinCore = parseBenchPinCoreHint(getVariable("JINGUISSL_BENCH_PIN_CORE") ?? "")
    let pinResult = benchTryPinCurrentThread(pinCore)
    println(
        "bench_cpu_binding requested=${pinResult.requested} supported=${pinResult.supported} " +
        "applied=${pinResult.applied} core=${pinResult.coreId} detail=${pinResult.detail}"
    )

    let profile = FipsProfile.phase1Default()
    let key = sequenceBytes(32)
    let ctx = aesNewGcmContext(key)
    println(
        "engine=${ctx.engine.active.toString()} backend=${ctx.engine.backend} " +
        "accelerated=${ctx.engine.accelerated} (hardware_available=${aesHardwareAvailable()})"
    )
    let ivSeed = sequenceBytes(12)
    let aad = "jinguiSSL-bench".toArray()

    runCase(profile, ctx, ivSeed, aad, 1024, 160, 5, stability)
    runCase(profile, ctx, ivSeed, aad, 16 * 1024, 24, 4, stability)
    runCase(profile, ctx, ivSeed, aad, 1024 * 1024, 1, 3, stability)
    runAcquirePointerVsArrayProbe(stability)
    runPointerAlignmentProbe()

    if (ctx.engine.backend == "armv8-ce" && ctx.engine.accelerated) {
        println("native_managed_into=enabled")
        runArmv8ManagedIntoCase(profile, ctx, ivSeed, aad, 1024 * 1024, 48, 3, stability)
        runArmv8ManagedIntoCase(profile, ctx, ivSeed, aad, 8 * 1024 * 1024, 8, 2, stability)
        println("native_managed_pinned=enabled")
        runArmv8ManagedPinnedCase(ctx, ivSeed, aad, 1024 * 1024, 48, 3, stability)
        runArmv8ManagedPinnedCase(ctx, ivSeed, aad, 8 * 1024 * 1024, 8, 2, stability)
        println("native_pointer_direct=enabled")
        runArmv8PointerCase(sequenceBytes(32), ivSeed, aad, 1024 * 1024, 48, 3, stability)
        runArmv8PointerCase(sequenceBytes(32), ivSeed, aad, 8 * 1024 * 1024, 8, 2, stability)
    }
    0
}

private func runCase(
    profile: FipsProfile,
    ctx: AesGcmContext,
    ivSeed: Array<Byte>,
    aad: Array<Byte>,
    payloadSize: Int64,
    rounds: Int64,
    samples: Int64,
    stability: BenchStabilityConfig
): Unit {
    let payload = sequenceBytes(payloadSize)
    let iv = ivSeed.clone()
    let counter = BenchMutableInt64()
    let stable = benchRunStable(
        BenchConfig("software-${payloadSize}", warmupRounds: 2, samples: samples),
        stability,
        { =>
        var processedBytes: Int64 = 0
        var i = 0
        while (i < rounds) {
                counter.value += 1
                writeIvCounterArray(iv, counter.value)
            let (ct, tag) = aesGcmEncryptWithContextChecked(profile, ctx, iv, payload, aad: aad)
            _ = aesGcmDecryptWithContextChecked(profile, ctx, iv, ct, tag, aad: aad)
            processedBytes += payloadSize * 2
            i += 1
        }
        processedBytes
        }
    )

    println(
        "size=${payloadSize} rounds=${rounds} samples=${samples} " +
        benchFormatStableSummary(stable)
    )
}

private func runAcquirePointerVsArrayProbe(stability: BenchStabilityConfig): Unit {
    let payloadSize = 2 * 1024 * 1024
    let rounds = 24
    let input = sequenceBytes(payloadSize)
    let output = Array<Byte>(payloadSize, repeat: 0)
    let config = BenchConfig("access-probe", warmupRounds: 2, samples: 5)

    let arrayStable = benchRunStable(
        BenchConfig("array-index", warmupRounds: config.warmupRounds, samples: config.samples),
        stability,
        { =>
        xorArrayLoop(input, output, rounds)
        }
    )
    let pointerStable = benchRunStable(
        BenchConfig("acquired-pointer-read-write", warmupRounds: config.warmupRounds, samples: config.samples),
        stability,
        { =>
        xorPointerLoop(input, output, rounds)
        }
    )

    let ratio = if (pointerStable.summary.throughputMedianMiBS <= 0.0) {
        0.0
    } else {
        arrayStable.summary.throughputMedianMiBS / pointerStable.summary.throughputMedianMiBS
    }

    println("access_probe_payload=${payloadSize} rounds=${rounds}")
    println("access_probe_${benchFormatStableSummary(arrayStable)}")
    println("access_probe_${benchFormatStableSummary(pointerStable)}")
    println("access_probe_ratio_array_over_pointer=${ratio}")
}

private func runPointerAlignmentProbe(): Unit {
    let key = sequenceBytes(32)
    let iv = sequenceBytes(12)
    let aad = "align-probe".toArray()
    let input = sequenceBytes(4096)
    let output = Array<Byte>(4096, repeat: 0)
    let tag = Array<Byte>(16, repeat: 0)

    unsafe {
        var keyRaw = acquireArrayRawData<Byte>(key)
        var ivRaw = acquireArrayRawData<Byte>(iv)
        var aadRaw = acquireArrayRawData<Byte>(aad)
        var inputRaw = acquireArrayRawData<Byte>(input)
        var outputRaw = acquireArrayRawData<Byte>(output)
        var tagRaw = acquireArrayRawData<Byte>(tag)
        try {
            println(
                "align_probe_array " +
                "key_mod16=${pointerMod(keyRaw.pointer, 16)} key_mod64=${pointerMod(keyRaw.pointer, 64)} " +
                "iv_mod16=${pointerMod(ivRaw.pointer, 16)} iv_mod64=${pointerMod(ivRaw.pointer, 64)} " +
                "aad_mod16=${pointerMod(aadRaw.pointer, 16)} aad_mod64=${pointerMod(aadRaw.pointer, 64)} " +
                "input_mod16=${pointerMod(inputRaw.pointer, 16)} input_mod64=${pointerMod(inputRaw.pointer, 64)} " +
                "output_mod16=${pointerMod(outputRaw.pointer, 16)} output_mod64=${pointerMod(outputRaw.pointer, 64)} " +
                "tag_mod16=${pointerMod(tagRaw.pointer, 16)} tag_mod64=${pointerMod(tagRaw.pointer, 64)}"
            )
        } finally {
            releaseArrayRawData<Byte>(tagRaw)
            releaseArrayRawData<Byte>(outputRaw)
            releaseArrayRawData<Byte>(inputRaw)
            releaseArrayRawData<Byte>(aadRaw)
            releaseArrayRawData<Byte>(ivRaw)
            releaseArrayRawData<Byte>(keyRaw)
        }
    }

    let mallocProbe = unsafe { LibC.malloc<UInt8>(count: 4096) }
    if (mallocProbe.isNull()) {
        println("align_probe_malloc allocation_failed=true")
        return
    }
    try {
        println(
            "align_probe_malloc " +
            "ptr_mod16=${pointerMod(mallocProbe, 16)} ptr_mod64=${pointerMod(mallocProbe, 64)}"
        )
    } finally {
        unsafe { LibC.free(mallocProbe) }
    }
}

private func xorArrayLoop(input: Array<Byte>, output: Array<Byte>, rounds: Int64): Int64 {
    var round = 0
    while (round < rounds) {
        var i = 0
        while (i < input.size) {
            output[i] = UInt8(input[i]) ^ UInt8(i & 0xff)
            i += 1
        }
        round += 1
    }
    input.size * rounds
}

private func pointerMod(ptr: CPointer<UInt8>, align: Int64): Int64 {
    if (align <= 0) {
        return 0
    }
    let address = UInt64(ptr.toUIntNative())
    Int64(address % UInt64(align))
}

private func xorPointerLoop(input: Array<Byte>, output: Array<Byte>, rounds: Int64): Int64 {
    unsafe {
        var inputRaw = acquireArrayRawData<Byte>(input)
        var outputRaw = acquireArrayRawData<Byte>(output)
        try {
            let inputPtr = inputRaw.pointer
            let outputPtr = outputRaw.pointer
            var round = 0
            while (round < rounds) {
                var i = 0
                while (i < input.size) {
                    outputPtr.write(i, UInt8(inputPtr.read(i)) ^ UInt8(i & 0xff))
                    i += 1
                }
                round += 1
            }
        } finally {
            releaseArrayRawData<Byte>(outputRaw)
            releaseArrayRawData<Byte>(inputRaw)
        }
    }
    input.size * rounds
}

private func runArmv8ManagedIntoCase(
    profile: FipsProfile,
    ctx: AesGcmContext,
    ivSeed: Array<Byte>,
    aad: Array<Byte>,
    payloadSize: Int64,
    rounds: Int64,
    samples: Int64,
    stability: BenchStabilityConfig
): Unit {
    let payload = sequenceBytes(payloadSize)
    let ct = Array<Byte>(payloadSize, repeat: 0)
    let pt = Array<Byte>(payloadSize, repeat: 0)
    let tag = Array<Byte>(16, repeat: 0)
    let iv = ivSeed.clone()

    let counter = BenchMutableInt64()
    let stable = benchRunStable(
        BenchConfig("managed-into-${payloadSize}", warmupRounds: 3, samples: samples),
        stability,
        { =>
            var processedBytes: Int64 = 0
            var i = 0
            while (i < rounds) {
                counter.value += 1
                writeIvCounterArray(iv, counter.value)
                aesGcmEncryptIntoWithContextChecked(profile, ctx, iv, payload, ct, tag, aad: aad)
                aesGcmDecryptIntoWithContextChecked(profile, ctx, iv, ct, tag, pt, aad: aad)
                processedBytes += payloadSize * 2
                i += 1
            }
            processedBytes
        }
    )
    println(
        "managed_into_size=${payloadSize} rounds=${rounds} samples=${samples} " +
        benchFormatStableSummary(stable)
    )
}

private func runArmv8ManagedPinnedCase(
    ctx: AesGcmContext,
    ivSeed: Array<Byte>,
    aad: Array<Byte>,
    payloadSize: Int64,
    rounds: Int64,
    samples: Int64,
    stability: BenchStabilityConfig
): Unit {
    let payload = sequenceBytes(payloadSize)
    let iv = ivSeed.clone()
    let ct = Array<Byte>(payloadSize, repeat: 0)
    let dt = Array<Byte>(payloadSize, repeat: 0)
    let tag = Array<Byte>(16, repeat: 0)

    unsafe {
        let keyRaw = acquireArrayRawData<Byte>(ctx.schedule.key)
        let ivRaw = acquireArrayRawData<Byte>(iv)
        let aadRaw = acquireArrayRawData<Byte>(aad)
        let inputRaw = acquireArrayRawData<Byte>(payload)
        let outputRaw = acquireArrayRawData<Byte>(ct)
        let decryptRaw = acquireArrayRawData<Byte>(dt)
        let tagRaw = acquireArrayRawData<Byte>(tag)
        try {
            let counter = BenchMutableInt64()
            let stable = benchRunStable(
                BenchConfig("managed-pinned-${payloadSize}", warmupRounds: 3, samples: samples),
                stability,
                { =>
                var processedBytes: Int64 = 0
                var i = 0
                while (i < rounds) {
                        counter.value += 1
                        writeIvCounter(ivRaw.pointer, counter.value)
                    let encryptStatus = aesArmv8CeGcmEncryptPointers(
                        keyRaw.pointer,
                        ctx.schedule.key.size,
                        ivRaw.pointer,
                        iv.size,
                        aadRaw.pointer,
                        aad.size,
                        inputRaw.pointer,
                        payloadSize,
                        outputRaw.pointer,
                        tagRaw.pointer,
                        16
                    )
                    if (encryptStatus != 0) {
                        throw Exception("managed pinned AES-GCM encrypt failed with status ${encryptStatus}")
                    }
                    let decryptStatus = aesArmv8CeGcmDecryptPointers(
                        keyRaw.pointer,
                        ctx.schedule.key.size,
                        ivRaw.pointer,
                        iv.size,
                        aadRaw.pointer,
                        aad.size,
                        outputRaw.pointer,
                        payloadSize,
                        tagRaw.pointer,
                        16,
                        decryptRaw.pointer
                    )
                    if (decryptStatus != 0) {
                        throw Exception("managed pinned AES-GCM decrypt failed with status ${decryptStatus}")
                    }
                    processedBytes += payloadSize * 2
                    i += 1
                }
                processedBytes
                }
            )
            println(
                "managed_pinned_size=${payloadSize} rounds=${rounds} samples=${samples} " +
                benchFormatStableSummary(stable)
            )
        } finally {
            releaseArrayRawData<Byte>(tagRaw)
            releaseArrayRawData<Byte>(decryptRaw)
            releaseArrayRawData<Byte>(outputRaw)
            releaseArrayRawData<Byte>(inputRaw)
            releaseArrayRawData<Byte>(aadRaw)
            releaseArrayRawData<Byte>(ivRaw)
            releaseArrayRawData<Byte>(keyRaw)
        }
    }
}

private func runArmv8PointerCase(
    key: Array<Byte>,
    ivSeed: Array<Byte>,
    aad: Array<Byte>,
    payloadSize: Int64,
    rounds: Int64,
    samples: Int64,
    stability: BenchStabilityConfig
): Unit {
    let keyPtr = unsafe { LibC.malloc<UInt8>(count: key.size) }
    let ivPtr = unsafe { LibC.malloc<UInt8>(count: ivSeed.size) }
    let aadPtr = unsafe { LibC.malloc<UInt8>(count: aad.size) }
    let ptPtr = unsafe { LibC.malloc<UInt8>(count: payloadSize) }
    let ctPtr = unsafe { LibC.malloc<UInt8>(count: payloadSize) }
    let dtPtr = unsafe { LibC.malloc<UInt8>(count: payloadSize) }
    let tagPtr = unsafe { LibC.malloc<UInt8>(count: 16) }

    if (
        keyPtr.isNull() ||
        ivPtr.isNull() ||
        aadPtr.isNull() ||
        ptPtr.isNull() ||
        ctPtr.isNull() ||
        dtPtr.isNull() ||
        tagPtr.isNull()
    ) {
        if (keyPtr.isNotNull()) {
            unsafe { LibC.free(keyPtr) }
        }
        if (ivPtr.isNotNull()) {
            unsafe { LibC.free(ivPtr) }
        }
        if (aadPtr.isNotNull()) {
            unsafe { LibC.free(aadPtr) }
        }
        if (ptPtr.isNotNull()) {
            unsafe { LibC.free(ptPtr) }
        }
        if (ctPtr.isNotNull()) {
            unsafe { LibC.free(ctPtr) }
        }
        if (dtPtr.isNotNull()) {
            unsafe { LibC.free(dtPtr) }
        }
        if (tagPtr.isNotNull()) {
            unsafe { LibC.free(tagPtr) }
        }
        throw Exception("native pointer benchmark allocation failed")
    }

    try {
        writeArrayToPointer(key, keyPtr)
        writeArrayToPointer(ivSeed, ivPtr)
        writeArrayToPointer(aad, aadPtr)
        fillSequencePointer(ptPtr, payloadSize)

        let counter = BenchMutableInt64()
        let stable = benchRunStable(
            BenchConfig("native-pointer-${payloadSize}", warmupRounds: 3, samples: samples),
            stability,
            { =>
                var processedBytes: Int64 = 0
                var i = 0
                while (i < rounds) {
                    counter.value += 1
                    writeIvCounter(ivPtr, counter.value)
                    let encryptStatus = unsafe {
                        aesArmv8CeGcmEncryptPointers(
                            keyPtr,
                            key.size,
                            ivPtr,
                            ivSeed.size,
                            aadPtr,
                            aad.size,
                            ptPtr,
                            payloadSize,
                            ctPtr,
                            tagPtr,
                            16
                        )
                    }
                    if (encryptStatus != 0) {
                        throw Exception("native pointer AES-GCM encrypt failed with status ${encryptStatus}")
                    }
                    let decryptStatus = unsafe {
                        aesArmv8CeGcmDecryptPointers(
                            keyPtr,
                            key.size,
                            ivPtr,
                            ivSeed.size,
                            aadPtr,
                            aad.size,
                            ctPtr,
                            payloadSize,
                            tagPtr,
                            16,
                            dtPtr
                        )
                    }
                    if (decryptStatus != 0) {
                        throw Exception("native pointer AES-GCM decrypt failed with status ${decryptStatus}")
                    }
                    processedBytes += payloadSize * 2
                    i += 1
                }
                processedBytes
            }
        )
        println(
            "native_ptr_size=${payloadSize} rounds=${rounds} samples=${samples} " +
            benchFormatStableSummary(stable)
        )
    } finally {
        unsafe { LibC.free(tagPtr) }
        unsafe { LibC.free(dtPtr) }
        unsafe { LibC.free(ctPtr) }
        unsafe { LibC.free(ptPtr) }
        unsafe { LibC.free(aadPtr) }
        unsafe { LibC.free(ivPtr) }
        unsafe { LibC.free(keyPtr) }
    }
}

private func sequenceBytes(size: Int64): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    var i = 0
    while (i < size) {
        out[i] = UInt8(i & 0xff)
        i += 1
    }
    out
}

@OverflowWrapping
private func writeIvCounterArray(iv: Array<Byte>, counter: Int64): Unit {
    let base = UInt32(counter)
    iv[8] = UInt8((base >> 24) & UInt32(0xff))
    iv[9] = UInt8((base >> 16) & UInt32(0xff))
    iv[10] = UInt8((base >> 8) & UInt32(0xff))
    iv[11] = UInt8(base & UInt32(0xff))
}

private func writeArrayToPointer(bytes: Array<Byte>, ptr: CPointer<UInt8>): Unit {
    var i = 0
    while (i < bytes.size) {
        unsafe { ptr.write(i, bytes[i]) }
        i += 1
    }
}

private func fillSequencePointer(ptr: CPointer<UInt8>, size: Int64): Unit {
    var i = 0
    while (i < size) {
        unsafe { ptr.write(i, UInt8(i & 0xff)) }
        i += 1
    }
}

@OverflowWrapping
private func writeIvCounter(ivPtr: CPointer<UInt8>, counter: Int64): Unit {
    let base = UInt32(counter)
    unsafe { ivPtr.write(8, UInt8((base >> 24) & UInt32(0xff))) }
    unsafe { ivPtr.write(9, UInt8((base >> 16) & UInt32(0xff))) }
    unsafe { ivPtr.write(10, UInt8((base >> 8) & UInt32(0xff))) }
    unsafe { ivPtr.write(11, UInt8(base & UInt32(0xff))) }
}

private func parseBenchPinCoreHint(raw: String): Int64 {
    let text = raw.trimAscii()
    if (text.size == 0) {
        return -1
    }
    let (value, ok) = parseInt64Decimal(text)
    if (!ok) {
        return -1
    }
    value
}

private func resolveBenchStabilityConfig(): BenchStabilityConfig {
    let spreadRaw = (getVariable("JINGUISSL_BENCH_MAX_SPREAD_RATIO") ?? "").trimAscii()
    let retriesRaw = (getVariable("JINGUISSL_BENCH_MAX_RETRIES") ?? "").trimAscii()
    let stepRaw = (getVariable("JINGUISSL_BENCH_SAMPLE_STEP") ?? "").trimAscii()

    var spread = 1.25
    if (spreadRaw.size > 0) {
        let (parsed, ok) = parseFloat64Decimal(spreadRaw)
        if (ok && parsed > 0.0) {
            spread = parsed
        }
    }

    var retries: Int64 = 2
    if (retriesRaw.size > 0) {
        let (parsed, ok) = parseInt64Decimal(retriesRaw)
        if (ok && parsed >= 0) {
            retries = parsed
        }
    }

    var step: Int64 = 2
    if (stepRaw.size > 0) {
        let (parsed, ok) = parseInt64Decimal(stepRaw)
        if (ok && parsed > 0) {
            step = parsed
        }
    }
    BenchStabilityConfig(maxSpreadRatio: spread, maxRetries: retries, sampleStep: step)
}

private func parseFloat64Decimal(text: String): (Float64, Bool) {
    if (text.size == 0) {
        return (0.0, false)
    }

    var i = 0
    var value = 0.0
    var sawDigit = false
    while (i < text.size) {
        let ch = text[i]
        if (ch < b'0' || ch > b'9') {
            break
        }
        value = value * 10.0 + Float64(ch - b'0')
        sawDigit = true
        i += 1
    }

    if (i < text.size && text[i] == b'.') {
        i += 1
        var scale = 0.1
        while (i < text.size) {
            let ch = text[i]
            if (ch < b'0' || ch > b'9') {
                return (0.0, false)
            }
            value += Float64(ch - b'0') * scale
            sawDigit = true
            scale *= 0.1
            i += 1
        }
    } else if (i < text.size) {
        return (0.0, false)
    }

    if (!sawDigit) {
        return (0.0, false)
    }
    (value, true)
}

private func parseInt64Decimal(text: String): (Int64, Bool) {
    if (text.size == 0) {
        return (0, false)
    }
    var start = 0
    var negative = false
    if (text[0] == b'-') {
        negative = true
        start = 1
        if (text.size == 1) {
            return (0, false)
        }
    }
    var value: Int64 = 0
    var i = start
    while (i < text.size) {
        let ch = text[i]
        if (ch < b'0' || ch > b'9') {
            return (0, false)
        }
        value = value * 10 + Int64(ch - b'0')
        i += 1
    }
    if (negative) {
        return (-value, true)
    }
    (value, true)
}

private class BenchMutableInt64 {
    public var value: Int64

    public init(value!: Int64 = 0) {
        this.value = value
    }
}
