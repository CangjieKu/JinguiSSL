package jinguissl.tests

import jinguissl.crypto.error.CryptoException
import jinguissl.crypto.perf.*

@Test
public class PerfBenchTestSuite {
    @TestCase
    public func testBenchRunWarmupAndSamples() {
        let counter = BenchCallCounter()
        let summary = benchRun(BenchConfig("unit-bench", warmupRounds: 2, samples: 3), { =>
            counter.value += 1
            2 * 1024 * 1024
        })
        @Assert(counter.value, 5)
        @Assert(summary.name, "unit-bench")
        @Assert(summary.warmupRounds, 2)
        @Assert(summary.samples, 3)
        @Assert(summary.elapsedMedianNs >= 0, true)
        @Assert(summary.throughputMedianMiBS >= 0.0, true)
        @Assert(benchFormatSummary(summary).contains("unit-bench"), true)
    }

    @TestCase
    public func testBenchCpuBindingProbe() {
        let notRequested = benchTryPinCurrentThread(-1)
        @Assert(notRequested.requested, false)
        @Assert(notRequested.applied, false)

        let probe = benchTryPinCurrentThread(0)
        @Assert(probe.requested, true)
        @Assert(probe.coreId, 0)
        @Assert(probe.detail.size > 0, true)
    }

    @TestCase
    public func testBenchConfigValidation() {
        try {
            _ = BenchConfig("", warmupRounds: 1, samples: 1)
            @Fail("empty benchmark name should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            _ = BenchConfig("bad", warmupRounds: -1, samples: 1)
            @Fail("negative warmup should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            _ = BenchConfig("bad", warmupRounds: 1, samples: 0)
            @Fail("non-positive samples should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }
    }

    @TestCase
    public func testBenchRunStableReportsAttemptAndThreshold() {
        let counter = BenchCallCounter()
        let stable = benchRunStable(
            BenchConfig("stable-bench", warmupRounds: 1, samples: 2),
            BenchStabilityConfig(maxSpreadRatio: 100.0, maxRetries: 2, sampleStep: 1),
            { =>
                counter.value += 1
                1024 * 1024
            }
        )
        @Assert(stable.attempts, 1)
        @Assert(stable.stable, true)
        @Assert(stable.summary.name, "stable-bench")
        @Assert(stable.summary.samples, 2)
        @Assert(benchFormatStableSummary(stable).contains("attempts=1"), true)
    }

    @TestCase
    public func testBenchRunStableRetriesWhenThresholdTooStrict() {
        let counter = BenchCallCounter()
        let stable = benchRunStable(
            BenchConfig("retry-bench", warmupRounds: 0, samples: 2),
            BenchStabilityConfig(maxSpreadRatio: 0.5, maxRetries: 2, sampleStep: 1),
            { =>
                counter.value += 1
                var spin: Int64 = 0
                var i = 0
                while (i < 200000) {
                    spin += (i % 7)
                    i += 1
                }
                1024 * 1024 + (spin % 16)
            }
        )
        @Assert(stable.attempts, 3)
        @Assert(stable.stable, false)
    }

    @TestCase
    public func testBenchStabilityConfigValidation() {
        try {
            _ = BenchStabilityConfig(maxSpreadRatio: 0.0, maxRetries: 1, sampleStep: 1)
            @Fail("non-positive spread ratio should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            _ = BenchStabilityConfig(maxSpreadRatio: 1.2, maxRetries: -1, sampleStep: 1)
            @Fail("negative max retries should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }

        try {
            _ = BenchStabilityConfig(maxSpreadRatio: 1.2, maxRetries: 1, sampleStep: 0)
            @Fail("non-positive sample step should be rejected")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }
    }
}

private class BenchCallCounter {
    public var value: Int64 = 0
}
