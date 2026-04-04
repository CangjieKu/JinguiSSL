# AES Benchmark Example

This example runs the current `jinguiSSL` AES benchmark harness as a standalone executable.

On `macOS + aarch64`, the library now auto-selects the `armv8-ce` backend by default when no override is provided.

## Run

```bash
cjpm run
```

## Output

The program prints:

- effective AES engine / backend selection
- high-level managed round-trip throughput
- benchmark stability summary
- CPU binding attempt status
- array-vs-pointer access probe
- pointer alignment probe
- ARMv8 native-path probes when the hardware backend is active

## Optional Environment Variables

- `JINGUISSL_BENCH_ENGINE`
  - engine policy: `auto`, `hardware`, or `software`
  - `hardware` forces `requestedEngine: HARDWARE`, so unsupported platforms fail fast instead of silently falling back
  - if the requested hardware backend is unavailable, the example exits with a non-zero status
- `JINGUISSL_AES_HW_BACKEND`
  - backend hint such as `armv8-ce`, `aesni`, `shim`, or `none`
  - use `none` to force software mode even on platforms where the accelerated backend is auto-selected
- `JINGUISSL_BENCH_PIN_CORE`
  - request CPU affinity with a core id such as `0`
- `JINGUISSL_BENCH_MAX_SPREAD_RATIO`
  - stability threshold, default `1.25`
- `JINGUISSL_BENCH_MAX_RETRIES`
  - retry count when spread is too wide, default `2`
- `JINGUISSL_BENCH_SAMPLE_STEP`
  - extra samples per retry, default `2`

## Notes

- This example benchmarks the library as shipped; it does not change AES/GHASH hot-path code.
- The first reported case uses the allocating high-level round-trip API, so it is intentionally slower than the later `managed_into`, `managed_pinned`, and `native_pointer_direct` cases.
- On platforms where the native backend is unavailable, the example reports software-mode results only.
- Linux `aarch64/arm64` currently does not have a native AES backend implementation in `jinguiSSL`; forcing hardware mode there is useful because it fails early and makes the missing backend explicit.
