# AES Benchmark Example

This example runs the current `jinguiSSL` AES benchmark harness as a standalone executable.

## Run

```bash
cjpm run
```

## Output

The program prints:

- AES-256-GCM software-path throughput
- benchmark stability summary
- CPU binding attempt status
- array-vs-pointer access probe
- pointer alignment probe
- ARMv8 native-path probes when the hardware backend is active

## Optional Environment Variables

- `JINGUISSL_AES_HW_BACKEND`
  - backend hint such as `armv8-ce`, `aesni`, `shim`, or `none`
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
- On platforms where the native backend is unavailable, the example reports software-mode results only.
