# Contributing to OpenRecover

OpenRecover is a read-only deleted-file recovery library and CLI. The rules below are not style
preferences; they are the project's contract. Start by reading
[docs/READONLY_POLICY.md](READONLY_POLICY.md) and, for deeper context,
[docs/SPEC.md](SPEC.md) and [docs/DECISIONS.md](DECISIONS.md).

## The non-negotiables

1. **Read-only is inviolable.** No write path, write ioctl, repair, or format operation may ever
   appear in the library. `BlockDevice` exposes only `info()`, `read()` and `bad_sectors()`;
   `io::OutputSink` is the only writer. `tools/check_readonly.py` (run in CI, with a negative
   self-test) and a Linux `strace` test enforce this. A PR that trips the scanner does not get an
   exception.
2. **Released versions are frozen.** Never modify `dist/`. New work is additive on top of the
   latest released baseline.
3. **No new dependencies** and no network access in tests. Dependencies are pinned by URL and
   SHA-256 in `cmake/OpenRecoverDeps.cmake`; adding one is a spec-level decision.
4. **Tests use committed fixtures and synthetic images only.** No real drives, no real Android
   devices (fake `adb` is provided).

## Building

Requirements: CMake ≥ 3.24, Ninja, a C++20 compiler (MSVC 19.38+, Clang 16+, GCC 12+), Python 3.

```sh
cmake --preset win-msvc-release          # or win-msvc-debug, linux-clang-debug, linux-gcc-release
cmake --build --preset win-msvc-release
ctest --preset win-msvc-release -L "M[0-5]" --output-on-failure
```

All builds use warnings-as-errors — treat every warning as a build failure.

## Before opening a PR

- `ctest -L "M[0-5]"` passes on your preset (this is the CI gate).
- `python tools/check_readonly.py` and `python tools/check_readonly.py --selftest` pass.
- Public API changes: `tests/unit/test_recover_api.cpp`, `examples/recover_image.cpp`
  (`example_runs`) and the report goldens must agree; the façade is the stable surface, internals
  are allowed to change.
- Behavioural decisions and ambiguities: record them in `docs/DECISIONS.md` as a dated entry, the
  way the project already does.
- New parsers or format validators: add a libFuzzer target in `fuzz/` and seed corpora under
  `tests/fixtures/fuzz/` (invalid seeds use the `invalid_` prefix).

## Reporting issues

Include the OpenRecover version (`openrecover --version`), the preset and OS, the exact command
line, and the `report.json` if one was produced. For recovery-correctness bugs, attach or describe
a minimal synthetic image that reproduces the case — never attach a real disk image containing
personal data. See [SECURITY.md](../SECURITY.md) for vulnerability reporting.
