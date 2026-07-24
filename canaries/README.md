# Model-free verification canaries

These fixtures exercise Forge report adapters without calling Codex, Claude,
OpenAI, Anthropic, deployment services, or production systems.

- `python/` covers passing and failing pytest evidence.
- `typescript/` covers passing, failing, zero-test, and stale Vitest JSON.
- `playwright/` covers passed, skipped, flaky, and failed main-flow evidence.
- `android/` contains multi-module Gradle JUnit XML aggregation.

The fake-CLI unittest suite copies these files to temporary projects, refreshes
their timestamps, and verifies that failures and zero-test evidence block a
release gate. Android instrumentation remains a manual canary because normal CI
does not provision an emulator.
