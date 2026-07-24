# Model-free verification canaries

These fixtures exercise Forge report adapters without calling Codex, Claude,
OpenAI, Anthropic, deployment services, or production systems.

- `python/` covers passing and failing pytest evidence.
- `typescript/` covers passing and failing Vitest JSON.
- `playwright/` covers a passing main flow and a failing flow.
- `android/` contains multi-module Gradle JUnit XML aggregation.

The fake-CLI unittest suite copies these files to temporary projects, refreshes
their timestamps, and verifies that failures and zero-test evidence block a
release gate. Android instrumentation remains a manual canary because normal CI
does not provision an emulator.
