---
description: "Review Go provider changes for scafctl-specific method semantics, schema correctness, WhatIf parity, and tests."
agent: "go-reviewer"
---
# Provider Review

Review the current provider-related Go changes with extra focus on scafctl provider semantics.

## Phase 1: Normal Go review

Complete the standard Go review workflow first.

## Phase 2: Provider contract review

For each changed provider file, verify all of the following:

- `GetProviderDescriptor` accurately describes the implementation.
- Capabilities match the behavior the provider actually supports.
- `OutputSchemas` includes an entry for every declared capability. Missing output schemas cause silent host registration failure.
- Required schema fields match runtime expectations.
- Output field names are stable across versions.
- Examples are realistic and aligned with README and tests.

## Phase 3: Execution review

- Unknown provider names are rejected consistently.
- Nil, empty, and zero-value inputs are handled deliberately.
- Output structure matches `OutputSchemas`.
- Side effects are limited to `ExecuteProvider` (not in descriptor, WhatIf, or config methods).

## Phase 4: WhatIf parity

- `DescribeWhatIf` describes the same operation as `ExecuteProvider`.
- No I/O or mutation happens in WhatIf.
- Important inputs are mentioned in the description.

## Phase 5: Test review

- Tests cover known and unknown provider names.
- Tests cover happy path and error paths.
- Tests verify descriptor validity and OutputSchemas coverage.
- Tests verify WhatIf parity with execution.
- Tests cover any new configuration-dependent logic.

## Output format

Use severity levels: CRITICAL > HIGH > MEDIUM > LOW > INFO.

For each finding include:
- file
- line
- severity
- description
- suggested fix

End with a short summary stating whether the provider contract is coherent across descriptor, execution, WhatIf, and tests.
