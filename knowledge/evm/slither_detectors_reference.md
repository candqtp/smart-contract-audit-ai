# Slither Detectors Reference (Trail of Bits)

## Tags
slither, static-analysis, detector, solidity, vulnerability, reentrancy, detector-list


## What is Slither
Slither is Trail of Bits' static analysis framework for Solidity. It analyzes contract bytecode and source, runs ~100 built-in detectors, and supports writing custom detectors in Python. It is the industry standard first-pass tool for Solidity audits.

## Running Slither

```bash
# Basic run — output all findings
slither .

# Filter by severity
slither . --filter-paths "test|mock" --exclude-informational

# Specific detector only
slither . --detect reentrancy-eth

# JSON output for CI
slither . --json slither-report.json

# Print contract inheritance, call graph, CFG
slither . --print inheritance-graph
slither . --print call-graph
slither . --print cfg

# Check for specific function
slither . --detect unprotected-upgrade
```

## Critical / High Severity Detectors

```
reentrancy-eth           — reentrancy that can drain ETH
reentrancy-no-eth        — reentrancy with no ETH transfer (state manipulation)
suicidal                 — unprotected selfdestruct
unprotected-upgrade      — UUPS upgrade without access control
arbitrary-send-eth       — ETH sent to arbitrary address
controlled-delegatecall  — delegatecall with user-controlled target or data
msg-value-loop           — msg.value used in a loop (multi-call pattern)
```

## High Severity Detectors

```
incorrect-equality       — strict equality on balance (== instead of >=)
locked-ether             — contract receives ETH but has no withdrawal function
tx-origin                — tx.origin used for authentication
weak-prng                — randomness from block.timestamp or blockhash
tautology                — condition always true or always false
boolean-equality         — == true or == false (unnecessary)
```

## Medium Severity Detectors

```
divide-before-multiply   — precision loss: division before multiplication
incorrect-return         — return in assembly returns from full function, not just assembly block
integer-overflow         — potential overflow (flags for manual review in 0.8+)
shadowing-local          — local variable shadows state variable
shadowing-state          — state variable shadows another state variable
events-maths             — arithmetic operations without event emission
reentrancy-events        — reentrancy with event emission only (no ETH/state)
calls-loop               — external calls inside a loop
costly-loop              — storage writes inside a loop
```

## Low / Informational Detectors

```
dead-code                — unreachable code
uninitialized-local      — local variable never initialized
unused-return            — return value of external call ignored
missing-zero-check       — address param not checked for address(0)
reentrancy-benign        — reentrancy with no exploitable effect
timestamp                — use of block.timestamp (informational)
assembly                 — use of inline assembly
low-level-calls          — use of low-level call/delegatecall
unchecked-lowlevel       — return of low-level call not checked
unchecked-send           — return of .send() not checked
unchecked-transfer       — return of ERC20 transfer not checked
```

## Commonly Missed by Slither (Manual Review Required)

```
Business logic errors    — wrong formula, inverted conditions
Oracle manipulation      — Slither can't reason about economic manipulation
Access control design    — has modifier, but modifier is wrong
Governance attacks        — flash loan + vote in same block
Economic invariants      — k = x*y relationships
ERC4626 inflation        — requires understanding of vault accounting
Cross-chain replay       — chainid analysis is limited
```

## Custom Detector Example

```python
# custom_detector.py — detect unchecked transfer return values
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function

class UncheckedTransfer(AbstractDetector):
    ARGUMENT = "unchecked-transfer-custom"
    HELP = "Return value of transfer not checked"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for func in contract.functions:
                for node in func.nodes:
                    for call in node.low_level_calls:
                        if call[1] == "transfer" and not self._is_checked(node):
                            results.append(self.generate_result([
                                "Unchecked transfer in ", func, "\n"
                            ]))
        return results
```

## Slither in CI/CD (GitHub Actions)

```yaml
# .github/workflows/slither.yml
name: Slither Analysis
on: [push, pull_request]
jobs:
  slither:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: crytic/slither-action@v0.3.0
        with:
          target: '.'
          slither-args: '--filter-paths "test" --exclude-informational --exclude-low'
          fail-on: high
```

## Interpreting Slither Output

```
# Each finding shows:
# - Detector name and impact/confidence
# - Affected function/contract
# - Reference: SWC number or internal ID
# - Recommended fix

Example output:
Reentrancy in Vault.withdraw(uint256) (contracts/Vault.sol#45-62):
    External calls:
    - (success,None) = msg.sender.call{value: amount}()(Vault.sol#58)
    State variables written after the call:
    - balances[msg.sender] = 0 (Vault.sol#60)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities

# Always verify: is this actually exploitable given the contract's logic?
# Slither has false positives — use findings as leads, not conclusions
```

## Slither Printers Useful for Audit

```bash
# Who calls what — find admin function entry points
slither . --print call-graph

# Data flow — which functions write which storage vars
slither . --print data-dependency

# Inheritance chain — find overridden functions
slither . --print inheritance

# Function summary — modifiers, visibility, read/write
slither . --print function-summary

# ERC compliance check
slither . --print erc-conformance

# Variables that could be constants/immutables (gas savings + security)
slither . --detect constable-variables
slither . --detect immutable-states
```

## False Positive Handling

```bash
# Suppress with inline comment (use sparingly)
// slither-disable-next-line reentrancy-eth
(bool ok,) = msg.sender.call{value: amount}("");

// Or in .slither.config.json
{
  "filter_paths": "lib,test,mock",
  "exclude_informational": true,
  "detectors_to_exclude": ["timestamp", "assembly"]
}
```

## Severity Guide for Audit Reports
When using Slither findings in a report:
- Slither `High` + confirmed exploitable = **Critical or High**
- Slither `High` + not directly exploitable = **Medium**
- Slither `Medium` + confirmed = **Medium or High** depending on impact
- Slither `Low/Info` = **Low or Informational**
- Never report Slither output verbatim — always verify and contextualize
