# Postmortem: Nomad Bridge Hack ($190M, August 1 2022)

## Tags
nomad, bridge, replay-attack, zero-root, initialization, merkle, committedRoot, acceptableRoot, upgrade, cross-chain, message-verification, crowd-loot

## Summary
The Nomad bridge was drained of ~$190M after a routine upgrade accidentally set the zero bytes32 value (`0x00`) as a trusted Merkle root. Since unverified messages also have a root of `0x00` (default Solidity mapping value), ANY message was automatically "proven" valid. The first attacker discovered this and drained funds; hundreds of copycats then replayed the exploit by simply copying the transaction and replacing the recipient address. It was the first "crowd-looted" exploit in DeFi history.

---

## Background: How Nomad Worked

### Optimistic Verification
Nomad used an optimistic message-passing model (similar to optimistic rollups):
1. A message is submitted to the origin chain with a Merkle proof
2. The message enters a "pending" state for a timeout period
3. If no fraud proof is submitted during the timeout, the message is considered valid
4. The `Replica` contract on the destination chain processes the message and releases funds

### Key Components
- **Replica contract**: Validates incoming messages on the destination chain
- **committedRoot**: The last confirmed Merkle root — messages must prove membership in this tree
- **acceptableRoot()**: Function that checks if a given root has been confirmed (past the optimistic timeout)
- **messages mapping**: `mapping(bytes32 => bytes32)` — maps message hashes to their Merkle roots. Unprocessed messages have a root of `0x00` (Solidity default)

---

## The Vulnerability

### The Routine Upgrade (April 21, 2022)
During a standard upgrade, the `committedRoot` was initialized to `0x00`. The initialization code then set `confirmAt[0x00] = 1`, meaning the zero root was marked as confirmed and acceptable.

```
// During initialization:
committedRoot = 0x00;  // Set to zero
confirmAt[committedRoot] = 1;  // confirmAt[0x00] = 1
// Now 0x00 is a VALID, CONFIRMED root
```

### Why This Breaks Everything
The `process()` function checks if a message is valid by:
1. Looking up the message hash in the `messages` mapping: `root = messages[messageHash]`
2. For any message that was NEVER submitted legitimately, this returns `0x00` (Solidity default for uninitialized mapping entries)
3. Calling `acceptableRoot(root)` which checks `confirmAt[root] > 0`
4. Since `confirmAt[0x00] = 1` (set during the bad initialization), this returns `true`
5. The fabricated message passes verification

### The Core Bug
```
// Pseudocode of the verification flow:
function process(bytes memory _message) public {
    bytes32 messageHash = keccak256(_message);
    bytes32 root = messages[messageHash];
    // For a never-seen message: root = 0x00 (default)

    require(acceptableRoot(root), "not acceptable root");
    // acceptableRoot(0x00) returns TRUE because confirmAt[0x00] = 1

    // Message is now considered "proven" — process it
    // ... release tokens to the recipient specified in _message
}
```

---

## The Exploit

### First Attacker
1. Crafted a fake message specifying: "Transfer 100 WBTC to attacker_address"
2. Called `process()` with this fabricated message
3. The message hash didn't exist in `messages` mapping → returned `0x00`
4. `acceptableRoot(0x00)` returned `true` → message was processed
5. Bridge released 100 WBTC to the attacker

### The Crowd-Looting (Unique to This Exploit)
After the first successful transaction, copycats realized they could:
1. Copy the original attacker's transaction calldata
2. Replace only the recipient address with their own
3. Submit the modified transaction → it also passes verification (new message hash, still maps to `0x00`)
4. No smart contract expertise required — literally copy-paste and change the address

Over 960 transactions from hundreds of different wallets drained the bridge over ~150 minutes.

---

## Root Cause Analysis

### Primary: Zero Value as Valid Sentinel
Using `0x00` as an initialized/trusted value in a system where `0x00` is also the default "uninitialized" state. This is a fundamental footgun in EVM smart contracts.

### Contributing Factor: No Replay Protection Per-Message
While Nomad tracked processed message hashes to prevent re-processing the SAME message, the vulnerability allowed fabricating entirely NEW messages. Each fake message had a unique hash, so the replay protection didn't apply.

### Contributing Factor: No Rate Limiting or Circuit Breaker
$190M was drained over 150 minutes with no automated response. There was no mechanism to detect anomalous withdrawal volumes and pause the bridge.

### Contributing Factor: Upgrade Testing Gaps
The initialization with `0x00` as a trusted root was a routine upgrade. The parameter was likely not flagged as security-critical during testing, since "zero initialization" is common practice in Solidity.

---

## Lessons for Auditors

### Pattern: Zero Value as Valid State
**NEVER use `0x00` or empty/default values as valid states in verification logic.** In Solidity, ALL uninitialized mapping entries return `0x00`. If `0x00` is also a valid/trusted value, any uninitialized entry becomes implicitly trusted.

### Rule
```
Any system where:
  1. A mapping returns 0x00 for non-existent keys (always true in Solidity), AND
  2. 0x00 is treated as a valid/trusted/confirmed value
= CRITICAL vulnerability. Every non-existent key is now "trusted."
```

### Pattern: Initialization Parameter Validation
Upgrade initialization functions should validate that critical parameters are non-zero and sensible:
```solidity
function initialize(bytes32 _committedRoot) external initializer {
    require(_committedRoot != bytes32(0), "root cannot be zero");
    committedRoot = _committedRoot;
    confirmAt[_committedRoot] = 1;
}
```

### Pattern: Bridge-Specific Safety
- Rate limiting on withdrawals (daily/hourly caps)
- Circuit breakers that pause on anomalous volume
- Multi-validator confirmation (not just optimistic single-signer)
- Withdrawal delays that give humans time to react

---

## Detection Checklist (For Similar Vulnerabilities)

1. [ ] Does any mapping's default return value (`0x00`, `false`, `0`) have special meaning in the protocol?
2. [ ] Are initialization parameters validated to be non-zero / non-default?
3. [ ] During contract upgrades, are ALL initialized values reviewed for security implications?
4. [ ] Is there rate limiting or circuit breaking on high-value operations?
5. [ ] Can fabricated messages pass verification? (Not just replayed — entirely new fakes)
6. [ ] Are upgrade tests specifically checking: "what happens if I send a message that was never legitimately submitted?"
7. [ ] Is the zero address / zero hash / zero root explicitly excluded from valid states?
8. [ ] For bridges: is there a withdrawal delay or multi-sig requirement for large withdrawals?
