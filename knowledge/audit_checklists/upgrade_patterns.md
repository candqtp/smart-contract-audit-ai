# Upgrade Pattern Security: UUPS, Transparent, and Beacon Proxies

## Tags
uups, transparent-proxy, beacon, upgrade, storage-collision, EIP-1967, EIP-1822, delegatecall, _authorizeUpgrade, initializer, selfdestruct, function-clashing, storage-gap

## Overview
Upgradeable proxy contracts separate storage (proxy) from logic (implementation). The proxy DELEGATECALLs to the implementation, executing its code against the proxy's storage. Upgrades change which implementation the proxy points to. The three main patterns — Transparent, UUPS, and Beacon — each have distinct security profiles and failure modes.

---

## Pattern Comparison

### Transparent Proxy (EIP-1967)
- Upgrade logic lives in the PROXY contract, managed by a separate ProxyAdmin
- Admin calls are routed to the proxy; non-admin calls are delegated to the implementation
- **Risk**: Function selector clashing between proxy admin functions and implementation functions
- **Cost**: Higher gas per call (SLOAD to check if caller is admin)

### UUPS (EIP-1822)
- Upgrade logic lives in the IMPLEMENTATION contract
- The implementation must include `upgradeTo()` function
- **Risk**: If upgraded to an implementation that LACKS `upgradeTo()`, the proxy is permanently bricked — no more upgrades possible
- **Cost**: Lower gas per call (no admin check in proxy), slightly higher implementation deploy cost

### Beacon Proxy
- Multiple proxies read implementation address from a shared Beacon contract
- Upgrading the Beacon upgrades ALL proxies simultaneously
- **Risk**: Single point of failure — compromised Beacon = all proxies compromised
- **Cost**: Extra SLOAD to read Beacon + SLOAD to read implementation from Beacon

---

## Vulnerability 1: Uninitialized Implementation (THE Most Common Proxy Bug)

### Severity: Critical

### The Problem
Implementation contracts don't use constructors (constructor logic runs in implementation's own storage, not the proxy's). They use `initialize()` instead. BUT the implementation contract itself must also be locked against initialization — otherwise an attacker can:

1. Call `initialize()` on the implementation contract directly (not through the proxy)
2. Become the owner of the implementation
3. For UUPS: call `upgradeToAndCall()` pointing to a malicious contract with `selfdestruct`
4. The `selfdestruct` executes in the implementation's context, destroying it
5. All proxies pointing to this implementation are now bricked

### Historical Examples
- **Wormhole**: After a routine update, the implementation was left uninitialized. A white-hat hacker called `initialize()`, became guardian, and could have destroyed the bridge contract controlling hundreds of millions in assets.
- **OpenZeppelin UUPS v4.1.0-4.3.1**: Critical vulnerability where uninitialized implementations could be taken over and self-destructed via `upgradeToAndCall`.
- **Harvest Finance, Teller, KeeperDAO**: All had uninitialized implementations.

### The Fix
```solidity
// Implementation contract MUST have this:
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}

// This prevents ANYONE from calling initialize() on the implementation itself
// The proxy's initialize() still works because it DELEGATECALLs
```

### Detection
- Check if the implementation contract has a constructor that calls `_disableInitializers()`
- Check the `_initialized` storage slot on the implementation contract: if it's 0, the implementation is vulnerable
- Tools: `slither-check-upgradeability` detects this

---

## Vulnerability 2: Storage Layout Collision

### Severity: Critical

### The Problem
Since DELEGATECALL uses the proxy's storage with the implementation's code, storage variables must be in the same slots across upgrades. If a V2 implementation reorders variables, inserts new ones, or changes inheritance order, storage slots shift and data gets corrupted.

### Example
```solidity
// V1 Implementation
contract V1 {
    address public owner;    // slot 0
    uint256 public balance;  // slot 1
    uint256 public rate;     // slot 2
}

// V2 Implementation — WRONG: inserted new variable
contract V2 {
    address public owner;     // slot 0
    address public newAdmin;  // slot 1 — COLLISION! Was 'balance' in V1
    uint256 public balance;   // slot 2 — Now reads V1's 'rate' value!
    uint256 public rate;      // slot 3
}

// V2 Implementation — CORRECT: append only
contract V2 {
    address public owner;     // slot 0 (same)
    uint256 public balance;   // slot 1 (same)
    uint256 public rate;      // slot 2 (same)
    address public newAdmin;  // slot 3 (NEW — appended at end)
}
```

### The __gap Pattern
```solidity
// Base contract reserves slots for future use
contract BaseV1 {
    address public owner;
    uint256[49] private __gap;  // Reserves 49 slots
}

// When adding a variable in V2, shrink the gap:
contract BaseV2 {
    address public owner;
    address public newAdmin;   // Uses one of the reserved slots
    uint256[48] private __gap; // 49 - 1 = 48 remaining
}
```

### Real-World Example (Audius)
Audius introduced new storage in the proxy that collided with implementation storage, allowing an attacker to overwrite the governance address.

### Detection
- Use OpenZeppelin's upgrade plugin: `npx @openzeppelin/upgrades-core validate`
- Use Slither: `slither-check-upgradeability`
- Manual check: compare storage layouts between V1 and V2 implementations

---

## Vulnerability 3: Missing _authorizeUpgrade Access Control (UUPS)

### Severity: Critical

### The Problem
In UUPS proxies, the `_authorizeUpgrade()` function controls who can upgrade. If it's empty or improperly restricted, anyone can upgrade the proxy to a malicious implementation.

```solidity
// VULNERABLE: No access control
function _authorizeUpgrade(address newImplementation) internal override {
    // Empty — anyone can upgrade!
}

// SECURE: Only owner
function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
    // Only owner can call upgradeTo()
}
```

### What To Look For
- `_authorizeUpgrade()` with no modifier or require statement
- Access control that can be bypassed (e.g., checked against a storage variable that the attacker can modify)
- Timelock on upgrade — ideally upgrades should have a delay so users can exit

---

## Vulnerability 4: Function Selector Clashing (Transparent Proxy)

### Severity: Medium-High

### The Problem
Solidity function selectors are 4 bytes derived from the function signature hash. With 4 bytes, collisions are statistically likely as contracts grow. If a function in the implementation has the same selector as a proxy admin function, calls get misrouted.

### Example
- Proxy has `admin()` — selector `0xf851a440`
- Implementation has `burn(uint256)` — selector could collide if unlucky
- User calling `burn(100)` actually hits the proxy's `admin()` function instead

### Transparent Proxy Mitigation
The Transparent Proxy routes ALL calls from the admin address to the proxy itself, and ALL calls from non-admin addresses to the implementation. This eliminates selector clashing at the cost of an extra `msg.sender == admin` check on every call.

### Detection
```bash
# Check for selector collisions
solc --hashes MyContract.sol  # Lists all function selectors
# Compare proxy selectors vs implementation selectors for collisions
```

---

## Vulnerability 5: UUPS "Bricking" — Upgrading to Non-UUPS Implementation

### Severity: Critical

### The Problem
If a UUPS proxy is upgraded to an implementation that does NOT contain the `upgradeTo()` function, the proxy can never be upgraded again. It's permanently stuck on that implementation. If the new implementation has bugs, they cannot be fixed.

### Protection
OpenZeppelin v4.5+ added an ERC-1822 compliance check: the new implementation must declare a `proxiableUUID()` that returns the correct EIP-1967 implementation slot. Non-UUPS contracts will fail this check.

```solidity
// OpenZeppelin's UUPS check:
function _upgradeToAndCallUUPS(address newImplementation, bytes memory data, bool forceCall) internal {
    try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
        require(slot == _IMPLEMENTATION_SLOT, "ERC1967Upgrade: unsupported proxiableUUID");
    } catch {
        revert("ERC1967Upgrade: new implementation is not UUPS");
    }
    _upgradeToAndCall(newImplementation, data, forceCall);
}
```

### What To Look For
- UUPS proxy using a pre-4.5 OpenZeppelin version without this check
- Custom UUPS implementation that doesn't verify the new implementation is also UUPS-compatible

---

## Vulnerability 6: Delegatecall to Arbitrary Address

### Severity: Critical

### The Problem
If the implementation contains a `delegatecall` to an address controlled by the caller (or derived from user input), the caller can execute arbitrary code in the proxy's context — reading/writing any storage slot, including the implementation pointer itself.

### What To Look For
- `delegatecall` in the implementation that takes an address parameter from user input
- Multicall patterns in upgradeable contracts where `delegatecall` is used internally
- Libraries that use `delegatecall` and are called from upgradeable implementations

---

## Audit Checklist for Upgrade Patterns

1. [ ] Is the implementation contract's constructor calling `_disableInitializers()`?
2. [ ] Is `_authorizeUpgrade()` (UUPS) properly access-controlled?
3. [ ] Is the storage layout append-only between versions with `__gap` arrays?
4. [ ] Has the upgrade been tested with OpenZeppelin's upgrade plugin or Slither?
5. [ ] For UUPS: does the new implementation pass the ERC-1822 proxiableUUID check?
6. [ ] For Transparent: are there no function selector collisions between proxy and implementation?
7. [ ] For Beacon: is the Beacon admin a multisig with a timelock?
8. [ ] Is there no reachable `selfdestruct` in the implementation or any contract it delegatecalls to?
9. [ ] Is the upgrade process documented and uses a timelock for production deployments?
10. [ ] Are there monitoring alerts for `Upgraded` events and admin changes?
11. [ ] Is the implementation free of `delegatecall` to user-controlled addresses?
12. [ ] After every upgrade, is the proxy tested to confirm it still functions correctly?
