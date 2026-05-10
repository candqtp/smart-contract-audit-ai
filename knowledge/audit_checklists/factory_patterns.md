# Factory and Minimal Proxy (EIP-1167) Security

## Tags
factory, minimal-proxy, clone, EIP-1167, delegatecall, storage-collision, uninitialized, beacon, create2, implementation, initializer

## Overview
Factory patterns deploy multiple identical contracts cheaply. EIP-1167 minimal proxies ("clones") are ~45 bytes of runtime bytecode that DELEGATECALL to a fixed implementation. Clones share logic but have independent storage. They CANNOT be upgraded — the implementation address is baked into bytecode. Key vulnerabilities: uninitialized clones, implementation destruction, and storage layout mismatches.

---

## Vulnerability 1: Uninitialized Clone / Missing Initializer Call

### Severity: Critical

### The Problem
Clones cannot use constructors (constructors run in the implementation's context, not the clone's). Instead, they must call an `initialize()` function after deployment. If the factory deploys a clone but doesn't call `initialize()` atomically, an attacker can front-run and initialize it with their own parameters (e.g., setting themselves as owner).

### Attack Pattern
1. Factory calls `Clones.clone(implementation)` — deploys new clone
2. Factory sends a separate transaction to call `clone.initialize(owner, params)`
3. Attacker front-runs step 2: calls `clone.initialize(attacker, maliciousParams)`
4. Attacker is now the owner of the clone

### What To Look For
- Factory's `createClone()` function that deploys and initializes in SEPARATE calls
- Initializer without `initializer` modifier (can be called multiple times)
- Initializer that checks `initialized` flag but uses a simple bool (not OpenZeppelin's Initializable pattern which is more robust)

### Secure Pattern
```solidity
// Deploy and initialize atomically
function createClone(address _owner, uint256 _param) external returns (address) {
    address clone = Clones.clone(implementation);
    IMyContract(clone).initialize(_owner, _param);  // Same transaction
    return clone;
}

// In the clone contract:
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
contract MyContract is Initializable {
    function initialize(address _owner, uint256 _param) external initializer {
        owner = _owner;
        param = _param;
    }
}
```

---

## Vulnerability 2: Implementation Contract Destruction

### Severity: Critical

### The Problem
If the implementation contract (master copy) that clones point to is destroyed via `selfdestruct`, ALL clones that DELEGATECALL to it become bricked. Every call to any clone will silently succeed but do nothing (post-Dencun, `selfdestruct` only sends ETH without destroying code except in same-transaction-as-creation scenarios, but on pre-Dencun chains or in create-then-destroy patterns this is still fatal).

### Pre-Dencun Attack
1. Implementation contract has an unprotected `selfdestruct` path (or an upgradeable path that can be pointed to a contract with `selfdestruct`)
2. Attacker triggers `selfdestruct` on the implementation
3. All clones now DELEGATECALL to an empty address — all calls return success with no effect
4. All funds in all clones are permanently stuck

### What To Look For
- Implementation contract with `selfdestruct` anywhere in its code or reachable via delegatecall
- Implementation contract that is upgradeable (UUPS pattern) — if upgraded to contain selfdestruct, same risk
- Implementation contract that is not initialized — attacker initializes it, gains owner role, and may be able to trigger destruction

### Mitigation
- Implementation contract should call `_disableInitializers()` in its constructor
- Implementation should have no `selfdestruct` reachable path
- Implementation should NOT be upgradeable unless absolutely necessary
- Consider making the implementation immutable (non-upgradeable)

---

## Vulnerability 3: Storage Collision Between Proxy and Implementation

### Severity: High

### The Problem
DELEGATECALL executes the implementation's code in the proxy's storage context. If the proxy contract declares its own state variables, they occupy storage slots that may overlap with the implementation's variables. Writing to slot 0 in the implementation's logic actually writes to slot 0 in the proxy — which might be the proxy's admin address or implementation pointer.

### EIP-1967 Solution
Standard storage slots for proxy metadata are defined at pseudo-random positions:
- Implementation slot: `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)`
- Admin slot: `bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)`
These slots are extremely unlikely to collide with normal sequential storage.

### Real-World Example (Audius Hack)
Audius introduced new state variables in their proxy contract that collided with the implementation's storage layout. The attacker exploited the collision to overwrite the governance address and drain funds.

### What To Look For
- Proxy contract declaring its own `uint256`, `address`, or other state variables (not using EIP-1967 slots)
- Upgraded implementation that reorders state variables or inserts new ones in the middle
- Missing `__gap` array in base contracts used with upgradeable patterns

### Detection
```solidity
// DANGEROUS: Proxy has its own state that can collide
contract MyProxy {
    address public admin;       // slot 0 — COLLIDES with implementation's slot 0!
    address public implementation;  // slot 1

    fallback() external {
        // delegatecall to implementation
    }
}

// SAFE: Uses EIP-1967 slots
contract MyProxy {
    bytes32 private constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    fallback() external {
        address impl = StorageSlot.getAddressSlot(IMPL_SLOT).value;
        // delegatecall to impl
    }
}
```

---

## Vulnerability 4: Unprotected Implementation Contract

### Severity: Critical

### The Problem
The implementation contract (master copy) itself must be initialized and locked. If left uninitialized, an attacker can:
1. Call `initialize()` on the implementation contract directly
2. Become the owner of the implementation
3. If the implementation is UUPS-upgradeable, call `upgradeTo()` pointing to a malicious contract
4. If the malicious contract contains `selfdestruct`, it can destroy the implementation

### Historical Examples
- Harvest Finance, Teller, KeeperDAO, Rivermen NFT all had uninitialized implementations
- Wormhole's UUPS implementation was left uninitialized after an upgrade — a white-hat called `initialize()`, became guardian, and triggered `selfdestruct` through the upgrade mechanism

### The Fix
```solidity
// In the implementation contract's constructor:
constructor() {
    _disableInitializers();  // Prevents anyone from calling initialize() on the implementation itself
}
```

---

## Vulnerability 5: Beacon Proxy Shared Risk

### Severity: High

### How Beacon Proxies Work
Multiple proxies point to a single Beacon contract that stores the implementation address. Upgrading the Beacon simultaneously upgrades ALL proxies.

### The Risk
- One bad Beacon upgrade affects EVERY proxy in the system
- If the Beacon admin is compromised, attacker controls all proxies simultaneously
- No way for individual proxy users to opt out of an upgrade

### What To Look For
- Beacon admin is an EOA (should be multisig + timelock)
- No timelock on Beacon upgrades (users can't exit before malicious upgrade takes effect)
- No upgrade event emission for monitoring
- Beacon proxy system used for user wallets or individual vaults — compromise = total loss for all users

---

## Vulnerability 6: CREATE2 Deterministic Address Exploitation

### Severity: Medium

### The Problem
Factories using CREATE2 deploy clones at predictable addresses. An attacker who knows the salt can precompute the address and send tokens to it BEFORE deployment. After deployment, the clone's initialization may not account for pre-existing balances, creating accounting discrepancies.

### Also
- If a CREATE2-deployed contract is destroyed and redeployed at the same address with different code (metamorphic contracts), approvals and balances from the old contract persist

### What To Look For
- Factory using CREATE2 without restricting who can choose the salt
- Clone initialization that doesn't check for pre-existing token balances
- CREATE2 deployment of upgradeable contracts (metamorphic pattern)

---

## Audit Checklist for Factory and Proxy Patterns

1. [ ] Are clones initialized atomically in the same transaction as deployment?
2. [ ] Does the initializer use OpenZeppelin's `initializer` modifier (not a simple bool)?
3. [ ] Is the implementation contract's initializer disabled via `_disableInitializers()` in the constructor?
4. [ ] Is the implementation contract free of `selfdestruct` in any reachable code path?
5. [ ] Are proxy storage slots using EIP-1967 standard positions?
6. [ ] In upgradeable implementations, are state variables append-only with `__gap` arrays?
7. [ ] For Beacon proxies: is the Beacon admin a multisig with a timelock?
8. [ ] Are upgrade events emitted for monitoring?
9. [ ] If CREATE2 is used: is the salt restricted? Are pre-existing balances handled?
10. [ ] Has the storage layout been verified with tools like `slither-check-upgradeability` or OpenZeppelin's upgrade plugin?
