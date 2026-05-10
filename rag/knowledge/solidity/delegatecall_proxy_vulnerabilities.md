# Delegatecall and Proxy Vulnerabilities in Solidity (SWC-112)

## Tags
delegatecall, proxy, storage-collision, upgradeability, EIP-1967, UUPS, transparent


## How delegatecall Works
`delegatecall` executes the target's code in the CALLER's storage context. The implementation's `msg.sender` and `msg.value` are preserved. Storage slots are accessed by INDEX — not by name — across the proxy/implementation boundary.

```
Proxy storage slot 0: address implementation  ← proxy uses this
Implementation slot 0: address owner          ← impl thinks this is owner
// COLLISION: both point to same slot — proxy's implementation address IS the owner variable
```

## Vulnerability 1: Storage Collision

```solidity
// VULNERABLE — proxy and implementation share slot 0
contract Proxy {
    address public implementation;  // slot 0

    fallback() external payable {
        (bool ok,) = implementation.delegatecall(msg.data);
        require(ok);
    }
}

contract Implementation {
    address public owner;  // slot 0 — COLLISION with proxy.implementation!

    function initialize() public {
        owner = msg.sender;  // WRITES to slot 0 → overwrites proxy.implementation!
        // Attacker calls initialize(), sets owner = themselves, overwrites implementation addr
    }
}

// FIXED — use EIP-1967 storage slots (pseudorandom, collision-resistant)
// Implementation slot: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
// Admin slot:          bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
```

## Vulnerability 2: Uninitialized Implementation Contract

```solidity
// VULNERABLE — implementation deployed but never initialized
// Anyone can call initialize() on the implementation directly
contract ImplementationV1 is Initializable {
    address public owner;
    uint256 public fee;

    function initialize(address _owner, uint256 _fee) public initializer {
        owner = _owner;
        fee = _fee;
    }

    // If implementation.initialize() never called:
    // Attacker calls implementation.initialize(attacker, 0)
    // Now attacker owns implementation — can call selfdestruct → breaks all proxies
}

// MITIGATION: always call _disableInitializers() in implementation constructor
constructor() {
    _disableInitializers();  // prevents init on implementation directly
}
```

## Vulnerability 3: Function Selector Clashing

```solidity
// Different function signatures can produce the same 4-byte selector
// bytes4(keccak256("collate_propagate_storage(bytes16)")) == bytes4(keccak256("burn(uint256)"))

// In a proxy: if proxy has admin function "upgradeTo(address)" selector = 0x3659cfe6
// and implementation accidentally has a different function with same selector,
// admin call routes to wrong function or vice versa

// Real example: UUPS proxy — if upgradeToAndCall selector clashes with a protocol function,
// user tx could trigger an upgrade
```

## Vulnerability 4: UUPS — Missing upgradeToAndCall Authorization

```solidity
// VULNERABLE — UUPS upgrade function not protected
contract ImplementationUUPS is UUPSUpgradeable {
    // Missing: override _authorizeUpgrade
    // Default OpenZeppelin _authorizeUpgrade reverts — but if overridden incorrectly:

    function _authorizeUpgrade(address) internal override {
        // no check — anyone can upgrade to malicious implementation!
    }
}

// FIXED
function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
```

## Vulnerability 5: Delegatecall to User-Controlled Address

```solidity
// VULNERABLE — attacker controls target of delegatecall
contract Forwarder {
    function forward(address target, bytes calldata data) external {
        target.delegatecall(data);  // attacker passes malicious contract as target
        // Malicious contract runs in Forwarder's context:
        // - reads/writes Forwarder's storage
        // - calls selfdestruct to destroy Forwarder
        // - transfers Forwarder's ETH balance
    }
}

// FIXED — whitelist allowed targets, or use call not delegatecall
mapping(address => bool) public whitelistedTargets;

function forward(address target, bytes calldata data) external {
    require(whitelistedTargets[target], "Target not whitelisted");
    target.delegatecall(data);
}
```

## Vulnerability 6: Transparent Proxy Admin/User Selector Conflict

```solidity
// Transparent proxy: admin calls go to proxy, user calls go to implementation
// Problem: if user sends tx with selector matching proxy admin function, it's handled by proxy

// OpenZeppelin TransparentUpgradeableProxy solution:
// If msg.sender == admin → route to proxy (upgrade/admin fns)
// If msg.sender != admin → route to implementation (no admin fn access)

// RISK: admin can't interact with implementation as a user
// If admin calls implementation.foo(), it hits proxy admin fn instead
// Solution: admin must use a separate account for protocol interactions
```

## Vulnerability 7: Upgrade Changes Storage Layout

```solidity
// VULNERABLE — V2 reorders or removes V1 storage variables
contract ImplementationV1 {
    uint256 public totalSupply;  // slot 0
    mapping(address => uint256) balances;  // slot 1
}

contract ImplementationV2 {
    address public newField;     // slot 0 ← OVERWRITES totalSupply!
    uint256 public totalSupply;  // slot 1 ← now points to balances mapping!
    mapping(address => uint256) balances;  // slot 2
}

// FIXED — append-only storage: never remove/reorder existing variables
contract ImplementationV2 {
    uint256 public totalSupply;  // slot 0 — preserved
    mapping(address => uint256) balances;  // slot 1 — preserved
    address public newField;     // slot 2 — appended at end
}
```

## Vulnerability 8: Metamorphic Contracts

```solidity
// A contract deployed via CREATE2 can be destroyed (selfdestruct) and
// redeployed to the same address with different bytecode
// This breaks "code is law" assumptions — audited code can be swapped out

// Detection: check if protocol uses CREATE2 + selfdestruct pattern
// If yes: the contract code auditors reviewed may not be the code that runs

// Mitigation: extcodehash checks, time-locks before redeployment
```

## Real-World Examples
- **Parity Multisig V2 (2017, $150M frozen)**: delegatecall to unprotected library → selfdestruct
- **Audius (2022, $6M)**: governance proxy storage collision — attacker overwrote proxy vars
- **Wormhole (2022, $320M)**: deprecated Solana function still callable — analogous proxy logic
- **Pickle Finance (2020, $20M)**: delegatecall to attacker-controlled jar contract

## Detection Signals (Slither)
- `controlled-delegatecall` — delegatecall with user-controlled target or data
- `delegatecall-loop` — delegatecall inside a loop
- Storage slot analysis: compare proxy vs implementation slot 0-N
- `_disableInitializers()` missing in UUPS/Transparent implementations
- `_authorizeUpgrade` with empty or missing access control body
- Storage layout diff between V1 and V2 implementations

## Severity Guide
- User-controlled delegatecall target: **Critical**
- Storage collision proxy/impl: **Critical**
- Uninitialized implementation (selfdestruct path): **Critical**
- Missing _authorizeUpgrade guard: **Critical**
- Storage layout change on upgrade: **Critical**
- Selector clashing: **High**
