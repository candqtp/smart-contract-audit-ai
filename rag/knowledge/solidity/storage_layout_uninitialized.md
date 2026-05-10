# Storage Layout, Uninitialized Storage, and State Variable Vulnerabilities (SWC-109)

## Tags
storage, layout, uninitialized, proxy, slot-collision, delegatecall, ghost-variable


## Solidity Storage Layout Rules
- State variables are stored sequentially starting at slot 0
- Each slot = 32 bytes. Variables smaller than 32 bytes are packed.
- Mappings: keccak256(key . slot) — actual data stored at derived slot
- Arrays: length at base slot, elements at keccak256(slot) + index
- `storage` pointer in a function defaults to slot 0 if uninitialized

## Vulnerability 1: Uninitialized Storage Pointer (SWC-109)

```solidity
// VULNERABLE (Solidity < 0.5.0, but still in audited legacy code)
struct User {
    address addr;
    uint256 balance;
}

mapping(address => User) users;

function register() public {
    User storage user;  // UNINITIALIZED — points to slot 0 and slot 1 by default!
    user.addr = msg.sender;     // WRITES to storage slot 0
    user.balance = 100;         // WRITES to storage slot 1

    // If slot 0 holds a critical variable (e.g., owner address), it gets OVERWRITTEN
    // If slot 0 holds contract logic flags, attacker can flip them
}

// FIXED
function register() public {
    User storage user = users[msg.sender];  // explicitly initialized
    user.addr = msg.sender;
    user.balance = 100;
}
```

## Vulnerability 2: Storage Collision in Inheritance

```solidity
// VULNERABLE — Base and derived contract declare same-slot variables
contract Base {
    uint256 public totalSupply;  // slot 0
    address public owner;        // slot 1
}

contract Extension is Base {
    // This is fine — Extension inherits Base slots 0, 1
    // Extension adds new variables at slot 2+
    uint256 public fee;  // slot 2
}

// DANGEROUS: Multiple inheritance
contract A {
    uint256 public x;  // slot 0
}
contract B {
    uint256 public y;  // slot 0 in B's layout
}
contract C is A, B {
    // C: x at slot 0 (from A), y at slot 1 (from B, shifted)
    // Layout depends on linearization order — easy to get wrong
}
```

## Vulnerability 3: Packed Storage Variable Manipulation

```solidity
// Solidity packs multiple small variables into one slot
contract Packed {
    bool public paused;      // slot 0, byte 0
    bool public initialized; // slot 0, byte 1
    address public owner;    // slot 0, bytes 12-31 (address is 20 bytes)
    // All three share slot 0!
}

// If a low-level write touches slot 0 (e.g., via assembly or delegatecall):
// Writing a full uint256 to slot 0 overwrites ALL THREE values simultaneously
// A proxy storage collision could corrupt paused, initialized, and owner at once
```

## Vulnerability 4: Array Length Manipulation

```solidity
// In Solidity < 0.6.0, dynamic array length was directly writable
// Setting length to uint256.max → array "contains" all storage slots

// VULNERABLE (pre-0.6.0)
uint256[] public data;

function exploit() external {
    data.length = type(uint256).max;  // array now covers all 2^256 storage slots
    data[attackerSlot] = maliciousValue;  // write to any storage slot
}
// Fixed in Solidity 0.6.0 — array length no longer directly assignable
```

## Vulnerability 5: Dirty High Bits in Packed Slots

```solidity
// When a value smaller than 32 bytes is stored, only the relevant bytes are set
// High bits from a previous value may "bleed" into a new packed variable

// Example in assembly:
assembly {
    // Writing a uint8 to a slot that previously held different data
    sstore(0, or(and(sload(0), not(0xff)), newUint8Value))
    // Incorrect masking leaves old bits — subtle state corruption
}
// Use Solidity's type system rather than manual assembly when packing
```

## Vulnerability 6: Public Storage Leaking Sensitive Data

```solidity
// "private" in Solidity means not accessible via ABI — but ALL storage is readable on-chain
contract VulnerableLottery {
    bytes32 private secretSeed;     // NOT actually secret!
    uint256 private winningNumber;  // anyone can read this with eth_getStorageAt

    function guess(uint256 number) external {
        require(number == winningNumber);  // trivially beatable
        payable(msg.sender).transfer(address(this).balance);
    }
}
// Any sensitive value stored on-chain is public — don't use private for secrets
```

## Vulnerability 7: Immutable Variable Not Set

```solidity
// Immutable variables set once in constructor, baked into bytecode
// VULNERABLE — immutable set to address(0) if constructor arg omitted

contract Protocol {
    address public immutable treasury;

    constructor(address _treasury) {
        treasury = _treasury;  // if _treasury = address(0), all fees go to dead address
    }
}

// FIXED
constructor(address _treasury) {
    require(_treasury != address(0), "Zero treasury");
    treasury = _treasury;
}
```

## Storage Slot Calculation Reference

```solidity
// Mapping storage slot: keccak256(abi.encode(key, mappingSlot))
// Array element slot: keccak256(abi.encode(arraySlot)) + index
// EIP-1967 implementation slot:
//   bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
//   = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
// EIP-1967 admin slot:
//   bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
//   = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103

// Useful for audit: check if proxy slots collide with implementation layout
```

## Detection Signals (Slither)
- `uninitialized-local` — uninitialized local storage pointer
- `uninitialized-state` — state variable never assigned
- `constable-variables` — variable that should be constant/immutable but isn't
- Assembly `sstore` / `sload` in non-library code
- `address(0)` not checked for immutable or constructor arguments
- `private` used for sensitive values that should never be on-chain

## Severity Guide
- Uninitialized storage pointer (can overwrite critical state): **Critical**
- Private variable used for secrets (trivially readable): **High**
- Immutable set to address(0) (fees/access burned): **High**
- Array length manipulation (pre-0.6.0): **Critical**
- Storage collision via inheritance in proxy: **Critical**
