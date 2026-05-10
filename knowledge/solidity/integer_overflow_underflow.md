# Integer Overflow and Underflow in Solidity (SWC-101)

## Tags
overflow, underflow, SafeMath, unchecked, arithmetic, wrapping, uint256


## Overview
Before Solidity 0.8.0, all arithmetic silently wrapped on overflow/underflow. After 0.8.0, arithmetic reverts by default. However, unchecked blocks, assembly, and downcasting still produce silent overflow.

## Pre-0.8.0 Pattern (Still in Production Codebases)

```solidity
// VULNERABLE (Solidity < 0.8.0 without SafeMath)
mapping(address => uint256) public balances;

function transfer(address to, uint256 amount) public {
    // Underflow: if balances[msg.sender] = 0 and amount = 1
    // 0 - 1 = 2^256 - 1 (wraps to max uint)
    balances[msg.sender] -= amount;  // no revert — attacker has infinite balance
    balances[to] += amount;
}
```

```solidity
// VULNERABLE — reward calculation overflow
function calculateReward(uint256 shares, uint256 rewardPerShare) public pure returns (uint256) {
    return shares * rewardPerShare;  // overflows if both large
}
```

## Post-0.8.0 Risks — unchecked Blocks

```solidity
// VULNERABLE — unchecked disables overflow protection
function decrement(uint256 x) public pure returns (uint256) {
    unchecked {
        return x - 1;  // if x = 0, returns 2^256 - 1
    }
}

// Legitimate use of unchecked (gas optimization — safe because bounds guaranteed):
for (uint256 i = 0; i < length;) {
    // ... loop body ...
    unchecked { ++i; }  // safe: i < length guarantees no overflow before increment
}
```

## Downcasting Overflow

```solidity
// VULNERABLE — silent truncation when casting to smaller type
function toUint128(uint256 value) internal pure returns (uint128) {
    return uint128(value);  // if value > 2^128-1, high bits silently dropped
}

// FIXED — use OpenZeppelin SafeCast
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
function toUint128Safe(uint256 value) internal pure returns (uint128) {
    return SafeCast.toUint128(value);  // reverts if overflow
}
```

## Token Balance Underflow Attack (Classic)

```solidity
// VULNERABLE — The DAO-era style; still seen in audits on older codebases
contract VulnerableToken {
    mapping(address => uint256) balances;  // Solidity 0.4.x

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));
        require(balances[msg.sender] - _value >= 0);  // ALWAYS TRUE for uint — underflow means wrap
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }
}
// require(balances[msg.sender] - _value >= 0) is always true for uint256
// because underflow wraps to a huge positive number
```

## Timestamp / Block Arithmetic

```solidity
// VULNERABLE — subtraction underflow if end < start in edge cases
function timeRemaining(uint256 startTime, uint256 endTime) public view returns (uint256) {
    return endTime - block.timestamp;  // underflows if deadline passed
}

// FIXED
function timeRemaining(uint256 startTime, uint256 endTime) public view returns (uint256) {
    if (block.timestamp >= endTime) return 0;
    return endTime - block.timestamp;
}
```

## Signed Integer Overflow

```solidity
// Solidity 0.8.0 reverts on signed overflow too, but assembly bypasses this
// VULNERABLE — inline assembly with signed arithmetic
function signedDiv(int256 a, int256 b) public pure returns (int256 result) {
    assembly {
        result := sdiv(a, b)  // INT256_MIN / -1 = overflow (undefined in EVM, returns INT256_MIN)
    }
}
```

## Real-World Examples
- **BatchOverflow (BEC Token, 2018)**: `uint256 amount = uint256(cnt) * _value` overflow → mint arbitrary tokens
- **SMT Token**: same pattern, `batchTransfer` with overflow in multiplication
- **Proof of Weak Hands (PoWH)**: integer underflow in sell function → attacker drained contract

## Detection Signals (Slither)
- Slither: `taint-analysis`, `integer-overflow` detector
- Solidity < 0.8.0 arithmetic without SafeMath library
- `unchecked {}` blocks containing user-controlled arithmetic
- Explicit downcasts: `uint128(x)`, `uint64(x)`, `int256(x)` without SafeCast
- `require(a - b >= 0)` patterns — always true for uint

## Severity Guide
- Underflow allowing balance inflation: **Critical**
- Overflow in token transfer multiplication: **Critical**
- Downcast truncation in price calculation: **High**
- Underflow in time calculations (wrong deadline): **Medium**
