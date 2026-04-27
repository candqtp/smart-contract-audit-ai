# Reentrancy Vulnerabilities in Solidity

## What it is
Reentrancy occurs when an external call is made before state is updated, allowing the callee to re-enter the calling contract and exploit stale state.

## Classic Pattern (Single-function)
```solidity
// VULNERABLE
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");  // external call BEFORE state update
    balances[msg.sender] -= amount;                    // state updated AFTER — too late
}
```

## Cross-function Reentrancy
Attacker calls a second function that reads stale state after the first function's external call.

```solidity
// VULNERABLE — transfer uses balances before withdraw zeroes it
function transfer(address to, uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[to] += amount;
    balances[msg.sender] -= amount;
}
function withdraw() public {
    uint bal = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: bal}("");  // attacker re-enters transfer()
    balances[msg.sender] = 0;
}
```

## Read-only Reentrancy
Price oracles or view functions read mid-execution state during a reentrancy window.

## Detection Signals
- `.call{value:}()`, `.send()`, `.transfer()` before state writes
- ERC777 `tokensReceived` hooks
- ERC721 `onERC721Received` hooks
- Low-level `call()` to untrusted addresses

## Fix
```solidity
// Checks-Effects-Interactions pattern
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // effect FIRST
    (bool ok,) = msg.sender.call{value: amount}("");  // interaction LAST
    require(ok);
}

// OR use ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    function withdraw(uint amount) public nonReentrant { ... }
}
```

## Severity: Critical
Any unauthorized fund drain is Critical severity.
