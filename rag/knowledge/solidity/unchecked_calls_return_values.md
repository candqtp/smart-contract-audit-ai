# Unchecked Return Values and Low-Level Calls (SWC-104)

## Tags
unchecked, return-value, call, low-level, assembly, send, transfer


## Overview
Solidity's low-level call functions (`call`, `delegatecall`, `staticcall`, `send`) return a bool indicating success. Ignoring this return value silently swallows failures. This is especially dangerous for ETH transfers and token interactions.

## Vulnerability 1: Unchecked .send() / .transfer()

```solidity
// .transfer() reverts on failure — SAFE but deprecated (2300 gas limit breaks with EIP-1884)
payable(recipient).transfer(amount);  // will revert if recipient is contract that uses > 2300 gas

// .send() returns false on failure — MUST check return value
bool sent = payable(recipient).send(amount);
// VULNERABLE: sent not checked — failure is silently ignored

// FIXED — use .call{value:}() and check return
(bool success, ) = payable(recipient).call{value: amount}("");
require(success, "Transfer failed");
```

## Vulnerability 2: Unchecked Low-Level call()

```solidity
// VULNERABLE — call return value ignored
contract Executor {
    function execute(address target, bytes calldata data) external {
        target.call(data);  // silently ignores failure
        // If target reverts, executor continues as if nothing happened
        // State may be partially updated
    }
}

// FIXED
(bool success, bytes memory returnData) = target.call(data);
require(success, string(returnData));
```

## Vulnerability 3: ERC20 Non-Standard Return Values

```solidity
// ERC20 standard: transfer() should return bool
// But some tokens (USDT, BNB) return nothing OR return false without reverting

// VULNERABLE — assumes standard ERC20 behavior
function depositToken(IERC20 token, uint256 amount) external {
    token.transfer(address(this), amount);  // USDT returns nothing — call "succeeds"
    // or returns false — not checked — deposit not actually received
}

// FIXED — use SafeERC20 from OpenZeppelin
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

using SafeERC20 for IERC20;

function depositToken(IERC20 token, uint256 amount) external {
    token.safeTransfer(address(this), amount);  // handles non-standard returns
    token.safeTransferFrom(msg.sender, address(this), amount);  // for deposits
}
```

## Vulnerability 4: Incorrect Return Value Assumption

```solidity
// VULNERABLE — assumes call returns specific data without length check
function getPrice(address oracle) external returns (uint256) {
    (bool ok, bytes memory data) = oracle.call(abi.encodeWithSignature("getPrice()"));
    require(ok);
    return abi.decode(data, (uint256));  // reverts if oracle returns empty bytes
    // Malicious/broken oracle returning empty bytes causes revert — DoS
    // Malicious oracle returning wrong-length bytes — abi.decode reverts with confusing error
}

// FIXED — check data length
require(ok && data.length >= 32, "Oracle failed");
return abi.decode(data, (uint256));
```

## Vulnerability 5: Ignored Failure in Multi-Transfer

```solidity
// VULNERABLE — batch transfer ignores individual failures
function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        (bool ok,) = recipients[i].call{value: amounts[i]}("");
        // ok not checked — failed transfers not retried or tracked
        // Some recipients may not receive payment silently
    }
}

// FIXED — track and handle failures
mapping(address => uint256) public failedTransfers;

function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        (bool ok,) = recipients[i].call{value: amounts[i]}("");
        if (!ok) {
            failedTransfers[recipients[i]] += amounts[i];  // allow withdrawal later
        }
    }
}
```

## Vulnerability 6: DoS via Revert in Receiver (Pull over Push)

```solidity
// VULNERABLE — if any recipient reverts, entire distribution fails
// Attacker deploys contract that always reverts on receive()
contract MaliciousReceiver {
    receive() external payable {
        revert("I reject ETH");
    }
}

// Distribution contract:
function distribute(address[] calldata recipients) external {
    for (uint i = 0; i < recipients.length; i++) {
        payable(recipients[i]).transfer(share);  // if one reverts, all fail
    }
}
// Attacker becomes a recipient → permanently DoS the distribution

// FIXED — use pull pattern (claimable balances)
mapping(address => uint256) public claimable;

function distribute(address[] calldata recipients, uint256 share) external {
    for (uint i = 0; i < recipients.length; i++) {
        claimable[recipients[i]] += share;
    }
}

function claim() external {
    uint256 amount = claimable[msg.sender];
    require(amount > 0);
    claimable[msg.sender] = 0;
    (bool ok,) = payable(msg.sender).call{value: amount}("");
    require(ok);
}
```

## Vulnerability 7: Return Value of approve() Not Checked

```solidity
// Some tokens return false from approve() instead of reverting
// VULNERABLE
IERC20(token).approve(spender, amount);  // return not checked

// FIXED
require(IERC20(token).approve(spender, amount), "Approve failed");
// OR
SafeERC20.safeApprove(token, spender, amount);
```

## Real-World Examples
- **King of the Ether (2016)**: `.send()` failure not checked — dethroned king's refund silently failed
- **SpankChain (2018)**: unchecked return on token transfer allowed re-entry
- **USDT fee-on-transfer**: protocols using `transfer` instead of checking actual received amount

## Detection Signals (Slither)
- `unchecked-lowlevel` — return of low-level call not checked
- `unchecked-send` — .send() return not checked
- `unchecked-transfer` — ERC20 transfer not using SafeERC20
- Direct `.transfer()` or `.send()` to arbitrary address (should use `.call`)
- `abi.decode` without data length validation

## Severity Guide
- ETH transfer with unchecked return to user: **High**
- ERC20 transfer without SafeERC20 (USDT, BNB affected): **High**
- Ignored failure in critical multi-step operation: **High**
- DoS via revert-in-receiver without pull pattern: **Medium/High**
- approve() return not checked: **Low/Medium**
