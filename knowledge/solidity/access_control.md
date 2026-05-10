# Access Control Vulnerabilities in Solidity (SWC-105, SWC-106)

## Tags
access-control, onlyOwner, roles, RBAC, privilege-escalation, authorization, modifier


## Overview
Access control flaws are the #1 cause of DeFi hacks by dollar value. They range from missing `onlyOwner` modifiers to complex privilege escalation through initialization races and misconfigured proxies.

## SWC-105: Unprotected Ether Withdrawal

```solidity
// VULNERABLE — anyone can drain contract
contract Vault {
    function withdraw(uint256 amount) public {
        payable(msg.sender).transfer(amount);  // no auth check
    }
}

// FIXED
contract Vault is Ownable {
    function withdraw(uint256 amount) public onlyOwner {
        payable(msg.sender).transfer(amount);
    }
}
```

## SWC-106: Unprotected SELFDESTRUCT

```solidity
// VULNERABLE — anyone can destroy contract and steal ETH balance
contract Killable {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}

// FIXED
function kill() public onlyOwner {
    selfdestruct(payable(owner()));
}
```

## Uninitialized Proxy / Implementation Contract

```solidity
// VULNERABLE — implementation contract not initialized, anyone can call initialize()
// Parity Multisig Hack ($30M, 2017) — uninitialized library contract
contract WalletLibrary {
    address public owner;

    function initWallet(address _owner) public {
        owner = _owner;  // no check if already initialized
    }

    function kill() public {
        require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }
}
// Attacker calls initWallet() on library directly, sets themselves as owner, calls kill()
// All proxy wallets pointing to this library lose funds

// FIXED — initialize only once
bool private initialized;
function initWallet(address _owner) public {
    require(!initialized, "Already initialized");
    initialized = true;
    owner = _owner;
}
// Or use OpenZeppelin Initializable with initializer modifier
```

## tx.origin Authentication (SWC-115)

```solidity
// VULNERABLE — tx.origin is the EOA that started the chain, not msg.sender
// Phishing attack: victim calls malicious contract → malicious contract calls target
contract Vulnerable {
    address owner;
    function transfer(address to, uint256 amount) public {
        require(tx.origin == owner, "Not owner");  // tx.origin = victim (if victim called attacker)
        payable(to).transfer(amount);
    }
}
// Attack: owner calls MaliciousContract.foo() → foo() calls Vulnerable.transfer(attacker, all)
// tx.origin = owner ✓ — check passes, funds drained

// FIXED — always use msg.sender for auth
require(msg.sender == owner, "Not owner");
```

## Missing Access Control on Sensitive State Setters

```solidity
// VULNERABLE — price oracle, fee, or admin address can be set by anyone
contract DeFiProtocol {
    address public priceOracle;
    uint256 public fee;

    function setOracle(address _oracle) public {
        priceOracle = _oracle;  // no auth — attacker sets malicious oracle
    }

    function setFee(uint256 _fee) public {
        fee = _fee;  // no auth — attacker sets 100% fee
    }
}
```

## Role-Based Access Control (RBAC) Misuse

```solidity
// VULNERABLE — role assignment not protected
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Protocol is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor() {
        // BUG: DEFAULT_ADMIN_ROLE not assigned — no one can grant/revoke roles
        // OR: DEFAULT_ADMIN_ROLE given to address(0) — roles locked forever
        _grantRole(ADMIN_ROLE, address(0));  // 💀
    }
}

// FIXED
constructor() {
    _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    _grantRole(ADMIN_ROLE, msg.sender);
    _grantRole(MINTER_ROLE, msg.sender);
}
```

## Ownership Renouncement Without Successor

```solidity
// RISK — renounceOwnership() called on contract with critical owner-gated functions
// After renouncement: fee changes, pausing, oracle updates all permanently locked

// Pattern seen in rugpull setups:
// 1. Deploy with owner
// 2. Take funds or set malicious params
// 3. renounceOwnership() — prevents any recovery

// Always check: what owner-only functions exist? What happens if owner is address(0)?
```

## Two-Step Ownership Transfer

```solidity
// VULNERABLE — one-step transfer, typo in address = ownership lost forever
function transferOwnership(address newOwner) public onlyOwner {
    owner = newOwner;  // if newOwner is wrong address, ownership permanently lost
}

// FIXED — two-step: propose then accept
address public pendingOwner;

function proposeOwnership(address newOwner) public onlyOwner {
    pendingOwner = newOwner;
}

function acceptOwnership() public {
    require(msg.sender == pendingOwner, "Not pending owner");
    emit OwnershipTransferred(owner, pendingOwner);
    owner = pendingOwner;
    pendingOwner = address(0);
}
```

## Function Visibility Errors (SWC-100)

```solidity
// VULNERABLE — function intended as internal is public
function _updateReserves(uint256 a, uint256 b) public {  // should be internal/private
    reserveA = a;
    reserveB = b;
}

// VULNERABLE — constructor-like function in older Solidity (pre-0.4.22)
// If contract name changes but constructor function name is not updated:
contract Token {
    function Token() public {  // old-style constructor
        owner = msg.sender;
    }
    // Renaming contract to "MyToken" without updating function name:
    // "Token()" becomes a regular public function anyone can call to reset owner
}
```

## Real-World Examples
- **Parity Multisig (2017, $30M)**: uninitialized library contract, attacker claimed ownership
- **Ronin Bridge (2022, $625M)**: 5/9 validator keys compromised — insufficient multisig threshold
- **Nomad Bridge (2022, $190M)**: initialization bug allowed any message to be "proven"
- **Euler Finance (2023, $197M)**: donation + liquidation logic accessible without auth guard

## Detection Signals (Slither)
- `unprotected-ether-withdrawal`, `suicidal` detectors
- `missing-zero-check` on ownership transfer targets
- `tx-origin` detector
- Functions named `set*`, `update*`, `initialize*` without access modifiers
- `public` functions that modify state variables not gated by modifier

## Severity Guide
- Unprotected withdraw/selfdestruct: **Critical**
- Uninitialized proxy initialization: **Critical**
- tx.origin authentication: **High**
- Missing auth on oracle/fee setters: **High**
- One-step ownership transfer: **Medium**
- RBAC DEFAULT_ADMIN_ROLE to address(0): **Critical**
