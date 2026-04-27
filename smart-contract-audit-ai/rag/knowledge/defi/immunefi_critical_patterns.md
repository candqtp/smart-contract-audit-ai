# Immunefi Critical and High Vulnerability Patterns

## About Immunefi
Immunefi is the largest bug bounty platform for DeFi. Critical findings pay $50K-$10M+. The disclosed reports represent real exploits found by white-hat researchers, making them the most reliable signal for high-severity vulnerability patterns.

## Critical Pattern 1: Infinite Mint via Accounting Mismatch

Real Immunefi disclosures have found this pattern across multiple protocols.

```solidity
// VULNERABLE — mint function doesn't check existing supply or uses wrong balance
function mint(address to, uint256 amount) external {
    require(msg.sender == vault, "Only vault");
    // BUG: vault's internal accounting is out of sync with token supply
    // If vault calls mint() twice for same deposit (reentrancy or double-processing),
    // tokens are minted twice for one deposit
    _mint(to, amount);
}

// Also seen: cross-contract accounting mismatch
// Contract A records deposit → tells Contract B to mint
// If Contract A can be called twice before B records the mint → double mint

// Immunefi Example: SushiSwap MISO (2021)
// Crowdsale contract allowed function to be called again during token transfer callback
// Result: attacker could drain auction proceeds
```

## Critical Pattern 2: Logic Error in Loan/Flash Loan Repayment Check

```solidity
// VULNERABLE — repayment check uses wrong balance reference

function flashLoan(address token, uint256 amount, address receiver, bytes calldata data) external {
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transfer(receiver, amount);

    IFlashReceiver(receiver).executeOperation(token, amount, data);

    uint256 balanceAfter = IERC20(token).balanceOf(address(this));
    require(balanceAfter >= balanceBefore, "Loan not repaid");
    // VULNERABLE: if receiver donates a different token to inflate balanceAfter,
    // or if token has a weird transfer implementation,
    // or if balanceBefore was already inflated by a previous donation...
    // The require() passes without actual repayment
}

// Better check: require exact amount + fee returned
require(balanceAfter >= balanceBefore + fee, "Insufficient repayment");
// Even better: track expected balance explicitly
require(balanceAfter == balanceBefore - amount + amount + fee, "Exact repayment required");
```

## Critical Pattern 3: Price Calculation With balanceOf Manipulation

One of the most exploited patterns across Immunefi disclosures.

```solidity
// VULNERABLE — price derived from contract's token balance
// Token balance manipulable by direct transfer (donation attack)

function getPrice() public view returns (uint256) {
    uint256 tokenBalance = IERC20(token).balanceOf(address(this));
    uint256 baseBalance = IERC20(baseToken).balanceOf(address(this));
    return baseBalance * 1e18 / tokenBalance;  // price = base per token
}

// Attack:
// 1. Flash loan 1M base tokens
// 2. Transfer directly to price contract (donation — not through swap function)
// 3. baseBalance inflates → price inflates
// 4. Use inflated price to borrow/mint
// 5. Repay flash loan
// Real example: Inverse Finance ($15.6M, 2022) — Keep3r-based oracle used pool balance

// FIXED — use reserves tracked by protocol, not live balanceOf
(uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pool).getReserves();
// Reserves updated only via swap/sync — not affected by direct transfer
```

## Critical Pattern 4: Signature Verification Bypass via Encoding

```solidity
// VULNERABLE — ABI encoding edge case allows signature collision

// Two different structs that ABI-encode to the same bytes:
struct Order { address token; uint256 amount; bytes data; }
struct Approval { address spender; uint256 value; bytes extraData; }

// abi.encode(Order{token:X, amount:Y, data:Z}) == abi.encode(Approval{spender:X, value:Y, extraData:Z})
// if Z == extraData == "" and other fields match

// A signature for an Order can be used as an Approval signature
// Real Immunefi finding: protocols using abi.encode for EIP-712 with struct packing

// FIXED — use EIP-712 typed structs with domain separator
// Each struct type has a unique typeHash that's part of the signed data
// Two different struct types produce different hashes even with same field values
bytes32 ORDER_TYPEHASH = keccak256("Order(address token,uint256 amount,bytes data)");
bytes32 APPROVAL_TYPEHASH = keccak256("Approval(address spender,uint256 value,bytes extraData)");
// Different typeHashes → different final hashes → signatures not interchangeable
```

## Critical Pattern 5: Incorrect Validation Order (TOCTOU)

```solidity
// Time-of-check vs Time-of-use
// VULNERABLE — validation uses a value that changes before execution

function liquidateAndClose(address user) external {
    // CHECK at time T1
    require(isUnderwater(user), "Not liquidatable");
    uint256 debt = getDebt(user);  // read debt at T1

    // External call — potentially reenters
    IERC20(collateralToken).safeTransfer(msg.sender, calculateSeize(debt));

    // USE at time T2 (after potential reentrancy)
    repayDebt(user, debt);  // debt may have changed during external call
    // If user's debt increased (via reentrancy), only original amount repaid
    // Remaining debt never collected
}
```

## Critical Pattern 6: Access Control Via Callback

```solidity
// VULNERABLE — privileged function callable via callback chain
// Direct call blocked → indirect call through callback allowed

contract Vault {
    address public admin;

    function adminWithdraw(uint256 amount) external {
        require(msg.sender == admin, "Not admin");  // blocks direct calls
        payable(admin).transfer(amount);
    }

    // Flash loan callback — called by pool during flash loan
    function uniswapV2Call(address sender, uint256, uint256, bytes calldata data) external {
        require(msg.sender == uniswapPair, "Only Uniswap");
        // Calls encoded function — including adminWithdraw!
        (bool ok,) = address(this).call(data);  // BUG: self-call with arbitrary data
        require(ok);
    }
}
// Attack: call uniswapPair.swap() with data = abi.encode(adminWithdraw, amount)
// uniswapPair calls vault.uniswapV2Call() → vault calls itself with adminWithdraw data
// msg.sender == vault (self-call) → admin check... depends on implementation
// Some implementations check tx.origin, some check msg.sender == address(this)

// FIXED — never decode and execute arbitrary calldata in callbacks
// Whitelist specific allowed operations in callbacks
```

## Critical Pattern 7: Integer Underflow in Fee Calculation

```solidity
// VULNERABLE (pre-0.8 or in unchecked blocks)
// Fee-on-transfer with large percentage can underflow

function transferWithFee(address from, address to, uint256 amount) internal {
    uint256 fee = amount * feePercent / 100;
    unchecked {
        // BUG: if fee > amount (feePercent > 100), underflow
        uint256 amountAfterFee = amount - fee;  // wraps to huge number
        balances[to] += amountAfterFee;
    }
}

// Also: fee percent set to 0 by admin → fee = 0, division "safe" but
// if feePercent is a config value that can be 0 → wrong economic behavior
```

## Critical Pattern 8: Vault Withdrawal Exceeds Deposited Amount

```solidity
// VULNERABLE — vault allows withdrawing more than deposited due to accounting bug

// Common pattern: deposit records "shares" at old exchange rate
// But withdrawal uses current (higher) exchange rate AND original share count

struct UserData {
    uint256 shares;
    uint256 depositedAmount;  // unused in withdrawal calculation
}

function withdraw(uint256 shares) external {
    uint256 amount = shares * currentPricePerShare / 1e18;
    // amount could exceed what user deposited if exchange rate increased
    // This is by design (yield) — BUT: if currentPricePerShare is manipulable,
    // user can withdraw much more than they deposited + yield

    _burn(msg.sender, shares);
    token.transfer(msg.sender, amount);
}
```

## Immunefi Severity Taxonomy

```
Critical: funds at risk of being stolen/drained directly
  - Any bug allowing unauthorized minting
  - Any bug allowing bypass of signature/auth checks
  - Oracle manipulation leading to protocol drain
  - Flash loan attacks on financial functions

High: significant protocol damage but not total loss
  - DoS making protocol permanently unusable
  - Griefing attacks with significant financial impact
  - Governance takeover
  - Bridge insolvency

Medium: limited financial impact or difficult to exploit
  - Incorrect calculation affecting small amounts
  - Temporary DoS
  - Missing input validation with limited blast radius

Low: minimal impact
  - Gas optimization issues
  - Informational findings
  - Events missing

Out of Scope (common Immunefi exclusions):
  - Admin key compromise (separate from contract bugs)
  - Frontend attacks (phishing, DNS hijack)
  - Social engineering
  - Issues requiring compromised oracle providers
```

## Protocol-Specific Attack Surfaces (Immunefi Patterns)

```
Lending (Compound forks):
  - Flash loan → inflate oracle → borrow more than collateral
  - Block liquidation → health factor never restored → bad debt

AMMs:
  - Add/remove liquidity with wrong slippage → sandwiched
  - Fee tier manipulation
  - LP position boundary manipulation (V3 specific)

Bridges:
  - Replay on forked chains
  - Message validation bypass
  - Guardian key compromise path

Vaults (Yearn forks):
  - Strategy migration without settling debts
  - Emergency mode that doesn't protect LPs
  - Harvest front-running (JIT deposit before harvest)

Stablecoins:
  - Collateral oracle manipulation → unbacked minting
  - Liquidation gap too small → bad debt exceeds buffer
  - PSM (Peg Stability Module) imbalance attacks
```

## Detection Signals
- `balanceOf(address(this))` used directly for pricing (not internal accounting)
- Flash loan callback executes arbitrary `address(this).call(data)`
- Repayment check: `balanceAfter >= balanceBefore` without fee validation
- Accounting for deposits/withdrawals uses different precision than token decimals
- Any critical function callable via flash loan callback chain
- TOCTOU: validation read before external call, execution uses same stale value

## Severity Guide
- Infinite mint via accounting mismatch: **Critical**
- Price from balanceOf → donation attack: **Critical**
- Signature bypass via encoding collision: **Critical**
- Flash loan access control bypass via callback: **Critical**
- TOCTOU in liquidation/repayment: **High/Critical**
- Integer underflow in fee (pre-0.8): **Critical**
