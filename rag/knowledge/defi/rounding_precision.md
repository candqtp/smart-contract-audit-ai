# Rounding and Precision Vulnerabilities in Solidity

## Tags
rounding, precision-loss, division-before-multiplication, fixed-point, fee-on-transfer, rebase, truncation, integer-math, scaling

## Overview
Solidity has no floating-point arithmetic. All division truncates (rounds toward zero). This means order of operations matters critically: `(a / b) * c` ≠ `(a * c) / b` when intermediate results lose precision. Rounding errors are consistently ranked in the top 10 smart contract vulnerability types by Immunefi.

---

## Vulnerability 1: Division Before Multiplication

### Severity: Medium-High

### The Core Rule
**ALWAYS multiply before dividing.** In Solidity, `(a / b) * c` truncates the intermediate `a / b` result, permanently losing the remainder. `(a * c) / b` preserves precision through the multiplication step.

### Example (Vulnerable)
```solidity
// Fee calculation: 5% of amount
function calculateFee(uint256 amount) public pure returns (uint256) {
    return (amount / 100) * 5;  // BUG: if amount=99, result=0 instead of 4
}
```

### Example (Fixed)
```solidity
function calculateFee(uint256 amount) public pure returns (uint256) {
    return (amount * 5) / 100;  // Correct: if amount=99, result=4
}
```

### What To Look For
- Any expression where division appears LEFT of multiplication: `x / y * z`
- Fee calculations, reward distributions, exchange rate computations
- Ratio calculations in lending protocols (LTV, interest, utilization)
- Multi-step calculations where an intermediate result is stored as a truncated uint, then later multiplied

### Real-World Impact
- The KyberSwap hack (~$53M lost) was partly attributed to rounding errors in concentrated liquidity math
- Numerous audit contest findings on Code4rena, Sherlock, and CodeHawks flag this pattern at Medium-High severity

---

## Vulnerability 2: Accumulated Precision Loss Over Many Operations

### Severity: Medium

### How It Happens
Even with multiply-before-divide, repeated operations compound small losses. In high-frequency operations (reward distribution per block, interest accrual per second), a 1-wei loss per operation can become significant over thousands of iterations.

### Example
```solidity
// Vulnerable: fee calculated per-transaction loses dust each time
uint256 feePct = timeDiff * licenseFee / ONE_YEAR;
uint256 fee = startSupply * feePct / (BASE - feePct);
// Two separate divisions = two truncation events
// Over thousands of calls, this compounds into material loss
```

### Mitigations
- Use a single division at the end of a chain of multiplications
- Use fixed-point libraries (e.g., PRBMath, ABDKMath64x64) for complex calculations
- Track accumulated dust in a remainder variable: `remainder += (numerator % denominator);`
- Use higher internal precision (scale by 1e18 or 1e27) and only descale at the final output

---

## Vulnerability 3: Rounding Direction Exploits

### Severity: High

### The Rule of Thumb
- Round AGAINST the user, IN FAVOR of the protocol.
- Deposits: round shares DOWN (user gets fewer shares)
- Withdrawals: round assets DOWN (user gets fewer assets)
- Fee collection: round UP (protocol collects more)
- Loan repayment: round UP (borrower pays more)

### Why It Matters
If a protocol rounds in the user's favor, an attacker can repeatedly deposit-then-withdraw in a loop, extracting 1 wei of value per round-trip. With enough gas, this drains the protocol.

### What To Look For
- Using `mulDivDown` where `mulDivUp` is needed (or vice versa)
- Using Solidity's built-in `/` (always rounds down) without considering which direction favors the protocol
- OpenZeppelin's `Math.mulDiv` with `Math.Rounding.Floor` vs `Math.Rounding.Ceil` — check every usage

### Rounding Helper Pattern
```solidity
// Round up: (a * b + c - 1) / c
function mulDivUp(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
    return (a * b + c - 1) / c;
}
```

---

## Vulnerability 4: Fixed-Point Scaling Errors

### Severity: Medium-High

### Common Patterns
- Protocols use 1e18 as a WAD (18 decimals) or 1e27 as a RAY (27 decimals)
- Bugs occur when mixing tokens of different decimals (USDC=6, WETH=18) without normalizing first
- Forgetting to descale after a multiplication of two scaled values: `(1e18 * 1e18)` = 1e36, not 1e18

### What To Look For
- Arithmetic mixing tokens with different `decimals()` without explicit conversion
- Two WAD-scaled values multiplied without dividing by WAD after: `a.wadMul(b)` should be `(a * b) / 1e18`
- Casting between fixed-point libraries (e.g., PRBMath to raw uint) without adjusting scale
- Chainlink price feeds returning 8-decimal values mixed with 18-decimal token amounts

### Example (Vulnerable)
```solidity
// USDC has 6 decimals, ETH has 18 decimals
// oraclePrice is in 8 decimals (Chainlink)
uint256 valueInUSD = ethAmount * oraclePrice / 1e18;
// BUG: should normalize to same decimals first
// If ethAmount = 1e18 and price = 2000e8:
// 1e18 * 2000e8 / 1e18 = 2000e8 — still in 8 decimals, not 6!
```

---

## Vulnerability 5: Fee-on-Transfer Token Precision Issues

### Severity: Medium-High

### The Problem
Tokens that deduct a fee on `transfer()` or `transferFrom()` deliver fewer tokens than the `amount` parameter specifies. If a contract assumes it received the full amount, its internal accounting becomes inflated.

### Affected Tokens
- USDT (has a fee toggle, currently 0 but can be activated)
- PAXG (0.02% transfer fee)
- STA, DEFLECT, and many deflationary meme tokens

### Detection Pattern
```solidity
// VULNERABLE — assumes full amount received
token.transferFrom(msg.sender, address(this), amount);
balances[msg.sender] += amount;  // Wrong! Actual received < amount

// SAFE — measures actual received amount
uint256 before = token.balanceOf(address(this));
token.transferFrom(msg.sender, address(this), amount);
uint256 received = token.balanceOf(address(this)) - before;
balances[msg.sender] += received;  // Correct
```

---

## Vulnerability 6: Rebasing Token Accounting Errors

### Severity: Medium-High

### The Problem
Rebasing tokens (stETH, AMPL, OHM variants) change user balances automatically without transfers. If a vault or pool tracks balances via internal mapping rather than live `balanceOf`, the internal state diverges from reality.

### Common Failure Modes
- Positive rebase: vault has more assets than tracked, but share price doesn't reflect it — arbitrageurs deposit right before rebase, withdraw after, extracting the difference
- Negative rebase: vault has fewer assets than tracked — last withdrawers get less than their fair share (bank run dynamic)
- stETH specifically: use `wstETH` (wrapped, non-rebasing) instead of raw `stETH` in DeFi integrations

### What To Look For
- Protocol claims "supports any ERC-20" without explicit rebase handling
- `totalAssets()` or `totalSupply` derived from cached values rather than live balanceOf
- No documentation about which token types are explicitly supported vs excluded

---

## Audit Checklist for Precision Issues

1. [ ] Is every arithmetic chain structured as multiply-first-divide-last?
2. [ ] Are rounding directions correct for every operation? (Against the user, for the protocol)
3. [ ] When mixing tokens of different decimals, is normalization applied before any arithmetic?
4. [ ] Are Chainlink oracle prices (8 decimals) properly scaled before use with 18-decimal tokens?
5. [ ] Do token transfers use before/after balance checks to handle fee-on-transfer tokens?
6. [ ] Is the protocol explicitly tested with 6-decimal (USDC), 8-decimal (WBTC), and 18-decimal tokens?
7. [ ] Are rebasing tokens supported? If so, how? If not, is this documented?
8. [ ] Is there a risk of rounding to zero in reward distribution, fee calculation, or share conversion for small amounts?
9. [ ] Are fixed-point library functions used correctly (e.g., `wadMul` divides by WAD after multiplication)?
10. [ ] Are there invariant/fuzz tests that deposit+withdraw loops to detect slow value leakage?
