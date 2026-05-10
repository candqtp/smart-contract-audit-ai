# AMM Math and Security Vulnerabilities

## Tags
amm, constant-product, xy=k, uniswap, LP-share, dilution, flash-loan, sandwich, sqrt, slippage, spot-price, oracle, TWAP, MEV

## Overview
Automated Market Makers use the constant product formula `x * y = k` to price assets without an order book. The spot price is `reserveY / reserveX`. This price is trivially manipulable within a single transaction using flash loans, making AMM spot prices fundamentally insecure as price oracles.

---

## Vulnerability 1: Flash Loan Price Manipulation

### Severity: Critical

### The Core Problem
AMM spot price reflects only the current reserve ratio, not global market value. With flash-loan capital, an attacker can shift reserves, trigger an action on a vulnerable protocol that reads the manipulated price, then trade back — all in one atomic transaction.

### Attack Pattern
1. Flash borrow a large amount of token A
2. Swap token A for token B on the target AMM — price of B drops drastically
3. Call vulnerable protocol that uses AMM spot price as oracle (e.g., borrow against inflated collateral, mint stablecoins at wrong price)
4. Swap back to restore price
5. Repay flash loan plus fee, keep profit

### What To Look For
- **ANY protocol reading AMM `getReserves()` or `price0CumulativeLast` in a single block as a price oracle** — this is the #1 AMM vulnerability pattern
- `getAmountOut()` used as a price feed
- Collateral valued using pool ratio rather than external oracle
- No TWAP (time-weighted average price) implementation

### Real-World Examples
- PancakeBunny: $45M lost — used PancakeSwap spot price to value BUNNY tokens
- Cream Finance: $18.8M — spot price manipulation on lending protocol
- Beanstalk: $182M — governance attack using flash-loaned voting power

### Secure Pattern
```
// NEVER do this:
(uint112 reserve0, uint112 reserve1,) = pair.getReserves();
uint256 price = reserve1 * 1e18 / reserve0;  // Trivially manipulable

// DO this instead:
uint256 price = chainlinkOracle.latestAnswer();  // External oracle
// OR use Uniswap V3 TWAP:
uint32[] memory secondsAgos = new uint32[](2);
secondsAgos[0] = 1800;  // 30 minutes ago
secondsAgos[1] = 0;      // now
(int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 1800);
```

---

## Vulnerability 2: Sandwich Attacks (MEV)

### Severity: Medium-High

### How It Works
1. Attacker bot monitors the mempool for a large pending swap
2. Front-runs with a same-direction swap — moves price against the victim
3. Victim's swap executes at a worse price
4. Attacker back-runs with a reverse swap — profits from the price impact

### Impact
- Victim receives fewer tokens than expected
- Value extracted goes to the MEV bot, not to LPs
- Estimated that over 12% of Ethereum AMM transactions are sandwich attacks

### What To Look For (In Protocol Code)
- No slippage protection: `amountOutMin = 0` in swap calls
- Router functions that don't enforce deadline or minimum output
- Auto-compounding vaults that swap with no slippage protection on harvest
- Governance or treasury operations that do large swaps without MEV protection

### What To Look For (In AMM Implementation)
- No `deadline` parameter on swap functions
- No minimum output amount enforcement
- Missing `require(amountOut >= amountOutMin)` check

---

## Vulnerability 3: LP Share Dilution / First Liquidity Provider Attack

### Severity: High

### The Problem (Analogous to ERC-4626 Inflation)
When a new pool has zero liquidity, the first LP's share calculation has the same integer rounding issue as vault inflation. An attacker can:
1. Add minimal liquidity (1 wei of each token) to get 1 LP share
2. Donate a large amount of tokens directly to the pool
3. Next LP provider's share calculation rounds to 0

### Uniswap V2 Mitigation
Uniswap V2 burns the first `MINIMUM_LIQUIDITY` (1000 wei) of LP tokens to the zero address on pool creation. This ensures `totalSupply` is never trivially small.

```solidity
if (_totalSupply == 0) {
    liquidity = Math.sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
    _mint(address(0), MINIMUM_LIQUIDITY);  // Dead shares
}
```

### What To Look For
- Custom AMM without minimum liquidity lock on first deposit
- Fork of Uniswap V2 that removed the `MINIMUM_LIQUIDITY` constant
- Pool creation flow where anyone can be the first depositor without restrictions

---

## Vulnerability 4: sqrt Precision Issues

### Severity: Medium

### The Problem
LP token minting often uses `sqrt(amount0 * amount1)`. The square root of a product of two large numbers can overflow `uint256` before the sqrt is taken, or lose precision for small values.

### What To Look For
- `amount0 * amount1` can overflow uint256 when both are large (e.g., >1e38 each)
- Custom sqrt implementation that is imprecise for small values
- No check that `liquidity > 0` after sqrt calculation (could round to 0)

### Safe Pattern
```solidity
// Use a battle-tested sqrt (e.g., OpenZeppelin Math.sqrt or Solmate)
// Check for overflow before multiplication
require(amount0 <= type(uint256).max / amount1, "overflow");
uint256 liquidity = Math.sqrt(amount0 * amount1);
require(liquidity > 0, "insufficient liquidity minted");
```

---

## Vulnerability 5: Reentrancy in LP Operations

### Severity: High

### The Problem
AMM contracts that interact with arbitrary tokens (especially tokens with hooks like ERC-777 or tokens with callbacks) are vulnerable to reentrancy. An attacker can reenter during a swap or liquidity operation to manipulate reserves or drain funds.

### Classic Pattern
1. Token with transfer hook (ERC-777) calls back to attacker contract
2. During callback, attacker calls another pool function (swap, removeLiquidity)
3. Pool state is inconsistent mid-operation — attacker extracts value

### What To Look For
- No reentrancy guard on swap, addLiquidity, removeLiquidity
- Pools that accept arbitrary ERC-20 tokens without excluding hookable tokens
- State updates AFTER external calls (violating Checks-Effects-Interactions)

---

## Vulnerability 6: Insecure Fee Accounting

### Severity: Medium

### Common Mistakes
- Fee accumulation uses `balanceOf` snapshots that can be manipulated by direct token transfers
- Fee-on-transfer tokens cause actual received amount to differ from expected, breaking fee math
- Concentrated liquidity (V3-style) fee calculations have precision loss in tick math

### What To Look For
- `protocolFee = balance - lastKnownBalance` pattern (manipulable via donation)
- Fees computed using division-before-multiplication
- No handling for tokens that don't transfer the full amount

---

## Audit Checklist for AMM Contracts

1. [ ] Does ANY external protocol use this AMM's spot price as an oracle? If yes: Critical.
2. [ ] Is there `MINIMUM_LIQUIDITY` burned on first deposit to prevent LP share inflation?
3. [ ] Do all swap functions enforce `amountOutMin` and `deadline`?
4. [ ] Is there a reentrancy guard on all state-modifying functions?
5. [ ] Does the sqrt implementation handle edge cases (overflow, rounding to 0)?
6. [ ] Is the pool tested with fee-on-transfer and rebasing tokens?
7. [ ] Are LP tokens safe from inflation attacks (analogous to ERC-4626 vault inflation)?
8. [ ] Does the protocol have MEV protection guidance for integrators?
9. [ ] Is the constant product invariant `k` checked to never decrease after swaps (accounting for fees)?
10. [ ] Are there integration tests with flash loans that attempt price manipulation?
