# Flash Loan Attack Patterns

## Tags
flash-loan, attack, reentrancy, arbitrage, price-manipulation, uncollateralized, AAVE


## What is a Flash Loan
A flash loan borrows a large amount of tokens within a single transaction with no collateral, on the condition it is repaid before the transaction ends. Attackers use them to temporarily hold massive capital to manipulate prices or exploit vulnerabilities.

## Attack Pattern 1: Oracle Price Manipulation
```
1. Borrow 10M USDC via flash loan (Aave/Uniswap)
2. Dump tokens into AMM pool → crash spot price
3. Call vulnerable protocol that uses spot price as oracle
4. Protocol undervalues collateral → drain protocol
5. Repay flash loan + fee
Net profit: drained protocol funds
```

**Vulnerable oracle pattern:**
```solidity
// VULNERABLE — uses Uniswap spot price (manipulable in same tx)
function getPrice(address token) public view returns (uint) {
    (uint112 reserve0, uint112 reserve1,) = IUniswapPair(pair).getReserves();
    return reserve1 * 1e18 / reserve0;
}
```

**Fix — use TWAP:**
```solidity
// SAFE — time-weighted average price, expensive to manipulate
function getTWAP(address pair, uint period) external view returns (uint) {
    return IUniswapV3Pool(pair).observe(period);
}
```

## Attack Pattern 2: Governance Manipulation
```
1. Flash borrow governance tokens
2. Vote on malicious proposal (if snapshot taken in same block)
3. Proposal passes with borrowed voting power
4. Repay tokens
```
**Fix**: Use time-delayed governance with snapshot at proposal creation, not vote time.

## Attack Pattern 3: Liquidation Manipulation
Borrow to artificially move an account below liquidation threshold, liquidate for bonus, repay.

## Detection Signals
- `flashLoan`, `flashSwap`, `borrow` callbacks (`uniswapV2Call`, `executeOperation`)
- Price reads from `getReserves()` without TWAP
- Single-block governance snapshots
- `balanceOf(address(this))` used for pricing

## Severity: Critical
Flash loan attacks typically drain entire protocol TVL.
