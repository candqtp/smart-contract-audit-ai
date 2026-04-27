# Lending and Borrowing Protocol Vulnerabilities

## Architecture Reference (Compound/Aave Model)
- Users deposit collateral → receive cTokens/aTokens representing their share
- Users borrow against collateral up to Loan-to-Value (LTV) ratio
- Interest accrues per block, stored as index
- Liquidation: if health factor < 1, liquidators repay debt and seize collateral at discount

## Vulnerability 1: Interest Accrual Not Called Before State Read

```solidity
// VULNERABLE — borrow balance stale if interest not accrued first
// (Code4rena finding — common in Compound forks)
function getAccountLiquidity(address account) public view returns (uint256 liquidity, uint256 shortfall) {
    // Reads borrowBalance WITHOUT accruing interest first
    uint256 borrowBalance = accountBorrows[account].principal;  // stale!
    // Real balance = principal × (currentIndex / indexAtBorrow) — but index not updated
    // Protocol thinks user owes less than they do → allows over-borrowing
}

// FIXED — always accrue before reading
function getAccountLiquidity(address account) public returns (uint256, uint256) {
    accrueInterest();  // update borrowIndex first
    uint256 borrowBalance = borrowBalanceCurrent(account);  // uses current index
    // ...
}
```

## Vulnerability 2: Borrow Rate Manipulation via Single Large Deposit/Withdrawal

```solidity
// Utilization rate: borrows / (borrows + supplies)
// Interest rate = f(utilization) — higher utilization = higher rate
// VULNERABLE: large whale can manipulate utilization to drain borrowers via rate spike

// Attack: Whale has large borrow position
// 1. Whale withdraws all supply → utilization jumps to ~100%
// 2. Interest rate spikes to max (e.g., 1000% APY)
// 3. Borrowers accrue massive interest in a few blocks
// 4. Whale's borrow is now worth much more in collateral terms OR
//    regular borrowers get liquidated immediately
// 5. Whale re-deposits → rate normalizes

// Mitigation: borrow rate caps (max rate per block)
// Mitigation: interest rate model with kink — above kink, rate rise is bounded
uint256 constant BORROW_RATE_MAX_MANTISSA = 0.0005e16;  // ~146% APY maximum
```

## Vulnerability 3: Incorrect Exchange Rate on First Deposit (ERC4626 Pattern)

```solidity
// cToken exchange rate = (totalCash + totalBorrows - totalReserves) / totalSupply
// On empty market: both totalCash and totalSupply are 0

// VULNERABLE — division by zero OR first depositor sets arbitrary exchange rate
function exchangeRateCurrent() public returns (uint256) {
    if (totalSupply == 0) {
        return initialExchangeRate;  // hardcoded — OK
    }
    return (getCash() + totalBorrows - totalReserves) * 1e18 / totalSupply;
}

// Real attack (ERC4626 variant):
// 1. Deposit 1 wei → receive 1 share
// 2. Donate 1e18 tokens directly to contract (not via deposit)
// 3. exchangeRate = (1e18 + 1 wei) / 1 share ≈ 1e18 per share
// 4. Next depositor: 1e18 tokens → floor(1e18 / 1e18) = 1 share (maybe)
//    Or: 1e18 - 1 tokens → 0 shares (rounds to zero) — attacker steals

// FIXED (OZ ERC4626 virtual offset):
// Add virtual shares: pretend 1000 shares always exist
function totalAssets() public view returns (uint256) {
    return super.totalAssets() + 1;  // virtual asset
}
function totalSupply() public view returns (uint256) {
    return super.totalSupply() + 1000;  // virtual shares
}
```

## Vulnerability 4: Health Factor Calculation Uses Wrong Price

```solidity
// VULNERABLE — uses different oracle for liquidation vs borrowing
// Code4rena: multiple findings where borrow uses TWAP but liquidation uses spot
function canLiquidate(address borrower) public view returns (bool) {
    uint256 collateralValue = getCollateralValue(borrower);  // uses TWAP (slow to update)
    uint256 debtValue = getDebtValue(borrower);              // uses spot (instant)
    return collateralValue < debtValue * LIQUIDATION_THRESHOLD / 100;
}
// During price drop: spot price falls fast, TWAP lags
// Debt value (spot) rises relative to collateral (TWAP) → false liquidation signal
// Or opposite: TWAP doesn't reflect spike → under-liquidated positions

// FIXED — use same oracle for both, with appropriate lag
```

## Vulnerability 5: Liquidation Incentive Creates Bad Debt

```solidity
// Liquidation bonus: liquidator repays debt and receives collateral + bonus (e.g., 5%)
// VULNERABLE: if collateral drops below debt + bonus, no liquidator is profitable
// Position becomes "bad debt" — protocol is insolvent

// Example: ETH crashes 50% in one block (or sequencer down)
// - User had 150% collateralization ratio
// - Price drops to 60% of original → 90% collateralization
// - Liquidation bonus = 5% → liquidator pays $100 debt, gets $94.5 of collateral ($99*95%)
//   Wait: collateral = $90, debt = $100 → position already bad debt — no liquidation
//   Protocol is stuck with $10 bad debt per position

// Mitigations:
// 1. Conservative LTV ratios (never allow > 75% LTV for volatile assets)
// 2. Liquidation at higher health factor threshold (0.85 not 1.0)
// 3. Bad debt socialization — spread across suppliers
// 4. Insurance fund for bad debt absorption
```

## Vulnerability 6: Reentrancy in Liquidation (Compound Fork)

```solidity
// VULNERABLE — ERC777 token as collateral, liquidation triggers callback
function liquidateBorrow(
    address liquidator,
    address borrower,
    uint256 repayAmount,
    CToken cTokenCollateral
) external {
    require(repayAmount > 0);
    // Repay debt — transfers ERC777 tokens (triggers tokensReceived on liquidator)
    doTransferIn(underlying, liquidator, repayAmount);
    // State not yet updated — liquidator can re-enter here
    seizeInternal(msg.sender, liquidator, borrower, seizeTokens);
    // Update borrower state AFTER transfers — reentrancy window
    accountBorrows[borrower].principal = accountBorrows[borrower].principal - repayAmount;
}
```

## Vulnerability 7: Unlimited Borrow via Recursive Collateralization

```solidity
// VULNERABLE (self-borrowing loop): if protocol allows borrowing the same token as collateral
// 1. Deposit 100 USDC → get cUSDC
// 2. Use cUSDC as collateral to borrow 80 USDC (80% LTV)
// 3. Re-deposit 80 USDC → get more cUSDC
// 4. Borrow 64 USDC... repeat
// Total leverage: ~5x with 80% LTV
// Risk: this is often INTENDED (leverage loops) but without position limits,
// a price drop liquidates multiple layers simultaneously → bad debt

// Most protocols intentionally allow this — but audit should:
// Verify liquidation can unwind recursive positions
// Verify fee accumulation doesn't allow unbounded recursion
// Verify not all steps in same tx (could be free leverage)
```

## Vulnerability 8: Missing Pause on Borrowing During Market Stress

```solidity
// When external oracle fails or price deviates too much,
// protocol should pause new borrows/withdrawals

// VULNERABLE — no circuit breaker
function borrow(uint256 amount) external {
    // No check if market is in distress
    // No check if oracle data is fresh
    // Borrows continue even during market crashes
}

// FIXED — guardian can pause individual market operations
bool public borrowGuardianPaused;

function borrow(uint256 amount) external {
    require(!borrowGuardianPaused, "Borrow paused");
    // ...
}
```

## Code4rena Common Findings in Lending Protocols

```
HIGH severity patterns found repeatedly:
1. accrueInterest() not called before borrowBalance check — stale debt
2. Liquidation can be blocked if borrower's account is a contract that reverts
3. Collateral factor set to 100% on some asset — unlimited leverage
4. Bad debt not tracked — protocol claims solvency it doesn't have
5. Interest index overflow at extreme rates over long periods

MEDIUM severity patterns:
1. Missing slippage on collateral liquidation (liquidator front-ran)
2. Dust amounts bypass minimum borrow check via fee accounting
3. Market pausing doesn't prevent existing borrows from growing via interest
4. Borrow cap and supply cap not enforced atomically — race condition
```

## Detection Signals
- `borrowBalance` read without preceding `accrueInterest()`
- `totalSupply() == 0` path in exchange rate calculation
- Different oracle used for health check vs liquidation trigger
- `LTV >= 100%` for any asset in config
- No `borrowGuardianPaused` or equivalent emergency stop
- ERC777 or ERC721 collateral without reentrancy guard in liquidation
- No bad debt tracking variable

## Severity Guide
- Stale interest index allows over-borrowing: **High**
- ERC4626 first depositor inflation: **High/Critical**
- Liquidation creates bad debt (LTV too high): **High**
- Wrong oracle for liquidation: **High**
- Reentrancy in liquidation via ERC777 collateral: **Critical**
- No circuit breaker on oracle failure: **Medium**
