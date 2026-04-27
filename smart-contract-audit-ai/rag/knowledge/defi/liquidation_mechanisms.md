# Liquidation Mechanism Vulnerabilities

## Liquidation Fundamentals
Liquidation protects lending protocols from insolvency. When a borrower's health factor drops below 1, liquidators repay their debt and receive their collateral at a discount (the liquidation bonus). Bugs in liquidation logic = bad debt, user losses, or protocol insolvency.

## Vulnerability 1: Liquidation Can Be Blocked by Dust Positions

```solidity
// VULNERABLE — small borrow positions impossible to liquidate profitably
// If gas cost > liquidation bonus, no rational liquidator participates

// Example: user borrows $5 of USDC against $6 of ETH
// Price drops: ETH now worth $4.50 → undercollateralized
// Liquidation bonus = 5% of $5 = $0.25
// Gas cost for liquidation = $10+
// Net: liquidator LOSES $9.75 per liquidation
// Result: position never liquidated → bad debt accumulates

// FIXED — enforce minimum borrow amount
uint256 public minBorrowAmount = 100e6;  // $100 minimum

function borrow(uint256 amount) external {
    require(amount >= minBorrowAmount, "Below minimum borrow");
    // ...
}
```

## Vulnerability 2: Partial Liquidation Leaves Dust

```solidity
// VULNERABLE — liquidator can repay partial amount, leaving behind tiny position
// After partial liquidation, remaining position may be below profitable liquidation threshold
// Creates permanent bad debt from valid positions

// Partial liquidation math:
// Borrow: $1000 USDC, Collateral: $900 ETH (health factor 0.9)
// Liquidator repays $500 → receives $500 * 1.05 = $525 of ETH
// Remaining: $500 debt, $375 ETH collateral
// Health factor: 0.75 — still unhealthy but now too small to liquidate profitably

// FIXED — if remaining position would be below threshold, force full liquidation
function liquidate(address borrower, uint256 repayAmount) external {
    uint256 totalDebt = getDebt(borrower);
    uint256 remainingAfterLiquidation = totalDebt - repayAmount;
    if (remainingAfterLiquidation < MIN_BORROW) {
        // Force full liquidation — take entire position
        repayAmount = totalDebt;
    }
    // execute liquidation with adjusted repayAmount
}
```

## Vulnerability 3: Unhealthy Position Cannot Be Liquidated (Griefing)

```solidity
// VULNERABLE — borrower is a smart contract that reverts on collateral receipt
// Liquidator calls liquidate() → contract tries to send collateral → borrower.receive() reverts

contract MaliciousBorrower {
    receive() external payable {
        revert("No ETH");  // or uses all gas in receive()
    }
}
// Borrow against ETH collateral → fall below health factor → liquidation always reverts

// FIXED — use pull model for collateral return, or whitelist EOA-only borrowers
// OR: store pending liquidations, let liquidator claim separately
mapping(address => uint256) public pendingCollateral;

function liquidate(address borrower, uint256 repayAmount) external {
    // ... verify liquidation is valid ...
    uint256 seizedCollateral = calculateSeize(repayAmount);
    accountCollateral[borrower] -= seizedCollateral;
    pendingCollateral[msg.sender] += seizedCollateral;  // don't transfer — let them pull
}

function claimCollateral() external {
    uint256 amount = pendingCollateral[msg.sender];
    require(amount > 0);
    pendingCollateral[msg.sender] = 0;
    (bool ok,) = payable(msg.sender).call{value: amount}("");
    require(ok);
}
```

## Vulnerability 4: Self-Liquidation Profiting From Bonus

```solidity
// VULNERABLE — borrower can liquidate themselves and pocket the liquidation bonus
// Normally: liquidator is a third party who receives bonus as incentive
// Attack: user creates two accounts (or uses flash loan)
// Account A: has undercollateralized position
// Account B: repays Account A's debt, receives A's collateral + bonus
// Net: user extracts liquidation bonus from protocol at no cost

// Mathematical condition for profitability:
// (collateralReceived × price) - debtRepaid > 0
// i.e., collateralReceived × price = debtRepaid × (1 + bonusFactor)
// Self-liquidation extracts bonusFactor% from protocol

// Mitigation: self-liquidation acceptable if it restores health
// The protocol designs liquidation bonus to come from the liquidated user, not protocol
// Check: is liquidation bonus larger than protocol can sustainably offer?

// CRITICAL BUG variation: bonus paid from protocol reserves, not user's collateral
// Then self-liquidation is a direct protocol drain
```

## Vulnerability 5: Oracle Price Used for Liquidation Different From Borrow

```solidity
// VULNERABLE — using spot price for liquidation, TWAP for borrowing
// During volatile period: spot price drops faster than TWAP
// Healthy positions (by TWAP) get liquidated by spot price check

function isLiquidatable(address borrower) public view returns (bool) {
    uint256 debtValue = getDebt(borrower);
    uint256 collateralValue = getCollateral(borrower) * getSpotPrice();  // spot price!
    return collateralValue < debtValue * LIQUIDATION_THRESHOLD / 1e18;
}
// During flash crash: spot drops 30%, TWAP only drops 5%
// Millions in "healthy" positions get liquidated — users lose to illegitimate liquidations

// FIXED — use same oracle for both, with grace period after oracle price change
```

## Vulnerability 6: Liquidation Bonus Calculation Rounds in Wrong Direction

```solidity
// VULNERABLE — bonus rounds DOWN in favor of liquidator, reducing protocol solvency
function calculateSeizeTokens(
    uint256 repayAmount,
    uint256 collateralPrice,
    uint256 debtPrice,
    uint256 liquidationIncentive
) internal pure returns (uint256 seizeTokens) {
    // Formula: seizeTokens = repayAmount × debtPrice × incentive / collateralPrice
    seizeTokens = repayAmount * debtPrice * liquidationIncentive / collateralPrice;
    // Division rounds DOWN → liquidator gets slightly less
    // This means collateral left in account → not liquidated fully
    // Leaves fractional bad debt
    // Should round UP to ensure full liquidation
}
```

## Vulnerability 7: Liquidation During Paused State

```solidity
// VULNERABLE — protocol paused but liquidations still allowed
// If price oracle is compromised/stale → protocol pauses new borrows
// BUT liquidations continue using stale price → users liquidated incorrectly

function liquidate(address borrower, ...) external {
    // No check: require(!paused) — should liquidations be allowed when paused?
    // OR: require(!liquidationsPaused) — separate pause for liquidations
}

// Common design: separate guardian flags
bool public borrowPaused;
bool public liquidationPaused;
bool public repayPaused;

// During oracle failure: pause BOTH borrows AND liquidations
// During normal market stress: pause borrows, allow liquidations
```

## Vulnerability 8: Max LTV Allows Zero-Cost Liquidation

```solidity
// If LTV is 100% (collateral factor = 1.0):
// User borrows exactly the value of their collateral
// Any price decline → immediately liquidatable
// Liquidation bonus comes entirely from protocol reserves (user has no equity)
// Attacker can loop: borrow → collateral drops 1% → liquidate self → repeat

// ALSO: LTV close to liquidation threshold (e.g., LTV=90%, liquidation=95%)
// 5% buffer — any 5% price drop → liquidation
// Flash crash -10% → 50%+ of all positions liquidated simultaneously → bad debt cascade

// Recommendation: LTV ≤ 75% for volatile assets, 85% for stablecoins
// Liquidation threshold 10-15% above LTV for buffer
```

## Code4rena/Sherlock Liquidation Findings

```
CRITICAL:
1. liquidate() has no reentrancy guard — ERC777 collateral allows double-liquidation
2. Health factor calculation uses wrong decimals — all healthy positions liquidatable
3. Liquidation bonus exceeds collateral — liquidator can extract from protocol treasury

HIGH:
1. Dust positions create permanent bad debt
2. Borrower contract can grief liquidation by reverting in receive()
3. Self-liquidation extracts bonus when bonus is paid by protocol
4. Liquidation front-running: MEV bots extract 100% of liquidation bonus
5. Close factor of 100% forces full liquidation before partial is tried

MEDIUM:
1. Healthy positions liquidatable during price feed delays
2. Liquidation doesn't update interest index before executing
3. Attacker can liquidate in one block, preventing price recovery for healthy positions
```

## Detection Signals
- No minimum borrow amount
- Partial liquidation with no check on remaining dust
- Liquidation calls `transfer`/`safeTransfer` to borrower (should be pull model)
- Same account can be both borrower and liquidator with no restriction
- Spot price used for liquidation threshold, TWAP for borrow limit
- Collateral factor > 85% for volatile assets
- No reentrancy guard on `liquidate()` function
- Liquidation bonus not capped at remaining collateral

## Severity Guide
- Reentrancy in liquidation: **Critical**
- Health factor decimal error: **Critical**
- Self-liquidation extracting protocol funds: **High/Critical**
- Dust positions → permanent bad debt: **High**
- Wrong oracle for liquidation: **High**
- Liquidation blocked by contract receiver revert: **High**
- No minimum borrow amount: **Medium**
