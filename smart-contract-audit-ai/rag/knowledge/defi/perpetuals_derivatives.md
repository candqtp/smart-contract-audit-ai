# Perpetual Futures and Derivatives Vulnerabilities

## Architecture Overview
Perpetual protocols (GMX, dYdX, Gains, Hyperliquid) allow leveraged trading without expiry. Key components:
- **Funding rate**: periodic payment between longs and shorts to keep price near index
- **Mark price**: used for PnL and liquidation (usually oracle-based)
- **Margin**: collateral posted to cover potential losses
- **Insurance fund**: absorbs bad debt when positions go deeply negative

## Vulnerability 1: Funding Rate Manipulation

```solidity
// VULNERABLE — funding rate manipulable by one side taking dominant position
// Funding: longs pay shorts (or vice versa) every 8 hours based on skew

// Attack: if attacker controls >50% of open interest on one side:
// 1. Take massive long position → funding rate skews to pay shorts
// 2. Also take massive short position (separate account)
// 3. Shorts receive massive funding payments from longs
// 4. Net: extract funding payments from smaller traders

// Real example: Perpetual Protocol v1 funding manipulation
// Attacker pushed one side to 90%+ dominance, extracted funding

// Mitigation: funding rate caps
uint256 constant MAX_FUNDING_RATE = 0.01e18;  // 1% max per hour

function calculateFundingRate(int256 skew) internal pure returns (int256) {
    int256 rate = skew * FUNDING_SENSITIVITY;
    // Clamp to max
    if (rate > int256(MAX_FUNDING_RATE)) rate = int256(MAX_FUNDING_RATE);
    if (rate < -int256(MAX_FUNDING_RATE)) rate = -int256(MAX_FUNDING_RATE);
    return rate;
}
```

## Vulnerability 2: Price Impact Calculation Allows Free Trading

```solidity
// VULNERABLE — buy then sell in same block, rounding difference is free money
// Or: price impact calculation uses integer division with exploitable rounding

function getPriceImpact(uint256 size, uint256 poolSize) public pure returns (uint256 slippage) {
    // slippage = (size / poolSize)^2 * BASE_PRICE
    uint256 ratio = size * 1e18 / poolSize;
    slippage = ratio * ratio / 1e18;  // precision loss here
    // For small size: slippage rounds to 0 → free trades of any size
}

// Attack: trade 0.001% of pool in one direction repeatedly
// Each trade has 0 slippage (rounds to 0)
// Accumulate position → large exposure with no cost
// Market moves → profit

// FIXED — minimum slippage floor
slippage = max(ratio * ratio / 1e18, MIN_SLIPPAGE);
```

## Vulnerability 3: Liquidation via Market Manipulation (vs Oracle Price)

```solidity
// VULNERABLE — mark price comes from a manipulable on-chain source
// Attacker can force-liquidate any leveraged position

// Attack:
// 1. Identify target: large leveraged long with tight liquidation price
// 2. Flash loan large amount, dump on spot market
// 3. Mark price drops temporarily (if using spot-based oracle)
// 4. Target's position is now liquidatable
// 5. Liquidate target → receive liquidation bonus
// 6. Repay flash loan, buy back
// Net: extract liquidation bonus + spot trade profit

// Mitigation: mark price must be resistant to manipulation
// Use TWAP, Chainlink, or Pyth — NOT spot AMM price
// Add liquidation price buffer ("liquidation gap")
```

## Vulnerability 4: Negative PnL Exceeds Margin (Bad Debt)

```solidity
// VULNERABLE — position can go deeply negative, insurance fund drained
// Happens during: flash crash, oracle failure, cascading liquidations

// Example: ETH at $2000, trader long 100 ETH with $10,000 margin (20x leverage)
// ETH crashes to $1800 instantly (gap down via oracle failure)
// PnL = 100 × ($1800 - $2000) = -$20,000
// Margin: $10,000 — not enough! Bad debt: $10,000

// Protocol handles this by:
// 1. Closing at market price (slippage makes it worse)
// 2. Insurance fund absorbs shortfall
// 3. If insurance fund drained: socialize losses to LPs/depositors

// Audit focus: Is insurance fund adequately capitalized?
// What leverage limits are in place?
// What's the maximum per-block price movement the protocol can handle?
```

## Vulnerability 5: Unrealized PnL Withdrawal Before Settlement

```solidity
// VULNERABLE — trader withdraws margin while position has large unrealized gains
// If market reverses before settlement, protocol may not have enough to pay
// (Protocol counted unrealized gains as liquid)

function withdrawMargin(uint256 amount) external {
    uint256 margin = getMargin(msg.sender);
    uint256 unrealizedPnL = getUnrealizedPnL(msg.sender);  // could be large positive
    // VULNERABLE: allows withdrawal up to margin + unrealized PnL
    require(amount <= margin + unrealizedPnL, "Insufficient margin");
    // Unrealized gains not yet settled — if price reverses, protocol can't pay others
}

// FIXED — only allow withdrawal against settled/realized balance
// Unrealized PnL only counts for maintenance margin, not for withdrawal
```

## Vulnerability 6: Position Size Limits Not Enforced

```solidity
// VULNERABLE — no per-user or global open interest cap
// Large position can overwhelm liquidity pool on close

// Example: $100M liquidity pool, user opens $80M long position
// When user closes: pool must pay $80M × (exit_price - entry_price)
// If position is profitable: pool may not have enough liquidity to pay PnL
// Protocol admits PnL payment at a worse price than mark → trader loss

// Mitigation: open interest cap per market
uint256 public maxNetOpenInterest;
uint256 public currentLongOI;
uint256 public currentShortOI;

function openPosition(bool isLong, uint256 size) external {
    if (isLong) {
        require(currentLongOI + size <= maxNetOpenInterest, "OI cap exceeded");
        currentLongOI += size;
    }
    // ...
}
```

## Vulnerability 7: Funding Rate Accounting Error

```solidity
// VULNERABLE — funding payments not properly settled before position close
// Trader opens position → funding accumulates unpaid → trader closes
// Net funding debt not deducted from PnL → trader receives too much

function closePosition(uint256 positionId) external {
    Position storage pos = positions[positionId];
    int256 pnl = calculatePnL(pos);
    // MISSING: settle accumulated funding before PnL calculation
    int256 fundingOwed = calculatePendingFunding(pos);
    // If fundingOwed not subtracted from pnl, trader escapes funding payment
    uint256 payout = uint256(pnl - fundingOwed);  // correct
    // VULNERABLE:
    // uint256 payout = uint256(pnl);  // ignores funding
}
```

## Vulnerability 8: Insurance Fund Griefing

```solidity
// Insurance fund grows from liquidation fees
// VULNERABLE — attacker can drain insurance fund through targeted bad debt creation

// Attack:
// 1. Open large position near maximum leverage
// 2. Self-liquidate OR wait for price to move 1%
// 3. Create position with bad debt = insurance fund contribution per liquidation
// 4. Repeat thousands of times
// Net: each iteration extracts slightly more than it costs (bonus > loss)

// Mitigation: minimum margin requirements high enough that single positions
// don't create bad debt exceeding their insurance fund contribution
```

## Code4rena/Immunefi Perpetuals Findings

```
CRITICAL:
1. Funding rate not applied before position close → funding avoided
2. Liquidation uses manipulable spot price → targeted liquidation
3. PnL withdrawal counted against unrealized profits → bank run possible
4. ADL (auto-deleveraging) triggers wrong user's position

HIGH:
1. Position size rounding allows tiny positions that accumulate to avoid minimums
2. Funding rate direction inverted in code (bug in sign)
3. Margin requirement bypassed via flash loan during same-block open/close
4. Oracle circuit breaker freezes liquidation — bad positions accumulate

MEDIUM:
1. Fee on close not applied for emergency liquidations
2. Funding payment distributed only to current holders — JIT funding extraction
```

## Detection Signals
- Funding rate with no cap (can be driven to extreme values)
- Price impact formula with integer division that rounds to 0 for small trades
- Liquidation function uses spot AMM price
- `withdrawMargin` allowing withdrawals against unrealized PnL
- No open interest caps per market
- `closePosition` not settling pending funding before PnL calculation
- Insurance fund balance not checked before promising payout

## Severity Guide
- Funding not settled before close (free leverage): **High**
- Mark price from manipulable spot: **Critical**
- Unrealized PnL withdrawable (insolvency risk): **High/Critical**
- No OI caps (liquidity pool overwhelmed): **High**
- Funding rate manipulation with no cap: **High**
- Insurance fund drain via bad debt loop: **High**
