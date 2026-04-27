# Oracle Manipulation — Advanced Patterns (Immunefi Critical/High)

## Why Oracles Are the #1 DeFi Attack Vector
Every protocol that prices assets uses an oracle. If the oracle can be moved faster than the protocol responds, the protocol can be drained. The flash loan democratized oracle attacks — no capital required, just code.

## Attack Class 1: Single-Block AMM Spot Price (Classic)

```solidity
// VULNERABLE — reads current reserves as price
function getAssetPrice(address token) public view returns (uint256) {
    (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
    return uint256(r1) * 1e18 / uint256(r0);
}

// Attack in one PTB/transaction:
// 1. Flash borrow 10M USDC from Aave
// 2. Swap all USDC → TOKEN on Uniswap (price of TOKEN skyrockets)
// 3. Call protocol — getAssetPrice() now returns 10x inflated price
// 4. Borrow/withdraw against inflated collateral
// 5. Swap TOKEN back to USDC (price normalizes)
// 6. Repay flash loan
// 7. Keep profit
```

## Attack Class 2: Low-Liquidity Pool Oracle

```solidity
// VULNERABLE — protocol uses a thinly-traded pool as oracle
// 1000 ETH of liquidity is easy to manipulate with a $500K flash loan
// Protocols must verify pool liquidity depth before trusting its price

// Attack: even TWAP is manipulable if pool is thin
// Cost to manipulate TWAP = (pool_liquidity × blocks_in_TWAP_window × gas)
// For a 1000 ETH pool with 30-min TWAP: ~$30K cost to manipulate
// If protocol has $10M TVL: profitable attack

// Mitigation: minimum liquidity threshold for oracle pools
// Chainlink or Pyth for production (liquidity requirements built in)
```

## Attack Class 3: Chainlink Oracle Freshness

```solidity
// VULNERABLE — stale Chainlink price accepted
function getPrice(address feed) public view returns (int256 price) {
    (, price,,,) = AggregatorV3Interface(feed).latestRoundData();
    // No staleness check — if Chainlink heartbeat is 1h and last update was 3h ago,
    // price could be significantly wrong
}

// FIXED — check freshness
function getPrice(address feed) public view returns (int256 price) {
    uint256 updatedAt;
    (, price,, updatedAt,) = AggregatorV3Interface(feed).latestRoundData();
    require(price > 0, "Invalid price");
    require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "Stale price");
    // MAX_PRICE_AGE should be slightly > feed's heartbeat (e.g., heartbeat=1h → MAX=1.1h)
}
```

## Attack Class 4: Multi-Block TWAP Manipulation (Sandwich Over Time)

```solidity
// TWAP (Time-Weighted Average Price) is the standard defense against single-block attacks
// BUT: if TWAP window is short AND pool liquidity is low, multi-block manipulation is viable

// Attack on 5-minute TWAP with thin pool:
// Block N:   Buy massive position → price spikes
// Blocks N+1 to N+30 (5 min): Hold position → TWAP accumulates inflated price
// Block N+30: Protocol uses TWAP price — still elevated
// Block N+31: Sell position + exploit protocol

// Defense: longer TWAP window (30 min minimum for high-value lending)
// + minimum pool liquidity requirement
// + circuit breaker: reject price if > X% deviation from 24h TWAP

// Uniswap V3 TWAP usage:
function getTWAP(address pool, uint32 secondsAgo) public view returns (uint256 price) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = secondsAgo;
    secondsAgos[1] = 0;
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(secondsAgo)));
    price = TickMath.getSqrtRatioAtTick(arithmeticMeanTick);
    // This is still manipulable with enough capital over secondsAgo window
}
```

## Attack Class 5: Oracle Price Decimal / Precision Error

```solidity
// Chainlink feeds have varying decimal places:
// ETH/USD: 8 decimals
// BTC/USD: 8 decimals
// Some feeds: 18 decimals

// VULNERABLE — wrong decimal assumption
function getCollateralValue(uint256 tokenAmount, address feed) public view returns (uint256) {
    (, int256 price,,,) = AggregatorV3Interface(feed).latestRoundData();
    // Assumes 18 decimals — but ETH/USD feed has 8 decimals
    return tokenAmount * uint256(price) / 1e18;
    // Result is 1e10 times too small — collateral massively undervalued
    // Or: WAD math conflicts — 18 decimal token × 8 decimal price = 26 decimal result
}

// FIXED — use feed's reported decimals
function getCollateralValue(uint256 tokenAmount, address feed) public view returns (uint256) {
    uint8 feedDecimals = AggregatorV3Interface(feed).decimals();
    (, int256 price,,,) = AggregatorV3Interface(feed).latestRoundData();
    // Normalize to 18 decimals
    uint256 normalizedPrice = uint256(price) * 10**(18 - feedDecimals);
    return tokenAmount * normalizedPrice / 1e18;
}
```

## Attack Class 6: L2 Sequencer Down — Stale Oracle on L2

```solidity
// On L2s (Arbitrum, Optimism): if the sequencer goes down,
// Chainlink price feeds stop updating
// When sequencer comes back, prices may be significantly stale
// A liquidation based on stale prices could be illegitimate

// Chainlink provides a Sequencer Uptime Feed for this
// VULNERABLE — no sequencer check
function isLiquidatable(address user) public view returns (bool) {
    uint256 price = getChainlinkPrice();  // stale if sequencer was down
    return getCollateralValue(user, price) < getDebt(user) * LIQUIDATION_THRESHOLD;
}

// FIXED — check sequencer uptime
address constant SEQUENCER_FEED = 0xFdB631F5EE196F0ed6FAa767959853A9F217697D;
uint256 constant GRACE_PERIOD = 3600;  // 1 hour after sequencer restart

function isSequencerUp() internal view returns (bool) {
    (, int256 answer, uint256 startedAt,,) = AggregatorV3Interface(SEQUENCER_FEED).latestRoundData();
    bool isUp = (answer == 0);
    if (!isUp) return false;
    return block.timestamp - startedAt > GRACE_PERIOD;
}
```

## Attack Class 7: Composite Oracle Price Path

```solidity
// Protocol needs TOKEN/USDC price but no direct feed exists
// Uses TOKEN/ETH × ETH/USDC (two hops)
// VULNERABLE: each hop has its own manipulation surface and staleness

function getTokenPrice(address token) public view returns (uint256) {
    uint256 tokenPerEth = getChainlinkPrice(TOKEN_ETH_FEED);
    uint256 ethPerUsdc = getChainlinkPrice(ETH_USDC_FEED);
    return tokenPerEth * ethPerUsdc / 1e18;
    // If either feed is stale/manipulated, final price is wrong
    // No validation that both feeds have fresh data
    // Multiplication can overflow if both are 18 decimal before normalization
}

// FIXED — check BOTH feeds for staleness, use checked math
function getTokenPrice(address token) public view returns (uint256) {
    (uint256 tokenPerEth, uint256 updatedAt1) = getPriceWithTimestamp(TOKEN_ETH_FEED);
    (uint256 ethPerUsdc, uint256 updatedAt2) = getPriceWithTimestamp(ETH_USDC_FEED);
    require(block.timestamp - updatedAt1 <= MAX_AGE, "Feed 1 stale");
    require(block.timestamp - updatedAt2 <= MAX_AGE, "Feed 2 stale");
    return tokenPerEth * ethPerUsdc / 1e18;  // ensure decimal normalization first
}
```

## Immunefi Critical Patterns Found Repeatedly

```
1. Lending protocol uses Uniswap V2 spot price → flash loan drain
   Seen: CREAM, Harvest Finance, Cheese Bank, bEarn

2. Chainlink feed staleness not checked → stale price exploited during high volatility
   Seen: Multiple lending protocols during ETH crashes

3. L2 sequencer downtime + liquidation → illegitimate liquidations
   Seen: Multiple Arbitrum/Optimism protocols

4. Low-liquidity pool used as price oracle → easy manipulation
   Seen: Indexed Finance ($16M), Rari Capital

5. Price oracle uses balanceOf() of pool contract
   Single transaction: donate tokens to pool → inflate "price"
   Seen: Inverse Finance, several Compound forks
```

## Detection Signals
- `getReserves()` used in any pricing function
- `balanceOf(pairAddress)` used for pricing
- No `updatedAt` check after `latestRoundData()`
- `price > 0` check missing (negative price accepted as large uint)
- Decimal conversion assuming fixed 18 decimals
- No sequencer uptime check on L2 deployments
- Single-block TWAP (secondsAgo = 0)
- Two-hop oracle path without independent freshness checks

## Severity Guide
- Spot price oracle on lending protocol: **Critical**
- Stale Chainlink price: **High/Critical** depending on what it prices
- L2 sequencer not checked: **High**
- Low-liquidity TWAP (thin pool): **High**
- Decimal mismatch in price calculation: **High**
- Two-hop oracle without staleness: **High**
