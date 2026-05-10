# Stablecoin Integration Vulnerabilities

## Tags
stablecoin, depeg, oracle, USDC, USDT, DAI, blacklist, liquidation, price-assumption, freeze, transfer-revert

## Overview
Protocols that integrate stablecoins often make dangerous assumptions: that the price is always exactly $1, that transfers always succeed, and that balances never change unexpectedly. Each of these assumptions has been violated in production, leading to hundreds of millions in losses.

---

## Vulnerability 1: Hardcoded $1 Price Assumption

### Severity: Critical

### The Problem
Many protocols hardcode stablecoin price as 1e18 (or 1e6, 1e8 depending on decimals) without consulting an oracle. During a depeg event, this creates arbitrage opportunities and bad debt.

### Historical Precedent
- USDC depegged to $0.88 in March 2023 during the Silicon Valley Bank crisis
- DAI depegged simultaneously because 40% of its collateral was in USDC
- UST collapsed from $1 to near $0 in May 2022

### Attack Scenario
1. Protocol hardcodes USDC = $1.00
2. USDC depegs to $0.90 on open market
3. Attacker buys USDC at $0.90 on a DEX
4. Deposits into protocol which credits it at $1.00 face value
5. Borrows $0.99 worth of ETH against the $0.90 USDC
6. Protocol now holds undercollateralized debt

### What To Look For
- Any constant like `STABLECOIN_PRICE = 1e18` or `1e8`
- Price feeds that return a hardcoded value for stablecoins
- Lending protocols that skip oracle checks for "stable" assets
- Liquidation logic that assumes collateral value doesn't drop below a threshold

### Secure Pattern
```solidity
// Always use a price feed, even for stablecoins
uint256 usdcPrice = chainlinkOracle.getPrice(USDC_FEED);
require(usdcPrice > MIN_PRICE_THRESHOLD, "Stablecoin depeg detected");
// Use the actual price, not 1e8
uint256 collateralValue = usdcBalance * usdcPrice / PRICE_PRECISION;
```

---

## Vulnerability 2: Oracle Manipulation During Depeg Events

### Severity: High

### The Problem
During a depeg, oracle behavior becomes unpredictable:
- Chainlink may report a stale price if the depeg moves faster than heartbeat updates
- DEX-based oracles (TWAP) will lag behind the actual crash
- Some oracles have circuit breakers that freeze the price at a minimum — Chainlink's aggregators have `minAnswer` bounds that prevent reporting below a threshold

### Chainlink minAnswer Trap
```
If USDC crashes to $0.80 but Chainlink's feed has minAnswer = $0.95,
the oracle reports $0.95 even though the real price is $0.80.
A lending protocol relying on this feed allows borrowing against USDC at $0.95,
creating instant bad debt.
```

### What To Look For
- No stale price check: `(, int256 price,, uint256 updatedAt,) = feed.latestRoundData(); require(block.timestamp - updatedAt < MAX_STALENESS);`
- No minAnswer/maxAnswer bounds check on Chainlink feeds
- Single oracle source with no fallback
- No circuit breaker that pauses borrowing/minting during extreme price deviations

---

## Vulnerability 3: USDC/USDT Blacklist and Freeze Risk

### Severity: High

### The Problem
USDC and USDT have blacklist functions at the smart contract level. Circle and Tether can freeze any address, making all transfers to/from that address revert. Over 700 USDT addresses have been frozen on Ethereum alone.

### Impact on DeFi Protocols
- **Lending pools**: If a pool address is blacklisted, no one can deposit or withdraw that stablecoin — protocol is bricked
- **Liquidity pools**: Blacklisted LP address means stuck liquidity, imbalanced pools
- **Collateral**: Frozen USDC used as collateral becomes worthless but the debt remains — instant bad debt
- **Bridges**: Frozen bridge address means all locked stablecoins become inaccessible on the destination chain

### What To Look For
- Protocol holds large amounts of a single blacklistable stablecoin with no fallback
- No handling for `transfer()` or `transferFrom()` reverting unexpectedly
- No contingency mechanism (governance pause, emergency withdrawal to alternative asset)
- Vaults or pools that would be completely bricked if their address were blacklisted

### Important Contract Details
```solidity
// USDC's FiatTokenV2.sol has:
mapping(address => bool) internal blacklisted;
modifier notBlacklisted(address _account) {
    require(!blacklisted[_account]);
    _;
}
// transfer() and transferFrom() both use this modifier
// If sender OR recipient is blacklisted, transaction reverts

// DAI, LUSD, RAI have NO blacklist functions — decentralized stablecoins
```

### Secure Pattern
```solidity
// Always wrap stablecoin transfers in try-catch or check return value
(bool success, ) = address(usdc).call(
    abi.encodeWithSelector(IERC20.transfer.selector, recipient, amount)
);
if (!success) {
    // Fallback: convert to another asset, or queue for later
    emit TransferFailed(recipient, amount);
}
```

---

## Vulnerability 4: Liquidation Logic Failures During Depeg

### Severity: Critical

### The Problem
When stablecoins are used as collateral in lending protocols, depeg events can trigger cascading liquidations. If the liquidation mechanism is not robust, it creates a death spiral.

### Failure Modes
- **Oracle lag**: Price feed reports $0.99 while market is at $0.88 — liquidations don't trigger in time, creating bad debt
- **Liquidation assumes stable value**: Bot calculates profit based on $1 value, but actual market value is lower — liquidation is unprofitable, no one executes it
- **Stablecoin-stablecoin pairs**: Protocol assumes DAI/USDC is always 1:1 and doesn't run liquidations on these pairs — during a simultaneous depeg, positions become undercollateralized with no mechanism to clear them
- **Auction failures**: During mass liquidations, not enough capital to fill auctions — protocol takes on bad debt

### What To Look For
- Lending protocols with stablecoin-stablecoin pairs that have no liquidation mechanism
- Hardcoded liquidation thresholds that don't account for depeg scenarios
- No bad debt socialization mechanism (protocol surplus buffer, insurance fund)
- Liquidation incentives calculated assuming stable price

---

## Vulnerability 5: Approval and Transfer Quirks

### Severity: Medium

### USDT Approval Bug
USDT's `approve()` function requires the current allowance to be 0 before setting a new non-zero value. Failing to reset to 0 first causes the transaction to revert.

```solidity
// FAILS with USDT if current allowance != 0
usdt.approve(spender, newAmount);

// WORKS — reset first
usdt.approve(spender, 0);
usdt.approve(spender, newAmount);

// BEST — use SafeERC20
SafeERC20.forceApprove(usdt, spender, newAmount);
```

### Transfer Return Value
- USDT's `transfer()` does not return `bool` on some chains — using the standard IERC20 interface will revert
- Always use OpenZeppelin's `SafeERC20` library for stablecoin transfers

---

## Audit Checklist for Stablecoin Integrations

1. [ ] Does the protocol hardcode any stablecoin price? If yes: Critical finding.
2. [ ] Are oracle price feeds used for stablecoins, with staleness checks and minAnswer bounds?
3. [ ] Is there a circuit breaker that pauses operations during extreme depeg events?
4. [ ] How does the protocol handle blacklisted/frozen addresses? Would a freeze brick the contract?
5. [ ] Are USDT approval quirks handled (approve to 0 first, or SafeERC20)?
6. [ ] Does the protocol use `SafeERC20.safeTransfer` for all stablecoin transfers?
7. [ ] Can stablecoin-collateralized positions be liquidated during a depeg?
8. [ ] Is there a bad debt socialization mechanism (surplus buffer, insurance fund)?
9. [ ] Does the protocol diversify across stablecoins or depend on a single one?
10. [ ] Are there integration tests simulating depeg scenarios (e.g., USDC at $0.90)?
