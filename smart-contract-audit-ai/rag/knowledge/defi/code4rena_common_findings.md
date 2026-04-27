# Code4rena Top Findings — Patterns Across Contests

## About Code4rena
Code4rena runs competitive audits. Wardens compete to find bugs; sponsors pay for the best findings. The public reports are the highest-signal source of real-world DeFi bugs. These patterns repeat across dozens of contests.

## Pattern 1: Unchecked Return of transferFrom (Medium → High depending on token)

Found in: nearly every contest that handles ERC20 tokens from user input

```solidity
// VULNERABLE — transferFrom return not checked, not using SafeERC20
function deposit(address token, uint256 amount) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    // Non-standard tokens (USDT, BNB, OMG) return false instead of reverting
    // Protocol records deposit even though tokens weren't received
    balances[msg.sender][token] += amount;
}

// Also found: depositing fee-on-transfer tokens
// 1000 PAXG sent → 990 PAXG received (1% fee)
// but 1000 recorded → 10 tokens created from thin air per deposit
```

## Pattern 2: Missing Input Validation on Critical Parameters

Found in: every single Code4rena contest — 30-40% of Medium findings

```solidity
// VULNERABLE — admin can set fee to 100%
function setFee(uint256 fee) external onlyOwner {
    fee_rate = fee;  // no upper bound
}

// VULNERABLE — zero address recipient for critical roles
function setTreasury(address treasury) external onlyOwner {
    _treasury = treasury;  // no address(0) check
}

// VULNERABLE — zero amount causes division by zero
function setRewardsDuration(uint256 duration) external onlyOwner {
    rewardsDuration = duration;  // duration = 0 → rewardRate = rewards / 0 → revert
}

// PATTERN: ANY admin setter without bounds is a finding
// Common bounds to check:
// - Fees: 0 < fee <= MAX_FEE (usually ≤ 10-20%)
// - Durations: > 0
// - Addresses: != address(0)
// - Thresholds: within protocol's valid range
```

## Pattern 3: Stale State Read Without Checkpoint Update

This pattern generates more High findings on Code4rena than any other single issue.

```solidity
// VULNERABLE — seen in reward contracts, lending, governance, vaults
// State read before updating accumulated value

// Reward contract variant (most common):
function earned(address account) public view returns (uint256) {
    return _balances[account] * (rewardPerToken() - userRewardPerTokenPaid[account]) / 1e18 + rewards[account];
}

// If rewardPerToken() hasn't been updated (no recent staking/withdrawal):
// earned() returns stale value — but this is by design (view function)
// The bug is when withdraw() or stake() changes balance WITHOUT calling updateReward first

function withdraw(uint256 amount) external {
    // MISSING: updateReward(msg.sender)
    _balances[msg.sender] -= amount;
    // Now balances changed but rewards not settled — rewards calculation wrong forever
}
```

## Pattern 4: First Depositor / Empty Pool Edge Case

Found in: ERC4626 vaults, liquidity pools, staking contracts — very frequently

```solidity
// VULNERABLE — division by zero or extreme precision loss when pool is empty

function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply();
    if (supply == 0) return assets;  // first depositor: 1:1 ratio
    return assets * supply / totalAssets();  // precision loss if totalAssets >> supply
    // OR: if totalAssets() is 0 (despite supply > 0 due to donation drain): divide by 0
}

// Code4rena High: protocol doesn't handle the case where
// all liquidity is withdrawn but rewards still accumulate
// Next depositor gets 0 shares (rounds to 0) or absurd shares
```

## Pattern 5: Incorrect Precision / Decimal Scaling

Very common Medium finding — about 1 per contest involving multi-token math

```solidity
// VULNERABLE — prices mixed with different decimal assumptions
// e.g., protocol assumes all prices are 18 decimal but Chainlink uses 8

function getCollateralUSD(uint256 amount, address feed) external view returns (uint256) {
    (, int256 price,,,) = AggregatorV3Interface(feed).latestRoundData();
    return amount * uint256(price) / 1e18;
    // If price has 8 decimals: 1 ETH ($2000) = 200000000000 (8 dec)
    // amount = 1e18 (18 dec ETH), price = 200000000000 (8 dec)
    // result = 1e18 * 2e11 / 1e18 = 2e11 = $200 (10 decimal places = wrong)
    // correct result: $2000 in 18 dec = 2000e18 — off by factor of 1e7
}
```

## Pattern 6: Reentrancy Via Low-Level Calls in Logic-Heavy Functions

Code4rena's #1 Critical — found in almost every DeFi protocol

```solidity
// VULNERABLE — external call mid-function with state update after
function claimAndReinvest() external {
    uint256 pending = pendingRewards(msg.sender);
    pendingRewards[msg.sender] = 0;
    // External call before final state update
    (bool ok,) = rewardToken.call(
        abi.encodeWithSelector(IERC20.transfer.selector, msg.sender, pending)
    );
    require(ok);
    // If rewardToken is ERC777: tokensReceived hook re-enters claimAndReinvest
    // pending is already 0 but the hook sees new pending from reinvest → claims again
    totalPaidOut += pending;  // updated AFTER external call — stale during reentrancy
}
```

## Pattern 7: Access Control on Initialize-Like Functions

Found in every contest involving proxies or clones

```solidity
// VULNERABLE — initialize() callable by anyone
// Extremely common in Clones (minimal proxy pattern)

// Factory deploys clone, doesn't call initialize immediately
// Attacker calls initialize() first on the new clone
// Becomes the owner before legitimate protocol setup

contract ProtocolClone {
    address public owner;
    bool private initialized;

    function initialize(address _owner) external {
        // MISSING: require(!initialized)
        owner = _owner;
    }
}
```

## Pattern 8: Wrong Sign / Direction in Financial Calculation

Found in: yield protocols, perpetuals, anything with positive/negative returns

```solidity
// VULNERABLE — fee subtracted instead of added (or vice versa)
function calculateAmountOut(uint256 amountIn, bool buyFee) internal view returns (uint256) {
    uint256 fee = amountIn * FEE_BPS / 10_000;
    if (buyFee) {
        return amountIn - fee;  // BUG: should ADD fee (input includes fee)
    }
    return amountIn + fee;  // BUG: should SUBTRACT fee (output after fee deducted)
}

// Another direction bug (found in C4 Perpetuals contests):
int256 fundingPayment = skew * fundingRate;
// if skew = +100 (net long), longs should PAY, shorts receive
// payment = -100 * rate (negative = longs pay)
// BUG: fundingPayment used as positive in long account update
// longs RECEIVE payment instead of paying → economic drain
```

## Pattern 9: Block.number Used as Timestamp on L2

Found in: almost every L2 protocol audit — Arbitrum/Optimism/Base specific

```solidity
// VULNERABLE — Arbitrum's block.number is NOT Ethereum's block.number
// On Arbitrum: block.number ≈ L1 block number (much slower)
// On Optimism/Base: block.number is L2 block number (much faster)

// Protocol deployed on Ethereum uses:
// duration = 100 blocks ≈ 20 minutes (OK on L1)

// Same contract on Optimism:
// 100 blocks ≈ 2 minutes (2s L2 blocks — much shorter than intended)

// On Arbitrum:
// 100 blocks ≈ 30 minutes (same as L1 — but Arbitrum can process many L2 txs per L1 block)

// FIXED — use block.timestamp instead of block.number for time-based logic on L2
// Use block.number ONLY for Ethereum mainnet where block time is consistent (12s)
```

## Pattern 10: Precision Loss in Compound Interest (Repeated Division)

Found in: lending protocols, time-locked vaults

```solidity
// VULNERABLE — interest compounded per second using integer division
// Over time, truncation errors accumulate significantly

// Wrong: simple interest per second
function accruedInterest(uint256 principal, uint256 ratePerSecond, uint256 elapsed) public pure returns (uint256) {
    return principal * ratePerSecond * elapsed / 1e18;  // not compounding
}

// Wrong: repeated integer division loses precision
function compound(uint256 principal, uint256 rate, uint256 periods) public pure returns (uint256) {
    for (uint i = 0; i < periods; i++) {
        principal = principal * (1e18 + rate) / 1e18;  // each iteration truncates
        // Error grows with number of periods
    }
    return principal;
}

// FIXED — use exponentiation with fixed-point math (e.g., MathUtils.calculateCompoundedInterest)
// Aave uses: (1 + rate/secondsPerYear)^secondsElapsed via binomial approximation
```

## Immunefi-Specific Pattern: Emergency Withdrawal Race Condition

```solidity
// VULNERABLE — user detects vulnerability, races to withdraw before protocol pauses
// Protocol has emergency withdraw function but:
// 1. Emergency withdraw has lower priority in gas auction than attacker's drain tx
// 2. Emergency withdraw requires multisig (slow) while exploit is instant
// 3. Emergency withdraw function itself is vulnerable

// Real pattern: protocol detects attack in progress, calls pause()
// Attacker frontruns pause() with final drain tx

// Mitigation: circuit breakers that trigger automatically
// e.g., "if single tx withdraws > 10% of TVL, auto-pause for 1 hour"
uint256 public maxSingleWithdrawal;  // e.g., 10% of TVL

function withdraw(uint256 amount) external {
    require(amount <= maxSingleWithdrawal, "Exceeds circuit breaker");
    // ...
}
```

## Detection Signals Summary (Code4rena Most Common)
- Any `ERC20.transfer` or `ERC20.transferFrom` without SafeERC20
- Any `setXxx` admin function without bounds check
- Balance-changing function without preceding reward checkpoint update
- `totalSupply() == 0` path not handled in share calculations
- Chainlink price with no `decimals()` normalization
- `block.number` used for time on L2 deployments
- `initialize()` without `initializer` modifier
- Division in loop or in compounding formula

## Severity Guide (Code4rena Standard)
- Drain of user funds via reentrancy: **Critical**
- ERC4626 share price manipulation: **High**
- Admin can set fee to 100%: **High**
- Stale reward state on withdrawal: **High**
- Wrong sign in financial calculation: **High**
- Missing input validation (admin): **Medium**
- Decimal precision error: **Medium**
- block.number on L2: **Medium**
