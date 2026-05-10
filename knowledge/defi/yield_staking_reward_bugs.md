# Yield Farming, Staking, and Reward Distribution Vulnerabilities

## Tags
yield, staking, reward, distribution, farming, emission, per-share, reward-debt


## Reward Accounting Models
Two main models:
1. **Snapshot model**: distribute at epoch end, proportional to balance at snapshot
2. **Continuous accrual model** (Synthetix/MasterChef): `rewardPerToken` accumulator updated per block, each user tracks their personal checkpoint

Both are exploited differently. Most Sherlock/Code4rena bugs are in continuous accrual.

## Vulnerability 1: Reward Per Token Not Updated Before State Change (Most Common)

```solidity
// VULNERABLE — the classic MasterChef-fork bug
// Found in hundreds of Code4rena contests
mapping(address => uint256) public userRewardPerTokenPaid;
mapping(address => uint256) public rewards;
uint256 public rewardPerTokenStored;

// MISSING: update rewardPerTokenStored and user.rewards BEFORE any balance change
function stake(uint256 amount) external {
    _totalSupply += amount;
    _balances[msg.sender] += amount;
    // BUG: user stakes → balance increases → next rewardPerToken update
    // credits user for more rewards than they earned
    // Must call _updateReward(msg.sender) FIRST
}

// FIXED — modifier updates before every mutating function
modifier updateReward(address account) {
    rewardPerTokenStored = rewardPerToken();
    lastUpdateTime = lastTimeRewardApplicable();
    if (account != address(0)) {
        rewards[account] = earned(account);
        userRewardPerTokenPaid[account] = rewardPerTokenStored;
    }
    _;
}

function stake(uint256 amount) external updateReward(msg.sender) {
    _totalSupply += amount;
    _balances[msg.sender] += amount;
}
```

## Vulnerability 2: Flash Loan Reward Harvesting

```solidity
// VULNERABLE — large stake at end of reward period, immediate unstake
// Attacker earns a disproportionate share of rewards relative to time staked

// Attack:
// 1. Wait until near the end of a reward period
// 2. Flash borrow 1M tokens
// 3. Stake all → now hold 90% of total staked
// 4. Wait 1 block (or don't wait if snapshot is per-block)
// 5. Unstake → claim 90% of period rewards
// 6. Repay flash loan
// Cost: flash loan fee (~0.1%)
// Revenue: 90% of reward pool

// Mitigation: minimum staking duration before rewards vest
// Mitigation: time-weighted reward calculation (not balance-at-snapshot)
mapping(address => uint256) public stakeTimestamp;
uint256 constant MIN_STAKE_DURATION = 1 days;

function claim() external {
    require(block.timestamp >= stakeTimestamp[msg.sender] + MIN_STAKE_DURATION, "Too early");
    uint256 reward = earned(msg.sender);
    rewards[msg.sender] = 0;
    rewardToken.transfer(msg.sender, reward);
}
```

## Vulnerability 3: Reward Rate Precision Loss

```solidity
// VULNERABLE — division by large duration causes near-zero reward rate
// rewardRate = totalRewards / duration
// if duration = 365 days = 31,536,000 seconds
// and totalRewards = 1000 tokens (1e21 wei with 18 decimals)
// rewardRate = 1e21 / 31536000 = 31,709,791 wei/second ✓ (fine)

// BUT: if totalRewards = 100 tokens = 1e20 wei
// rewardRate = 1e20 / 31536000 = 3,170,979 wei/second ✓ (still fine)

// PROBLEM: reward per token calculation
function rewardPerToken() public view returns (uint256) {
    if (_totalSupply == 0) return rewardPerTokenStored;
    return rewardPerTokenStored + (
        rewardRate * (lastTimeRewardApplicable() - lastUpdateTime) * 1e18 / _totalSupply
    );
}
// If _totalSupply is very large (e.g., 1e30), the division loses all precision
// rewardRate * elapsed = 1e10
// 1e10 * 1e18 / 1e30 = 0 ← all rewards lost to rounding

// Mitigation: scale reward rate by 1e18 at storage time
uint256 public rewardRateStored;  // stored as rewardRate * 1e18 / duration
```

## Vulnerability 4: Wrong Reward Calculation After Emergency Withdrawal

```solidity
// VULNERABLE — user withdraws but reward state not cleared
function emergencyWithdraw() external {
    uint256 amount = _balances[msg.sender];
    _balances[msg.sender] = 0;
    _totalSupply -= amount;
    // Missing: rewards[msg.sender] = 0;
    // User can later call claim() and get rewards even after emergency exit
    stakingToken.transfer(msg.sender, amount);
}

// ALSO VULNERABLE: balance set to 0 but userRewardPerTokenPaid not updated
// On next stake: earned() = newBalance * (rewardPerToken - 0) = inflated rewards
```

## Vulnerability 5: Reward Token = Staking Token (Compounding Attack)

```solidity
// When reward token == staking token, users can compound
// But if rewardPerToken calculation uses _totalSupply that includes unclaimed rewards:
// Claiming rewards → increases claimable rewards → infinite loop of inflating rewards

// VULNERABLE: totalStaked used in rewardPerToken includes rewards not yet claimed
function notifyRewardAmount(uint256 reward) external {
    rewardRate = reward / DURATION;
    // Adds to existing pool — but if users stake their rewards,
    // the denominator (totalSupply) grows, affecting unclaimed rewards of others
}
```

## Vulnerability 6: Rebasing Staking Token — Balance Drift

```solidity
// If staking token rebases (AMPL, stETH), user's staked balance changes
// without going through the staking contract

// VULNERABLE — fixed balance stored, actual balance drifts
mapping(address => uint256) public stakedBalance;  // snapshot at stake time

function stake(uint256 amount) external {
    stakingToken.transferFrom(msg.sender, address(this), amount);
    stakedBalance[msg.sender] += amount;  // fixed — doesn't track rebase
}

function unstake(uint256 amount) external {
    // If token rebased upward: contract has MORE than recorded
    // User unstakes their "recorded" amount → leftover tokens stuck in contract forever
    require(stakedBalance[msg.sender] >= amount);
    stakedBalance[msg.sender] -= amount;
    stakingToken.transfer(msg.sender, amount);
}
```

## Vulnerability 7: notifyRewardAmount Called With Leftover Rewards

```solidity
// Synthetix staking: notifyRewardAmount restarts reward period
// VULNERABLE — called before previous period ends, leftover rewards handled incorrectly

function notifyRewardAmount(uint256 reward) external onlyRewardsDistribution {
    if (block.timestamp >= periodFinish) {
        rewardRate = reward / DURATION;
    } else {
        uint256 remaining = periodFinish - block.timestamp;
        uint256 leftover = remaining * rewardRate;
        rewardRate = (reward + leftover) / DURATION;
        // VULNERABLE: if leftover > type(uint256).max - reward → overflow
        // (pre-0.8 only, but still seen in deployed code)
    }
    // Also: if rewardRate * DURATION > rewardToken.balanceOf(address(this)),
    // the contract promises more rewards than it has
}

// FIXED — check contract has enough balance for promised rewards
require(
    rewardRate * DURATION <= rewardToken.balanceOf(address(this)),
    "Insufficient reward balance"
);
```

## Vulnerability 8: Boosted Rewards via NFT/Lock — Not Decayed on Transfer

```solidity
// Protocols with vote-escrow (veCRV style) or NFT boosts:
// Boost should be tied to holder, not transferable

// VULNERABLE — NFT confers boost, but boost not removed on transfer
mapping(address => uint256) public boostMultiplier;
mapping(uint256 => address) public nftBoostHolder;

function stakeWithBoost(uint256 nftId) external {
    require(IERC721(boostNFT).ownerOf(nftId) == msg.sender);
    boostMultiplier[msg.sender] = 2;  // 2x rewards
    nftBoostHolder[nftId] = msg.sender;
}

// After NFT is transferred/sold:
// New owner can also call stakeWithBoost → two users both have 2x boost from one NFT
// Old owner's boost not revoked
```

## Sherlock Patterns — Reward Distribution

```
HIGH severity:
1. updateReward modifier missing on withdraw() — user withdraws without settling rewards
2. rewardPerToken() not called in earned() with current timestamp
3. addReward called by anyone (not just authorized) — reward rate manipulation
4. Emergency exit sets balance = 0 but rewards still claimable
5. First staker gets all rewards accumulated before any staking occurred

MEDIUM severity:
1. Dust amounts in reward calculation accumulate to non-trivial loss over time
2. rewardsDuration can be set to 0 — division by zero in rewardRate
3. User can stake 0 amount — triggers reward accounting with no stake
4. Lock period extension not updating reward checkpoint
```

## Detection Signals
- `stake()` or `withdraw()` without `updateReward(msg.sender)` first
- `earned()` calculation that doesn't use `lastTimeRewardApplicable()` (rewards continue past end)
- `emergencyWithdraw()` without clearing reward state
- `notifyRewardAmount()` without checking contract reward balance is sufficient
- Staking reward token == staking token without loop prevention
- Rebasing token used as staking token with fixed-balance accounting
- Boost mechanism where boost NFT not burned or escrowed

## Severity Guide
- Reward state not updated before balance change: **High**
- Flash loan reward harvesting: **High**
- Reward balance insufficient for promised rate: **High**
- Emergency withdraw without clearing rewards: **Medium**
- Boost NFT transferable with permanent boost: **Medium**
- Precision loss in reward rate: **Medium** (accumulates over time)
