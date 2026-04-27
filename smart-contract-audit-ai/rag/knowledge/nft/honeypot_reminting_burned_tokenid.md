
## Severity

Low Risk

## Description

The `burn()` marks `stakes[tokenId].burned = true` and sets `burnedAt`. ERC-721 `_burn()` sets owner to `address(0)`, and standard `_mint()` allows minting tokenId again. That means the NFT collection may later re-mint the same `tokenId` to someone else.

The staking contract retains a `stake()` record with `burned = true` and `owner = original staker`. A new owner of a re-minted `tokenId` has no stake record. The original staker will continue to collect burn-phase rewards even though the token was re-minted to someone else. This creates a state inconsistency/design mismatch that you should document and decide on.

## Location of Affected Code

File: [src/NFTStaking.sol#L232](https://github.com/Honeypot-Finance/new_nft_staking/blob/02d5afe0b5327642f48fffe29ec2cb4607a078e7/src/NFTStaking.sol#L232)

```solidity
// Burn staked NFT and start earning burn bonus
function burn(uint256 tokenId) external nonReentrant {
    StakeData storage s = stakes[tokenId];
    require(s.owner == msg.sender, "NOT_OWNER");
    require(!s.burned, "ALREADY_BURNED");
    require(s.stakedAt != 0, "NOT_STAKED");

    // IMPORTANT: Claim all pending normal rewards before burning
    _claim(tokenId);

    // Burn the NFT
    IERC721Burnable(address(nft)).burn(tokenId);

    // Mark as burned and set burn timestamp
    s.burned = true;
    s.burnedAt = uint64(block.timestamp);

    emit Burned(msg.sender, tokenId);
}
```

## Recommendation

Document that staking assumes tokenIds are unique forever and must never be re-minted or add detection/guard:

- block `mint()` of any `tokenId` that previously had a stake record (requires coordination with NFT contract) or
- on burn, delete the stake and emit a one-time burn reward instead of leaving a perpetual burn-state, or cap burn reward time.

## Team Response

Acknowledged.

## [I-01] Integer Division Dust - Small WEI Truncation in Reward Math

## Severity

Informational Risk

## Description

Reward math uses integer division and floors results. Small per-claim “dust” (wei) is lost. Example: `1e18 / 86400` truncates, costing ~6,400 wei/day for a 1 token/day rate (1 token/day rate is set in the tests). This affects accounting precision.

## Location of Affected Code

File: [src/NFTStaking.sol#L174](https://github.com/Honeypot-Finance/new_nft_staking/blob/02d5afe0b5327642f48fffe29ec2cb4607a078e7/src/NFTStaking.sol#L174)

```solidity
// rewardRatePerSecond set in initialize:
rewardRatePerSecond = _ratePerSecond; // e.g., 1e18 / 86400

// claim math:
uint256 amount = (rewardRatePerSecond * delta * m) / ONE;

// burn math:
amount = (rewardRatePerSecond * sinceBurn * mBurn * burnBonusBps) / (ONE * MAX_BPS);
```

## Recommendation

Minimize dust by doing multiplication first with safe `mulDiv` and performing division as late as possible:

```solidity
// compute t = rate * delta safely
uint256 t = FullMath.mulDiv(rewardRatePerSecond, delta, 1);
// amount = (t * m) / ONE safely
uint256 amount = FullMath.mulDiv(t, m, ONE);
```

## Team Response

Acknowledged.

## [I-02] Deduplicate Reward Calculation Logic to Prevent Drift

## Severity

Informational Risk

## Description

Reward and multiplier computations are duplicated across preview and claim paths for both normal and burn modes. Duplicate logic raises the risk of future divergence between previews and actual payouts during upgrades.

## Location of Affected Code

File: [src/NFTStaking.sol#L96](https://github.com/Honeypot-Finance/new_nft_staking/blob/02d5afe0b5327642f48fffe29ec2cb4607a078e7/src/NFTStaking.sol#L96)

```solidity
// Preview pending rewards for a token
function previewPayout(uint256 tokenId) external view returns (uint256) {
    StakeData memory s = stakes[tokenId];
    if (s.owner == address(0)) return 0;

    if (s.burned) {
        // Calculate burn bonus accrual since last burn claim
        if (s.burnedAt == 0) return 0;
        uint256 sinceBurn = block.timestamp - uint256(s.burnedAt);
        if (sinceBurn == 0) return 0;
        uint256 mBurn = _multiplier(sinceBurn);
        // reward = rate * sinceBurn * mBurn scaled by burnBonusBps
        return
            (rewardRatePerSecond * sinceBurn * mBurn * burnBonusBps) /
            (ONE * MAX_BPS);
    }

    // Calculate normal staking rewards
    uint256 nowTs = block.timestamp;
    if (nowTs <= s.lastClaimAt) return 0;

    uint256 delta = nowTs - uint256(s.lastClaimAt);
    uint256 elapsed = nowTs - uint256(s.stakedAt);
    uint256 m = _multiplier(elapsed);

    return (rewardRatePerSecond * delta * m) / ONE;
}
```

File: [src/NFTStaking.sol#L161](https://github.com/Honeypot-Finance/new_nft_staking/blob/02d5afe0b5327642f48fffe29ec2cb4607a078e7/src/NFTStaking.sol#L161)

```solidity
// Handle normal staking claim
function _claim(uint256 tokenId) internal returns (uint256 amount) {
    StakeData storage s = stakes[tokenId];
    require(s.owner == msg.sender, "NOT_OWNER");
    require(s.stakedAt != 0, "NOT_STAKED");

    if (s.burned) {
        // Handle burn bonus claim
        require(s.burnedAt != 0, "INVALID_BURN_STATE");

        uint256 sinceBurn = block.timestamp - uint256(s.burnedAt);
        if (sinceBurn == 0) return 0;

        uint256 mBurn = _multiplier(sinceBurn);
        amount =
            (rewardRatePerSecond * sinceBurn * mBurn * burnBonusBps) /
            (ONE * MAX_BPS);

        if (amount == 0) return 0;

        // Update last burn claim time
        s.burnedAt = uint64(block.timestamp);

        // Mint burn bonus rewards
        rewards.mint(msg.sender, amount);
        emit BurnRewardClaimed(msg.sender, tokenId, amount);

        return amount;
    }

    // Handle normal staking claim
    uint256 nowTs = block.timestamp;
    if (nowTs <= s.lastClaimAt) return 0;

    uint256 delta = nowTs - uint256(s.lastClaimAt);
    uint256 elapsed = nowTs - uint256(s.stakedAt);
    uint256 m = _multiplier(elapsed);

    amount = (rewardRatePerSecond * delta * m) / ONE;

    if (amount == 0) return 0;

    // Update last claim time
    s.lastClaimAt = uint64(nowTs);

    // Mint rewards
    rewards.mint(s.owner, amount);
    emit RewardClaimed(s.owner, tokenId, amount);

    return amount;
}
```

## Impact

Inconsistent or incorrect rewards between preview and actual minting, undermining user expectations and potentially causing over-/under-payments.

## Recommendation

Reuse `previewPayout()` in the claim path.

## Team Response

Fixed.

## [I-03] Inconsistent Mint Recipient in Burn Claims Risks Future Misdirection

## Severity

Informational Risk

## Description

Normal claims mint to the recorded stake owner, while burn claims mint to `msg.sender`. Although currently gated by `require(s.owner == msg.sender)`, future changes (e.g., permissionless claims) could direct rewards to an arbitrary caller instead of the rightful owner. Because the protocol is UUPS-upgradeable, any future implementation that relaxes claim access (permissionless/delegated/batch/relayed claims) can turn this inconsistency into a concrete payout-redirection bug.

## Location of Affected Code

File: [src/NFTStaking.sol#L206](https://github.com/Honeypot-Finance/new_nft_staking/blob/02d5afe0b5327642f48fffe29ec2cb4607a078e7/src/NFTStaking.sol#L206)

```solidity
function _claim(uint256 tokenId) internal returns (uint256 amount) {
  // code
  if (s.burned) {
    // code
    // Mint burn bonus rewards
    rewards.mint(msg.sender, amount);
    emit BurnRewardClaimed(msg.sender, tokenId, amount);
  }
  // Mint rewards
  rewards.mint(s.owner, amount);
  emit RewardClaimed(s.owner, tokenId, amount);
}
```

## Impact

Rewards could be stolen or misdirected if a future UUPS upgrade enables permissionless, delegated, automated, or relayed claiming without aligning payout recipient semantics. Specifically, the burn-claim path paying `msg.sender` would let any caller siphon rewards that should go to the recorded stake owner.

## Recommendation

Standardize on minting to `s.owner` in all claim paths.

## Team Response

Fixed.

