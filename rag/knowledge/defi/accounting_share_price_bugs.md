# Accounting, Share Price, and Vault Invariant Bugs

## Tags
defi, accounting, share-price, vault, pricing-bugs, rounding, per-share


## Why Accounting Bugs Are Pervasive
DeFi protocols track user shares, exchange rates, and token balances. Any discrepancy between the protocol's internal accounting and actual token balances creates a profit opportunity. These bugs are the most common High findings in Sherlock and Code4rena contests.

## Vulnerability 1: Accounting Uses totalSupply Instead of totalAssets

```solidity
// ERC4626 vault: shares represent proportion of total assets
// Exchange rate = totalAssets() / totalSupply()

// VULNERABLE — protocol uses token.totalSupply() not vault.totalAssets()
function pricePerShare() public view returns (uint256) {
    return token.totalSupply() * 1e18 / totalShares;
    // token.totalSupply() is NOT the same as vault's balance of that token
    // If vault holds partial allocation or tokens are distributed outside vault,
    // token.totalSupply includes ALL tokens everywhere — grossly inflated
}

// FIXED
function pricePerShare() public view returns (uint256) {
    return totalAssets() * 1e18 / totalShares;
    // totalAssets() = token.balanceOf(address(this)) + external deployments
}
```

## Vulnerability 2: Shares Minted Before Receiving Assets (Reentrancy Profit)

```solidity
// VULNERABLE — mint shares, then receive payment
// Combined with reentrancy: mint shares without paying

function deposit(uint256 amount) external returns (uint256 shares) {
    shares = previewDeposit(amount);
    _mint(msg.sender, shares);  // shares minted FIRST
    asset.safeTransferFrom(msg.sender, address(this), amount);  // payment SECOND
    // Reentrancy via asset.safeTransferFrom (ERC777) → re-enter deposit
    // Second call: totalAssets() still reflects old balance → mint more shares at old rate
}

// FIXED — CEI: receive assets before minting shares
function deposit(uint256 amount) external returns (uint256 shares) {
    uint256 before = asset.balanceOf(address(this));
    asset.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = asset.balanceOf(address(this)) - before;  // handle fee-on-transfer
    shares = convertToShares(received);  // use ACTUAL received amount
    _mint(msg.sender, shares);  // mint AFTER receiving
}
```

## Vulnerability 3: Donation Attack on Exchange Rate

```solidity
// VULNERABLE — attacker directly transfers tokens to vault without going through deposit()
// This inflates totalAssets() without increasing totalShares
// Exchange rate artificially inflated → next depositor gets fewer shares

// Example:
// Vault: 100 assets, 100 shares → 1:1 rate
// Attacker donates 100 assets directly (transfer to vault address)
// Vault: 200 assets, 100 shares → 2:1 rate
// Next depositor: 100 assets → 50 shares (not 100)
// Attacker's 100 shares are now worth 200/100 × 100 = 200 assets
// Attacker doubled their money at depositor's expense

// FIXED — use internal balance tracking (don't trust balanceOf directly)
uint256 internal _totalDeposited;  // manually track deposits

function deposit(uint256 amount) external {
    asset.safeTransferFrom(msg.sender, address(this), amount);
    _totalDeposited += amount;  // only increases via deposit()
    // shares = amount * totalShares / _totalDeposited (not balanceOf)
}

// Donations still increase balanceOf but not _totalDeposited
// Protocol uses _totalDeposited for share pricing → donation has no effect
```

## Vulnerability 4: Total Assets Includes Unearned Future Rewards

```solidity
// VULNERABLE — totalAssets() includes rewards not yet earned/received
// Inflated exchange rate → users who deposit now get fewer shares
// If rewards don't materialize, previous depositors get diluted

function totalAssets() public view override returns (uint256) {
    return asset.balanceOf(address(this)) + pendingRewards();  // not yet received!
}

// pendingRewards() might include: unvested amounts, off-chain claims, speculative yields
// FIXED — only include settled/received assets
function totalAssets() public view override returns (uint256) {
    return asset.balanceOf(address(this));  // only what vault actually holds
}
```

## Vulnerability 5: Fee Accounting Error — Protocol Takes More Than Declared

```solidity
// VULNERABLE — fee subtracted from wrong value
// Protocol charges 1% performance fee on profits

function withdraw(uint256 shares) external returns (uint256 assets) {
    assets = convertToAssets(shares);
    uint256 fee = assets * FEE_BPS / 10_000;
    assets -= fee;
    _burn(msg.sender, shares);
    asset.transfer(fee_recipient, fee);
    asset.transfer(msg.sender, assets);
    // BUG: shares burned corresponds to full assets (before fee)
    // but user only gets assets - fee
    // The fee is being taken from user's share value AND the exchange rate shifts
    // causing double-counting — users pay more than declared fee
}

// FIXED — burn only shares corresponding to net assets received
function withdraw(uint256 shares) external returns (uint256 assets) {
    uint256 grossAssets = convertToAssets(shares);
    uint256 fee = grossAssets * FEE_BPS / 10_000;
    uint256 netAssets = grossAssets - fee;
    _burn(msg.sender, shares);
    asset.transfer(fee_recipient, fee);
    asset.transfer(msg.sender, netAssets);
    return netAssets;
}
```

## Vulnerability 6: Slippage on Vault Deposit/Withdrawal Not Bounded

```solidity
// VULNERABLE — exchange rate can change between tx submission and execution
// Attacker front-runs large deposit with donation → exchange rate inflated
// Victim's deposit gets fewer shares than expected

function deposit(uint256 amount) external returns (uint256 shares) {
    shares = convertToShares(amount);
    // No minimum shares check!
    _mint(msg.sender, shares);
    asset.safeTransferFrom(msg.sender, address(this), amount);
    return shares;
}

// FIXED — add minimum shares output parameter
function deposit(uint256 amount, uint256 minShares) external returns (uint256 shares) {
    shares = convertToShares(amount);
    require(shares >= minShares, "Slippage too high");
    _mint(msg.sender, shares);
    asset.safeTransferFrom(msg.sender, address(this), amount);
}
```

## Vulnerability 7: Rounding in Convert Functions Favors User

```solidity
// ERC4626 spec: rounding MUST favor the vault (protocol), not the user
// convertToShares: round DOWN (user gets fewer shares on deposit) — correct
// convertToAssets: round DOWN (user gets fewer assets on withdraw) — correct
// previewMint: round UP (user pays more assets to get shares) — correct
// previewWithdraw: round UP (user burns more shares to get assets) — correct

// VULNERABLE — wrong rounding direction
function convertToAssets(uint256 shares) public view override returns (uint256) {
    return shares * totalAssets() / totalSupply();
    // Division rounds DOWN — correct for assets-out calculation
    // But if totalSupply = 0 and user calls with shares > 0 → division by zero
}

// ALSO VULNERABLE — integer overflow before division
function convertToAssets(uint256 shares) public view returns (uint256) {
    return shares * totalAssets() / totalSupply();
    // If shares = 1e30 and totalAssets = 1e30 → shares * totalAssets overflows uint256
    // Use mulDiv from OZ: Math.mulDiv(shares, totalAssets(), totalSupply())
}

// FIXED
function convertToAssets(uint256 shares) public view returns (uint256) {
    uint256 supply = totalSupply();
    if (supply == 0) return shares;  // initial rate is 1:1
    return Math.mulDiv(shares, totalAssets(), supply);  // no overflow, rounds down
}
```

## Vulnerability 8: Strategy Accounting Mismatch in Multi-Strategy Vault

```solidity
// Yearn-style vault deploys assets across multiple strategies
// VULNERABLE — totalAssets() sums strategy balances, but strategies report stale values

// Strategy.estimatedTotalAssets() may be cached / not account for recent losses
// Vault reports inflated totalAssets → users withdraw at inflated rate
// Late withdrawers get less than their fair share

// Mitigation: harvest() must be called before large withdrawals
// Or: accounting update triggered on every significant action
modifier harvestFirst() {
    harvest();  // update all strategy balances
    _;
}
function withdraw(uint256 shares) external harvestFirst {
    // now totalAssets() is fresh
}
```

## Sherlock High Findings in Vaults

```
HIGH:
1. previewDeposit returns wrong value when fee-on-transfer token used
2. totalAssets() includes dust balance from fee tokens — shares mispriced
3. Vault holds ETH/WETH, wrapping not accounted → totalAssets() misses ETH
4. First depositor gets artificially large shares due to no virtual offset
5. maxWithdraw() doesn't account for liquidity constraints — reverts on execution

MEDIUM:
1. Deposit and withdraw in same transaction extracts rounding profit repeatedly
2. Vault allows deposit of 0 → mints 0 shares → events confuse accounting off-chain
3. totalAssets() uses balanceOf which includes donations → exchange rate unstable
4. Fee calculation truncates to 0 for small amounts → free withdrawal for small users
```

## Detection Signals
- `totalAssets()` uses `token.totalSupply()` instead of `token.balanceOf(address(this))`
- `_mint(shares)` called before `safeTransferFrom` (assets received after shares issued)
- No minimum shares output in `deposit()`
- `convertToAssets()` or `convertToShares()` overflow possible for large inputs (no mulDiv)
- `totalAssets()` includes pending/unreceived future rewards
- Fee charged by reducing user's assets but shares burned at gross rate
- No `harvest()` before withdrawal in multi-strategy vault
- `totalSupply == 0` path missing in `convertToAssets()`

## Severity Guide
- Mint before receive (reentrancy): **Critical**
- Donation attack on first depositor: **High/Critical**
- totalAssets includes unearned rewards: **High**
- Wrong rounding direction (favors user): **Medium/High** (accumulates)
- No slippage on deposit/withdraw: **Medium**
- Overflow in mulDiv-missing conversion: **High**
- Fee double-counting: **High**
