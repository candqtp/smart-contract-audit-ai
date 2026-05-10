# ERC-4626 Tokenized Vault Vulnerabilities

## Tags
erc4626, vault, share-inflation, first-depositor, rounding, previewDeposit, donation-attack, exchange-rate, frontrunning

## Overview
ERC-4626 standardizes tokenized vaults: users deposit assets, receive shares; shares are later redeemed for assets. The exchange rate between shares and assets is `totalAssets() / totalSupply()`. All critical pricing flows through `totalAssets()` — if it is wrong or manipulable, deposits and redemptions are mispriced.

---

## Vulnerability 1: Share Inflation / First Depositor Attack

### Severity: Critical

### How It Works
1. Attacker front-runs the first legitimate depositor by depositing 1 wei of the underlying token, receiving 1 share.
2. Attacker donates a large amount of tokens (e.g., 100e18) directly to the vault via `transfer()` — NOT through `deposit()`. This inflates `totalAssets` without minting new shares.
3. The exchange rate is now massively skewed: 1 share = 100e18 + 1 wei of underlying.
4. When the victim deposits (e.g., 100e18 tokens), the share calculation `assets * totalSupply / totalAssets` rounds DOWN to 0 in Solidity integer math.
5. Victim receives 0 shares. Attacker redeems their 1 share for all assets including the victim's deposit.

### What To Look For In Code
- `convertToShares()` or `previewDeposit()` using `assets * supply / totalAssets` with no offset
- Empty vault has no minimum initial deposit or dead shares mechanism
- `totalAssets()` uses `balanceOf(address(this))` directly — vulnerable to direct transfers
- No slippage protection (no minimum shares parameter on deposit)

### Code Pattern (Vulnerable)
```solidity
function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply();
    return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
    // When supply=1 and totalAssets=100e18+1, a deposit of 99e18 yields 0 shares
}
```

### Mitigations (What Secure Code Looks Like)
1. **Virtual offset (OpenZeppelin default)**: Override `_decimalsOffset()` to return a non-zero value (e.g., 3-6). This adds virtual shares and assets that make inflation economically infeasible.
2. **Dead shares on first deposit**: Mint a fixed amount of shares to the zero address on first deposit (Uniswap V2 pattern). `if (supply == 0) return 10**decimals;`
3. **Internal asset tracking**: Track `totalAssets` via internal bookkeeping instead of `balanceOf(address(this))`. Donations via `transfer()` don't affect the exchange rate.
4. **Minimum deposit/share requirement**: Revert if shares minted would be 0 or below a threshold.

---

## Vulnerability 2: Rounding Direction Errors

### Severity: Medium-High

### Rule
- On **deposit/mint**: round shares DOWN (favor the vault/protocol). User gets fewer shares.
- On **withdraw/redeem**: round assets DOWN (favor the vault/protocol). User gets fewer assets.
- Violating this rule means value leaks from the vault to users, which can be exploited repeatedly.

### What To Look For
- `mulDivDown` used where `mulDivUp` is needed (or vice versa)
- Custom fee calculations that round in the user's favor
- Inconsistency between `previewDeposit` and actual `deposit` behavior

---

## Vulnerability 3: previewDeposit vs deposit Divergence

### Severity: Medium

### ERC-4626 Compliance Requirement
The spec requires: calling `deposit(X, receiver)` must deposit EXACTLY X assets (including fees), and the receiver must get shares matching `previewDeposit(X)`. If preview functions don't account for fees identically to the actual functions, integrators will build broken logic on top.

### What To Look For
- Fee-on-transfer tokens where `previewDeposit` calculates shares on nominal amount but actual deposit receives fewer tokens
- Time-dependent yields where preview is calculated at a different block than execution
- Rebasing tokens where `balanceOf` changes between preview call and deposit execution

---

## Vulnerability 4: Dangerous totalAssets() Implementations

### Severity: High

### Common Mistakes
- Using `asset.balanceOf(address(this))` when the vault deploys assets to external strategies — under-counts during deployment, over-counts on direct donations
- Not accounting for strategy PnL, pending yield, or accrued fees
- Using a single oracle without sanity checks for LP token or derivative pricing
- Not handling rebasing token balance changes

### Secure Pattern
```solidity
function totalAssets() public view returns (uint256) {
    return _internalBalance + _strategyDeployedAmount - _accruedFees;
    // Never uses balanceOf(address(this)) directly
}
```

---

## Vulnerability 5: Fee-on-Transfer and Rebasing Token Incompatibility

### Severity: Medium-High

### Fee-on-Transfer Tokens
Tokens like USDT (with fee toggle), PAXG, or deflationary tokens take a fee on every `transfer()`. If the vault assumes it received the full `amount` passed to `deposit()`, the internal accounting will be inflated vs actual balance. Over time this creates a deficit that last withdrawers absorb.

### Rebasing Tokens
Tokens like stETH or AMPL change balances automatically. If `totalAssets()` uses `balanceOf`, the exchange rate fluctuates outside of deposit/withdraw calls, creating arbitrage opportunities where users deposit before a positive rebase and withdraw after.

### What To Look For
- No before/after balance check on token transfers: `uint256 before = token.balanceOf(address(this)); token.transferFrom(...); uint256 received = token.balanceOf(address(this)) - before;`
- Vault documentation claims compatibility with "any ERC-20" without explicit exclusions
- Missing explicit rebase or fee-on-transfer handling in the README or NatSpec

---

## Audit Checklist for ERC-4626 Vaults

1. [ ] Does the vault use a virtual offset or dead shares to prevent first-depositor inflation?
2. [ ] Does `totalAssets()` avoid raw `balanceOf(address(this))`?
3. [ ] Are rounding directions correct? (deposit/mint: round DOWN shares; withdraw/redeem: round DOWN assets)
4. [ ] Do `previewDeposit/previewMint/previewWithdraw/previewRedeem` exactly match their counterpart functions including fees?
5. [ ] Is there slippage protection (min shares on deposit, max assets on withdraw)?
6. [ ] Is the vault tested with fee-on-transfer tokens?
7. [ ] Is the vault tested with rebasing tokens, or does it explicitly disallow them?
8. [ ] Are reentrancy guards present on deposit/withdraw/mint/redeem?
9. [ ] Can `totalAssets()` be manipulated within a single transaction (flash loan)?
10. [ ] Are there invariant tests: `convertToAssets(convertToShares(x)) ≈ x` and `sum(userShares) == totalSupply`?
