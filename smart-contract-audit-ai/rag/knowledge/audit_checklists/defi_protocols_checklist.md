# DeFi Protocol Full Audit Checklist

Comprehensive checklist for DeFi protocols — covers all Immunefi, Code4rena, and Sherlock common findings.

---

## 1. Oracle Security

- [ ] Protocol does NOT use Uniswap V2 `getReserves()` or any spot price as primary oracle
- [ ] Chainlink feeds checked for staleness: `updatedAt >= block.timestamp - MAX_AGE`
- [ ] Chainlink answer checked for validity: `answer > 0`
- [ ] Chainlink feeds: `decimals()` called and used for normalization (not assumed 18)
- [ ] Multi-hop oracle paths validate ALL feeds for freshness independently
- [ ] L2 deployments check Chainlink sequencer uptime feed + grace period after restart
- [ ] TWAP window is ≥ 30 minutes for high-value lending markets
- [ ] Minimum pool liquidity verified before using pool as oracle source
- [ ] Price circuit breaker: reject if price moved > X% in single update
- [ ] Same oracle used for both borrowing limit AND liquidation threshold (no inconsistency)

## 2. Lending and Borrowing

- [ ] `accrueInterest()` called before any read of borrow balance or health factor
- [ ] Minimum borrow amount enforced (prevents unliquidatable dust positions)
- [ ] Collateral factor (LTV) ≤ 75% for volatile assets, ≤ 85% for stablecoins
- [ ] Liquidation threshold 10-15% above LTV (buffer against bad debt)
- [ ] Liquidation bonus capped at remaining collateral (no bad debt from over-bonus)
- [ ] Self-liquidation (borrower liquidates own position) analyzed for profitability
- [ ] Partial liquidation leaves remaining position above minimum or forces full close
- [ ] Liquidation function has reentrancy guard
- [ ] Borrow rate has maximum cap per block (protects against utilization spike)
- [ ] Bad debt tracking variable exists and is socialized or insured
- [ ] Market guardian can pause borrows/liquidations independently

## 3. ERC4626 / Vault Security

- [ ] First depositor attack prevented: virtual shares offset OR minimum deposit enforced
- [ ] `deposit()` receives assets BEFORE minting shares (not reverse)
- [ ] `totalAssets()` uses internal accounting, not raw `balanceOf(address(this))`
- [ ] `convertToShares()` and `convertToAssets()` use `Math.mulDiv` (no overflow)
- [ ] Rounding direction: shares round DOWN on deposit, assets round DOWN on withdrawal
- [ ] `deposit(amount, minShares)` and `withdraw(shares, minAssets)` slippage params exist
- [ ] Fee calculation rounds in favor of protocol (ceiling division on amounts owed)
- [ ] `totalAssets()` does NOT include unreceived/pending future rewards
- [ ] Multi-strategy vault: `harvest()` called before withdrawal to settle strategy balances
- [ ] Donation attack: direct token transfer to vault can't inflate exchange rate above safe limit

## 4. Reward and Staking

- [ ] `updateReward(account)` modifier on ALL balance-changing functions (stake, withdraw, transfer)
- [ ] `rewardPerToken()` uses `lastTimeRewardApplicable()` (stops accumulating after period end)
- [ ] `notifyRewardAmount()` checks `rewardRate * duration <= rewardToken.balanceOf(this)`
- [ ] `emergencyWithdraw()` clears reward state (sets `rewards[user] = 0`)
- [ ] Flash loan reward harvesting prevented: minimum staking duration OR time-weighted rewards
- [ ] Reward rate precision: if rate can round to 0 for reasonable inputs, scale by 1e18
- [ ] Rebasing staking tokens tracked by shares, not absolute balances
- [ ] Boost NFT/lock escrowed in contract (not just referenced) — can't be transferred while staking

## 5. Flash Loan and Composability

- [ ] Protocol doesn't assume funds source is from user's own wallet
- [ ] Flash loan receipts/callbacks: repayment enforced, balance check is `>=` not `==`
- [ ] Callback functions don't execute arbitrary `address(this).call(data)`
- [ ] Privileged functions inaccessible via callback chain (test: can uniswapV2Call reach admin fns?)
- [ ] No function depends on `balanceOf(address(this))` that can be inflated by donation
- [ ] Price and oracle reads done BEFORE any flash-loanable state changes in same tx path

## 6. AMM / DEX Security

- [ ] Swap functions require `amountOutMin` and `deadline` parameters
- [ ] First liquidity provision: minimum liquidity burned to dead address (inflation attack)
- [ ] Constant-product invariant verified after every swap: `k_new >= k_old`
- [ ] AMM math uses `uint256` intermediates with `mulDiv` for precision
- [ ] Fee calculation: multiply before divide, not divide before multiply
- [ ] Pool tick/range math (V3-style): boundary conditions at min/max tick tested
- [ ] Remove liquidity slippage: `minAmount0` and `minAmount1` parameters required

## 7. Governance

- [ ] Voting uses `getPastVotes(account, snapshotBlock)` — NOT current balance
- [ ] Snapshot block set at proposal CREATION, not vote or execution time
- [ ] Timelock delay ≥ 48 hours between vote passing and execution
- [ ] Quorum re-checked at execution time (not just at vote time)
- [ ] Guardian/council veto power works even after quorum reached
- [ ] Proposal threshold > 0 (not anyone can propose)
- [ ] Proposal timelock cannot be bypassed via any execution path
- [ ] Flash loan governance attack tested: can 1-block supermajority execute?
- [ ] Governance can be paused during emergency without requiring a passing vote

## 8. Bridge and Cross-Chain

- [ ] All cross-chain messages include `chainId` and `address(this)` in hash
- [ ] Processed messages tracked: `processedMessages[id] = true` checked BEFORE execution
- [ ] Validator threshold ≥ 2/3 of total validators
- [ ] No single entity controls > 1/3 of validators
- [ ] Per-asset, per-day transfer limits implemented
- [ ] Large single withdrawals require timelock (auto-triggered, not admin-triggered)
- [ ] Message executor does NOT call arbitrary targets — whitelist required
- [ ] Cross-chain token address mapping verified against canonical registry

## 9. Perpetuals / Derivatives

- [ ] Mark price from robust oracle (Chainlink/Pyth), NOT spot AMM
- [ ] Funding rate capped at maximum (cannot be driven to extreme via OI imbalance)
- [ ] Pending funding settled BEFORE position close (no funding avoidance)
- [ ] Open interest caps per market (prevents pool insolvency on large position close)
- [ ] Unrealized PnL NOT withdrawable as margin (only realized/settled balance)
- [ ] Insurance fund sized appropriately for maximum leverage × max price gap
- [ ] ADL (auto-deleveraging) correctly selects highest-profit longs to reduce

## 10. NFT and Marketplace

- [ ] Per-address mint count tracked (whitelist can't be used multiple times)
- [ ] Merkle leaf includes `msg.sender` (proof not transferable to other addresses)
- [ ] Order signatures include nonce, chainId, contract address, and expiry
- [ ] Auction refunds use pull pattern (not push via transfer)
- [ ] Auction extends on late bids (prevents sniping)
- [ ] Staking contracts escrow NFT (not just record ownership)
- [ ] Lazy mint vouchers have expiry timestamp
- [ ] Royalty recipient `!= address(0)` enforced

## 11. General DeFi (Code4rena Patterns)

- [ ] All ERC20 interactions use SafeERC20 (`safeTransfer`, `safeTransferFrom`)
- [ ] Fee-on-transfer tokens: balance measured before/after transfer, not trusting stated amount
- [ ] All admin setter functions have bounds checks (fee ≤ max, address != 0, duration > 0)
- [ ] `block.number` NOT used for time-based logic on L2 (use `block.timestamp`)
- [ ] `block.timestamp` NOT used for sub-15-minute precision or as randomness source
- [ ] `initialize()` protected with `initializer` modifier (not callable twice)
- [ ] Clone/minimal proxy implementations: factory calls `initialize` immediately after deploy
- [ ] TOCTOU patterns: state read and state used are separated by external calls? Check ordering.

---

## Severity Quick Reference (DeFi-Specific)

| Pattern | Severity |
|---|---|
| Spot price oracle on lending protocol | Critical |
| Infinite mint via accounting mismatch | Critical |
| Flash loan governance (no snapshot) | Critical |
| First depositor vault inflation | High/Critical |
| Bridge replay (no message tracking) | Critical |
| Oracle staleness unchecked | High/Critical |
| Reward state not updated on withdraw | High |
| Donation attack on balanceOf price | Critical |
| Self-liquidation extracting protocol funds | High/Critical |
| Funding rate not settled before close | High |
| Unbounded loop DoS on distribution | High |
| Fee-on-transfer token not handled | High |
| Admin fee setter without upper bound | High |
| block.number on L2 (wrong timing) | Medium |
| Missing input validation (address(0), zero) | Medium |
| Precision loss (division before multiply) | Medium |
| Auction without sniping protection | Medium |
| Royalty recipient address(0) | Medium |
