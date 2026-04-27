# Solidity / EVM Full Audit Checklist

Use on every Solidity smart contract audit. Each item maps to a known vulnerability class or real-world exploit pattern.

---

## 1. Reentrancy

- [ ] All external calls (`.call`, `.transfer`, ERC721 safeTransfer, ERC777 send) follow CEI order: Checks → Effects → Interactions
- [ ] State updates happen BEFORE external calls, not after
- [ ] `ReentrancyGuard` (nonReentrant modifier) applied to all withdraw/claim functions
- [ ] Cross-function reentrancy checked: function A's external call cannot re-enter function B reading stale state
- [ ] View functions that read state during an external call window don't expose price/balance info to reentering callers
- [ ] ERC721 `safeTransfer*` and ERC1155 `safeTransfer*` treated as external calls — state must be final before calling

## 2. Access Control

- [ ] Every state-mutating external/public function has an appropriate modifier (onlyOwner, hasRole, etc.)
- [ ] No `tx.origin` used for authentication — only `msg.sender`
- [ ] No unprotected `selfdestruct`
- [ ] No unprotected ETH withdrawal
- [ ] Proxy implementations call `_disableInitializers()` in constructor
- [ ] `initialize()` can only be called once (OpenZeppelin `initializer` modifier)
- [ ] DEFAULT_ADMIN_ROLE is assigned to a real address (not address(0))
- [ ] Ownership transfer is two-step (propose + accept) — not single-step
- [ ] No `renounceOwnership()` reachable if critical owner-only functions exist
- [ ] Function visibility matches intent: `external` vs `public` vs `internal` reviewed

## 3. Integer Arithmetic

- [ ] Contract uses Solidity ^0.8.0 OR uses SafeMath for all arithmetic
- [ ] All `unchecked {}` blocks verified safe — document why overflow is impossible
- [ ] All explicit downcasts use `SafeCast`: `uint128(x)` → `SafeCast.toUint128(x)`
- [ ] No division before multiplication in fee/reward formulas
- [ ] No `require(uint - uint >= 0)` patterns (always true for uint)
- [ ] Intermediate calculations use `uint256` (not `uint128` or smaller) before final cast
- [ ] Fee/rate parameters have upper bound assertions

## 4. Flash Loan and Price Oracle

- [ ] Price oracle is NOT Uniswap/AMM spot price (`getReserves()`)
- [ ] Oracle uses TWAP (Uniswap V3 observe), Chainlink, or Pyth
- [ ] Chainlink price feeds checked for staleness: `updatedAt >= block.timestamp - MAX_AGE`
- [ ] Chainlink price checked for negative/zero: `answer > 0`
- [ ] Liquidation uses same oracle as borrowing (no inconsistency)
- [ ] Flash loan integration: protocol state is safe to read during callback window
- [ ] ERC4626: virtual shares offset present to prevent inflation attack on first deposit

## 5. Front-Running / MEV

- [ ] All swap functions have `amountOutMin` and `deadline` parameters
- [ ] ERC20 approvals use `increaseAllowance`/`decreaseAllowance` OR reset to 0 before setting
- [ ] High-value auctions use commit-reveal, not visible-bid
- [ ] NFT mints with desirable IDs use commit-reveal or verifiable randomness
- [ ] Governance: snapshot taken at proposal creation, not vote time
- [ ] Governance: timelock between vote passing and execution (≥48h for DeFi)
- [ ] No governance function executable in same block as proposal submission

## 6. Denial of Service

- [ ] No unbounded loops over user-controlled arrays
- [ ] No ETH transfers inside loops (use pull payment pattern)
- [ ] No `require(externalCall())` inside loops — use try/catch
- [ ] No `address(this).balance` used for internal accounting (force-send susceptible)
- [ ] Array sizes bounded or pagination implemented
- [ ] All external calls that can revert don't block critical protocol functions

## 7. Signature Security

- [ ] All signed messages include: nonce + chainId + address(this) + function-specific data
- [ ] Nonces incremented after use (no replay)
- [ ] Uses `ECDSA.recover()` (OZ) not raw `ecrecover` (prevents malleability)
- [ ] `sig.length == 65` checked OR OZ ECDSA handles it
- [ ] Recovered address checked for `!= address(0)`
- [ ] EIP-712 domain separator includes `block.chainid` (not hardcoded)
- [ ] Permit-based flows use try/catch around permit call (front-run resilience)

## 8. Proxy and Upgradeability

- [ ] Implementation contract calls `_disableInitializers()` in constructor
- [ ] Proxy storage slots use EIP-1967 pseudo-random slots (no collision with implementation)
- [ ] `_authorizeUpgrade()` in UUPS has access control (not empty)
- [ ] Storage layout preserved on upgrades (no removed/reordered variables)
- [ ] Upgrade timelocked (≥48h for production DeFi)
- [ ] No `delegatecall` to user-controlled addresses
- [ ] Function selector collision check performed between proxy admin fns and implementation fns

## 9. Token Handling

- [ ] All ERC20 interactions use SafeERC20 (`safeTransfer`, `safeTransferFrom`)
- [ ] Deposit functions measure actual balance delta for fee-on-transfer token support
- [ ] Rebasing tokens (stETH, AMPL) not snapshot-accounted
- [ ] USDT approvals reset to 0 before setting new amount
- [ ] Decimal normalization applied when comparing/combining tokens of different decimals
- [ ] ERC721/ERC1155 transfers have nonReentrant guard (callbacks trigger reentrancy)

## 10. Randomness

- [ ] No randomness from `block.timestamp`, `blockhash`, `block.difficulty`
- [ ] High-value randomness uses Chainlink VRF
- [ ] Commit-reveal used when VRF not available — slashing for non-revealers
- [ ] NFT rarity assignment deferred until VRF response (not at mint)

## 11. Storage

- [ ] No uninitialized local storage pointers (in legacy code pre-0.5.0)
- [ ] No `private` variables used for secrets (all on-chain data is public)
- [ ] All `immutable` and `constant` variables checked for non-zero initialization
- [ ] Constructor arguments for critical addresses checked `!= address(0)`
- [ ] Assembly `sstore`/`sload` reviewed for correctness and slot targeting

## 12. Timestamp and Block Values

- [ ] `block.timestamp` not used for sub-15-minute precision decisions
- [ ] `block.number` not used as time proxy (block time varies)
- [ ] Locked funds have reasonable unlock windows (>15 minutes per block manipulation risk)

## 13. Events and Monitoring

- [ ] All state changes emit events (fund movements, config changes, role grants)
- [ ] Events contain enough data for off-chain reconstruction of state
- [ ] No indexed parameters for dynamic types (bytes, strings) without reason
- [ ] Emergency pause events emitted with reason

## 14. Governance Security

- [ ] Quorum requirement high enough to prevent flash loan attack
- [ ] Voting power snapshot at proposal creation block
- [ ] Proposal execution timelocked
- [ ] Cancel/veto mechanism exists for malicious proposals
- [ ] Guardian/multisig can pause governance in emergency

---

## Quick Severity Map

| Finding | Severity |
|---|---|
| Reentrancy draining ETH/tokens | Critical |
| Unprotected initialize() | Critical |
| tx.origin authentication | High |
| Flash loan governance (no snapshot) | Critical |
| Spot price oracle | Critical |
| ERC4626 inflation attack | High/Critical |
| Unsigned delegatecall | Critical |
| Missing nonce in signature | Critical |
| UUPS _authorizeUpgrade empty | Critical |
| Storage layout broken on upgrade | Critical |
| Fee-on-transfer token not handled | High |
| Swap without slippage | High |
| No SafeERC20 (USDT) | High |
| Integer overflow (pre-0.8) | Critical |
| Unsafe downcast | High |
| Division before multiply | Medium |
| Unbounded loop DoS | High |
| Blockhash randomness | High |
| Missing zero address check | Medium |
| Missing event on admin op | Low |
