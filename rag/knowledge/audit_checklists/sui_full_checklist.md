# Sui Move Full Audit Checklist

## Tags
sui, move, checklist, audit, security-review, full-checklist


Use this checklist on every Sui Move smart contract audit. Each item maps to a known vulnerability class. Flag every YES as a finding candidate — verify exploitability before assigning severity.

---

## 1. Access Control

- [ ] Every state-mutating `public fun` or `public entry fun` requires a capability object parameter
- [ ] No state-changing function uses only `ctx.sender` address checks (capability preferred)
- [ ] `init()` transfers capabilities to `tx_context::sender(ctx)`, not hardcoded addresses
- [ ] High-privilege caps (`AdminCap`, `MintCap`) do NOT have `store` ability (prevents trading)
- [ ] If caps have `store`, there is a revocation mechanism (versioned caps or registry)
- [ ] Capability transfer functions are not publicly callable without the cap held by value
- [ ] Multi-sig or timelock required for critical operations (upgrades, treasury withdrawals)

## 2. TreasuryCap and Token Security

- [ ] `TreasuryCap` is NOT passed to `share_object` (would allow unlimited minting)
- [ ] `TreasuryCap` is NOT stored in a publicly accessible shared object
- [ ] Total supply cap is enforced: `coin::total_supply(treasury) + amount <= MAX_SUPPLY`
- [ ] Token `metadata` is frozen after creation
- [ ] OTW (`is_one_time_witness`) is validated in any public token registration function
- [ ] `Publisher` object is verified with `package::from_module<T>` where applicable
- [ ] Coin operations return change to sender (no lost SUI/tokens on split)
- [ ] `coin::value > 0` checked before accepting payments

## 3. Shared Object Race Conditions

- [ ] All AMM swap functions have `min_amount_out` slippage parameter
- [ ] All time-sensitive operations have `deadline_ms` expiry with `Clock` check
- [ ] Read-then-write patterns on shared objects check for replay (e.g., `already_claimed`)
- [ ] Effects (state writes) happen BEFORE transfers/interactions
- [ ] Auctions and first-come-first-served logic use commit-reveal scheme
- [ ] No single shared object serves as global bottleneck (consider sharding)

## 4. Integer Arithmetic

- [ ] All `u64 * u64` in financial math uses intermediate `u128`
- [ ] No division before multiplication in fee/reward calculations
- [ ] All subtractions have `assert!(a >= b)` guard
- [ ] All `(x as u64)` casts from u128 have bounds check
- [ ] Rounding direction favors protocol on debt, favors precision on output
- [ ] Fee/rate parameters have upper bound assertions (e.g., `fee_bps <= 1000`)
- [ ] AMM constant-product invariant verified: `new_k >= old_k`

## 5. Clock and Time

- [ ] `clock::timestamp_ms(&Clock)` used instead of `tx_context::epoch()`  for sub-day precision
- [ ] `tx_context::epoch_timestamp_ms()` NOT used as current time (it's epoch START)
- [ ] All orders, signed messages, and bids have expiry timestamps
- [ ] Vesting/unlock logic uses Clock for precision, not epoch boundaries
- [ ] Price feeds have staleness checks (max age: 60s for high-value, 5min for lower-value)

## 6. Object Model

- [ ] Object deletion (`object::delete`) preceded by removal of all dynamic fields
- [ ] Wrapped objects cannot escape capability checks via unwrapping
- [ ] `transfer::freeze_object` called at correct time (not prematurely locking admin out)
- [ ] Owned vs shared object choice is intentional — shared object use is justified
- [ ] No objects transferred to `@0x0` except for intentional burns with minimum liquidity

## 7. Dynamic Fields and Tables

- [ ] Dynamic field keys are typed structs (not raw string literals)
- [ ] No key collisions possible across modules sharing the same parent object
- [ ] `table::contains` checked before `table::borrow` to prevent DoS via abort
- [ ] Tables/vectors iterated in public functions have size bounds or pagination
- [ ] `Bag` heterogeneous storage uses typed keys to prevent wrong-type retrieval

## 8. DeFi Specific

- [ ] Price oracle uses TWAP or external feed (Pyth), NOT spot `getReserves()`
- [ ] First-depositor LP inflation attack prevented (minimum liquidity burned)
- [ ] Flash loan receipt/proof structs have NO `copy` or `drop` ability (hot potato)
- [ ] Flash loan pool state locked during loan (no reads of inconsistent state)
- [ ] Liquidation payout capped at actual collateral (no bad debt from over-bonus)
- [ ] Borrowing/lending uses isolated collateral or cross-collateral risk is documented
- [ ] Decimal precision normalization applied when mixing tokens of different decimals

## 9. Package Upgrades

- [ ] `UpgradeCap` is protected by timelock (minimum 48h for DeFi)
- [ ] Upgrade policy (`COMPATIBLE`/`ADDITIVE`/`DEP_ONLY`) matches stated immutability guarantees
- [ ] `package::make_immutable` called for protocols intended to be non-upgradeable
- [ ] Upgrade proposals emit events with digest and proposer
- [ ] Emergency pause possible without requiring an upgrade

## 10. PTB Composability

- [ ] Protocol does not assume fund source (any Coin can be flash-borrowed in same PTB)
- [ ] Proof/receipt objects are hot potatoes (no abilities) — cannot be reused across PTBs
- [ ] Sequence-dependent operations enforce ordering via state flags (`initialized`, `phase`)
- [ ] No function assumes it is the first call in a transaction

## 11. Events and Observability

- [ ] All admin operations emit events (`FeeChanged`, `AdminChanged`, `ProtocolPaused`)
- [ ] All fund movements above threshold emit events
- [ ] All capability transfers emit events
- [ ] Upgrade proposals and executions emit events
- [ ] Event structs include `sender`, `timestamp_ms` (from Clock), and relevant IDs

## 12. Initialization

- [ ] `init()` uses OTW for coin creation
- [ ] All required objects created in `init()` (no lazy initialization that can be skipped)
- [ ] `init()` does not share high-privilege objects
- [ ] Protocol has a documented "initial state" that `init()` enforces

## 13. Move Type Safety

- [ ] Asset/value structs do NOT have `copy` ability
- [ ] Asset/value structs do NOT have `drop` ability (prevent silent discard)
- [ ] Generic functions that operate on coins verify type parameters match expected types
- [ ] `std::type_name::get<T>()` used to verify type identity at runtime where needed
- [ ] `phantom` type parameters used correctly — type used only for type safety, not runtime

## 14. Error Handling

- [ ] All `assert!` statements use named error constants (not magic numbers)
- [ ] Error constants are descriptive: `ENotOwner`, `EInsufficientBalance`, not `E1`, `E2`
- [ ] No panics possible from missing table entries in user-facing functions
- [ ] Abort codes are unique per module (no reuse across different error conditions)

---

## Quick Severity Map

| Finding | Severity |
|---|---|
| TreasuryCap shared | Critical |
| Missing cap on fund-moving function | Critical |
| Hot potato with copy/drop | Critical |
| AMM overflow in u64 math | Critical |
| Spot price oracle | Critical |
| LP first-depositor inflation | High/Critical |
| Missing slippage + deadline | High |
| Epoch misuse for time logic | High |
| Missing OTW validation | High |
| Unprotected UpgradeCap | Critical |
| Orphaned dynamic fields with funds | Critical |
| Asset type with copy ability | Critical |
| Missing initialized check | High |
| Rounding favoring attacker | Medium |
| Missing events on admin ops | Low |
| Unbounded table iteration | High |
