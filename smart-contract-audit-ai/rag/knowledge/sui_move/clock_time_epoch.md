# Time, Clock, and Epoch Vulnerabilities in Sui Move

## Sui Time Primitives
Sui provides two time sources:
- `sui::clock::Clock` — consensus-verified millisecond timestamp, passed as shared object
- `tx_context::epoch(ctx)` — current epoch number (~24h periods), cheap but coarse
- `tx_context::epoch_timestamp_ms(ctx)` — epoch start time in ms (NOT current time)

**Critical distinction:** `epoch_timestamp_ms` returns when the EPOCH STARTED, not the current time. Using it as "now" is almost always wrong.

## Vulnerability 1: Using epoch() for Time-Sensitive Logic

```move
// VULNERABLE — epoch boundaries are validator-controlled (±30min drift possible)
// Two txs in same epoch can have 24h difference in real time
public fun claim_daily_reward(state: &mut RewardState, ctx: &TxContext) {
    let current_epoch = tx_context::epoch(ctx);
    assert!(current_epoch > state.last_claim_epoch, EAlreadyClaimed);
    state.last_claim_epoch = current_epoch;
    // give reward — but user can claim multiple times within same epoch at different times
    // or be blocked from claiming for up to 24h depending on epoch boundary
}

// FIXED — use Clock for fine-grained time
public fun claim_daily_reward(
    state: &mut RewardState,
    clock: &Clock,
    ctx: &TxContext
) {
    let now = clock::timestamp_ms(clock);
    assert!(now >= state.last_claim_ms + 86_400_000, EAlreadyClaimed);  // 24h in ms
    state.last_claim_ms = now;
    // give reward
}
```

## Vulnerability 2: epoch_timestamp_ms() Misused as Current Time

```move
// VULNERABLE — epoch_timestamp_ms returns epoch START, not current time
// Can be up to 24h in the past
public fun is_expired(deadline_ms: u64, ctx: &TxContext): bool {
    tx_context::epoch_timestamp_ms(ctx) > deadline_ms
    // BUG: epoch started 12h ago, deadline is 1h ago — this returns false (not expired)
    // when the deadline has already passed
}

// FIXED — use Clock::timestamp_ms
public fun is_expired(deadline_ms: u64, clock: &Clock): bool {
    clock::timestamp_ms(clock) > deadline_ms
}
```

## Vulnerability 3: No Expiry on Orders/Bids

```move
// VULNERABLE — orders never expire, can be replayed or filled at stale prices
struct Order has store {
    price: u64,
    amount: u64,
    maker: address,
    // no expiry field
}

public fun fill_order(order: &Order, payment: Coin<SUI>, ctx: &mut TxContext) {
    assert!(coin::value(&payment) >= order.price * order.amount, EInsufficientPayment);
    // Order could be months old — price no longer reflects market
}

// FIXED — add expiry
struct Order has store {
    price: u64,
    amount: u64,
    maker: address,
    expires_at_ms: u64,
}

public fun fill_order(order: &Order, payment: Coin<SUI>, clock: &Clock, ctx: &mut TxContext) {
    assert!(clock::timestamp_ms(clock) <= order.expires_at_ms, EOrderExpired);
    assert!(coin::value(&payment) >= order.price * order.amount, EInsufficientPayment);
}
```

## Vulnerability 4: Vesting Bypass via Epoch Manipulation

```move
// VULNERABLE — epoch() advances at validator discretion within protocol rules
// A validator colluding with a beneficiary could delay or accelerate epoch advancement
public fun vest(schedule: &mut VestingSchedule, ctx: &TxContext) {
    let epoch = tx_context::epoch(ctx);
    assert!(epoch >= schedule.cliff_epoch, ENotVested);
    // purely epoch-based vesting can be influenced by validators
}

// BETTER — use Clock-based vesting with epoch as secondary check
public fun vest(schedule: &mut VestingSchedule, clock: &Clock, ctx: &TxContext) {
    let now_ms = clock::timestamp_ms(clock);
    assert!(now_ms >= schedule.cliff_timestamp_ms, ENotVested);
    let vested = calculate_vested_amount(schedule, now_ms);
    assert!(vested > schedule.claimed, ENothingToVest);
    let to_claim = vested - schedule.claimed;
    schedule.claimed = vested;
    // transfer to_claim
}
```

## Vulnerability 5: Stale Clock Reference

```move
// Clock object ID is 0x6 on Sui mainnet/testnet
// VULNERABLE — if a mock clock is accepted instead of the real one
// (only possible in tests, but verify the clock object is trusted in production)

// In production code, Clock is always the real consensus clock.
// In tests: use sui::clock::create_for_testing and sui::clock::set_for_testing
// Audit should verify test mocks don't allow time manipulation in prod paths.
```

## Vulnerability 6: Checkpoint Timestamp vs Clock

```move
// tx_context does NOT provide a timestamp directly.
// Devs sometimes try to derive time from other fields:

// WRONG — epoch_timestamp_ms is epoch START, already explained above
// WRONG — using object IDs or tx digests as entropy for time
// WRONG — counting transactions as a proxy for time (variable tx rate)

// ONLY CORRECT: clock::timestamp_ms(&Clock)
// Clock is updated every checkpoint (~400ms on Sui mainnet)
// Maximum clock drift: ~2 checkpoints = ~1 second
```

## Time-Lock Patterns

```move
// Correct time-lock implementation
struct TimeLock has key {
    id: UID,
    unlock_at_ms: u64,
    value: u64,
}

public fun create_timelock(value: u64, delay_ms: u64, clock: &Clock, ctx: &mut TxContext) {
    let unlock_at = clock::timestamp_ms(clock) + delay_ms;
    transfer::transfer(
        TimeLock { id: object::new(ctx), unlock_at_ms: unlock_at, value },
        tx_context::sender(ctx)
    );
}

public fun unlock(lock: TimeLock, clock: &Clock, ctx: &TxContext): u64 {
    assert!(clock::timestamp_ms(clock) >= lock.unlock_at_ms, EStillLocked);
    let TimeLock { id, unlock_at_ms: _, value } = lock;
    object::delete(id);
    value
}
```

## Detection Signals
- `tx_context::epoch(ctx)` in time-sensitive logic (vesting, claims, locks)
- `tx_context::epoch_timestamp_ms(ctx)` used as current time
- Time-sensitive functions without `clock: &Clock` parameter
- Orders, bids, or signed messages without expiry fields
- Comparisons like `epoch >= deadline` for sub-epoch precision requirements

## Severity Guide
- Epoch misuse allowing double-claim: **High**
- epoch_timestamp_ms used as current time (wrong by up to 24h): **High**
- Orders without expiry (stale price fills): **High**
- Vesting using epoch() (validator influence): **Medium**
- Missing deadline on user-facing operations: **Medium**
