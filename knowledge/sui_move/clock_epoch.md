# Sui Move Clock and Epoch Security

## Tags
sui, move, clock, epoch, timestamp, time-manipulation, rate-limit, boundary-attack, milliseconds, seconds, time-lock

## Overview
Sui provides two time primitives: the `Clock` shared object (address `0x6`) for wall-clock time in milliseconds, and `tx_context::epoch()` for the current epoch number (~24 hour periods). Both have unique security properties compared to Ethereum's `block.timestamp` that developers frequently get wrong.

---

## Clock Object Mechanics

### How It Works
- `Clock` is a system shared object at a fixed address (`0x6`)
- Updated by validators each consensus checkpoint (every ~2-3 seconds)
- Returns time in **milliseconds** since Unix epoch via `clock::timestamp_ms(&clock)`
- Unlike Ethereum's `block.timestamp`, individual users and validators cannot meaningfully manipulate the clock — it reflects validator consensus
- Granularity is checkpoint-level, NOT transaction-level: multiple transactions in the same checkpoint see the same clock value

### Key Difference from Ethereum
- Ethereum: `block.timestamp` can be manipulated by miners/validators within ~15 second tolerance
- Sui: Clock is consensus-derived, much harder to manipulate, but has coarser granularity
- Sui: No equivalent of `block.number` for sequencing — use clock or epoch

---

## Vulnerability 1: Milliseconds vs Seconds Unit Confusion

### Severity: High

### The Problem
`clock::timestamp_ms()` returns milliseconds. Constants for time periods are often written in seconds. Comparing or combining values in different units creates errors of 1000x magnitude.

### Example (From Real Audit)
```move
const STAKE_LOCK_TIME_SECONDS: u64 = 10 * 24 * 60 * 60; // 10 days in seconds = 864000

struct StakePosition has key {
    id: UID,
    start_time: u64,  // Stored as milliseconds from clock
    amount: u64,
}

public entry fun stake(clock: &Clock, ctx: &mut TxContext) {
    let position = StakePosition {
        id: object::new(ctx),
        start_time: clock::timestamp_ms(clock),  // milliseconds!
        amount: 100,
    };
}

public entry fun unstake(position: &StakePosition, clock: &Clock) {
    let now = clock::timestamp_ms(clock) / 1000;  // Convert to seconds
    // BUG: position.start_time is in milliseconds, STAKE_LOCK_TIME_SECONDS is in seconds
    // This comparison is ms vs seconds — lock expires 1000x sooner than intended
    assert!(now >= position.start_time + STAKE_LOCK_TIME_SECONDS, ETooEarly);
}
```

### Detection Rule
- Search for `clock::timestamp_ms` — trace where the return value is stored and compared
- Check if named constants mention "seconds" but are compared against ms values
- Check if division by 1000 happens inconsistently (applied to one value but not the other)

### Secure Pattern
```move
// Option A: Store everything in milliseconds
const STAKE_LOCK_TIME_MS: u64 = 10 * 24 * 60 * 60 * 1000; // 10 days in ms

public entry fun unstake(position: &StakePosition, clock: &Clock) {
    let now_ms = clock::timestamp_ms(clock);
    assert!(now_ms >= position.start_time + STAKE_LOCK_TIME_MS, ETooEarly);
}

// Option B: Convert immediately on storage
public entry fun stake(clock: &Clock, ctx: &mut TxContext) {
    let position = StakePosition {
        id: object::new(ctx),
        start_time: clock::timestamp_ms(clock) / 1000,  // Convert to seconds at storage
        amount: 100,
    };
}
```

---

## Vulnerability 2: Epoch Boundary Rate Limit Bypass

### Severity: Medium-High

### The Problem
Epoch-based rate limits reset at epoch boundaries. An attacker acting at the end of epoch N and the start of epoch N+1 can effectively double their allowance.

### Example
```move
public fun mint(treasury: &mut Treasury, amount: u64, ctx: &mut TxContext) {
    let cap = get_minter_cap(treasury, tx_context::sender(ctx));

    // Reset limit if new epoch
    if (tx_context::epoch(ctx) > cap.last_epoch) {
        cap.remaining = cap.limit;
        cap.last_epoch = tx_context::epoch(ctx);
    };

    assert!(amount <= cap.remaining, EMintLimitExceeded);
    cap.remaining = cap.remaining - amount;
    // ...mint tokens...
}
```

### Attack
1. At end of epoch 42: mint full `limit` amount (cap.remaining = 0)
2. Epoch transitions to 43
3. At start of epoch 43: mint full `limit` amount again (reset triggered)
4. Result: 2x the intended rate limit within minutes

### Mitigation
- Use time-based (clock) rate limiting instead of epoch-based when precision matters
- If epoch-based is required, use a sliding window: track total minted in last N epochs, not just current epoch
- Document the epoch-boundary behavior as an accepted risk if the doubled limit is tolerable

---

## Vulnerability 3: Time Lock Bypass via Object Wrapping

### Severity: Medium

### The Problem
If a time-locked object can be wrapped inside another object, the wrapper can be transferred even though the inner object is "locked." The time lock applies to direct operations on the object, not to the wrapper.

### Example
```move
// Time-locked token
struct LockedToken has key {
    id: UID,
    unlock_time: u64,
    value: u64,
}

// Attacker wraps it
struct Wrapper has key, store {
    id: UID,
    inner: LockedToken,  // Wrapped, effectively transferable!
}
// The Wrapper can be transferred freely, circumventing the time lock
```

### Mitigation
- Do not give time-locked types the `store` ability (prevents wrapping)
- Use dynamic fields instead of direct struct composition for lockable assets
- Check lock status at the operation level, not just at the transfer level

---

## Vulnerability 4: Stale Clock Reference in Multi-Step Operations

### Severity: Low-Medium

### The Problem
If a function reads the clock once and then performs multiple operations that depend on time ordering, the clock value is fixed for the entire transaction. This is usually fine but can matter for:
- Auction end times where millisecond precision matters
- Sequential time-dependent operations within a single programmable transaction block

### Note
This is mostly a design consideration rather than a direct vulnerability, but auditors should be aware that all operations within a Sui transaction see the same clock value.

---

## Vulnerability 5: Missing Clock Parameter in Time-Sensitive Functions

### Severity: Medium

### The Problem
Some developers use `tx_context::epoch()` for time-sensitive operations because it doesn't require passing the `Clock` object. But epoch granularity is ~24 hours — far too coarse for most time-dependent logic (auction deadlines, cooldown periods, vesting schedules).

### Detection Rule
- If a function uses `tx_context::epoch(ctx)` for anything more granular than "daily" operations → should use `Clock` instead
- If a time lock or deadline is supposed to be hours or minutes → epoch is wrong

---

## Audit Checklist for Clock and Epoch Usage

1. [ ] Are all time constants in the same unit (ms) as `clock::timestamp_ms()`?
2. [ ] Are comparisons between stored timestamps and current time using consistent units?
3. [ ] Do epoch-based rate limits account for boundary exploitation (2x limit at transition)?
4. [ ] Is `Clock` used instead of `epoch()` for sub-day time precision?
5. [ ] Are time-locked types protected from wrapping (no `store` ability)?
6. [ ] Are named constants clear about their units? (e.g., `_MS` or `_SECONDS` suffix)
7. [ ] Do time-dependent functions actually accept `&Clock` as a parameter?
8. [ ] Are there tests for time edge cases: epoch boundary, zero timestamp, far-future timestamps?
9. [ ] Is there documentation about the expected time granularity and its limitations?
10. [ ] Are vesting/unlock schedules using Clock (ms precision) rather than epoch (day precision)?
