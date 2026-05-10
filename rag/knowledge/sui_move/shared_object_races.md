# Shared Object Race Conditions and Ordering Attacks in Sui Move

## Tags
sui, move, shared-object, race-condition, concurrent, contention, MVCC


## Why Shared Objects Are Dangerous
Owned objects in Sui execute without consensus — they're fast and sequential per owner. Shared objects require Sui's consensus layer (Mysticeti). This means:
1. Any transaction touching a shared object can be observed by validators before execution
2. Transaction ordering within a checkpoint is influenced by validators
3. Multiple transactions in the same checkpoint touching the same shared object are ordered — this ordering can be exploited

## Front-Running on Shared Pools

```move
// VULNERABLE — AMM pool is shared, price computed at execution time
public fun swap(
    pool: &mut Pool,
    coin_in: Coin<SUI>,
    ctx: &mut TxContext
): Coin<USDC> {
    let price = get_spot_price(pool);
    let out = coin::value(&coin_in) * price / 1_000_000;
    pool_deposit(pool, coin_in);
    coin::split(&mut pool.usdc, out, ctx)
}
// Attacker sees victim swap tx, inserts own swap before and after (sandwich)
```

```move
// FIXED — slippage protection
public fun swap(
    pool: &mut Pool,
    coin_in: Coin<SUI>,
    min_out: u64,
    deadline_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext
): Coin<USDC> {
    assert!(clock::timestamp_ms(clock) <= deadline_ms, EExpired);
    let price = get_spot_price(pool);
    let out = coin::value(&coin_in) * price / 1_000_000;
    assert!(out >= min_out, ESlippage);
    pool_deposit(pool, coin_in);
    coin::split(&mut pool.usdc, out, ctx)
}
```

## Read-Modify-Write Race (TOCTOU)

```move
// VULNERABLE — time-of-check vs time-of-use on shared state
public fun claim_reward(state: &mut RewardState, ctx: &mut TxContext) {
    let user = tx_context::sender(ctx);
    let reward = calculate_reward(state, user);    // read
    // Another tx can execute between read and write, double-spending rewards
    state.claimed[user] = true;                    // write
    transfer::transfer(coin::split(&mut state.pool, reward, ctx), user);
}

// FIXED — mark claimed BEFORE transferring
public fun claim_reward(state: &mut RewardState, ctx: &mut TxContext) {
    let user = tx_context::sender(ctx);
    assert!(!state.claimed[user], EAlreadyClaimed);
    let reward = calculate_reward(state, user);
    state.claimed[user] = true;  // effect first
    transfer::transfer(coin::split(&mut state.pool, reward, ctx), user);
}
```

## Epoch Boundary Races

```move
// VULNERABLE — epoch() can change mid-checkpoint
public fun vest(schedule: &mut VestingSchedule, ctx: &TxContext) {
    assert!(tx_context::epoch(ctx) >= schedule.unlock_epoch, ENotYet);
    // Another tx in same checkpoint can already be in new epoch
    // if unlock_epoch is the current epoch, two txs can both see epoch >= unlock
    let amount = schedule.amount;
    schedule.amount = 0;
    transfer::transfer(coin::split(&mut schedule.pool, amount, ctx), schedule.owner);
}
// FIXED: check schedule.amount > 0 as a guard against double-claim
assert!(schedule.amount > 0, EAlreadyClaimed);
```

## Shared Object Lock Contention (DoS)

```move
// DESIGN ISSUE — single shared object = global bottleneck
// All transactions must serialize through this one object
struct GlobalState has key {
    id: UID,
    counter: u64,
    // ... all protocol state
}
// High-traffic protocol with one shared object will have degraded throughput
// and is susceptible to spam-based DoS (flood shared obj txs to delay victims)

// BETTER — shard state, use owned objects where possible
// Move user-specific state to owned objects, keep only global invariants shared
```

## Validator Censorship / Ordering Attack

In Sui, within a checkpoint, validator can influence ordering of transactions on the same shared object. For protocols where ordering matters (e.g., first-come-first-served auctions, priority queues), a malicious validator can:
- Reorder transactions to favor certain users
- Delay specific transactions to the next checkpoint

**Mitigation:** Use commit-reveal schemes for auctions. Use time-locked bids.

```move
// VULNERABLE — first bidder in checkpoint wins, validator can reorder
public fun bid(auction: &mut Auction, payment: Coin<SUI>, ctx: &TxContext) {
    assert!(coin::value(&payment) > auction.current_bid, EBidTooLow);
    // return old bid, record new bidder
    auction.current_bid = coin::value(&payment);
    auction.current_bidder = tx_context::sender(ctx);
}

// BETTER — commit-reveal: bid hash committed first, revealed later
public fun commit_bid(auction: &mut Auction, bid_hash: vector<u8>, ctx: &TxContext) {
    table::add(&mut auction.commits, tx_context::sender(ctx), bid_hash);
}
public fun reveal_bid(auction: &mut Auction, amount: u64, salt: vector<u8>, payment: Coin<SUI>, ctx: &TxContext) {
    let expected_hash = hash::sha2_256(bcs::to_bytes(&amount));
    // verify hash matches commit
}
```

## Detection Signals
- `share_object` on pools, treasuries, or registries with read-then-write patterns
- No `min_out` / slippage parameter on swap functions
- No deadline/expiry on time-sensitive operations
- `epoch()` used for unlock logic without additional guards
- Single shared object holding all protocol state (DoS surface)
- Auction/bid logic on shared objects without commit-reveal

## Severity Guide
- Sandwich attack on unprotected AMM: **High**
- Double-claim via TOCTOU on rewards: **High/Critical**
- DoS via shared object spam: **Medium**
- Validator ordering manipulation in auction: **Medium** (requires malicious validator)
