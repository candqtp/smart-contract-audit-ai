# Programmable Transaction Blocks (PTBs) and Composability Security

## Tags
sui, move, ptb, programmable-transaction, composability, batch, multi-step


## What are PTBs
Sui's Programmable Transaction Blocks let users batch multiple Move calls, object transfers, and coin operations into a single atomic transaction. This is more powerful than Ethereum's single-function-call model — and creates unique attack surfaces.

## PTB Capabilities (Attack Surface)
A single PTB can:
- Call multiple Move functions from different packages
- Pass return values from one call as input to the next
- Split and merge coins
- Transfer objects to arbitrary addresses
- Publish new packages
- All atomically — either everything succeeds or nothing does

## Vulnerability 1: Flash Loan Attack via PTB

```move
// The PTB makes flash loans trivial — no callback needed
// PTB step 1: borrow from pool (get Coin + Receipt)
// PTB step 2: use Coin to manipulate price in another protocol
// PTB step 3: repay Receipt to pool
// PTB step 4: take profit from manipulated protocol
// All in one tx — no reentrancy, just composability

// Protocol MUST assume any function call may be preceded/followed by
// arbitrary actions in the same PTB.

// VULNERABLE — assumes caller has legitimate source of funds
public fun buy(
    shop: &mut Shop,
    payment: Coin<SUI>,
    ctx: &mut TxContext
): Item {
    // payment might be flash-borrowed — shop doesn't know or care
    // If item can be resold in same PTB for more than flash loan cost: profit
    assert!(coin::value(&payment) >= shop.price, EInsufficientPayment);
    coin::put(&mut shop.treasury, payment);
    get_item(shop, ctx)
}
```

## Vulnerability 2: Bypassing Sequence Requirements

```move
// VULNERABLE — if function A must happen before function B,
// but they're in separate public functions, PTB can call B before A

struct Protocol has key {
    id: UID,
    initialized: bool,
    config: Option<Config>,
}

public fun initialize(proto: &mut Protocol, config: Config) {
    proto.initialized = true;
    proto.config = option::some(config);
}

public fun operate(proto: &mut Protocol, ...) {
    // VULNERABLE — user could PTB: operate() then initialize()
    // if operate() doesn't check proto.initialized
    let config = option::borrow(&proto.config);  // aborts if not initialized
    // BUT: if operate() uses optional logic, it might run without config
}

// FIXED — always assert prerequisite state
public fun operate(proto: &mut Protocol, ...) {
    assert!(proto.initialized, ENotInitialized);
    // ...
}
```

## Vulnerability 3: Input Validation Bypass via PTB Coin Splitting

```move
// VULNERABLE — user passes exact payment, but coin was split from a larger one in PTB
// Protocol may incorrectly assume the full wallet balance is being used
public fun stake(
    pool: &mut StakePool,
    payment: Coin<SUI>,
    ctx: &mut TxContext
) {
    let amount = coin::value(&payment);
    // Protocol charges a 1% fee on "total wallet balance" — but user only passes slice
    // No way to enforce full-balance payment — don't try to
    let fee = amount * 100 / 10_000;  // 1% of payment is fine
    // But if protocol assumed: "user must stake their entire balance" — it can't
}
```

## Vulnerability 4: PTB Object Passing — Type Confusion

```move
// PTBs can construct objects from one module and pass to another
// If protocol A and protocol B share a struct name but different modules:
// Move's type system prevents actual confusion — fully qualified module paths
// But witness/proof patterns can be confused if not using OTW properly

// SAFE — Move types are module-namespaced, PTBs cannot forge types
// my_protocol::token::TOKEN != evil_protocol::token::TOKEN

// RISK — if a function accepts `any T: drop` as witness without is_one_time_witness check
public fun register<T: drop>(w: T, ...) {
    // T could be anything — evil module passes its own OTW-looking struct
    // MUST use: assert!(sui::types::is_one_time_witness(&w))
}
```

## Vulnerability 5: Multiple Returns — Unclaimed Objects

```move
// If a function returns objects and caller doesn't handle them in PTB,
// the transaction aborts — Move's "resource safety" ensures this
// BUT: if return values are Options or vectors, partial consumption is possible

// VULNERABLE — Coin<SUI> returned but not consumed → tx aborts
// This is actually SAFE due to Move resource safety
// BUT: if function returns (Coin<A>, Coin<B>) and PTB only uses Coin<A>...
// The Coin<B> MUST be transferred somewhere — PTB must explicitly handle it
// Forgetting to route excess output in a PTB = tx abort
```

## Vulnerability 6: Reuse of Receipt / Proof Objects

```move
// VULNERABLE — receipt used to prove a flash loan was repaid
// If receipt has `copy` ability, user can satisfy multiple repayments with one actual repayment

struct FlashReceipt has copy, drop {  // CRITICAL BUG — copy!
    amount: u64,
    pool_id: ID,
}

public fun repay(pool: &mut Pool, payment: Coin<SUI>, receipt: FlashReceipt) {
    // User copies the receipt, provides multiple repayments using same proof
}

// FIXED — receipt must NOT have copy or drop
struct FlashReceipt {  // no abilities — hot potato pattern
    amount: u64,
    pool_id: ID,
}
// Hot potato: struct with no abilities MUST be consumed in same PTB
// Cannot be stored, dropped, or copied — forces repayment
```

## Hot Potato Pattern (Correct Pattern for Flash Loans)

```move
// Hot potato = struct with no abilities
// It MUST be passed to a consuming function — cannot be ignored
struct FlashReceipt { pool_id: ID, amount: u64 }  // no copy, drop, store, key

public fun flash_loan(pool: &mut Pool, amount: u64, ctx: &mut TxContext): (Coin<SUI>, FlashReceipt) {
    let coin = coin::split(&mut pool.reserve, amount, ctx);
    (coin, FlashReceipt { pool_id: object::id(pool), amount })
}

// User MUST call repay() with the receipt — no way around it in PTB
public fun repay(pool: &mut Pool, payment: Coin<SUI>, receipt: FlashReceipt) {
    let FlashReceipt { pool_id, amount } = receipt;  // destructure = consume
    assert!(object::id(pool) == pool_id, EWrongPool);
    assert!(coin::value(&payment) >= amount, EInsufficientRepayment);
    coin::put(&mut pool.reserve, payment);
}
```

## Detection Signals
- `FlashReceipt` or proof structs with `copy` ability — **Critical**
- `FlashReceipt` or proof structs with `drop` ability — **Critical**
- Functions assuming funds come from user's wallet (can be flash-borrowed)
- State-checking functions without prerequisite `assert!(initialized)`
- `register<T: drop>` without `is_one_time_witness` check
- Lending protocols without price staleness checks (flash loan TWAP manipulation)

## Severity Guide
- Hot potato with copy/drop ability: **Critical** (flash loan repayment bypass)
- Missing initialization check (function order bypass): **High**
- Flash loan price manipulation surface: **Critical**
