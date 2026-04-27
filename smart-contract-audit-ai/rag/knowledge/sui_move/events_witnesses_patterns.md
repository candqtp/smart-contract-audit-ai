# Events, Witnesses, and Safe Initialization Patterns in Sui Move

## One-Time Witness (OTW) Pattern

The OTW is a zero-field struct defined at the module's top level. The Move VM guarantees it can only be created once — at module `init` time. It proves that a call is happening at deploy time from the correct module.

```move
// Define OTW — must match module name exactly, all uppercase
module my_protocol::token {
    struct TOKEN has drop {}  // OTW — same name as module in uppercase

    fun init(witness: TOKEN, ctx: &mut TxContext) {
        // witness is guaranteed unique — only called once at publish
        let (treasury, metadata) = coin::create_currency(
            witness, 6, b"TKN", b"My Token", b"", option::none(), ctx
        );
        transfer::public_freeze_object(metadata);
        transfer::transfer(treasury, tx_context::sender(ctx));
    }
}
```

## Vulnerability 1: OTW Not Validated in Registration Functions

```move
// VULNERABLE — protocol accepts any T as a "witness" for registration
// A malicious module can register fake pools/coins without OTW enforcement
public fun register_pool<T>(witness: T, registry: &mut Registry, ctx: &mut TxContext) {
    // Missing: assert!(sui::types::is_one_time_witness(&witness))
    let pool = Pool<T> { id: object::new(ctx), ... };
    table::add(&mut registry.pools, type_name::get<T>(), object::id(&pool));
    transfer::share_object(pool);
}

// FIXED
public fun register_pool<T: drop>(witness: T, registry: &mut Registry, ctx: &mut TxContext) {
    assert!(sui::types::is_one_time_witness(&witness), ENotOTW);
    // now guaranteed: only the module that defined T can call this
}
```

## Vulnerability 2: Publisher Object Misuse

```move
// sui::package::Publisher proves which module published a type
// VULNERABLE — Publisher not verified when it should be
public fun authorize<T>(publisher: &Publisher, config: &mut Config) {
    // Missing: assert!(package::from_module<T>(publisher))
    // Any Publisher object (even from unrelated module) accepted
    config.authorized_type = type_name::get<T>();
}

// FIXED
public fun authorize<T>(publisher: &Publisher, config: &mut Config) {
    assert!(package::from_module<T>(publisher), EUnauthorizedPublisher);
    config.authorized_type = type_name::get<T>();
}
```

## Witness Pattern for Type-Gating

```move
// Protocol uses a witness to prove "T was defined in the calling module"
// Pattern: function requires both the type T and a zero-field struct from T's module

struct Witness has drop {}  // each module defines its own

// Correct: function signature forces caller to construct Witness{}
// which only the module itself can do (struct is not public)
public(friend) fun register_internal(w: Witness, ...) { ... }

// Modules declare friends to allow cross-module witness usage safely
```

## Events — Required for Auditability

```move
// All state-changing operations MUST emit events
// Events are the only way to track protocol activity off-chain

// Define events
struct SwapEvent has copy, drop {
    pool_id: ID,
    sender: address,
    amount_in: u64,
    amount_out: u64,
    timestamp_ms: u64,
}

struct LiquidationEvent has copy, drop {
    position_id: ID,
    liquidator: address,
    collateral_seized: u64,
    debt_repaid: u64,
}

// Emit in functions
public fun swap(pool: &mut Pool, coin_in: Coin<SUI>, clock: &Clock, ctx: &mut TxContext): Coin<USDC> {
    // ... swap logic ...
    event::emit(SwapEvent {
        pool_id: object::id(pool),
        sender: tx_context::sender(ctx),
        amount_in: coin::value(&coin_in),
        amount_out,
        timestamp_ms: clock::timestamp_ms(clock),
    });
    result
}
```

## Vulnerability 3: Missing Events on Critical Operations

```move
// VULNERABLE — no events = no on-chain audit trail
// Impossible to track who called admin functions or when
public fun set_fee(_: &AdminCap, config: &mut Config, fee: u64) {
    config.fee = fee;
    // no event emitted
}

// Standard events to require:
// - All admin config changes (fee updates, param changes)
// - All fund movements above threshold
// - Capability transfers
// - Upgrade proposals and executions
// - Protocol pause/unpause
```

## init() Function Security

```move
// init() runs exactly once at package publish
// VULNERABLE patterns:
fun init(ctx: &mut TxContext) {
    // 1. Transferring caps to wrong address
    transfer::transfer(AdminCap { id: object::new(ctx) }, @0xdead);  // oops

    // 2. Sharing high-privilege objects
    transfer::share_object(TreasuryCap { ... });  // anyone can mint

    // 3. Not initializing required state
    // If Config object not created here, protocol may be unusable

    // 4. Not freezing metadata objects
    // Metadata should be frozen after creation for on-chain verifiability
}

// CORRECT pattern
fun init(otw: MYTOKEN, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(otw, 9, b"MTK", b"MyToken", b"", option::none(), ctx);
    transfer::public_freeze_object(metadata);     // freeze metadata
    transfer::transfer(treasury, tx_context::sender(ctx));  // keep treasury controlled
    let config = Config {
        id: object::new(ctx),
        fee_bps: 30,
        paused: false,
    };
    transfer::share_object(config);
    transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
}
```

## Struct Abilities Checklist

```move
// Abilities: copy, drop, store, key
// key  — can be a top-level Sui object (has UID as first field)
// store — can be stored inside other objects or transferred with transfer::public_transfer
// copy  — value can be duplicated (never for assets!)
// drop  — value can be discarded (witnesses, event types)

// NEVER give copy or drop to asset/value types:
struct Coin<phantom T> has key, store { id: UID, balance: Balance<T> }
// No copy — can't duplicate coins
// No drop — can't discard without explicit handling (prevents lost funds)

// VULNERABLE — accidental copy ability on asset
struct Ticket has key, store, copy { id: UID, value: u64 }
// Tickets can be copied — users can duplicate them
```

## Detection Signals
- `register` or `create` functions accepting generic `T` without `is_one_time_witness` check
- `Publisher` accepted as parameter without `from_module` verification
- State-changing functions without `event::emit`
- `init()` transferring objects to hardcoded non-deployer addresses
- `init()` calling `share_object` on TreasuryCap or AdminCap
- Asset structs with `copy` ability
- Asset structs with `drop` ability (funds can be silently discarded)

## Severity Guide
- OTW not validated (fake type registration): **High**
- Publisher not verified (unauthorized authorization): **High**
- TreasuryCap shared in init: **Critical**
- Asset type with copy ability: **Critical**
- Missing events on admin operations: **Low** (but required for governance)
