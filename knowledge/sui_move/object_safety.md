# Sui Move Security Patterns

## Tags
sui, move, object, safety, owned, shared, transfer, freeze


## Object Ownership Model
Sui Move uses an object-centric ownership model. Every object has an owner:
- **Owned objects**: single owner, passed by value into transactions
- **Shared objects**: accessible by anyone, require consensus
- **Immutable objects**: frozen, read-only for all

## Common Vulnerabilities

### 1. Missing Capability Check
```move
// VULNERABLE — anyone can call admin function
public fun set_fee(config: &mut Config, fee: u64) {
    config.fee = fee;
}

// FIXED — requires AdminCap
public fun set_fee(_: &AdminCap, config: &mut Config, fee: u64) {
    config.fee = fee;
}
```

### 2. Shared Object Race Conditions
Shared objects are subject to transaction ordering. A function that reads and writes a shared object can be front-run.

### 3. Phantom Type Misuse
Without proper phantom type constraints, a generic function may accept wrong coin types.

```move
// VULNERABLE — T not constrained, could mix SUI and USDC
public fun deposit<T>(pool: &mut Pool<T>, coin: Coin<T>) { ... }

// Must verify T matches pool's registered coin type at runtime
```

### 4. Epoch/Clock Manipulation
```move
// VULNERABLE — using ctx.epoch() for time-sensitive logic
// Validators can influence epoch boundaries
let current_epoch = ctx.epoch();
assert!(current_epoch >= vesting_start, ENotVested);

// BETTER — use Clock object with consensus timestamp
use sui::clock::{Self, Clock};
let ts = clock::timestamp_ms(clock);
```

### 5. Object Wrapping Escape
Wrapping an object inside another to avoid capability checks:
```move
// If admin checks are on the outer object, the inner object's value
// may be accessible by wrapping/unwrapping
```

### 6. Dynamic Field Confusion
```move
// Key collision: different types with same value produce same key hash
dynamic_field::add(&mut obj.id, b"balance", 100u64);
dynamic_field::add(&mut obj.id, b"balance", 200u64); // PANICS — key exists
```

## Detection Signals in Move
- `public fun` without capability parameter — check if it modifies shared state
- `transfer::share_object` — shared objects need race condition analysis
- `clock::timestamp_ms` — check for manipulation surface
- `dynamic_field::borrow_mut` — check key uniqueness
- Missing `assert!` before state mutations

## Audit Checklist
1. Every state-mutating public function must require a capability object
2. Shared objects: identify all writers, check for ordering dependencies
3. Coin operations: verify type parameters match expected coin types
4. Epoch/time logic: prefer Clock over epoch for precision
5. Dynamic fields: verify key namespacing to prevent collisions
