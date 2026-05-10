# Dynamic Fields, Tables, and Bags in Sui Move

## Tags
sui, move, dynamic-fields, tables, bag, storage, object-bag, vec-map


## Overview
Sui provides heterogeneous storage via dynamic fields — key-value pairs attached to any object at runtime. Unlike struct fields, dynamic fields can be added/removed after object creation. `Table<K,V>`, `Bag`, `ObjectTable`, and `ObjectBag` all build on this primitive. Misuse causes silent data loss, DoS, and logic bypasses.

## Dynamic Field Fundamentals

```move
use sui::dynamic_field as df;
use sui::dynamic_object_field as dof;

// Add a dynamic field
df::add(&mut obj.id, b"balance", 100u64);

// Read
let val: &u64 = df::borrow(&obj.id, b"balance");

// Mutate
let val: &mut u64 = df::borrow_mut(&mut obj.id, b"balance");

// Remove (must remove all before object can be deleted)
let _: u64 = df::remove(&mut obj.id, b"balance");
```

## Vulnerability 1: Key Collision

```move
// VULNERABLE — same key string used for different types panics at runtime
df::add(&mut obj.id, b"data", 100u64);
df::add(&mut obj.id, b"data", b"hello");  // ABORTS — key already exists

// VULNERABLE — key collision across modules sharing same object
// Module A adds field with key @"price" as u64
// Module B tries to add field with key @"price" as address
// One will abort, or worse: Module B reads Module A's value with wrong type

// FIXED — namespace keys with module-specific prefix
df::add(&mut obj.id, b"module_a::price", price_value);
df::add(&mut obj.id, b"module_b::price", price_address);
// Or use typed keys (structs as keys enforce type safety)
struct PriceKey has copy, drop, store {}
df::add(&mut obj.id, PriceKey {}, price_value);
```

## Vulnerability 2: Silent Orphaned Fields (Object Deletion Without Cleanup)

```move
// VULNERABLE — object deleted but dynamic fields remain as orphans in global storage
// They can never be recovered — permanent fund loss if fields hold Coin or objects
public fun close_account(account: Account) {
    let Account { id, owner: _ } = account;
    object::delete(id);  // BUG: any df::add'd fields still exist, unreachable forever
}

// FIXED — remove all dynamic fields before deleting
public fun close_account(mut account: Account, ctx: &TxContext) {
    // Must know all keys to remove them — design with this in mind
    if (df::exists_(&account.id, b"balance")) {
        let balance: u64 = df::remove(&mut account.id, b"balance");
        // return balance to owner
        transfer::transfer(coin::from_balance(balance::create_for_testing(balance), ctx), account.owner);
    };
    let Account { id, owner: _ } = account;
    object::delete(id);
}
```

## Vulnerability 3: Unbounded Table Iteration (DoS)

```move
// VULNERABLE — table with unbounded size, function iterates all entries
// Attacker spams entries to make function exceed gas limit
struct Whitelist has key {
    id: UID,
    users: Table<address, bool>,
}

public fun process_all_users(wl: &mut Whitelist, ctx: &TxContext) {
    // Move has no native table iteration — but pattern equivalent:
    // if using vector + table, iterating the vector is O(n)
    // attacker can grow n to cause gas exhaustion
}

// FIXED — use pagination or lazy processing
// Process N entries per transaction, track cursor
public fun process_batch(wl: &mut Whitelist, cursor: u64, batch_size: u64) {
    // process entries [cursor, cursor+batch_size)
}
```

## Vulnerability 4: Dynamic Object Field Access Without Ownership Check

```move
// Dynamic object fields store key-accessible objects
// The parent object owns the child — but borrow_mut gives mutable access
// to the child without additional checks

struct Treasury has key { id: UID }
// Coins stored as dynamic object fields

public fun withdraw(treasury: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<SUI> {
    // VULNERABLE — no capability check
    let coin_ref: &mut Coin<SUI> = dof::borrow_mut(&mut treasury.id, b"reserve");
    coin::split(coin_ref, amount, ctx)
}

// FIXED
public fun withdraw(_: &AdminCap, treasury: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<SUI> {
    let coin_ref: &mut Coin<SUI> = dof::borrow_mut(&mut treasury.id, b"reserve");
    coin::split(coin_ref, amount, ctx)
}
```

## Vulnerability 5: Bag Type Confusion

```move
// Bag is heterogeneous — values can be any type, retrieved by key
// If key is predictable, attacker can retrieve wrong type and cause abort or confusion
struct DataBag has key { id: UID, bag: Bag }

// VULNERABLE — integer key, attacker can predict/guess slot to read
bag::add(&mut obj.bag, 0u64, sensitive_data);

// If another function adds a different type at key 0, borrow<WrongType> will abort
// but may leak information about what keys exist

// FIXED — use typed struct keys
struct SlotKey has copy, drop, store { slot: u64, version: u64 }
bag::add(&mut obj.bag, SlotKey { slot: 0, version: 1 }, data);
```

## Vulnerability 6: Table Contains Check Missing

```move
// VULNERABLE — borrow on non-existent key aborts the transaction
// Can be exploited to DoS legitimate transactions if key existence is not verified
public fun get_user_balance(balances: &Table<address, u64>, user: address): u64 {
    *table::borrow(balances, user)  // ABORTS if user not in table
}

// FIXED
public fun get_user_balance(balances: &Table<address, u64>, user: address): u64 {
    if (table::contains(balances, user)) {
        *table::borrow(balances, user)
    } else {
        0
    }
}
```

## Correct Pattern: Namespaced Typed Keys

```move
// Best practice — one struct per semantic field, prevents all key collisions
struct BalanceKey has copy, drop, store {}
struct LockedUntilKey has copy, drop, store {}
struct LastClaimKey has copy, drop, store {}

public fun init_user(account: &mut Account, balance: u64, lock_time: u64) {
    df::add(&mut account.id, BalanceKey {}, balance);
    df::add(&mut account.id, LockedUntilKey {}, lock_time);
    df::add(&mut account.id, LastClaimKey {}, 0u64);
}
```

## Detection Signals
- `df::add` with string/byte literals as keys (collision risk)
- `object::delete` without preceding `df::remove` for all fields
- Vector-backed tables in functions called by public users (unbounded iteration)
- `table::borrow` or `bag::borrow` without preceding `contains` check
- `dof::borrow_mut` on treasury/vault objects without capability parameter
- Large `Table` or `Bag` in functions that process all entries

## Severity Guide
- Orphaned Coin fields (permanent loss): **Critical**
- Missing capability on dof borrow_mut of treasury: **Critical**
- Unbounded iteration DoS: **High**
- Key collision causing wrong-type panic: **Medium/High**
- Missing contains check (DoS via abort): **Medium**
