# Sui Move Object Model Security Vulnerabilities

## Tags
sui, move, object, owned, shared, immutable, transfer, public_transfer, capability, access-control, TxContext, UID, public-vs-package

## Overview
Sui Move uses an object-centric model where every on-chain data entity is an object with a defined ownership type: owned (single address), shared (accessible by anyone), immutable (frozen, read-only), or object-owned (owned by another object). Ownership determines who can pass an object into a transaction and what operations are possible. Security vulnerabilities arise from incorrect ownership assignments, exposed internal functions, and missing relationship validation between objects.

---

## Vulnerability 1: public vs public(package) Function Visibility

### Severity: Critical

### The Problem
In Sui Move, `public` functions are callable by ANY module in ANY package. `public(package)` restricts calls to modules within the same package. Marking an internal helper as `public` instead of `public(package)` exposes it to external callers, bypassing all access control.

### Real-World Example (Lombard Finance Audit)
An `account_mut()` function returning a mutable reference to a trading account was marked `public` instead of `public(package)`. Any external contract could call it to get write access to any trading account, bypassing ownership checks.

### Real-World Example (SuiFrens Audit)
A function that mixed SuiFrens with a cooldown period was marked `public` with an `epoch` parameter. Anyone could call it directly with `epoch = 0` to bypass the cooldown.

### Detection Rule
For every `public` function, ask: **Should external packages be able to call this?**
- If NO → change to `public(package)`
- If the function mutates state, returns mutable references, or bypasses checks → almost certainly should be `public(package)` or `entry`

### What To Look For
```move
// VULNERABLE: Anyone can call this from any package
public fun update_balance(account: &mut Account, amount: u64) {
    account.balance = amount;
}

// SAFE: Only this package can call it
public(package) fun update_balance(account: &mut Account, amount: u64) {
    account.balance = amount;
}
```

---

## Vulnerability 2: Shared Object Abuse

### Severity: High

### The Problem
Shared objects (`transfer::share_object`) are accessible by anyone on the network. Any transaction can read or mutate a shared object. This means:
- No built-in access control — the module must enforce its own checks
- Shared object transactions require consensus (slower, more expensive)
- If a critical object is shared when it should be owned, anyone can modify it

### Common Mistakes
- Making an admin config or treasury object shared instead of owned
- Not checking `tx_context::sender(ctx)` inside functions that operate on shared objects
- Assuming shared objects have implicit access control (they don't)

### Detection Rules
- Any `transfer::share_object(obj)` call → verify the module enforces access control on all functions that take `&mut SharedObj`
- If only one address should modify an object, it should be owned, not shared
- Shared objects that hold funds or control protocol parameters must have capability-gated access

### Pattern
```move
// VULNERABLE: Shared treasury, no access check
public entry fun withdraw(treasury: &mut Treasury, amount: u64, ctx: &mut TxContext) {
    let coin = coin::take(&mut treasury.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
    // Anyone can call this and drain the treasury!
}

// SAFE: Requires AdminCap (capability pattern)
public entry fun withdraw(
    _admin: &AdminCap,  // Only admin can pass this
    treasury: &mut Treasury,
    amount: u64,
    ctx: &mut TxContext
) {
    let coin = coin::take(&mut treasury.balance, amount, ctx);
    transfer::public_transfer(coin, tx_context::sender(ctx));
}
```

---

## Vulnerability 3: transfer vs public_transfer Misuse

### Severity: Medium-High

### The Rule
- `transfer::transfer(obj, recipient)` — can only be called within the module that defines the object's type. The type must have `store` ability for `public_transfer` but not for `transfer`.
- `transfer::public_transfer(obj, recipient)` — can be called from any module, but the object's type must have the `store` ability.

### Security Implications
- If a type has `store`, it can be freely transferred by anyone using `public_transfer` — the module loses control over transfer logic
- If you want to enforce transfer restrictions (e.g., soulbound tokens, non-transferable credentials), do NOT add `store` to the type — only use `transfer::transfer` within the defining module

### What To Look For
- Types with `store` ability that should not be freely transferable
- Custom transfer logic that can be bypassed because the type has `store`
- Objects that represent permissions or capabilities with `store` — anyone can transfer them away from the intended holder

### Pattern
```move
// VULNERABLE: AdminCap has store, so anyone can transfer it
struct AdminCap has key, store {
    id: UID
}
// An admin could be social-engineered into approving a transaction that transfers their cap

// SAFER: AdminCap without store — only this module controls transfers
struct AdminCap has key {
    id: UID
}
// Must use transfer::transfer (module-only) to move it
```

---

## Vulnerability 4: Capability Pattern Abuse

### Severity: High

### The Pattern
Sui Move uses "capability objects" for access control — whoever possesses an `AdminCap` object can perform admin actions. This is analogous to key-based access but with object ownership semantics.

### Common Vulnerabilities
1. **Capability created but not transferred**: `AdminCap` created in `init()` but transferred to wrong address or not transferred at all
2. **Capability has `store`**: Can be freely moved, wrapped, or dropped — may end up in unintended hands
3. **No capability revocation**: Once minted, there's no way to invalidate a capability without burning it
4. **Single capability, no separation of concerns**: One `AdminCap` controls everything — compromise = total loss

### What To Look For
```move
// Check init() function — where does the cap go?
fun init(ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };
    transfer::public_transfer(admin_cap, tx_context::sender(ctx));
    // OK — goes to deployer. But what if deployer is a script wallet?
}

// Check: is there only ONE cap type for all admin operations?
// Should there be separate MintCap, PauseCap, UpgradeCap?
```

---

## Vulnerability 5: Missing Object Relationship Validation

### Severity: High

### The Problem
When multiple shared objects are used together (e.g., a Launchpad and its Whitelist), the function must validate that they belong to each other. Without this check, an attacker can pass a valid Whitelist from a different Launchpad.

### Real-World Pattern (MoveBit Audit)
```move
// VULNERABLE: No check that whitelist belongs to this launchpad
public entry fun invest(
    launchpad: &mut Launchpad,
    whitelist: &Whitelist,
    payment: Coin<SUI>,
    ctx: &mut TxContext
) {
    assert!(whitelist::is_whitelisted(whitelist, tx_context::sender(ctx)), ENotWhitelisted);
    // Attacker uses whitelist from a different launchpad where they ARE whitelisted
}

// SAFE: Validate relationship
public entry fun invest(
    launchpad: &mut Launchpad,
    whitelist: &Whitelist,
    payment: Coin<SUI>,
    ctx: &mut TxContext
) {
    assert!(whitelist.launchpad_id == object::id(launchpad), EWrongWhitelist);
    assert!(whitelist::is_whitelisted(whitelist, tx_context::sender(ctx)), ENotWhitelisted);
}
```

### Detection Rule
When a function takes 2+ shared/owned objects as parameters, check: is there validation that they're related?

---

## Vulnerability 6: Clock and Epoch Manipulation

### Severity: Medium

### Clock Object
- `clock::timestamp_ms(clock)` returns milliseconds since Unix epoch
- The `Clock` is a shared object (address `0x6`) updated by validators each checkpoint
- Granularity is ~2-3 seconds (not per-transaction), so it's not as fine-grained as `block.timestamp`
- Unlike Ethereum, users cannot manipulate the clock — validators control it

### Epoch Boundaries
- `tx_context::epoch(ctx)` returns the current Sui epoch (roughly 24 hours)
- Epoch transitions can reset per-epoch rate limits or allowances

### Common Vulnerabilities
1. **Milliseconds vs seconds confusion**: Storing `timestamp_ms` but comparing against a constant in seconds — creates a 1000x error in time locks
2. **Epoch boundary race**: Rate limits that reset per epoch can be exploited at epoch boundaries — user gets 2x the limit by acting at end of epoch N and start of epoch N+1
3. **Hardcoded time assumptions**: Using magic numbers instead of named constants for time periods

### What To Look For
```move
// VULNERABLE: Milliseconds stored as "seconds"
struct StakePosition has key {
    id: UID,
    seconds: u64,  // Misleading name!
    amount: u64,
}

public entry fun stake(vault: &mut Vault, amount: u64, clock: &Clock, ctx: &mut TxContext) {
    let position = StakePosition {
        id: object::new(ctx),
        seconds: clock::timestamp_ms(clock),  // Actually storing milliseconds!
        amount,
    };
}

public entry fun unstake(position: &StakePosition, clock: &Clock) {
    let now_seconds = clock::timestamp_ms(clock) / 1000;  // Converting to seconds
    // BUG: Comparing seconds against milliseconds!
    assert!(now_seconds >= position.seconds + STAKE_LOCK_TIME_SECONDS, ETooEarly);
}
```

---

## Audit Checklist for Sui Move Contracts

1. [ ] Is every `public` function reviewed — should it be `public(package)` instead?
2. [ ] Do shared objects have proper access control in all functions that take `&mut`?
3. [ ] Are capability objects created correctly in `init()` and transferred to the right address?
4. [ ] Do capability types lack `store` if they should not be freely transferable?
5. [ ] When functions take multiple objects, are relationships validated (matching IDs)?
6. [ ] Are time comparisons using consistent units (all ms or all seconds)?
7. [ ] Are epoch-based rate limits tested at epoch boundaries?
8. [ ] Is `transfer::transfer` used instead of `public_transfer` for types that should not be freely movable?
9. [ ] Are there types with both `key` and `store` that should only have `key`?
10. [ ] Does the `init()` function properly initialize ALL protocol state and capabilities?
