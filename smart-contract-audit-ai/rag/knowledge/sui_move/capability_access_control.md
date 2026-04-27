# Capability Pattern and Access Control in Sui Move

## The Capability Pattern
Sui Move uses capability objects (structs with `key` or `store`) as proof of permission. A function requires a capability as a parameter — if you don't hold the object, you can't call the function. This replaces `onlyOwner` modifiers.

## Correct Capability Usage

```move
// Define capability
struct AdminCap has key, store { id: UID }
struct MintCap has key, store { id: UID }

// Issue capabilities at init — only once
fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
}

// Require capability to call sensitive function
public fun set_fee(_: &AdminCap, config: &mut Config, fee: u64) {
    config.fee = fee;
}

public fun mint(_: &MintCap, treasury: &mut TreasuryCap<TOKEN>, amount: u64, ctx: &mut TxContext): Coin<TOKEN> {
    coin::mint(treasury, amount, ctx)
}
```

## Vulnerability 1: Missing Capability Check

```move
// VULNERABLE — no cap required, anyone can call
public fun set_fee(config: &mut Config, fee: u64) {
    config.fee = fee;
}

// VULNERABLE — ctx.sender check is bypassable if sender changes
public fun set_fee(config: &mut Config, fee: u64, ctx: &TxContext) {
    assert!(tx_context::sender(ctx) == config.admin, ENotAdmin);
    // Hardcoded address checks are fragile — admin address can't be rotated safely
    config.fee = fee;
}
```

## Vulnerability 2: Capability Issued to Wrong Address

```move
// VULNERABLE — hardcoded address instead of deployer
fun init(ctx: &mut TxContext) {
    transfer::transfer(
        AdminCap { id: object::new(ctx) },
        @0x1234abcd  // if this address is wrong, cap is permanently lost
    );
}

// FIXED — always use tx_context::sender
fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
}
```

## Vulnerability 3: Capability Has `store` — Can Be Transferred Unintentionally

```move
// RISK — `store` allows wrapping inside other objects and transferring
struct AdminCap has key, store { id: UID }
// An admin could accidentally transfer AdminCap to wrong address, permanently losing it.
// Or a marketplace contract could list it for sale.

// SAFER for high-privilege caps — drop `store`
struct AdminCap has key { id: UID }
// Now it can only live in the owner's address — cannot be wrapped or traded
```

## Vulnerability 4: Public Transfer of Capability

```move
// VULNERABLE — anyone can call transfer_admin_cap and steal the cap
// if they somehow get a reference (e.g., via a shared wrapper)
public fun transfer_admin_cap(cap: AdminCap, to: address) {
    transfer::transfer(cap, to);
}

// FIXED — use transfer::transfer directly in PTB, or require current cap holder
public entry fun transfer_admin_cap(cap: AdminCap, to: address, ctx: &TxContext) {
    // cap passed by value means only its current owner can call this entry fun
    transfer::transfer(cap, to);
}
```

## Vulnerability 5: One-Time Witness (OTW) Misuse

```move
// OTW must be used exactly once at module init — it proves module identity
struct TOKEN has drop {}

// VULNERABLE — if OTW is accepted by any function, not just init-time registrations,
// an attacker could craft a fake module with same struct name
// Always verify OTW with sui::types::is_one_time_witness
public fun register<T: drop>(witness: T, ...) {
    // missing: assert!(sui::types::is_one_time_witness(&witness), EBadWitness);
}

// FIXED
public fun register<T: drop>(witness: T, ...) {
    assert!(sui::types::is_one_time_witness(&witness), EBadWitness);
    // ...
}
```

## Vulnerability 6: No Capability Revocation Path

```move
// If AdminCap has `store`, there's no way to invalidate a compromised cap.
// Design pattern: use a versioned capability with a global registry
struct AdminCap has key, store {
    id: UID,
    version: u64,
}
struct Config has key {
    id: UID,
    admin_version: u64,  // bump to invalidate all old caps
}
public fun set_fee(cap: &AdminCap, config: &mut Config, fee: u64) {
    assert!(cap.version == config.admin_version, ECapRevoked);
    config.fee = fee;
}
```

## Multi-Sig / DAO Governance Pattern

```move
// For high-value protocols: require multiple capabilities from different keyholders
public fun execute_upgrade(_: &AdminCap, _: &SecurityCap, package: UpgradeCap) {
    // Both AdminCap and SecurityCap must be present — 2-of-2 multisig equivalent
}
```

## Detection Signals
- `public fun` or `public entry fun` modifying protocol state without cap parameter
- `init` transferring caps to hardcoded addresses
- Caps with both `key` and `store` used for highest-privilege operations
- `transfer::transfer(cap, ...)` in a public function without provenance check
- Missing `is_one_time_witness` check in token/coin registration
- Admin address stored as `address` field instead of using capability object

## Severity Guide
- Missing cap check on fund-moving functions: **Critical**
- Missing cap check on protocol config: **High**
- Cap transferable without restriction (store ability on critical cap): **High**
- No revocation mechanism: **Medium**
- OTW not validated: **High** (fake token registration)
