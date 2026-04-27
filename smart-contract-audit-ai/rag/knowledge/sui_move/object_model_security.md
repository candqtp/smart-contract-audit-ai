# Sui Object Model Security

## Overview
Sui's object-centric model differs fundamentally from account-based blockchains. Every piece of state is an object with an explicit owner. Understanding ownership is the foundation of all Sui security analysis.

## Object Ownership Types

### Owned Objects (Single Owner)
- Passed by value into transactions — only the owner can use them
- No consensus needed — fast path execution
- Security: if ownership transfer is unguarded, objects can be stolen

### Shared Objects (Anyone Can Access)
- Require Sui consensus for all transactions
- All writers must go through sequencer — enables front-running
- Security: race conditions, sandwich attacks, ordering dependencies

### Immutable Objects
- Frozen forever — no mutations possible
- Safe to pass by reference to anyone
- Security: make sure freeze happens at the right time; premature freeze locks out legitimate admin

### Wrapped Objects
- Object stored inside another object's fields
- Invisible to global storage — cannot be found by ID
- Security: wrapping can bypass capability checks on inner objects

## Critical Vulnerability: Unauthorized Transfer

```move
// VULNERABLE — no check on who can transfer
public fun transfer_nft(nft: NFT, recipient: address) {
    transfer::transfer(nft, recipient);
}

// FIXED — only owner can initiate
public fun transfer_nft(nft: NFT, recipient: address, ctx: &TxContext) {
    assert!(nft.owner == tx_context::sender(ctx), ENotOwner);
    transfer::transfer(nft, recipient);
}
```

## Critical Vulnerability: Object Theft via Missing Ownership Check

```move
// VULNERABLE — anyone can call burn and destroy someone else's object
public fun burn(token: Token) {
    let Token { id, value: _ } = token;
    object::delete(id);
}
// An attacker who gets a reference cannot burn — but if token is passed by value
// and function is entry, only the owner can pass it. The risk is in non-entry funs
// that accept objects from untrusted callers without verifying provenance.
```

## Shared Object Front-Running

```move
// VULNERABLE — shared pool can be front-run
public fun swap(pool: &mut Pool, coin_in: Coin<SUI>) : Coin<USDC> {
    // attacker sandwiches: swap before and after victim tx
    let amount_out = calculate_output(pool, coin::value(&coin_in));
    update_pool(pool, coin_in);
    coin::split(&mut pool.usdc_reserve, amount_out, ctx)
}

// MITIGATION — add slippage parameter
public fun swap(
    pool: &mut Pool,
    coin_in: Coin<SUI>,
    min_amount_out: u64,
    ctx: &mut TxContext
) : Coin<USDC> {
    let amount_out = calculate_output(pool, coin::value(&coin_in));
    assert!(amount_out >= min_amount_out, ESlippageTooHigh);
    // ...
}
```

## Object Wrapping Escape

```move
// VULNERABLE — inner object bypasses outer capability check
struct Vault has key {
    id: UID,
    inner: AdminKey,  // wrapped — now invisible and unprotected
}

// Anyone who owns Vault can extract AdminKey without AdminCap check
public fun extract_key(vault: Vault): AdminKey {
    let Vault { id, inner } = vault;
    object::delete(id);
    inner  // no capability check — inner object escapes
}
```

## Detection Signals
- `transfer::transfer` without `assert!(sender == owner)`
- `transfer::share_object` — everything accessing this needs race condition review
- Functions accepting `key` objects by value without capability co-parameter
- Struct fields containing other objects with `key` ability (wrapping)
- `transfer::freeze_object` — verify timing is correct

## Severity Guide
- Unauthorized transfer of user assets: **Critical**
- Shared object ordering exploit leading to fund loss: **Critical**
- Object wrapping capability bypass: **High**
- Premature freeze locking admin functions: **High**
