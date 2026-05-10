# Type System Safety and Coin Security in Sui Move

## Tags
sui, move, type-system, coin, safety, phantom-type, generic, one-time-witness


## Move's Type System as a Security Boundary
Move's type system is its primary security mechanism. Generic type parameters, phantom types, and the coin module rely on the type system to prevent mixing of different asset types. Bypassing or misusing generics is a critical vulnerability class.

## Vulnerability 1: Phantom Type Confusion

```move
// VULNERABLE — generic function doesn't enforce T matches pool's coin type
struct Pool<phantom T> has key {
    id: UID,
    reserve: Balance<T>,
    lp_supply: Supply<LP<T>>,
}

public fun add_liquidity<T>(pool: &mut Pool<T>, coin: Coin<T>): Coin<LP<T>> {
    // If someone creates Pool<FAKE> with a fake coin type, they can drain real value
    // by exploiting any function that doesn't verify the pool's registered type
}
```

```move
// SAFER — register coin type at pool creation, verify at every interaction
struct Pool has key {
    id: UID,
    coin_type: TypeName,  // stored at creation
    reserve: Balance<SUI>,
}
// Use std::type_name::get<T>() and compare to stored coin_type
```

## Vulnerability 2: TreasuryCap Misuse

```move
// TreasuryCap<T> is the ONLY authority to mint T tokens
// If TreasuryCap is shared or publicly accessible, unlimited minting is possible

// VULNERABLE — TreasuryCap shared as a shared object
fun init(witness: TOKEN, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(witness, 6, b"TKN", b"Token", b"", option::none(), ctx);
    transfer::share_object(treasury);  // CRITICAL BUG — anyone can call coin::mint
}

// FIXED — transfer to admin or wrap in controlled object
fun init(witness: TOKEN, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(witness, 6, b"TKN", b"Token", b"", option::none(), ctx);
    transfer::transfer(treasury, tx_context::sender(ctx));
    transfer::public_freeze_object(metadata);
}
```

## Vulnerability 3: Coin Split / Join Errors

```move
// VULNERABLE — coin value not fully consumed, change not returned
public fun pay(payment: Coin<SUI>, price: u64, ctx: &mut TxContext) {
    assert!(coin::value(&payment) >= price, EInsufficientFunds);
    let paid = coin::split(&mut payment, price, ctx);
    transfer::transfer(paid, PROTOCOL_ADDRESS);
    // BUG: remaining `payment` value is not returned to sender — funds stuck or lost
}

// FIXED — return change
public fun pay(mut payment: Coin<SUI>, price: u64, ctx: &mut TxContext) {
    assert!(coin::value(&payment) >= price, EInsufficientFunds);
    let paid = coin::split(&mut payment, price, ctx);
    transfer::transfer(paid, PROTOCOL_ADDRESS);
    transfer::public_transfer(payment, tx_context::sender(ctx));  // return change
}
```

## Vulnerability 4: Zero-Value Coin Acceptance

```move
// VULNERABLE — accepts zero-value coin, may process it as valid payment
public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
    // No check for zero value — attacker can spam with Coin { value: 0 }
    // may increment deposit counter, earn LP tokens for free
    let balance = coin::into_balance(coin);
    balance::join(&mut pool.reserve, balance);
}

// FIXED
public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
    assert!(coin::value(&coin) > 0, EZeroValue);
    let balance = coin::into_balance(coin);
    balance::join(&mut pool.reserve, balance);
}
```

## Vulnerability 5: Integer Arithmetic in AMM Math

```move
// VULNERABLE — integer division truncation causes rounding errors
// Attacker exploits rounding to extract value over many small transactions
public fun get_amount_out(amount_in: u64, reserve_in: u64, reserve_out: u64): u64 {
    // Uniswap formula without fee: out = (in * reserve_out) / (reserve_in + in)
    let numerator = amount_in * reserve_out;  // OVERFLOW if both > 2^32
    let denominator = reserve_in + amount_in;
    numerator / denominator  // truncation always rounds down — does protocol benefit?
}

// FIXED — use u128 for intermediate calculations
public fun get_amount_out(amount_in: u64, reserve_in: u64, reserve_out: u64): u64 {
    let amount_in_128 = (amount_in as u128);
    let reserve_in_128 = (reserve_in as u128);
    let reserve_out_128 = (reserve_out as u128);
    let numerator = amount_in_128 * reserve_out_128;
    let denominator = reserve_in_128 + amount_in_128;
    ((numerator / denominator) as u64)
}
```

## Vulnerability 6: Supply Cap Not Enforced

```move
// VULNERABLE — mints without checking total supply cap
public fun mint(_: &MintCap, treasury: &mut TreasuryCap<TOKEN>, amount: u64, ctx: &mut TxContext): Coin<TOKEN> {
    coin::mint(treasury, amount, ctx)
    // No check: assert!(coin::total_supply(treasury) + amount <= MAX_SUPPLY)
}

// FIXED
const MAX_SUPPLY: u64 = 1_000_000_000_000_000; // 1B tokens with 6 decimals
public fun mint(_: &MintCap, treasury: &mut TreasuryCap<TOKEN>, amount: u64, ctx: &mut TxContext): Coin<TOKEN> {
    assert!(coin::total_supply(treasury) + amount <= MAX_SUPPLY, ESupplyCapExceeded);
    coin::mint(treasury, amount, ctx)
}
```

## Vulnerability 7: Decimal Precision Mismatch

```move
// VULNERABLE — mixing tokens with different decimal scales without normalization
// e.g., SUI (9 decimals) vs USDC (6 decimals)
public fun price(sui_amount: u64, usdc_amount: u64): u64 {
    usdc_amount / sui_amount  // WRONG — 1 SUI = 1e9, 1 USDC = 1e6, ratio is off by 1000
}

// FIXED — normalize to common precision
const SUI_DECIMALS: u64 = 1_000_000_000;  // 1e9
const USDC_DECIMALS: u64 = 1_000_000;    // 1e6
const PRECISION: u64 = 1_000_000_000_000; // 1e12 base

public fun price(sui_amount: u64, usdc_amount: u64): u64 {
    (usdc_amount as u128) * (SUI_DECIMALS as u128) * (PRECISION as u128)
        / ((sui_amount as u128) * (USDC_DECIMALS as u128)) as u64
}
```

## Detection Signals
- `TreasuryCap` passed to `share_object` — **immediate Critical**
- Generic functions with `<T>` operating on coin reserves without type verification
- `coin::split` without returning remainder to sender
- AMM math using `u64` for intermediate multiplications
- Missing `> 0` assertions on incoming coin values
- `coin::mint` without total supply check
- Price calculations mixing different decimal scales

## Severity Guide
- TreasuryCap shared: **Critical** (unlimited token minting)
- Type confusion in pools: **Critical** (drain reserves)
- Coin change not returned: **High** (fund loss)
- Integer overflow in AMM math: **High**
- Zero-value coin bypass: **Medium**
- Supply cap not enforced: **High**
