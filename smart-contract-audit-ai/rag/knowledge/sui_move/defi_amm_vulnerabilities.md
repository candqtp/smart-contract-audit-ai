# DeFi and AMM Vulnerabilities in Sui Move

## Sui DeFi Ecosystem Context
Major Sui DeFi protocols: Cetus, Turbos, Aftermath Finance, Scallop, Navi Protocol, Bucket Protocol, FlowX. Common patterns: Uniswap-style AMMs, lending/borrowing, liquid staking, perpetuals. Most use shared objects for pools.

## Vulnerability 1: Price Manipulation via Spot Price Oracle

```move
// VULNERABLE — reads current pool ratio as price
// Can be manipulated in the same PTB (Programmable Transaction Block)
public fun get_price(pool: &Pool): u64 {
    let (reserve_a, reserve_b) = get_reserves(pool);
    reserve_b * PRECISION / reserve_a
}

// Attack using PTB:
// Step 1: swap huge amount of A for B (move price up)
// Step 2: call protocol function that reads get_price() — now inflated
// Step 3: exploit inflated price (e.g., borrow more than collateral worth)
// Step 4: swap back (optionally)

// FIXED — use TWAP (time-weighted average)
// Cetus and other Sui AMMs expose TWAP observation functions
// Or use Pyth Network price feeds for off-chain oracle
```

## Vulnerability 2: LP Token Inflation Attack (First Depositor)

```move
// VULNERABLE — empty pool, first depositor can manipulate LP token supply
public fun add_liquidity_initial(
    pool: &mut Pool,
    coin_a: Coin<A>,
    coin_b: Coin<B>,
    ctx: &mut TxContext
): Coin<LP> {
    let amount_a = coin::value(&coin_a);
    let amount_b = coin::value(&coin_b);
    let lp_amount = math::sqrt(amount_a * amount_b);  // geometric mean
    // VULNERABLE: if attacker donates 1 wei first, then sqrt rounds to 0
    // attacker receives 0 LP but later "donates" large amount to inflate share price
    // new depositors receive 0 LP tokens due to rounding
    coin::mint(&mut pool.lp_treasury, lp_amount, ctx)
}

// FIXED — mint minimum LP to dead address to prevent first-depositor attack
const MINIMUM_LIQUIDITY: u64 = 1000;

public fun add_liquidity_initial(...) {
    let lp_amount = math::sqrt(amount_a * amount_b);
    assert!(lp_amount > MINIMUM_LIQUIDITY, EInsufficientLiquidity);
    // burn MINIMUM_LIQUIDITY to @0x0 (dead address)
    transfer::transfer(coin::mint(&mut pool.lp_treasury, MINIMUM_LIQUIDITY, ctx), @0x0);
    let user_lp = lp_amount - MINIMUM_LIQUIDITY;
    coin::mint(&mut pool.lp_treasury, user_lp, ctx)
}
```

## Vulnerability 3: Reentrancy-Equivalent via Callbacks

```move
// Sui Move prevents classic reentrancy (no recursive calls mid-execution)
// BUT: flash loan callbacks create equivalent risk

// Flash loan provider:
public fun flash_loan(pool: &mut Pool, amount: u64, ctx: &mut TxContext): (Coin<SUI>, FlashReceipt) {
    let coin = coin::split(&mut pool.reserve, amount, ctx);
    let receipt = FlashReceipt { amount, pool_id: object::id(pool) };
    (coin, receipt)
}

public fun repay(pool: &mut Pool, payment: Coin<SUI>, receipt: FlashReceipt) {
    let FlashReceipt { amount, pool_id } = receipt;
    assert!(object::id(pool) == pool_id, EWrongPool);
    assert!(coin::value(&payment) >= amount + fee, EInsufficientRepayment);
    coin::put(&mut pool.reserve, payment);
}

// VULNERABLE: if between flash_loan and repay, the pool state is inconsistent
// and other functions can read it — equivalent to reentrancy window
// Mitigation: use a `flash_loan_active: bool` flag in pool state
```

## Vulnerability 4: Constant Product Invariant Violation

```move
// x * y = k must hold after every swap (minus fees going to LPs)
// VULNERABLE — fee calculation error can break invariant
public fun swap_a_for_b(pool: &mut Pool, amount_in: u64): u64 {
    let fee = amount_in * pool.fee_bps / 10_000;
    let amount_in_after_fee = amount_in - fee;
    let reserve_a = balance::value(&pool.reserve_a);
    let reserve_b = balance::value(&pool.reserve_b);
    // k = reserve_a * reserve_b
    // new_reserve_a = reserve_a + amount_in_after_fee
    // new_reserve_b = k / new_reserve_a
    let new_reserve_a = reserve_a + amount_in_after_fee;
    let amount_out = reserve_b - (reserve_a * reserve_b / new_reserve_a);
    // BUG: fee subtracted from input but fee tokens not added to reserves
    // k is violated: new_reserve_a * (reserve_b - amount_out) < original k
    amount_out
}

// FIXED — fee stays in pool, both reserves updated correctly
public fun swap_a_for_b(pool: &mut Pool, amount_in: u64): u64 {
    let fee = amount_in * pool.fee_bps / 10_000;
    let amount_in_after_fee = amount_in - fee;
    let reserve_a = balance::value(&pool.reserve_a);
    let reserve_b = balance::value(&pool.reserve_b);
    let amount_out = reserve_b * amount_in_after_fee / (reserve_a + amount_in_after_fee);
    // amount_in (full, including fee) goes into reserve_a
    // amount_out goes out of reserve_b
    // k' = (reserve_a + amount_in) * (reserve_b - amount_out) >= k ✓
    amount_out
}
```

## Vulnerability 5: Liquidation Threshold Manipulation

```move
// Lending protocol: collateral_value / debt_value must stay above threshold
// VULNERABLE — price feed used for liquidation is manipulable
public fun is_liquidatable(position: &Position, pool: &Pool): bool {
    let collateral_price = get_spot_price(pool);  // manipulable!
    let collateral_value = position.collateral * collateral_price;
    let debt_value = position.debt;
    collateral_value * 100 < debt_value * LIQUIDATION_THRESHOLD
}
// Attacker flash-dumps collateral price, triggers liquidation of healthy position,
// buys collateral at discount, lets price recover — profit

// FIXED — use Pyth TWAP or multi-source oracle with staleness check
public fun is_liquidatable(position: &Position, price_feed: &PriceInfoObject): bool {
    let price = pyth::get_price_no_older_than(price_feed, clock, 60_000); // 60s max age
    // ...
}
```

## Vulnerability 6: Bad Debt Accumulation

```move
// If liquidation bonus > bad debt threshold, protocol can accumulate bad debt
// Liquidator gets bonus from protocol reserves when position is underwater

// VULNERABLE — liquidation allowed when position is already in bad debt
public fun liquidate(
    protocol: &mut Protocol,
    position: &mut Position,
    liquidator: address,
    ctx: &mut TxContext
) {
    // No check if position is already underwater (debt > collateral)
    // Liquidation bonus paid from protocol reserves even on uncollectable debt
    let bonus = position.collateral * LIQUIDATION_BONUS / 100;
    transfer::transfer(coin::split(&mut protocol.reserves, bonus, ctx), liquidator);
}

// FIXED — cap liquidation payout to available collateral
public fun liquidate(...) {
    let max_payout = position.collateral;  // can't pay more than collateral
    let intended_payout = position.debt + position.debt * LIQUIDATION_BONUS / 100;
    let actual_payout = math::min(max_payout, intended_payout);
    // ...
}
```

## Detection Signals
- `get_reserves()` or `balance::value` used directly for pricing
- AMM pool initialization without minimum liquidity burn
- Flash loan with no state lock during callback window
- Fee arithmetic using integer division before multiplication
- Liquidation functions that don't cap payout to collateral value
- Price checks using spot price without freshness/staleness validation
- `(x as u128)` missing on u64*u64 multiplications in AMM math

## Severity Guide
- Spot price oracle manipulation: **Critical**
- LP token inflation (first depositor): **High/Critical**
- Invariant violation: **Critical** (pool drain)
- Bad debt accumulation: **High**
- Liquidation price manipulation: **Critical**
- Missing slippage protection: **High**
