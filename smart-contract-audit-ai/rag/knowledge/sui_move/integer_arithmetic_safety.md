# Integer Arithmetic Safety in Sui Move

## Move Integer Types
Move provides: `u8`, `u16`, `u32`, `u64`, `u128`, `u256`
All integers are unsigned. Arithmetic aborts on overflow/underflow by default (unlike Solidity unchecked).
Move does NOT have signed integers natively.

## Why Overflow Still Happens

Move aborts on overflow — which is safe for fund preservation, but causes DoS.
The real risks are:
1. **Overflow before abort** — intermediate calculation overflows u64 before result is truncated
2. **Underflow abort** — subtraction with wrong order causes DoS
3. **Precision loss** — division before multiplication destroys precision
4. **Incorrect cast** — (x as u64) silently truncates high bits from u128

## Vulnerability 1: Overflow in Intermediate Calculation

```move
// VULNERABLE — both operands are u64, multiplication can overflow u64
// max u64 = 18,446,744,073,709,551,615 (~1.8 × 10^19)
// 2 * 10^9 * 2 * 10^9 = 4 * 10^18 — fits in u64
// 5 * 10^9 * 5 * 10^9 = 2.5 * 10^19 — OVERFLOWS u64 → ABORT

public fun get_liquidity(reserve_a: u64, reserve_b: u64): u64 {
    math::sqrt(reserve_a * reserve_b)  // OVERFLOW if reserves > ~4.3B each
}

// FIXED — cast to u128 for intermediate calculation
public fun get_liquidity(reserve_a: u64, reserve_b: u64): u64 {
    let product = (reserve_a as u128) * (reserve_b as u128);
    (math::sqrt_u128(product) as u64)
}
```

## Vulnerability 2: Division Before Multiplication (Precision Loss)

```move
// VULNERABLE — division first loses precision irreversibly
public fun calculate_fee(amount: u64, fee_bps: u64): u64 {
    amount / 10_000 * fee_bps  // e.g., amount=999, fee=30: 999/10000=0, 0*30=0 — WRONG
}

// FIXED — multiply first
public fun calculate_fee(amount: u64, fee_bps: u64): u64 {
    amount * fee_bps / 10_000  // 999*30=29970, 29970/10000=2 — CORRECT (rounding down)
}

// For large amounts, use u128:
public fun calculate_fee(amount: u64, fee_bps: u64): u64 {
    ((amount as u128) * (fee_bps as u128) / 10_000) as u64
}
```

## Vulnerability 3: Underflow Causing DoS

```move
// VULNERABLE — subtraction without ordering check
// If b > a, transaction aborts — attacker can trigger this
public fun remove_stake(pool: &mut Pool, amount: u64) {
    pool.total_staked = pool.total_staked - amount;  // ABORT if amount > total_staked
    // Attacker may be able to manipulate total_staked to be less than expected
}

// FIXED
public fun remove_stake(pool: &mut Pool, amount: u64) {
    assert!(pool.total_staked >= amount, EInsufficientStake);
    pool.total_staked = pool.total_staked - amount;
}
```

## Vulnerability 4: Unsafe Cast Truncation

```move
// VULNERABLE — high bits silently dropped on downcast
public fun calculate_output(numerator: u128, denominator: u128): u64 {
    (numerator / denominator) as u64  // if result > u64::MAX, truncates silently
    // e.g., result = 2^65 → cast gives 2 (completely wrong)
}

// FIXED — check before casting
public fun calculate_output(numerator: u128, denominator: u128): u64 {
    let result = numerator / denominator;
    assert!(result <= (u64::MAX as u128), EOutputTooLarge);
    result as u64
}
```

## Vulnerability 5: Rounding Direction Favoring Attacker

```move
// In DeFi: rounding should ALWAYS favor the protocol, never the user
// Round UP when computing what user owes (debt, repayment)
// Round DOWN when computing what user receives (output tokens, rewards)

// VULNERABLE — rounding favors user on debt calculation
public fun calculate_interest(principal: u64, rate_bps: u64): u64 {
    principal * rate_bps / 10_000  // rounds DOWN — protocol loses tiny amounts per tx
    // Over millions of txs, this accumulates to significant protocol loss
}

// FIXED — ceiling division for amounts owed to protocol
public fun calculate_interest_ceil(principal: u64, rate_bps: u64): u64 {
    (principal * rate_bps + 9_999) / 10_000  // ceiling: always rounds up
}
```

## Vulnerability 6: Percentage > 100% Not Checked

```move
// VULNERABLE — fee_bps can be set > 10_000 (= > 100%), breaking invariants
public fun set_fee(_: &AdminCap, config: &mut Config, fee_bps: u64) {
    config.fee_bps = fee_bps;  // no upper bound check
}
// If fee_bps = 20_000 (200%), swap output = input - 200% = underflow/abort

// FIXED
const MAX_FEE_BPS: u64 = 1_000;  // 10% maximum
public fun set_fee(_: &AdminCap, config: &mut Config, fee_bps: u64) {
    assert!(fee_bps <= MAX_FEE_BPS, EFeeTooHigh);
    config.fee_bps = fee_bps;
}
```

## Vulnerability 7: Accumulated Rounding Error in Reward Distribution

```move
// VULNERABLE — per-user rounding errors accumulate, last withdrawer can't claim
struct RewardPool has key {
    id: UID,
    total_rewards: u64,
    total_shares: u64,
}

public fun claim(pool: &mut RewardPool, user_shares: u64, ctx: &mut TxContext): u64 {
    let reward = pool.total_rewards * user_shares / pool.total_shares;
    // Every user rounds DOWN — leftover stays in pool but may be unclaimable
    // if total_shares eventually reaches 0 with remaining rewards
    pool.total_rewards = pool.total_rewards - reward;
    reward
}

// FIXED — track accumulated rewards per share with high precision
const PRECISION: u128 = 1_000_000_000_000;  // 1e12
struct RewardPool has key {
    id: UID,
    reward_per_share_scaled: u128,  // accumulated, scaled by PRECISION
}
```

## AMM Math Safety Checklist

```move
// For any AMM swap calculation, verify:
// 1. All intermediate u64*u64 → use u128
// 2. Multiply before divide
// 3. k invariant holds: assert!(new_k >= old_k)
// 4. Output > 0: assert!(amount_out > 0)
// 5. Output < reserve: assert!(amount_out < reserve_out)
// 6. Slippage check: assert!(amount_out >= min_out)

public fun swap_exact_in(
    pool: &mut Pool,
    amount_in: u64,
    min_out: u64,
    ctx: &mut TxContext
): u64 {
    let reserve_in = (balance::value(&pool.reserve_in) as u128);
    let reserve_out = (balance::value(&pool.reserve_out) as u128);
    let amount_in_128 = (amount_in as u128);
    let fee = amount_in_128 * (pool.fee_bps as u128) / 10_000;
    let amount_in_after_fee = amount_in_128 - fee;
    let amount_out_128 = reserve_out * amount_in_after_fee / (reserve_in + amount_in_after_fee);
    let amount_out = (amount_out_128 as u64);
    assert!(amount_out > 0, EZeroOutput);
    assert!(amount_out < balance::value(&pool.reserve_out), EInsufficientLiquidity);
    assert!(amount_out >= min_out, ESlippage);
    amount_out
}
```

## Detection Signals
- `u64 * u64` in AMM/financial math without u128 cast
- Division operator `/` appearing before multiplication `*` in same expression
- `a - b` without preceding `assert!(a >= b)`
- `(x as u64)` on result of u128 expression without bounds check
- `fee_bps` or `rate` parameters without upper bound assertion
- Reward/yield calculations using integer division without precision scaling
- `math::sqrt(a * b)` where a, b are u64 pool reserves

## Severity Guide
- Overflow in AMM reserve calculation: **Critical** (pool drain)
- Underflow DoS in withdrawal: **High**
- Rounding favoring attacker on debt: **Medium** (accumulates over time)
- Fee parameter without upper bound: **High** (admin can set 100%+ fee)
- Precision loss in reward distribution: **Medium**
