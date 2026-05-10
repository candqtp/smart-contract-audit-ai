# Postmortem: Mango Markets Exploit ($110M, October 11 2022)

## Tags
mango, oracle, price-manipulation, self-liquidation, MNGO, perpetual, perps, thin-liquidity, Solana, collateral-inflation, cross-market, borrowing, Pyth

## Summary
Avraham Eisenberg exploited Mango Markets (a Solana-based DEX/lending platform) by manipulating the price of the MNGO token across multiple exchanges that fed Mango's price oracle. He pumped the MNGO price by ~2,300% within 10 minutes using $5M in capital, then used his artificially inflated MNGO perpetual position as collateral to borrow over $110M in stablecoins and other assets from Mango's lending pools. When the MNGO price collapsed back to reality, the borrowed funds were already withdrawn. The protocol was left with $110M in bad debt.

---

## Background: How Mango Markets Worked

### Architecture
- Mango was a decentralized exchange on Solana offering spot trading, perpetual futures, and lending/borrowing
- Users could deposit assets, trade perps, and borrow against their portfolio value
- The platform allowed borrowing up to ~90% of collateral value
- Price feeds came from oracles (likely Pyth and centralized exchange feeds) that monitored average prices across multiple exchanges

### Key Design Choice: Using the Same Collateral System for Perps and Lending
Users' unrealized PnL on perpetual positions counted toward their borrowing power. If you had a profitable long position on MNGO perps, that unrealized gain could be used to borrow real assets.

---

## The Exploit (Step by Step)

### Setup (Pre-Attack)
1. Eisenberg deposited $5M USDC into two separate Mango accounts (Account A and Account B)

### Phase 1: Create Offsetting Positions
2. Using Account A: opened a massive **long** position on MNGO-PERP (perpetual futures)
3. Using Account B: opened an equally massive **short** position on MNGO-PERP
4. These positions offset each other — at this point, net exposure is zero, and no manipulation has occurred yet

### Phase 2: Pump the Oracle Price
5. Over ~10 minutes, Eisenberg bought $4M worth of MNGO tokens on three external exchanges: FTX, AscendEX, and Serum (decentralized)
6. MNGO had extremely thin liquidity on these exchanges — $4M of buying pressure moved the price by ~2,300% (from ~$0.03 to ~$0.91)
7. Mango's oracle, which averaged prices from these exchanges, reported the inflated MNGO price

### Phase 3: Borrow Against Inflated Collateral
8. Account A's long MNGO-PERP position now showed massive unrealized profit (MNGO price 23x higher)
9. This unrealized profit counted as collateral on Mango
10. Using this inflated collateral, Eisenberg borrowed $110M in USDC, SOL, and other assets from Mango's lending pools
11. Withdrew the borrowed assets immediately

### Phase 4: Let It Collapse
12. Eisenberg stopped buying MNGO → price crashed back to normal
13. Account A's long position was now deeply underwater → liquidated, but no assets left to seize
14. Account B's short position was profitable, but Eisenberg had already drained the lending pools
15. Mango was left with ~$110M in bad debt

### Aftermath
- Eisenberg publicly claimed the exploit was "legal open market actions, using the protocol as designed"
- He returned $67M after negotiations with the Mango DAO
- He was later arrested and convicted of commodities fraud and manipulation (though convictions were overturned in May 2025 by a federal judge)

---

## Root Cause Analysis

### Primary: Oracle Manipulability via Thin Liquidity
The MNGO token had very low liquidity across all exchanges that fed the oracle. Moving the price 23x required only $4M — trivially small compared to the $110M extractable from the protocol. The oracle reported the manipulated price as truth.

### Contributing Factor: Unrealized PnL as Borrowing Collateral
Allowing unrealized perpetual futures PnL to serve as borrowing collateral creates a direct path from price manipulation to fund extraction. The unrealized gain was never "real" — it was a paper profit on a manipulated price — but the protocol treated it as valid collateral.

### Contributing Factor: No Position Size Limits Relative to Market Liquidity
There was no check that the user's position size was reasonable relative to the underlying market's liquidity. A position that represents >50% of the total market depth is inherently manipulable.

### Contributing Factor: No Collateral Concentration Limits
The protocol allowed a single user to borrow against a single, illiquid asset without limits. There was no cap on how much of total lending pool TVL could be borrowed against a single collateral type.

### Contributing Factor: No Withdrawal Limits or Delays
$110M was withdrawn instantly with no circuit breaker, rate limiting, or time delay for large withdrawals.

---

## Lessons for Auditors

### Pattern: Oracle Manipulation via Thin Liquidity
**Any protocol that uses price feeds for collateral valuation must consider the cost of manipulating those feeds.** The key metric is:

```
Manipulation Cost = Capital needed to move price X% on all oracle sources
Extractable Value = Total borrowable amount at manipulated price

If Extractable Value > Manipulation Cost → the protocol is exploitable
```

### What To Look For
- Single-source oracle (only one exchange or one DEX pool)
- Oracle for low-liquidity tokens used as collateral
- No TWAP (time-weighted average price) — spot price is trivially manipulable
- No liquidity-weighted averaging — a $1M pool and a $1B pool weighted equally
- No oracle deviation circuit breakers ("if price moves >X% in Y minutes, pause")

### Pattern: Unrealized PnL as Collateral
If a protocol counts unrealized derivatives PnL as borrowing collateral, ask:
- Can the user manipulate the price of the underlying to inflate their PnL?
- Is there a delay before unrealized PnL becomes usable as collateral?
- Is there a cap on how much can be borrowed against unrealized gains?

### Pattern: Missing Economic Security Parameters
- **No borrowing cap per asset type**: A single illiquid token shouldn't back unlimited borrowing
- **No borrowing cap per user**: One user shouldn't be able to drain the entire lending pool
- **No withdrawal rate limiting**: Large withdrawals should trigger delays or manual review
- **No open interest limits**: Position sizes should be bounded relative to market liquidity

---

## Detection Checklist (For Similar Vulnerabilities)

1. [ ] Does the protocol use oracle prices for collateral valuation? If yes, what is the cost to manipulate those prices?
2. [ ] Is there a TWAP or multi-source oracle, or just spot price from a single source?
3. [ ] Are there circuit breakers for sudden large price movements?
4. [ ] Does unrealized PnL from derivatives count as borrowing collateral?
5. [ ] Are there per-asset borrowing caps relative to the asset's market liquidity?
6. [ ] Are there per-user borrowing limits or position size limits?
7. [ ] Is there withdrawal rate limiting for large amounts?
8. [ ] Can a single user's position represent a majority of the oracle source's liquidity?
9. [ ] Are oracle sources weighted by liquidity depth?
10. [ ] Is there a minimum liquidity requirement for assets used as collateral?
