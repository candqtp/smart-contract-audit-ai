# Postmortem: Euler Finance Hack ($197M, March 13 2023)

## Tags
euler, donation-attack, donateToReserves, checkLiquidity, health-check, self-liquidation, soft-liquidation, lending, flash-loan, eToken, dToken, bad-debt, invariant

## Summary
Euler Finance was exploited for ~$197M due to a missing health check in the `donateToReserves()` function. The attacker used flash-loaned capital to create a large leveraged position, then donated their own collateral to protocol reserves — deliberately making themselves insolvent — and self-liquidated at a 20% discount to extract profit. The root cause was a single missing line: a call to `checkLiquidity()` after the donation.

---

## Background: How Euler Worked

### Token System
- **eTokens**: Equity/collateral tokens. Depositors receive eTokens representing their share of the pool.
- **dTokens**: Debt tokens. Borrowers receive dTokens representing their outstanding debt.
- **Health score**: `(collateral_value * MaxLTV) / debt_value`. If < 1.0, the position is liquidatable.

### Self-Collateralized Leverage
Euler allowed users to create leveraged positions within a single transaction by minting and depositing in the same call. This let users hold more eTokens than the protocol's actual underlying balance — an intentional feature for capital efficiency.

### Soft Liquidation
Euler used a dynamic "soft liquidation" model: the less healthy a position, the higher the proportion of collateral a liquidator could seize, up to a maximum 20% discount. This was designed to incentivize faster liquidation of deeply underwater positions.

---

## The Vulnerability

### Origin of donateToReserves
The function was added in **eIP-14** as a fix for a separate "first depositor" exchange rate manipulation bug found via Immunefi's bug bounty program. The original bug: an attacker could inflate the eToken exchange rate when a pool had no prior depositors, causing the first legitimate depositor to receive 0 eTokens due to rounding.

The fix was to establish an initial reserve of eTokens. `donateToReserves()` allowed users to voluntarily donate their eTokens to the protocol's reserve balance.

### The Missing Check
Every state-modifying function in Euler was supposed to route through a "risk manager" module that called `checkLiquidity()` — verifying the caller's health score remained >= 1.0 after the operation. **`donateToReserves()` was the one function that skipped this check.**

```
// Pseudocode of the vulnerable flow:
function donateToReserves(uint amount) {
    // Burns caller's eTokens, adds to reserveBalance
    balances[msg.sender] -= amount;
    reserveBalance += amount;
    // MISSING: checkLiquidity(msg.sender)
    // Caller's debt (dTokens) remains unchanged
    // Caller can now be underwater with no health check preventing it
}
```

### Why This Was Missed
- The function seemed harmless — "who would voluntarily donate their own collateral?"
- It was added as a fix for a different bug, and the security review focused on the original bug, not the new code path
- Six security firms had audited Euler at various points, but the donateToReserves addition was reviewed by only one (Sherlock)
- The vulnerability only became exploitable in combination with soft liquidation — individually, neither feature was broken

---

## The Attack (Step by Step)

### Setup
1. Attacker deploys two contracts: **Violator** (creates the bad position) and **Liquidator** (self-liquidates)

### Execution
2. Flash loan a large amount of DAI (e.g., 30M)
3. **Violator** deposits 20M DAI → receives eDAI
4. **Violator** uses Euler's leverage feature to mint additional eDAI and dDAI (self-collateralized borrowing), reaching ~310M eDAI and ~390M dDAI
5. **Violator** calls `donateToReserves(100M eDAI)` — donates 100M of their collateral to reserves
6. After donation: Violator has 210M eDAI collateral but 390M dDAI debt → health score drops to ~0.75 → deeply underwater
7. **Liquidator** (attacker's second contract) calls `liquidate()` on the Violator's position
8. Euler's soft liquidation gives the Liquidator collateral at a 20% discount: Liquidator receives 310M eDAI and takes on ~259M dDAI
9. **Liquidator** redeems eDAI for underlying DAI (burns 38.9M eDAI → withdraws 38.9M DAI)
10. Repay flash loan, keep the profit

### Key Insight
Because the donation made the Violator deeply insolvent (not just slightly underwater), the soft liquidation mechanism gave the maximum discount. The collateral the Liquidator received was worth MORE than the debt they assumed, because the discount was calculated assuming positions couldn't be THIS far underwater.

---

## Root Cause Analysis

### Primary: Missing Invariant Enforcement
The invariant `health_score >= 1.0` should hold after EVERY state change. `donateToReserves()` broke this invariant without any check.

### Contributing Factor: Soft Liquidation Assumed Bounded Insolvency
The liquidation math assumed positions would only be slightly underwater (since health checks should prevent deep insolvency). The 20% discount was profitable for the attacker precisely because the position was FAR underwater — something that should have been impossible.

### Contributing Factor: Code Added Without Full Context Review
The donation feature was a fix for a different bug. The review focused narrowly on whether the fix resolved the original issue, not on what new attack surfaces it created.

---

## Lessons for Auditors

### Pattern: Missing Health Check After State Modification
**Any function in a lending protocol that modifies a user's collateral or debt ratio MUST call a health check afterward.** This includes seemingly benign operations like:
- Donating collateral
- Transferring debt tokens
- Admin functions that modify collateral factors
- Fee collection that reduces a user's balance

### Pattern: Interaction Between Features Creates New Attack Surface
Neither self-collateralized leverage nor soft liquidation was individually vulnerable. The combination — plus the missing check — created the exploit. Auditors must consider cross-feature interactions, not just individual function correctness.

### Pattern: Fixes That Introduce New Bugs
The donation function existed solely as a fix for a prior bug. New code added to remediate issues deserves the same (or more) scrutiny as original code.

---

## Detection Checklist (For Similar Vulnerabilities)

1. [ ] Does every function that modifies collateral or debt call a health/solvency check afterward?
2. [ ] Are there ANY code paths that can make a position insolvent without triggering liquidation?
3. [ ] Does the liquidation mechanism handle deeply underwater positions correctly (not just slightly underwater)?
4. [ ] Are functions added as bug fixes audited as thoroughly as new features?
5. [ ] Is there invariant testing that `health_score >= 1.0` holds after every possible operation?
6. [ ] Can a user self-liquidate? If so, is the outcome always unprofitable for the attacker?
7. [ ] Are reserve/treasury operations (donate, sweep, fee collection) subject to the same safety checks as user operations?
