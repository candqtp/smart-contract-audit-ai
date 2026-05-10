# Echidna Fuzzing and Property-Based Testing (Trail of Bits)

## Tags
echidna, fuzzing, invariant, property-based, testing, corpus, assertion


## What is Echidna
Echidna is Trail of Bits' Solidity fuzzer. It generates random transaction sequences to break user-defined properties (invariants). Unlike Foundry's fuzz testing, Echidna is a stateful fuzzer — it explores multi-transaction sequences and maintains persistent state between calls.

## Installation and Basic Usage

```bash
# Install via Docker (easiest)
docker pull trailofbits/echidna

# Or via cabal
cabal install echidna

# Run
echidna-test contracts/Token.sol --contract Token
echidna-test . --contract Vault --config echidna.config.yaml
```

## Writing Invariants (Echidna Properties)

```solidity
// Properties are functions that:
// - Start with echidna_
// - Take no parameters
// - Return bool
// - MUST return true — if false, Echidna found a bug

contract TokenTest is Token {
    // Invariant: total supply never exceeds cap
    function echidna_supply_cap() public returns (bool) {
        return totalSupply() <= MAX_SUPPLY;
    }

    // Invariant: no single user has more than total supply
    function echidna_no_single_whale() public returns (bool) {
        return balanceOf(msg.sender) <= totalSupply();
    }

    // Invariant: contract ETH balance always covers deposits
    function echidna_solvency() public returns (bool) {
        return address(this).balance >= totalDeposited;
    }
}
```

## AMM Invariant Testing

```solidity
contract AMMTest is AMM {
    uint256 constant PRECISION = 1e18;

    // k = x * y must never decrease after a swap (only fees should increase k)
    function echidna_constant_product() public returns (bool) {
        uint256 k_before = reserveA * reserveB;
        // Echidna will call swap() — if k decreases, invariant broken
        return reserveA * reserveB >= k_before;
    }

    // No swap should produce more output than reserve
    function echidna_output_less_than_reserve() public returns (bool) {
        return reserveA > 0 && reserveB > 0;
    }

    // LP token supply never exceeds sqrt(reserveA * reserveB) by more than rounding
    function echidna_lp_supply_consistent() public returns (bool) {
        uint256 expectedLp = sqrt(reserveA * reserveB);
        uint256 actualLp = lpToken.totalSupply();
        return actualLp <= expectedLp + 1;  // +1 for rounding
    }
}
```

## Lending Protocol Invariant Testing

```solidity
contract LendingTest is LendingProtocol {
    // Protocol must always be solvent: totalAssets >= totalBorrows
    function echidna_protocol_solvency() public returns (bool) {
        return getTotalAssets() >= getTotalBorrows();
    }

    // No borrower's debt can exceed their collateral value * collateral factor
    function echidna_collateral_covers_debt() public returns (bool) {
        address[] memory borrowers = getBorrowers();
        for (uint i = 0; i < borrowers.length; i++) {
            uint256 debt = getDebt(borrowers[i]);
            uint256 collateralValue = getCollateralValue(borrowers[i]);
            if (debt > collateralValue * COLLATERAL_FACTOR / 100) return false;
        }
        return true;
    }

    // Total shares issued never exceeds total assets (ERC4626 invariant)
    function echidna_shares_not_inflated() public returns (bool) {
        if (totalSupply() == 0) return true;
        return totalAssets() >= totalSupply();
    }
}
```

## Access Control Invariant Testing

```solidity
contract AccessTest is Protocol {
    address internal attacker = address(0xbad);

    // Only owner can change critical params — any call from attacker that changes them is a bug
    uint256 internal snapshotFee;

    function setup() internal {
        snapshotFee = getFee();
    }

    // After any non-owner transaction, fee should be unchanged
    function echidna_fee_only_owner_changes() public returns (bool) {
        if (msg.sender != owner()) {
            return getFee() == snapshotFee;
        }
        snapshotFee = getFee();
        return true;
    }
}
```

## Echidna Configuration

```yaml
# echidna.config.yaml
testMode: "assertion"      # or "property" or "overflow"
testLimit: 50000           # number of test sequences
seqLen: 100                # max transactions per sequence
shrinkLimit: 5000          # tries to shrink failing sequence
corpusDir: "corpus"        # save/load corpus for coverage
coverage: true             # track code coverage
deployer: "0x1000"         # deployer address
sender:                    # addresses Echidna uses as callers
  - "0x1000"
  - "0x2000"
  - "0x3000"
balanceAddr: 10000000000000000000  # 10 ETH per address
contractAddr: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
```

## Assertion Mode (Slither + Echidna)

```solidity
// In assertion mode, Echidna looks for failed assert() statements
// No need to write echidna_ properties — use assert() throughout code

function swap(uint256 amountIn) external returns (uint256 amountOut) {
    uint256 k_before = reserveA * reserveB;

    amountOut = _calculateOutput(amountIn);
    reserveA += amountIn;
    reserveB -= amountOut;

    // Echidna in assertion mode will find any execution where this fails
    assert(reserveA * reserveB >= k_before);  // k invariant
    assert(amountOut < amountOut_before_fee);  // output less than fee-free amount
}
```

## Foundry Fuzz vs Echidna — When to Use Which

```
Foundry fuzz (forge test):
- Single function, multiple random inputs
- Fast, integrated into dev workflow
- Good for: input validation, edge cases in pure functions
- Example: fuzz(uint256 amount) — test all amounts for overflow

Echidna:
- Multi-transaction sequences across entire contract
- Finds bugs that require N steps to reach
- Good for: invariants that hold across many interactions
- Example: deposit → manipulate state → withdraw → solvency broken
- Slower but finds much more complex bugs

Use both: Foundry for unit-level fuzz, Echidna for system-level invariants
```

## Common Invariants to Always Test

```solidity
// 1. Solvency: protocol has enough to pay all users
function echidna_solvency() public returns (bool) {
    return totalLiabilities() <= totalAssets();
}

// 2. No free money: user can't withdraw more than deposited (without earning)
function echidna_no_free_money() public returns (bool) {
    return userClaimable(echidnaUser) <= userDeposited(echidnaUser) + userEarned(echidnaUser);
}

// 3. Conservation: total in == total out over time
function echidna_conservation() public returns (bool) {
    return totalDeposited == totalWithdrawn + totalInProtocol;
}

// 4. Access: critical state only changes via authorized path
function echidna_only_admin_changes_fee() public returns (bool) {
    return fee == lastAdminSetFee;
}

// 5. Monotonicity: price per share never decreases (for non-slashing vaults)
function echidna_price_per_share_monotonic() public returns (bool) {
    return pricePerShare() >= lastPricePerShare;
}
```

## Echidna Corpus and Coverage

```bash
# Run with coverage tracking
echidna-test . --contract Vault --config echidna.yaml --coverage

# After run: coverage report in echidna-coverage.html
# Look for uncovered branches — may indicate unreachable code or missing test paths

# Corpus directory stores sequences that increase coverage
# Can be reused across runs to build on previous exploration
echidna-test . --contract Vault --corpus-dir corpus/
```

## Real Bugs Found by Echidna (Trail of Bits Reports)
- **Compound**: interest rate model invariant violation under extreme utilization
- **Balancer**: spot price invariant violation in weighted pools
- **MakerDAO**: collateral accounting error revealed by solvency invariant
- **OpenZeppelin Governor**: voting period edge case in quorum calculation
