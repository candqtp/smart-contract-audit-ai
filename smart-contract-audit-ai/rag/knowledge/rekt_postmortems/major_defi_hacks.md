# Major DeFi Hack Post-Mortems

Technical breakdown of critical DeFi exploits. Each entry: root cause, attack steps, code pattern, fix.

---

## Ronin Bridge — $625M (March 2022)

**Root cause:** Insufficient validator multisig threshold + social engineering

**Attack:**
1. Ronin used a 5-of-9 validator multisig for bridge withdrawals
2. Sky Mavis (Axie developer) had been granted temporary approval of 4 validator keys during high traffic — approval never revoked
3. Attacker (North Korea's Lazarus Group) compromised Sky Mavis keys via spear phishing
4. With 4 Sky Mavis keys + 1 Axie DAO key (also compromised), attacker reached 5/9 threshold
5. Signed two fraudulent withdrawal transactions: 173,600 ETH + 25.5M USDC

**Root cause pattern:**
```solidity
// VULNERABLE: temporary key grants never audited or revoked
// Sky Mavis controlled 4/9 validators — if compromised, only 1 more needed
// No time-based expiry on delegated validator roles
// No anomaly detection on large single withdrawals
```

**Fix:** Increase threshold to 8/9, implement time-limited delegations, add withdrawal amount circuit breakers, monitor for anomalous large single transactions.

---

## Euler Finance — $197M (March 2023)

**Root cause:** Donation + liquidation interaction — violating health factor assumptions

**Attack sequence:**
1. Attacker uses a flash loan to get initial capital
2. Deposits into Euler (gets eTokens representing collateral)
3. Calls `donateToReserves()` — a function that decreases the caller's eToken balance but NOT their debt
4. This artificially makes the attacker's position undercollateralized
5. Attacker uses a second account to liquidate the first — receives the discounted collateral
6. The liquidation bonus paid out exceeds what the protocol can sustain → bad debt

**Vulnerable code pattern:**
```solidity
// The donateToReserves function should have checked health factor after donation
function donateToReserves(uint subAccountId, uint amount) external {
    // ... reduce user's eToken balance ...
    // MISSING: checkLiquidity(account) — health factor check after donation
    // Without this check, position becomes liquidatable immediately after donation
}
```

**Fix:** Any function that reduces collateral must check health factor after execution.

---

## Nomad Bridge — $190M (August 2022)

**Root cause:** Uninitialized trusted root — every message treated as valid

**Attack:**
1. Nomad stores a mapping of `acceptableRoots` — Merkle roots of valid message batches
2. During an upgrade, the `confirmAt` mapping for root `0x00` was set to `1` (non-zero)
3. `0x00` (zero bytes) is the default value for uninitialized bytes32
4. Any message with a zero Merkle proof (`bytes32(0)`) would pass validation
5. Attackers copied the original attacker's transaction, changed only the recipient address, and submitted it — each copy drained funds
6. No special knowledge needed — attack became permissionless, crowd-sourced drain

**Vulnerable pattern:**
```solidity
// After upgrade, trusted root mapping had this state:
acceptableRoots[bytes32(0)] = 1;  // zero root accepted!

function process(bytes memory message) public {
    bytes32 messageHash = keccak256(message);
    // VULNERABLE: if proof == bytes32(0) and acceptableRoots[0] is set, passes
    require(acceptableRoots[provenAt[messageHash]] != 0, "Not proven");
    // Anyone sending a message with proof = 0x00 passes this check
}
```

**Fix:** Never allow zero values as valid roots. Validate that root is non-zero before accepting.

---

## Cream Finance — $130M (October 2021)

**Root cause:** Price oracle manipulation via flash loan + AMP token reentrancy

**Attack (two-step):**
1. Flash loan 500M USDC from MakerDAO
2. Deposit into Cream → get crUSDC as collateral
3. Use crUSDC to borrow ETH
4. AMP token implements ERC777 — calling `transfer` triggers `tokensReceived` hook on receiver
5. During AMP transfer (step in re-borrowing), attacker's `tokensReceived` hook re-enters Cream
6. At this point, Cream's state shows original collateral but debt not yet updated
7. Borrow again using same collateral — double-spend of collateral
8. Repeat re-entry 17 times — borrow much more than collateral should allow

**Pattern:**
```solidity
// Cream's borrow function didn't account for ERC777 reentrancy
function borrow(uint borrowAmount) external {
    // Check collateral
    require(getAccountLiquidity(msg.sender) >= borrowAmount, "Insufficient collateral");
    // Transfer borrowed tokens — triggers ERC777 hook if token is ERC777!
    doTransferOut(msg.sender, borrowAmount);  // ← REENTRANCY POINT
    // Update debt — happens AFTER transfer, so re-entering sees stale state
    accountBorrows[msg.sender] += borrowAmount;
}
```

**Fix:** Always update state BEFORE external token transfers. Use reentrancy guards.

---

## Wormhole Bridge — $320M (February 2022)

**Root cause:** Deprecated Solana instruction accepted as valid guardian signature

**Attack:**
1. Wormhole cross-chain bridge relies on guardian signatures to validate cross-chain messages
2. Solana instruction `load_instruction_at` was deprecated — replaced with `load_instruction_at_checked`
3. The deprecated version did not properly validate the instruction was a sysvar (system account)
4. Attacker used a fake sysvar account that mimicked the expected structure
5. Signature verification passed against this fake account
6. Attacker minted 120,000 wETH on Solana without depositing any ETH on Ethereum

**Pattern:**
```rust
// Vulnerable: deprecated instruction doesn't validate account is actual sysvar
let ix = load_instruction_at(0, &sysvar_account)?;  // accepts fake accounts

// Fixed: checked version validates sysvar account is legitimate
let ix = load_instruction_at_checked(0, &sysvar_account_info)?;
```

**Lesson:** Always use the latest, checked versions of standard library functions. Deprecated functions often exist because they had security issues.

---

## Poly Network — $611M (August 2021)

**Root cause:** Attacker manipulated cross-chain message to call `putCurEpochConPubKeyBytes` — changing the "keeper" address to attacker-controlled address

**Attack:**
1. Cross-chain messages are processed by a `EthCrossChainManager` contract
2. This contract called a method on `EthCrossChainData` contract
3. The method `putCurEpochConPubKeyBytes` could be called by the manager contract
4. Attacker crafted a malicious cross-chain message that, when processed, called this privileged function
5. Changed the keeper (admin) to attacker's address — giving them control over the bridge

**Pattern:**
```solidity
// VULNERABLE: cross-chain message executor can call any function on any contract
function executeCrossChainTx(address _toContract, bytes memory _method, bytes memory _args) internal {
    (bool success, bytes memory returnData) = _toContract.call(
        abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bytes,bytes,uint64)"))), abi.encode(_args, ...)
    );
    // No whitelist of allowed functions — can call ANYTHING on _toContract
}
```

**Fix:** Whitelist functions that cross-chain messages can invoke. Never allow arbitrary function calls from external message sources.

---

## Mango Markets — $114M (October 2022)

**Root cause:** Oracle price manipulation using the protocol's own native token

**Attack:**
1. Attacker took two large opposing positions on Mango's perpetual futures
2. On one account: large long position on MNGO (Mango's token)
3. Used second account: large short position (providing the other side of the trade)
4. Bought MNGO heavily on spot markets — pumped price 10x in minutes
5. Mango's oracle used spot price — inflated collateral value of long position
6. Used inflated collateral to borrow ~$114M in various tokens
7. Let accounts go to bad debt — borrowed funds never repaid
8. Attempted to "negotiate" keeping $47M as "bug bounty"

**Pattern:**
```
VULNERABLE: oracle reads current spot price
Attacker controls spot price by being dominant buyer
Collateral value = amount × manipulated_price → inflated
Borrow limit = inflated collateral × factor → borrow more than real value
```

**Fix:** TWAP oracles resistant to single-block manipulation. Circuit breakers on price movement. Position size limits relative to token liquidity.

---

## Beanstalk — $182M (April 2022)

**Root cause:** Flash loan governance attack — snapshot taken at vote time, not proposal creation

**Attack:**
1. Attacker submitted a malicious governance proposal (BIP-18) two days in advance
2. Waited for proposal to be ready for execution
3. Flash borrowed ~$1B in stablecoins via Aave
4. Used borrowed funds to acquire supermajority of Beanstalk governance tokens in one block
5. Voted on and immediately executed the malicious proposal (no timelock!)
6. Proposal transferred all Beanstalk protocol funds to attacker
7. Repaid flash loan in same transaction
8. Net profit: $80M (after repaying flash loan and other costs)

**Pattern:**
```solidity
// VULNERABLE: no timelock + snapshot at vote time
function vote(uint256 proposalId) external {
    uint256 votes = governanceToken.balanceOf(msg.sender);  // current balance
    // Flash borrow → huge balance → supermajority → execute immediately
}

// FIXED:
// 1. Snapshot at proposal CREATION, not vote time
uint256 votes = governanceToken.getPastVotes(msg.sender, proposal.snapshotBlock);
// 2. Mandatory timelock between vote passing and execution (48h minimum)
// 3. Quorum must be held for >1 block (holding borrowed tokens for 1 block is costly)
```

---

## Parity Multisig — $30M (July 2017) + $150M Frozen (November 2017)

**Root cause July:** Unprotected wallet initialization — anyone could call `initWallet` on the deployed wallet library

**Root cause November:** Library contract self-destructed — all dependent proxy wallets lost their logic

**Attack (July):**
1. Parity multisig wallets delegatecall to a shared library contract
2. Library contract had `initWallet` with no protection
3. Attacker called `initWallet` on the library directly, set themselves as owner
4. Called `execute()` to drain funds from 3 multisig wallets

**Pattern:**
```solidity
// VULNERABLE: no initialization guard
function initWallet(address[] _owners, uint _required, uint _daylimit) {
    m_owners[1] = uint(msg.sender);  // no check if already initialized
    m_numOwners = 1;
    // ...
}
```

**November (150M frozen):**
A "white hat" accidentally called `initWallet` on the library thinking they were protecting it — then called `kill()` to prevent further exploitation. Library self-destructed. All proxy wallets depending on it permanently lost their delegatecall target — funds frozen forever.

**Fix:** `initializer` modifier (only once). Always test what happens if someone calls `selfdestruct` on your dependencies.

---

## Lessons Summary

| Hack | Root Cause | Key Pattern |
|------|-----------|-------------|
| Ronin | Key management | Multisig threshold + revocation |
| Euler | Logic error | State change before health check |
| Nomad | Initialization | Zero value treated as valid |
| Cream | Reentrancy + ERC777 | External call before state update |
| Wormhole | Deprecated API | Old function not fully validated |
| Poly | Auth bypass | Cross-chain arbitrary call |
| Mango | Oracle manipulation | Spot price + own token |
| Beanstalk | Flash loan governance | No snapshot at proposal creation |
| Parity | Uninitialized library | No init guard + unprotected selfdestruct |
