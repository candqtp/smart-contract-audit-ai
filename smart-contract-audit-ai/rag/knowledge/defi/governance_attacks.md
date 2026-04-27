# Governance Attack Patterns in DeFi

## Why Governance Is High Risk
Governance controls protocol parameters, treasury, contract upgrades. Compromise of governance = compromise of everything. Flash loans made token-based governance catastrophically vulnerable.

## Attack Class 1: Flash Loan Governance Takeover (Beanstalk Pattern)

```solidity
// VULNERABLE — voting power from current balance, not historical snapshot
// Execution not timelocked, or timelock can be bypassed

contract Governance {
    IToken public token;
    mapping(uint256 => Proposal) public proposals;

    struct Proposal {
        address target;
        bytes callData;
        uint256 forVotes;
        bool executed;
        uint256 deadline;
    }

    function vote(uint256 proposalId) external {
        uint256 votes = token.balanceOf(msg.sender);  // CURRENT balance — flash loanable
        proposals[proposalId].forVotes += votes;
    }

    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(block.timestamp > p.deadline);  // deadline passed
        require(p.forVotes > quorum);
        require(!p.executed);
        p.executed = true;
        (bool ok,) = p.target.call(p.callData);
        require(ok);
    }
}
// Attack:
// 1. Submit malicious proposal: target=treasury, callData=transferAll(attacker)
// 2. Flash borrow huge amount of governance token
// 3. vote() — gain supermajority
// 4. Repay flash loan (can do in same tx if execute is immediate)
// 5. execute() — drain treasury

// FIXED:
// 1. Use historical snapshot: token.getPastVotes(account, proposal.snapshotBlock)
// 2. Mandatory timelock between vote passing and execution (48h+)
// 3. Quorum must be maintained at execution time too
```

## Attack Class 2: Snapshot Block Manipulation

```solidity
// Even with snapshots, snapshot block choice matters
// VULNERABLE — snapshot taken at proposal EXECUTION, not CREATION

function execute(uint256 proposalId) external {
    Proposal storage p = proposals[proposalId];
    // Takes snapshot NOW — attacker accumulates tokens just before execution
    uint256 forVotes = countVotesAtBlock(p, block.number);  // current block!
    require(forVotes > quorum);
    // ...
}

// FIXED — snapshot at proposal creation
function propose(...) external returns (uint256 proposalId) {
    uint256 snapshotBlock = block.number;
    proposals[proposalId] = Proposal({
        snapshotBlock: snapshotBlock,  // locked in at creation
        // ...
    });
}

function vote(uint256 proposalId) external {
    uint256 votes = token.getPastVotes(msg.sender, proposals[proposalId].snapshotBlock);
    // Historical balance — flash loans have no effect
}
```

## Attack Class 3: Governance Proposal Frontrunning

```solidity
// Attacker watches mempool for a legitimate governance proposal
// Submits a malicious proposal with higher gas (executes first)
// Legitimate proposal executed AFTER malicious one — state already changed

// Or: attacker frontruns proposal CANCELLATION
// Just before guardian cancels malicious proposal, attacker executes it

// Mitigation: guardian veto power that works even after quorum reached
// Mitigation: multi-sig controlled guardian can pause execution
mapping(uint256 => bool) public vetoed;

function veto(uint256 proposalId) external onlyGuardian {
    vetoed[proposalId] = true;
}

function execute(uint256 proposalId) external {
    require(!vetoed[proposalId], "Proposal vetoed");
    // ...
}
```

## Attack Class 4: Governance Griefing via Spam Proposals

```solidity
// VULNERABLE — no cost to propose
function propose(address target, bytes calldata data) external returns (uint256) {
    // No proposal threshold — anyone with 1 token can propose
    proposals.push(Proposal(target, data, block.number, 0, false));
    return proposals.length - 1;
}
// Attacker spams proposals — governance queue flooded, real proposals delayed/missed

// FIXED — proposal threshold
uint256 public proposalThreshold = 1000e18;  // must hold 1000 tokens

function propose(...) external returns (uint256) {
    require(
        token.getPastVotes(msg.sender, block.number - 1) >= proposalThreshold,
        "Below proposal threshold"
    );
    // ...
}
```

## Attack Class 5: Timelock Bypass

```solidity
// Compound Governor uses a separate Timelock contract
// VULNERABLE — multiple paths to execute without full timelock

// Pattern 1: admin bypass
// If Timelock.admin can change implementation without delay, attacker targets admin

// Pattern 2: queued tx cancellation race
// Governance queues legitimate upgrade
// Attacker submits conflicting tx to same timelock slot → first queued tx cancelled
// (requires some knowledge of slot hash collision)

// Pattern 3: expired queued transaction
// Transaction queued but not executed within grace period (default 14 days)
// After grace period, tx is expired and must be re-queued
// Attacker exploits the window between expiry and re-queue

// FIXED — grace period should be long enough for governance to re-queue if needed
// Monitor for queued txs approaching expiry
```

## Attack Class 6: Delegate Manipulation

```solidity
// Many governance systems use ERC20Votes delegation
// VULNERABLE — self-delegation creates vote amplification in some buggy implementations

// Bug seen in Code4rena: delegating to address(0) then from address(0)
// Total vote supply miscounted
contract VotesToken is ERC20Votes {
    // VULNERABLE pattern: delegate(address(0)) miscounts checkpoint
    // Some implementations treat address(0) as a "burn" of votes
    // Then delegating FROM address(0) in same block can create votes from nothing
}

// ALSO: checkpointing not atomic with transfer
// If transfer and delegate happen in same block, vote snapshot can be wrong
```

## Attack Class 7: Malicious Proposal Disguised as Legitimate

```solidity
// Multi-action proposals can hide malicious actions
// Attacker proposes: [legitimate_action_1, legitimate_action_2, DRAIN_TREASURY]
// Community reviews actions 1 and 2 (both fine), misses action 3

// Mitigation: require review period proportional to number of actions
// Require independent security review for upgrades

// Common disguise pattern:
targets = [
    address(treasury),         // seems like routine maintenance
    address(implementation),   // "minor bug fix upgrade"
    address(attacker_contract) // buried in proposal — actually drains everything
];
```

## Immunefi Critical Governance Patterns

```
1. Governance token minted by admin without cap → admin can gain supermajority
   Seen: Multiple DAO protocols

2. proposal() callable by address with borrowed tokens (no delegation required)
   Seen: Fei Protocol near-miss, multiple Code4rena findings

3. Timelock delay is 0 → immediate execution, no human review window
   Seen: Several newly launched protocols

4. Guardian role is a smart contract that can be front-run to drain it
   Seen: Multiple Compound forks

5. Quorum check only at vote time, not execution time
   User sells tokens after voting → quorum is actually lower at execution
   Seen: OpenZeppelin Governor inherited bug (fixed in v4.6)
```

## Sherlock Governance Findings

```
HIGH:
1. Token holder can vote and then transfer to another address to vote again
   (double voting — missing delegation checkpoint)
2. Proposals can be executed before timelock via emergency bypass path
3. Governance can be permanently bricked if admin renounces before setting guardian

MEDIUM:
1. Proposal threshold not enforced at execution — proposer can lose tokens and still execute
2. Vote counting off-by-one — boundary condition in block range
3. Quorum denominator includes tokens in bridge/locked contracts (inflated quorum)
```

## Detection Signals
- `token.balanceOf(msg.sender)` in `vote()` instead of `getPastVotes`
- Timelock delay set to 0 or very short (< 2 days for DeFi)
- No guardian veto mechanism
- Proposal threshold is 0 (anyone can propose)
- Same address can vote multiple times (transfer → vote → transfer back)
- `execute()` doesn't re-check quorum at execution time
- Proposals accepted with calldata targeting unrestricted admin functions

## Severity Guide
- Flash loan governance with immediate execution: **Critical**
- No snapshot (current balance for voting): **Critical**
- Zero timelock: **Critical**
- No guardian veto: **High**
- No proposal threshold: **Medium**
- Double voting via transfer: **High**
- Quorum not rechecked at execution: **Medium**
