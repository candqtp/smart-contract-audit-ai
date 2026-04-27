# Denial of Service Vulnerabilities in Solidity (SWC-113)

## Overview
DoS attacks either permanently break a contract's functionality or make it economically infeasible to use. The most common vectors: gas exhaustion from unbounded loops, state that becomes impossible to progress, and revert-in-receiver patterns.

## Vulnerability 1: Unbounded Loop Over User-Controlled Array

```solidity
// VULNERABLE — array grows with each user, loop gas cost O(n)
address[] public stakers;
mapping(address => uint256) public stakes;

function addStaker(address staker) external {
    stakers.push(staker);
}

function distributeRewards(uint256 totalReward) external onlyOwner {
    for (uint256 i = 0; i < stakers.length; i++) {  // O(n) — hits gas limit when n large
        uint256 share = totalReward * stakes[stakers[i]] / totalStaked;
        payable(stakers[i]).transfer(share);  // if any staker is contract that reverts → DoS
    }
}
// Attacker adds 10,000 addresses to stakers array → distributeRewards() always out of gas

// FIXED — pull pattern with per-user claim
mapping(address => uint256) public claimable;
uint256 public rewardPerShareAccumulated;

// Users call claim() themselves — no loop, no DoS
function claim() external {
    uint256 pending = rewardPerShareAccumulated * stakes[msg.sender] / PRECISION - claimed[msg.sender];
    claimed[msg.sender] = rewardPerShareAccumulated * stakes[msg.sender] / PRECISION;
    payable(msg.sender).transfer(pending);
}
```

## Vulnerability 2: Revert in Receiver Blocks Progress

```solidity
// VULNERABLE — leader board auction where current leader gets refunded
contract Auction {
    address public leader;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid);
        // Refund previous leader
        payable(leader).transfer(highestBid);  // REVERTS if leader is malicious contract
        leader = msg.sender;
        highestBid = msg.value;
    }
}

// Attack: MaliciousContract takes the lead, receive() always reverts
// No one can ever outbid — auction frozen, attacker wins by default

// FIXED — pull refunds
mapping(address => uint256) public pendingRefunds;

function bid() external payable {
    require(msg.value > highestBid);
    pendingRefunds[leader] += highestBid;  // store refund, don't send
    leader = msg.sender;
    highestBid = msg.value;
}

function withdrawRefund() external {
    uint256 amount = pendingRefunds[msg.sender];
    require(amount > 0);
    pendingRefunds[msg.sender] = 0;
    (bool ok,) = payable(msg.sender).call{value: amount}("");
    require(ok);
}
```

## Vulnerability 3: Gas Limit DoS with External Calls in Loop

```solidity
// VULNERABLE — external call inside loop, any one failure blocks all
address[] public governors;

function executeVotes() external {
    for (uint i = 0; i < governors.length; i++) {
        IGovernor(governors[i]).vote(proposalId, true);  // external call in loop
        // One malicious/broken governor → whole loop reverts
    }
}

// FIXED — try/catch to isolate failures
function executeVotes() external {
    for (uint i = 0; i < governors.length; i++) {
        try IGovernor(governors[i]).vote(proposalId, true) {
            // success
        } catch {
            emit VoteFailed(governors[i]);
            // continue with next
        }
    }
}
```

## Vulnerability 4: Mapping with Struct Array — Storage Growth Attack

```solidity
// VULNERABLE — unbounded storage growth per user
mapping(address => uint256[]) public userHistory;

function recordAction(uint256 value) external {
    userHistory[msg.sender].push(value);  // user can push unlimited entries
}

function processUser(address user) external {
    uint256[] storage history = userHistory[user];
    for (uint i = 0; i < history.length; i++) {  // O(n) read of user's storage
        // process each entry
    }
}
// Attacker calls recordAction() 100,000 times → processUser() always OOG

// FIXED — cap array size or use pagination
uint256 constant MAX_HISTORY = 100;
function recordAction(uint256 value) external {
    require(userHistory[msg.sender].length < MAX_HISTORY, "History full");
    userHistory[msg.sender].push(value);
}
```

## Vulnerability 5: Gas Exhaustion via Large calldata / returndata

```solidity
// VULNERABLE — contract processes arbitrary-length user input
function processData(bytes calldata data) external {
    for (uint i = 0; i < data.length; i++) {
        // process each byte — O(n) gas, caller controls n
    }
}

// FIXED — enforce input length limits
function processData(bytes calldata data) external {
    require(data.length <= MAX_DATA_SIZE, "Data too large");
    // ...
}
```

## Vulnerability 6: Block Stuffing DoS

```solidity
// Attack: fill blocks with high-gas transactions to delay victim's time-sensitive tx
// Example: prevent liquidation call from landing before deadline expires
// Defender's tx can't get included because attacker bids higher gas for full blocks

// Mitigation: use time windows > 1 block for time-sensitive operations
// Acceptable liquidation windows: 30 min - 1 hour minimum
// Not: "within the same block" or "before next checkpoint"
```

## Vulnerability 7: ERC777 / ERC721 Hook DoS

```solidity
// ERC777 tokens trigger tokensReceived() hook on receiver
// ERC721 triggers onERC721Received() on safe transfers

// VULNERABLE — protocol loops over token holders and does safe transfers
function airdrop(address[] calldata recipients, uint256 amount) external {
    for (uint i = 0; i < recipients.length; i++) {
        IERC777(token).send(recipients[i], amount, "");  // triggers receiver hook
        // Malicious recipient hook uses all remaining gas → loop fails
    }
}

// FIXED — use ERC20-style transfer (no hook) for batch operations
// OR: use pull model for ERC777 distributions
```

## Vulnerability 8: Selfdestruct Forcing ETH Into Contract

```solidity
// VULNERABLE — contract logic depends on address(this).balance being in sync with internal accounting
contract PreciseAccounting {
    uint256 public totalDeposited;

    function deposit() external payable {
        totalDeposited += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount <= totalDeposited);
        require(address(this).balance >= amount);  // ALWAYS TRUE due to forced ETH
        totalDeposited -= amount;
        payable(msg.sender).transfer(amount);
    }
}
// Attacker sends ETH via selfdestruct — address(this).balance > totalDeposited
// NOT a critical bug here, but can break invariants in more complex contracts

// RULE: never use address(this).balance for internal accounting
// Use a separate uint256 variable that you control
```

## Real-World Examples
- **GovernMental (2016)**: creditor array grew to 1500+ entries — loop hit gas limit, jackpot stuck
- **King of the Ether**: revert in receiver blocked throne transfer
- **FOMO3D**: block stuffing to prevent other players from extending the timer
- **Akutars NFT (2022, $34M)**: DoS bug locked funds — auction refund loop could be blocked

## Detection Signals (Slither)
- `costly-loop` — storage writes inside loops
- `calls-loop` — external calls inside loops
- `divide-before-multiply` — precision loss in loop accumulation
- Array length used as loop bound where array is user-writable
- `.transfer()` or `.send()` inside loops (receiver can revert)
- `address(this).balance` used for internal logic (susceptible to force-send)

## Severity Guide
- Unbounded loop with ETH transfer (auction DoS): **High**
- Reward distribution permanently blocked: **Critical** (funds stuck)
- Block stuffing on time-sensitive protocol: **High**
- Forced ETH breaking contract invariant: **Medium**
- ERC777 hook DoS in batch operation: **Medium**
