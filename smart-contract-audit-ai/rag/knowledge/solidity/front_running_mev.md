# Front-Running, MEV, and Transaction Ordering in Solidity (SWC-114)

## Overview
The Ethereum mempool is public. Any pending transaction can be observed before inclusion. MEV (Maximal Extractable Value) bots and validators can reorder, insert, or censor transactions for profit.

## Vulnerability 1: DEX Swap Without Slippage (Sandwich Attack)

```solidity
// VULNERABLE — no minimum output specified
function swapExactTokensForTokens(
    uint amountIn,
    address[] calldata path,
    address to
) external returns (uint[] memory amounts) {
    amounts = UniswapV2Library.getAmountsOut(amountIn, path);
    // No amountOutMin check — bot sandwiches: buy before, sell after victim
    TransferHelper.safeTransferFrom(path[0], msg.sender, pair, amountIn);
    _swap(amounts, path, to);
}

// FIXED — always pass amountOutMin and deadline
function swapExactTokensForTokens(
    uint amountIn,
    uint amountOutMin,     // minimum acceptable output
    address[] calldata path,
    address to,
    uint deadline          // tx invalid after this timestamp
) external returns (uint[] memory amounts) {
    require(block.timestamp <= deadline, "Expired");
    amounts = UniswapV2Library.getAmountsOut(amountIn, path);
    require(amounts[amounts.length - 1] >= amountOutMin, "Insufficient output");
    // ...
}
```

## Vulnerability 2: ERC20 Approve Front-Running (SWC-114)

```solidity
// VULNERABLE — approve race condition
// Alice approves Bob for 100 tokens. Later changes to 50.
// Bob sees pending approve(50) tx in mempool.
// Bob front-runs: spends 100 tokens BEFORE tx confirms.
// Alice's tx confirms: allowance now 50.
// Bob spends the remaining 50.
// Bob spent 150 total — Alice intended at most 50.

token.approve(bob, 100);  // initial approval
// ... time passes ...
token.approve(bob, 50);  // RACE CONDITION

// FIXED — use increaseAllowance / decreaseAllowance (not standard ERC20 but widely used)
token.increaseAllowance(bob, 50);
token.decreaseAllowance(bob, 50);

// OR: reset to 0 first then set new value
token.approve(bob, 0);
token.approve(bob, 50);
```

## Vulnerability 3: Auction Sniping

```solidity
// VULNERABLE — English auction, highest bid visible, last-second outbid trivial
contract Auction {
    address public highestBidder;
    uint256 public highestBid;
    uint256 public endTime;

    function bid() external payable {
        require(block.timestamp < endTime, "Ended");
        require(msg.value > highestBid, "Bid too low");
        // Refund previous bidder
        payable(highestBidder).transfer(highestBid);
        highestBidder = msg.sender;
        highestBid = msg.value;
        // Bot sees this tx, frontruns with slightly higher bid using higher gas
    }
}

// FIXED — commit-reveal auction
mapping(address => bytes32) public commitments;
mapping(address => uint256) public deposits;

// Phase 1: commit (hash of bid amount + salt)
function commit(bytes32 commitment) external payable {
    commitments[msg.sender] = commitment;
    deposits[msg.sender] = msg.value;
}

// Phase 2: reveal (after commit period ends)
function reveal(uint256 amount, bytes32 salt) external {
    require(keccak256(abi.encodePacked(amount, salt)) == commitments[msg.sender]);
    // now compare revealed bids
}
```

## Vulnerability 4: Oracle Price Update Front-Running

```solidity
// VULNERABLE — oracle price update is public in mempool
// Attacker sees price update: ETH going from $2000 to $2500
// Front-runs: borrows maximum at $2000, after update collateral worth $2500 more
// Or: front-runs liquidation — liquidates position just before price recovers

// FIXED — use time-weighted prices, private mempools (Flashbots Protect),
// or commit-reveal for sensitive oracle updates

// On-chain mitigation: price staleness check + circuit breaker
function getPrice() external view returns (uint256) {
    require(block.timestamp - lastUpdate <= MAX_PRICE_AGE, "Stale price");
    require(newPrice <= oldPrice * 110 / 100, "Price spike circuit breaker"); // max 10% change
    return price;
}
```

## Vulnerability 5: NFT Mint Front-Running

```solidity
// VULNERABLE — NFT with desirable tokenIds predictable or first-come-first-served
// Attacker monitors mempool, sees reveal tx, frontruns mint of specific ID

// Common patterns:
// - Sequential IDs revealed before mint
// - Rarity based on tokenId (lower ID = rarer)
// - Whitelist check based on Merkle proof (proof visible in mempool, frontrunnable if not tied to sender)

// FIXED — Merkle proof tied to msg.sender
function mintWhitelist(bytes32[] calldata proof, uint256 amount) external {
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));  // tied to sender
    require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");
    // proof is useless for anyone except msg.sender
}
```

## Vulnerability 6: Governance Vote Front-Running

```solidity
// VULNERABLE — governance vote outcome predictable before deadline
// Large holder sees proposal about to pass, frontruns final vote with cancellation
// OR: attacker front-runs critical "execute proposal" call with flash loan governance attack

// MITIGATION:
// - Timelock between vote passing and execution (Compound Governor: 2 day timelock)
// - Vote delegation snapshot at proposal creation, not vote time
// - Quorum requirements high enough to prevent flash loan voting
```

## MEV Searcher Patterns to Know

```
Sandwich Attack:
1. Frontrun victim's swap (buy token, raise price)
2. Victim's swap executes at worse price
3. Backrun (sell token at inflated price)
Profit: victim's slippage extracted

Arbitrage:
1. Price difference between DEX A and DEX B
2. Buy low on A, sell high on B in same tx
No victim, net positive for ecosystem

Liquidation Racing:
1. Position becomes undercollateralized
2. Multiple bots compete to liquidate first
3. Gas wars — higher gas wins
Protocol-approved behavior, but gas inefficient

JIT Liquidity:
1. Bot sees large swap in mempool
2. Adds liquidity just before (in same block, lower tx index)
3. Collects fees from swap
4. Removes liquidity after
Harms passive LPs by extracting concentrated fees
```

## Commit-Reveal Pattern (General)

```solidity
// Phase 1: commit — hash conceals value
function commit(bytes32 hash) external {
    require(commitments[msg.sender] == bytes32(0), "Already committed");
    commitments[msg.sender] = hash;
    commitDeadline[msg.sender] = block.timestamp + COMMIT_PERIOD;
}

// Phase 2: reveal — after all committed
function reveal(uint256 value, bytes32 salt) external {
    require(block.timestamp > commitDeadline[msg.sender], "Commit period active");
    require(keccak256(abi.encodePacked(value, salt, msg.sender)) == commitments[msg.sender]);
    // process revealed value
    delete commitments[msg.sender];
}
```

## Detection Signals
- Swap functions without `amountOutMin` and `deadline` parameters
- `approve(spender, newAmount)` directly without intermediate 0 reset
- Auctions using visible bids without commit-reveal
- Oracle updates using spot price without TWAP or circuit breaker
- Governance with no timelock between proposal pass and execution
- NFT mint where token assignment is deterministic and predictable

## Severity Guide
- Swap without slippage (sandwich): **High**
- ERC20 approve race: **Medium** (requires active front-runner)
- Auction without commit-reveal: **Medium**
- Oracle front-runnable during update: **High**
- Governance flash loan attack (no snapshot): **Critical**
