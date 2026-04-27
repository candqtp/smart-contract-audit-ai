# Timestamp Dependence and Weak Randomness (SWC-116, SWC-120)

## SWC-116: Block Timestamp Manipulation

Miners/validators can manipulate `block.timestamp` by approximately ±15 seconds (PoW) or within slot timing (PoS). For precision less than 15 seconds, timestamp is unreliable.

```solidity
// VULNERABLE — game outcome determined by timestamp modulo
function flipCoin() external payable {
    require(msg.value == 1 ether);
    if (block.timestamp % 2 == 0) {
        payable(msg.sender).transfer(2 ether);
    }
    // Miner can choose timestamp (within ~15s) to always win
}

// VULNERABLE — lock expires exactly at timestamp
function unlock() external {
    require(block.timestamp >= lockExpiry, "Still locked");
    // Miner can include tx 15 seconds early
}

// RULE: block.timestamp is safe for:
// - Durations > 15 minutes (validator manipulation is negligible)
// - Non-financial logic where ±15s is acceptable
//
// block.timestamp is NOT safe for:
// - Randomness source
// - Sub-minute precision logic
// - Zero-sum games where miner is a player
```

## SWC-120: Weak PRNG — block.timestamp / blockhash

```solidity
// VULNERABLE — predictable "random" based on public blockchain data
function roll() external payable returns (uint256) {
    uint256 rand = uint256(keccak256(abi.encodePacked(
        block.timestamp,
        block.difficulty,  // deprecated in PoS — always 0 or PREVRANDAO
        msg.sender
    ))) % 6;
    // All inputs are public or predictable:
    // block.timestamp: known when miner builds block
    // block.difficulty: known before block
    // msg.sender: known by attacker
    return rand;
}
```

```solidity
// VULNERABLE — blockhash(block.number - 1) as randomness
function random() internal view returns (uint256) {
    return uint256(blockhash(block.number - 1));
    // Miner can withhold block if they lose, mine again with different txs
    // blockhash only available for last 256 blocks — returns 0 for older
}
```

## EVM PREVRANDAO (PoS, post-Merge)

```solidity
// block.difficulty is now PREVRANDAO in PoS
// PREVRANDAO = previous beacon chain RANDAO value
// Better than blockhash but STILL manipulable by validators:
// - Validator can see PREVRANDAO before deciding to propose
// - Can abstain if outcome is unfavorable (costs 1 attestation reward)

uint256 rand = uint256(block.prevrandao) % 100;
// Acceptable for low-stakes randomness (gas giveaways, non-financial games)
// NOT acceptable for high-value NFT rarity, lottery with large prizes
```

## Correct Randomness: Chainlink VRF

```solidity
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";

contract FairLottery is VRFConsumerBaseV2 {
    VRFCoordinatorV2Interface COORDINATOR;
    uint64 subscriptionId;
    bytes32 keyHash;

    mapping(uint256 => address) public requestToPlayer;

    function enterLottery() external payable {
        uint256 requestId = COORDINATOR.requestRandomWords(
            keyHash, subscriptionId, 3, 100000, 1
        );
        requestToPlayer[requestId] = msg.sender;
    }

    // Called by Chainlink node — cannot be predicted by anyone
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
        address winner = determineWinner(randomWords[0]);
        payable(winner).transfer(address(this).balance);
    }
}
```

## Commit-Reveal Randomness (No Oracle Needed)

```solidity
// Two-phase: user commits hash, then reveals — combined with block hash
// Neither party can manipulate alone, but both must participate honestly

struct Round {
    bytes32 playerCommit;
    uint256 commitBlock;
    bool revealed;
}

function commit(bytes32 hash) external {
    rounds[msg.sender] = Round(hash, block.number, false);
}

function reveal(uint256 value, bytes32 salt) external {
    Round storage r = rounds[msg.sender];
    require(!r.revealed);
    require(keccak256(abi.encodePacked(value, salt)) == r.playerCommit);
    require(block.number > r.commitBlock, "Same block");  // prevent same-block reveal
    require(block.number <= r.commitBlock + 250, "Too late — blockhash unavailable");
    r.revealed = true;

    // Combine player's value with block hash they couldn't know at commit time
    uint256 rand = uint256(keccak256(abi.encodePacked(
        value,
        blockhash(r.commitBlock + 1)  // block after commit — not known at commit time
    )));
    // use rand
}
```

## Griefing: Revealing Only When Outcome is Favorable

```solidity
// VULNERABILITY in commit-reveal: player can simply not reveal if they'd lose
// Only works for protocols where not-revealing is acceptable (they lose their stake)

// MITIGATION: slash non-revealers (take their deposit)
function forceRevealDeadline(address player) external {
    Round storage r = rounds[player];
    require(block.number > r.commitBlock + REVEAL_DEADLINE);
    require(!r.revealed);
    // slash r.deposit — sent to protocol or caller as bounty
}
```

## Real-World Examples
- **Fomo3D (2018)**: blockhash randomness manipulated by miners to win jackpot
- **Meebits NFT (2021)**: randomness based on blockhash — attacker predicted rarity, minted rare tokens
- **SmartBillions lottery**: `block.blockhash(block.number)` returns 0 in same block — always predictable
- **CryptoKitties gen0**: weak PRNG — rare attributes predicted by miners

## Detection Signals (Slither)
- `weak-prng` — randomness derived from block.timestamp or blockhash
- `timestamp` detector — business logic sensitive to 15s timestamp manipulation
- `block-values` — critical decisions on block.number, block.timestamp
- Lottery/NFT rarity/gaming contracts using any on-chain data as sole randomness source

## Severity Guide
- Lottery/jackpot with blockhash randomness: **High** (miner can guarantee win)
- NFT rarity deterministic from block data: **High** (attacker can cherry-pick)
- Timelock with <15min precision (validator can bypass): **Medium**
- PREVRANDAO for low-stakes randomness: **Low** (acceptable risk)
