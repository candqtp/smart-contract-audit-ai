# Bridge and Cross-Chain Vulnerabilities

## Architecture Overview
Bridges move assets between chains. Common designs:
- **Lock-and-mint**: lock tokens on chain A, mint wrapped tokens on chain B
- **Burn-and-release**: burn wrapped tokens on chain B, release originals on chain A
- **Liquidity pool bridges**: maintain liquidity on both chains (Connext, Hop)
- **Validator/oracle bridges**: validators/guardians attest to cross-chain events (Wormhole, Multichain)

Every bridge has two surfaces: the on-chain smart contracts AND the off-chain validator/relayer network.

## Vulnerability 1: Arbitrary Message Execution Without Whitelist

```solidity
// VULNERABLE — bridge can execute any function call on destination
// Root cause of Poly Network ($611M), Nomad ($190M) style attacks

function executeMessage(
    bytes calldata message,
    address target,
    bytes calldata callData
) external onlyBridgeValidator {
    // No whitelist of allowed target contracts
    // No whitelist of allowed function selectors
    (bool ok,) = target.call(callData);
    require(ok);
}
// Attacker crafts message calling protocol's admin function (setOwner, drain, etc.)

// FIXED
mapping(address => mapping(bytes4 => bool)) public allowedCalls;

function executeMessage(...) external onlyBridgeValidator {
    bytes4 selector = bytes4(callData);
    require(allowedCalls[target][selector], "Call not whitelisted");
    (bool ok,) = target.call(callData);
    require(ok);
}
```

## Vulnerability 2: Replay Attack Across Chains

```solidity
// VULNERABLE — message hash doesn't include destination chain ID
// A message intended for chain B can be replayed on chain C (a fork or testnet)

bytes32 messageHash = keccak256(abi.encode(
    recipient, amount, nonce
    // MISSING: destinationChainId
));

// FIXED
bytes32 messageHash = keccak256(abi.encode(
    recipient, amount, nonce,
    block.chainid,     // destination chain
    sourceChainId,     // source chain
    address(this)      // this bridge contract
));
```

## Vulnerability 3: Double-Spend via Message Replay

```solidity
// VULNERABLE — processed messages not tracked
mapping(bytes32 => bool) public processedMessages;

function processMessage(bytes32 messageId, bytes calldata message) external {
    // MISSING: require(!processedMessages[messageId], "Already processed");
    // Same withdrawal message can be submitted multiple times
    processedMessages[messageId] = true;
    _release(message);
}

// Attack: submit same valid withdrawal message 100 times → drain bridge 100x
// FIXED — check and mark BEFORE releasing
function processMessage(bytes32 messageId, bytes calldata message) external {
    require(!processedMessages[messageId], "Already processed");
    processedMessages[messageId] = true;  // mark BEFORE any external call
    _release(message);
}
```

## Vulnerability 4: Validator Threshold Too Low

```solidity
// Bridge uses M-of-N multisig for message validation
// VULNERABLE: if M is too small, compromise of M validators = full bridge drain

// Common insecure configs seen in production:
// - 3-of-5 validators (3 keys = 60% of network if colluding)
// - Same entity controls multiple validators (Ronin: 4/9 from one company)
// - Validator set is public — targeted social engineering possible

// Best practice:
// - Threshold ≥ 2/3 of validators (Byzantine fault tolerance)
// - Validators are geographically and organizationally diverse
// - No single entity controls > 1/3 of validators
// - Validator key rotation schedule
// - On-chain anomaly detection (large withdrawals require time-lock)
```

## Vulnerability 5: Bridge Liquidity Imbalance Exploit

```solidity
// Liquidity pool bridge: LPs deposit on both sides, bridge swaps between pools
// VULNERABLE: if one side's pool is drained, bridge is insolvent on that side

// Attack:
// 1. Identify chain where bridge has low liquidity (e.g., only 100 ETH on chain B)
// 2. Move 100+ ETH worth of value from chain A to chain B
// 3. Bridge can't fulfill — users on chain B get IOUs or partial fills
// 4. During insolvency window: protocol may have bugs handling undercollateralized state

// Real example: many "any-to-any" bridges after Multichain hack
// drained liquidity on multiple chains simultaneously

// Mitigation: per-asset transfer limits per time period
uint256 public dailyTransferLimit;
uint256 public dailyTransferred;
uint256 public lastTransferReset;

function transfer(uint256 amount) external {
    if (block.timestamp > lastTransferReset + 1 days) {
        dailyTransferred = 0;
        lastTransferReset = block.timestamp;
    }
    require(dailyTransferred + amount <= dailyTransferLimit, "Daily limit exceeded");
    dailyTransferred += amount;
}
```

## Vulnerability 6: Off-Chain Relayer Compromise

```solidity
// Bridges with centralized relayers: relayer signs messages off-chain
// If relayer private key is compromised → all bridge funds at risk

// Pattern: single admin key controls bridge minting
// Seen: Ronin, Multichain (CEO arrested, keys seized)
// Mitigation: time-delayed large withdrawals

function mintWrapped(address to, uint256 amount, bytes calldata sig) external {
    // Verify guardian signature
    address signer = ECDSA.recover(messageHash, sig);
    require(signer == guardian, "Invalid guardian");
    // VULNERABLE: guardian is a single EOA — if compromised, unlimited minting
    _mint(to, amount);
}

// FIXED — multi-sig guardian
function mintWrapped(address to, uint256 amount, bytes[] calldata sigs) external {
    require(sigs.length >= MIN_SIGNATURES, "Insufficient signatures");
    bytes32 hash = keccak256(abi.encode(to, amount, nonce));
    for (uint i = 0; i < sigs.length; i++) {
        address signer = ECDSA.recover(hash, sigs[i]);
        require(isValidator[signer], "Not a validator");
    }
    nonce++;
    _mint(to, amount);
}
```

## Vulnerability 7: Cross-Chain Message Ordering

```solidity
// Messages from chain A may arrive on chain B out of order
// VULNERABLE: if message B depends on message A being processed first

// Example: depositAndBorrow(collateral) on chain A
// sends two messages to chain B: 1) record collateral  2) release borrow
// If message 2 arrives before message 1:
// borrow released without collateral recorded → undercollateralized

// Mitigation: sequential nonces per user
mapping(address => uint256) public expectedNonce;

function processMessage(address user, uint256 nonce, MessageType msgType, bytes calldata data) external {
    require(nonce == expectedNonce[user], "Wrong nonce order");
    expectedNonce[user]++;
    _process(msgType, data);
}
```

## Vulnerability 8: Token Mismatch on Different Chains

```solidity
// VULNERABLE — bridge maps token address on chain A to wrong address on chain B
// Could be exploited during token migration (old token → new token)

// Example:
// Chain A: USDC = 0xA0b...  (legitimate Circle USDC)
// Chain B: bridge has mapping USDC_A → 0xEvil (attacker-deployed fake USDC)
// Users bridge real USDC from A → receive fake USDC on B
// OR: attacker deposits fake USDC on B → receives real USDC on A

// Mitigation: token registration via governance with time-delay
// Verify canonical token addresses against official issuer registries
```

## Code4rena/Sherlock Bridge Findings

```
CRITICAL:
1. Replay protection missing — same proof redeemable multiple times
2. Message hash doesn't bind to destination chain or contract
3. Validator set update not timelocked — attacker flips validator set instantly
4. Guardian role transferable to address(0) — bridge permanently locked

HIGH:
1. Bridge fee calculation overflow — user pays less than required
2. Cross-chain message can trigger reentrancy on destination
3. Large withdrawal not timelocked — instant drain if key compromised
4. Token allowance on bridge left after bridging (griefing/drain vector)
```

## Detection Signals
- No `processedMessages[id]` check before executing a cross-chain message
- Bridge message hash missing `chainid` or `address(this)`
- Single EOA or small multisig as sole bridge validator
- No per-day/per-transaction transfer amount limits
- `target.call(userProvidedCalldata)` without selector whitelist
- Token address mappings set by admin without timelock or registry verification

## Severity Guide
- Missing replay protection: **Critical** (drain entire bridge)
- Arbitrary cross-chain call execution: **Critical**
- Single-validator bridge: **Critical**
- Missing chain binding in message hash: **Critical**
- No transfer limits: **High**
- Cross-chain ordering vulnerability: **High**
