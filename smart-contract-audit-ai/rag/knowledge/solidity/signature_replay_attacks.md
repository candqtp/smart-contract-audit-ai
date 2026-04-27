# Signature and Replay Attack Vulnerabilities (SWC-117, SWC-121, SWC-122)

## Overview
Off-chain signatures (EIP-712, EIP-191) allow gasless approvals and meta-transactions. Poorly implemented signature validation leads to replay attacks, signature malleability, and cross-chain exploitation.

## Vulnerability 1: Missing Nonce (Replay Attack)

```solidity
// VULNERABLE — same signature valid indefinitely
function executeWithSig(
    address to,
    uint256 amount,
    bytes calldata signature
) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    address signer = ECDSA.recover(hash, signature);
    require(signer == owner, "Invalid sig");
    payable(to).transfer(amount);
    // Signature never invalidated — can replay the same transfer forever
}

// FIXED — include nonce, increment after use
mapping(address => uint256) public nonces;

function executeWithSig(
    address to,
    uint256 amount,
    uint256 nonce,
    bytes calldata signature
) external {
    require(nonce == nonces[owner], "Invalid nonce");
    bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, address(this), block.chainid));
    address signer = ECDSA.recover(hash, signature);
    require(signer == owner, "Invalid sig");
    nonces[owner]++;
    payable(to).transfer(amount);
}
```

## Vulnerability 2: Missing Chain ID (Cross-Chain Replay)

```solidity
// VULNERABLE — signature valid on mainnet AND on any fork/testnet
bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce));
// If protocol deploys on Ethereum AND Polygon, a signature for Ethereum is valid on Polygon

// FIXED — include chainid in signed data
bytes32 hash = keccak256(abi.encodePacked(
    to, amount, nonce,
    block.chainid,     // prevents cross-chain replay
    address(this)      // prevents cross-contract replay
));
```

## Vulnerability 3: Missing Contract Address (Cross-Contract Replay)

```solidity
// VULNERABLE — signature valid for any contract that accepts same format
bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, block.chainid));
// If two different contracts on same chain accept this format,
// sig intended for Contract A is valid for Contract B

// FIXED — include address(this) in hash (EIP-712 domain separator approach)
```

## Vulnerability 4: EIP-712 Domain Separator Not Validated

```solidity
// EIP-712 uses domain separator to bind signatures to contract+chain+version
// VULNERABLE — domain separator not checked or computed incorrectly

bytes32 constant DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256("MyProtocol"),
    keccak256("1"),
    1,              // HARDCODED chain ID — breaks if contract used on other chains
    address(this)
));

// FIXED — compute domain separator dynamically if deploying cross-chain
bytes32 private immutable _DOMAIN_SEPARATOR;

constructor() {
    _DOMAIN_SEPARATOR = keccak256(abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256("MyProtocol"),
        keccak256("1"),
        block.chainid,    // use actual chain ID at deployment
        address(this)
    ));
}
// If protocol supports chain forks: recompute per-call using block.chainid
```

## Vulnerability 5: Signature Malleability (SWC-117)

```solidity
// ECDSA signatures have two valid forms: (r, s) and (r, -s mod n)
// If protocol uses ecrecover() directly (not OZ ECDSA), both forms are accepted
// A signature can be transformed into a "different" but valid signature for same message

// VULNERABLE — raw ecrecover
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (address) {
    return ecrecover(hash, v, r, s);  // both (r,s) and (r, n-s) recover same signer
}
// If a nonce is consumed by first form, attacker submits second form and nonce might differ

// FIXED — use OpenZeppelin ECDSA which enforces s in lower half
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

address signer = ECDSA.recover(hash, signature);  // rejects malleable signatures
```

## Vulnerability 6: Signature Length Not Checked

```solidity
// VULNERABLE — signature not validated for correct length
function verify(bytes32 hash, bytes memory sig) public pure returns (address) {
    (bytes32 r, bytes32 s, uint8 v) = splitSignature(sig);
    return ecrecover(hash, v, r, s);
}
// If sig.length != 65, splitSignature reads garbage bytes
// Short signatures (< 65 bytes) can cause ecrecover to return address(0)

// If then checked: require(signer != address(0)) — this check exists
// But if not: signer = address(0) passes if owner == address(0) (uninitialized)

// FIXED
function verify(bytes32 hash, bytes memory sig) public pure returns (address) {
    require(sig.length == 65, "Invalid signature length");
    // ...
}
// OR use OZ ECDSA which handles length internally
```

## Vulnerability 7: Permit Function Front-Running

```solidity
// EIP-2612 permit() allows gasless approvals
// VULNERABLE — protocol relies on permit() not being front-runnable

function depositWithPermit(
    uint256 amount,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    token.permit(msg.sender, address(this), amount, deadline, v, r, s);
    token.transferFrom(msg.sender, address(this), amount);
}
// Attacker can front-run depositWithPermit:
// 1. Extract permit params from mempool
// 2. Call token.permit() directly (consumes the nonce)
// 3. Victim's depositWithPermit() reverts on permit (nonce already used)
// 4. token.transferFrom fails — victim never deposits
// THIS IS MOSTLY GRIEFING — victim loses gas, not funds
// But if protocol has state side effects before permit(), attacker can exploit that

// FIXED — wrap permit in try/catch (permit may already be consumed, that's ok)
function depositWithPermit(...) external {
    try token.permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {}
    // If permit already valid (front-run executed it), allowance exists, proceed
    token.transferFrom(msg.sender, address(this), amount);
}
```

## Vulnerability 8: Zero Address Signer

```solidity
// ecrecover returns address(0) for invalid signatures
// VULNERABLE — no zero address check after recovery
function execute(bytes32 hash, bytes calldata sig) external {
    address signer = ECDSA.recover(hash, sig);
    require(authorized[signer], "Not authorized");
    // If authorized[address(0)] == true (uninitialized mapping is false, BUT
    // if admin accidentally calls setAuthorized(address(0), true)), anyone can execute
}

// FIXED — always check for zero address
address signer = ECDSA.recover(hash, sig);
require(signer != address(0) && authorized[signer], "Invalid signer");
```

## Detection Signals (Slither)
- `arbitrary-send-eth` with signature validation
- Direct `ecrecover` calls (should use OZ ECDSA)
- Signature verified without nonce — replay possible
- `block.chainid` absent from signed message data
- `address(this)` absent from signed message data
- Missing `sig.length == 65` check before manual split

## Severity Guide
- Missing nonce (unlimited replay): **Critical**
- Missing chain ID (cross-chain replay): **High**
- ecrecover returns address(0) accepted: **Critical**
- Signature malleability with nonce bypass: **High**
- Missing contract address binding: **High**
- Permit front-running (griefing only): **Low**
