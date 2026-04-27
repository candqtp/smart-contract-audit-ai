# NFT and Marketplace Vulnerabilities

## Common NFT Attack Surfaces
- Minting logic (whitelist bypass, supply cap bypass, ID prediction)
- Royalty handling (ERC2981 misuse, royalty avoidance)
- Marketplace order matching (order replay, signature misuse)
- Trait/rarity assignment (randomness manipulation)
- Auction mechanisms (sniping, last-minute bid griefing)

## Vulnerability 1: Merkle Whitelist Proof Reuse

```solidity
// VULNERABLE — Merkle proof valid for any address in the tree, not just msg.sender
// AND: no per-address mint count tracked

function mintWhitelist(bytes32[] calldata proof, uint256 quantity) external payable {
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
    require(MerkleProof.verify(proof, merkleRoot, leaf), "Not whitelisted");
    require(quantity <= MAX_PER_WALLET, "Too many");
    // VULNERABLE: no tracking that msg.sender already minted
    // User calls mintWhitelist multiple times → mints MAX_PER_WALLET each time
    _mint(msg.sender, quantity);
}

// FIXED — track per-address mints
mapping(address => uint256) public whitelistMinted;

function mintWhitelist(bytes32[] calldata proof, uint256 quantity) external payable {
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
    require(MerkleProof.verify(proof, merkleRoot, leaf), "Not whitelisted");
    require(whitelistMinted[msg.sender] + quantity <= MAX_PER_WALLET, "Exceeds allowance");
    whitelistMinted[msg.sender] += quantity;
    _mint(msg.sender, quantity);
}
```

## Vulnerability 2: Signature Allows Marketplace Order Replay

```solidity
// VULNERABLE — signed order has no nonce, valid forever
struct Order {
    address seller;
    uint256 tokenId;
    uint256 price;
    address paymentToken;
}

function fillOrder(Order calldata order, bytes calldata sig) external payable {
    bytes32 hash = keccak256(abi.encode(order));
    address signer = ECDSA.recover(hash, sig);
    require(signer == order.seller, "Invalid sig");
    // VULNERABLE: same sig used multiple times
    // Seller signed order for 1 ETH → sold → sig still valid
    // Buyer buys again using same sig → seller forced to sell again

    IERC721(nft).transferFrom(order.seller, msg.sender, order.tokenId);
    payable(order.seller).transfer(order.price);
}

// FIXED — nonce per seller
mapping(address => uint256) public nonces;
mapping(bytes32 => bool) public cancelledOrders;

function fillOrder(Order calldata order, uint256 nonce, bytes calldata sig) external payable {
    bytes32 hash = keccak256(abi.encode(order, nonce, address(this), block.chainid));
    require(nonce == nonces[order.seller], "Invalid nonce");
    require(!cancelledOrders[hash], "Order cancelled");
    address signer = ECDSA.recover(hash, sig);
    require(signer == order.seller, "Invalid sig");
    nonces[order.seller]++;
    // execute order
}
```

## Vulnerability 3: Royalty Bypass via Wrapper Contract

```solidity
// ERC2981 royalties are voluntary — marketplaces choose to enforce them
// Attack: wrap NFT in a contract, trade the wrapper
// The underlying NFT never changes hands → no royalty trigger

// Protocol impact: royalty recipients lose income on secondary sales
// This is a known ecosystem problem, not a single contract bug
// Audit should flag: does the protocol depend on royalty income for security?
// If yes: royalty avoidance breaks the economic model

// On-chain royalty enforcement attempt (rare, controversial):
// Override ERC721 transfer to check if recipient is whitelisted marketplace
function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal override {
    if (from != address(0) && to != address(0)) {  // not mint or burn
        require(approvedMarketplaces[to] || approvedMarketplaces[msg.sender], "Marketplace only");
    }
}
// This breaks composability — not recommended but auditor should identify intent
```

## Vulnerability 4: NFT Mint Price Not Validated

```solidity
// VULNERABLE — price check allows 0 payment
function mint(uint256 quantity) external payable {
    require(quantity <= MAX_MINT, "Too many");
    require(msg.value == PRICE * quantity, "Wrong payment");
    // VULNERABLE if PRICE = 0 (initialization error) or if quantity = 0
    // Also: if PRICE * quantity overflows, require passes with wrong check
    _mint(msg.sender, quantity);
}

// Edge cases to check:
// 1. PRICE = 0 (unset/default value) → free mint
// 2. quantity = 0 → zero payment required, zero minted (griefing/event spam)
// 3. PRICE * quantity overflow (uint256 wraps) → require passes, underpaid

// FIXED
require(PRICE > 0, "Price not set");
require(quantity > 0 && quantity <= MAX_MINT);
require(msg.value == PRICE * quantity, "Wrong payment");
// uint256 overflow protection: PRICE * quantity overflows only if quantity > 2^256/PRICE
// For reasonable PRICE (> 1 gwei = 1e9), max quantity before overflow = 2^247 > 10^74 — fine
```

## Vulnerability 5: Auction Sniping and Last-Block Extension

```solidity
// VULNERABLE — auction ends at fixed timestamp, sniped in final second
function endAuction() external {
    require(block.timestamp > auctionEnd, "Still active");
    IERC721(nft).transferFrom(address(this), highestBidder, tokenId);
    payable(seller).transfer(highestBid);
}
// Snipers watch mempool, submit higher bid 1 second before end
// Gas prioritization lets them always win at minimal premium

// FIXED — extend auction on late bids
uint256 constant EXTENSION_PERIOD = 10 minutes;

function bid() external payable {
    require(block.timestamp < auctionEnd, "Ended");
    require(msg.value > highestBid * 105 / 100, "Bid too low (5% increment)");

    // Refund previous bidder
    pendingReturns[highestBidder] += highestBid;
    highestBidder = msg.sender;
    highestBid = msg.value;

    // Extend auction if bid arrives near the end
    if (auctionEnd - block.timestamp < EXTENSION_PERIOD) {
        auctionEnd = block.timestamp + EXTENSION_PERIOD;
    }
}
```

## Vulnerability 6: Lazy Minting — Voucher Replay

```solidity
// Lazy minting: NFT minted on-demand when buyer redeems a signed voucher
// Voucher signed off-chain by creator, verified on-chain at mint time

// VULNERABLE — voucher has no expiry, no single-use protection
struct LazyMintVoucher {
    uint256 tokenId;
    uint256 minPrice;
    string tokenURI;
    bytes signature;
}

function redeem(LazyMintVoucher calldata voucher) external payable {
    bytes32 hash = keccak256(abi.encode(voucher.tokenId, voucher.minPrice, voucher.tokenURI));
    address signer = ECDSA.recover(hash, voucher.signature);
    require(signer == creator, "Invalid voucher");
    require(msg.value >= voucher.minPrice, "Insufficient payment");
    // VULNERABLE: same voucher for tokenId=1 can be redeemed multiple times
    // First redemption mints token — second redemption fails (token exists)
    // BUT: creator signed minimum price in 2021, ETH was cheap
    // In 2024: buyer gets NFT worth 100x the minPrice creator signed for

    _mint(msg.sender, voucher.tokenId);
    _setTokenURI(voucher.tokenId, voucher.tokenURI);
}

// FIXED — add expiry and nonce
struct LazyMintVoucher {
    uint256 tokenId;
    uint256 minPrice;
    uint256 expiry;
    uint256 nonce;
    string tokenURI;
    bytes signature;
}
// Check: require(block.timestamp <= voucher.expiry && !usedNonces[voucher.nonce])
```

## Vulnerability 7: NFT Staking — Token Still Tradeable While Staked

```solidity
// VULNERABLE — NFT "staked" but not escrowed in staking contract
// User stakes token → receives rewards
// User sells token → new owner unaware of stake
// Original staker still earning rewards for token they no longer own

function stake(uint256 tokenId) external {
    require(ownerOf(tokenId) == msg.sender, "Not owner");
    stakedTokens[tokenId] = msg.sender;  // record stake
    // BUG: NFT not transferred to staking contract
    // Owner can still transfer/sell it
}

// FIXED — escrow NFT in staking contract
function stake(uint256 tokenId) external {
    IERC721(nftContract).transferFrom(msg.sender, address(this), tokenId);  // escrow
    stakedTokens[tokenId] = msg.sender;
    stakeTimestamp[tokenId] = block.timestamp;
}
```

## Vulnerability 8: Royalty Recipient is address(0)

```solidity
// VULNERABLE — ERC2981 royaltyInfo returns address(0) as recipient
// Marketplaces that enforce royalties try to send to address(0)
// Transaction may revert OR payment is burned

function royaltyInfo(uint256 tokenId, uint256 salePrice) external view returns (address, uint256) {
    return (royaltyRecipient, salePrice * royaltyBPS / 10_000);
    // If royaltyRecipient was never set, returns address(0)
    // Marketplaces call this before completing sale — if it sends to address(0) and reverts, sale blocked
}

// FIXED
constructor() {
    royaltyRecipient = msg.sender;  // default to deployer
}

function setRoyaltyRecipient(address recipient) external onlyOwner {
    require(recipient != address(0), "Zero recipient");
    royaltyRecipient = recipient;
}
```

## Code4rena NFT Marketplace Findings

```
HIGH:
1. Order signature valid across multiple NFT contracts (missing contract address in hash)
2. Bid refund uses transfer() — malicious bidder can block next bid (DoS auction)
3. NFT staked but approval not revoked → owner transfers NFT, staking broken
4. Royalty calculated on gross payment including marketplace fee → creator overtaxed

MEDIUM:
1. Mint count bypassed via batch transfer and re-minting
2. tokenId 0 can be minted twice due to default mapping value check
3. Dutch auction price calculation overflows at start → free mint
4. royaltyInfo reverts for burned tokens → secondary sales of burned tokens impossible
```

## Detection Signals
- `whitelistMinted` mapping missing (no per-user mint tracking)
- Marketplace orders without nonce or expiry
- Auction bidding with `transfer()` for refund (DoS possible)
- Staking contract that records stake but doesn't escrow NFT
- `royaltyRecipient` address not checked for `!= address(0)`
- Signed vouchers without expiry timestamp
- Order hash missing `address(this)` or `block.chainid`

## Severity Guide
- Whitelist mint without per-address tracking: **High** (unlimited minting)
- Order signature replay: **High** (forced re-sale)
- Auction DoS via malicious bidder: **High**
- NFT staking without escrow: **Medium** (rewards theft)
- Royalty recipient address(0): **Medium** (sale blocked or ETH burned)
- Lazy mint voucher without expiry: **Medium** (stale price exploit)
