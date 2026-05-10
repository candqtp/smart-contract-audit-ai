# ERC20, ERC721, ERC1155 Token Vulnerabilities

## Tags
ERC20, ERC721, token, transfer, approve, allowance, fee-on-transfer, rebasing, weird-tokens


## ERC20 — Fee-on-Transfer Tokens

```solidity
// Some ERC20 tokens (USDT on some chains, PAXG, STA) deduct a fee on transfer
// Protocol receives LESS than amount specified in transferFrom

// VULNERABLE — assumes amount received == amount specified
function deposit(address token, uint256 amount) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // WRONG: actual received = amount - fee
    // User deposited 1000, fee took 10, protocol got 990
    // But balances[msg.sender] = 1000 — 10 tokens credited for free
}

// FIXED — measure actual balance change
function deposit(address token, uint256 amount) external {
    uint256 before = IERC20(token).balanceOf(address(this));
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    uint256 received = IERC20(token).balanceOf(address(this)) - before;
    balances[msg.sender] += received;  // use actual received amount
}
```

## ERC20 — Rebasing Tokens

```solidity
// Rebasing tokens (stETH, ampl) change all balances automatically
// A balance snapshot taken at T1 is wrong at T2

// VULNERABLE — snapshot balance used for later calculations
mapping(address => uint256) public depositedAt; // snapshot balance
mapping(address => uint256) public snapshots;

function deposit(uint256 amount) external {
    IERC20(stETH).transferFrom(msg.sender, address(this), amount);
    snapshots[msg.sender] = amount;  // stale — actual balance grows with staking rewards
}

function withdraw() external {
    uint256 toSend = snapshots[msg.sender];  // WRONG — actual balance is higher
    snapshots[msg.sender] = 0;
    IERC20(stETH).transfer(msg.sender, toSend);  // user doesn't get their rewards
    // OR: contract thinks it has more than it does → withdrawal fails
}

// FIXED — use share-based accounting for rebasing tokens
// Or use wrapped versions (wstETH instead of stETH) that don't rebase
```

## ERC20 — Infinite Approval Attack

```solidity
// If protocol holds an approval for infinite amount,
// and protocol is compromised, attacker can drain all approved tokens from all users

// Common dangerous pattern:
// DApp UI asks users to approve(protocol, type(uint256).max)  // "unlimited approval"
// If protocol is later exploited, approved tokens drained

// MITIGATION from user perspective: use permit with exact amounts
// MITIGATION from protocol perspective: rotate approval addresses, use time-limited approvals
// From audit perspective: flag any protocol requesting unlimited approvals without justification
```

## ERC20 — USDT Approval Race and Non-Standard Return

```solidity
// USDT (mainnet) specifics:
// 1. Does not return bool from transfer/transferFrom (returns nothing)
//    → must use SafeERC20
// 2. Requires allowance to be set to 0 before setting new non-zero value
//    → direct approve(spender, newAmount) reverts if current allowance != 0

// VULNERABLE — sets new allowance directly on USDT
IERC20(USDT).approve(spender, 1000e6);  // reverts if existing allowance != 0

// FIXED
IERC20(USDT).safeApprove(spender, 0);       // reset first
IERC20(USDT).safeApprove(spender, 1000e6);  // then set new
// OR use safeIncreaseAllowance
```

## ERC721 — Reentrancy via onERC721Received

```solidity
// VULNERABLE — state not updated before safe transfer (triggers callback)
function sellNFT(uint256 tokenId, uint256 price) external {
    require(listings[tokenId].seller == msg.sender);
    require(msg.value >= price);

    // Payment sent first — triggers receive() which can reenter
    payable(msg.sender).transfer(price);

    // NFT transferred after — triggers onERC721Received callback
    IERC721(nft).safeTransferFrom(address(this), msg.sender, tokenId);
    delete listings[tokenId];  // state updated LAST — stale during callbacks
}

// FIXED — CEI (Checks-Effects-Interactions)
function sellNFT(uint256 tokenId, uint256 price) external {
    require(listings[tokenId].seller == msg.sender);
    require(msg.value >= price);

    address seller = listings[tokenId].seller;
    delete listings[tokenId];  // effect FIRST

    IERC721(nft).safeTransferFrom(address(this), msg.sender, tokenId);
    payable(seller).call{value: price}("");  // interaction LAST
}
```

## ERC721 — Missing Ownership Check on Approve

```solidity
// ERC721 approve allows delegating transfer rights
// VULNERABLE — custom approve doesn't check owner
function approveNFT(uint256 tokenId, address approved) external {
    // Missing: require(ownerOf(tokenId) == msg.sender)
    approvals[tokenId] = approved;  // anyone can approve anyone for any token
}
```

## ERC1155 — Batch Transfer Reentrancy

```solidity
// ERC1155 safeBatchTransferFrom calls onERC1155BatchReceived
// VULNERABLE — same CEI violation as ERC721 but across multiple tokens

function batchSell(uint256[] calldata ids, uint256[] calldata amounts) external {
    // calculate total payment...
    IERC1155(token).safeBatchTransferFrom(address(this), msg.sender, ids, amounts, "");
    // onERC1155BatchReceived triggered on receiver
    // state update happens after — stale during callback
    for (uint i = 0; i < ids.length; i++) {
        delete listings[ids[i]];
    }
}
```

## ERC4626 — Vault Inflation Attack (First Depositor)

```solidity
// ERC4626 tokenized vaults: shares = assets * totalSupply / totalAssets
// Empty vault: first depositor can inflate share price

// Attack:
// 1. Attacker deposits 1 wei → gets 1 share
// 2. Attacker donates 1e18 tokens directly (not via deposit)
// 3. totalAssets = 1e18 + 1 wei, totalShares = 1
// 4. Victim deposits 1e18 tokens → receives 0 shares (rounds down)
// 5. Attacker redeems 1 share → gets ~2e18 tokens

// FIXED — OpenZeppelin ERC4626 adds virtual shares offset
// Or: mint initial shares to dead address on first deposit
// Or: enforce minimum deposit size to make attack uneconomical
```

## Token Decimal Mismatch

```solidity
// Protocols mixing tokens with different decimals without normalization
// USDC: 6 decimals, ETH: 18 decimals, WBTC: 8 decimals

// VULNERABLE — 1 USDC = 1e6, 1 ETH = 1e18, comparing directly is wrong
function getCollateralValue(uint256 ethAmount, uint256 usdcAmount) public view returns (uint256) {
    uint256 ethPrice = getEthPrice();  // in USD with 8 decimals (Chainlink)
    // WRONG: ethAmount (18 dec) * ethPrice (8 dec) vs usdcAmount (6 dec)
    return ethAmount * ethPrice + usdcAmount;  // comparing apples to oranges
}

// FIXED — normalize to 18 decimal base
uint256 constant USDC_SCALAR = 1e12;  // 18 - 6 = 12
uint256 ethValue = (ethAmount * ethPrice) / 1e8;        // normalize price feed (8 dec)
uint256 usdcValue = usdcAmount * USDC_SCALAR;           // normalize to 18 dec
return ethValue + usdcValue;
```

## Detection Signals
- `transferFrom` without pre/post balance check when token has fee-on-transfer risk
- Storing deposit amounts directly (not accounting for rebasing)
- ERC721/ERC1155 state updates AFTER `safeTransfer` (reentrancy via callback)
- Direct `approve` on USDT without zeroing first
- ERC4626 without virtual shares offset (inflation attack)
- Arithmetic mixing token amounts of different decimal counts without normalization

## Severity Guide
- Fee-on-transfer token accounting error: **High** (free credits)
- ERC721 callback reentrancy: **Critical** (repeated withdrawal)
- ERC4626 inflation on first deposit: **High/Critical**
- USDT non-standard return silently failing: **High**
- Decimal mismatch in price calculation: **High**
- Missing owner check on ERC721 approve: **High**
