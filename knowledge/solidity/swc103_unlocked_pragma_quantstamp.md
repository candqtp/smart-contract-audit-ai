Executive Summary

## Tags
pragma, version, unlocked, SWC-103, compiler, floating-pragma


This smart contract audit was prepared by Quantstamp, the protocol for securing smart contracts.
Type
Layer2 Token Bridge
Timeline
2021-06-22 through 2021-08-04
Language
Solidity, Javascript
Methods
Architecture Review, Unit Testing, Computer-Aided Verification, Manual Review
Specification
Bridging Assets
Source Code

    arbitrum
    #b368fd7
    arbitrum
    #d28cf4c

Auditors

    Jake Goh Si Yuan Senior Security Researcher
    Jan Gorzny Blockchain Researcher
    Poming Lee Research Engineer

Documentation quality
Undetermined
Test quality
Undetermined
Total Findings
9
Fixed: 4Acknowledged: 4Mitigated: 1
High severity findingsInfo icon
1
Fixed: 1
Medium severity findingsInfo icon
1
Fixed: 1
Low severity findingsInfo icon
3
Acknowledged: 3
Undetermined severity findingsInfo icon
1
Fixed: 1
Informational findingsInfo icon
3
Fixed: 1Acknowledged: 1Mitigated: 1
Summary of Findings

During auditing, we found 9 potential issues of various levels of severity: 1 high-severity, 2 medium-severity, 2 low-severity, 3 informational-level findings, and 1 finding with undetermined severity. We made 8 best practices recommendations. We highly recommend addressing the findings before going live.

Disclaimer: This project utilized Arbitrum layer2 blockchain and its existing cross-chain communication infrastructures. All the dependencies and external infrastructures are not part of this audit. This scope of the current audit is for all the contracts under packages\arb-bridge-peripherals\contracts\tokenbridge, except those contracts under misc folder.

2021-08-03 Update: During this fix-review, the admin team has brought the status of some of the findings into fixed or mitigated. Some of the low and informational-severity issues have been solely acknowledged. One undetermined finding has been confirmed as a false positive and one medium-severity finding has been changed from Medium to Low.
ID	Description	Severity	Status
ARB-1	Missing Permission Check for Function setBridge()	
HighInfo icon
	Fixed
ARB-2	ERC-677 Standard Not Adhered to/Return Value Unchecked	
MediumInfo icon
	Fixed
ARB-3	Dangerous External Calls From TokenGateways to Arbitrary Contact by Anyone	
LowInfo icon
	Acknowledged
ARB-4	Greedy Contract	
LowInfo icon
	Acknowledged
ARB-5	Missing Checks if Address Is Non-Zero	
LowInfo icon
	Acknowledged
ARB-6	User May Lose Their Fund when Transferring Them From Layer1 to Layer2 with Insufficient Gas Provided	
InformationalInfo icon
	Mitigated
ARB-7	Privileged Roles and Ownership	
InformationalInfo icon
	Fixed
ARB-8	Unlocked Pragma	
InformationalInfo icon
	Acknowledged
ARB-9	[False Positive] Function initialize() Not Protected	
UndeterminedInfo icon
	Fixed
Assessment Breakdown

Quantstamp's objective was to evaluate the repository for security-related issues, code quality, and adherence to specification and best practices.
Possible issues we looked for included (but are not limited to):

    Transaction-ordering dependence
    Timestamp dependence
    Mishandled exceptions and call stack limits
    Unsafe external calls
    Integer overflow / underflow
    Number rounding errors
    Reentrancy and cross-function vulnerabilities
    Denial of service / logical oversights
    Access control
    Centralization of power
    Business logic contradicting the specification
    Code clones, functionality duplication
    Gas usage
    Arbitrary token minting

Methodology

    Code review that includes the following
        Review of the specifications, sources, and instructions provided to Quantstamp to make sure we understand the size, scope, and functionality of the smart contract.
        Manual review of code, which is the process of reading source code line-by-line in an attempt to identify potential vulnerabilities.
        Comparison to specification, which is the process of checking whether the code does what the specifications, sources, and instructions provided to Quantstamp describe.
    Testing and automated analysis that includes the following:
        Test coverage analysis, which is the process of determining whether the test cases are actually covering the code and how much code is exercised when we run those test cases.
        Symbolic execution, which is analyzing a program to determine what inputs cause each part of a program to execute.
    Best practices review, which is a review of the smart contracts to improve efficiency, effectiveness, clarify, maintainability, security, and control based on the established industry and academic practices, recommendations, and research.
    Specific, itemized, and actionable recommendations to help you take steps to secure your smart contracts.

Findings
ARB-1  

Missing Permission Check for Function setBridge()
HighInfo icon
Fixed
Alert icon
Update

2021-08-03: fixed by deleting the file.

File(s) affected: packages\arb-bridge-peripherals\contracts\tokenbridge\misc\L1PassiveFastExitManager.sol

Description: There is a missing permission check for the function setBridge. This could be used for DDoS attacks.

Recommendation: Please add a permission check to this function to make sure not everyone can change bridge at will.
ARB-2  

ERC-677 Standard Not Adhered to/Return Value Unchecked
MediumInfo icon
Fixed

File(s) affected: packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\gateway\ArbitrumGateway.sol,packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\ERC677Token.sol

Description: 0. packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\gateway\ArbitrumGateway.sol: function inboundEscrowAndCall does not check for whether an external call to ERC677Receiver actually succeeds. It is part of the ERC677 proposal that onTokenTransfer returns a boolean that signifies success or failure. There is an assumption here that _to necessarily implements a revert system too. It would be much better to check for return boolean of onTokenTransfer and revert on failure.

    packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\ERC677Token.sol: transferAndCall ignores return value of transfer; same for onTokenTransfer.

Recommendation: Check for the correct return value and revert if necessary.
ARB-3  

Dangerous External Calls From TokenGateways to Arbitrary Contact by Anyone
LowInfo icon
Acknowledged
Alert icon
Update

2021-08-03: the admin team stated that "There’s no reentrancy attack vector, since the external calls occur after all other effects. If there’s an example of where the L1ArbitrumExtendedGateway contract (or any other contract in the token bridge system) isn’t resilient against arbitrary external calls from other contracts, that indeed is/would be an issue, but that’s true regardless of the onExitTransfer hook."

File(s) affected: packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumExtendedGateway.sol

Description: The function transferExitAndCall can be called by any user to call any external contracts. This enables a user to have privilege of the TokenGateway contract and could be used as a tool to conduct a complex attack.

Recommendation: Consider limiting the target calling contracts of this function. For instance, only calls the whitelisted liquidity providers that provide the Fast Withdraw service. Otherwise, state this risk explicitly to your public document. It is also suggested to consider adding a restriction to the function that if the call is successfully completed, it should never process the request for the same _exitNum, _initialDestination, and _newDestination again.
ARB-4  

Greedy Contract
LowInfo icon
Acknowledged
Alert icon
Update

2021-08-03: the admin team decided to leave it unchanged to save gas.

File(s) affected: packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1WethGateway.sol,packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2WethGateway.sol

Description: A greedy contract is a contract that can receive ether which can never be redeemed.

Recommendation: Revert whenever the function receive is called and without sending the msg.value to the counterpart gateway.
ARB-5  

Missing Checks if Address Is Non-Zero
LowInfo icon
Acknowledged
Alert icon
Update

2021-08-03: the admin team considered adding these checks to the contracts are dangerous.

Description: There are many functions that do not validate input addresses. A list of them is provided below, but they might not be comprehensive since there are too many of them.

    packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\gateway\ArbitrumMessenger.sol: sendTxToL2, sendTxToL1.
    packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\gateway\GatewayRouter.sol: _initialize, setDefaultGateway, outboundTransfer, finalizeInboundTransfer, inboundExcrowAndCall, getOutboundCalldata.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1GatewayRouter.sol: _initialize.
    packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\gateway\ArbitrumGateway.sol: _initialize, outboundTransfer, finalizeInboundTransfer, inboundExcrowAndCall.
    packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\gateway\TokenGateway.sol: _initialize, isRouter, isCounterpartGateway, calculateL2TokenAddress, getOutboundCalldata, finalizeInboundTransfer.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumGateway.sol: _initialize getExternalCall, createOutboundTx.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumExtendedGateway.sol: transferExitAndCall, getExternalCall.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1CustomGateway.sol: initialize.
    packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2ArbitrumGateway.sol: _initialize, createOutboundTx, getOutboundCalldata, outboundTransfer.
    packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\L2GatewayToken.sol: _initialize.
    packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2ERC20Gateway.sol: _initialize, handleNoContract.
    packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2WethGateway.sol: _initialize, handleNoContract, outBoundEscrowTransfer, _calculateL2TokenAddress.
    packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2CustomGateway.sol: _initialize, handleNoContract.
    packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\aeWETH.sol: _initialize.

Recommendation: Add relevant checks or make sure the checks are done in their caller/callee functions.
ARB-6  

User May Lose Their Fund when Transferring Them From Layer1 to Layer2 with Insufficient Gas Provided
InformationalInfo icon
Mitigated
Alert icon
Update

2021-08-03: the admin team stated that "With retryable tickets, there is no risk due to insufficient gas. The only risk is if the maxSubmissionCost to create a retryable ticket is too low. The documentation is clear about this, and tooling sets this value with appropriate safety margin for users. This will not be an issue in future releases where the retryable ticket will revert in the L1 if the maxSubmissionCost is too low (requires London hardfork’s basefee opcode)."

File(s) affected: packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumGateway.sol

Description: Although there is the Retryable Tickets mechanism to help retry transactions sent from layer1 to layer2 when the transaction does not succeed the first time. A user may still lose their funds when transferring them from layer1 to layer2 and insufficient gas is provided. Currently, there is no way the user can rescue those lost funds.

Recommendation: This risk needs to be made clear to the users and have them accountable for providing sufficient gas for making sure the layer2 execution can go through successfully.
ARB-7  

Privileged Roles and Ownership
InformationalInfo icon
Fixed

File(s) affected: packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1GatewayRouter.sol

Description: There are some actions that could have important consequences for end-users.

    The owner of the packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1GatewayRouter.sol can call functions setDefaultGateway and setGateways at any point in time, to alter the existing token contract and gateway addresses mapping record.

Recommendation: This centralization of power needs to be made clear to the users, especially depending on the level of privilege the contract allows to the owner.
ARB-8  

Unlocked Pragma
InformationalInfo icon
Acknowledged
Alert icon
Update

2021-08-03: the admin team stated that "We assessed locking the pragma, but the hardhat configuration enforces a single and consistent compiler version."

File(s) affected: All

Description: Every Solidity file specifies in the header a version number of the format pragma solidity (^)0.8.*. The caret (^) before the version number implies an unlocked pragma, meaning that the compiler will use the specified version and above, hence the term "unlocked".

Recommendation: For consistency and to prevent unexpected behavior in the future, it is recommended to remove the caret to lock the file onto a specific Solidity version.
ARB-9  

[False Positive] Function initialize() Not Protected
UndeterminedInfo icon
Fixed
Alert icon
Update

With clarification from the admin team, this issue has been identified as a false-positive. We decided to leave it in the report for completeness.

File(s) affected: packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2ERC20Gateway.sol, packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2CustomGateway.sol, packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2GatewayRouter.sol, packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2WethGateway.sol, packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1CustomGateway.sol, packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ERC20Gateway.sol, packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1GatewayRouter.sol, packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1WethGateway.sol

Description: Function initialize is used as a constructor-like function and used to set important state variables for a contract. However, it seems to be public and not protected. Typically you expect some sort of modifier that checks whether the contract has already been initialized. It could be used as an implementation with a proxy that protects initialize, but this is not clear with the current scope of the audit. If that assumption is wrong then this is a severe exploit waiting to happen.

Recommendation: Add checks to protect it.
Code Documentation

    https://developer.offchainlabs.com/docs/bridging_assets#bridging-erc20-tokens: "with empty calldataForL1" => should use ` for the variablecalldataForL1`.
    "https://developer.offchainlabs.com/docs/l1_l2_messages": for "Arbitrum offers several ways for an Ethereum transaction to send a message to Arbitrum (see "L2 Messages");", the hyperlink of "L2 Messages" is broken.
    packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2ArbitrumGateway.sol: L29: gatways -> gateways. 0.packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2CustomGateway.sol: L55: not deploy -> not “deployed".
    packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2CustomGateway.sol: handleNoContract does not describe @param for _from, _to, _amount.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumExtendedGateway.sol: L64 comment seems to trail off and sentence is not complete.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumExtendedGateway.sol: L78: transfering you exit -> transferring “your” exit.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumExtendedGateway.sol: L118 is redundant .
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumGateway.sol: L31: gatways -> gateways. 0.packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1CustomGateway.sol: L27: Gatway -> Gateway.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1CustomGateway.sol: L104: exrecution -> execution.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1CustomGateway.sol: L106: tick3et -> ticket. 0.packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1GatewayRouter.sol: L28: Erhereum -> Ethereum, and itnerface -> interface.

Adherence to Best Practices

    TODOs in packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\BytesParser.sol: L31, L42.
    TODOs in packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\gateway\TokenGateway.sol: L39, L46
    TODOs in packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ERC20Gateway.sol: L74, L106.
    TODOs in packages\arb-bridge-peripherals\contracts\tokenbridge\arbitrum\gateway\L2ArbitrumGateway.sol: L98, L99. 0.packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1ArbitrumExtendedGateway.sol: L118 is redundant.
    packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\aeWETH.sol: initialize: should fix all the WETH information (name, symbol, decimals) since those are all already known.
    packages\arb-bridge-peripherals\contracts\tokenbridge\ethereum\gateway\L1GatewayRouter.sol: comment on L152 is not clear - why not implement it? 0.packages\arb-bridge-peripherals\contracts\tokenbridge\libraries\gateway\ArbitrumGateway.sol: L71-L72 could better phrased as

require(gasleft() > gasReserveIfCallRevert(), "insufficient gas");
uint256 gasAvailable = gasleft() - gasReserveIfCallRevert();

Definitions

    High severity – High-severity issues usually put a large number of users' sensitive information at risk, or are reasonably likely to lead to catastrophic impact for client's reputation or serious financial implications for client and users.
    Medium severity – Medium-severity issues tend to put a subset of users' sensitive information at risk, would be detrimental for the client's reputation if exploited, or are reasonably likely to lead to moderate financial impact.
    Low severity – The risk is relatively small and could not be exploited on a recurring basis, or is a risk that the client has indicated is low impact in view of the client's business circumstances.
    Informational – The issue does not pose an immediate risk, but is relevant to security best practices or Defence in Depth.
    Undetermined – The impact of the issue is uncertain.
    Fixed – Adjusted program implementation, requirements or constraints to eliminate the risk.
    Mitigated – Implemented actions to minimize the impact or likelihood of the risk.
    Acknowledged – The issue remains in the code but is a result of an intentional business or design decision. As such, it is supposed to be addressed outside the programmatic means, such as: 1) comments, documentation, README, FAQ; 2) business processes; 3) analyses showing that the issue shall have no negative consequences in practice (e.g., gas analysis, deployment settings).

Appendix
File Signatures

The following are the SHA-256 hashes of the reviewed files. A file with a different SHA-256 hash has been modified, intentionally or otherwise, after the security review. You are cautioned that a different SHA-256 hash could be (but is not necessarily) an indication of a changed condition or potential vulnerability that was not within the scope of the review.
Files

    47b...dd1 ./tokenbridge/test/GatewayTest.sol
    498...783 ./tokenbridge/test/InboxMock.sol
    d24...545 ./tokenbridge/test/TestArbCustomToken.sol
    90f...700 ./tokenbridge/test/TestCustomTokenL1.sol
    164...67f ./tokenbridge/test/TestERC20.sol
    864...b4a ./tokenbridge/test/TestPostDepositCall.sol
    799...f1c ./tokenbridge/test/TestWETH9.sol
    d72...3b0 ./tokenbridge/libraries/BytesParser.sol
    ee3...edd ./tokenbridge/libraries/ClonableBeaconProxy.sol
    9dc...1e9 ./tokenbridge/libraries/ITransferAndCall.sol
    75e...545 ./tokenbridge/libraries/IWETH9.sol
    af3...1b6 ./tokenbridge/libraries/L2GatewayToken.sol
    6cd...133 ./tokenbridge/libraries/TransferAndCallToken.sol
    544...986 ./tokenbridge/libraries/aeERC20.sol
    03f...1cf ./tokenbridge/libraries/aeWETH.sol
    7a9...f5e ./tokenbridge/libraries/gateway/ArbitrumGateway.sol
    b79...eca ./tokenbridge/libraries/gateway/ArbitrumMessenger.sol
    396...04c ./tokenbridge/libraries/gateway/GatewayRouter.sol
    a06...256 ./tokenbridge/libraries/gateway/ICustomGateway.sol
    63e...033 ./tokenbridge/libraries/gateway/IGatewayRouter.sol
    ff0...4d4 ./tokenbridge/libraries/gateway/ITokenGateway.sol
    134...3ca ./tokenbridge/libraries/gateway/TokenGateway.sol
    171...3e5 ./tokenbridge/ethereum/ICustomToken.sol
    fd5...aad ./tokenbridge/ethereum/gateway/L1ArbitrumExtendedGateway.sol
    92d...88a ./tokenbridge/ethereum/gateway/L1ArbitrumGateway.sol
    faa...078 ./tokenbridge/ethereum/gateway/L1CustomGateway.sol
    371...f03 ./tokenbridge/ethereum/gateway/L1ERC20Gateway.sol
    a67...08c ./tokenbridge/ethereum/gateway/L1GatewayRouter.sol
    15e...0d4 ./tokenbridge/ethereum/gateway/L1WethGateway.sol
    674...6eb ./tokenbridge/arbitrum/IArbToken.sol
    b7f...c4c ./tokenbridge/arbitrum/StandardArbERC20.sol
    7b3...579 ./tokenbridge/arbitrum/gateway/L2ArbitrumGateway.sol
    951...bc0 ./tokenbridge/arbitrum/gateway/L2CustomGateway.sol
    3b6...f82 ./tokenbridge/arbitrum/gateway/L2ERC20Gateway.sol
    2e2...ba3 ./tokenbridge/arbitrum/gateway/L2GatewayRouter.sol
    6c9...c77 ./tokenbridge/arbitrum/gateway/L2WethGateway.sol

Tests

    47b...dd1 ./test/GatewayTest.sol
    498...783 ./test/InboxMock.sol
    d24...545 ./test/TestArbCustomToken.sol
    90f...700 ./test/TestCustomTokenL1.sol
    164...67f ./test/TestERC20.sol
    864...b4a ./test/TestPostDepositCall.sol
    799...f1c ./test/TestWETH9.sol

Toolset

The notes below outline the setup and steps performed in the process of this audit.
Setup

Tool Setup:

    SolidityCoverage  v0.7.16
    Slither  v0.8.0

Steps taken to run the tools:

    npm install solidity-coverage
    add plugins: ["solidity-coverage"] to truffle-config.js
    change truffle-config.js to add a development network

development: {
            host: "127.0.0.1",     // Localhost (default: none)
            gasPrice: 100000000000,
            port: 8545,            // Standard Ethereum port (default: none)
            network_id: "5555",       // Any network (default: none)
           },

    modifying the secret.localnet.json to have recipient[1,2]_address from the new network

    {
      "mnemonic": "",
      "infura_api_key": "",
      "recipient1_address": "0xb56ec59083bca56e374f25677108cb4534a474d7",
      "recipient2_address": "0xb538d7a6d7495689e2219b26c3e189e2ad3c92e7",
      "usdt_token_address": "",
      "stmx_token_address": "",
      "eth_usd_aggregator_address": "",
      "stmx_usd_aggregator_address": "",
      "usdt_usd_aggregator_address": ""
    }

    comment out L2-L3 in truffle-config.js
    ganache-cli --networkId 5555
    truffle migrate --network development
    truffle run coverage --network development

    Installed the Slither tool: pip install slither-analyzer
    Run Slither from the project directory: slither .

Automated Analysis
Slither

Failed to execute due to a FileNotFoundError: "[Errno 2] No such file or directory: 'artifacts/build-info'".
Test Suite Results

All tests have passed.

=================yarn test:e2e=================
  Bridge peripherals end-to-end
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should deposit tokens (182ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should withdraw erc20 tokens from L2 without router (252ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should withdraw erc20 tokens from L2 using router (176ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should communicate with inbox mock correctly (194ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should force withdraw correctly if deposit is incorrect (144ms)

  Bridge peripherals end-to-end custom gateway
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should deposit tokens (165ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should withdraw tokens (170ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should withdraw tokens if no token is deployed (116ms)

  Bridge peripherals end-to-end weth gateway
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should deposit tokens (78ms)
    ✓ should withdraw tokens (87ms)
    ✓ should withdraw tokens if no token is deployed (104ms)


  11 passing (7s)

Done in 37.78s.




=================yarn test:l1=================

  Bridge peripherals layer 1
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should escrow depositted tokens (197ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should withdraw erc20 tokens from L2 (196ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should submit the correct submission cost to the inbox (137ms)

  Bridge peripherals layer 1
    ✓ should submit the correct submission cost to the inbox (85ms)


  4 passing (2s)

Done in 9.96s.



=================yarn test:l2=================
  Bridge peripherals layer 2
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should deploy erc20 tokens correctly (331ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should mint erc20 tokens correctly (316ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should execute post mint call (444ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should revert post mint call correctly (415ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should reserve gas in post mint call to ensure rest of function can be executed (1214ms)
    ✓ should revert post mint call if sent to EOA (285ms)
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
    ✓ should burn on withdraw (370ms)

  Bridge peripherals weth layer 2
Duplicate definition of Transfer (Transfer(address,address,uint256,bytes), Transfer(address,address,uint256))
here
    ✓ should deposit weth correctly (67ms)
    ✓ should burn on withdraw (128ms)


  9 passing (9s)

Done in 17.22s.

Code Coverage

The coverage score could not be obtained due to the fact that the solidity-coverage does not support the cross chain design at this moment.
Changelog

    2021-07-16 - Initial report
    2021-08-04 - Final report

About Quantstamp

Quantstamp is a global leader in blockchain security. Founded in 2017, Quantstamp’s mission is to securely onboard the next billion users to Web3 through its best-in-class Web3 security products and services.

Quantstamp’s team consists of cybersecurity experts hailing from globally recognized organizations including Microsoft, AWS, BMW, Meta, and the Ethereum Foundation. Quantstamp engineers hold PhDs or advanced computer science degrees, with decades of combined experience in formal verification, static analysis, blockchain audits, penetration testing, and original leading-edge research.

To date, Quantstamp has performed more than 500 audits and secured over $200 billion in digital asset risk from hackers. Quantstamp has worked with a diverse range of customers, including startups, category leaders and financial institutions. Brands that Quantstamp has worked with include Ethereum 2.0, Binance, Visa, PayPal, Polygon, Avalanche, Curve, Solana, Compound, Lido, MakerDAO, Arbitrum, OpenSea and the World Economic Forum.

Quantstamp’s collaborations and partnerships showcase our commitment to world-class research, development and security. We're honored to work with some of the top names in the industry and proud to secure the future of web3.

Notable Collaborations & Customers:

    Blockchains: Ethereum 2.0, Near, Flow, Avalanche, Solana, Cardano, Binance Smart Chain, Hedera Hashgraph, Tezos
    DeFi: Curve, Compound, Maker, Lido, Polygon, Arbitrum, SushiSwap
    NFT: OpenSea, Parallel, Dapper Labs, Decentraland, Sandbox, Axie Infinity, Illuvium, NBA Top Shot, Zora
    Academic institutions: National University of Singapore, MIT

Timeliness of content

The content contained in the report is current as of the date appearing on the report and is subject to change without notice, unless indicated otherwise by Quantstamp; however, Quantstamp does not guarantee or warrant the accuracy, timeliness, or completeness of any report you access using the internet or other means, and assumes no obligation to update any information following publication or other making available of the report to you by Quantstamp.
Notice of confidentiality

This report, including the content, data, and underlying methodologies, are subject to the confidentiality and feedback provisions in your agreement with Quantstamp. These materials are not to be disclosed, extracted, copied, or distributed except to the extent expressly authorized by Quantstamp.
Links to other websites

You may, through hypertext or other computer links, gain access to web sites operated by persons other than Quantstamp. Such hyperlinks are provided for your reference and convenience only, and are the exclusive responsibility of such web sites' owners. You agree that Quantstamp are not responsible for the content or operation of such web sites, and that Quantstamp shall have no liability to you or any other person or entity for the use of third-party web sites. Except as described below, a hyperlink from this web site to another web site does not imply or mean that Quantstamp endorses the content on that web site or the operator or operations of that site. You are solely responsible for determining the extent to which you may use any content at any other web sites to which you link from the report. Quantstamp assumes no responsibility for the use of third-party software on any website and shall have no liability whatsoever to any person or entity for the accuracy or completeness of any output generated by such software.
Disclaimer

The review and this report are provided on an as-is, where-is, and as-available basis. To the fullest extent permitted by law, Quantstamp disclaims all warranties, expressed implied, in connection with this report, its content, and the related services and products and your use thereof, including, without limitation, the implied warranties of merchantability, fitness for a particular purpose, and non-infringement. You agree that access and/or use of the report and other results of the review, including but not limited to any associated services, products, protocols, platforms, content, and materials, will be at your sole risk. FOR AVOIDANCE OF DOUBT, THE REPORT, ITS CONTENT, ACCESS, AND/OR USAGE THEREOF, INCLUDING ANY ASSOCIATED SERVICES OR MATERIALS, SHALL NOT BE CONSIDERED OR RELIED UPON AS ANY FORM OF FINANCIAL, INVESTMENT, TAX, LEGAL, REGULATORY, OR OTHER ADVICE. This report is based on the scope of materials and documentation provided for a limited review at the time provided. You acknowledge that Blockchain technology remains under development and is subject to unknown risks and flaws and, as such, the report may not be complete or inclusive of all vulnerabilities. The review is limited to the materials identified in the report and does not extend to the compiler layer, or any other areas beyond the programming language, or programming aspects that could present security risks. The report does not indicate the endorsement by Quantstamp of any particular project or team, nor guarantee its security, and may not be represented as such. No third party is entitled to rely on the report in any way, including for the purpose of making any decisions to buy or sell a product, service or any other asset. Quantstamp does not warrant, endorse, guarantee, or assume responsibility for any product or service advertised or offered by a third party, or any open source or third-party software, code, libraries, materials, or information to, called by, referenced by or accessible through the report, its content, or any related services and products, any hyperlinked websites, or any other websites or mobile applications, and we will not be a party to or in any way be responsible for monitoring any transaction between you and any third party. As with the purchase or use of a product or service through any medium or in any environment, you should use your best judgment and exercise caution where appropriate.
