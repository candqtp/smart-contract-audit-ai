Overview

## Tags
approve, return-value, unchecked, ERC20, USDT, safeApprove, forceApprove

About C4

Code4rena (C4) is a competitive audit platform where security researchers, referred to as Wardens, review, audit, and analyze codebases for security vulnerabilities in exchange for bounties provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the Garden Finance smart contract system. The audit took place from November 24 to December 08, 2025.

Final report assembled by Code4rena.
Summary

The C4 analysis yielded an aggregated total of 1 unique vulnerabilities. Of these vulnerabilities, 0 received a risk rating in the category of HIGH severity and 1 received a risk rating in the category of MEDIUM severity.

Additionally, C4 analysis included 64 QA reports compiling issues with a risk rating of LOW severity or informational.

All of the issues presented here are linked back to their original finding, which may include relevant context from the judge and Garden Finance team.
Scope

The code under review can be found within the C4 Garden Finance repository, and is composed of 15 smart contracts written in the Cairo, Move, Rust and Solidity programming language and includes 2,163 lines of code.
Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/informational.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

    Malicious Input Handling
    Escalation of privileges
    Arithmetic
    Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on the C4 website, specifically our section on Severity Categorization.
Medium Risk Findings (1)
[M-01] Unchecked approve( ) return causes permanent fund loss in UDA.sol

Submitted by barah, also found by 0xDemon, 0xFBI, 0xGutzzz, fullstop, holtzzx, makarov, NexusAudits, rox_k, and topenga

swap/UDA.sol #L38
Finding description

The UniqueDepositAddress.initialize() function at line 38 ignores the return value of ERC20.approve():

function initialize() public initializer {
    // ... parameter extraction ...
    
    HTLC(_addressHTLC).token().approve(_addressHTLC, amount);  // ❌ Return value ignored
    
    HTLC(_addressHTLC).initiateOnBehalf(
        refundAddress, redeemer, timelock, amount, secretHash, destinationData
    );
}

Root Cause

Non-standard ERC20 tokens (USDT, BNB, etc.) return false instead of reverting when approve() fails. The current implementation does not verify this return value, allowing execution to continue even when approval fails.
Impact

When a user deposits tokens into the UDA and approve() silently fails:

    The contract marks itself as initialized.
    The allowance remains at 0.
    initiateOnBehalf() executes but HTLC cannot transfer tokens.
    User funds become permanently locked with no recovery mechanism.

Recommended mitigation steps

The contract already imports SafeERC20 but doesn’t use it for the critical approve() call. Apply one of these fixes:

function initialize() public initializer {
    // ... parameter extraction ...
    
    //  Use SafeERC20 that's already imported
    IERC20(HTLC(_addressHTLC).token()).safeApprove(_addressHTLC, amount);
    
    HTLC(_addressHTLC).initiateOnBehalf(
        refundAddress, redeemer, timelock, amount, secretHash, destinationData
    );
}

This fix is recommended as it provides comprehensive protection against all ERC20 edge cases and maintains consistency with the contract’s existing use of SafeERC20 in the recover() functions (lines 59, 106).
Proof of Concept

This PoC demonstrates how the unchecked approve() return value leads to permanent fund loss with non-standard ERC20 tokens like USDT.

View detailed Proof of Concept

Running the PoC:

    Navigate to project root: cd evm/
    Install dependencies (if needed): forge install foundry-rs/forge-std --no-commit
    Run the complete exploit: forge test --match-contract ApproveVulnerabilityPOC -vvv
    Run with detailed traces: forge test --match-test testPOC_ApproveFailsSilently -vvvv

Expected Output

EXPLOIT: Complete Fund Loss

    User deposited: 10000 USDT
        UDA Balance: 10000000000
        Allowance: 0
    USDT approve() will return false (real USDT behavior)

    Calling initialize()...
        initialize() completed: SUCCESS
        Contract initialized: true
        Allowance after init: 0

    VULNERABILITY CONFIRMED:
        initialize() succeeded
        But allowance = 0 (approve failed silently)
        Contract marked as initialized

    Attempting to withdraw funds…
        Withdrawal FAILED: Insufficient allowance

RESULT: 10,000 USDT PERMANENTLY LOCKED

    Final UDA Balance: 10000 USDT
    User Loss: $10,000 USD

Trace Analysis (with -vvvv):

[37060] VulnerableUDA::initialize()
  ├─ [549] MockUSDT::balanceOf(VulnerableUDA)
  │   └─ ← 10000000000
  ├─ [573] MockUSDT::approve(MockHTLC, 10000000000)
  │   └─ ← false  ⚠️ RETURNS FALSE - NOT DETECTED!
  └─ ← [Stop]  ❌ Continues execution despite failure

[31720] MockHTLC::withdrawFromUDA(VulnerableUDA, 10000000000)
  ├─ [2805] MockUSDT::transferFrom(VulnerableUDA, user, 10000000000)
  │   └─ ← revert: Insufficient allowance  ❌ FUNDS LOCKED
  └─ ← revert: Insufficient allowance

Key Evidence:

    approve() returns false but no revert occurs.
    Allowance remains 0: Despite “successful” initialization.
    Withdrawal fails: HTLC cannot access funds.
    No recovery: Contract marked as initialized, blocking re-initialization.

This PoC conclusively demonstrates that 10,000 USDT ($10,000 USD) becomes permanently locked due to the unchecked return value at line 38 of UDA.sol.
Low Risk and Informational Issues

For this audit, 64 QA reports were submitted by wardens compiling low risk and informational issues. The QA report highlighted below by eta received the top score from the judge. 11 Low-severity findings were also submitted individually, and can be viewed here.

The following wardens also submitted QA reports: 0x_DyDx, 0x_kmr_, 0xki, 0xnija, 0xsh, 0xSH10, ahahaHard1k, AlexCzm, Almanax, amirhossineedalat, avoloder, Bala1796, bam0x7, Bauer, BlockBuster, boodieboodieboo, Bube, calc1f4r, cosin3, crypt0g33k, czarcas7ic, dman, Ekene, francoHacker, freebird0323, Glitchunter, happykilling, Heyu, jiangling, JJS, K42, kestyvickky, KineticsOfWeb3, KKKKK, kmkm, legat, mahdifa, Manosh19, Manvita, maze, Meks079, Meoww, MinionTechs, poInT, pro_king, psyone, Q7, rare_one, redfox, richa, rmrf480, Rorschach, Seeker, Spektor, sudais_b, th3_hybrid, trilobyteS, valarislife, Vivekz, wardenx, x0rc1ph3r, ZeronautX, and zubyoz.
[01] Missing validation for redeemer != refundee enables same-party orders and instant self-refunds, weakening HTLC semantics

    solana-native-swaps/src/lib.rs::initiate #L20-L64
    solana-native-swaps/src/lib.rs::instant_refund #L130-L153
    solana-spl-swaps/src/lib.rs::initiate #L22-L80
    solana-native-swaps/src/lib.rs::instant_refund #L188-L23

Finding description

The initiate instruction in both Solana HTLC implementations (native SOL and SPL token) does not enforce redeemer != refundee. Orders can be created where the redeemer and refundee are the same address, despite HTLC’s intended separation of redeem and refund roles.
Impact

    Instant self-refund: instant_refund requires the redeemer’s consent but no secret or timelock, allowing the same address to immediately refund to itself when redeemer == refundee without revealing the secret.
    Dual single-beneficiary paths: The same address becomes the beneficiary of both redeem and refund flows, breaking the expected “counterparty provides secret to redeem; initiator receives refund after expiry” contract.
    Operational ambiguity: Events and on-chain audit trails no longer distinguish counterpart roles, complicating monitoring, reconciliation, and downstream integrations that assume distinct actors.

    pub fn initiate(
        ctx: Context<Initiate>,
        redeemer: Pubkey,
        refundee: Pubkey,
        secret_hash: [u8; 32],
        swap_amount: u64,
        timelock: u64,
        destination_data: Option<Vec<u8>>,
    ) -> Result<()> {
        let transfer_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.funder.to_account_info(),
                to: ctx.accounts.swap_account.to_account_info(),
            },
        );
        system_program::transfer(transfer_context, swap_amount)?;

        let expiry_slot = Clock::get()?
            .slot
            .checked_add(timelock)
            .expect("timelock should not cause an overflow");
        *ctx.accounts.swap_account = SwapAccount {
            expiry_slot,
            bump: ctx.bumps.swap_account,
            rent_sponsor: ctx.accounts.rent_sponsor.key(),
            refundee,
            redeemer,
            secret_hash,
            swap_amount,
            timelock,
        };

        emit!(Initiated {
            redeemer,
            refundee,
            secret_hash,
            swap_amount,
            timelock,
            destination_data,
            funder: ctx.accounts.funder.key(),
        });

        Ok(())
    }

    pub fn instant_refund(ctx: Context<InstantRefund>) -> Result<()> {
        let SwapAccount {
            refundee,
            redeemer,
            secret_hash,
            swap_amount,
            timelock,
            ..
        } = *ctx.accounts.swap_account;

        ctx.accounts.swap_account.sub_lamports(swap_amount)?;
        ctx.accounts.refundee.add_lamports(swap_amount)?;

        emit!(InstantRefunded {
            redeemer,
            refundee,
            secret_hash,
            swap_amount,
            timelock,
        });

        Ok(())
    }
}

Recommended Mitigation Steps

Enforce participant distinctness at initiation: Add require!(redeemer != refundee, ...) in both initiate functions (solana-native-swaps and solana-spl-swaps).
[02] Project-wide spelling and identifier typos
Finding description

Several spelling mistakes exist across EVM and Starknet codebases, including incorrect error identifier spelling “Recieved” instead of “Received”, parameter name typos in doc comments, and multiple “initiate” misspellings in Cairo/Starknet tests.
Impact

    EVM error identifiers are part of the ABI via custom error selectors (keccak256(ErrorSignature)); renaming changes the selector. Any external tooling, tests, or off-chain decoders expecting the old selector will fail unless updated.
    Developer ergonomics and documentation quality degrade; typos in comments and test names reduce readability and can mislead integrators.
    Cross-language code consistency suffers (Solidity, Cairo, TypeScript), increasing maintenance burden and risk of subtle mismatches in protocol messaging or test fixtures.

Code locations

    Incorrect error name NativeHTLC__IncorrectFundsRecieved: swap/NativeHTLC.sol #L-82
    Usage of incorrect error name in safeParams: swap/NativeHTLC.sol #L91
    Incorrect error name ArbNativeHTLC__IncorrectFundsRecieved: swap/ArbNativeHTLC.sol #L88
    Usage of incorrect error name in safeParams: swap/ArbNativeHTLC.sol #L97
    Cairo variable name typo intiate (should be initiate): htlc.cairo #L249
    Cairo variable name typo intiate: htlc.cairo #L257

    Starknet tests type/identifier typo INTIATE_TYPE (should be INITIATE_TYPE) representative occurrences in HTLC.test.ts:
        #L449
        #L477
        #L514
        #L551
        #L587
        #L623
        #L1305
        #L1374
        #L1503

Recommended Mitigation Steps

    EVM contracts: Rename NativeHTLC__IncorrectFundsRecieved to NativeHTLC__IncorrectFundsReceived and update all references including require sites and tests.
    Rename ArbNativeHTLC__IncorrectFundsRecieved to ArbNativeHTLC__IncorrectFundsReceived and update references.
    Starknet/Cairo and tests: Rename intiate variables to initiate in starknet/src/htlc.cairo and adjust all uses.
    Standardize INTIATE_TYPE → INITIATE_TYPE across the Starknet test suite; update all references where used as type names or constants.

Disclosures

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
