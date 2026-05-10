"""One-shot script: insert ## Tags block after the first # heading in each file that lacks one."""
import pathlib, re

KNOWLEDGE_DIR = pathlib.Path(__file__).parent / "knowledge"

TAGS = {
    # audit_checklists
    "audit_checklists/defi_protocols_checklist.md":
        "defi, checklist, audit, security-review, protocol, vulnerabilities, DeFi-patterns",
    "audit_checklists/solidity_evm_checklist.md":
        "solidity, evm, checklist, audit, security-review, common-vulnerabilities, EVM",
    "audit_checklists/sui_full_checklist.md":
        "sui, move, checklist, audit, security-review, full-checklist",

    # defi
    "defi/accounting_share_price_bugs.md":
        "defi, accounting, share-price, vault, pricing-bugs, rounding, per-share",
    "defi/bridge_cross_chain_vulnerabilities.md":
        "bridge, cross-chain, vulnerabilities, message-passing, relay, L2, replay",
    "defi/code4rena_common_findings.md":
        "code4rena, common-findings, audit, DeFi, high-severity, medium, recurring",
    "defi/defiapp_pashov_airdrop_audit_2025.md":
        "airdrop, pashov, audit, merkle-proof, claim, distribution, whitelist",
    "defi/easedefi_stnxm_nft_hide_inflate_shares.md":
        "ease-defi, nft, shares, inflation, hide-shares, ERC1155, vault",
    "defi/easedefi_stnxm_oracle_price_validation_dos.md":
        "ease-defi, oracle, price-validation, dos, denial-of-service, revert",
    "defi/easedefi_stnxm_tranche_tracking_missing.md":
        "ease-defi, tranche, tracking, accounting, missing-update",
    "defi/easedefi_stnxm_uniswap_cardinality_dos.md":
        "ease-defi, uniswap, cardinality, dos, oracle, observation-buffer",
    "defi/easedefi_stnxm_uniswap_spot_price_manipulation.md":
        "ease-defi, uniswap, spot-price, manipulation, oracle, sandwich",
    "defi/easedefi_stnxm_wrong_uniswap_tokenid_burn.md":
        "ease-defi, uniswap, tokenid, burn, nft, wrong-id",
    "defi/flash_loans.md":
        "flash-loan, attack, reentrancy, arbitrage, price-manipulation, uncollateralized, AAVE",
    "defi/gmx_vault_block_ui_fee_dos.md":
        "gmx, vault, fee, dos, block, griefing, perpetuals",
    "defi/governance_attacks.md":
        "governance, attack, voting, flash-loan, dao, proposal, quorum, timelock",
    "defi/immunefi_critical_patterns.md":
        "immunefi, critical, bug-bounty, high-severity, patterns, exploit",
    "defi/lending_borrowing_vulnerabilities.md":
        "lending, borrowing, collateral, liquidation, interest-rate, DeFi, compound, aave",
    "defi/liquidation_mechanisms.md":
        "liquidation, collateral, health-factor, bad-debt, DeFi, underwater, seize",
    "defi/nft_marketplace_vulnerabilities.md":
        "nft, marketplace, royalty, bid, offer, signature, seaport, blur",
    "defi/oracle_manipulation_advanced.md":
        "oracle, manipulation, price-feed, twap, chainlink, spot-price, TWAP",
    "defi/perpetuals_derivatives.md":
        "perpetuals, derivatives, funding-rate, leverage, liquidation, mark-price",
    "defi/steadefi_depositor_loss_zero_equity.md":
        "steadefi, depositor, loss, zero-equity, vault, delta-neutral",
    "defi/yield_staking_reward_bugs.md":
        "yield, staking, reward, distribution, farming, emission, per-share, reward-debt",

    # evm
    "evm/echidna_fuzzing_patterns.md":
        "echidna, fuzzing, invariant, property-based, testing, corpus, assertion",
    "evm/slither_detectors_reference.md":
        "slither, static-analysis, detector, solidity, vulnerability, reentrancy, detector-list",

    # nft
    "nft/honeypot_burn_reward_multiplier_bug.md":
        "nft, honeypot, burn, reward, multiplier, bug, ERC721",
    "nft/honeypot_reminting_burned_tokenid.md":
        "nft, honeypot, reminting, burned, tokenid, ghost-token",

    # rekt_postmortems
    "rekt_postmortems/major_defi_hacks.md":
        "rekt, defi, hack, postmortem, major, history, exploit, billion-dollar",

    # solidity
    "solidity/access_control.md":
        "access-control, onlyOwner, roles, RBAC, privilege-escalation, authorization, modifier",
    "solidity/delegatecall_proxy_vulnerabilities.md":
        "delegatecall, proxy, storage-collision, upgradeability, EIP-1967, UUPS, transparent",
    "solidity/denial_of_service.md":
        "dos, denial-of-service, gas-griefing, loop, revert, block-stuffing, push-over-pull",
    "solidity/erc_token_vulnerabilities.md":
        "ERC20, ERC721, token, transfer, approve, allowance, fee-on-transfer, rebasing, weird-tokens",
    "solidity/fiamma_bridge_ownership_loss.md":
        "fiamma, bridge, ownership, loss, admin, renounce",
    "solidity/front_running_mev.md":
        "front-running, mev, sandwich, mempool, slippage, flashbots, commit-reveal",
    "solidity/integer_overflow_underflow.md":
        "overflow, underflow, SafeMath, unchecked, arithmetic, wrapping, uint256",
    "solidity/reentrancy_erc1155_bridge_mutual_audit.md":
        "reentrancy, ERC1155, bridge, cross-chain, mutual-audit, onERC1155Received",
    "solidity/reentrancy.md":
        "reentrancy, reentrant-call, checks-effects-interactions, CEI, fallback, withdraw, drain",
    "solidity/signature_replay_attacks.md":
        "signature, replay, ECDSA, nonce, domain-separator, EIP-712, ecrecover",
    "solidity/storage_layout_uninitialized.md":
        "storage, layout, uninitialized, proxy, slot-collision, delegatecall, ghost-variable",
    "solidity/swc103_unlocked_pragma_quantstamp.md":
        "pragma, version, unlocked, SWC-103, compiler, floating-pragma",
    "solidity/swc107_reentrancy_reference.md":
        "reentrancy, SWC-107, reentrant, cross-function, CEI, mutex",
    "solidity/timestamp_randomness.md":
        "timestamp, block.timestamp, randomness, manipulation, miner, entropy, PREVRANDAO",
    "solidity/unchecked_approve_return_uda.md":
        "approve, return-value, unchecked, ERC20, USDT, safeApprove, forceApprove",
    "solidity/unchecked_calls_return_values.md":
        "unchecked, return-value, call, low-level, assembly, send, transfer",

    # sui_move
    "sui_move/capability_access_control.md":
        "sui, move, capability, access-control, admin-cap, witness, one-time-witness",
    "sui_move/defi_amm_vulnerabilities.md":
        "sui, move, defi, amm, vulnerability, liquidity, swap, curve",
    "sui_move/dynamic_fields_tables.md":
        "sui, move, dynamic-fields, tables, bag, storage, object-bag, vec-map",
    "sui_move/events_witnesses_patterns.md":
        "sui, move, events, witnesses, one-time-witness, otw, phantom-type",
    "sui_move/initia_move_expiration_bypass_h03.md":
        "initia, move, expiration, bypass, time-lock, proposal, off-by-one",
    "sui_move/initia_move_oracle_request_type_m04.md":
        "initia, move, oracle, request-type, type-confusion, band-protocol",
    "sui_move/initia_multisig_expiration_logic_bug.md":
        "initia, multisig, expiration, logic-bug, time, proposal",
    "sui_move/integer_arithmetic_safety.md":
        "sui, move, integer, arithmetic, overflow, division, rounding, u64, u128",
    "sui_move/object_safety.md":
        "sui, move, object, safety, owned, shared, transfer, freeze",
    "sui_move/package_upgrades_admin.md":
        "sui, move, package, upgrade, admin, capability, version, upgrade-cap",
    "sui_move/ptb_composability.md":
        "sui, move, ptb, programmable-transaction, composability, batch, multi-step",
    "sui_move/shared_object_races.md":
        "sui, move, shared-object, race-condition, concurrent, contention, MVCC",
    "sui_move/thala_lsd_inflation_attack_move.md":
        "thala, lsd, inflation, attack, move, shares, staking",
    "sui_move/type_system_coin_safety.md":
        "sui, move, type-system, coin, safety, phantom-type, generic, one-time-witness",
}

inserted = 0
for rel, tags in TAGS.items():
    path = KNOWLEDGE_DIR / rel
    if not path.exists():
        print(f"  [skip] {rel} — not found")
        continue
    text = path.read_text()
    if "## Tags" in text:
        print(f"  [skip] {rel} — already has Tags")
        continue
    # Insert after first # heading line
    lines = text.split("\n")
    insert_at = 1
    for i, line in enumerate(lines):
        if line.startswith("# "):
            insert_at = i + 1
            break
    tag_block = ["", "## Tags", tags, ""]
    lines = lines[:insert_at] + tag_block + lines[insert_at:]
    path.write_text("\n".join(lines))
    inserted += 1
    print(f"  [ok] {rel}")

print(f"\nDone — {inserted} files updated")
