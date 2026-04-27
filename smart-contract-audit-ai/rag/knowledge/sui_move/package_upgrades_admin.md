# Package Upgrades and Admin Patterns in Sui Move

## Sui Upgrade System
Sui packages are immutable by default. Upgrades require an `UpgradeCap` object issued at publish time. The upgrade policy encoded in `UpgradeCap` controls what kinds of changes are allowed.

## UpgradeCap Policies

```move
// Three upgrade policies (set at publish, can only become more restrictive):
// package::COMPATIBLE  — most permissive: add new functions, keep existing signatures
// package::ADDITIVE    — can only add new modules, not modify existing
// package::DEP_ONLY    — can only upgrade dependencies, not the package itself

// After publishing:
// sui client publish --upgrade-capability <path>
// The UpgradeCap is transferred to the sender
```

## Vulnerability 1: UpgradeCap Left Accessible / Unprotected

```move
// VULNERABLE — UpgradeCap transferred to deployer address without governance wrapper
// A compromised deployer key → unlimited upgrades → protocol takeover
fun init(ctx: &mut TxContext) {
    // UpgradeCap auto-issued by the framework at publish time, sent to sender
    // If no additional protection, single EOA controls all upgrades
}

// BETTER — wrap UpgradeCap in a timelock or multisig
struct TimeLocked UpgradeGuard has key {
    id: UID,
    cap: UpgradeCap,
    timelock_ms: u64,
    pending_upgrade: Option<UpgradeTicket>,
}
// Require 48h delay between proposing and executing upgrade
```

## Vulnerability 2: Upgrade Removes Security Checks

```move
// COMPATIBLE upgrades allow:
// - Adding new public functions
// - Adding new modules
// - Modifying function BODIES (not signatures)
//
// RISK: An upgraded function body can remove capability checks, change logic,
// add backdoors — all while the on-chain ABI looks the same.
//
// Users interacting with a "COMPATIBLE" upgradeable package must trust the deployer.
// Audit should flag: is this protocol upgradeable? Is the upgrade mechanism governed?
```

## Vulnerability 3: Missing Upgrade Cooldown

```move
// No cooldown = deployer can upgrade and immediately exploit
// Standard practice: 48-72 hour timelock minimum for DeFi protocols

struct UpgradeProposal has key {
    id: UID,
    digest: vector<u8>,
    proposed_at_ms: u64,
}

const UPGRADE_DELAY_MS: u64 = 172_800_000; // 48 hours

public fun propose_upgrade(
    _: &AdminCap,
    guard: &mut UpgradeGuard,
    digest: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext
) {
    guard.pending = option::some(UpgradeProposal {
        id: object::new(ctx),
        digest,
        proposed_at_ms: clock::timestamp_ms(clock),
    });
}

public fun execute_upgrade(
    _: &AdminCap,
    guard: &mut UpgradeGuard,
    clock: &Clock,
    ctx: &mut TxContext
): UpgradeReceipt {
    let proposal = option::borrow(&guard.pending);
    assert!(
        clock::timestamp_ms(clock) >= proposal.proposed_at_ms + UPGRADE_DELAY_MS,
        ETimelockNotExpired
    );
    package::authorize_upgrade(&mut guard.cap, package::COMPATIBLE, proposal.digest)
}
```

## Vulnerability 4: Freeze After Init Not Done

```move
// If a protocol publishes with upgrade ability but intends to be immutable,
// failure to destroy/freeze UpgradeCap leaves a backdoor

// To make a package permanently immutable:
public fun renounce_upgrades(cap: UpgradeCap) {
    package::make_immutable(cap);  // destroys the cap — irreversible
}
// This should be called once protocol is stable and audited
```

## Vulnerability 5: Admin Key Rotation Not Supported

```move
// VULNERABLE — hardcoded admin address with no rotation path
struct Config has key {
    id: UID,
    admin: address,
}

// If admin key is compromised, no way to rotate without an upgrade
// An upgrade itself requires the compromised key — circular dependency

// FIXED — use capability object, add rotation function
struct AdminCap has key { id: UID }

public fun rotate_admin(cap: AdminCap, new_admin: address) {
    // pass old cap by value (destroys it), send new cap to new_admin
    let AdminCap { id } = cap;
    object::delete(id);
    // emit AdminRotated event
}
// In init: create NEW AdminCap and transfer to new_admin
```

## Vulnerability 6: Emergency Pause Not Implemented

```move
// HIGH-VALUE DeFi MUST have a pause mechanism
struct Config has key {
    id: UID,
    paused: bool,
}

public fun pause(_: &AdminCap, config: &mut Config) {
    config.paused = true;
}

public fun unpause(_: &AdminCap, config: &mut Config) {
    config.paused = false;
}

// Add to all state-changing public functions:
public fun swap(config: &Config, pool: &mut Pool, ...) {
    assert!(!config.paused, EProtocolPaused);
    // ...
}
```

## Correct Admin Architecture

```move
// Production-grade admin setup:
// 1. AdminCap — for routine operations (fee changes, param updates)
// 2. EmergencyPauseCap — for incident response (separate key from admin)
// 3. UpgradeGuard — for package upgrades (48h timelock)
// 4. All caps without `store` ability (can't be wrapped/traded)
// 5. Events emitted for every admin action (on-chain audit trail)

public fun set_fee(_: &AdminCap, config: &mut Config, fee: u64, ctx: &TxContext) {
    assert!(fee <= MAX_FEE, EFeeTooHigh);
    let old_fee = config.fee;
    config.fee = fee;
    event::emit(FeeChanged { old_fee, new_fee: fee, changed_by: tx_context::sender(ctx) });
}
```

## Detection Signals
- `UpgradeCap` sent directly to deployer with no governance wrapper
- No timelock between upgrade proposal and execution
- `COMPATIBLE` upgrade policy on TVL-holding protocol
- Admin stored as `address` field instead of capability object
- No pause mechanism in DeFi contracts
- Admin operations without `event::emit`
- `make_immutable` never called on mature protocols

## Severity Guide
- Unprotected UpgradeCap (single EOA controls upgrades): **Critical**
- No upgrade timelock on DeFi protocol: **High**
- No pause/emergency mechanism: **High**
- Admin key rotation not supported: **Medium**
- No events for admin actions: **Low** (but required for audit trail)
