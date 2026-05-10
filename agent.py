"""
Devstral Audit Agent — smart contract security auditor + code generator.

Capabilities:
  - Audit Solidity and Sui Move contracts for vulnerabilities
  - Generate professional audit reports (Markdown)
  - Generate secure smart contracts
  - Read/write local files
  - Run Slither static analysis
  - Semantic search over 1728 audit findings + custom knowledge docs (RAG)
  - Multi-turn conversation with tool loop — never runs out of context

Requirements:
    pip install mistralai chromadb sentence-transformers rich

Usage:
    # Interactive REPL (local Ollama devstral):
    python agent.py

    # Use fine-tuned model via Mistral API:
    python agent.py --api --model ft:devstral-small-2505:audit-v1:...

    # Audit a specific file:
    python agent.py --file contracts/Vault.sol

    # Audit entire directory:
    python agent.py --dir contracts/

    # Audit from stdin:
    cat MyContract.sol | python agent.py --stdin

    # Generate a contract:
    python agent.py --generate "ERC20 token with vesting schedule and reentrancy protection"

    # Build RAG index first (one-time):
    python rag/build_index.py

Setup:
    # Local (Ollama):
    ollama pull devstral

    # Cloud (Mistral API after fine-tuning):
    export MISTRAL_API_KEY=sk-...
    python agent.py --api --model ft:devstral-small-2505:audit-v1:...
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent
INDEX_DIR = ROOT / ".rag_index"
REPORTS_DIR = ROOT / "reports"

DEFAULT_OLLAMA_MODEL = "deepseek-r1:14b"
DEFAULT_API_MODEL = "devstral-small-2505"
RAG_K = 5              # number of RAG results to fetch per query
MAX_TOOL_ROUNDS = 12   # max tool call rounds per turn (more for deepseek's thinking steps)
RELEVANCE_THRESHOLD = 0.55  # discard RAG chunks below this score — bad context triggers hallucinations
DEFAULT_PHASE = "hunt"

# Cross-phase context carry — recon/threats output is stored here and injected into hunt
_phase_carry: dict[str, str] = {}   # phase_name → output text

# Bounty/audit program context — loaded once, injected into every session
_bounty_brief: str = ""        # from --brief flag or REPL `brief` command
_project_guidelines: str = ""  # from audit.config.md auto-loaded from target dir
_tools_supported: bool | None = None  # None=unknown; True=native API; False=ReAct text mode


# ── phase-specific RAG seed queries ──────────────────────────────────────────
PHASE_RAG_QUERIES: dict[str, str] = {
    "recon":        "attack surface entry points privileged roles external calls asset flow",
    "threats":      "flash loan oracle manipulation governance attack trust assumption exploit",
    "hunt":         "reentrancy integer overflow access control flash loan oracle manipulation front-running",
    "focused":      "vulnerability detection exploit proof of concept code pattern",
    "interactions": "cross-contract reentrancy trust assumption delegatecall proxy state manipulation",
    "report":       "audit report findings severity classification remediation recommendation",
}


# ── phase prompts (deepseek-r1 adapted) ──────────────────────────────────────
# {prior_context} is replaced with output from earlier phases if available.
# {rag_context}   is replaced with RAG chunks at query time.
PHASE_PROMPTS: dict[str, str] = {

    "recon": textwrap.dedent("""\
        You are DeepAudit in RECONNAISSANCE phase.
        Map the contract's attack surface. Do NOT hunt for bugs yet.
        Only report things you can confirm exist in the code.

        WORKFLOW:
        1. Call extract_code_elements(code) first — list what exists
        2. Use read_file / list_directory to read any additional files
        3. Fill the output format strictly — stop when done

        OUTPUT FORMAT (use exactly this structure):
        ## [ContractName] — Recon
        **Purpose:** (one sentence — what does this contract do)
        **Entry points:** list each public/external function with one-line description
        **Privileged roles:** role name — what it controls
        **External calls:** to which interface/contract and why
        **Asset flow:** what tokens/ETH enter, leave, or are held and in which functions
        **Watch list for hunt phase:** (max 3 specific functions or patterns worth deep-diving)

        HARD RULES:
        - Do not report vulnerabilities in this phase
        - Only list functions that appear in extract_code_elements output
        - If a field has nothing, write "none detected"
        {rag_context}
        """),

    "threats": textwrap.dedent("""\
        You are DeepAudit in THREAT MODELING phase.
        Think adversarially about what an attacker COULD do — before reading code.

        {prior_context}

        WORKFLOW:
        1. Search the knowledge base for attack patterns relevant to this protocol type
        2. Fill each field — do not add extra sections

        OUTPUT FORMAT:
        ## Threat Model
        **Worst case:** (fund theft / freeze / price manipulation / supply inflation)
        **Actors:** all parties and their malicious capabilities
        **Trust assumptions:** external systems trusted — what breaks if compromised
        **Invariants:** conditions that must ALWAYS hold
        **High-risk flows:** liquidation, flash loan, upgrade, bridge, governance

        {rag_context}
        """),

    "hunt": textwrap.dedent("""\
        You are DeepAudit in VULNERABILITY HUNT phase.

        {prior_context}

        MANDATORY STEPS — in this exact order:
        1. Call extract_code_elements(code) — ground every finding in its output
        2. Call run_slither(code) for Solidity, or run_sui_analyzer(code) for Move
        3. Call search_knowledge() using actual code identifiers you confirmed in step 1
        4. Write findings using ONLY the format below

        GROUNDING RULES:
        - Every finding must cite a function/variable that appeared in extract_code_elements
        - Oracle manipulation: only if oracle_indicators is non-empty
        - Flash loan: only if flash_loan_indicators is non-empty
        - Reentrancy: only if external_calls is non-empty AND state modified after the call
        - Delegatecall: only if delegatecall: YES
        - Selfdestruct: only if selfdestruct: YES
        - tx.origin: only if tx_origin: YES
        - If unsure, call grep_codebase(pattern) to verify before claiming

        OUTPUT FORMAT per finding:
        ### [SEVERITY] Title
        **Location:** `functionName()` line ~N
        **Description:** cite exact identifiers from the code
        **Attack:** numbered steps — concrete exploit scenario
        **Impact:** what the attacker gains
        **Recommendation:** minimal code fix

        If no issues found: write exactly `No vulnerabilities found.`

        {rag_context}
        """),

    "focused": textwrap.dedent("""\
        You are DeepAudit performing a FOCUSED CHECK on a specific vulnerability class.

        {prior_context}

        WORKFLOW:
        1. Call extract_code_elements(code) to confirm the relevant indicator exists
        2. Search the knowledge base for detection signals for this class
        3. Read every relevant function — document each instance (safe OR unsafe)

        OUTPUT FORMAT:
        ### [SEVERITY] Title — [VulnClass]
        **Location:** file:line
        **Safe or Vulnerable:** state clearly
        **Why:** specific identifiers, line references
        **Attack path:** step-by-step if vulnerable, "N/A" if safe
        **Fix:** minimal code change if vulnerable

        {rag_context}
        """),

    "interactions": textwrap.dedent("""\
        You are DeepAudit analyzing CROSS-CONTRACT INTERACTIONS.
        Only report bugs visible across contract boundaries.

        {prior_context}

        WORKFLOW:
        1. Call extract_code_elements on each contract
        2. Map the call graph and trust relationships
        3. Check each class below

        CHECKS:
        - Cross-contract reentrancy: state updates after external calls to other contracts
        - Trust assumption violations: unvalidated return values from external contracts
        - Price/state manipulation: shared readable state across contracts
        - Access control gaps: privileged function reachable via a secondary contract
        - Initialization order: contracts requiring each other to exist first
        - Inconsistent accounting: same balance tracked differently across contracts

        OUTPUT FORMAT:
        ### [SEVERITY] Title — Cross-Contract
        **Contracts involved:** ContractA.sol × ContractB.sol
        **Interaction:** which function calls which
        **Why vulnerable:** specific assumption that breaks
        **Attack path:** step-by-step exploit using both contracts
        **Recommendation:** which contract changes and how

        {rag_context}
        """),

    "report": textwrap.dedent("""\
        You are DeepAudit writing the FINAL AUDIT REPORT.
        Consolidate all prior phase findings. Do NOT re-analyse. Order by severity.

        {prior_context}

        OUTPUT FORMAT:
        # Audit Report — [Protocol Name]
        **Date:** {date} | **Auditor:** DeepAudit (deepseek-r1:14b) | **Severity:** Critical > High > Medium > Low

        ## Executive Summary
        (2-3 sentences: what the protocol does, overall security posture, most critical finding)

        ## Findings
        ### [C-01] Title — CRITICAL
        | Field | Value |
        |---|---|
        | Severity | CRITICAL |
        | File | filename:line |
        | Status | Open |
        **Description:** ...
        **Impact:** ...
        **Recommendation:** ...

        ## Summary Table
        | ID | Title | Severity | Status |
        |---|---|---|---|

        ## Scope and Limitations
        (what was NOT examined and why)

        Save the report with write_file to reports/.

        {rag_context}
        """),
}
PHASE_PROMPTS["default"] = PHASE_PROMPTS[DEFAULT_PHASE]


def _build_phase_system(phase: str, rag_context: str = "") -> str:
    """Resolve placeholders in the phase prompt."""
    template = PHASE_PROMPTS.get(phase, PHASE_PROMPTS[DEFAULT_PHASE])

    # Inject prior phase context (recon/threats output fed into hunt)
    prior_parts = []
    if phase == "hunt" and "recon" in _phase_carry:
        prior_parts.append(f"## Prior Recon Output\n{_phase_carry['recon']}")
    if phase == "hunt" and "threats" in _phase_carry:
        prior_parts.append(f"## Prior Threat Model\n{_phase_carry['threats']}")
    if phase == "report":
        for p, out in _phase_carry.items():
            prior_parts.append(f"## Prior {p.title()} Output\n{out}")
    prior_block = "\n\n".join(prior_parts)

    rag_block = rag_context if (rag_context and "not built" not in rag_context) else ""

    # Inject project guidelines (audit.config.md) into system prompt
    guidelines_block = (
        f"\n\n## Project Guidelines (audit.config.md)\n{_project_guidelines}"
        if _project_guidelines else ""
    )

    result = template.replace("{prior_context}", f"PRIOR PHASE CONTEXT:\n{prior_block}" if prior_block else "")
    result = result.replace("{rag_context}", f"\nRAG CONTEXT:\n{rag_block}" if rag_block else "")
    result = result.replace("{date}", datetime.now().strftime("%Y-%m-%d"))
    result += guidelines_block
    return result


def _build_messages(phase: str, rag_context: str = "") -> list[dict]:
    """
    Build the initial message list for a session.
    If a bounty brief is loaded, inject it as a priming user/assistant exchange
    BEFORE any code is seen — this makes deepseek explicitly commit to the scope
    and vulnerability classes, which dramatically reduces out-of-scope findings.
    """
    system = _build_phase_system(phase, rag_context)
    messages: list[dict] = [{"role": "system", "content": system}]

    if _bounty_brief:
        messages.append({
            "role": "user",
            "content": (
                "Before we start the audit, here is the program brief. "
                "It defines the scope, vulnerability classes in scope, severity scale, "
                "and any special rules. Apply this throughout every finding:\n\n"
                f"---\n{_bounty_brief}\n---\n\n"
                "Confirm you've read it and list: (1) which vulnerability classes are IN scope, "
                "(2) which files/contracts are in scope, (3) the minimum severity to report."
            ),
        })
        messages.append({
            "role": "assistant",
            "content": _extract_bounty_summary(_bounty_brief),
        })

    return messages


def _extract_bounty_summary(brief: str) -> str:
    """
    Generate a concise acknowledgement of the bounty brief.
    Parsed deterministically — no LLM call — to avoid a slow round-trip just for the ack.
    """
    lines = brief.strip().splitlines()
    # Try to pull out scope/severity/focus lines heuristically
    scope_lines = [l.strip() for l in lines if any(k in l.lower() for k in ("in scope", "scope:", "contracts:", "files:"))]
    severity_lines = [l.strip() for l in lines if any(k in l.lower() for k in ("severity", "critical", "high", "minimum", "reward"))]
    focus_lines = [l.strip() for l in lines if any(k in l.lower() for k in ("focus", "vuln", "vulnerability class", "out of scope"))]

    parts = ["Understood. I've read the program brief and will apply it throughout the audit.\n"]
    if scope_lines:
        parts.append("**In-scope contracts:** " + " | ".join(scope_lines[:3]))
    if severity_lines:
        parts.append("**Severity / rewards:** " + " | ".join(severity_lines[:2]))
    if focus_lines:
        parts.append("**Focus areas / exclusions:** " + " | ".join(focus_lines[:3]))
    parts.append("\nI will only report findings that match the scope and meet the minimum severity. Out-of-scope items will be omitted.")
    return "\n".join(parts)


# ── bounty config loading ─────────────────────────────────────────────────────
def _load_brief(source: str) -> None:
    """Load bounty brief from a file path or accept raw text. Sets _bounty_brief."""
    global _bounty_brief
    p = Path(source).expanduser()
    if p.exists():
        _bounty_brief = p.read_text(errors="ignore").strip()
        _print_info(f"[+] Bounty brief loaded from {p} ({len(_bounty_brief)} chars)")
    else:
        _bounty_brief = source.strip()
        _print_info(f"[+] Bounty brief set from inline text ({len(_bounty_brief)} chars)")


def _load_project_guidelines(target_path: str) -> None:
    """Auto-load audit.config.md from the target directory."""
    global _project_guidelines
    target = Path(target_path).expanduser().resolve()
    config_dir = target if target.is_dir() else target.parent
    config_file = config_dir / "audit.config.md"
    if config_file.exists():
        _project_guidelines = config_file.read_text(errors="ignore").strip()
        _print_info(f"[+] Project guidelines loaded from {config_file}")
    else:
        _project_guidelines = ""


_BOUNTY_TEMPLATE = """\
# Bounty / Audit Program Brief

## Program
- **Platform:** Immunefi / Code4rena / Sherlock / private  ← fill in
- **Project name:**
- **Audit date:**

## Scope — In Scope Contracts
<!-- List every file or contract that is IN scope. Deepseek will only report findings here. -->
- `contracts/Vault.sol`
- `contracts/Strategy.sol`

## Out of Scope
<!-- Files, libraries, or issue classes explicitly excluded. -->
- `contracts/mocks/`
- `node_modules/`
- Issues requiring governance compromise as precondition

## Vulnerability Classes in Scope
<!-- List the vuln classes this program rewards. Deepseek skips everything else. -->
- Reentrancy
- Access control
- Integer overflow / underflow
- Oracle manipulation
- Flash loan attacks
- Logic errors leading to fund loss
- Signature replay

## Minimum Severity to Report
<!-- Findings below this severity will be omitted. -->
Medium

## Severity Scale
<!-- Use the program's own scale so findings map correctly to rewards. -->
| Severity | Criteria |
|---|---|
| Critical | Direct fund loss, no preconditions |
| High | Fund loss with low-complexity preconditions |
| Medium | Temporary fund lock, griefing, or loss < 1% TVL |
| Low | Best-practice issues, no direct fund impact |

## Special Rules
<!-- Program-specific rules, e.g. minimum attacker profit, DoS requirements. -->
- DoS findings only valid if lockup > 24 hours
- Economic exploits must have realistic profit > $10,000
- Centralization risk is out of scope unless it results in direct fund loss

## Known Issues (Do Not Report)
<!-- Issues already acknowledged by the team. -->
- Owner can pause the contract (intended)
"""


def _scaffold_bounty_config(output_path: str = "audit.config.md") -> None:
    """Write a bounty.config.md template to the given path."""
    p = Path(output_path)
    if p.exists():
        _print_info(f"[!] {p} already exists — not overwriting. Delete it first.")
        return
    p.write_text(_BOUNTY_TEMPLATE)
    _print_info(f"[+] Bounty config template written to {p}")
    _print_info(f"    Edit it, then run: python agent.py --brief {p} --file <contract>")


# ── dependency check ──────────────────────────────────────────────────────────


# ── dependency check ──────────────────────────────────────────────────────────
def _check_deps(use_api: bool):
    missing = []
    if use_api:
        try:
            import mistralai
        except ImportError:
            missing.append("mistralai")
    else:
        try:
            import ollama
        except ImportError:
            missing.append("ollama")
    for pkg in ("chromadb", "sentence_transformers"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg if pkg != "sentence_transformers" else "sentence-transformers")
    if missing:
        print(f"[error] Missing packages: pip install {' '.join(missing)}")
        sys.exit(1)


# ── system prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = textwrap.dedent("""\
You are DeepAudit, an expert smart contract security auditor powered by DeepSeek-R1.

╔══════════════════════════════════════════════════════════════════╗
║  MANDATORY AUDIT WORKFLOW — EXECUTE EVERY STEP IN ORDER         ║
╚══════════════════════════════════════════════════════════════════╝

STEP 0 — EXTRACT CODE FACTS (ALWAYS FIRST, NO EXCEPTIONS):
  Call extract_code_elements(code) on the full contract source.
  This produces the ONLY facts you are allowed to reason from.
  Every vulnerability claim MUST be traceable to something in that output.

STEP 1 — SEARCH KNOWLEDGE BASE (using actual code identifiers, not guesses):
  Call search_knowledge() using patterns you CONFIRMED in STEP 0.
  Example: search for "balance mapping withdrawal .call" not "reentrancy".
  Do NOT search for vulnerability names you have not yet confirmed exist.

STEP 2 — STATIC ANALYSIS:
  Solidity → run_slither(code)
  Sui Move  → run_sui_analyzer(code)

STEP 3 — REASON AND WRITE FINDINGS:
  Ground every finding in the STEP 0 output. Then write the report.

╔══════════════════════════════════════════════════════════════════╗
║  ANTI-HALLUCINATION RULES — THESE ARE HARD CONSTRAINTS          ║
╚══════════════════════════════════════════════════════════════════╝

ORACLE MANIPULATION:
  Only report if extract_code_elements shows oracle_indicators is non-empty.
  Required: AggregatorV3Interface, IOracle, getPrice, latestAnswer, latestRoundData,
  twap, consult, or similar price feed interface. If none found → no oracle finding.

FLASH LOAN:
  Only report if extract_code_elements shows flash_loan_indicators is non-empty.
  Required: flashLoan, executeOperation, onFlashLoan, IERC3156. If none → no flash loan finding.

REENTRANCY:
  Only report if there is an external call (.call, .transfer, .send, ERC777) AND
  state is modified in the same function. Check reentrancy_guards — if nonReentrant
  is present, reentrancy is likely mitigated (note it, don't flag as critical).

SIGNATURE REPLAY:
  Only report if ecrecover, ECDSA.recover, or keccak256+signature pattern is present.

DELEGATECALL / PROXY COLLISION:
  Only report if delegatecall: YES in STEP 0 output.

SELFDESTRUCT:
  Only report if selfdestruct: YES in STEP 0 output.

TX.ORIGIN:
  Only report if tx_origin: YES in STEP 0 output.

GENERAL RULE:
  If you cannot find the exact function name or variable in the extract output,
  use grep_codebase(pattern) to verify it exists before claiming it.
  NEVER invent identifiers. If you are not certain something is in the code, say so.

╔══════════════════════════════════════════════════════════════════╗
║  TOOLS                                                           ║
╚══════════════════════════════════════════════════════════════════╝
  extract_code_elements(code)    CALL THIS FIRST. Returns exact code facts.
  search_knowledge(query)        Semantic search over 1728 audit findings + docs.
  read_file(path)                Read any local file.
  write_file(path, content)      Save audit reports.
  list_directory(path)           Discover contract files in a directory.
  run_slither(code)              Slither static analysis (Solidity).
  run_sui_analyzer(code)         Move vulnerability pattern scan.
  grep_codebase(pattern, path)   Verify a pattern exists before claiming it.

╔══════════════════════════════════════════════════════════════════╗
║  REPORT FORMAT                                                   ║
╚══════════════════════════════════════════════════════════════════╝
# Security Audit Report — [ContractName]
**Date:** [date]  **Auditor:** DeepAudit  **Severity:** Critical > High > Medium > Low

## Executive Summary
[1-2 sentences. State what the contract does and the overall risk level.]

## Findings

### [H-01] [Vulnerability Title] — [Severity]
**Location:** `FunctionName()` line ~XX
**Description:** [Cite exact identifiers from the code. No invented names.]
**Attack Scenario:** [Concrete step-by-step. Who does what, in what order.]
**Impact:** [What the attacker gains or what breaks.]
**Proof of Concept:**
\`\`\`solidity
// exploit code
\`\`\`
**Recommendation:**
\`\`\`solidity
// fixed code
\`\`\`

## Summary Table
| ID | Title | Severity | Status |
|---|---|---|---|

CONTRACT GENERATION:
  Write complete, compilable Solidity/Move code. Use OpenZeppelin for Solidity.
  Apply CEI pattern, access control, overflow checks. Save with write_file.\
""")


# ── RAG ───────────────────────────────────────────────────────────────────────
_embedder = None

def _get_embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedder


def _rag_search(query: str, k: int = RAG_K) -> str:
    if not INDEX_DIR.exists():
        return "RAG index not built. Run: python rag/build_index.py"
    try:
        import chromadb
        client = chromadb.PersistentClient(path=str(INDEX_DIR))
        embedder = _get_embedder()
        qemb = embedder.encode([query]).tolist()

        results = []
        for col_name in ("dataset_findings", "knowledge_docs"):
            try:
                col = client.get_collection(col_name)
                if col.count() == 0:
                    continue
                n = min(k, col.count())
                res = col.query(query_embeddings=qemb, n_results=n)
                for doc, meta, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0]):
                    results.append({"text": doc, "meta": meta, "score": round(1 - dist, 3)})
            except Exception:
                pass

        results.sort(key=lambda x: x["score"], reverse=True)
        results = [r for r in results if r["score"] >= RELEVANCE_THRESHOLD]
        results = results[:k]

        if not results:
            return "No relevant results found above relevance threshold. Do not invent vulnerabilities — only report what the code itself shows."

        parts = []
        for i, r in enumerate(results):
            src = r["meta"].get("file", r["meta"].get("vuln_type", "audit-finding"))
            parts.append(f"[{i+1}] {src} (relevance: {r['score']})\n{r['text'][:600]}")
        return "\n\n---\n".join(parts)
    except Exception as e:
        return f"RAG search error: {e}"


# ── tools ─────────────────────────────────────────────────────────────────────
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "search_knowledge",
            "description": "Search the audit knowledge base (1728 real findings + docs) for similar vulnerabilities or patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Vulnerability type, pattern, or code feature to search for"}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read source code or text from a local file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path (absolute or relative to working directory)"}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file (creates or overwrites). Use for saving audit reports and generated contracts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to write to"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List files in a directory. Useful to discover contracts before auditing a project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path (default: current directory)"},
                    "pattern": {"type": "string", "description": "Glob pattern, e.g. '**/*.sol' (optional)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_slither",
            "description": "Run Slither static analysis on Solidity source code. Returns detected vulnerabilities with impact levels.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Solidity source code to analyze"},
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sui_analyzer",
            "description": "Run basic static analysis on Sui Move code to detect common vulnerability patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Sui Move source code to analyze"},
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_codebase",
            "description": "Search for a regex pattern across all .sol and .move files in a directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex pattern to search for"},
                    "path": {"type": "string", "description": "Directory to search (default: current dir)"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_code_elements",
            "description": (
                "CALL THIS FIRST on every audit. Deterministically extracts all functions, "
                "state variables, imports, external calls, and vulnerability-specific indicators "
                "from Solidity or Move source code — no LLM involved, 100% accurate. "
                "Use the output to ground every claim you make. Never report a vulnerability "
                "type whose indicator is absent from this output."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Full Solidity or Sui Move source code to analyse"},
                },
                "required": ["code"],
            },
        },
    },
]


def _tool_search_knowledge(args: dict) -> str:
    return _rag_search(args.get("query", ""), k=RAG_K)


def _tool_read_file(args: dict) -> str:
    p = Path(args.get("path", ""))
    if not p.exists():
        return f"File not found: {p}"
    if p.stat().st_size > 300_000:
        return f"File too large. Reading first 300KB.\n" + p.read_text(errors="ignore")[:300_000]
    return p.read_text(errors="ignore")


def _tool_write_file(args: dict) -> str:
    path = Path(args.get("path", ""))
    content = args.get("content", "")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return f"Written {len(content)} chars to {path}"


def _tool_list_directory(args: dict) -> str:
    path = Path(args.get("path", "."))
    pattern = args.get("pattern", "**/*")
    if not path.exists():
        return f"Directory not found: {path}"
    try:
        files = sorted(path.glob(pattern))[:100]
        lines = [str(f.relative_to(path)) + (" [dir]" if f.is_dir() else f" ({f.stat().st_size}B)") for f in files]
        return "\n".join(lines) or "Empty directory."
    except Exception as e:
        return f"Error: {e}"


def _tool_run_slither(args: dict) -> str:
    code = args.get("code", "")
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name
    try:
        r = subprocess.run(
            ["slither", tmp_path, "--json", "-"],
            capture_output=True, text=True, timeout=60,
        )
        try:
            data = json.loads(r.stdout)
            detectors = data.get("results", {}).get("detectors", [])
            if not detectors:
                return "Slither: no issues detected."
            lines = [f"[{d.get('impact','?')}] {d.get('check','?')}: {d.get('description','')[:200]}"
                     for d in detectors[:15]]
            return "\n".join(lines)
        except json.JSONDecodeError:
            out = (r.stdout + r.stderr)[:1000]
            return out or "Slither ran but produced no output."
    except FileNotFoundError:
        return "Slither not installed. pip install slither-analyzer  (requires solc)"
    except subprocess.TimeoutExpired:
        return "Slither timed out (>60s)."
    finally:
        os.unlink(tmp_path)


def _tool_run_sui_analyzer(args: dict) -> str:
    code = args.get("code", "")
    findings = []

    checks = [
        (r"public\s+fun\s+\w+\s*\([^)]*\)\s*\{", "public function without capability parameter — verify access control"),
        (r"transfer::share_object", "shared object — check for transaction ordering / race conditions"),
        (r"clock::timestamp_ms|ctx\.epoch\(\)", "time-dependent logic — verify manipulation resistance"),
        (r"dynamic_field::(add|borrow_mut)", "dynamic field usage — verify key uniqueness and type safety"),
        (r"abort\s+\d+|assert!\s*\(\s*false", "unconditional abort/assert — review control flow"),
        (r"balance::split|coin::split", "coin split — verify amount bounds and overflow"),
        (r"object::delete", "object deletion — verify no dangling references"),
        (r"tx_context::sender", "sender-based auth — check for spoofing risk"),
    ]

    import re
    for pattern, msg in checks:
        matches = re.findall(pattern, code)
        if matches:
            findings.append(f"[INFO] {msg} (found {len(matches)}x)")

    if not findings:
        return "Sui analyzer: no pattern-based issues detected. Manual review recommended."
    return "\n".join(findings)


def _tool_grep_codebase(args: dict) -> str:
    pattern = args.get("pattern", "")
    path = args.get("path", ".")
    try:
        r = subprocess.run(
            ["grep", "-rn", "--include=*.sol", "--include=*.move", "-E", pattern, path],
            capture_output=True, text=True, timeout=15,
        )
        lines = r.stdout.strip().splitlines()[:40]
        if not lines:
            return f"No matches for: {pattern}"
        result = "\n".join(lines)
        if len(r.stdout.splitlines()) > 40:
            result += f"\n... ({len(r.stdout.splitlines())-40} more matches)"
        return result
    except Exception as e:
        return f"grep error: {e}"


def _tool_extract_code_elements(args: dict) -> str:
    """
    Pure-regex extraction of code facts. No LLM. 100% grounded.
    Handles both Solidity and Sui Move.
    """
    code = args.get("code", "")
    if not code.strip():
        return "No code provided."

    is_move = bool(re.search(r'\bmodule\b', code) and re.search(r'\bfun\b', code))

    facts: dict = {}

    if is_move:
        facts["language"] = "Sui Move"
        facts["functions"] = re.findall(r'(?:public\s+(?:entry\s+)?)?fun\s+(\w+)', code) or ["(none)"]
        facts["structs"] = re.findall(r'struct\s+(\w+)', code) or ["(none)"]
        facts["imports"] = re.findall(r'use\s+([\w:]+)', code) or ["(none)"]
        facts["transfer_calls"] = re.findall(r'transfer::\w+|coin::\w+|balance::\w+', code) or ["(none)"]
        facts["shared_object"] = "YES" if re.search(r'transfer::share_object', code) else "NO"
        facts["time_dependent"] = "YES" if re.search(r'clock::timestamp_ms|ctx\.epoch', code) else "NO"
        facts["dynamic_fields"] = "YES" if re.search(r'dynamic_field::', code) else "NO"
        facts["tx_context_sender"] = "YES" if re.search(r'tx_context::sender', code) else "NO"
        raw_calls = re.findall(r'(\w+)::(\w+)\s*\(', code)
        facts["cross_module_calls"] = [f"{a}::{b}" for a, b in raw_calls[:20]] or ["(none)"]
    else:
        facts["language"] = "Solidity"
        facts["functions"] = re.findall(r'function\s+(\w+)', code) or ["(none)"]
        facts["modifiers_defined"] = re.findall(r'modifier\s+(\w+)', code) or ["(none)"]
        facts["events"] = re.findall(r'event\s+(\w+)', code) or ["(none)"]
        facts["errors"] = re.findall(r'error\s+(\w+)', code) or ["(none)"]
        facts["imports"] = re.findall(r'import\s+["\']([^"\']+)["\']', code) or ["(none)"]
        facts["state_variables"] = (
            re.findall(
                r'^\s*(?:address|uint\d*|int\d*|bool|bytes\d*|string|mapping)\s+'
                r'(?:(?:public|private|internal|constant|immutable)\s+)*(\w+)\s*[;=]',
                code, re.MULTILINE,
            ) or ["(none)"]
        )

        # External call patterns — the most critical for reentrancy
        ext_calls = re.findall(r'\.call\s*[\({]|\.transfer\s*\(|\.send\s*\(', code)
        facts["external_calls"] = ext_calls if ext_calls else ["(none)"]

        # Per-vulnerability indicators — if empty, DO NOT report that vuln class
        oracle = re.findall(
            r'AggregatorV3Interface|AggregatorV3|IChainlinkAggregator|IOracle|'
            r'getPrice\b|latestAnswer\b|latestRoundData\b|TWAP|twap\b|consult\b|observe\b|'
            r'IPriceFeed|PriceOracle|UniswapV2OracleSimple', code)
        facts["oracle_indicators"] = oracle if oracle else ["(none — do not report oracle manipulation)"]

        flash = re.findall(
            r'flashLoan\b|FlashLoan\b|executeOperation\b|onFlashLoan\b|'
            r'IERC3156FlashLender|IERC3156FlashBorrower|IFlashLoanReceiver', code)
        facts["flash_loan_indicators"] = flash if flash else ["(none — do not report flash loan)"]

        reentrant_guards = re.findall(r'nonReentrant\b|ReentrancyGuard\b|_locked\b|_status\b', code)
        facts["reentrancy_guards"] = reentrant_guards if reentrant_guards else ["(none)"]

        sig_patterns = re.findall(r'ecrecover\b|ECDSA\.recover\b|SignatureChecker', code)
        facts["signature_patterns"] = sig_patterns if sig_patterns else ["(none — do not report signature replay)"]

        facts["delegatecall"] = "YES" if re.search(r'\.delegatecall\s*\(', code) else "NO"
        facts["selfdestruct"] = "YES" if re.search(r'selfdestruct\s*\(|suicide\s*\(', code) else "NO"
        facts["tx_origin"] = "YES" if re.search(r'tx\.origin', code) else "NO"
        facts["assembly_blocks"] = len(re.findall(r'\bassembly\s*\{', code))
        facts["unchecked_blocks"] = len(re.findall(r'\bunchecked\s*\{', code))
        facts["access_control_patterns"] = (
            re.findall(r'onlyOwner\b|onlyRole\b|Ownable\b|AccessControl\b|'
                       r'require\s*\(\s*msg\.sender\s*==', code) or ["(none)"]
        )

    lines = ["=== CODE ELEMENT EXTRACTION (ground ALL claims in these facts) ===", ""]
    for key, val in facts.items():
        if isinstance(val, list):
            lines.append(f"  {key}: {', '.join(str(v) for v in val[:25])}")
        else:
            lines.append(f"  {key}: {val}")

    lines += [
        "",
        "⚠  HARD RULE: Only report a vulnerability if its required indicator appears above.",
        "⚠  If an indicator column says '(none — do not report X)', you MUST NOT report X.",
        "⚠  If unsure whether a pattern exists, call grep_codebase() to verify first.",
    ]
    return "\n".join(lines)


TOOL_DISPATCH = {
    "search_knowledge": _tool_search_knowledge,
    "read_file": _tool_read_file,
    "write_file": _tool_write_file,
    "list_directory": _tool_list_directory,
    "run_slither": _tool_run_slither,
    "run_sui_analyzer": _tool_run_sui_analyzer,
    "grep_codebase": _tool_grep_codebase,
    "extract_code_elements": _tool_extract_code_elements,
}


def dispatch_tool(name: str, args: dict) -> str:
    fn = TOOL_DISPATCH.get(name)
    if not fn:
        return f"Unknown tool: {name}"
    try:
        return fn(args)
    except Exception as e:
        return f"Tool error ({name}): {e}"


# ── deepseek-r1 thinking token handling ──────────────────────────────────────
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
_think_log: list[str] = []  # accumulated thinking blocks for this session


def _strip_think(text: str) -> tuple[str, str]:
    """
    Remove <think>...</think> blocks from deepseek-r1 output.
    Returns (clean_text, thinking_content).
    The thinking content is saved separately — it's deepseek's reasoning chain,
    not part of the final report.
    """
    thinking_blocks = _THINK_RE.findall(text)
    thinking = "\n\n".join(thinking_blocks)
    clean = _THINK_RE.sub("", text).strip()
    if thinking:
        _think_log.append(thinking)
    return clean, thinking


def _save_think_log(label: str) -> None:
    """Save accumulated thinking blocks to a .think file next to the report."""
    if not _think_log:
        return
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", label)[:40]
    out = REPORTS_DIR / f"audit_{safe}_{ts}.think"
    out.write_text("\n\n---\n\n".join(_think_log))
    _print_info(f"[+] DeepSeek reasoning chain saved → {out}")
    _think_log.clear()


# ── ReAct text-mode fallback (for models that don't support the tools API) ───
_ACT_RE   = re.compile(r"Action:\s*(\w+)", re.I)
_ARG_RE   = re.compile(r"Action Input:\s*(\{.*?\})", re.DOTALL | re.I)
_FINAL_RE = re.compile(r"Final Answer:\s*(.*)", re.DOTALL | re.I)

# Appended to the system prompt when native tools aren't available.
_REACT_INSTR = (
    "\n\n════════════════════════════════════════\n"
    " TOOL USE INSTRUCTIONS (read carefully)\n"
    "════════════════════════════════════════\n"
    "To call a tool output EXACTLY these two lines — nothing else on those lines:\n"
    "  Action: <tool_name>\n"
    "  Action Input: {\"key\": \"value\"}\n\n"
    "After you see 'Observation: ...', continue reasoning.\n"
    "When finished, output EXACTLY:\n"
    "  Final Answer: <your complete response>\n\n"
    "Available tools:\n"
    "  extract_code_elements   — CALL THIS FIRST on every audit\n"
    "  search_knowledge        — semantic search over audit findings\n"
    "  read_file               — read a local file\n"
    "  write_file              — save a report\n"
    "  list_directory          — list files in a directory\n"
    "  run_slither             — Slither static analysis (Solidity)\n"
    "  run_sui_analyzer        — Move vulnerability scan\n"
    "  grep_codebase           — regex search across .sol/.move files\n"
    "════════════════════════════════════════"
)

# Markers that indicate the model is hallucinating or looping — abort the turn
_GARBAGE_MARKERS = [
    "as an ai language model", "i am an ai", "i'm an ai",
    "your task is to", "based on typical vulnerabilities",
    "based on my knowledge", "in a typical contract",
    "commonly found in contracts", "i can create an example",
    "example input", "example question", "example answer",
    "<|assistant|>", "<|user|>", "<|system|>",
    "### instruction", "### response",
]

def _looks_garbage(text: str) -> bool:
    """Detect hallucinated / looping output so we can abort early."""
    if not text:
        return False
    low = text.lower()
    if any(m in low for m in _GARBAGE_MARKERS):
        return True
    # Repeated identical lines → model is looping
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) >= 8 and len(set(lines[-6:])) <= 2:
        return True
    # Long response with zero contract-related terms → totally off-topic
    if len(text) > 400:
        contract_terms = ("function", "contract", "solidity", "move", "finding",
                          "severity", "vulnerability", "access", "overflow",
                          "reentr", "transfer", "oracle", "price", "emit", "revert")
        if not any(t in low for t in contract_terms):
            return True
    return False


def _parse_react(text: str) -> tuple[str | None, dict, str | None]:
    """
    Parse a ReAct-format response.
    Returns (tool_name, tool_args, final_answer).
    Exactly one of tool_name or final_answer will be set.
    """
    if m := _FINAL_RE.search(text):
        return None, {}, m.group(1).strip()
    if a := _ACT_RE.search(text):
        name = a.group(1)
        args: dict = {}
        if inp := _ARG_RE.search(text):
            try:
                args = json.loads(inp.group(1))
            except Exception:
                pass
        return name, args, None
    return None, {}, text.strip()


# ── inference backends ────────────────────────────────────────────────────────
_OLLAMA_OPTIONS = {
    "temperature": 0.1,
    "num_predict": 8192,   # deepseek needs budget for thinking + output
    "num_ctx": 32768,      # real context window — ollama default is 2048, far too small
}


def _chat_ollama(model: str, messages: list[dict], stream: bool = False) -> tuple[str, list]:
    """
    Returns (content, tool_calls). Strips deepseek-r1 thinking tokens.
    Auto-detects if the model doesn't support the tools API and falls back
    to ReAct text-mode (Action: / Action Input: / Final Answer:).
    """
    global _tools_supported
    import ollama

    call_kw: dict = {"model": model, "messages": messages, "options": _OLLAMA_OPTIONS}

    # Only attach tools if we haven't confirmed they're unsupported
    if _tools_supported is not False:
        call_kw["tools"] = TOOL_DEFINITIONS

    # ── streaming path (final-answer rounds only, ReAct mode) ─────────────────
    if stream and _tools_supported is False:
        full_text = ""
        in_think = False
        print("\n", end="", flush=True)
        for chunk in ollama.chat(**call_kw, stream=True):
            token = chunk.message.content or ""
            full_text += token
            for char in token:
                if not in_think:
                    print(char, end="", flush=True)
                if "<think>" in full_text[-10:]:
                    in_think = True
                if "</think>" in full_text[-12:]:
                    in_think = False
                    print()
        print()
        content, _ = _strip_think(full_text)
        _, _, final = _parse_react(content)
        return final or content, []

    # ── non-streaming path ────────────────────────────────────────────────────
    try:
        resp = ollama.chat(**call_kw)
        if _tools_supported is None:
            _tools_supported = True

    except ollama.ResponseError as e:
        if "does not support tools" in str(e):
            _tools_supported = False
            _print_info("[!] Model doesn't support tools API — switching to ReAct text mode.")
            call_kw.pop("tools", None)
            # Inject ReAct instructions once into the system message
            if messages and messages[0]["role"] == "system":
                if "Action Input:" not in messages[0]["content"]:
                    messages[0]["content"] += _REACT_INSTR
            try:
                resp = ollama.chat(**call_kw)
            except Exception as e2:
                return f"[ollama error] {e2}", []
        else:
            return f"[ollama error] {e}\nIs ollama running? (ollama serve)", []
    except Exception as e:
        return f"[ollama error] {e}\nIs ollama running? (ollama serve)", []

    msg = resp.message
    raw_content = msg.content or ""
    content, _ = _strip_think(raw_content)

    # ── native tools API path ─────────────────────────────────────────────────
    if _tools_supported:
        tool_calls = []
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                tool_calls.append({"name": tc.function.name, "args": tc.function.arguments or {}})
        return content, tool_calls

    # ── ReAct text parsing path ───────────────────────────────────────────────
    if _looks_garbage(content):
        _print_info("[!] Garbage output detected — skipping this round.")
        return "No analysis available — model output was off-topic.", []

    tool_name, tool_args, final = _parse_react(content)
    if tool_name:
        # Signal to chat_turn that this is a ReAct-style call
        return content, [{"name": tool_name, "args": tool_args, "_react": True}]

    return final or content, []


def _chat_api(client, model: str, messages: list[dict]) -> tuple[str, list]:
    """Returns (content, tool_calls)."""
    resp = client.chat.complete(
        model=model,
        messages=messages,
        tools=TOOL_DEFINITIONS,
        temperature=0.1,
        max_tokens=3000,
    )
    choice = resp.choices[0]
    msg = choice.message
    tool_calls = []
    if hasattr(msg, "tool_calls") and msg.tool_calls:
        for tc in msg.tool_calls:
            fn = tc.function
            try:
                args = json.loads(fn.arguments) if isinstance(fn.arguments, str) else fn.arguments
            except Exception:
                args = {}
            tool_calls.append({"id": tc.id, "name": fn.name, "args": args})
    return msg.content or "", tool_calls


# ── main chat loop ────────────────────────────────────────────────────────────
def chat_turn(
    messages: list[dict],
    model: str,
    use_api: bool,
    api_client=None,
    verbose: bool = True,
    stream: bool = False,
) -> str:
    """
    Run one user turn through the tool loop. Mutates messages in place.
    Handles both native tools API and ReAct text-mode fallback transparently.
    """
    for round_i in range(MAX_TOOL_ROUNDS):
        # In ReAct mode stream the FINAL round only; tool rounds must not stream
        # so we can parse Action:/Final Answer: cleanly.
        # In native-tools mode: stream after the first tool round.
        in_react = _tools_supported is False
        is_final_candidate = round_i > 0
        do_stream = stream and not use_api and (
            (in_react and is_final_candidate) or
            (not in_react and is_final_candidate)
        )

        if use_api:
            content, tool_calls = _chat_api(api_client, model, messages)
        else:
            content, tool_calls = _chat_ollama(model, messages, stream=do_stream)

        if not tool_calls:
            messages.append({"role": "assistant", "content": content})
            return content

        is_react_call = bool(tool_calls and tool_calls[0].get("_react"))

        if is_react_call:
            # ── ReAct text-mode: use user/Observation messages ────────────────
            for tc in tool_calls:
                name = tc["name"]
                args = {k: v for k, v in tc["args"].items()}  # drop _react key
                if verbose:
                    args_str = ", ".join(f"{k}={repr(v)[:50]}" for k, v in args.items())
                    print(f"  [react] {name}({args_str})", flush=True)
                result = dispatch_tool(name, args)
                if verbose:
                    print(f"  → {result[:200]}{'...' if len(result) > 200 else ''}", flush=True)
                # Append the model's action text, then the tool result as Observation
                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": f"Observation: {result[:2000]}\nContinue your analysis.",
                })
        else:
            # ── Native tools API ──────────────────────────────────────────────
            messages.append({"role": "assistant", "content": content or "", "tool_calls": tool_calls})
            for tc in tool_calls:
                name = tc["name"]
                args = tc["args"]
                if verbose:
                    args_str = ", ".join(f"{k}={repr(v)[:50]}" for k, v in args.items())
                    print(f"  [tool] {name}({args_str})", flush=True)
                result = dispatch_tool(name, args)
                if verbose:
                    print(f"  → {result[:200]}{'...' if len(result) > 200 else ''}", flush=True)
                tool_msg = {"role": "tool", "content": result, "name": name}
                if "id" in tc:
                    tool_msg["tool_call_id"] = tc["id"]
                messages.append(tool_msg)

    return content or "[max tool rounds reached]"


# ── output formatting ─────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    _console = Console()
    def _print_response(text: str, title: str = "Response"):
        _console.print(Panel(Markdown(text), title=f"[bold green]{title}[/bold green]", border_style="green"))
    def _print_info(msg: str):
        _console.print(f"[cyan]{msg}[/cyan]")
except ImportError:
    def _print_response(text: str, title: str = "Response"):
        print(f"\n{'─'*60}\n{text}\n{'─'*60}")
    def _print_info(msg: str):
        print(msg)


# ── post-processing hallucination filter ─────────────────────────────────────
# Maps keyword patterns found in finding titles → code patterns that MUST be present.
# If the code pattern is absent, the finding is flagged UNVERIFIED.
_HALLUCINATION_GUARD: list[tuple[str, str]] = [
    (r"oracle|price.?feed|price.?manipulat",
     r"AggregatorV3|IOracle|IChainlink|getPrice|latestAnswer|latestRoundData|twap|TWAP|consult\(|observe\(|IPriceFeed"),
    (r"flash.?loan",
     r"flashLoan|FlashLoan|executeOperation|onFlashLoan|IERC3156"),
    (r"re.?entr",
     r"\.call\s*[\({]|\.transfer\s*\(|\.send\s*\(|ERC777|tokensReceived"),
    (r"signature.?replay|sig.?replay",
     r"ecrecover|ECDSA\.recover|SignatureChecker"),
    (r"delegatecall|delegate.call|proxy.?storage",
     r"\.delegatecall\s*\("),
    (r"selfdestruct|self.?destruct",
     r"selfdestruct\s*\(|suicide\s*\("),
    (r"tx\.origin|tx_origin",
     r"tx\.origin"),
    (r"front.?run|mev|sandwich",
     r"block\.|deadline|slippage|approve\s*\("),
]


def _post_filter_hallucinations(report: str, code: str) -> tuple[str, list[str]]:
    """
    Scan finding headers in the report for vulnerability keywords.
    For each match, check whether the required code pattern exists in the source.
    If not, annotate the finding header with ⚠ UNVERIFIED.
    Returns (annotated_report, list_of_flagged_titles).
    """
    flagged: list[str] = []
    lines = report.split("\n")

    for i, line in enumerate(lines):
        if not re.match(r'^###\s*\[', line):
            continue
        title_lower = line.lower()
        for vuln_kw, code_pattern in _HALLUCINATION_GUARD:
            if re.search(vuln_kw, title_lower, re.IGNORECASE):
                if not re.search(code_pattern, code, re.IGNORECASE):
                    lines[i] = line + "  ⚠ **[UNVERIFIED — required code pattern absent]**"
                    flagged.append(line.strip())
                break  # one annotation per finding is enough

    return "\n".join(lines), flagged


# ── self-verification second pass ─────────────────────────────────────────────
def _verify_findings(report: str, code: str, model: str, use_api: bool, api_client) -> str:
    """
    Optional second LLM pass. Sends code + draft report to deepseek and asks it
    to quote the exact code line for each finding, or mark it UNVERIFIED.
    Doubles inference time — only activated with --verify.
    """
    _print_info("\n[+] Running self-verification pass (--verify)...")
    verify_prompt = (
        "Below is a smart contract source and a draft audit report. "
        "For EACH finding (### [X-NN] ... section), do the following:\n"
        "1. Search the contract source for the exact function name or code line "
        "that proves the vulnerability is real.\n"
        "2. If you find it: add a line '**Verified at:** `<exact code snippet>`' "
        "right after the **Location:** line.\n"
        "3. If you CANNOT find any supporting code: change the finding header to "
        "add '[UNVERIFIED]' at the end.\n"
        "Do not add new findings. Only annotate existing ones. "
        "Return the complete annotated report.\n\n"
        f"=== CONTRACT SOURCE ===\n```\n{code[:8000]}\n```\n\n"
        f"=== DRAFT REPORT ===\n{report}"
    )
    messages = [
        {"role": "system", "content": "You are a precise smart contract auditor verifying a draft report against source code."},
        {"role": "user", "content": verify_prompt},
    ]
    verified = chat_turn(messages, model, use_api, api_client, verbose=False)
    return verified if verified.strip() else report


# ── report saving ─────────────────────────────────────────────────────────────
def _auto_save_report(response: str, label: str) -> None:
    """If response looks like an audit report, auto-save it."""
    if "## Findings" not in response and "# Security Audit" not in response:
        return
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", label)[:40]
    out = REPORTS_DIR / f"audit_{safe}_{ts}.md"
    out.write_text(response)
    _print_info(f"\n[+] Report saved → {out}")


# ── entry points ──────────────────────────────────────────────────────────────
_PHASE_INSTRUCTIONS: dict[str, str] = {
    "recon":        "Map the attack surface of this contract. Call extract_code_elements first.",
    "threats":      "Build a threat model for this contract type.",
    "hunt": (
        "Hunt for vulnerabilities. START by calling extract_code_elements on the code below, "
        "then run_slither (Solidity) or run_sui_analyzer (Move), then search_knowledge "
        "using patterns you confirmed exist. Write and save a professional audit report."
    ),
    "focused":      "Perform a focused check on the vulnerability class requested.",
    "interactions": "Analyse cross-contract interactions for vulnerabilities.",
    "report":       "Write the final consolidated audit report from all prior phase findings.",
}


def audit_file(path: str, model: str, use_api: bool, api_client,
               verify: bool = False, phase: str = DEFAULT_PHASE, stream: bool = True) -> str:
    p = Path(path)
    code = _tool_read_file({"path": path})
    lang = "move" if p.suffix == ".move" else "solidity"

    # Auto-load audit.config.md from the contract's directory if not already loaded
    if not _project_guidelines:
        _load_project_guidelines(str(p))

    rag_context = _rag_search(PHASE_RAG_QUERIES.get(phase, PHASE_RAG_QUERIES[DEFAULT_PHASE]))
    instruction = _PHASE_INSTRUCTIONS.get(phase, _PHASE_INSTRUCTIONS["hunt"])

    # Build messages with bounty brief priming exchange if a brief is loaded
    messages = _build_messages(phase, rag_context)
    messages.append({
        "role": "user",
        "content": (
            f"[Phase: {phase.upper()}] {instruction}\n\n"
            f"Contract: `{p.name}` (language: {lang})\n\n"
            f"```{lang}\n{code}\n```"
        ),
    })
    _print_info(f"[+] Phase: {phase.upper()} | File: {path} | Model: deepseek-r1:14b | Stream: {'on' if stream else 'off'}")
    result = chat_turn(messages, model, use_api, api_client, stream=stream)

    # Post-processing: flag findings whose required code pattern is absent
    result, flagged = _post_filter_hallucinations(result, code)
    if flagged:
        _print_info(f"\n[!] Hallucination filter flagged {len(flagged)} finding(s) as UNVERIFIED:")
        for f in flagged:
            _print_info(f"    {f}")

    # Store output for cross-phase carry (recon/threats → hunt → report)
    _phase_carry[phase] = result

    # Optional second-pass self-verification
    if verify:
        result = _verify_findings(result, code, model, use_api, api_client)

    _auto_save_report(result, f"{p.stem}_{phase}")
    _save_think_log(f"{p.stem}_{phase}")
    return result


def audit_directory(dirpath: str, model: str, use_api: bool, api_client,
                    verify: bool = False, phase: str = DEFAULT_PHASE, stream: bool = True) -> str:
    files = list(Path(dirpath).rglob("*.sol")) + list(Path(dirpath).rglob("*.move"))
    if not files:
        return f"No .sol or .move files found in {dirpath}"
    _print_info(f"[+] Found {len(files)} contracts in {dirpath} | Phase: {phase.upper()}")
    all_code = "\n".join(Path(f).read_text(errors="ignore") for f in files[:20])

    if not _project_guidelines:
        _load_project_guidelines(dirpath)

    rag_context = _rag_search(PHASE_RAG_QUERIES.get(phase, PHASE_RAG_QUERIES[DEFAULT_PHASE]))
    messages = _build_messages(phase, rag_context)
    messages.append({
        "role": "user",
        "content": (
            f"[Phase: {phase.upper()}] Audit the smart contract project in `{dirpath}`. "
            f"Use list_directory to discover files. Call extract_code_elements on each contract "
            f"before reasoning about it. Write a consolidated report and save it with write_file."
        ),
    })
    result = chat_turn(messages, model, use_api, api_client, stream=stream)
    result, flagged = _post_filter_hallucinations(result, all_code)
    if flagged:
        _print_info(f"\n[!] Hallucination filter flagged {len(flagged)} finding(s) as UNVERIFIED:")
        for f in flagged:
            _print_info(f"    {f}")
    _phase_carry[phase] = result
    if verify:
        result = _verify_findings(result, all_code, model, use_api, api_client)
    _auto_save_report(result, f"{Path(dirpath).name}_{phase}")
    _save_think_log(f"{Path(dirpath).name}_{phase}")
    return result


def generate_contract(spec: str, model: str, use_api: bool, api_client) -> str:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"Generate a complete, production-ready smart contract: {spec}\n\n"
            f"Requirements: full implementation, NatSpec comments, security best practices, "
            f"tests outline. Search the knowledge base for relevant patterns first. "
            f"Save the contract to an appropriate file with write_file."
        )},
    ]
    return chat_turn(messages, model, use_api, api_client)


def repl(model: str, use_api: bool, api_client, verify: bool = False, phase: str = DEFAULT_PHASE, stream: bool = True) -> None:
    current_phase = phase
    rag_ok = INDEX_DIR.exists()
    brief_status = f"brief loaded ({len(_bounty_brief)} chars)" if _bounty_brief else "no brief"
    _print_info(
        f"\nDeepAudit  |  model: {model}  |  phase: {current_phase}  |  "
        f"verify: {'on' if verify else 'off'}  |  {brief_status}  |  "
        f"RAG: {'ready' if rag_ok else 'not built — run: python rag/build_index.py'}"
    )
    _print_info(
        "Commands: audit <file>  |  dir <directory>  |  gen <spec>  |  brief <file>  |  "
        "/phase <name>  |  /phases  |  /context  |  /brief  |  clear  |  quit\n"
    )

    messages = _build_messages(current_phase, "")

    while True:
        try:
            user_input = input(f"[{current_phase}] >>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not user_input or user_input.lower() in ("quit", "exit", "q"):
            break

        # /phase switch
        if user_input.lower().startswith("/phase "):
            new_phase = user_input[7:].strip().lower()
            if new_phase in PHASE_PROMPTS:
                current_phase = new_phase
                rag_context = _rag_search(PHASE_RAG_QUERIES.get(current_phase, ""))
                messages = _build_messages(current_phase, rag_context)
                _print_info(f"[+] Switched to phase: {current_phase.upper()}")
            else:
                _print_info(f"[!] Unknown phase '{new_phase}'. Valid: {', '.join(p for p in PHASE_PROMPTS if p != 'default')}")
            continue

        if user_input.lower() == "/phases":
            _print_info("Available phases: recon | threats | hunt | focused | interactions | report")
            _print_info("Carried context: " + (", ".join(_phase_carry.keys()) or "none"))
            continue

        if user_input.lower() == "/context":
            if _phase_carry:
                for p, out in _phase_carry.items():
                    _print_info(f"\n--- {p.upper()} output (first 400 chars) ---\n{out[:400]}")
            else:
                _print_info("No cross-phase context yet. Run recon or threats first.")
            continue

        if user_input.lower() == "/brief":
            if _bounty_brief:
                _print_info(f"\n--- Active bounty brief ({len(_bounty_brief)} chars) ---\n{_bounty_brief[:600]}{'...' if len(_bounty_brief) > 600 else ''}")
            else:
                _print_info("No brief loaded. Use: brief <path/to/file.md>  or  python agent.py --brief <file>")
            continue

        # `brief <file_or_text>` — load a bounty brief mid-session
        if user_input.lower().startswith("brief "):
            _load_brief(user_input[6:].strip())
            # Rebuild messages so the priming exchange is injected immediately
            rag_context = _rag_search(PHASE_RAG_QUERIES.get(current_phase, ""))
            messages = _build_messages(current_phase, rag_context)
            _print_info("[+] Brief injected — session reset with bounty context.")
            continue

        if user_input.lower() == "clear":
            _phase_carry.clear()
            messages = _build_messages(current_phase, "")
            _print_info("[+] Context cleared.")
            continue

        if user_input.lower().startswith("audit "):
            path = user_input[6:].strip()
            response = audit_file(path, model, use_api, api_client, verify=verify, phase=current_phase, stream=stream)
        elif user_input.lower().startswith("dir "):
            dirpath = user_input[4:].strip()
            response = audit_directory(dirpath, model, use_api, api_client, verify=verify, phase=current_phase, stream=stream)
        elif user_input.lower().startswith("gen "):
            spec = user_input[4:].strip()
            response = generate_contract(spec, model, use_api, api_client)
        else:
            messages.append({"role": "user", "content": user_input})
            response = chat_turn(messages, model, use_api, api_client, stream=stream)

        _print_response(response)


def _check_ollama_model(model: str) -> bool:
    try:
        import ollama
        models = ollama.list()
        names = [m.model for m in models.models]
        base = model.split(":")[0]
        if not any(base in n for n in names):
            print(f"[warn] Model '{model}' not in Ollama. Run: ollama pull {model}")
            return False
        return True
    except Exception:
        print("[error] Ollama not running. Start: ollama serve")
        return False


# ── main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepAudit — smart contract security auditor (deepseek-r1:14b)")
    parser.add_argument("--api", action="store_true",
                        help="Use Mistral API instead of local Ollama")
    parser.add_argument("--api-key", help="Mistral API key (or set MISTRAL_API_KEY env var)")
    parser.add_argument("--model", help="Model name (default: deepseek-r1:14b)")
    parser.add_argument("--file", help="Audit a specific .sol or .move file")
    parser.add_argument("--dir", help="Audit all contracts in a directory")
    parser.add_argument("--stdin", action="store_true", help="Read contract from stdin")
    parser.add_argument("--generate", metavar="SPEC", help="Generate a contract from a description")
    parser.add_argument("--quiet", action="store_true", help="Suppress tool call output")
    parser.add_argument("--verify", action="store_true",
                        help="Run a self-verification second pass after the main audit (slower but catches more hallucinations)")
    parser.add_argument("--no-stream", action="store_true",
                        help="Disable streaming output (streaming is on by default — shows tokens live during long CPU inference)")
    parser.add_argument(
        "--brief", metavar="FILE_OR_TEXT",
        help=(
            "Bounty/audit program brief. Accepts a path to a .md/.txt file or raw text. "
            "Injected into every audit session so deepseek knows the scope, severity scale, "
            "in-scope vulnerability classes, and special rules before reading any code."
        ),
    )
    parser.add_argument(
        "--init-bounty", metavar="PATH",
        nargs="?", const="audit.config.md",
        help=(
            "Write a bounty config template to PATH (default: audit.config.md) and exit. "
            "Edit the file, then pass it with --brief. "
            "Also auto-loaded if present in the target contract's directory."
        ),
    )
    parser.add_argument(
        "--phase",
        default=DEFAULT_PHASE,
        choices=["recon", "threats", "hunt", "focused", "interactions", "report"],
        help=(
            "Audit phase to run (default: hunt).\n"
            "  recon        — map attack surface, entry points, roles, asset flow\n"
            "  threats      — adversarial threat model before reading code\n"
            "  hunt         — full vulnerability hunt (default)\n"
            "  focused      — deep dive on one vulnerability class\n"
            "  interactions — cross-contract interaction bugs\n"
            "  report       — consolidate all prior phase findings into final report\n"
            "Phases carry context forward: run recon first, then hunt uses its output."
        ),
    )
    args = parser.parse_args()

    # --init-bounty: scaffold the template and exit immediately
    if args.init_bounty:
        _scaffold_bounty_config(args.init_bounty)
        sys.exit(0)

    # --brief: load bounty program brief before any audit begins
    if args.brief:
        _load_brief(args.brief)

    _check_deps(args.api)

    api_client = None
    if args.api:
        from mistralai import Mistral
        key = args.api_key or os.environ.get("MISTRAL_API_KEY", "")
        if not key:
            print("[error] Provide --api-key or set MISTRAL_API_KEY")
            sys.exit(1)
        api_client = Mistral(api_key=key)
        model = args.model or DEFAULT_API_MODEL
    else:
        model = args.model or DEFAULT_OLLAMA_MODEL
        if not _check_ollama_model(model):
            sys.exit(1)

    if not INDEX_DIR.exists():
        _print_info("[warn] RAG index not built. Run: python rag/build_index.py")

    # Auto-load audit.config.md from target directory (only if --brief not already set)
    if not _bounty_brief:
        if args.file:
            _load_project_guidelines(args.file)
        elif args.dir:
            _load_project_guidelines(args.dir)

    do_stream = not args.no_stream and not args.api

    if args.stdin:
        code = sys.stdin.read()
        rag_context = _rag_search(PHASE_RAG_QUERIES.get(args.phase, PHASE_RAG_QUERIES[DEFAULT_PHASE]))
        messages = _build_messages(args.phase, rag_context)
        messages.append({
            "role": "user",
            "content": (
                f"[Phase: {args.phase.upper()}] Audit this contract. "
                f"START by calling extract_code_elements on the code below.\n\n```\n{code}\n```"
            ),
        })
        result = chat_turn(messages, model, args.api, api_client, verbose=not args.quiet, stream=do_stream)
        result, flagged = _post_filter_hallucinations(result, code)
        if flagged:
            _print_info(f"\n[!] {len(flagged)} finding(s) flagged UNVERIFIED by hallucination filter.")
        if args.verify:
            result = _verify_findings(result, code, model, args.api, api_client)
        _phase_carry[args.phase] = result
        _print_response(result, f"Audit Report [{args.phase.upper()}]")
    elif args.file:
        result = audit_file(args.file, model, args.api, api_client, verify=args.verify, phase=args.phase, stream=do_stream)
        _print_response(result, f"Audit [{args.phase.upper()}]: {args.file}")
    elif args.dir:
        result = audit_directory(args.dir, model, args.api, api_client, verify=args.verify, phase=args.phase, stream=do_stream)
        _print_response(result, f"Audit [{args.phase.upper()}]: {args.dir}")
    elif args.generate:
        result = generate_contract(args.generate, model, args.api, api_client)
        _print_response(result, "Generated Contract")
    else:
        repl(model, args.api, api_client, verify=args.verify, phase=args.phase, stream=do_stream)
