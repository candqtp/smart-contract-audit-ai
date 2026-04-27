"""
Phi-3.5 Mini Instruct — smart contract audit agent with tools + RAG.

Phi-3.5 has native tool-calling support via Ollama, so this agent uses
the proper function-calling API instead of a ReAct text parser.
Falls back to ReAct pattern automatically if tool calls aren't returned.

Requirements:
    pip install ollama chromadb sentence-transformers rich
    ollama pull phi3.5

RAG index (one-time setup):
    python rag/build_index.py

Usage:
    python agent_phi35.py                            # interactive REPL
    python agent_phi35.py --file Vault.sol           # audit one file
    python agent_phi35.py --dir ./contracts/         # audit entire project
    python agent_phi35.py --stdin < Token.sol        # read from stdin
    python agent_phi35.py --generate "ERC4626 vault with timelock"
    python agent_phi35.py --model audit-phi35        # use fine-tuned model

After fine-tuning + Ollama import:
    python agent_phi35.py --model audit-phi35 --file Vault.sol
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

ROOT = Path(__file__).parent
INDEX_DIR = ROOT / ".rag_index"
REPORTS_DIR = ROOT / "reports"
DEFAULT_MODEL = "phi3.5"
MAX_TOOL_ROUNDS = 10
RAG_K = 4


# ── system prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = textwrap.dedent("""\
You are AuditPhi, an expert smart contract security auditor and blockchain developer.
You have deep knowledge of Solidity, Sui Move, DeFi vulnerabilities — reentrancy,
oracle manipulation, access control, flash loans, integer overflow, front-running,
DoS, signature replay, unchecked returns, timestamp dependence — and all EVM/Move patterns.

WORKFLOW for every audit request:
1. Call search_knowledge with the vulnerability type or code pattern you see
2. Call run_slither (Solidity) or run_sui_analyzer (Move) on the code
3. Reason step-by-step, citing specific function names and variable names
4. Write a professional Markdown report and save it with write_file

REPORT FORMAT:
# Security Audit Report — [ContractName]
**Auditor:** AuditPhi | **Severity Scale:** Critical > High > Medium > Low

## Executive Summary
[1-2 sentence overview of findings]

## Findings

### [H-01] [Title] — [Severity]
**Location:** `FunctionName()` / line ~XX
**Description:** [concrete explanation citing identifiers]
**Attack Scenario:** [numbered steps]
**Impact:** [what attacker gains]
**Recommendation:** [fixed code snippet]

## Summary Table
| ID | Title | Severity |
|---|---|---|

RULES:
- Never hallucinate identifiers not present in the code
- Always verify with tool results before making claims
- For contract generation: write complete compilable code with NatSpec\
""")


# ── dependency check ──────────────────────────────────────────────────────────
def _check_deps():
    missing = []
    for pkg in ("ollama", "chromadb", "sentence_transformers"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg if pkg != "sentence_transformers" else "sentence-transformers")
    if missing:
        print(f"[error] pip install {' '.join(missing)}")
        sys.exit(1)

_check_deps()


# ── RAG ───────────────────────────────────────────────────────────────────────
_embedder = None

def _rag_search(query: str) -> str:
    if not INDEX_DIR.exists():
        return "RAG index not built — run: python rag/build_index.py"
    try:
        global _embedder
        import chromadb
        from sentence_transformers import SentenceTransformer
        if _embedder is None:
            _embedder = SentenceTransformer("all-MiniLM-L6-v2")

        client = chromadb.PersistentClient(path=str(INDEX_DIR))
        qemb = _embedder.encode([query]).tolist()
        results = []
        for name in ("dataset_findings", "knowledge_docs"):
            try:
                col = client.get_collection(name)
                if col.count() == 0:
                    continue
                res = col.query(query_embeddings=qemb, n_results=min(RAG_K, col.count()))
                for doc, dist in zip(res["documents"][0], res["distances"][0]):
                    results.append((round(1 - dist, 3), doc))
            except Exception:
                pass
        results.sort(reverse=True)
        if not results:
            return "No relevant results found in knowledge base."
        parts = [f"[relevance={s:.2f}]\n{d[:600]}" for s, d in results[:RAG_K]]
        return "\n\n---\n\n".join(parts)
    except Exception as e:
        return f"RAG error: {e}"


# ── tools ─────────────────────────────────────────────────────────────────────
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "search_knowledge",
            "description": (
                "Search the local audit knowledge base (1728 real findings + docs) "
                "for similar vulnerabilities, attack patterns, or code signatures. "
                "Call this first for every audit."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Vulnerability type, pattern name, or code construct to search for"
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read source code or text from a local file path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a local file. Use to save audit reports and generated contracts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to write"},
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
            "description": "List files in a directory. Use to discover all contracts in a project before auditing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path (default: current dir)"},
                    "pattern": {"type": "string", "description": "Glob pattern e.g. '**/*.sol'"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_slither",
            "description": "Run Slither static analysis on Solidity source code. Returns vulnerabilities with impact levels. Use for every Solidity audit.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Solidity source code"}
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sui_analyzer",
            "description": "Scan Sui Move code for common vulnerability patterns: missing capability checks, shared object races, clock manipulation, dynamic field issues.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Sui Move source code"}
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_codebase",
            "description": "Search for a regex pattern across all .sol and .move files in a directory. Useful to find all uses of a dangerous pattern.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex pattern"},
                    "path": {"type": "string", "description": "Directory to search (default: .)"},
                },
                "required": ["pattern"],
            },
        },
    },
]


def _tool_search_knowledge(args: dict) -> str:
    return _rag_search(args.get("query", ""))

def _tool_read_file(args: dict) -> str:
    p = Path(args.get("path", ""))
    if not p.exists():
        return f"File not found: {p}"
    if p.stat().st_size > 250_000:
        return "File large — reading first 250KB:\n" + p.read_text(errors="ignore")[:250_000]
    return p.read_text(errors="ignore")

def _tool_write_file(args: dict) -> str:
    p = Path(args.get("path", "output.md"))
    p.parent.mkdir(parents=True, exist_ok=True)
    content = args.get("content", "")
    p.write_text(content)
    return f"Saved {len(content):,} chars → {p}"

def _tool_list_directory(args: dict) -> str:
    p = Path(args.get("path", "."))
    pattern = args.get("pattern", "**/*")
    if not p.exists():
        return f"Not found: {p}"
    files = sorted(f for f in p.glob(pattern) if f.is_file())[:100]
    return "\n".join(str(f.relative_to(p)) for f in files) or "Empty."

def _tool_run_slither(args: dict) -> str:
    code = args.get("code", "")
    if not code.strip():
        return "No code provided."
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name
    try:
        r = subprocess.run(["slither", tmp_path, "--json", "-"],
                           capture_output=True, text=True, timeout=60)
        try:
            detectors = json.loads(r.stdout).get("results", {}).get("detectors", [])
            if not detectors:
                return "Slither: no issues detected."
            return "\n".join(
                f"[{d.get('impact','?')}] {d.get('check','?')}: {d.get('description','')[:200]}"
                for d in detectors[:15]
            )
        except Exception:
            return (r.stdout + r.stderr).strip()[:800] or "No output."
    except FileNotFoundError:
        return "Slither not installed: pip install slither-analyzer"
    except subprocess.TimeoutExpired:
        return "Slither timed out (>60s)."
    finally:
        os.unlink(tmp_path)

def _tool_run_sui_analyzer(args: dict) -> str:
    code = args.get("code", "")
    findings = []
    checks = [
        (r"public\s+fun\s+\w+\s*\((?![^)]*Cap)", "[WARN] public fun without capability — verify access control"),
        (r"transfer::share_object",               "[INFO] shared object — check for race conditions"),
        (r"clock::timestamp_ms|ctx\.epoch\(\)",   "[WARN] time-dependent logic — check manipulation surface"),
        (r"dynamic_field::(add|borrow_mut)",      "[INFO] dynamic field — verify key uniqueness"),
        (r"balance::split|coin::split",           "[INFO] coin split — verify amount bounds"),
        (r"tx_context::sender",                   "[INFO] sender-based auth — verify spoofing resistance"),
        (r"\babort\s+0\b",                        "[STYLE] abort(0) — use named error constants"),
        (r"vector::borrow_mut",                   "[INFO] mutable vector borrow — check index bounds"),
    ]
    for pattern, msg in checks:
        if re.search(pattern, code):
            findings.append(msg)
    return "\n".join(findings) if findings else "No pattern issues detected. Manual review recommended."

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
        suffix = f"\n... ({len(r.stdout.splitlines())-40} more)" if len(r.stdout.splitlines()) > 40 else ""
        return "\n".join(lines) + suffix
    except Exception as e:
        return f"grep error: {e}"


TOOL_DISPATCH = {
    "search_knowledge": _tool_search_knowledge,
    "read_file":        _tool_read_file,
    "write_file":       _tool_write_file,
    "list_directory":   _tool_list_directory,
    "run_slither":      _tool_run_slither,
    "run_sui_analyzer": _tool_run_sui_analyzer,
    "grep_codebase":    _tool_grep_codebase,
}

def dispatch(name: str, args: dict) -> str:
    fn = TOOL_DISPATCH.get(name)
    if not fn:
        return f"Unknown tool: {name}. Available: {list(TOOL_DISPATCH)}"
    try:
        return fn(args)
    except Exception as e:
        return f"Tool error ({name}): {e}"


# ── ReAct fallback parser (when Ollama doesn't return tool_calls) ─────────────
_ACT_RE  = re.compile(r"Action:\s*(\w+)", re.I)
_ARG_RE  = re.compile(r"Action Input:\s*(\{.*?\})", re.DOTALL | re.I)
_FINAL_RE = re.compile(r"Final Answer:\s*(.*)", re.DOTALL | re.I)

def _parse_react(text: str):
    """Returns (tool_name, tool_args, final_answer)."""
    if m := _FINAL_RE.search(text):
        return None, None, m.group(1).strip()
    if a := _ACT_RE.search(text):
        tool = a.group(1)
        args = {}
        if inp := _ARG_RE.search(text):
            try:
                args = json.loads(inp.group(1))
            except Exception:
                pass
        return tool, args, None
    return None, None, text.strip()


# ── main chat loop ────────────────────────────────────────────────────────────
def chat_turn(messages: list[dict], model: str, verbose: bool = True) -> str:
    import ollama

    for _ in range(MAX_TOOL_ROUNDS):
        try:
            resp = ollama.chat(
                model=model,
                messages=messages,
                tools=TOOL_DEFINITIONS,
                options={"temperature": 0.1, "num_predict": 2500},
            )
        except Exception as e:
            return f"[ollama error] {e}\nCheck: ollama serve"

        msg = resp.message
        content = msg.content or ""
        tool_calls = getattr(msg, "tool_calls", None) or []

        # If Ollama returned tool calls via the API
        if tool_calls:
            messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})
            for tc in tool_calls:
                fn = tc.function
                raw_args = fn.arguments or {}
                args = raw_args if isinstance(raw_args, dict) else {}
                if verbose:
                    a_str = ", ".join(f"{k}={repr(v)[:60]}" for k, v in args.items())
                    print(f"  [tool] {fn.name}({a_str})", flush=True)
                result = dispatch(fn.name, args)
                if verbose:
                    print(f"  → {result[:200]}{'...' if len(result)>200 else ''}", flush=True)
                messages.append({"role": "tool", "content": result, "name": fn.name})
            continue

        # Fallback: parse ReAct format from text
        tool_name, tool_args, final = _parse_react(content)
        if final is not None:
            messages.append({"role": "assistant", "content": final})
            return final
        if tool_name:
            if verbose:
                print(f"  [react] {tool_name}({tool_args})", flush=True)
            result = dispatch(tool_name, tool_args or {})
            if verbose:
                print(f"  → {result[:200]}{'...' if len(result)>200 else ''}", flush=True)
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": f"Observation: {result[:1000]}\nContinue."})
            continue

        # No tool call, no final answer marker — it's the response
        messages.append({"role": "assistant", "content": content})
        return content

    return content


# ── helpers ───────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    _con = Console()
    def _print_md(text: str, title: str = ""):
        _con.print(Panel(Markdown(text), title=f"[bold green]{title}[/bold green]", border_style="green"))
    def _info(msg: str):
        _con.print(f"[cyan]{msg}[/cyan]")
except ImportError:
    def _print_md(text: str, title: str = ""):
        print(f"\n{'─'*60}\n{text}\n{'─'*60}")
    def _info(msg: str):
        print(msg)


def _auto_save(response: str, label: str):
    if "## Finding" not in response and "# Security Audit" not in response:
        return
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^a-z0-9]", "_", label.lower())[:30]
    out = REPORTS_DIR / f"audit_{slug}_{ts}.md"
    out.write_text(response)
    _info(f"[+] Report auto-saved → {out}")


def _check_ollama(model: str) -> bool:
    try:
        import ollama
        names = [m.model for m in ollama.list().models]
        base = model.split(":")[0]
        if not any(base in n for n in names):
            print(f"[warn] '{model}' not in Ollama.")
            print(f"       Run: ollama pull {model}")
            return False
        return True
    except Exception:
        print("[error] Ollama not running. Start: ollama serve")
        return False


def _new_session() -> list[dict]:
    return [{"role": "system", "content": SYSTEM_PROMPT}]


# ── REPL ──────────────────────────────────────────────────────────────────────
def repl(model: str) -> None:
    rag = "ready" if INDEX_DIR.exists() else "NOT built — run: python rag/build_index.py"
    _info(f"\nAuditPhi — Phi-3.5 Mini | model={model} | RAG={rag}")
    _info("Commands: audit <file>  |  dir <path>  |  gen <spec>  |  clear  |  quit\n")

    messages = _new_session()

    while True:
        try:
            user = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not user or user.lower() in ("quit", "exit", "q"):
            break

        if user.lower() == "clear":
            messages = _new_session()
            _info("[+] Context cleared.")
            continue

        if user.lower().startswith("audit "):
            path = user[6:].strip()
            code = _tool_read_file({"path": path})
            lang = "move" if path.endswith(".move") else "solidity"
            content = (
                f"Perform a complete security audit of `{path}` ({lang}). "
                f"Use all available tools. Write a professional report and save it with write_file.\n\n"
                f"```{lang}\n{code[:4000]}\n```"
            )
        elif user.lower().startswith("dir "):
            dirpath = user[4:].strip()
            content = (
                f"Audit all smart contracts in `{dirpath}`. "
                f"Use list_directory to find all files, audit each one, then write a "
                f"consolidated report with write_file covering all findings."
            )
        elif user.lower().startswith("gen "):
            spec = user[4:].strip()
            content = (
                f"Generate a complete, production-ready smart contract: {spec}. "
                f"First search_knowledge for relevant security patterns. "
                f"Write full code with NatSpec comments, then save with write_file."
            )
        else:
            content = user

        messages.append({"role": "user", "content": content})
        response = chat_turn(messages, model)
        _print_md(response, "AuditPhi")
        _auto_save(response, user[:40])


# ── entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phi-3.5 smart contract audit agent")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Ollama model (default: {DEFAULT_MODEL}). "
                             "After fine-tuning: --model audit-phi35")
    parser.add_argument("--file", help="Audit a .sol or .move file")
    parser.add_argument("--dir",  help="Audit all contracts in a directory")
    parser.add_argument("--stdin", action="store_true", help="Read contract from stdin")
    parser.add_argument("--generate", metavar="SPEC", help="Generate a secure contract from spec")
    parser.add_argument("--quiet", action="store_true", help="Suppress tool call output")
    args = parser.parse_args()

    if not _check_ollama(args.model):
        sys.exit(1)

    if not INDEX_DIR.exists():
        _info("[warn] RAG not built. Run: python rag/build_index.py for best results.")

    verbose = not args.quiet

    if args.stdin:
        code = sys.stdin.read()
        lang = "solidity"
        msgs = _new_session()
        msgs.append({"role": "user", "content": f"Audit this contract:\n\n```{lang}\n{code}\n```"})
        result = chat_turn(msgs, args.model, verbose)
        _print_md(result, "Audit Report")
        _auto_save(result, "stdin")

    elif args.file:
        code = _tool_read_file({"path": args.file})
        lang = "move" if args.file.endswith(".move") else "solidity"
        msgs = _new_session()
        msgs.append({"role": "user", "content": (
            f"Complete security audit of `{args.file}` ({lang}). "
            f"Use all tools. Save report with write_file.\n\n```{lang}\n{code[:4000]}\n```"
        )})
        result = chat_turn(msgs, args.model, verbose)
        _print_md(result, f"Audit: {args.file}")
        _auto_save(result, Path(args.file).stem)

    elif args.dir:
        msgs = _new_session()
        msgs.append({"role": "user", "content": (
            f"Audit all contracts in `{args.dir}`. Use list_directory, audit each file, "
            f"write consolidated report with write_file."
        )})
        result = chat_turn(msgs, args.model, verbose)
        _print_md(result, f"Audit: {args.dir}")
        _auto_save(result, Path(args.dir).name)

    elif args.generate:
        msgs = _new_session()
        msgs.append({"role": "user", "content": (
            f"Generate a complete secure contract: {args.generate}. "
            f"search_knowledge first, then write full code with write_file."
        )})
        result = chat_turn(msgs, args.model, verbose)
        _print_md(result, "Generated Contract")

    else:
        repl(args.model)
