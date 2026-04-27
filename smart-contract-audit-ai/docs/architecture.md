# Architecture

## System overview

```
                         ┌─────────────────────────────┐
                         │         User / CLI           │
                         │     python agent_phi35.py    │
                         └──────────────┬──────────────┘
                                        │
                         ┌──────────────▼──────────────┐
                         │         Agent Loop           │
                         │   ReAct: Reason → Act →      │
                         │   Observe → Reason → ...     │
                         └──┬──────────────────────┬───┘
                            │                      │
               ┌────────────▼──────┐   ┌───────────▼──────────┐
               │    Tool Calls     │   │   Language Model      │
               │                   │   │   Phi-3.5 Mini        │
               │  search_knowledge │   │   (fine-tuned LoRA)   │
               │  read_file        │   │   served via Ollama   │
               │  grep_codebase    │   └───────────────────────┘
               │  run_slither      │
               │  write_file       │
               └────────┬──────────┘
                        │
          ┌─────────────▼───────────────┐
          │        RAG Index            │
          │        ChromaDB             │
          │                             │
          │  Collection 1: knowledge    │
          │  61 docs → 978 chunks       │
          │                             │
          │  Collection 2: findings     │
          │  1,728 training examples    │
          └─────────────────────────────┘
```

---

## Components

### Language model — `agent_phi35.py`

**Phi-3.5 Mini Instruct** (microsoft/Phi-3.5-mini-instruct, 3.8B parameters) served locally via Ollama. The agent calls Ollama's `/api/chat` endpoint with tool definitions. If the model outputs a tool call in JSON, the agent executes it and feeds the result back. If the model writes free text instead (ReAct fallback), the agent parses `Action:` / `Observation:` lines.

The fine-tuned LoRA adapter is merged into the base model weights and exported to GGUF format for Ollama. To use it:

```bash
# After training completes:
python train_phi35_lora.py --merge-on-finish --export-gguf
ollama create audit-phi35 -f Modelfile

# Then in agent_phi35.py, change:
MODEL = "phi3.5"
# to:
MODEL = "audit-phi35"
```

### Fine-tuning pipeline — `train_phi35_lora.py`

```
Raw dataset (JSONL)
    │
    ▼  load_and_format()
Phi-3.5 chat template
<|user|> ... <|end|>
<|assistant|> ... <|end|>
    │
    ▼  SFTTrainer (TRL)
LoRA adapters trained
r=16, α=32
targets: qkv_proj, o_proj, gate_up_proj, down_proj
    │
    ▼  --merge-on-finish
Full merged model
    │
    ▼  --export-gguf (llama.cpp)
audit-phi35.gguf
    │
    ▼  ollama create
Local Ollama model
```

**Why LoRA?** Full fine-tuning of a 3.8B model requires ~30GB GPU memory. LoRA injects small trainable matrices (rank 16) into the attention and feed-forward layers — only ~1% of parameters are updated. This runs on CPU or a consumer GPU with 8GB VRAM, with minimal quality loss for domain adaptation tasks.

### RAG pipeline — `rag/build_index.py`

```
rag/knowledge/**/*.md
    │
    ▼  chunk (800 chars, 150 overlap)
    ▼  embed (all-MiniLM-L6-v2, 384-dim)
    ▼  store (ChromaDB, collection: knowledge_docs)

datasets/sui_audit_combined.jsonl
    │
    ▼  extract assistant turns
    ▼  embed
    ▼  store (ChromaDB, collection: dataset_findings)
```

At query time, the agent calls `search_knowledge(query, n_results=5)`. Both collections are searched; results are ranked by cosine distance and the top chunks are injected into the model prompt as context.

**Why RAG alongside fine-tuning?** Fine-tuning teaches the model *how* to reason about security (output format, severity assessment, remediation style). RAG provides *what* to reason about (specific CVEs, code patterns, checklist items). The two are complementary: the fine-tuned model uses RAG results more effectively because it understands the domain.

### Knowledge base — `rag/knowledge/`

| Folder | Files | Content |
|---|---|---|
| `sui_move/` | 23 | Object model, capabilities, shared objects, integer safety, real audit PDFs |
| `solidity/` | 16 | Reentrancy, access control, proxy/delegatecall, MEV, SWC patterns |
| `defi/` | 21 | Oracle attacks, flash loans, AMM exploits, bridges, governance |
| `audit_checklists/` | 3 | Full checklists for Sui, Solidity, DeFi |
| `evm/` | 2 | Slither detector reference, Echidna fuzzing patterns |
| `rekt_postmortems/` | 1 | 9 major DeFi hacks with technical breakdown |

Each file follows the same structure: vulnerability description → vulnerable code example → fixed code example → detection signals → severity guide.

---

## Data flow for a single audit query

```
1. User: "audit contracts/Vault.sol"

2. Agent thinks: "I need to read the file and search for relevant patterns"

3. Tool call: read_file("contracts/Vault.sol")
   → returns source code

4. Tool call: search_knowledge("vault reentrancy withdrawal")
   → returns top 5 chunks from RAG index

5. Model receives: [system prompt] + [RAG chunks] + [source code]
   → generates structured audit report

6. Agent writes report to reports/Vault_audit.md
```

---

## Extending the system

**Add knowledge:** drop a `.md` file into any `rag/knowledge/` subfolder, then run:
```bash
python rag/build_index.py --docs-only --rebuild
```

**Add training data:** append examples to `datasets/sui_audit_combined.jsonl` in conversations format, then re-run `train_phi35_lora.py`.

**Add a tool:** define a function in `agent_phi35.py` following the existing tool pattern, add its JSON schema to `TOOLS`, and add a branch in `execute_tool()`.
