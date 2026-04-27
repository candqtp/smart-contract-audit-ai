# Smart Contract Audit AI----DEMO!!Not ready

> Local AI assistant that reads smart contract source code and produces structured security reports — powered by a fine-tuned language model and a retrieval-augmented knowledge base of real-world vulnerability patterns.

---

## What it does

You point it at a Solidity or Sui Move file. It reads the code, searches a knowledge base of 1,700+ real audit findings, and writes a report that lists vulnerabilities, severity ratings, and recommended fixes — the same output a human security auditor would produce, running entirely on your machine.

```
$ python agent_phi35.py

audit-ai> audit contracts/Vault.sol

[searching knowledge base...]
[reading file: contracts/Vault.sol]

## Audit Report — Vault.sol

### [CRITICAL] Reentrancy in withdraw()
Line 47: external call before state update. Attacker can re-enter and
drain the vault before balances[msg.sender] is zeroed.

Recommendation: move `balances[msg.sender] = 0` before the transfer,
or add a ReentrancyGuard modifier.

...
```

---

## How it works

```
User query
    │
    ▼
┌─────────────────────────────────────────┐
│              Agent Loop (ReAct)         │
│  reason → pick tool → observe → repeat  │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴────────┐
       ▼                ▼
  RAG Search       File / Code Tools
  (ChromaDB)       read_file, grep,
  top-5 chunks     run_slither, etc.
       │
       ▼
  Knowledge Base
  978 chunks · 61 documents
  (real CVEs, audit reports, exploit patterns)
       │
       └──────────────────────────────────────┐
                                              ▼
                                   Fine-tuned Phi-3.5 Mini
                                   (LoRA, 1,728 training examples)
                                   served locally via Ollama
```

### 1. Fine-tuned language model

Phi-3.5 Mini Instruct (3.8B parameters) fine-tuned with **LoRA** (Low-Rank Adaptation) on 1,728 real smart contract audit findings. LoRA freezes 99% of the model weights and trains only small adapter matrices — reducing compute by ~100x compared to full fine-tuning, while preserving the model's pre-trained knowledge.

Training: `train_phi35_lora.py` — SFTTrainer + TRL, LoRA r=16 α=32, targets attention and feed-forward projections.

### 2. RAG knowledge base

61 documents (Markdown) covering:
- Sui Move: object safety, capability patterns, shared-object races, integer arithmetic, PTB composability, 8 real audit PDFs
- Solidity/EVM: reentrancy, access control, delegatecall/proxy, front-running, signature replay, SWC patterns
- DeFi: oracle manipulation, flash loan attacks, lending/borrowing, AMM exploits, bridges, governance
- Checklists: full audit checklists for Sui, Solidity, and DeFi protocols
- Post-mortems: 9 major DeFi hacks with technical breakdowns (Euler, Curve, Nomad, Wormhole, Ronin…)

At query time: documents are chunked (800 chars, 150 overlap), embedded with `all-MiniLM-L6-v2`, and stored in ChromaDB. The top-5 most relevant chunks are injected into the model's context.

### 3. Agent loop

ReAct pattern (Reason + Act): the model outputs a thought, calls a tool, reads the result, and repeats until it has enough information to write the report. Tools include file reading, codebase search, knowledge base retrieval, and optional Slither/Sui analyzer integration.

---

## Stack

| Layer | Technology |
|---|---|
| Language model | Phi-3.5 Mini Instruct (Microsoft) |
| Fine-tuning | LoRA via HuggingFace TRL + SFTTrainer |
| Vector database | ChromaDB |
| Embeddings | sentence-transformers / all-MiniLM-L6-v2 |
| Local serving | Ollama |
| Agent pattern | ReAct (Reason + Act) |
| Language | Python 3.11 |

---

## Results

- Training loss: 12.0 → 2.1 over 309 steps (healthy convergence)
- Knowledge base: 978 indexed chunks across 61 security documents
- Agent covers: reentrancy, access control, oracle manipulation, flash loan attacks, integer overflow, signature replay, proxy storage collisions, and 40+ other vulnerability classes

---

## Project structure

```
smart-contract-audit-ai/
├── agent_phi35.py          # agent — run this to audit contracts
├── train_phi35_lora.py     # LoRA fine-tuning pipeline
├── rag/
│   ├── build_index.py      # builds ChromaDB index from knowledge files
│   └── knowledge/          # 61 markdown documents (vulnerability patterns)
│       ├── sui_move/       # 23 files — Sui Move specific
│       ├── solidity/       # 16 files — Solidity/EVM
│       ├── defi/           # 21 files — DeFi protocols
│       ├── audit_checklists/
│       ├── evm/
│       └── rekt_postmortems/
├── datasets/
│   └── README.md           # dataset description (data not committed)
├── reports/                # sample audit outputs
└── docs/
    └── architecture.md
```

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Build the knowledge base index
python rag/build_index.py

# 3. Pull the base model (requires Ollama installed)
ollama pull phi3.5

# 4. Run the agent
python agent_phi35.py
```

To use the fine-tuned adapter instead of the base model, see [`docs/architecture.md`](docs/architecture.md).

---

## Sample report

See [`reports/example_report.md`](reports/example_report.md) for a full agent-generated audit output.(not yet!!)
