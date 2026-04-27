# Training Dataset

## Overview

The fine-tuning dataset contains **1,728 examples** of smart contract security analysis in multi-turn conversation format. Each example is a realistic audit interaction: a user presents contract code or asks a security question, and the assistant responds with structured analysis including vulnerability identification, severity assessment, and remediation advice.

The `.jsonl` file is not committed to this repo (model weights and training data are excluded via `.gitignore`).

## Coverage

| Category | Examples |
|---|---|
| Sui Move vulnerabilities | ~600 |
| Solidity / EVM vulnerabilities | ~700 |
| DeFi protocol patterns | ~300 |
| Mixed / cross-chain | ~128 |

## Format

Each line is a JSON object in HuggingFace conversations format:

```json
{
  "conversations": [
    {
      "role": "system",
      "content": "You are an expert smart contract security auditor..."
    },
    {
      "role": "user",
      "content": "Audit this Solidity function for vulnerabilities:\n\n```solidity\nfunction withdraw(uint256 amount) external {\n    require(balances[msg.sender] >= amount);\n    (bool ok,) = msg.sender.call{value: amount}(\"\");\n    require(ok);\n    balances[msg.sender] -= amount;\n}\n```"
    },
    {
      "role": "assistant",
      "content": "## Vulnerability Analysis\n\n### [CRITICAL] Reentrancy\n\nThe state update (`balances[msg.sender] -= amount`) occurs **after** the external call on line 3. An attacker whose fallback function re-calls `withdraw()` will pass the `require` check repeatedly before the balance is ever decremented.\n\n**Recommendation:** Apply the checks-effects-interactions pattern — decrement the balance before the transfer..."
    }
  ]
}
```

## Sources

Examples were generated and curated from:
- Real audit reports (Sui Move protocols: Mysten, Lombard, Mayan, Solend/Steamm)
- SWC Registry (Smart Contract Weakness Classification)
- Code4rena and Sherlock disclosed findings
- Immunefi bug bounty disclosures
- Trail of Bits, ConsenSys Diligence public reports

## Reconstruction

To rebuild the dataset from the source scripts:

```bash
python sui_dataset_generator.py       # generates Sui Move examples
python convert_hf_datasets.py         # converts public HF datasets
python convert_v2_to_conversations.py # normalizes to conversations format
```
