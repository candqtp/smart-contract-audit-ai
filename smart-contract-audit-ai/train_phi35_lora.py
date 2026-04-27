"""
LoRA fine-tuning for Phi-3.5 Mini Instruct (3.8B) on smart contract audit dataset.

CPU-first design: no GPU, no bitsandbytes needed.
Peak RAM: ~13-16 GB with LoRA + gradient checkpointing — comfortable on 32 GB.
Inference after training: GGUF Q4 ~2.3 GB, ~12 tok/s on a modern CPU.

Requirements:
    pip install transformers peft trl accelerate datasets

Usage:
    python train_phi35_lora.py                       # 3 epochs, default settings
    python train_phi35_lora.py --epochs 5 --lr 1e-4  # more epochs, lower lr
    python train_phi35_lora.py --merge-on-finish      # merge adapter → full weights
    python train_phi35_lora.py --export-gguf          # export for Ollama (needs llama.cpp)

After training:
    ollama create audit-phi35 -f audit-phi35/Modelfile
    ollama run audit-phi35
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
DATASET_FILE = ROOT / "datasets" / "sui_audit_combined.jsonl"
MODEL_ID = "microsoft/Phi-3.5-mini-instruct"

SYSTEM_PROMPT = (
    "You are an expert smart contract security auditor with deep knowledge of "
    "Solidity, Sui Move, DeFi vulnerabilities, reentrancy, oracle manipulation, "
    "access control flaws, integer overflows, flash loan attacks, and all common "
    "EVM and Move security patterns. When auditing code: reason step-by-step, "
    "cite specific function names and variable identifiers, state vulnerability "
    "type, severity (Critical/High/Medium/Low), attack scenario, impact, and "
    "provide a concrete fix. When generating contracts: write complete, secure, "
    "well-commented code. Never hallucinate identifiers not present in the code."
)

# Phi-3.5 response marker — loss computed only on tokens after this
RESPONSE_TEMPLATE = "<|assistant|>\n"

# Phi-3.5 Mini architecture module names
# Uses fused QKV and fused gate+up projections — NOT separate q/k/v_proj
LORA_TARGET_MODULES = [
    "qkv_proj",      # fused attention Q+K+V
    "o_proj",        # attention output
    "gate_up_proj",  # fused MLP gate+up
    "down_proj",     # MLP down
]
LORA_R = 16
LORA_ALPHA = 32
LORA_DROPOUT = 0.05


def _check_deps():
    for pkg in ("transformers", "peft", "trl", "accelerate", "datasets"):
        try:
            __import__(pkg)
        except ImportError:
            print(f"[error] Missing: {pkg}. Run: pip install transformers peft trl accelerate datasets")
            sys.exit(1)

_check_deps()

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTTrainer

# TRL >= 0.12 moved dataset_text_field + max_seq_length into SFTConfig
try:
    from trl import SFTConfig as _TrainingClass
    _USE_SFT_CONFIG = True
except ImportError:
    from transformers import TrainingArguments as _TrainingClass
    _USE_SFT_CONFIG = False


def _get_collator(tokenizer):
    """Response-only loss masking — handles TRL version differences."""
    for mod in ("trl", "trl.trainer", "trl.data_utils"):
        try:
            m = __import__(mod, fromlist=["DataCollatorForCompletionOnlyLM"])
            cls = getattr(m, "DataCollatorForCompletionOnlyLM", None)
            if cls:
                return cls(RESPONSE_TEMPLATE, tokenizer=tokenizer)
        except Exception:
            pass
    from transformers import DataCollatorForLanguageModeling
    print("[warn] Response-only masking unavailable — training on full sequence")
    return DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)


def load_and_format(path: Path, tokenizer) -> Dataset:
    """Convert conversations format → Phi-3.5 chat template strings."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            convs = entry.get("conversations", [])
            if not convs:
                continue

            # Inject our system prompt, keep user/assistant turns
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            for c in convs:
                if c["role"] in ("user", "assistant"):
                    messages.append({"role": c["role"], "content": c["content"]})

            if not any(m["role"] == "user" for m in messages):
                continue
            if not any(m["role"] == "assistant" for m in messages):
                continue

            try:
                text = tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=False,
                )
            except Exception:
                continue

            records.append({"text": text})

    print(f"[+] Formatted {len(records)} examples")
    return Dataset.from_list(records)


def train(
    output_dir: Path,
    epochs: int,
    batch_size: int,
    grad_accum: int,
    lr: float,
    max_seq_len: int,
    merge_on_finish: bool,
    export_gguf: bool,
) -> None:
    backend = "cuda" if torch.cuda.is_available() else "cpu"
    is_rocm = backend == "cuda" and getattr(torch.version, "hip", None)
    label = "ROCm" if is_rocm else backend.upper()
    print(f"[+] Backend: {label}")

    print(f"[+] Loading tokenizer: {MODEL_ID}")
    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_ID, trust_remote_code=True, padding_side="right"
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"[+] Loading dataset...")
    ds = load_and_format(DATASET_FILE, tokenizer)
    split = ds.train_test_split(test_size=0.05, seed=42)
    train_ds, eval_ds = split["train"], split["test"]
    print(f"[+] Train: {len(train_ds)} | Eval: {len(eval_ds)}")

    print(f"[+] Loading Phi-3.5 Mini (~7 GB bf16)...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        dtype=torch.bfloat16,
        device_map="auto" if backend != "cpu" else None,
        trust_remote_code=True,
        attn_implementation="eager",   # flash_attention_2 needs CUDA; eager is safe everywhere
    )
    # enable_input_require_grads needed for PEFT + gradient checkpointing
    model.enable_input_require_grads()

    lora_cfg = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        lora_dropout=LORA_DROPOUT,
        target_modules=LORA_TARGET_MODULES,
        bias="none",
        inference_mode=False,
    )
    model = get_peft_model(model, lora_cfg)
    trainable, total = model.get_nb_trainable_parameters()
    print(f"[+] LoRA: {trainable:,} / {total:,} trainable ({100*trainable/total:.2f}%)")

    collator = _get_collator(tokenizer)

    import inspect

    base_kwargs = dict(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        gradient_checkpointing=True,
        learning_rate=lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,           # warmup_steps is deprecated in newer transformers
        fp16=False,
        bf16=(backend != "cpu"),
        optim="adamw_torch",
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=100,
        save_strategy="steps",
        save_steps=200,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        report_to="none",
        dataloader_num_workers=0,
        use_cpu=(backend == "cpu"),
    )

    sft_trainer_params = inspect.signature(SFTTrainer.__init__).parameters

    if _USE_SFT_CONFIG:
        # Detect correct seq-length param name (renamed across TRL versions)
        cfg_params = inspect.signature(_TrainingClass.__init__).parameters
        seq_key = "max_seq_length" if "max_seq_length" in cfg_params else "max_length"
        txt_key = "dataset_text_field" if "dataset_text_field" in cfg_params else None

        sft_extra = {seq_key: max_seq_len}
        if txt_key:
            sft_extra[txt_key] = "text"

        training_args = _TrainingClass(**base_kwargs, **sft_extra)
        trainer_kwargs = dict(
            model=model,
            train_dataset=train_ds,
            eval_dataset=eval_ds,
            data_collator=collator,
            args=training_args,
        )
        # If dataset_text_field not in SFTConfig, try passing to trainer
        if not txt_key and "dataset_text_field" in sft_trainer_params:
            trainer_kwargs["dataset_text_field"] = "text"
    else:
        # Old TRL: all extra params go on SFTTrainer
        training_args = _TrainingClass(**base_kwargs)
        trainer_kwargs = dict(
            model=model,
            train_dataset=train_ds,
            eval_dataset=eval_ds,
            data_collator=collator,
            args=training_args,
        )
        if "dataset_text_field" in sft_trainer_params:
            trainer_kwargs["dataset_text_field"] = "text"
        if "max_seq_length" in sft_trainer_params:
            trainer_kwargs["max_seq_length"] = max_seq_len

    # tokenizer param renamed to processing_class in newer TRL
    if "processing_class" in sft_trainer_params:
        trainer_kwargs["processing_class"] = tokenizer
    elif "tokenizer" in sft_trainer_params:
        trainer_kwargs["tokenizer"] = tokenizer

    trainer = SFTTrainer(**trainer_kwargs)

    print(f"\n[+] Training — {epochs} epochs | lr={lr} | seq={max_seq_len} | batch={batch_size}×{grad_accum}")
    print(f"    Est. time on CPU: ~{len(train_ds) * epochs * 8 // 3600 + 1}h (varies by CPU)")
    trainer.train()

    adapter_dir = output_dir / "adapter"
    adapter_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))
    print(f"\n[+] Adapter saved → {adapter_dir}")

    if merge_on_finish or export_gguf:
        merged_dir = output_dir / "merged"
        _merge(adapter_dir, merged_dir)
        _write_modelfile(output_dir)
        if export_gguf:
            _export_gguf(merged_dir, output_dir)


def _merge(adapter_dir: Path, merged_dir: Path) -> None:
    from peft import PeftModel
    print("\n[+] Merging adapter into base weights (bf16)...")
    backend = "cuda" if torch.cuda.is_available() else "cpu"
    base = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        dtype=torch.bfloat16,
        device_map="auto" if backend != "cpu" else None,
        trust_remote_code=True,
    )
    tok = AutoTokenizer.from_pretrained(str(adapter_dir), trust_remote_code=True)
    merged = PeftModel.from_pretrained(base, str(adapter_dir)).merge_and_unload()
    merged_dir.mkdir(parents=True, exist_ok=True)
    merged.save_pretrained(str(merged_dir))
    tok.save_pretrained(str(merged_dir))
    print(f"[+] Merged model → {merged_dir}")


def _write_modelfile(output_dir: Path) -> None:
    gguf_path = output_dir / "audit_phi35_q8.gguf"
    mf = output_dir / "Modelfile"
    mf.write_text(
        f"FROM {gguf_path}\n"
        f'SYSTEM """{SYSTEM_PROMPT}"""\n'
        "PARAMETER temperature 0.1\n"
        "PARAMETER num_predict 2500\n"
        "PARAMETER stop <|end|>\n"
        "PARAMETER stop <|user|>\n"
    )
    print(f"[+] Modelfile → {mf}")
    print(f"    After GGUF export: ollama create audit-phi35 -f {mf}")


def _export_gguf(merged_dir: Path, output_dir: Path) -> None:
    llama_cpp = Path(os.environ.get("LLAMA_CPP_PATH", str(ROOT.parent / "llama.cpp")))
    convert = llama_cpp / "convert_hf_to_gguf.py"
    gguf_path = output_dir / "audit_phi35_q8.gguf"
    if not convert.exists():
        print(f"\n[warn] llama.cpp not found at {llama_cpp}")
        print(f"       git clone https://github.com/ggerganov/llama.cpp ../llama.cpp")
        print(f"       Then: python {convert} {merged_dir} --outtype q8_0 --outfile {gguf_path}")
        return
    print(f"\n[+] Exporting GGUF → {gguf_path}")
    r = subprocess.run([sys.executable, str(convert), str(merged_dir),
                        "--outtype", "q8_0", "--outfile", str(gguf_path)])
    if r.returncode == 0:
        print(f"[+] Done: ollama create audit-phi35 -f {output_dir}/Modelfile")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fine-tune Phi-3.5 Mini for smart contract auditing")
    parser.add_argument("--output", default="./audit-phi35")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=1,
                        help="Keep at 1 for CPU to minimise RAM peak")
    parser.add_argument("--grad-accum", type=int, default=16,
                        help="Effective batch = batch_size × grad_accum (default 16)")
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--max-seq-len", type=int, default=1536)
    parser.add_argument("--merge-on-finish", action="store_true",
                        help="Merge LoRA adapter into full model weights after training")
    parser.add_argument("--export-gguf", action="store_true",
                        help="Export merged model to GGUF for Ollama (requires llama.cpp)")
    args = parser.parse_args()

    if not DATASET_FILE.exists():
        print(f"[error] Dataset not found: {DATASET_FILE}")
        print(f"        Run: python convert_v2_to_conversations.py")
        sys.exit(1)

    train(
        output_dir=Path(args.output),
        epochs=args.epochs,
        batch_size=args.batch_size,
        grad_accum=args.grad_accum,
        lr=args.lr,
        max_seq_len=args.max_seq_len,
        merge_on_finish=args.merge_on_finish,
        export_gguf=args.export_gguf,
    )
