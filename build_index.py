"""
Build RAG knowledge index for the audit agent.

Indexes TWO sources:
  1. Training dataset (1728 audit findings) — the model's learned knowledge, searchable
  2. Markdown knowledge docs in rag/knowledge/ — your custom reference material

Both are stored in ChromaDB with metadata for filtering.

Usage:
    python rag/build_index.py                  # build / rebuild full index
    python rag/build_index.py --dataset-only   # only index the dataset
    python rag/build_index.py --docs-only      # only index knowledge docs
    python rag/build_index.py --stats          # show index stats
    python rag/build_index.py --search "reentrancy delegatecall"  # test search

Adding new knowledge:
    Drop any .md, .txt, or .sol file into rag/knowledge/ (any subdirectory)
    then re-run: python rag/build_index.py --docs-only

RAG document format (Markdown recommended):
    Each file = one knowledge unit. Use headers for structure.
    Filename should describe content: reentrancy_patterns.md, sui_object_safety.md
    No special format required — plain prose and code blocks work best.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"
INDEX_DIR = ROOT / ".rag_index"
DATASET_FILE = ROOT / "datasets" / "sui_audit_combined.jsonl"
EMBED_MODEL = "all-MiniLM-L6-v2"   # 90MB, CPU-only, fast

CHUNK_SIZE = 800      # chars per chunk for long documents
CHUNK_OVERLAP = 150


def _check_deps():
    missing = []
    for pkg in ("chromadb", "sentence_transformers"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg if pkg != "sentence_transformers" else "sentence-transformers")
    if missing:
        print(f"[error] pip install {' '.join(missing)}")
        sys.exit(1)

_check_deps()

import chromadb
from sentence_transformers import SentenceTransformer


def _chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split long text into overlapping chunks."""
    if len(text) <= size:
        return [text]
    chunks = []
    start = 0
    while start < len(text):
        end = start + size
        chunks.append(text[start:end])
        start += size - overlap
    return chunks


def _get_collection(client: chromadb.PersistentClient, name: str):
    try:
        return client.get_collection(name)
    except Exception:
        return client.create_collection(name)


def build_dataset_index(client, embedder, force: bool = False) -> int:
    """Index all 1728 audit findings from training dataset."""
    col = _get_collection(client, "dataset_findings")

    if not force and col.count() > 0:
        print(f"[+] Dataset index already has {col.count()} entries (use --rebuild to refresh)")
        return col.count()

    # Clear existing
    try:
        client.delete_collection("dataset_findings")
    except Exception:
        pass
    col = client.create_collection("dataset_findings")

    if not DATASET_FILE.exists():
        print(f"[warn] Dataset not found: {DATASET_FILE}")
        return 0

    print(f"[+] Indexing training dataset...")
    entries = []
    with open(DATASET_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    docs, ids, metas = [], [], []
    for i, entry in enumerate(entries):
        convs = entry.get("conversations", [])
        user_msg = next((c["content"] for c in convs if c["role"] == "user"), "")
        asst_msg = next((c["content"] for c in convs if c["role"] == "assistant"), "")
        if not asst_msg:
            continue

        # Extract vuln type and severity from assistant response header
        vuln_type = "unknown"
        severity = "unknown"
        for line in asst_msg.splitlines()[:5]:
            if line.startswith("## Vulnerability:"):
                vuln_type = line.replace("## Vulnerability:", "").strip().lower().replace(" ", "-")
            if "**Severity:**" in line:
                severity = line.replace("**Severity:**", "").strip()

        # Index the assistant response (the audit finding) as the document
        doc_text = asst_msg[:1200]
        docs.append(doc_text)
        ids.append(f"dataset_{i}")
        metas.append({
            "source": "dataset",
            "vuln_type": vuln_type,
            "severity": severity,
            "code_snippet": user_msg[user_msg.find("```"):user_msg.find("```")+300] if "```" in user_msg else "",
        })

    # Batch embed
    batch_size = 128
    for start in range(0, len(docs), batch_size):
        batch_docs = docs[start:start+batch_size]
        batch_ids = ids[start:start+batch_size]
        batch_metas = metas[start:start+batch_size]
        embeddings = embedder.encode(batch_docs, show_progress_bar=False).tolist()
        col.add(documents=batch_docs, embeddings=embeddings, ids=batch_ids, metadatas=batch_metas)
        print(f"  {min(start+batch_size, len(docs))}/{len(docs)}", end="\r")

    print(f"\n[+] Dataset: {col.count()} findings indexed")
    return col.count()


def build_docs_index(client, embedder, force: bool = False) -> int:
    """Index all markdown/text/sol files from rag/knowledge/."""
    col = _get_collection(client, "knowledge_docs")

    if not force and col.count() > 0:
        print(f"[+] Docs index already has {col.count()} chunks (use --rebuild to refresh)")
        return col.count()

    try:
        client.delete_collection("knowledge_docs")
    except Exception:
        pass
    col = client.create_collection("knowledge_docs")

    if not KNOWLEDGE_DIR.exists():
        print(f"[warn] Knowledge dir not found: {KNOWLEDGE_DIR}")
        return 0

    files = list(KNOWLEDGE_DIR.rglob("*.md")) + \
            list(KNOWLEDGE_DIR.rglob("*.txt")) + \
            list(KNOWLEDGE_DIR.rglob("*.sol")) + \
            list(KNOWLEDGE_DIR.rglob("*.move"))

    if not files:
        print(f"[warn] No documents in {KNOWLEDGE_DIR}")
        print(f"       Add .md/.txt/.sol/.move files to rag/knowledge/ and re-run")
        return 0

    print(f"[+] Indexing {len(files)} knowledge files...")
    docs, ids, metas = [], [], []
    chunk_idx = 0

    for fpath in files:
        try:
            text = fpath.read_text(errors="ignore")
        except Exception:
            continue

        rel = fpath.relative_to(KNOWLEDGE_DIR)
        category = rel.parts[0] if len(rel.parts) > 1 else "general"
        chunks = _chunk_text(text)

        for j, chunk in enumerate(chunks):
            if len(chunk.strip()) < 50:
                continue
            docs.append(chunk)
            ids.append(f"doc_{chunk_idx}")
            metas.append({
                "source": "knowledge",
                "file": str(rel),
                "category": category,
                "chunk": j,
            })
            chunk_idx += 1

    if docs:
        embeddings = embedder.encode(docs, show_progress_bar=True).tolist()
        col.add(documents=docs, embeddings=embeddings, ids=ids, metadatas=metas)

    print(f"[+] Docs: {col.count()} chunks indexed from {len(files)} files")
    return col.count()


def search(query: str, k: int = 5, source: str = "both") -> list[dict]:
    """Search the index. source = 'dataset', 'knowledge', or 'both'."""
    client = chromadb.PersistentClient(path=str(INDEX_DIR))
    embedder = SentenceTransformer(EMBED_MODEL)
    qemb = embedder.encode([query]).tolist()

    results = []
    collections = []
    if source in ("dataset", "both"):
        try:
            collections.append(("dataset", client.get_collection("dataset_findings")))
        except Exception:
            pass
    if source in ("knowledge", "both"):
        try:
            collections.append(("knowledge", client.get_collection("knowledge_docs")))
        except Exception:
            pass

    for name, col in collections:
        if col.count() == 0:
            continue
        n = min(k, col.count())
        res = col.query(query_embeddings=qemb, n_results=n)
        for doc, meta, dist in zip(
            res["documents"][0], res["metadatas"][0], res["distances"][0]
        ):
            results.append({
                "source": name,
                "text": doc,
                "meta": meta,
                "score": round(1 - dist, 3),
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:k]


def format_rag_context(results: list[dict]) -> str:
    """Format search results as context block for the agent prompt."""
    if not results:
        return ""
    parts = ["### Retrieved Knowledge\n"]
    for i, r in enumerate(results):
        src = r["meta"].get("file", r["meta"].get("vuln_type", "finding"))
        parts.append(f"**[{i+1}] {src}** (score: {r['score']})\n{r['text']}\n")
    return "\n".join(parts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-only", action="store_true")
    parser.add_argument("--docs-only", action="store_true")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild even if index exists")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--search", metavar="QUERY", help="Test a search query")
    args = parser.parse_args()

    INDEX_DIR.mkdir(parents=True, exist_ok=True)

    if args.stats:
        client = chromadb.PersistentClient(path=str(INDEX_DIR))
        for name in ("dataset_findings", "knowledge_docs"):
            try:
                col = client.get_collection(name)
                print(f"  {name}: {col.count()} entries")
            except Exception:
                print(f"  {name}: not built yet")
        sys.exit(0)

    if args.search:
        results = search(args.search, k=3)
        if not results:
            print("No results — run build_index.py first")
        for r in results:
            print(f"\n[{r['source']}] score={r['score']} | {r['meta']}")
            print(r['text'][:400])
        sys.exit(0)

    client = chromadb.PersistentClient(path=str(INDEX_DIR))
    embedder = SentenceTransformer(EMBED_MODEL)
    print(f"[+] Embedding model: {EMBED_MODEL}")

    if not args.docs_only:
        build_dataset_index(client, embedder, force=args.rebuild)
    if not args.dataset_only:
        build_docs_index(client, embedder, force=args.rebuild)

    print(f"\n[+] Index ready at {INDEX_DIR}")
    print(f"    Test: python rag/build_index.py --search 'reentrancy delegatecall'")
