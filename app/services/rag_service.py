"""RAG service — indexes SentinelFlow documentation and retrieves relevant chunks at query time."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_CHUNK_MAX_WORDS = 350
_CHUNK_OVERLAP_WORDS = 40


def _word_count(text: str) -> int:
    return len(text.split())


def _chunk_section(title: str, body: str, source: str) -> list[dict]:
    """Split a section body into overlapping word-window chunks."""
    words = body.split()
    if not words:
        return []

    chunks: list[dict] = []
    start = 0
    while start < len(words):
        end = min(start + _CHUNK_MAX_WORDS, len(words))
        chunk_text = f"{title}\n\n" + " ".join(words[start:end])
        chunks.append({"text": chunk_text, "source": source, "section": title})
        if end == len(words):
            break
        start += _CHUNK_MAX_WORDS - _CHUNK_OVERLAP_WORDS

    return chunks


def _load_chunks(docs_dir: Path) -> list[dict]:
    """Load all .md files and split into semantically coherent chunks."""
    chunks: list[dict] = []
    for md_file in sorted(docs_dir.glob("*.md")):
        content = md_file.read_text(encoding="utf-8")
        source = md_file.name

        # Split on ## or ### headers
        sections = re.split(r"\n(?=#{1,3} )", content)
        for section in sections:
            lines = section.strip().splitlines()
            if not lines:
                continue
            # First line is the header (or file title if no header)
            title = lines[0].lstrip("#").strip()
            body = "\n".join(lines[1:]).strip()
            if not body:
                continue

            if _word_count(body) <= _CHUNK_MAX_WORDS:
                chunks.append({"text": f"{title}\n\n{body}", "source": source, "section": title})
            else:
                chunks.extend(_chunk_section(title, body, source))

    logger.info("Loaded %d chunks from %s", len(chunks), docs_dir)
    return chunks


def _docs_fingerprint(docs_dir: Path) -> str:
    """SHA-256 of all .md file contents — used to detect when docs change."""
    h = hashlib.sha256()
    for md_file in sorted(docs_dir.glob("*.md")):
        h.update(md_file.read_bytes())
    return h.hexdigest()


class RagService:
    """Singleton that embeds documentation chunks and retrieves relevant ones per query."""

    def __init__(self) -> None:
        self._ready = False
        self._collection = None  # chromadb.Collection
        self._fallback = False   # True when chromadb/embed not available

    async def initialize(self, docs_dir: Path, persist_dir: Path, embed_model: str, ollama_base_url: str) -> None:
        """Load docs, embed with nomic-embed-text, store in ChromaDB. Idempotent if docs unchanged."""
        try:
            import chromadb  # type: ignore[import]
        except ImportError:
            logger.warning("chromadb not installed — RAG disabled. Install with: pip install chromadb")
            self._fallback = True
            return

        if not docs_dir.exists():
            logger.warning("RAG docs directory %s not found — RAG disabled", docs_dir)
            self._fallback = True
            return

        fingerprint = _docs_fingerprint(docs_dir)
        persist_dir.mkdir(parents=True, exist_ok=True)
        fingerprint_file = persist_dir / "docs_fingerprint.json"

        client = chromadb.PersistentClient(path=str(persist_dir))
        collection = client.get_or_create_collection(
            name="sentinelflow_docs",
            metadata={"hnsw:space": "cosine"},
        )

        # Check if we can reuse the existing index
        stored_fp = None
        if fingerprint_file.exists():
            try:
                stored_fp = json.loads(fingerprint_file.read_text())
            except Exception:
                pass

        if stored_fp == fingerprint and collection.count() > 0:
            logger.info("RAG index up-to-date (%d chunks) — skipping re-indexing", collection.count())
            self._collection = collection
            self._ready = True
            return

        # (Re-)index
        chunks = _load_chunks(docs_dir)
        if not chunks:
            logger.warning("No documentation chunks found in %s — RAG disabled", docs_dir)
            self._fallback = True
            return

        logger.info("Embedding %d chunks with %s …", len(chunks), embed_model)
        embeddings: list[list[float]] = []
        for i, chunk in enumerate(chunks):
            embedding = await _embed(chunk["text"], embed_model, ollama_base_url)
            if embedding is None:
                logger.warning("RAG: embedding failed for chunk %d — falling back to no-RAG mode", i)
                self._fallback = True
                return
            embeddings.append(embedding)
            if (i + 1) % 10 == 0:
                logger.info("  Embedded %d/%d chunks", i + 1, len(chunks))

        ids = [f"chunk_{i}" for i in range(len(chunks))]
        documents = [c["text"] for c in chunks]
        metadatas = [{"source": c["source"], "section": c["section"]} for c in chunks]

        # Wipe and repopulate
        try:
            client.delete_collection("sentinelflow_docs")
        except Exception:
            pass
        collection = client.get_or_create_collection(
            name="sentinelflow_docs",
            metadata={"hnsw:space": "cosine"},
        )
        collection.upsert(ids=ids, embeddings=embeddings, documents=documents, metadatas=metadatas)
        fingerprint_file.write_text(json.dumps(fingerprint))

        logger.info("RAG index built: %d chunks from %s", len(chunks), docs_dir)
        self._collection = collection
        self._ready = True

    async def retrieve(self, query: str, top_k: int, embed_model: str, ollama_base_url: str) -> list[str]:
        """Return the top_k most relevant documentation chunks for the given query."""
        if self._fallback or not self._ready or self._collection is None:
            return []

        query_embedding = await _embed(query, embed_model, ollama_base_url)
        if query_embedding is None:
            return []

        try:
            results = self._collection.query(
                query_embeddings=[query_embedding],
                n_results=min(top_k, self._collection.count()),
            )
            docs: list[str] = results["documents"][0] if results["documents"] else []
            return docs
        except Exception as exc:
            logger.warning("RAG retrieval error: %s", exc)
            return []


async def _embed(text: str, model: str, ollama_base_url: str) -> list[float] | None:
    """Embed text using Ollama's /api/embeddings endpoint. Returns None on failure."""
    url = f"{ollama_base_url.rstrip('/')}/api/embeddings"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            response = await client.post(url, json={"model": model, "prompt": text})
            if response.is_error:
                logger.warning("Ollama embed returned HTTP %s", response.status_code)
                return None
            data = response.json()
            embedding = data.get("embedding")
            if not isinstance(embedding, list) or not embedding:
                logger.warning("Ollama embed returned unexpected shape: %s", list(data.keys()))
                return None
            return embedding
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        logger.warning("Ollama not reachable for embedding: %s", exc)
        return None
    except Exception as exc:
        logger.warning("Unexpected error during embedding: %s", exc)
        return None


# Module-level singleton
rag_service = RagService()
