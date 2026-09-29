import hashlib
import numpy as np
from typing import Protocol, List

class EmbeddingProvider(Protocol):
    """Protocol for embedding generation providers."""
    def embed(self, text: str) -> List[float]:
        """Generates a dense vector representation of input text."""
        ...

class DeterministicFixtureEmbedding:
    """Deterministic, non-semantic embedding generator for reproducible testbeds.
    
    Uses SHA-256 seed hashing to produce a stable 128-dimensional unit vector.
    This provides reproducible vector coordinates for testing vector indexing,
    graph traversal, and metadata pre-filtering without introducing external
    model download overhead or GPU requirements.
    
    NOTE: For semantic retrieval quality evaluation, plug in SentenceTransformerEmbedding.
    """

    def __init__(self, vector_dim: int = 128):
        self.vector_dim = vector_dim

    def embed(self, text: str) -> List[float]:
        h = hashlib.sha256(text.encode("utf-8")).digest()
        # Seed pseudo-random generator with first 4 bytes of hash
        seed = int.from_bytes(h[:4], "big")
        rng = np.random.RandomState(seed)
        vec = rng.normal(0.0, 1.0, self.vector_dim)
        norm = np.linalg.norm(vec)
        return (vec / norm).tolist() if norm > 0 else vec.tolist()
