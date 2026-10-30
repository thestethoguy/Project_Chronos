"""100% local, free, deterministic 768-dim text embeddings (no API keys, no model downloads).

Hashing trick over word 1-2-grams (semantic-ish keyword signal) plus a lighter char n-gram channel
(robust to node-id / hyphenation variants such as "pass-the-hash" vs "pass the hash").
The result is L2-normalised, so cosine similarity == dot product.
"""
from __future__ import annotations

import math

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer

EMBEDDING_DIM = 768
_CHAR_WEIGHT = 0.35

_word_vec = HashingVectorizer(
    n_features=EMBEDDING_DIM,
    norm="l2",
    alternate_sign=False,
    ngram_range=(1, 2),
    lowercase=True,
    stop_words="english",
    token_pattern=r"(?u)\b[a-zA-Z0-9_]{2,}\b",
)
_char_vec = HashingVectorizer(
    n_features=EMBEDDING_DIM,
    norm="l2",
    alternate_sign=False,
    analyzer="char_wb",
    ngram_range=(4, 5),
    lowercase=True,
)


def embed_text(text: str) -> list[float]:
    """Deterministic 768-dim L2-normalised vector for `text` (zero vector for empty input)."""
    text = (text or "").replace("-", " ")
    if not text.strip():
        return [0.0] * EMBEDDING_DIM
    vec = _word_vec.transform([text]).toarray()[0] + _CHAR_WEIGHT * _char_vec.transform([text]).toarray()[0]
    norm = float(np.linalg.norm(vec))
    if norm > 0:
        vec = vec / norm
    return [float(x) for x in vec]


def cosine_similarity_score(vec_a: list[float], vec_b: list[float]) -> float:
    """Cosine similarity in [-1, 1]; 0.0 if either vector is empty/zero or lengths differ."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    a, b = np.asarray(vec_a, dtype=float), np.asarray(vec_b, dtype=float)
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0.0 or math.isnan(denom):
        return 0.0
    return float(np.dot(a, b) / denom)
