"""
Deterministic, offline, dependency-free stand-in for the real
sentence-transformers model, used only in tests.

This is a simple hashed bag-of-words embedder: it exists purely so that
cosine similarity behaves *qualitatively* sensibly (identical text -> 1.0
similarity, texts sharing many words -> higher similarity, disjoint word
sets -> lower similarity) without requiring network access to download the
real embedding model. It is NOT a substitute for the real model in any
accuracy sense — only use it to test control flow and threshold logic, never
to draw conclusions about real detection quality.
"""

import numpy as np

_DIM = 256


class FakeEncoder:
    def encode(self, texts, **kwargs):
        single = isinstance(texts, str)
        if single:
            texts = [texts]
        vecs = []
        for t in texts:
            v = np.zeros(_DIM)
            for w in str(t).lower().split():
                v[hash(w) % _DIM] += 1.0
            norm = np.linalg.norm(v)
            if norm > 0:
                v = v / norm
            vecs.append(v)
        arr = np.array(vecs)
        return arr[0] if single else arr

    def eval(self):
        return self


def fake_get_model():
    return FakeEncoder()
