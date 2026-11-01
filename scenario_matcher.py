"""Hybrid lexical and multilingual semantic search over curated scam examples."""

import unicodedata
from functools import lru_cache

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from rapidfuzz import fuzz

from scam_corpus import get_reference_rows

MODEL_NAME = "intfloat/multilingual-e5-small"
_SEMANTIC_DISABLED = False
_SEMANTIC_ERROR = ""


def _fold(text):
    decomposed = unicodedata.normalize("NFD", str(text).lower())
    plain = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return plain.replace("đ", "d")


def _word_text(text):
    try:
        from underthesea import word_tokenize
        return word_tokenize(text, format="text")
    except Exception:
        # Whitespace tokenization still works; char n-grams below provide a
        # second path for misspellings, spacing, and joined Vietnamese syllables.
        return text


@lru_cache(maxsize=1)
def _lexical_index():
    rows = get_reference_rows()
    texts = [row["text"] for row in rows]
    word_vectorizer = TfidfVectorizer(
        lowercase=True,
        tokenizer=lambda text: _word_text(text).split(),
        token_pattern=None,
        ngram_range=(1, 2),
        sublinear_tf=True,
    )
    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb", preprocessor=_fold,
        ngram_range=(2, 5), min_df=1, sublinear_tf=True,
    )
    return (
        rows,
        word_vectorizer.fit_transform(texts),
        word_vectorizer,
        char_vectorizer.fit_transform(texts),
        char_vectorizer,
    )


@lru_cache(maxsize=1)
def _semantic_index():
    """Load multilingual E5 once; first use downloads model weights if absent."""
    from sentence_transformers import SentenceTransformer

    rows = get_reference_rows()
    model = SentenceTransformer(MODEL_NAME, device="cpu")
    passages = ["passage: " + row["text"] for row in rows]
    embeddings = model.encode(
        passages, normalize_embeddings=True, convert_to_numpy=True,
        show_progress_bar=False, batch_size=16,
    )
    return model, embeddings


def compare_to_scenarios(text, top_k=3):
    """Find nearest labeled references; similarity is not a fraud probability."""
    global _SEMANTIC_DISABLED, _SEMANTIC_ERROR
    rows, word_matrix, word_vectorizer, char_matrix, char_vectorizer = _lexical_index()
    word_query = word_vectorizer.transform([text])
    char_query = char_vectorizer.transform([_fold(text)])
    word_scores = cosine_similarity(word_query, word_matrix).ravel()
    char_scores = cosine_similarity(char_query, char_matrix).ravel()
    fuzzy_scores = np.asarray([
        fuzz.token_set_ratio(_fold(text), _fold(row["text"])) / 100
        for row in rows
    ])
    lexical_scores = .58 * word_scores + .27 * char_scores + .15 * fuzzy_scores

    semantic_scores = None
    if not _SEMANTIC_DISABLED:
        try:
            model, reference_embeddings = _semantic_index()
            query_embedding = model.encode(
                ["query: " + text], normalize_embeddings=True,
                convert_to_numpy=True, show_progress_bar=False,
            )[0]
            semantic_scores = reference_embeddings @ query_embedding
        except Exception as error:
            _SEMANTIC_DISABLED = True
            _SEMANTIC_ERROR = str(error).splitlines()[0][:220]

    if semantic_scores is not None:
        scores = .68 * semantic_scores + .22 * word_scores + .07 * char_scores + .03 * fuzzy_scores
        method = "Ngữ nghĩa E5 + TF-IDF tiếng Việt + ký tự/fuzzy"
    else:
        scores = lexical_scores
        method = "TF-IDF tiếng Việt + n-gram ký tự + RapidFuzz (dự phòng)"

    # Collapse paraphrases to scenario-level scores so one scenario does not
    # occupy all three result rows just because it has multiple references.
    best_by_scenario = {}
    for index, row in enumerate(rows):
        score = float(scores[index])
        old = best_by_scenario.get(row["scenario_id"])
        if old is None or score > old["similarity"]:
            best_by_scenario[row["scenario_id"]] = {
                "scenario_id": row["scenario_id"],
                "title": row["title"],
                "label": row["label"],
                "reference": row["text"],
                "similarity": score,
            }
    matches = sorted(best_by_scenario.values(), key=lambda item: item["similarity"], reverse=True)[:top_k]
    return {
        "matches": matches,
        "method": method,
        "semantic_available": semantic_scores is not None,
        "semantic_error": _SEMANTIC_ERROR,
    }
