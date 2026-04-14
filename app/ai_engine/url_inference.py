"""
URL Threat Inference Module
============================
Multi-layered URL analysis combining heuristics, reputation, and neural networks.
"""

import numpy as np
from tensorflow.keras.preprocessing.sequence import pad_sequences
from typing import Tuple, Dict

from app.utils import is_whitelisted, check_domain_reputation, validate_url, check_local_threat
from app.ai_engine.model_loader import get_url_model, get_tokenizer


def predict_url_threat(url: str) -> Tuple[str, float, str, Dict]:
    """
    Analyze URL for threats using hybrid intelligence.

    Args:
        url: URL string to analyze

    Returns:
        Tuple of (status, confidence, method, metadata)
            - status: "SAFE", "MALICIOUS", "INVALID", or "ERROR"
            - confidence: Confidence score (0-100)
            - method: Analysis method used
            - metadata: Additional information

    Analysis Layers:
        Layer 1: Authority Whitelist (Heuristic)
        Layer 2: Local Threat Intelligence (CSV)
        Layer 3: Domain Reputation (WHOIS)
        Layer 4: Neural Analysis (LSTM)
    """

    # Validation
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        return "INVALID", 0.0, "Validation Failed", {"error": error_msg}

    # LAYER 1: Authority Whitelist Check
    if is_whitelisted(url):
        return "SAFE", 99.9, "Heuristic Whitelist", {
            "reason": "Authority Domain",
            "org": "Fortune 500 / Big Tech"
        }

    # LAYER 2: Local Threat Intelligence (CSV)
    found, threat_type = check_local_threat(url)
    if found:
        return "MALICIOUS", 100.0, "Local Intelligence", {
            "reason": "Matched local threat database",
            "category": threat_type,
            "source": "Local Threat CSV"
        }

    # LAYER 3: Domain Reputation Check (WHOIS)
    is_safe, confidence, metadata = check_domain_reputation(url)
    if is_safe:
        return "SAFE", confidence, "Domain Reputation", metadata

    # LAYER 4: Neural Analysis (LSTM)
    return _neural_url_analysis(url)


def _neural_url_analysis(url: str) -> Tuple[str, float, str, Dict]:
    """
    Perform neural network analysis on URL.

    Returns:
        Tuple of (status, confidence, method, metadata)
    """
    url_model = get_url_model()
    tokenizer = get_tokenizer()

    # Check model availability
    if not url_model or not tokenizer:
        return "ERROR", 0.0, "Neural Model Unavailable", {
            "fallback": "Models not loaded",
            "recommendation": "Verify model files exist"
        }

    try:
        # Tokenize URL (character-level)
        sequences = tokenizer.texts_to_sequences([url])

        # Pad to fixed length (200 characters). Must use 'pre' padding to match train_lstm.py defaults
        padded = pad_sequences(sequences, maxlen=200, padding='pre')

        # LSTM Inference
        raw_score = float(url_model.predict(padded, verbose=0)[0][0])

        # Determine verdict based on confidence bounds
        if raw_score > 0.8:
            status = "MALICIOUS"
        elif raw_score > 0.35:
            status = "SUSPICIOUS"
        else:
            status = "SAFE"

        # Calculate confidence (distance from decision boundary)
        confidence = float(max(raw_score, 1 - raw_score))
        confidence_pct = min(99.9, confidence * 100)  # Cap at 99.9%

        metadata = {
            "raw_score": round(raw_score, 6),
            "model": "LSTM Bi-RNN",
            "features": "Character-level sequences"
        }

        return status, round(confidence_pct, 2), "Neural Analysis (LSTM)", metadata

    except Exception as e:
        return "ERROR", 0.0, "Inference Error", {"error": str(e)}


def batch_predict_urls(urls: list) -> list:
    """
    Batch inference for multiple URLs (more efficient).

    Args:
        urls: List of URL strings

    Returns:
        List of prediction tuples
    """
    return [predict_url_threat(url) for url in urls]
