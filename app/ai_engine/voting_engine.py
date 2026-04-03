"""
Ensemble Voting Engine (XAI Module)
====================================
Multi-layer consensus system for transparent, explainable threat detection.

Features:
- SHAP-like feature attribution for URL analysis
- Ensemble voting across LSTM, WHOIS, and CSV layers
- Confidence-weighted consensus logic
- Top-3 suspicious feature extraction

Voting Rules:
1. MALICIOUS requires at least 2 layers to agree, OR
2. LSTM confidence > 90% (high-confidence override)
"""

import numpy as np
import re
import math
from typing import Dict, List, Tuple, Optional, NamedTuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse
from collections import Counter

from app.utils import is_whitelisted, check_local_threat
from app.utils.whois_checker import check_domain_reputation, extract_domain, clear_cache as _clear_whois_cache, get_cache_stats as _get_whois_stats
from app.ai_engine.model_loader import get_url_model, get_tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences


# =============================================================================
# CONFIGURATION
# =============================================================================

# Voting thresholds
LSTM_HIGH_CONFIDENCE_THRESHOLD = 0.90  # Override threshold for single-layer decision
CONSENSUS_MINIMUM_VOTES = 2            # Minimum votes required for MALICIOUS

# Feature attribution weights (simplified SHAP-like)
FEATURE_WEIGHTS = {
    "entropy": 0.15,
    "suspicious_tld": 0.20,
    "brand_impersonation": 0.25,
    "ip_address": 0.15,
    "excessive_subdomains": 0.10,
    "url_length": 0.08,
    "special_chars": 0.07,
}


# =============================================================================
# DATA CLASSES
# =============================================================================

class VoteType(Enum):
    """Enumeration of vote outcomes."""
    SAFE = "SAFE"
    MALICIOUS = "MALICIOUS"
    ABSTAIN = "ABSTAIN"  # Layer doesn't have enough info to vote


@dataclass
class LayerVote:
    """Represents a single layer's vote in the ensemble."""
    layer_name: str
    vote: VoteType
    confidence: float  # 0.0 - 1.0
    reason: str
    metadata: Dict = field(default_factory=dict)


@dataclass
class SuspiciousFeature:
    """Represents an extracted suspicious feature."""
    name: str
    description: str
    severity: float  # 0.0 - 1.0
    contribution: float  # SHAP-like contribution score


@dataclass
class EnsembleResult:
    """Complete result from ensemble voting."""
    final_verdict: str  # "SAFE", "MALICIOUS", "SUSPICIOUS"
    confidence: float
    votes: List[LayerVote]
    top_features: List[SuspiciousFeature]
    consensus_ratio: float
    explanation: str
    debug_info: Dict


# =============================================================================
# FEATURE EXTRACTION (SHAP-LIKE ATTRIBUTION)
# =============================================================================

class URLFeatureExtractor:
    """
    Extract and score suspicious features from URLs.
    Implements simplified SHAP-like feature attribution.
    """

    # Known suspicious TLDs (high phishing rates)
    SUSPICIOUS_TLDS = {
        '.xyz', '.top', '.club', '.work', '.click', '.link', '.gq', '.ml',
        '.cf', '.tk', '.ga', '.buzz', '.online', '.site', '.icu', '.vip',
        '.loan', '.win', '.download', '.racing', '.review', '.stream'
    }

    # Brand names commonly impersonated
    BRAND_KEYWORDS = {
        'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
        'facebook', 'instagram', 'linkedin', 'twitter', 'bank', 'chase',
        'wellsfargo', 'citibank', 'amex', 'visa', 'mastercard', 'dropbox',
        'icloud', 'outlook', 'office365', 'adobe', 'zoom', 'coinbase',
        'binance', 'crypto', 'wallet', 'secure', 'verify', 'update',
        'account', 'signin', 'login', 'confirm', 'suspended', 'locked'
    }

    # Phishing indicator patterns
    PHISHING_PATTERNS = [
        r'login.*verify', r'account.*suspend', r'secure.*update',
        r'confirm.*identity', r'unusual.*activity', r'verify.*now'
    ]

    def __init__(self, url: str):
        self.url = url
        self.parsed = urlparse(url if '://' in url else f'http://{url}')
        self.domain = self.parsed.netloc.lower()
        self.path = self.parsed.path.lower()
        self.full_url = f"{self.domain}{self.path}"

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        # Normalize to 0-1 scale (max entropy for URL chars is ~6)
        return min(entropy / 6.0, 1.0)

    def extract_features(self) -> List[SuspiciousFeature]:
        """
        Extract all suspicious features with SHAP-like contribution scores.

        Returns:
            List of SuspiciousFeature objects sorted by severity
        """
        features = []

        # 1. Character Entropy Check
        domain_entropy = self.calculate_entropy(self.domain)
        if domain_entropy > 0.7:
            features.append(SuspiciousFeature(
                name="High Character Entropy",
                description=f"Domain randomness score: {domain_entropy:.2f} (suspicious > 0.7)",
                severity=min(domain_entropy, 1.0),
                contribution=FEATURE_WEIGHTS["entropy"] * domain_entropy
            ))

        # 2. Suspicious TLD Check
        for tld in self.SUSPICIOUS_TLDS:
            if self.domain.endswith(tld):
                features.append(SuspiciousFeature(
                    name="Suspicious TLD",
                    description=f"Domain uses high-risk TLD: {tld}",
                    severity=0.85,
                    contribution=FEATURE_WEIGHTS["suspicious_tld"]
                ))
                break

        # 3. Brand Impersonation Detection
        impersonated_brands = [
            brand for brand in self.BRAND_KEYWORDS
            if brand in self.full_url
        ]
        if impersonated_brands:
            # Check if it's the legitimate domain
            legit_patterns = [f"{brand}.com" for brand in impersonated_brands]
            is_legit = any(pattern in self.domain for pattern in legit_patterns)

            if not is_legit:
                features.append(SuspiciousFeature(
                    name="Brand Impersonation Detected",
                    description=f"Contains brand keywords: {', '.join(impersonated_brands[:3])}",
                    severity=0.90,
                    contribution=FEATURE_WEIGHTS["brand_impersonation"]
                ))

        # 4. IP Address in URL
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, self.domain):
            features.append(SuspiciousFeature(
                name="IP Address in URL",
                description="URL uses IP address instead of domain name",
                severity=0.80,
                contribution=FEATURE_WEIGHTS["ip_address"]
            ))

        # 5. Excessive Subdomains
        subdomain_count = self.domain.count('.') - 1
        if subdomain_count >= 3:
            features.append(SuspiciousFeature(
                name="Excessive Subdomains",
                description=f"URL has {subdomain_count} subdomains (normal: 0-2)",
                severity=min(subdomain_count * 0.2, 0.8),
                contribution=FEATURE_WEIGHTS["excessive_subdomains"]
            ))

        # 6. Abnormal URL Length
        url_length = len(self.url)
        if url_length > 100:
            length_severity = min((url_length - 100) / 200, 1.0)
            features.append(SuspiciousFeature(
                name="Abnormal URL Length",
                description=f"URL length: {url_length} characters (suspicious > 100)",
                severity=length_severity,
                contribution=FEATURE_WEIGHTS["url_length"] * length_severity
            ))

        # 7. Special Characters Abuse
        special_chars = len(re.findall(r'[@%&=\-_~]', self.url))
        if special_chars > 5:
            char_severity = min(special_chars / 15, 1.0)
            features.append(SuspiciousFeature(
                name="Special Character Abuse",
                description=f"Contains {special_chars} special characters",
                severity=char_severity,
                contribution=FEATURE_WEIGHTS["special_chars"] * char_severity
            ))

        # 8. Phishing Pattern Matching
        for pattern in self.PHISHING_PATTERNS:
            if re.search(pattern, self.full_url):
                features.append(SuspiciousFeature(
                    name="Phishing Pattern Match",
                    description=f"URL matches known phishing pattern",
                    severity=0.85,
                    contribution=0.20
                ))
                break

        # 9. Homograph Attack Detection (mixed scripts)
        if self._detect_homograph():
            features.append(SuspiciousFeature(
                name="Homograph Attack",
                description="Domain contains mixed character scripts (IDN attack)",
                severity=0.95,
                contribution=0.25
            ))

        # Sort by severity descending
        features.sort(key=lambda f: f.severity, reverse=True)
        return features

    def _detect_homograph(self) -> bool:
        """Detect potential IDN homograph attacks."""
        try:
            # Check for punycode (xn--)
            if 'xn--' in self.domain:
                return True
            # Check for non-ASCII characters
            if not self.domain.isascii():
                return True
        except:
            pass
        return False

    def get_top_features(self, n: int = 3) -> List[SuspiciousFeature]:
        """Get top N most suspicious features."""
        all_features = self.extract_features()
        return all_features[:n]

    def calculate_total_risk_score(self) -> float:
        """
        Calculate aggregate risk score from all features.

        Returns:
            Risk score between 0.0 and 1.0
        """
        features = self.extract_features()
        if not features:
            return 0.0

        total_contribution = sum(f.contribution for f in features)
        # Normalize to 0-1 scale
        return min(total_contribution, 1.0)


# =============================================================================
# ENSEMBLE VOTING LAYERS
# =============================================================================

class EnsembleVoter:
    """
    Multi-layer ensemble voting system for URL threat detection.
    """

    def __init__(self, url: str):
        self.url = url
        self.feature_extractor = URLFeatureExtractor(url)
        self.votes: List[LayerVote] = []

    def _vote_whitelist_layer(self) -> LayerVote:
        """Layer 1: Authority Whitelist Check."""
        if is_whitelisted(self.url):
            return LayerVote(
                layer_name="Whitelist",
                vote=VoteType.SAFE,
                confidence=0.99,
                reason="Domain is in authority whitelist",
                metadata={"type": "Fortune 500 / Big Tech"}
            )
        return LayerVote(
            layer_name="Whitelist",
            vote=VoteType.ABSTAIN,
            confidence=0.0,
            reason="Domain not in whitelist"
        )

    def _vote_csv_layer(self) -> LayerVote:
        """Layer 2: Local Threat Intelligence (CSV)."""
        found, threat_type = check_local_threat(self.url)
        if found:
            return LayerVote(
                layer_name="Threat Intel (CSV)",
                vote=VoteType.MALICIOUS,
                confidence=1.0,
                reason=f"Matched threat database: {threat_type}",
                metadata={"category": threat_type}
            )
        return LayerVote(
            layer_name="Threat Intel (CSV)",
            vote=VoteType.ABSTAIN,
            confidence=0.0,
            reason="Not found in threat database"
        )

    def _cached_whois_check(self, domain: str) -> Tuple[bool, float, str]:
        """WHOIS lookup (caching handled by whois_checker module)."""
        is_safe, confidence, metadata = check_domain_reputation(domain)
        return is_safe, confidence, str(metadata)

    def _vote_whois_layer(self) -> LayerVote:
        """Layer 3: Domain Reputation (WHOIS) with LRU cache."""
        domain = extract_domain(self.url)
        if not domain:
            return LayerVote(
                layer_name="WHOIS Reputation",
                vote=VoteType.ABSTAIN,
                confidence=0.0,
                reason="Invalid domain"
            )

        try:
            is_safe, confidence, metadata_str = self._cached_whois_check(domain)

            if is_safe:
                return LayerVote(
                    layer_name="WHOIS Reputation",
                    vote=VoteType.SAFE,
                    confidence=confidence / 100.0,
                    reason="Established domain (5+ years)",
                    metadata={"cached": True}
                )

            # Check for suspiciously new domain
            # Parse age from metadata string if available
            if "age_days" in metadata_str:
                import ast
                metadata = ast.literal_eval(metadata_str)
                age_days = metadata.get("age_days", 365)
                if age_days < 30:
                    return LayerVote(
                        layer_name="WHOIS Reputation",
                        vote=VoteType.MALICIOUS,
                        confidence=0.75,
                        reason=f"Newly registered domain ({age_days} days old)",
                        metadata={"age_days": age_days}
                    )

            return LayerVote(
                layer_name="WHOIS Reputation",
                vote=VoteType.ABSTAIN,
                confidence=0.0,
                reason="Inconclusive WHOIS data"
            )

        except Exception as e:
            return LayerVote(
                layer_name="WHOIS Reputation",
                vote=VoteType.ABSTAIN,
                confidence=0.0,
                reason=f"WHOIS lookup failed: {str(e)}"
            )

    def _vote_lstm_layer(self) -> LayerVote:
        """Layer 4: Neural Analysis (LSTM)."""
        url_model = get_url_model()
        tokenizer = get_tokenizer()

        if not url_model or not tokenizer:
            return LayerVote(
                layer_name="LSTM Neural",
                vote=VoteType.ABSTAIN,
                confidence=0.0,
                reason="Model unavailable"
            )

        try:
            sequences = tokenizer.texts_to_sequences([self.url])
            padded = pad_sequences(sequences, maxlen=200, padding='post')
            raw_score = float(url_model.predict(padded, verbose=0)[0][0])

            # Convert to vote
            if raw_score > 0.5:
                confidence = raw_score
                vote = VoteType.MALICIOUS
                reason = f"Neural network detected threat (score: {raw_score:.3f})"
            else:
                confidence = 1 - raw_score
                vote = VoteType.SAFE
                reason = f"Neural network cleared URL (score: {raw_score:.3f})"

            return LayerVote(
                layer_name="LSTM Neural",
                vote=vote,
                confidence=confidence,
                reason=reason,
                metadata={"raw_score": raw_score}
            )

        except Exception as e:
            return LayerVote(
                layer_name="LSTM Neural",
                vote=VoteType.ABSTAIN,
                confidence=0.0,
                reason=f"Inference error: {str(e)}"
            )

    def _vote_feature_layer(self) -> LayerVote:
        """Layer 5: Feature Attribution (XAI)."""
        risk_score = self.feature_extractor.calculate_total_risk_score()
        top_features = self.feature_extractor.get_top_features(3)

        if risk_score > 0.5:
            return LayerVote(
                layer_name="Feature Analysis",
                vote=VoteType.MALICIOUS,
                confidence=risk_score,
                reason=f"Multiple suspicious features detected",
                metadata={
                    "risk_score": risk_score,
                    "top_features": [f.name for f in top_features]
                }
            )
        elif risk_score > 0.25:
            return LayerVote(
                layer_name="Feature Analysis",
                vote=VoteType.ABSTAIN,
                confidence=risk_score,
                reason="Some suspicious features present",
                metadata={"risk_score": risk_score}
            )
        else:
            return LayerVote(
                layer_name="Feature Analysis",
                vote=VoteType.SAFE,
                confidence=1 - risk_score,
                reason="No significant suspicious features",
                metadata={"risk_score": risk_score}
            )

    def collect_all_votes(self) -> List[LayerVote]:
        """Collect votes from all layers."""
        self.votes = [
            self._vote_whitelist_layer(),
            self._vote_csv_layer(),
            self._vote_whois_layer(),
            self._vote_lstm_layer(),
            self._vote_feature_layer(),
        ]
        return self.votes

    def calculate_consensus(self) -> EnsembleResult:
        """
        Apply consensus logic to determine final verdict.

        Rules:
        1. Whitelist SAFE → Immediate SAFE (authority override)
        2. CSV MALICIOUS → Immediate MALICIOUS (known threat)
        3. LSTM confidence > 90% → Follow LSTM verdict
        4. Otherwise: Require 2+ MALICIOUS votes for MALICIOUS verdict
        """
        if not self.votes:
            self.collect_all_votes()

        top_features = self.feature_extractor.get_top_features(3)

        # Rule 1: Whitelist authority override
        whitelist_vote = next((v for v in self.votes if v.layer_name == "Whitelist"), None)
        if whitelist_vote and whitelist_vote.vote == VoteType.SAFE:
            return EnsembleResult(
                final_verdict="SAFE",
                confidence=99.0,
                votes=self.votes,
                top_features=top_features,
                consensus_ratio=1.0,
                explanation="Domain is in trusted authority whitelist",
                debug_info={"override": "whitelist"}
            )

        # Rule 2: CSV threat match override
        csv_vote = next((v for v in self.votes if v.layer_name == "Threat Intel (CSV)"), None)
        if csv_vote and csv_vote.vote == VoteType.MALICIOUS:
            return EnsembleResult(
                final_verdict="MALICIOUS",
                confidence=100.0,
                votes=self.votes,
                top_features=top_features,
                consensus_ratio=1.0,
                explanation=f"URL matched known threat database: {csv_vote.metadata.get('category', 'Unknown')}",
                debug_info={"override": "csv_threat"}
            )

        # Rule 3: LSTM high-confidence override
        lstm_vote = next((v for v in self.votes if v.layer_name == "LSTM Neural"), None)
        if lstm_vote and lstm_vote.confidence > LSTM_HIGH_CONFIDENCE_THRESHOLD:
            verdict = "MALICIOUS" if lstm_vote.vote == VoteType.MALICIOUS else "SAFE"
            return EnsembleResult(
                final_verdict=verdict,
                confidence=lstm_vote.confidence * 100,
                votes=self.votes,
                top_features=top_features,
                consensus_ratio=1.0,
                explanation=f"High-confidence neural network verdict ({lstm_vote.confidence:.1%})",
                debug_info={"override": "lstm_high_confidence"}
            )

        # Rule 4: Consensus voting
        malicious_votes = [v for v in self.votes if v.vote == VoteType.MALICIOUS]
        safe_votes = [v for v in self.votes if v.vote == VoteType.SAFE]
        active_votes = [v for v in self.votes if v.vote != VoteType.ABSTAIN]

        malicious_count = len(malicious_votes)
        safe_count = len(safe_votes)
        total_active = len(active_votes)

        # Calculate weighted confidence
        if malicious_count >= CONSENSUS_MINIMUM_VOTES:
            avg_confidence = sum(v.confidence for v in malicious_votes) / malicious_count
            consensus_ratio = malicious_count / len(self.votes)

            return EnsembleResult(
                final_verdict="MALICIOUS",
                confidence=avg_confidence * 100,
                votes=self.votes,
                top_features=top_features,
                consensus_ratio=consensus_ratio,
                explanation=f"{malicious_count} layers agree: URL is malicious",
                debug_info={
                    "malicious_votes": malicious_count,
                    "safe_votes": safe_count,
                    "abstain_votes": len(self.votes) - total_active
                }
            )

        elif safe_count >= CONSENSUS_MINIMUM_VOTES:
            avg_confidence = sum(v.confidence for v in safe_votes) / safe_count
            consensus_ratio = safe_count / len(self.votes)

            return EnsembleResult(
                final_verdict="SAFE",
                confidence=avg_confidence * 100,
                votes=self.votes,
                top_features=top_features,
                consensus_ratio=consensus_ratio,
                explanation=f"{safe_count} layers agree: URL is safe",
                debug_info={
                    "malicious_votes": malicious_count,
                    "safe_votes": safe_count
                }
            )

        else:
            # No consensus - mark as SUSPICIOUS
            return EnsembleResult(
                final_verdict="SUSPICIOUS",
                confidence=50.0,
                votes=self.votes,
                top_features=top_features,
                consensus_ratio=0.0,
                explanation="Insufficient consensus between analysis layers",
                debug_info={
                    "malicious_votes": malicious_count,
                    "safe_votes": safe_count,
                    "abstain_votes": len(self.votes) - total_active
                }
            )


# =============================================================================
# PUBLIC API
# =============================================================================

def analyze_url_with_ensemble(url: str, debug: bool = True) -> EnsembleResult:
    """
    Analyze URL using ensemble voting with XAI explanations.

    Args:
        url: URL to analyze
        debug: Whether to print debug information

    Returns:
        EnsembleResult with verdict, confidence, votes, and top features
    """
    voter = EnsembleVoter(url)
    result = voter.calculate_consensus()

    if debug:
        print_ensemble_debug(result)

    return result


def get_top_suspicious_features(url: str, n: int = 3) -> List[Dict]:
    """
    Get top N suspicious features for UI display.

    Args:
        url: URL to analyze
        n: Number of features to return

    Returns:
        List of feature dictionaries for UI rendering
    """
    extractor = URLFeatureExtractor(url)
    features = extractor.get_top_features(n)

    return [
        {
            "name": f.name,
            "description": f.description,
            "severity": f"{'High' if f.severity > 0.7 else 'Medium' if f.severity > 0.4 else 'Low'}",
            "severity_score": round(f.severity, 2),
            "contribution": round(f.contribution, 3)
        }
        for f in features
    ]


def print_ensemble_debug(result: EnsembleResult) -> None:
    """Print detailed ensemble voting results."""
    COLORS = {
        "SAFE": "\033[92m",      # Green
        "MALICIOUS": "\033[91m", # Red
        "SUSPICIOUS": "\033[93m", # Yellow
        "RESET": "\033[0m"
    }

    color = COLORS.get(result.final_verdict, COLORS["RESET"])
    reset = COLORS["RESET"]

    print(f"\n{'='*70}")
    print(f"[ENSEMBLE] URL Threat Analysis - XAI Report")
    print(f"{'='*70}")

    print(f"\n  LAYER VOTES:")
    print(f"  {'-'*50}")
    for vote in result.votes:
        vote_color = COLORS.get(vote.vote.value, reset) if vote.vote != VoteType.ABSTAIN else ""
        vote_reset = reset if vote.vote != VoteType.ABSTAIN else ""
        print(f"  {vote.layer_name:20} | {vote_color}{vote.vote.value:10}{vote_reset} | {vote.confidence:.1%} | {vote.reason}")

    print(f"\n  TOP SUSPICIOUS FEATURES:")
    print(f"  {'-'*50}")
    if result.top_features:
        for i, feature in enumerate(result.top_features, 1):
            print(f"  {i}. {feature.name}")
            print(f"     {feature.description}")
            print(f"     Severity: {feature.severity:.2f} | Contribution: {feature.contribution:.3f}")
    else:
        print(f"  No suspicious features detected")

    print(f"\n  {'-'*50}")
    print(f"  FINAL VERDICT : {color}{result.final_verdict}{reset}")
    print(f"  CONFIDENCE    : {result.confidence:.1f}%")
    print(f"  CONSENSUS     : {result.consensus_ratio:.1%}")
    print(f"  EXPLANATION   : {result.explanation}")
    print(f"{'='*70}\n")


# =============================================================================
# WHOIS CACHE MANAGEMENT
# =============================================================================

def clear_whois_cache() -> None:
    """Clear the WHOIS LRU cache."""
    _clear_whois_cache()


def get_whois_cache_stats() -> Dict:
    """Get WHOIS cache statistics."""
    return _get_whois_stats()
