"""
WHOIS Domain Reputation Module (v2.0)
======================================
Enriches threat intelligence with domain age and registrar reputation.

Strategy: Domains > 5 years old with reputable registrars are statistically safe.
Threat actors typically use newly registered domains for attacks.

v2.0 Updates:
- LRU Cache for WHOIS lookups (reduces latency for repeated scans)
- Enhanced metadata extraction
- Suspicious registrar detection
- Cache statistics API
"""

import whois
import datetime
from functools import lru_cache
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict
from dataclasses import dataclass


# =============================================================================
# CONFIGURATION
# =============================================================================

# Statistical Thresholds
DOMAIN_AGE_THRESHOLD_DAYS = 1825  # 5 years
REPUTATION_CONFIDENCE = 95.0

# Suspicious indicators
SUSPICIOUS_AGE_DAYS = 30  # Domains younger than this are suspicious
VERY_SUSPICIOUS_AGE_DAYS = 7  # Domains younger than this are very suspicious

# Cache configuration
WHOIS_CACHE_SIZE = 256  # Maximum cached entries

# Known suspicious registrars (commonly used for phishing)
SUSPICIOUS_REGISTRARS = {
    'namecheap',
    'namesilo',
    'porkbun',
    'freenom',
    'dynadot',
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class WHOISResult:
    """Structured WHOIS lookup result."""
    domain: str
    registrar: Optional[str]
    creation_date: Optional[datetime.datetime]
    expiration_date: Optional[datetime.datetime]
    age_days: Optional[int]
    age_years: Optional[int]
    is_established: bool
    is_suspicious: bool
    suspicion_reasons: list
    raw_data: Dict


# =============================================================================
# CORE FUNCTIONS
# =============================================================================

def extract_domain(url: str) -> Optional[str]:
    """
    Extract clean domain from URL.

    Args:
        url: Full URL

    Returns:
        Clean domain string or None if invalid
    """
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        domain = parsed.netloc.lower().replace('www.', '')
        return domain if domain else None
    except:
        return None


@lru_cache(maxsize=WHOIS_CACHE_SIZE)
def _cached_whois_lookup(domain: str) -> Tuple[bool, str]:
    """
    Cached WHOIS lookup.

    This is the actual lookup function that gets cached.
    Returns serialized data to allow caching.

    Args:
        domain: Domain to lookup

    Returns:
        Tuple of (success, serialized_result_or_error)
    """
    try:
        w = whois.whois(domain)

        # Extract key fields
        result = {
            "registrar": w.registrar or "Unknown",
            "creation_date": None,
            "expiration_date": None,
            "name_servers": w.name_servers if hasattr(w, 'name_servers') else None,
            "status": w.status if hasattr(w, 'status') else None,
            "org": w.org if hasattr(w, 'org') else None,
        }

        # Handle creation_date (can be list or single value)
        if w.creation_date:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(creation, datetime.datetime):
                result["creation_date"] = creation.isoformat()

        # Handle expiration_date
        if w.expiration_date:
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if isinstance(expiration, datetime.datetime):
                result["expiration_date"] = expiration.isoformat()

        import json
        return True, json.dumps(result)

    except Exception as e:
        return False, str(e)


def parse_whois_result(domain: str, success: bool, data: str) -> WHOISResult:
    """
    Parse cached WHOIS result into structured format.

    Args:
        domain: The domain that was looked up
        success: Whether lookup succeeded
        data: JSON string of result or error message

    Returns:
        WHOISResult object
    """
    if not success:
        return WHOISResult(
            domain=domain,
            registrar=None,
            creation_date=None,
            expiration_date=None,
            age_days=None,
            age_years=None,
            is_established=False,
            is_suspicious=False,
            suspicion_reasons=[f"WHOIS lookup failed: {data}"],
            raw_data={"error": data}
        )

    import json
    result = json.loads(data)

    # Parse dates
    creation_date = None
    if result.get("creation_date"):
        creation_date = datetime.datetime.fromisoformat(result["creation_date"])

    expiration_date = None
    if result.get("expiration_date"):
        expiration_date = datetime.datetime.fromisoformat(result["expiration_date"])

    # Calculate age
    age_days = None
    age_years = None
    if creation_date:
        age_days = (datetime.datetime.now() - creation_date).days
        age_years = age_days // 365

    # Determine establishment status
    is_established = age_days is not None and age_days > DOMAIN_AGE_THRESHOLD_DAYS

    # Check for suspicious indicators
    suspicion_reasons = []
    is_suspicious = False

    # Age-based suspicion
    if age_days is not None:
        if age_days < VERY_SUSPICIOUS_AGE_DAYS:
            is_suspicious = True
            suspicion_reasons.append(f"Very new domain ({age_days} days old)")
        elif age_days < SUSPICIOUS_AGE_DAYS:
            is_suspicious = True
            suspicion_reasons.append(f"Recently registered ({age_days} days old)")

    # Registrar-based suspicion
    registrar = result.get("registrar", "").lower()
    for suspicious_reg in SUSPICIOUS_REGISTRARS:
        if suspicious_reg in registrar:
            is_suspicious = True
            suspicion_reasons.append(f"High-risk registrar pattern: {suspicious_reg}")
            break

    return WHOISResult(
        domain=domain,
        registrar=result.get("registrar"),
        creation_date=creation_date,
        expiration_date=expiration_date,
        age_days=age_days,
        age_years=age_years,
        is_established=is_established,
        is_suspicious=is_suspicious,
        suspicion_reasons=suspicion_reasons,
        raw_data=result
    )


def check_domain_reputation(url: str) -> Tuple[bool, float, Dict]:
    """
    Check domain reputation via WHOIS lookup with caching.

    Args:
        url: URL to check

    Returns:
        Tuple of (is_safe, confidence, metadata)
            - is_safe: True if domain passes reputation check
            - confidence: Confidence score (0-100)
            - metadata: WHOIS data (registrar, age, etc.)

    Logic:
        - Domain age > 5 years → SAFE (95% confidence)
        - Recent registration → Inconclusive (proceed to neural)
        - WHOIS error → Inconclusive (proceed to neural)
    """
    domain = extract_domain(url)
    if not domain:
        return False, 0.0, {"error": "Invalid domain"}

    # Perform cached WHOIS lookup
    success, data = _cached_whois_lookup(domain)

    # Parse result
    whois_result = parse_whois_result(domain, success, data)

    # Build metadata
    metadata = {
        "registrar": whois_result.registrar or "Unknown",
        "domain": domain,
        "cached": _cached_whois_lookup.cache_info().hits > 0
    }

    if whois_result.age_days is not None:
        metadata["age_days"] = whois_result.age_days
        metadata["age_years"] = whois_result.age_years

    if whois_result.is_suspicious:
        metadata["suspicion_reasons"] = whois_result.suspicion_reasons

    # Apply reputation rules
    if whois_result.is_established:
        metadata["verdict"] = f"Established domain ({whois_result.age_years}+ years)"
        return True, REPUTATION_CONFIDENCE, metadata

    # Recent domain - return suspicious info but don't mark as safe
    if whois_result.is_suspicious:
        metadata["verdict"] = "Suspicious domain characteristics"
        return False, 0.0, metadata

    # Inconclusive - proceed to neural analysis
    metadata["fallback"] = "Neural analysis"
    return False, 0.0, metadata


def get_whois_details(url: str) -> WHOISResult:
    """
    Get detailed WHOIS information for a URL.

    Args:
        url: URL to lookup

    Returns:
        WHOISResult with full details
    """
    domain = extract_domain(url)
    if not domain:
        return WHOISResult(
            domain=url,
            registrar=None,
            creation_date=None,
            expiration_date=None,
            age_days=None,
            age_years=None,
            is_established=False,
            is_suspicious=False,
            suspicion_reasons=["Invalid domain"],
            raw_data={}
        )

    success, data = _cached_whois_lookup(domain)
    return parse_whois_result(domain, success, data)


def format_reputation_response(is_safe: bool, confidence: float, metadata: Dict) -> Dict:
    """
    Format reputation check for API response.

    Returns:
        Formatted dictionary for logging/display
    """
    if is_safe:
        return {
            "status": "SAFE",
            "confidence": confidence,
            "method": "Domain Reputation",
            "details": metadata
        }
    return {
        "status": "INCONCLUSIVE",
        "confidence": 0.0,
        "method": "Reputation Check Failed",
        "details": metadata
    }


# =============================================================================
# CACHE MANAGEMENT API
# =============================================================================

def get_cache_stats() -> Dict:
    """
    Get WHOIS cache statistics.

    Returns:
        Dictionary with cache statistics
    """
    info = _cached_whois_lookup.cache_info()
    return {
        "hits": info.hits,
        "misses": info.misses,
        "size": info.currsize,
        "maxsize": info.maxsize,
        "hit_rate": round(info.hits / max(info.hits + info.misses, 1) * 100, 2)
    }


def clear_cache() -> Dict:
    """
    Clear the WHOIS cache.

    Returns:
        Cache stats before clearing
    """
    stats = get_cache_stats()
    _cached_whois_lookup.cache_clear()
    return {
        "cleared": True,
        "previous_stats": stats
    }


def warm_cache(domains: list) -> Dict:
    """
    Pre-populate cache with common domains.

    Args:
        domains: List of domains to lookup

    Returns:
        Summary of cache warming results
    """
    results = {"success": 0, "failed": 0, "domains": []}

    for domain in domains:
        try:
            success, _ = _cached_whois_lookup(domain)
            if success:
                results["success"] += 1
            else:
                results["failed"] += 1
            results["domains"].append({"domain": domain, "cached": success})
        except Exception as e:
            results["failed"] += 1
            results["domains"].append({"domain": domain, "error": str(e)})

    return results


# =============================================================================
# DEBUG UTILITIES
# =============================================================================

def print_whois_debug(url: str) -> None:
    """Print detailed WHOIS information for debugging."""
    result = get_whois_details(url)

    print(f"\n{'='*50}")
    print(f"[WHOIS] Domain Reputation Check")
    print(f"{'='*50}")
    print(f"  Domain        : {result.domain}")
    print(f"  Registrar     : {result.registrar or 'Unknown'}")
    print(f"  Created       : {result.creation_date or 'Unknown'}")
    print(f"  Expires       : {result.expiration_date or 'Unknown'}")
    print(f"  Age           : {result.age_years or '?'} years ({result.age_days or '?'} days)")
    print(f"  Established   : {'Yes' if result.is_established else 'No'}")
    print(f"  Suspicious    : {'Yes' if result.is_suspicious else 'No'}")

    if result.suspicion_reasons:
        print(f"\n  Suspicion Reasons:")
        for reason in result.suspicion_reasons:
            print(f"    - {reason}")

    print(f"\n  Cache Stats:")
    stats = get_cache_stats()
    print(f"    Hits: {stats['hits']} | Misses: {stats['misses']} | Size: {stats['size']}/{stats['maxsize']}")
    print(f"{'='*50}\n")
