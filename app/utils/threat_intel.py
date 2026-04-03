"""
Local Threat Intelligence Layer
================================
CSV-backed threat lookup for O(1) URL matching against known malicious URLs.
Loaded once at startup, sits between Whitelist (Layer 1) and WHOIS (Layer 3).
"""

import os
import pandas as pd
from typing import Tuple, Optional, Dict

# Module-level threat database
_threat_db: Dict[str, str] = {}

# Label mapping
_LABEL_MAP = {
    'phishing': 'Phishing',
    'defacement': 'Defacement',
    'malware': 'Malware',
}


def _normalize_url(url: str) -> str:
    """Normalize URL for consistent lookup: strip protocol, trailing slash, lowercase."""
    url = url.strip().lower()
    for prefix in ('https://', 'http://'):
        if url.startswith(prefix):
            url = url[len(prefix):]
    return url.rstrip('/')


def load_threat_csv(csv_path: str) -> int:
    """
    Load malicious URL dataset from CSV into memory.

    Args:
        csv_path: Path to the CSV file (columns: url, type)

    Returns:
        Number of threat entries loaded
    """
    global _threat_db

    if not os.path.exists(csv_path):
        print(f"[THREAT INTEL] CSV not found: {csv_path}")
        return 0

    try:
        df = pd.read_csv(csv_path)

        # Keep only malicious rows
        malicious = df[df['type'].isin(['phishing', 'defacement', 'malware'])]

        # Build lookup dict: normalized URL -> threat type
        _threat_db = {
            _normalize_url(row['url']): row['type']
            for _, row in malicious.iterrows()
        }

        print(f"[THREAT INTEL] Loaded {len(_threat_db)} threats from CSV")
        return len(_threat_db)

    except Exception as e:
        print(f"[THREAT INTEL] Failed to load CSV: {e}")
        return 0


def check_local_threat(url: str) -> Tuple[bool, Optional[str]]:
    """
    Check URL against local threat intelligence database. O(1) lookup.

    Args:
        url: URL string to check

    Returns:
        (True, threat_label) if found, (False, None) otherwise.
        threat_label is one of: "Phishing", "Defacement", "Malware"
    """
    normalized = _normalize_url(url)
    raw_type = _threat_db.get(normalized)

    if raw_type:
        return True, _LABEL_MAP.get(raw_type, raw_type.capitalize())

    return False, None


def get_threat_db_stats() -> dict:
    """Return stats about the loaded threat database."""
    return {
        'loaded': len(_threat_db) > 0,
        'count': len(_threat_db),
    }
