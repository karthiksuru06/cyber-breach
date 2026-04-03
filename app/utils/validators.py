"""
Input Validation Module
========================
Validates user inputs before processing.
"""

from urllib.parse import urlparse
from typing import Tuple


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate URL format and structure.

    Args:
        url: URL string to validate

    Returns:
        Tuple of (is_valid, error_message)

    Security:
        - Prevents empty/null inputs
        - Ensures parseable URL structure
        - Auto-prepends http:// if missing scheme
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"

    url = url.strip()

    if len(url) > 2000:  # Sanity check
        return False, "URL exceeds maximum length (2000 characters)"

    try:
        # Auto-prepend scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        parsed = urlparse(url)

        # Must have a domain (netloc)
        if not parsed.netloc:
            return False, "Invalid URL: No domain found"

        # Basic format check
        if '.' not in parsed.netloc:
            return False, "Invalid URL: Domain must contain TLD"

        return True, ""

    except Exception as e:
        return False, f"URL parsing error: {str(e)}"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded file names.

    Args:
        filename: Original filename from upload

    Returns:
        Sanitized filename safe for filesystem

    Security:
        - Prevents directory traversal (../../etc/passwd)
        - Removes dangerous characters
        - Limits length
    """
    from werkzeug.utils import secure_filename
    return secure_filename(filename)[:100]  # Limit to 100 chars
