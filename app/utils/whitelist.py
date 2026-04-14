"""
Authority Whitelist Module
===========================
Fortune 500 + Major Tech Infrastructure Domain Whitelist.

Purpose: Prevent false positives on trusted domains due to neural network bias.
"""

from urllib.parse import urlparse

# Global Authority Whitelist - Verified Top Domains
AUTHORITY_DOMAINS = {
    # Tech Giants
    'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'youtube.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'openai.com',

    # Developer Platforms
    'github.com', 'gitlab.com', 'stackoverflow.com', 'npmjs.com', 'geeksforgeeks.org', 
    'chatgpt.com', 'medium.com', 'dev.to',

    # Cloud & Infrastructure
    'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',

    # Enterprise SaaS
    'salesforce.com', 'slack.com', 'zoom.us', 'atlassian.com', 'dropbox.com',
    'notion.so', 'figma.com',

    # Financial & Payment
    'paypal.com', 'stripe.com', 'razorpay.com',

    # Media & Content
    'netflix.com', 'reddit.com', 'wikipedia.org', 'quora.com',

    # Security & Development
    'oracle.com', 'ibm.com', 'adobe.com', 'cisco.com',
}


def is_whitelisted(url: str) -> bool:
    """
    Check if domain is on authority whitelist.

    Args:
        url: Full URL or domain to check

    Returns:
        True if domain is whitelisted, False otherwise

    Example:
        >>> is_whitelisted('https://google.com/search?q=test')
        True
        >>> is_whitelisted('http://malicious-site.com')
        False
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower() if parsed.netloc else url.lower()

        # Remove 'www.' prefix for consistent matching
        domain = domain.replace('www.', '')

        # Check exact match
        if domain in AUTHORITY_DOMAINS:
            return True

        # Check if any whitelisted domain is a suffix (handles subdomains)
        for trusted_domain in AUTHORITY_DOMAINS:
            if domain.endswith(f'.{trusted_domain}') or domain == trusted_domain:
                return True

        return False

    except Exception as e:
        print(f"Whitelist check error: {e}")
        return False


def get_whitelist_info(url: str) -> dict:
    """
    Get detailed whitelist information for logging.

    Returns:
        Dictionary with whitelist metadata
    """
    if is_whitelisted(url):
        return {
            "status": "whitelisted",
            "reason": "Authority Domain",
            "org": "Fortune 500 / Big Tech"
        }
    return {}
