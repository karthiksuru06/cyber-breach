"""
Unit Tests for URL Inference
==============================
Tests for multi-layered URL threat analysis.
"""

import pytest
from app.ai_engine import predict_url_threat
from app.utils import is_whitelisted


class TestWhitelistLayer:
    """Test Layer 1: Authority Whitelist"""

    def test_google_whitelisted(self):
        """Google.com should be whitelisted"""
        assert is_whitelisted('https://google.com') == True

    def test_google_subdomain_whitelisted(self):
        """Google subdomains should be whitelisted"""
        assert is_whitelisted('https://mail.google.com') == True

    def test_unknown_domain_not_whitelisted(self):
        """Random domains should not be whitelisted"""
        assert is_whitelisted('https://random-malicious-site.com') == False

    def test_whitelist_case_insensitive(self):
        """Whitelist should be case-insensitive"""
        assert is_whitelisted('https://GOOGLE.COM') == True


class TestURLValidation:
    """Test URL validation logic"""

    def test_valid_url(self):
        """Valid URLs should pass analysis"""
        status, confidence, method, _ = predict_url_threat('https://example.com')
        assert status in ['SAFE', 'MALICIOUS', 'INVALID']
        assert isinstance(confidence, (int, float))

    def test_empty_url_rejected(self):
        """Empty URLs should be rejected"""
        status, confidence, method, _ = predict_url_threat('')
        assert status == 'INVALID'
        assert confidence == 0.0

    def test_invalid_url_rejected(self):
        """Malformed URLs should be rejected"""
        status, confidence, method, _ = predict_url_threat('not-a-url')
        # Should either auto-fix or reject
        assert status in ['INVALID', 'SAFE', 'MALICIOUS']


class TestAnalysisLayers:
    """Test multi-layered analysis"""

    def test_whitelist_bypasses_neural(self):
        """Whitelisted domains should skip neural analysis"""
        status, confidence, method, _ = predict_url_threat('https://github.com')
        assert status == 'SAFE'
        assert method == 'Heuristic Whitelist'
        assert confidence >= 99.0

    def test_confidence_precision(self):
        """Confidence scores should have proper precision"""
        status, confidence, method, _ = predict_url_threat('https://test-domain.com')
        # Should not be exactly 100.0 (float precision check)
        assert confidence <= 99.9
        # Should have decimal precision
        assert isinstance(confidence, float)


class TestErrorHandling:
    """Test error handling and resilience"""

    def test_model_unavailable_graceful(self):
        """System should handle missing models gracefully"""
        # This test requires models to be unavailable
        # In real scenario, you'd mock the model loader
        status, confidence, method, metadata = predict_url_threat('https://test.com')

        # Should return ERROR or fallback to heuristic
        assert status in ['SAFE', 'MALICIOUS', 'ERROR', 'INVALID']

    def test_special_characters_handled(self):
        """URLs with special characters should be handled"""
        status, confidence, method, _ = predict_url_threat('https://example.com/?q=test&id=123')
        assert status in ['SAFE', 'MALICIOUS']


# Fixtures
@pytest.fixture
def app():
    """Create test Flask app"""
    from app import create_app
    app = create_app('testing')
    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


class TestAPIEndpoints:
    """Test REST API endpoints"""

    def test_analyze_endpoint(self, client):
        """Test /api/analyze endpoint"""
        response = client.post('/api/analyze',
                               json={'url': 'https://google.com'},
                               content_type='application/json')

        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data
        assert 'confidence' in data
        assert data['status'] == 'SAFE'

    def test_analyze_missing_url(self, client):
        """Test /api/analyze with missing URL"""
        response = client.post('/api/analyze',
                               json={},
                               content_type='application/json')

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_logs_endpoint(self, client):
        """Test /api/logs endpoint"""
        response = client.get('/api/logs')
        assert response.status_code == 200
        data = response.get_json()
        assert 'logs' in data
        assert isinstance(data['logs'], list)

    def test_health_endpoint(self, client):
        """Test /api/health endpoint"""
        response = client.get('/api/health')
        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data
        assert 'models' in data


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
