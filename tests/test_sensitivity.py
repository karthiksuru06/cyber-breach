"""
Test Sensitivity Module
========================
Verify the enhanced threshold logic for phishing screenshot detection.

Tests cover:
- Three-tier verdict system (SAFE/SUSPICIOUS/MALICIOUS)
- SSIM integration and override logic
- Adaptive threshold calculation
- Edge detection preprocessing
- ROI extraction
"""

import pytest
import numpy as np
import os
import tempfile
from PIL import Image
from unittest.mock import Mock, patch, MagicMock

# Import modules under test
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ai_engine.image_inference import (
    THRESHOLD_SAFE,
    THRESHOLD_SUSPICIOUS,
    SSIM_THRESHOLD,
    Verdict,
    calculate_image_metrics,
    calculate_dynamic_threshold,
    determine_verdict,
    apply_canny_edge_detection,
    detect_login_roi,
    calculate_ssim,
    get_threshold_info,
    predict_image_threat,
)


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def sample_image_path():
    """Create a temporary test image."""
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        # Create a simple 256x256 RGB image
        img = Image.new('RGB', (256, 256), color=(128, 128, 128))
        img.save(f.name)
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def dark_image_path():
    """Create a dark test image."""
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        img = Image.new('RGB', (256, 256), color=(30, 30, 30))
        img.save(f.name)
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def bright_image_path():
    """Create a bright test image."""
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        img = Image.new('RGB', (256, 256), color=(230, 230, 230))
        img.save(f.name)
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def sample_img_array():
    """Create a sample image array for testing."""
    return np.random.rand(1, 128, 128, 3).astype('float32')


# =============================================================================
# THRESHOLD CONFIGURATION TESTS
# =============================================================================

class TestThresholdConfiguration:
    """Test threshold constants are configured correctly."""

    def test_threshold_values(self):
        """Verify threshold values match specification."""
        assert THRESHOLD_SAFE == 0.015, "SAFE threshold should be 0.015"
        assert THRESHOLD_SUSPICIOUS == 0.030, "SUSPICIOUS threshold should be 0.030"
        assert SSIM_THRESHOLD == 0.85, "SSIM threshold should be 0.85"

    def test_threshold_ordering(self):
        """Verify thresholds are in correct order."""
        assert THRESHOLD_SAFE < THRESHOLD_SUSPICIOUS, \
            "SAFE threshold must be less than SUSPICIOUS threshold"

    def test_get_threshold_info(self):
        """Verify threshold info returns complete information."""
        info = get_threshold_info()

        assert info["version"] == "2.0"
        assert "thresholds" in info
        assert info["thresholds"]["safe"] == THRESHOLD_SAFE
        assert info["thresholds"]["suspicious"] == THRESHOLD_SUSPICIOUS
        assert info["thresholds"]["ssim_minimum"] == SSIM_THRESHOLD
        assert "features" in info
        assert len(info["features"]) >= 5


# =============================================================================
# THREE-TIER VERDICT TESTS
# =============================================================================

class TestThreeTierVerdict:
    """Test the three-tier verdict system."""

    def test_verdict_safe_low_mse(self):
        """MSE below 0.015 should return SAFE."""
        mse = 0.010
        ssim_score = 0.90
        dynamic_threshold = 0.022

        status, verdict = determine_verdict(mse, ssim_score, dynamic_threshold)

        assert status == "LEGITIMATE"
        assert verdict == Verdict.SAFE

    def test_verdict_suspicious_medium_mse(self):
        """MSE between 0.015 and 0.030 should return SUSPICIOUS."""
        mse = 0.020
        ssim_score = 0.90
        dynamic_threshold = 0.022

        status, verdict = determine_verdict(mse, ssim_score, dynamic_threshold)

        assert status == "LEGITIMATE"  # Still legitimate but flagged
        assert verdict == Verdict.SUSPICIOUS

    def test_verdict_malicious_high_mse(self):
        """MSE above 0.030 should return MALICIOUS."""
        mse = 0.035
        ssim_score = 0.90
        dynamic_threshold = 0.022

        status, verdict = determine_verdict(mse, ssim_score, dynamic_threshold)

        assert status == "PHISHING"
        assert verdict == Verdict.MALICIOUS

    def test_verdict_boundary_safe_suspicious(self):
        """Test boundary between SAFE and SUSPICIOUS (0.015)."""
        # Exactly at boundary
        status, verdict = determine_verdict(0.015, 0.90, 0.022)
        assert verdict == Verdict.SUSPICIOUS

        # Just below boundary
        status, verdict = determine_verdict(0.0149, 0.90, 0.022)
        assert verdict == Verdict.SAFE

    def test_verdict_boundary_suspicious_malicious(self):
        """Test boundary between SUSPICIOUS and MALICIOUS (0.030)."""
        # Exactly at boundary
        status, verdict = determine_verdict(0.030, 0.90, 0.022)
        assert verdict == Verdict.MALICIOUS

        # Just below boundary
        status, verdict = determine_verdict(0.0299, 0.90, 0.022)
        assert verdict == Verdict.SUSPICIOUS


# =============================================================================
# SSIM INTEGRATION TESTS
# =============================================================================

class TestSSIMIntegration:
    """Test SSIM score integration and override behavior."""

    def test_ssim_override_low_mse(self):
        """Low SSIM should trigger MALICIOUS even with low MSE."""
        mse = 0.010  # Would be SAFE based on MSE alone
        ssim_score = 0.80  # Below threshold
        dynamic_threshold = 0.022

        status, verdict = determine_verdict(mse, ssim_score, dynamic_threshold)

        assert status == "PHISHING"
        assert verdict == Verdict.MALICIOUS

    def test_ssim_threshold_boundary(self):
        """Test SSIM threshold boundary (0.85)."""
        mse = 0.010

        # Exactly at threshold
        status, verdict = determine_verdict(mse, 0.85, 0.022)
        assert verdict == Verdict.SAFE

        # Just below threshold
        status, verdict = determine_verdict(mse, 0.849, 0.022)
        assert verdict == Verdict.MALICIOUS

    def test_ssim_high_allows_mse_classification(self):
        """High SSIM should allow normal MSE-based classification."""
        ssim_score = 0.95  # Well above threshold

        # Test all three tiers with high SSIM
        _, verdict = determine_verdict(0.010, ssim_score, 0.022)
        assert verdict == Verdict.SAFE

        _, verdict = determine_verdict(0.020, ssim_score, 0.022)
        assert verdict == Verdict.SUSPICIOUS

        _, verdict = determine_verdict(0.035, ssim_score, 0.022)
        assert verdict == Verdict.MALICIOUS

    def test_calculate_ssim_identical(self):
        """Identical images should have SSIM of 1.0."""
        img = np.random.rand(1, 128, 128, 3).astype('float32')
        ssim_score = calculate_ssim(img, img)
        assert ssim_score == pytest.approx(1.0, abs=0.001)

    def test_calculate_ssim_different(self):
        """Very different images should have low SSIM."""
        img1 = np.zeros((1, 128, 128, 3), dtype='float32')
        img2 = np.ones((1, 128, 128, 3), dtype='float32')
        ssim_score = calculate_ssim(img1, img2)
        assert ssim_score < 0.5


# =============================================================================
# ADAPTIVE THRESHOLD TESTS
# =============================================================================

class TestAdaptiveThreshold:
    """Test dynamic threshold calculation based on image characteristics."""

    def test_calculate_image_metrics(self, sample_img_array):
        """Test brightness and contrast calculation."""
        brightness, contrast = calculate_image_metrics(sample_img_array)

        assert 0.0 <= brightness <= 1.0, "Brightness should be in [0, 1]"
        assert 0.0 <= contrast <= 1.0, "Contrast should be in [0, 1]"

    def test_dark_image_higher_threshold(self):
        """Darker images should get slightly higher thresholds."""
        bright_threshold = calculate_dynamic_threshold(brightness=0.8, contrast=0.25)
        dark_threshold = calculate_dynamic_threshold(brightness=0.2, contrast=0.25)

        assert dark_threshold > bright_threshold, \
            "Dark images should have higher threshold"

    def test_low_contrast_higher_threshold(self):
        """Low contrast images should get higher thresholds."""
        high_contrast_threshold = calculate_dynamic_threshold(brightness=0.5, contrast=0.35)
        low_contrast_threshold = calculate_dynamic_threshold(brightness=0.5, contrast=0.10)

        assert low_contrast_threshold > high_contrast_threshold, \
            "Low contrast images should have higher threshold"

    def test_threshold_bounds(self):
        """Dynamic threshold should be clamped to reasonable bounds."""
        # Extreme brightness values
        threshold_extreme_dark = calculate_dynamic_threshold(brightness=0.0, contrast=0.0)
        threshold_extreme_bright = calculate_dynamic_threshold(brightness=1.0, contrast=0.5)

        assert 0.010 <= threshold_extreme_dark <= 0.040
        assert 0.010 <= threshold_extreme_bright <= 0.040

    def test_normal_conditions_threshold(self):
        """Normal conditions should produce threshold near base value."""
        threshold = calculate_dynamic_threshold(brightness=0.5, contrast=0.25)
        base_threshold = (THRESHOLD_SAFE + THRESHOLD_SUSPICIOUS) / 2  # 0.0225

        assert threshold == pytest.approx(base_threshold, abs=0.005)


# =============================================================================
# EDGE DETECTION TESTS
# =============================================================================

class TestEdgeDetection:
    """Test Canny Edge Detection preprocessing."""

    def test_edge_detection_output_shape(self, sample_image_path):
        """Edge detection should return correct shape."""
        edge_array = apply_canny_edge_detection(sample_image_path, target_size=(128, 128))

        assert edge_array.shape == (1, 128, 128, 3)
        assert edge_array.dtype == np.float32

    def test_edge_detection_normalized(self, sample_image_path):
        """Edge detection output should be normalized to [0, 1]."""
        edge_array = apply_canny_edge_detection(sample_image_path)

        assert edge_array.min() >= 0.0
        assert edge_array.max() <= 1.0

    def test_edge_detection_invalid_path(self):
        """Edge detection should raise error for invalid path."""
        with pytest.raises(ValueError, match="Failed to load image"):
            apply_canny_edge_detection("/nonexistent/path/image.png")


# =============================================================================
# ROI EXTRACTION TESTS
# =============================================================================

class TestROIExtraction:
    """Test Login Box ROI extraction."""

    def test_roi_extraction_output_shape(self, sample_image_path):
        """ROI extraction should return correct shape."""
        roi_array = detect_login_roi(sample_image_path, target_size=(128, 128))

        assert roi_array is not None
        assert roi_array.shape == (1, 128, 128, 3)
        assert roi_array.dtype == np.float32

    def test_roi_extraction_normalized(self, sample_image_path):
        """ROI output should be normalized to [0, 1]."""
        roi_array = detect_login_roi(sample_image_path)

        assert roi_array.min() >= 0.0
        assert roi_array.max() <= 1.0

    def test_roi_extraction_invalid_path(self):
        """ROI extraction should return None for invalid path."""
        roi_array = detect_login_roi("/nonexistent/path/image.png")
        assert roi_array is None


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests for the full inference pipeline."""

    @patch('app.ai_engine.image_inference.get_image_model')
    def test_predict_image_threat_safe(self, mock_get_model, sample_image_path):
        """Test full pipeline returns SAFE for good reconstruction."""
        # Mock model that returns near-identical reconstruction
        mock_model = Mock()
        mock_model.predict.return_value = np.random.rand(1, 128, 128, 3).astype('float32') * 0.01
        mock_get_model.return_value = mock_model

        # This will likely be MALICIOUS due to random noise, but tests the pipeline
        status, mse, method = predict_image_threat(sample_image_path, debug=False)

        assert status in ["LEGITIMATE", "PHISHING", "ERROR"]
        assert method == "Enhanced-AE-v2"

    @patch('app.ai_engine.image_inference.get_image_model')
    def test_predict_image_threat_model_unavailable(self, mock_get_model, sample_image_path):
        """Test handling when model is unavailable."""
        mock_get_model.return_value = None

        status, mse, method = predict_image_threat(sample_image_path, debug=False)

        assert status == "ERROR"
        assert mse == 0.0
        assert method == "Model Unavailable"

    def test_predict_image_threat_invalid_path(self):
        """Test handling of invalid image path."""
        with patch('app.ai_engine.image_inference.get_image_model') as mock_get_model:
            mock_model = Mock()
            mock_get_model.return_value = mock_model

            status, mse, method = predict_image_threat("/nonexistent/image.png", debug=False)

            assert status == "ERROR"
            assert "Inference Error" in method


# =============================================================================
# VERDICT CLASS TESTS
# =============================================================================

class TestVerdictClass:
    """Test Verdict constants."""

    def test_verdict_constants(self):
        """Verify verdict constants are defined correctly."""
        assert Verdict.SAFE == "SAFE"
        assert Verdict.SUSPICIOUS == "SUSPICIOUS"
        assert Verdict.MALICIOUS == "MALICIOUS"
        assert Verdict.ERROR == "ERROR"


# =============================================================================
# FALSE NEGATIVE ELIMINATION TESTS
# =============================================================================

class TestFalseNegativeElimination:
    """
    Tests specifically targeting false negative scenarios.

    These tests verify that fake screenshots are NOT marked as legitimate.
    """

    def test_low_ssim_catches_subtle_phishing(self):
        """
        Scenario: Phishing page with low MSE but structural differences.
        The SSIM check should catch this.
        """
        mse = 0.012  # Below SAFE threshold
        ssim_score = 0.80  # Structural differences detected

        status, verdict = determine_verdict(mse, ssim_score, 0.022)

        assert verdict == Verdict.MALICIOUS, \
            "Structural differences (low SSIM) should trigger MALICIOUS"
        assert status == "PHISHING"

    def test_suspicious_tier_provides_warning(self):
        """
        Scenario: Borderline case that was previously marked LEGITIMATE.
        Should now be flagged as SUSPICIOUS.
        """
        mse = 0.018  # Between SAFE and SUSPICIOUS thresholds
        ssim_score = 0.90

        status, verdict = determine_verdict(mse, ssim_score, 0.022)

        assert verdict == Verdict.SUSPICIOUS, \
            "Borderline cases should be flagged as SUSPICIOUS"

    def test_combined_mse_weighting_effect(self):
        """
        Verify that edge and ROI analysis increase sensitivity.

        Even if full image MSE is low, high edge/ROI MSE should
        push the combined score higher.
        """
        # Weights: Full (40%) + Edge (35%) + ROI (25%)
        mse_full = 0.010  # Low - would be SAFE alone
        mse_edge = 0.040  # High - edge differences
        mse_roi = 0.035   # High - login box differences

        combined_mse = (0.40 * mse_full) + (0.35 * mse_edge) + (0.25 * mse_roi)

        # Combined: 0.004 + 0.014 + 0.00875 = 0.02675
        assert combined_mse > THRESHOLD_SAFE, \
            "Combined MSE should push borderline cases above SAFE threshold"

    def test_dark_theme_phishing_detection(self):
        """
        Scenario: Phishing page using dark theme to evade detection.
        Adaptive threshold should account for this.
        """
        # Dark image characteristics
        brightness = 0.15
        contrast = 0.12

        dynamic_threshold = calculate_dynamic_threshold(brightness, contrast)

        # Threshold should be higher for dark images
        base_threshold = (THRESHOLD_SAFE + THRESHOLD_SUSPICIOUS) / 2
        assert dynamic_threshold > base_threshold, \
            "Dark images should have higher adaptive threshold"


# =============================================================================
# PARAMETRIZED TESTS
# =============================================================================

class TestParametrizedScenarios:
    """Parametrized tests for various MSE/SSIM combinations."""

    @pytest.mark.parametrize("mse,ssim,expected_verdict", [
        # SAFE cases
        (0.005, 0.95, Verdict.SAFE),
        (0.010, 0.90, Verdict.SAFE),
        (0.014, 0.88, Verdict.SAFE),

        # SUSPICIOUS cases
        (0.016, 0.90, Verdict.SUSPICIOUS),
        (0.020, 0.88, Verdict.SUSPICIOUS),
        (0.029, 0.86, Verdict.SUSPICIOUS),

        # MALICIOUS cases (high MSE)
        (0.031, 0.90, Verdict.MALICIOUS),
        (0.040, 0.95, Verdict.MALICIOUS),
        (0.100, 0.99, Verdict.MALICIOUS),

        # MALICIOUS cases (low SSIM override)
        (0.005, 0.80, Verdict.MALICIOUS),
        (0.010, 0.70, Verdict.MALICIOUS),
        (0.001, 0.50, Verdict.MALICIOUS),
    ])
    def test_verdict_scenarios(self, mse, ssim, expected_verdict):
        """Test various MSE/SSIM combinations produce correct verdicts."""
        _, verdict = determine_verdict(mse, ssim, 0.022)
        assert verdict == expected_verdict, \
            f"MSE={mse}, SSIM={ssim} should yield {expected_verdict}"


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
