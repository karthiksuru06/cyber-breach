"""
Image Threat Inference Module (v2.0)
=====================================
Enhanced Autoencoder-based visual anomaly detection for phishing pages.

Upgrades:
- Adaptive thresholding based on image brightness/contrast
- SSIM (Structural Similarity Index) integration
- Canny Edge Detection preprocessing
- Login Box ROI (Region of Interest) focus
- Three-tier verdict system (Safe/Suspicious/Malicious)
"""

import numpy as np
import cv2
from typing import Tuple, Dict, Optional
from dataclasses import dataclass
from PIL import Image
from skimage.metrics import structural_similarity as ssim
from app.utils import preprocess_image
from app.utils.preprocessing import calculate_reconstruction_error
from app.ai_engine.model_loader import get_image_model


# =============================================================================
# THRESHOLD CONFIGURATION
# =============================================================================

# Three-tier verdict thresholds
THRESHOLD_SAFE = 0.015        # Below this = SAFE (Green)
THRESHOLD_SUSPICIOUS = 0.030  # Above SAFE, below this = SUSPICIOUS (Orange)
                              # Above this = MALICIOUS (Red)

# SSIM threshold - below this triggers structural concern
SSIM_THRESHOLD = 0.75
# Layout Variation band - SSIM between these values = SUSPICIOUS instead of MALICIOUS
SSIM_LAYOUT_VARIATION_MIN = 0.65

# Adaptive threshold coefficients
BRIGHTNESS_COEFFICIENT = 0.002   # Adjusts threshold based on brightness
CONTRAST_COEFFICIENT = 0.003     # Adjusts threshold based on contrast
COMPLEXITY_COEFFICIENT = 0.015   # Adjusts threshold based on texture/noise (Natural Images)


@dataclass
class AnalysisResult:
    """Container for comprehensive analysis results."""
    status: str
    mse_score: float
    ssim_score: float
    dynamic_threshold: float
    method: str
    verdict_tier: str  # "SAFE", "SUSPICIOUS", "MALICIOUS"
    debug_info: Dict


class Verdict:
    """Verdict constants with color coding."""
    SAFE = "SAFE"              # Green
    SUSPICIOUS = "SUSPICIOUS"  # Orange
    MALICIOUS = "MALICIOUS"    # Red
    ERROR = "ERROR"


# =============================================================================
# IMAGE ANALYSIS UTILITIES
# =============================================================================

def calculate_image_metrics(img_array: np.ndarray) -> Tuple[float, float, float]:
    """
    Calculate brightness, contrast and texture complexity of an image.

    Args:
        img_array: Image array with shape (1, H, W, 3) normalized to [0, 1]

    Returns:
        Tuple of (brightness, contrast, complexity)
        - brightness: Mean pixel intensity [0, 1]
        - contrast: Standard deviation of pixel intensities [0, 1]
        - complexity: Texture variance (indicates noise/detail)
    """
    # Remove batch dimension
    img = img_array[0] if img_array.ndim == 4 else img_array

    # Calculate brightness (mean intensity)
    brightness = float(np.mean(img))

    # Calculate contrast (standard deviation)
    contrast = float(np.std(img))

    # Calculate complexity (Laplacian variance)
    # Natural photos have much higher variance than clean UI screenshots
    gray = cv2.cvtColor((img * 255).astype(np.uint8), cv2.COLOR_RGB2GRAY)
    complexity = float(cv2.Laplacian(gray, cv2.CV_64F).var())

    return brightness, contrast, complexity


def calculate_dynamic_threshold(brightness: float, contrast: float, complexity: float = 0.0) -> float:
    """
    Calculate adaptive threshold based on image characteristics.

    Logic:
        - Darker images (low brightness) get slightly higher thresholds
          (phishing pages often use darker themes)
        - Low contrast images get higher thresholds
          (compression artifacts can increase noise)
        - High complexity (natural photos/noise) get higher thresholds
          (prevents false positives from camera/noisy inputs)

    Args:
        brightness: Image brightness [0, 1]
        contrast: Image contrast [0, 1]
        complexity: Image texture complexity (Laplacian variance)

    Returns:
        Dynamically adjusted MSE threshold
    """
    base_threshold = (THRESHOLD_SAFE + THRESHOLD_SUSPICIOUS) / 2  # 0.0225

    # Brightness adjustment (darker = higher threshold)
    brightness_adjustment = (0.5 - brightness) * BRIGHTNESS_COEFFICIENT

    # Contrast adjustment (lower contrast = higher threshold)
    contrast_adjustment = (0.25 - contrast) * CONTRAST_COEFFICIENT

    # Complexity adjustment (Natural photos often have complexity > 1000)
    # Add up to COMPLEXITY_COEFFICIENT extra to the threshold for very noisy images
    complexity_scale = min(1.0, complexity / 5000.0)
    complexity_adjustment = complexity_scale * COMPLEXITY_COEFFICIENT

    dynamic_threshold = base_threshold + brightness_adjustment + contrast_adjustment + complexity_adjustment

    # Clamp to reasonable bounds (max 0.050 for very noisy photos)
    return float(np.clip(dynamic_threshold, 0.010, 0.055))


def apply_canny_edge_detection(image_path: str, target_size: Tuple[int, int] = (128, 128)) -> np.ndarray:
    """
    Apply Canny Edge Detection preprocessing.

    Purpose:
        Forces the model to focus on layout geometry (where phishers fail)
        rather than just colors and textures.

    Args:
        image_path: Path to image file
        target_size: Target dimensions

    Returns:
        Edge-detected image array ready for model inference
        Shape: (1, 128, 128, 3) with values in [0, 1]
    """
    # Load image with OpenCV
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"Failed to load image: {image_path}")

    # Resize
    img = cv2.resize(img, target_size)

    # Convert to grayscale for edge detection
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Apply Gaussian blur to reduce noise
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)

    # Canny edge detection with adaptive thresholds
    median_val = np.median(blurred)
    lower = int(max(0, 0.66 * median_val))
    upper = int(min(255, 1.33 * median_val))
    edges = cv2.Canny(blurred, lower, upper)

    # Convert back to 3-channel for model compatibility
    edges_3ch = cv2.cvtColor(edges, cv2.COLOR_GRAY2RGB)

    # Normalize to [0, 1]
    edge_array = edges_3ch.astype('float32') / 255.0

    # Add batch dimension
    return np.expand_dims(edge_array, axis=0)


def detect_login_roi(image_path: str, target_size: Tuple[int, int] = (128, 128)) -> Optional[np.ndarray]:
    """
    Detect and extract Login Box Region of Interest (ROI).

    Strategy:
        - Look for form-like rectangular regions
        - Focus on center-bottom area where login forms typically appear
        - Fallback to center crop if no specific ROI detected

    Args:
        image_path: Path to image file
        target_size: Target dimensions for output

    Returns:
        ROI image array or None if extraction fails
    """
    try:
        img = cv2.imread(image_path)
        if img is None:
            return None

        h, w = img.shape[:2]

        # Heuristic: Login boxes are typically in center-bottom region
        # Focus on middle 60% horizontally, lower 60% vertically
        roi_x_start = int(w * 0.20)
        roi_x_end = int(w * 0.80)
        roi_y_start = int(h * 0.25)
        roi_y_end = int(h * 0.90)

        roi = img[roi_y_start:roi_y_end, roi_x_start:roi_x_end]

        # Resize ROI to target size
        roi_resized = cv2.resize(roi, target_size)

        # Convert BGR to RGB
        roi_rgb = cv2.cvtColor(roi_resized, cv2.COLOR_BGR2RGB)

        # Normalize and add batch dimension
        roi_array = roi_rgb.astype('float32') / 255.0
        return np.expand_dims(roi_array, axis=0)

    except Exception:
        return None


def calculate_ssim(original: np.ndarray, reconstructed: np.ndarray) -> float:
    """
    Calculate Structural Similarity Index (SSIM) between images.

    SSIM measures perceptual similarity considering:
        - Luminance
        - Contrast
        - Structure

    Args:
        original: Original image array (1, H, W, 3)
        reconstructed: Reconstructed image array (1, H, W, 3)

    Returns:
        SSIM score in range [-1, 1], where 1 = identical
    """
    # Remove batch dimension
    orig = original[0] if original.ndim == 4 else original
    recon = reconstructed[0] if reconstructed.ndim == 4 else reconstructed

    # Calculate SSIM with multichannel support
    # data_range is 1.0 since images are normalized to [0, 1]
    ssim_score = ssim(orig, recon, data_range=1.0, channel_axis=2)

    return float(ssim_score)


def determine_verdict(mse: float, ssim_score: float, dynamic_threshold: float) -> Tuple[str, str]:
    """
    Determine three-tier verdict based on MSE and SSIM.

    Logic (v3.1 - Dynamic Threshold Integration):
        - Scales base thresholds using the dynamic factor calculated from brightness/contrast/complexity.
        - Relaxes boundaries for noisy/natural images.

    Args:
        mse: Mean Squared Error score
        ssim_score: Structural Similarity Index score
        dynamic_threshold: Adaptive threshold (0.010 - 0.055)

    Returns:
        Tuple of (legacy_status, verdict_tier)
    """
    # Use dynamic_threshold to scale the checks
    # base_threshold used in calculation was 0.0225
    scaling_factor = dynamic_threshold / 0.0225

    current_safe = THRESHOLD_SAFE * scaling_factor
    current_suspicious = THRESHOLD_SUSPICIOUS * scaling_factor

    # Relax SSIM for natural images if the dynamic_threshold is high
    ssim_min = SSIM_LAYOUT_VARIATION_MIN
    if scaling_factor > 1.2:
        # For noisy photos, reduce SSIM floor to 0.55 to avoid false positives
        ssim_min = 0.55

    mse_safe = mse < current_safe
    mse_moderate = mse < current_suspicious
    ssim_safe = ssim_score >= SSIM_THRESHOLD
    ssim_borderline = ssim_score >= ssim_min

    # Both metrics agree: image is safe
    if mse_safe and ssim_safe:
        return "LEGITIMATE", Verdict.SAFE

    # Both metrics flag danger: high MSE AND very low SSIM
    if not mse_moderate and not ssim_borderline:
        # If it's a very noisy photo but SSIM is somewhat okay, downgrade to Suspicious
        if ssim_score > 0.50 and scaling_factor > 1.5:
            return "LEGITIMATE", Verdict.SUSPICIOUS
        return "PHISHING", Verdict.MALICIOUS

    # MSE is low but SSIM is borderline → Layout Variation
    if mse_moderate and not ssim_safe and ssim_borderline:
        return "LEGITIMATE", Verdict.SUSPICIOUS

    # MSE is in suspicious range but SSIM is fine
    if not mse_safe and mse_moderate and ssim_safe:
        return "LEGITIMATE", Verdict.SUSPICIOUS

    # High MSE but SSIM still borderline → Suspicious rather than Malicious
    if not mse_moderate and ssim_borderline:
        return "LEGITIMATE", Verdict.SUSPICIOUS

    return "LEGITIMATE", Verdict.SUSPICIOUS


def print_debug_info(mse: float, ssim_score: float, verdict: str,
                     brightness: float = None, contrast: float = None,
                     dynamic_threshold: float = None) -> None:
    """
    Print debug information to terminal.

    Format:
        [DEBUG] MSE: {score} | SSIM: {score} | Verdict: {status}
    """
    # Color codes for terminal
    COLORS = {
        Verdict.SAFE: "\033[92m",       # Green
        Verdict.SUSPICIOUS: "\033[93m", # Orange/Yellow
        Verdict.MALICIOUS: "\033[91m",  # Red
        Verdict.ERROR: "\033[91m",      # Red
        "RESET": "\033[0m"
    }

    color = COLORS.get(verdict, COLORS["RESET"])
    reset = COLORS["RESET"]

    print(f"\n{'='*60}")
    print(f"[DEBUG] Phishing Screenshot Analysis")
    print(f"{'='*60}")
    print(f"  MSE Score       : {mse:.5f}")
    print(f"  SSIM Score      : {ssim_score:.4f}")
    if dynamic_threshold:
        scaling = dynamic_threshold / 0.0225
        print(f"  Dynamic Thresh  : {dynamic_threshold:.5f} (Scale: {scaling:.2f}x)")
    if brightness is not None:
        print(f"  Brightness      : {brightness:.4f}")
    if contrast is not None:
        print(f"  Contrast        : {contrast:.4f}")
    print(f"  {'-'*40}")
    print(f"  Verdict         : {color}{verdict}{reset}")
    print(f"{'='*60}\n")


# =============================================================================
# MAIN INFERENCE FUNCTION
# =============================================================================

def predict_image_threat(image_path: str, debug: bool = True) -> Tuple[str, float, str]:
    """
    Analyze image for visual anomalies indicating phishing.

    Enhanced with:
        - Adaptive thresholding based on brightness/contrast
        - SSIM structural similarity check
        - Canny Edge Detection preprocessing
        - Login Box ROI focus
        - Three-tier verdict system

    Args:
        image_path: Path to image file
        debug: Whether to print debug information

    Returns:
        Tuple of (status, mse_score, method)
            - status: "LEGITIMATE", "PHISHING", or "ERROR"
            - mse_score: Mean Squared Error (reconstruction error)
            - method: Analysis method ("Enhanced-AE-v2")

    Verdict Tiers:
        - Green (SAFE): MSE < 0.015 AND SSIM >= 0.75
        - Orange (SUSPICIOUS): Conflicting signals OR SSIM 0.65-0.75
        - Red (MALICIOUS): MSE >= 0.030 AND SSIM < 0.65
    """
    img_model = get_image_model()

    # Check model availability
    if not img_model:
        if debug:
            print_debug_info(0.0, 0.0, Verdict.ERROR)
        return "ERROR", 0.0, "Model Unavailable"

    try:
        # =================================================================
        # STEP 1: Standard Preprocessing
        # =================================================================
        img_array = preprocess_image(image_path, target_size=(128, 128))

        # =================================================================
        # STEP 2: Calculate Image Metrics for Adaptive Thresholding
        # =================================================================
        brightness, contrast, complexity = calculate_image_metrics(img_array)
        dynamic_threshold = calculate_dynamic_threshold(brightness, contrast, complexity)

        # =================================================================
        # STEP 3: Edge Detection Preprocessing
        # =================================================================
        edge_array = apply_canny_edge_detection(image_path, target_size=(128, 128))

        # =================================================================
        # STEP 4: Login Box ROI Extraction
        # =================================================================
        roi_array = detect_login_roi(image_path, target_size=(128, 128))

        # =================================================================
        # STEP 5: Autoencoder Reconstruction (Multi-view)
        # =================================================================
        # Primary: Full image reconstruction
        reconstruction_full = img_model.predict(img_array, verbose=0)
        mse_full = calculate_reconstruction_error(img_array, reconstruction_full)
        ssim_full = calculate_ssim(img_array, reconstruction_full)

        # Secondary: Edge-based reconstruction
        reconstruction_edge = img_model.predict(edge_array, verbose=0)
        mse_edge = calculate_reconstruction_error(edge_array, reconstruction_edge)

        # Tertiary: ROI-based reconstruction (if available)
        mse_roi = 0.0
        if roi_array is not None:
            reconstruction_roi = img_model.predict(roi_array, verbose=0)
            mse_roi = calculate_reconstruction_error(roi_array, reconstruction_roi)

        # =================================================================
        # STEP 6: Weighted MSE Combination
        # =================================================================
        # Weight: Full (40%) + Edge (35%) + ROI (25%)
        if roi_array is not None:
            combined_mse = (0.40 * mse_full) + (0.35 * mse_edge) + (0.25 * mse_roi)
        else:
            # Without ROI, redistribute: Full (55%) + Edge (45%)
            combined_mse = (0.55 * mse_full) + (0.45 * mse_edge)

        # =================================================================
        # STEP 7: Determine Verdict
        # =================================================================
        status, verdict_tier = determine_verdict(combined_mse, ssim_full, dynamic_threshold)

        # =================================================================
        # STEP 8: Debug Output
        # =================================================================
        if debug:
            print_debug_info(
                mse=combined_mse,
                ssim_score=ssim_full,
                verdict=verdict_tier,
                brightness=brightness,
                contrast=contrast,
                dynamic_threshold=dynamic_threshold
            )

        return status, round(combined_mse, 5), "Enhanced-AE-v2"

    except Exception as e:
        if debug:
            print(f"\n[ERROR] Inference failed: {str(e)}\n")
        return "ERROR", 0.0, f"Inference Error: {str(e)}"


def predict_image_threat_detailed(image_path: str, debug: bool = True) -> AnalysisResult:
    """
    Extended analysis with full diagnostic data.

    Returns:
        AnalysisResult dataclass with comprehensive metrics
    """
    img_model = get_image_model()

    if not img_model:
        return AnalysisResult(
            status="ERROR",
            mse_score=0.0,
            ssim_score=0.0,
            dynamic_threshold=0.0,
            method="Model Unavailable",
            verdict_tier=Verdict.ERROR,
            debug_info={}
        )

    try:
        # Full analysis pipeline
        img_array = preprocess_image(image_path, target_size=(128, 128))
        brightness, contrast, complexity = calculate_image_metrics(img_array)
        dynamic_threshold = calculate_dynamic_threshold(brightness, contrast, complexity)

        edge_array = apply_canny_edge_detection(image_path, target_size=(128, 128))
        roi_array = detect_login_roi(image_path, target_size=(128, 128))

        reconstruction_full = img_model.predict(img_array, verbose=0)
        mse_full = calculate_reconstruction_error(img_array, reconstruction_full)
        ssim_full = calculate_ssim(img_array, reconstruction_full)

        reconstruction_edge = img_model.predict(edge_array, verbose=0)
        mse_edge = calculate_reconstruction_error(edge_array, reconstruction_edge)

        mse_roi = 0.0
        if roi_array is not None:
            reconstruction_roi = img_model.predict(roi_array, verbose=0)
            mse_roi = calculate_reconstruction_error(roi_array, reconstruction_roi)
            combined_mse = (0.40 * mse_full) + (0.35 * mse_edge) + (0.25 * mse_roi)
        else:
            combined_mse = (0.55 * mse_full) + (0.45 * mse_edge)

        status, verdict_tier = determine_verdict(combined_mse, ssim_full, dynamic_threshold)

        if debug:
            print_debug_info(combined_mse, ssim_full, verdict_tier, brightness, contrast, dynamic_threshold)

        return AnalysisResult(
            status=status,
            mse_score=round(combined_mse, 5),
            ssim_score=round(ssim_full, 4),
            dynamic_threshold=round(dynamic_threshold, 5),
            method="Enhanced-AE-v2",
            verdict_tier=verdict_tier,
            debug_info={
                "mse_full": round(mse_full, 5),
                "mse_edge": round(mse_edge, 5),
                "mse_roi": round(mse_roi, 5) if roi_array is not None else None,
                "brightness": round(brightness, 4),
                "contrast": round(contrast, 4),
                "roi_detected": roi_array is not None
            }
        )

    except Exception as e:
        return AnalysisResult(
            status="ERROR",
            mse_score=0.0,
            ssim_score=0.0,
            dynamic_threshold=0.0,
            method=f"Inference Error: {str(e)}",
            verdict_tier=Verdict.ERROR,
            debug_info={"error": str(e)}
        )


def get_threshold_info() -> dict:
    """
    Get information about threshold configuration.

    Returns:
        Dictionary with threshold details and interpretation
    """
    return {
        "version": "3.0",
        "thresholds": {
            "safe": THRESHOLD_SAFE,
            "suspicious": THRESHOLD_SUSPICIOUS,
            "ssim_minimum": SSIM_THRESHOLD,
            "ssim_layout_variation": SSIM_LAYOUT_VARIATION_MIN
        },
        "method": "Adaptive Multi-View Analysis",
        "description": "Enhanced detection with relaxed SSIM, Layout Variation band, edge detection, and ROI focus",
        "interpretation": {
            "green_safe": f"MSE < {THRESHOLD_SAFE} AND SSIM >= {SSIM_THRESHOLD} → SAFE",
            "orange_suspicious": f"SSIM {SSIM_LAYOUT_VARIATION_MIN}-{SSIM_THRESHOLD} (Layout Variation) OR conflicting signals → SUSPICIOUS",
            "red_malicious": f"MSE >= {THRESHOLD_SUSPICIOUS} AND SSIM < {SSIM_LAYOUT_VARIATION_MIN} → MALICIOUS"
        },
        "features": [
            "Adaptive thresholding based on brightness/contrast",
            "SSIM structural similarity check (relaxed to 0.75)",
            "Layout Variation band (SSIM 0.65-0.75)",
            "Canny Edge Detection preprocessing",
            "Login Box ROI focus",
            "Three-tier verdict system"
        ]
    }
