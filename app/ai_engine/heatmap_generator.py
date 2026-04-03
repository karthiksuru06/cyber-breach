"""
Heatmap Generator Module (XAI Visualization)
==============================================
Visual explainability for Autoencoder-based phishing detection.

Features:
- Difference mapping between original and reconstructed images
- Reconstruction error heatmap overlay
- Region-specific anomaly highlighting
- Export to PNG with transparency

The heatmap visually proves to evaluators exactly WHERE
the "fake" elements are located on a phishing page.
"""

import numpy as np
import cv2
from PIL import Image
from typing import Tuple, Optional, Dict
from dataclasses import dataclass
import os

from app.utils import preprocess_image
from app.ai_engine.model_loader import get_image_model


# =============================================================================
# CONFIGURATION
# =============================================================================

# Heatmap color scheme
HEATMAP_COLORMAP = cv2.COLORMAP_JET  # Blue (low) -> Red (high)
HEATMAP_ALPHA = 0.6  # Overlay transparency

# Error thresholds for visualization
ERROR_LOW_THRESHOLD = 0.01    # Below this = Blue (normal)
ERROR_MED_THRESHOLD = 0.03    # Between low and med = Yellow (suspicious)
ERROR_HIGH_THRESHOLD = 0.05   # Above this = Red (anomalous)

# Output settings
DEFAULT_OUTPUT_SIZE = (512, 512)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class HeatmapResult:
    """Container for heatmap generation results."""
    success: bool
    heatmap_path: Optional[str]
    overlay_path: Optional[str]
    stats: Dict
    error_message: Optional[str] = None


@dataclass
class RegionAnomaly:
    """Represents an anomalous region in the image."""
    name: str
    location: Tuple[int, int, int, int]  # (x, y, width, height)
    mean_error: float
    max_error: float
    severity: str  # "LOW", "MEDIUM", "HIGH"


# =============================================================================
# CORE HEATMAP GENERATION
# =============================================================================

class ReconstructionHeatmap:
    """
    Generate visual heatmaps showing reconstruction error distribution.
    """

    def __init__(self, image_path: str):
        """
        Initialize heatmap generator.

        Args:
            image_path: Path to the screenshot image
        """
        self.image_path = image_path
        self.original_img = None
        self.reconstructed_img = None
        self.error_map = None
        self.model = get_image_model()

    def _load_and_preprocess(self) -> np.ndarray:
        """Load and preprocess image for model inference."""
        return preprocess_image(self.image_path, target_size=(128, 128))

    def _compute_reconstruction(self, img_array: np.ndarray) -> np.ndarray:
        """Get autoencoder reconstruction."""
        if self.model is None:
            raise ValueError("Image model not available")
        return self.model.predict(img_array, verbose=0)

    def _compute_error_map(self, original: np.ndarray, reconstructed: np.ndarray) -> np.ndarray:
        """
        Compute per-pixel reconstruction error.

        Args:
            original: Original image array (1, H, W, 3)
            reconstructed: Reconstructed image array (1, H, W, 3)

        Returns:
            Error map of shape (H, W) with values in [0, 1]
        """
        # Remove batch dimension
        orig = original[0] if original.ndim == 4 else original
        recon = reconstructed[0] if reconstructed.ndim == 4 else reconstructed

        # Compute MSE per pixel (across RGB channels)
        error = np.mean(np.power(orig - recon, 2), axis=2)

        return error

    def _normalize_error_map(self, error_map: np.ndarray) -> np.ndarray:
        """
        Normalize error map to 0-255 range for visualization.

        Uses percentile-based normalization to handle outliers.
        """
        # Clip extreme values
        p_low, p_high = np.percentile(error_map, [2, 98])
        clipped = np.clip(error_map, p_low, p_high)

        # Normalize to 0-255
        if p_high > p_low:
            normalized = (clipped - p_low) / (p_high - p_low)
        else:
            normalized = np.zeros_like(clipped)

        return (normalized * 255).astype(np.uint8)

    def _apply_colormap(self, error_map_normalized: np.ndarray) -> np.ndarray:
        """
        Apply colormap to normalized error map.

        Low error → Blue
        High error → Red
        """
        return cv2.applyColorMap(error_map_normalized, HEATMAP_COLORMAP)

    def _create_overlay(self, original_bgr: np.ndarray, heatmap: np.ndarray,
                        alpha: float = HEATMAP_ALPHA) -> np.ndarray:
        """
        Overlay heatmap on original image.

        Args:
            original_bgr: Original image in BGR format
            heatmap: Colored heatmap
            alpha: Transparency (0 = original only, 1 = heatmap only)

        Returns:
            Blended overlay image
        """
        # Ensure same size
        if original_bgr.shape[:2] != heatmap.shape[:2]:
            heatmap = cv2.resize(heatmap, (original_bgr.shape[1], original_bgr.shape[0]))

        # Blend images
        overlay = cv2.addWeighted(original_bgr, 1 - alpha, heatmap, alpha, 0)

        return overlay

    def _detect_anomalous_regions(self, error_map: np.ndarray) -> list:
        """
        Detect and label anomalous regions in the error map.

        Returns:
            List of RegionAnomaly objects
        """
        regions = []

        # Threshold to binary
        threshold = np.percentile(error_map, 90)
        binary = (error_map > threshold).astype(np.uint8) * 255

        # Find contours
        contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        for i, contour in enumerate(contours):
            if cv2.contourArea(contour) < 50:  # Skip tiny regions
                continue

            x, y, w, h = cv2.boundingRect(contour)

            # Extract region error stats
            region_error = error_map[y:y+h, x:x+w]
            mean_error = float(np.mean(region_error))
            max_error = float(np.max(region_error))

            # Classify severity
            if max_error > ERROR_HIGH_THRESHOLD:
                severity = "HIGH"
            elif max_error > ERROR_MED_THRESHOLD:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Determine region name based on position
            img_h, img_w = error_map.shape
            region_name = self._classify_region_position(x, y, w, h, img_w, img_h)

            regions.append(RegionAnomaly(
                name=region_name,
                location=(x, y, w, h),
                mean_error=mean_error,
                max_error=max_error,
                severity=severity
            ))

        # Sort by severity and error
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        regions.sort(key=lambda r: (severity_order[r.severity], -r.max_error))

        return regions[:5]  # Return top 5 regions

    def _classify_region_position(self, x: int, y: int, w: int, h: int,
                                  img_w: int, img_h: int) -> str:
        """Classify region based on its position in the image."""
        center_x = x + w / 2
        center_y = y + h / 2

        # Vertical position
        if center_y < img_h * 0.33:
            v_pos = "Header"
        elif center_y < img_h * 0.66:
            v_pos = "Body"
        else:
            v_pos = "Footer"

        # Horizontal position
        if center_x < img_w * 0.33:
            h_pos = "Left"
        elif center_x < img_w * 0.66:
            h_pos = "Center"
        else:
            h_pos = "Right"

        # Special cases
        if v_pos == "Body" and h_pos == "Center":
            if h > img_h * 0.2:
                return "Login Form Area"
            return "Central Content"
        elif v_pos == "Header":
            return f"{h_pos} Header/Logo"
        elif v_pos == "Footer":
            return f"{h_pos} Footer"

        return f"{v_pos} {h_pos}"

    def _draw_region_boxes(self, image: np.ndarray,
                          regions: list) -> np.ndarray:
        """Draw bounding boxes around anomalous regions."""
        output = image.copy()

        colors = {
            "HIGH": (0, 0, 255),    # Red
            "MEDIUM": (0, 165, 255), # Orange
            "LOW": (0, 255, 255)    # Yellow
        }

        for region in regions:
            x, y, w, h = region.location
            color = colors.get(region.severity, (255, 255, 255))

            # Draw rectangle
            cv2.rectangle(output, (x, y), (x + w, y + h), color, 2)

            # Draw label background
            label = f"{region.name} ({region.severity})"
            (label_w, label_h), baseline = cv2.getTextSize(
                label, cv2.FONT_HERSHEY_SIMPLEX, 0.4, 1
            )
            cv2.rectangle(output, (x, y - label_h - 5), (x + label_w, y), color, -1)

            # Draw label text
            cv2.putText(output, label, (x, y - 3),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1)

        return output

    def generate(self, output_dir: str = None,
                output_size: Tuple[int, int] = DEFAULT_OUTPUT_SIZE) -> HeatmapResult:
        """
        Generate heatmap visualization.

        Args:
            output_dir: Directory to save output images (None = temp dir)
            output_size: Size of output images

        Returns:
            HeatmapResult with paths and statistics
        """
        if self.model is None:
            return HeatmapResult(
                success=False,
                heatmap_path=None,
                overlay_path=None,
                stats={},
                error_message="Image model not available"
            )

        try:
            # Step 1: Load and preprocess
            img_array = self._load_and_preprocess()
            self.original_img = img_array

            # Step 2: Get reconstruction
            self.reconstructed_img = self._compute_reconstruction(img_array)

            # Step 3: Compute error map
            self.error_map = self._compute_error_map(img_array, self.reconstructed_img)

            # Step 4: Normalize for visualization
            error_normalized = self._normalize_error_map(self.error_map)

            # Step 5: Resize error map to output size
            error_resized = cv2.resize(error_normalized, output_size)

            # Step 6: Apply colormap
            heatmap_colored = self._apply_colormap(error_resized)

            # Step 7: Load original image at output size
            original_pil = Image.open(self.image_path).convert('RGB')
            original_resized = original_pil.resize(output_size)
            original_bgr = cv2.cvtColor(np.array(original_resized), cv2.COLOR_RGB2BGR)

            # Step 8: Create overlay
            overlay = self._create_overlay(original_bgr, heatmap_colored)

            # Step 9: Detect anomalous regions (on resized error map)
            error_map_resized = cv2.resize(self.error_map, output_size)
            regions = self._detect_anomalous_regions(error_map_resized)

            # Step 10: Draw region boxes on overlay
            overlay_with_boxes = self._draw_region_boxes(overlay, regions)

            # Step 11: Save outputs
            if output_dir is None:
                output_dir = os.path.dirname(self.image_path)

            os.makedirs(output_dir, exist_ok=True)

            base_name = os.path.splitext(os.path.basename(self.image_path))[0]
            heatmap_path = os.path.join(output_dir, f"{base_name}_heatmap.png")
            overlay_path = os.path.join(output_dir, f"{base_name}_overlay.png")

            cv2.imwrite(heatmap_path, heatmap_colored)
            cv2.imwrite(overlay_path, overlay_with_boxes)

            # Step 12: Compute statistics
            stats = {
                "mean_error": float(np.mean(self.error_map)),
                "max_error": float(np.max(self.error_map)),
                "std_error": float(np.std(self.error_map)),
                "error_percentiles": {
                    "p50": float(np.percentile(self.error_map, 50)),
                    "p90": float(np.percentile(self.error_map, 90)),
                    "p99": float(np.percentile(self.error_map, 99))
                },
                "anomalous_regions": [
                    {
                        "name": r.name,
                        "location": r.location,
                        "mean_error": round(r.mean_error, 5),
                        "max_error": round(r.max_error, 5),
                        "severity": r.severity
                    }
                    for r in regions
                ],
                "high_error_percentage": float(
                    np.mean(self.error_map > ERROR_HIGH_THRESHOLD) * 100
                )
            }

            return HeatmapResult(
                success=True,
                heatmap_path=heatmap_path,
                overlay_path=overlay_path,
                stats=stats
            )

        except Exception as e:
            return HeatmapResult(
                success=False,
                heatmap_path=None,
                overlay_path=None,
                stats={},
                error_message=str(e)
            )


# =============================================================================
# DIFFERENCE MAPPING
# =============================================================================

class DifferenceMapper:
    """
    Generate side-by-side difference visualization.
    """

    def __init__(self, image_path: str):
        self.image_path = image_path
        self.model = get_image_model()

    def generate_comparison(self, output_path: str = None,
                           output_size: Tuple[int, int] = DEFAULT_OUTPUT_SIZE) -> Optional[str]:
        """
        Generate side-by-side comparison: Original | Reconstructed | Difference.

        Args:
            output_path: Path to save comparison image
            output_size: Size of each panel

        Returns:
            Path to saved comparison image or None on failure
        """
        if self.model is None:
            return None

        try:
            # Load and preprocess
            img_array = preprocess_image(self.image_path, target_size=(128, 128))

            # Get reconstruction
            reconstructed = self.model.predict(img_array, verbose=0)

            # Compute difference
            difference = np.abs(img_array[0] - reconstructed[0])

            # Amplify difference for visibility
            difference_amplified = np.clip(difference * 5, 0, 1)

            # Convert to display format
            original_display = (img_array[0] * 255).astype(np.uint8)
            recon_display = (reconstructed[0] * 255).astype(np.uint8)
            diff_display = (difference_amplified * 255).astype(np.uint8)

            # Resize all to output size
            original_resized = cv2.resize(original_display, output_size)
            recon_resized = cv2.resize(recon_display, output_size)
            diff_resized = cv2.resize(diff_display, output_size)

            # Create side-by-side comparison
            comparison = np.hstack([original_resized, recon_resized, diff_resized])

            # Add labels
            label_height = 30
            labeled = np.zeros((comparison.shape[0] + label_height, comparison.shape[1], 3), dtype=np.uint8)
            labeled[label_height:, :] = comparison

            # Add text labels
            labels = ["Original", "Reconstructed", "Difference (5x)"]
            for i, label in enumerate(labels):
                x = i * output_size[0] + output_size[0] // 2 - 50
                cv2.putText(labeled, label, (x, 20),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)

            # Save
            if output_path is None:
                base_name = os.path.splitext(os.path.basename(self.image_path))[0]
                output_path = os.path.join(
                    os.path.dirname(self.image_path),
                    f"{base_name}_comparison.png"
                )

            # Convert RGB to BGR for OpenCV saving
            labeled_bgr = cv2.cvtColor(labeled, cv2.COLOR_RGB2BGR)
            cv2.imwrite(output_path, labeled_bgr)

            return output_path

        except Exception as e:
            print(f"[HEATMAP] Comparison generation failed: {e}")
            return None


# =============================================================================
# PUBLIC API
# =============================================================================

def generate_reconstruction_heatmap(image_path: str,
                                   output_dir: str = None,
                                   debug: bool = True) -> HeatmapResult:
    """
    Generate heatmap visualization for a screenshot.

    Args:
        image_path: Path to the screenshot image
        output_dir: Directory to save outputs (default: same as input)
        debug: Whether to print debug information

    Returns:
        HeatmapResult with paths and statistics
    """
    generator = ReconstructionHeatmap(image_path)
    result = generator.generate(output_dir)

    if debug:
        print_heatmap_debug(result)

    return result


def generate_difference_comparison(image_path: str,
                                  output_path: str = None) -> Optional[str]:
    """
    Generate side-by-side difference comparison.

    Args:
        image_path: Path to the screenshot image
        output_path: Path to save comparison (auto-generated if None)

    Returns:
        Path to saved comparison image or None on failure
    """
    mapper = DifferenceMapper(image_path)
    return mapper.generate_comparison(output_path)


def print_heatmap_debug(result: HeatmapResult) -> None:
    """Print heatmap generation results."""
    COLORS = {
        "HIGH": "\033[91m",    # Red
        "MEDIUM": "\033[93m",  # Yellow
        "LOW": "\033[92m",     # Green
        "RESET": "\033[0m"
    }

    print(f"\n{'='*60}")
    print(f"[HEATMAP] Reconstruction Error Visualization")
    print(f"{'='*60}")

    if not result.success:
        print(f"  Status: FAILED")
        print(f"  Error: {result.error_message}")
        print(f"{'='*60}\n")
        return

    print(f"  Status: SUCCESS")
    print(f"  Heatmap: {result.heatmap_path}")
    print(f"  Overlay: {result.overlay_path}")

    print(f"\n  ERROR STATISTICS:")
    print(f"  {'-'*40}")
    stats = result.stats
    print(f"  Mean Error    : {stats['mean_error']:.5f}")
    print(f"  Max Error     : {stats['max_error']:.5f}")
    print(f"  Std Dev       : {stats['std_error']:.5f}")
    print(f"  High Error %  : {stats['high_error_percentage']:.2f}%")

    print(f"\n  ANOMALOUS REGIONS:")
    print(f"  {'-'*40}")
    regions = stats.get('anomalous_regions', [])
    if regions:
        for i, region in enumerate(regions, 1):
            color = COLORS.get(region['severity'], COLORS['RESET'])
            reset = COLORS['RESET']
            print(f"  {i}. {region['name']}")
            print(f"     Severity: {color}{region['severity']}{reset}")
            print(f"     Max Error: {region['max_error']:.5f}")
            print(f"     Location: {region['location']}")
    else:
        print(f"  No significant anomalous regions detected")

    print(f"{'='*60}\n")


# =============================================================================
# BATCH PROCESSING
# =============================================================================

def batch_generate_heatmaps(image_paths: list,
                           output_dir: str,
                           debug: bool = False) -> list:
    """
    Generate heatmaps for multiple images.

    Args:
        image_paths: List of image paths
        output_dir: Directory to save all outputs
        debug: Whether to print debug information

    Returns:
        List of HeatmapResult objects
    """
    results = []

    for i, path in enumerate(image_paths):
        if debug:
            print(f"[HEATMAP] Processing {i+1}/{len(image_paths)}: {os.path.basename(path)}")

        result = generate_reconstruction_heatmap(path, output_dir, debug=False)
        results.append(result)

    if debug:
        success_count = sum(1 for r in results if r.success)
        print(f"\n[HEATMAP] Batch complete: {success_count}/{len(results)} successful")

    return results
