"""
MasterEngine - Unified Intelligence Hub (v3.0)
================================================
Single orchestration layer integrating:
  - Ensemble Voting Engine (Whitelist -> CSV -> WHOIS -> LSTM)
  - XAI Feature Attribution (Top 3 Suspicious Features)
  - Visual Forensic Heatmap Generation (SSIM + Canny Edge)

Analysis Pipeline (URL):
    Layer 1: Authority Whitelist (Heuristic) -> O(1)
    Layer 2: Local CSV Intelligence (210k threats) -> O(1)
    Layer 3: WHOIS Domain Reputation (LRU-cached)
    Layer 4: Bi-LSTM Neural Engine (Character-level)
    Layer 5: XAI Feature Attribution

Analysis Pipeline (Image):
    Preprocessing -> Multi-View Autoencoder (Full + Edge + ROI)
    -> SSIM Structural Check -> Forensic Triptych Generation
    (Original | Heatmap | Anomaly Highlight)
"""

import os
import uuid
import numpy as np
import cv2
from PIL import Image
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field, asdict

from app.utils import is_whitelisted, validate_url, check_local_threat
from app.ai_engine.model_loader import get_image_model, models_available
from app.ai_engine.voting_engine import (
    EnsembleVoter, URLFeatureExtractor, VoteType,
    analyze_url_with_ensemble, get_top_suspicious_features
)
from app.ai_engine.image_inference import (
    predict_image_threat_detailed, AnalysisResult as ImageAnalysisResult
)
from app.utils.preprocessing import preprocess_image


# =============================================================================
# CONFIGURATION
# =============================================================================

LSTM_CONFIDENCE_OVERRIDE = 90.0   # >90% LSTM confidence overrides consensus
CONSENSUS_MIN_VOTES = 2           # Minimum votes required for MALICIOUS/SAFE
TRIPTYCH_PANEL_SIZE = (400, 400)  # Each panel in the forensic triptych
SAFE_MSE_THRESHOLD = 0.022        # Strict MSE threshold for SAFE verdict
SAFE_SSIM_THRESHOLD = 0.75        # Relaxed SSIM threshold for SAFE verdict
LAYOUT_VARIATION_SSIM = 0.65      # SSIM below 0.75 but above 0.65 = Layout Variation

# =============================================================================
# RESULT DATA CLASSES
# =============================================================================

@dataclass
class ForensicURLResult:
    """Complete forensic result for URL analysis."""
    verdict: str              # SAFE, MALICIOUS, SUSPICIOUS, INVALID
    confidence: float         # 0-100
    method: str               # e.g. "Consensus Neural", "Local Intelligence"
    safe_mode: bool           # True if running without neural models
    top_features: List[Dict]  # Top 3 suspicious feature badges
    layer_votes: List[Dict]   # Individual layer votes with reasons
    consensus_ratio: float    # Agreement ratio across voting layers
    explanation: str           # Human-readable consensus explanation
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ForensicImageResult:
    """Complete forensic result for image analysis."""
    verdict: str              # LEGITIMATE, PHISHING, ERROR
    verdict_tier: str         # SAFE, SUSPICIOUS, MALICIOUS, ERROR
    mse_score: float
    ssim_score: float
    method: str
    safe_mode: bool
    heatmap_url: Optional[str]       # URL path to triptych image
    anomalous_regions: List[Dict]    # Detected anomaly regions with severity
    debug_info: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


# =============================================================================
# MASTER ENGINE
# =============================================================================

class MasterEngine:
    """
    Unified Intelligence Hub orchestrating all analysis layers.
    """

    # =========================================================================
    # URL ANALYSIS
    # =========================================================================

    @staticmethod
    def analyze_url(url: str) -> ForensicURLResult:
        """
        Full forensic URL analysis via ensemble consensus.
        """
        # Step 0: Normalization & Validation (Handling gOogle.com cases)
        url = url.lower().strip()
        is_valid, error_msg = validate_url(url)
        if not is_valid:
            return ForensicURLResult(
                verdict="INVALID",
                confidence=0.0,
                method="Validation Failed",
                safe_mode=False,
                top_features=[],
                layer_votes=[],
                consensus_ratio=0.0,
                explanation=error_msg,
                metadata={"error": error_msg}
            )

        # Step 1: Check model availability for safe_mode flag
        status = models_available()
        models_online = status.get('url_model') and status.get('tokenizer')

        # Step 2: Run ensemble voting (all layers handled internally)
        try:
            ensemble_result = analyze_url_with_ensemble(url, debug=True)
        except Exception as e:
            return MasterEngine._safe_mode_url(url, str(e))

        # Step 3: Extract Top 3 Suspicious Features for XAI display
        top_features = get_top_suspicious_features(url, n=3)

        # Step 4: Determine human-readable analysis method label
        method = MasterEngine._determine_method_label(ensemble_result)

        # Step 5: Build layer vote summaries for UI
        layer_votes = [
            {
                "layer": v.layer_name,
                "vote": v.vote.value,
                "confidence": round(v.confidence * 100, 1),
                "reason": v.reason
            }
            for v in ensemble_result.votes
        ]

        return ForensicURLResult(
            verdict=ensemble_result.final_verdict,
            confidence=round(ensemble_result.confidence, 2),
            method=method,
            safe_mode=not models_online,
            top_features=top_features,
            layer_votes=layer_votes,
            consensus_ratio=round(ensemble_result.consensus_ratio, 2),
            explanation=ensemble_result.explanation,
            metadata=ensemble_result.debug_info
        )

    # =========================================================================
    # IMAGE ANALYSIS
    # =========================================================================

    @staticmethod
    def analyze_image(image_path: str, output_dir: str = None) -> ForensicImageResult:
        """
        Full forensic image analysis with heatmap generation.
        Rule: if mse < threshold AND ssim > 0.75: return SAFE.
        Layout Variation: if SSIM 0.65-0.75 with low MSE: return SUSPICIOUS.
        Else: Return MALICIOUS/SUSPICIOUS with specific trigger explanation.
        """
        img_model = get_image_model()
        if not img_model:
            return MasterEngine._safe_mode_image()

        try:
            # Step 1: Detailed image analysis (SSIM + MSE + Edge + ROI)
            analysis = predict_image_threat_detailed(image_path, debug=True)

            # Step 2: RULE ENFORCEMENT & EXPLANATION
            # Determine triggers
            triggers = []
            mse_failed = analysis.mse_score >= SAFE_MSE_THRESHOLD
            ssim_failed = analysis.ssim_score <= SAFE_SSIM_THRESHOLD
            ssim_borderline = (analysis.ssim_score > LAYOUT_VARIATION_SSIM and
                               analysis.ssim_score <= SAFE_SSIM_THRESHOLD)
            ssim_critical = analysis.ssim_score <= LAYOUT_VARIATION_SSIM

            if mse_failed:
                triggers.append(f"MSE Deviation ({analysis.mse_score:.4f} >= {SAFE_MSE_THRESHOLD})")
            if ssim_failed:
                triggers.append(f"SSIM Structure ({analysis.ssim_score:.4f} <= {SAFE_SSIM_THRESHOLD})")

            trigger_msg = " & ".join(triggers)

            # CORRECTED TIER LOGIC (v3.0 - Relaxed SSIM with Layout Variation):
            if not mse_failed and not ssim_failed:
                 # Strictly Safe: MSE < 0.022 AND SSIM > 0.75
                 analysis.status = "LEGITIMATE"
                 analysis.verdict_tier = "SAFE"
                 analysis.method = "Neural Autoencoder (Strict Criteria Met)"
            elif not mse_failed and ssim_borderline:
                 # Layout Variation: MSE is low but SSIM is 0.65-0.75
                 analysis.status = "LEGITIMATE"
                 analysis.verdict_tier = "SUSPICIOUS"
                 analysis.method = f"SUSPICIOUS: Layout Variation (SSIM {analysis.ssim_score:.4f})"
            elif mse_failed and ssim_critical:
                 # Both fail hard -> Malicious (confirmed threat)
                 analysis.status = "PHISHING"
                 analysis.verdict_tier = "MALICIOUS"
                 analysis.method = f"Alert Triggered by: {trigger_msg}"
            elif mse_failed and ssim_borderline:
                 # High MSE but SSIM is borderline → Suspicious
                 analysis.status = "LEGITIMATE"
                 analysis.verdict_tier = "SUSPICIOUS"
                 analysis.method = f"SUSPICIOUS: Layout Variation + MSE Elevated ({trigger_msg})"
            elif mse_failed:
                 # High MSE only, SSIM is fine
                 if analysis.mse_score > 0.03:
                     analysis.status = "PHISHING"
                     analysis.verdict_tier = "MALICIOUS"
                 else:
                     analysis.status = "LEGITIMATE"
                     analysis.verdict_tier = "SUSPICIOUS"
                 analysis.method = f"Alert Triggered by: {trigger_msg}"
            elif ssim_critical:
                 # Very low SSIM (< 0.65) but MSE is fine → Suspicious
                 analysis.status = "LEGITIMATE"
                 analysis.verdict_tier = "SUSPICIOUS"
                 analysis.method = f"SUSPICIOUS: Structural Mismatch ({trigger_msg})"

            # Step 3: Generate forensic heatmap triptych
            heatmap_url = None
            anomalous_regions = []

            if output_dir:
                heatmap_url, anomalous_regions = MasterEngine._generate_forensic_triptych(
                    image_path, output_dir
                )

            return ForensicImageResult(
                verdict=analysis.status,
                verdict_tier=analysis.verdict_tier,
                mse_score=analysis.mse_score,
                ssim_score=analysis.ssim_score,
                method=analysis.method,
                safe_mode=False,
                heatmap_url=heatmap_url,
                anomalous_regions=anomalous_regions,
                debug_info=analysis.debug_info
            )

        except Exception as e:
            return ForensicImageResult(
                verdict="ERROR",
                verdict_tier="ERROR",
                mse_score=0.0,
                ssim_score=0.0,
                method=f"Analysis Error: {str(e)}",
                safe_mode=False,
                heatmap_url=None,
                anomalous_regions=[],
                debug_info={"error": str(e)}
            )

    # =========================================================================
    # FORENSIC HEATMAP TRIPTYCH
    # =========================================================================

    @staticmethod
    def _generate_forensic_triptych(
        image_path: str, output_dir: str
    ) -> Tuple[Optional[str], List[Dict]]:
        """
        Generate side-by-side forensic comparison image:
            Panel 1: Original Screenshot
            Panel 2: Reconstruction Error Heatmap (SSIM-weighted, JET colormap)
            Panel 3: Anomaly Highlight (Canny edges + bounding boxes)
        """
        model = get_image_model()
        if not model:
            return None, []

        try:
            panel_w, panel_h = TRIPTYCH_PANEL_SIZE

            # --- Step 1: Preprocess for model inference ---
            img_array = preprocess_image(image_path, target_size=(128, 128))

            # --- Step 2: Autoencoder reconstruction ---
            reconstructed = model.predict(img_array, verbose=0)

            # --- Step 3: Per-pixel reconstruction error map ---
            orig = img_array[0]
            recon = reconstructed[0]
            error_map = np.mean(np.power(orig - recon, 2), axis=2)

            # --- Step 4: SSIM structural similarity ---
            from skimage.metrics import structural_similarity as ssim_fn
            ssim_score = float(ssim_fn(orig, recon, data_range=1.0, channel_axis=2))

            # --- Step 5: Load original at output size ---
            original_pil = Image.open(image_path).convert('RGB')
            # Use appropriate resampling based on Pillow version
            resample_filter = getattr(Image, 'Resampling', Image).LANCZOS
            original_resized = np.array(original_pil.resize((panel_w, panel_h), resample=resample_filter))
            original_bgr = cv2.cvtColor(original_resized, cv2.COLOR_RGB2BGR)

            # --- Step 6: PANEL 2 - Reconstruction Error Heatmap ---
            p_low, p_high = np.percentile(error_map, [2, 98])
            clipped = np.clip(error_map, p_low, p_high)
            
            if p_high > p_low:
                normalized = ((clipped - p_low) / (p_high - p_low) * 255).astype(np.uint8)
            else:
                normalized = np.zeros_like(clipped, dtype=np.uint8)

            error_resized = cv2.resize(normalized, (panel_w, panel_h))
            heatmap_colored = cv2.applyColorMap(error_resized, cv2.COLORMAP_JET)

            # Overlay heatmap on original for context
            heatmap_panel = cv2.addWeighted(original_bgr, 0.4, heatmap_colored, 0.6, 0)

            # --- Step 7: PANEL 3 - Anomaly Highlight (Canny + Boxes) ---
            error_map_resized = cv2.resize(error_map, (panel_w, panel_h))
            threshold_val = np.percentile(error_map_resized, 90)
            # Higher threshold for anomalies to reduce noise
            binary = (error_map_resized > threshold_val).astype(np.uint8) * 255

            contours, _ = cv2.findContours(
                binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
            )

            anomaly_panel = original_bgr.copy()
            anomalous_regions = []

            severity_colors = {
                "HIGH":   (0, 0, 255),     # Red
                "MEDIUM": (0, 165, 255),   # Orange
                "LOW":    (0, 255, 255)    # Yellow
            }

            for contour in contours:
                if cv2.contourArea(contour) < 50:
                    continue

                x, y, w, h = cv2.boundingRect(contour)
                region_error = error_map_resized[y:y+h, x:x+w]
                if region_error.size == 0:
                    continue
                
                mean_err = float(np.mean(region_error))
                max_err = float(np.max(region_error))

                # Classify severity
                if max_err > 0.05:
                    severity = "HIGH"
                elif max_err > 0.03:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                color = severity_colors[severity]
                cv2.rectangle(anomaly_panel, (x, y), (x + w, y + h), color, 2)

                # Severity label
                label = severity
                (lw, lh), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.4, 1)
                ly = max(y - 6, lh + 2)
                
                cv2.rectangle(
                    anomaly_panel, (x, ly - lh - 4), (x + lw + 4, ly + 2), color, -1
                )
                cv2.putText(
                    anomaly_panel, label, (x + 2, ly),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1
                )

                # Region Naming
                cx, cy = x + w // 2, y + h // 2
                v_pos = "Header" if cy < panel_h * 0.33 else ("Body" if cy < panel_h * 0.66 else "Footer")
                h_pos = "Left" if cx < panel_w * 0.33 else ("Center" if cx < panel_w * 0.66 else "Right")
                
                if v_pos == "Body" and h_pos == "Center":
                    region_name = "Login Form Area" if h > panel_h * 0.2 else "Central Content"
                elif v_pos == "Header":
                    region_name = f"{h_pos} Header/Logo"
                elif v_pos == "Footer":
                    region_name = f"{h_pos} Footer"
                else:
                    region_name = f"{v_pos} {h_pos}"

                anomalous_regions.append({
                    "name": region_name,
                    "severity": severity,
                    "mean_error": round(mean_err, 5),
                    "max_error": round(max_err, 5)
                })

            # Sort and Limit
            sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            anomalous_regions.sort(key=lambda r: sev_order.get(r["severity"], 3))
            anomalous_regions = anomalous_regions[:5]

            # --- Step 8: Compose triptych ---
            LABEL_H = 35
            total_w = panel_w * 3
            total_h = panel_h + LABEL_H

            canvas = np.zeros((total_h, total_w, 3), dtype=np.uint8)
            canvas[:] = (15, 15, 25)

            canvas[LABEL_H:, 0:panel_w] = original_bgr
            canvas[LABEL_H:, panel_w:panel_w * 2] = heatmap_panel
            canvas[LABEL_H:, panel_w * 2:panel_w * 3] = anomaly_panel

            labels = ["ORIGINAL", "RECONSTRUCTION HEATMAP", "ANOMALY HIGHLIGHT"]
            label_colors = [(255, 243, 0), (100, 180, 255), (80, 80, 255)]
            
            for i, (txt, clr) in enumerate(zip(labels, label_colors)):
                (tw, th), _ = cv2.getTextSize(txt, cv2.FONT_HERSHEY_SIMPLEX, 0.55, 2)
                x = i * panel_w + (panel_w - tw) // 2
                cv2.putText(canvas, txt, (x, 24), cv2.FONT_HERSHEY_SIMPLEX, 0.55, clr, 2)

            cv2.putText(canvas, f"SSIM: {ssim_score:.4f}", (total_w - 180, 24), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (157, 255, 0), 1)

            # --- Step 9: Save ---
            unique_id = uuid.uuid4().hex[:8]
            filename = f"forensic_{unique_id}.png"
            output_path = os.path.join(output_dir, filename)
            os.makedirs(output_dir, exist_ok=True)
            cv2.imwrite(output_path, canvas)

            return f"/static/uploads/{filename}", anomalous_regions

        except Exception as e:
            print(f"[MASTER ENGINE] Forensic triptych generation failed: {e}")
            return None, []

    # =========================================================================
    # SAFE MODE FALLBACKS
    # =========================================================================

    @staticmethod
    def _safe_mode_url(url: str, error: str = "") -> ForensicURLResult:
        """Heuristic-only analysis when neural models are unavailable."""
        if is_whitelisted(url):
            return ForensicURLResult(
                verdict="SAFE", confidence=99.0, method="Safe Mode: Heuristic Whitelist",
                safe_mode=True, top_features=[], layer_votes=[{
                    "layer": "Whitelist", "vote": "SAFE", "confidence": 99.0, "reason": "Authority Domain"
                }], consensus_ratio=1.0, explanation="Domain is in trusted whitelist (Safe Mode)",
                metadata={"safe_mode": True, "error": error}
            )

        found, threat_type = check_local_threat(url)
        if found:
            return ForensicURLResult(
                verdict="MALICIOUS", confidence=100.0, method="Safe Mode: Local Intelligence",
                safe_mode=True, top_features=get_top_suspicious_features(url, n=3),
                layer_votes=[{
                    "layer": "Threat Intel (CSV)", "vote": "MALICIOUS", 
                    "confidence": 100.0, "reason": f"Known threat: {threat_type}"
                }], consensus_ratio=1.0, explanation=f"Matched threat database: {threat_type}",
                metadata={"safe_mode": True, "category": threat_type}
            )

        features = get_top_suspicious_features(url, n=3)
        extractor = URLFeatureExtractor(url)
        risk = extractor.calculate_total_risk_score()
        verdict = "SUSPICIOUS" if risk > 0.3 else "SAFE"
        confidence = round((risk if verdict == "SUSPICIOUS" else 1 - risk) * 100, 2)

        return ForensicURLResult(
            verdict=verdict, confidence=confidence, method="Safe Mode: Heuristic Analysis Only",
            safe_mode=True, top_features=features, layer_votes=[{
                "layer": "Feature Analysis", "vote": verdict, "confidence": round(risk * 100, 1),
                "reason": "Heuristic feature scoring"
            }], consensus_ratio=0.0, explanation="Neural models unavailable - Heuristic Fallback",
            metadata={"safe_mode": True, "risk_score": risk, "error": error}
        )

    @staticmethod
    def _safe_mode_image() -> ForensicImageResult:
        return ForensicImageResult(
            verdict="ERROR", verdict_tier="ERROR", mse_score=0.0, ssim_score=0.0,
            method="Safe Mode: Heuristic Analysis Only", safe_mode=True, heatmap_url=None,
            anomalous_regions=[], debug_info={"safe_mode": True, "message": "Autoencoder model unavailable"}
        )

    @staticmethod
    def _determine_method_label(ensemble_result) -> str:
        debug = ensemble_result.debug_info
        override = debug.get("override", "")
        if override == "whitelist": return "Heuristic Whitelist"
        elif override == "csv_threat": return "Local Intelligence"
        elif override == "lstm_high_confidence": return "Neural Override (LSTM)"
        else:
            mal_count = debug.get("malicious_votes", 0)
            safe_count = debug.get("safe_votes", 0)
            suspicious_count = debug.get("suspicious_votes", 0)
            if mal_count >= CONSENSUS_MIN_VOTES or safe_count >= CONSENSUS_MIN_VOTES or suspicious_count >= CONSENSUS_MIN_VOTES: return "Consensus Neural"
            return "Ensemble Analysis"
