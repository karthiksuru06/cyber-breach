"""
Web Interface Routes
====================
Flask routes for HTML dashboard with MasterEngine integration.
Provides forensic analysis data (feature attribution, heatmaps) to the UI.
"""

import os
import datetime
from flask import render_template, request, jsonify, current_app
from werkzeug.utils import secure_filename

from app.routes import main_bp
from app.models import ThreatLog
from app import db
from app.ai_engine import MasterEngine
from app.ai_engine.model_loader import models_available


from flask_login import login_required, current_user

@main_bp.route('/', methods=['GET'])
@login_required
def index():
    """Main dashboard page with dual-engine interface."""
    logs = ThreatLog.query.order_by(ThreatLog.id.desc()).limit(10).all()
    status = models_available()
    return render_template('index.html', logs=logs, models_status=status, user=current_user)


@main_bp.route('/analyze/url', methods=['POST'])
@login_required
def analyze_url():
    """
    Handle URL analysis via AJAX using MasterEngine.
    Returns JSON with forensic analysis: verdict, features, consensus, votes.
    """
    url_input = request.form.get('url', '').strip()

    if not url_input:
        return jsonify({'error': 'URL cannot be empty'}), 400

    # Full forensic analysis via MasterEngine
    result = MasterEngine.analyze_url(url_input)

    # Log to database
    try:
        log = ThreatLog(
            timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
            scan_type="URL",
            input_data=url_input,
            result_status=result.verdict,
            confidence_score=result.confidence,
            analysis_method=result.method,
            whois_info=str(result.metadata)
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Database logging failed: {e}")

    return jsonify({
        'result': result.verdict,
        'score': result.confidence,
        'source': result.method,
        'metadata': result.metadata,
        'safe_mode': result.safe_mode,
        'forensic': {
            'top_features': result.top_features,
            'layer_votes': result.layer_votes,
            'consensus_ratio': result.consensus_ratio,
            'explanation': result.explanation
        }
    })


@main_bp.route('/analyze/image', methods=['POST'])
@login_required
def analyze_image():
    """
    Handle image upload and analysis via AJAX using MasterEngine.
    Returns JSON with forensic data: verdict, MSE, SSIM, heatmap URL, anomaly regions.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Validate file type
    allowed_ext = {'.png', '.jpg', '.jpeg'}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed_ext:
        return jsonify({'error': 'Invalid file type. Please upload a PNG or JPG image.'}), 400

    # Secure filename and save
    filename = secure_filename(file.filename)
    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    try:
        # Full forensic analysis with heatmap generation
        result = MasterEngine.analyze_image(filepath, output_dir=upload_folder)

        # Log to database
        try:
            log = ThreatLog(
                timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
                scan_type="IMG",
                input_data=filename,
                result_status=result.verdict,
                confidence_score=float(result.mse_score),
                analysis_method=result.method,
                whois_info=f"SSIM:{result.ssim_score}"
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            current_app.logger.error(f"Database logging failed: {e}")

        return jsonify({
            'result': result.verdict,
            'mse': round(float(result.mse_score), 5),
            'ssim': round(float(result.ssim_score), 4),
            'source': result.method,
            'threshold': 0.022,
            'verdict_tier': result.verdict_tier,
            'safe_mode': result.safe_mode,
            'forensic': {
                'heatmap_url': result.heatmap_url,
                'anomalous_regions': result.anomalous_regions
            }
        })

    except Exception as e:
        current_app.logger.error(f"Image analysis failed: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        # Clean up the original upload (heatmap triptych persists separately)
        try:
            os.remove(filepath)
        except OSError:
            pass


@main_bp.route('/api/feed', methods=['GET'])
def live_feed():
    """Return last 10 logs as JSON for live threat feed refresh."""
    logs = ThreatLog.query.order_by(ThreatLog.id.desc()).limit(10).all()
    return jsonify({'logs': [log.to_dict() for log in logs]})
