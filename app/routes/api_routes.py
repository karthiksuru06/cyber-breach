"""
REST API Routes
===============
JSON API endpoints for programmatic access with MasterEngine integration.
Returns full forensic data: ensemble votes, feature attribution, heatmaps.
"""

import os
import datetime
import json
from flask import request, jsonify, current_app
from werkzeug.utils import secure_filename

from app.routes import api_bp
from app.models import ThreatLog
from app import db
from app.ai_engine import MasterEngine


@api_bp.route('/analyze', methods=['POST'])
def analyze_url():
    """
    Analyze URL via JSON API with full forensic output.

    Request Body (JSON):
        {
            "url": "https://example.com"
        }

    Response (JSON):
        {
            "status": "SAFE",
            "confidence": 99.9,
            "analysis_method": "Heuristic Whitelist",
            "safe_mode": false,
            "forensic": {
                "top_features": [...],
                "layer_votes": [...],
                "consensus_ratio": 0.75,
                "explanation": "..."
            },
            "metadata": {...},
            "timestamp": "2026-02-06T17:30:00.123456"
        }

    Status Codes:
        200: Success
        400: Bad request (missing/invalid URL)
        500: Server error
    """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing "url" parameter in request body'}), 400

        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400

        # Full forensic analysis via MasterEngine
        result = MasterEngine.analyze_url(url)

        # Log to database
        try:
            log = ThreatLog(
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="URL",
                input_data=url,
                result_status=result.verdict,
                confidence_score=result.confidence,
                analysis_method=result.method,
                whois_info=json.dumps(result.metadata, default=str)
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            current_app.logger.error(f"Database logging failed: {e}")

        return jsonify({
            'status': result.verdict,
            'confidence': result.confidence,
            'analysis_method': result.method,
            'safe_mode': result.safe_mode,
            'forensic': {
                'top_features': result.top_features,
                'layer_votes': result.layer_votes,
                'consensus_ratio': result.consensus_ratio,
                'explanation': result.explanation
            },
            'metadata': result.metadata,
            'timestamp': datetime.datetime.now().isoformat()
        }), 200

    except Exception as e:
        current_app.logger.error(f"API error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/analyze/image', methods=['POST'])
def analyze_image_api():
    """
    Analyze image via API (multipart upload) with forensic heatmap.

    Request: multipart/form-data with 'file' field
    Response: JSON with verdict, MSE, SSIM, heatmap URL, anomaly regions
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
        return jsonify({'error': 'Invalid file type. Accepted formats: PNG, JPG, JPEG'}), 400

    filename = secure_filename(file.filename)
    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    try:
        # Full forensic analysis with heatmap generation
        result = MasterEngine.analyze_image(filepath, output_dir=upload_folder)

        try:
            log = ThreatLog(
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
            'status': result.verdict,
            'mse': round(float(result.mse_score), 5),
            'ssim': round(float(result.ssim_score), 4),
            'analysis_method': result.method,
            'verdict_tier': result.verdict_tier,
            'safe_mode': result.safe_mode,
            'threshold': 0.022,
            'forensic': {
                'heatmap_url': result.heatmap_url,
                'anomalous_regions': result.anomalous_regions
            },
            'timestamp': datetime.datetime.now().isoformat()
        }), 200

    except Exception as e:
        current_app.logger.error(f"API error: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        try:
            os.remove(filepath)
        except OSError:
            pass


@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """
    Retrieve threat intelligence logs.

    Query Parameters:
        limit: Number of logs to return (default: 50, max: 1000)
        status: Filter by status (SAFE, MALICIOUS, etc.)
        type: Filter by scan type (URL, IMG)

    Response (JSON):
        {
            "logs": [...],
            "count": 10,
            "filters": {...}
        }
    """
    try:
        limit = min(request.args.get('limit', 50, type=int), 1000)
        status_filter = request.args.get('status', None)
        type_filter = request.args.get('type', None)

        query = ThreatLog.query

        if status_filter:
            query = query.filter_by(result_status=status_filter.upper())

        if type_filter:
            query = query.filter_by(scan_type=type_filter.upper())

        logs = query.order_by(ThreatLog.id.desc()).limit(limit).all()

        return jsonify({
            'logs': [log.to_dict() for log in logs],
            'count': len(logs),
            'filters': {
                'status': status_filter,
                'type': type_filter,
                'limit': limit
            }
        }), 200

    except Exception as e:
        current_app.logger.error(f"API error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring.

    Response (JSON):
        {
            "status": "healthy" | "degraded",
            "mode": "Full Neural" | "Safe Mode: Heuristic Analysis Only",
            "models": {...},
            "version": "3.0"
        }
    """
    from app.ai_engine.model_loader import models_available
    from app.utils.threat_intel import get_threat_db_stats

    models_status = models_available()
    threat_stats = get_threat_db_stats()

    all_online = all(models_status.values())

    return jsonify({
        'status': 'healthy' if all_online else 'degraded',
        'mode': 'Full Neural' if all_online else 'Safe Mode: Heuristic Analysis Only',
        'models': models_status,
        'threat_intel_loaded': threat_stats['loaded'],
        'threat_count': threat_stats['count'],
        'version': '3.0'
    }), 200
