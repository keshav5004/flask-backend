import os
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from werkzeug.exceptions import BadRequest, InternalServerError

from services.checker import CSVBlacklistChecker
from services.similarity_checker import SimilarityChecker, get_risk_color, get_risk_label
from services.database import init_db, save_scan, get_history, get_stats

# Initialize Flask application
app = Flask(__name__)

# Enable Cross-Origin Resource Sharing (CORS)
CORS(app)

# Construct absolute path to the local blacklist database CSV
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, 'data', 'phishing_site_urls.csv')

# Global references
checker = None
similarity_checker = None
init_error = None

# Initialize database schema and services
try:
    init_db()
    checker = CSVBlacklistChecker(CSV_PATH)
    similarity_checker = SimilarityChecker(checker.blacklist)
except Exception as e:
    init_error = e


@app.before_request
def check_service_status():
    """
    Runs before every incoming request to ensure the threat intelligence services
    were correctly initialized.
    """
    global init_error
    if init_error:
        if isinstance(init_error, FileNotFoundError):
            raise init_error
        raise InternalServerError(f"Failed to initialize threat services: {str(init_error)}")


@app.context_processor
def inject_global_data():
    """
    Injects dynamic general telemetry data globally into templates.
    """
    count = len(checker.blacklist) if checker else 0
    return dict(dataset_count=count)


# ==========================================
# Template Frontend Routes
# ==========================================

@app.route('/')
def index():
    """Renders the main scanning hero page."""
    return render_template('index.html')


@app.route('/scan-result')
def scan_result_view():
    """
    Dedicated results page pulling telemetry for a past scan,
    or handling direct query param redirects.
    """
    scan_id = request.args.get('id')
    url = request.args.get('url')
    
    # Locate scan in history or perform scan on-the-fly
    history = get_history(limit=200)
    matched_scan = None
    
    if scan_id:
        for item in history:
            if str(item['id']) == str(scan_id):
                matched_scan = item
                break
                
    if not matched_scan and url:
        # If not found but URL is given, look up if already scanned
        for item in history:
            if item['url'].lower() == url.lower():
                matched_scan = item
                break

    if not matched_scan:
        return redirect(url_for('index'))

    # Determine risk highlight color for the frontend layout
    color = get_risk_color(matched_scan['risk_level'])
    return render_template('result.html', scan=matched_scan, risk_color=color)


@app.route('/dashboard')
def dashboard():
    """Renders the statistics and historical logs view."""
    stats = get_stats()
    history = get_history(limit=50)
    return render_template('dashboard.html', stats=stats, history=history)


@app.route('/about')
def about():
    """Renders the system explanation details page."""
    return render_template('about.html')


# ==========================================
# API Endpoints
# ==========================================

@app.route('/scan', methods=['POST'])
def scan_url():
    """
    POST endpoint to scan a website URL and determine its safety index.
    Combines exact matching database checks with fuzzy similarity heuristics.
    
    Accepts JSON body:
    {
        "url": "https://example.com"
    }
    """
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({
            "error": "Bad Request",
            "message": "Invalid JSON payload. Request must be application/json."
        }), 400

    url = data.get('url')
    if not url:
        return jsonify({
            "error": "Bad Request",
            "message": "Missing required field: 'url'"
        }), 400

    if not isinstance(url, str):
        return jsonify({
            "error": "Bad Request",
            "message": "The 'url' parameter must be a string."
        }), 400

    # 1. Normalize the URL
    normalized = checker.normalize_url(url)
    if not normalized:
        return jsonify({
            "error": "Bad Request",
            "message": "The provided URL could not be parsed."
        }), 400

    # 2. Level 1 Check: Blacklist Exact Match
    is_blacklisted = checker.is_malicious(url)

    if is_blacklisted:
        risk_score = 100
        risk_level = "malicious"
        similarity_score = 1.0
        matched_domain = normalized
        signals = ["This website is a known dangerous site — do not enter any personal information"]
        detection_method = "exact"
        status = "malicious"
        message = "Website found in exact blacklist. Danger: Do not visit."
    else:
        # 3. Level 2 Check: Similarity & Heuristics
        analysis = similarity_checker.analyze(url)
        risk_score = analysis["risk_score"]
        risk_level = analysis["risk_level"]
        similarity_score = analysis["similarity_score"]
        matched_domain = analysis["matched_domain"]
        signals = analysis["signals"]
        detection_method = analysis["detection_method"]
        status = "malicious" if risk_level in ["high", "malicious"] else "safe"
        
        if risk_level == "safe":
            message = "Website clean of threat matches."
        else:
            message = f"Suspicious activity index: {risk_level.upper()} threat rating."

    # 4. Save results to the SQLite local history db
    scan_id = save_scan(
        url=url,
        normalized_url=normalized,
        status=status,
        risk_level=risk_level,
        risk_score=risk_score,
        similarity_score=similarity_score,
        matched_domain=matched_domain,
        detection_method=detection_method,
        signals=signals
    )

    # 5. Return complete scan report response
    return jsonify({
        "scan_id": scan_id,
        "url": url,
        "normalized_url": normalized,
        "status": status,
        "safe": status == "safe",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "similarity_score": similarity_score,
        "matched_domain": matched_domain,
        "detection_method": detection_method,
        "signals": signals,
        "message": message
    }), 200


@app.route('/api/check', methods=['GET'])
def api_check_url():
    """
    GET endpoint for the Chrome Extension.
    Performs both exact blacklist matching AND similarity/heuristic analysis
    to properly detect phishing sites that use lookalike domains.
    Does NOT save to scan history to avoid polluting the database
    with automatic background scans from the extension.
    """
    url = request.args.get('url')
    if not url:
        return jsonify({
            "error": "Bad Request",
            "message": "Missing required query parameter: 'url'"
        }), 400

    normalized = checker.normalize_url(url)
    if not normalized:
        return jsonify({
            "error": "Bad Request",
            "message": "The provided URL could not be parsed."
        }), 400

    # Level 1: Exact blacklist match
    is_blacklisted = checker.is_malicious(url)

    if is_blacklisted:
        return jsonify({
            "url": url,
            "normalized_url": normalized,
            "status": "malicious",
            "safe": False,
            "risk_score": 100,
            "risk_level": "malicious",
            "detection_method": "exact",
            "signals": ["This website is a known dangerous site — do not enter any personal information"],
            "message": "PHISHING WEBSITE DETECTED - Do not visit."
        }), 200

    # Level 2: Similarity & heuristic analysis
    analysis = similarity_checker.analyze(url)
    risk_score = analysis["risk_score"]
    risk_level = analysis["risk_level"]
    status = "malicious" if risk_level in ["high", "malicious"] else "safe"

    if risk_level == "safe":
        message = "Website is safe."
    else:
        message = f"Suspicious activity index: {risk_level.upper()} threat rating."

    return jsonify({
        "url": url,
        "normalized_url": normalized,
        "status": status,
        "safe": status == "safe",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "similarity_score": analysis["similarity_score"],
        "matched_domain": analysis["matched_domain"],
        "detection_method": analysis["detection_method"],
        "signals": analysis["signals"],
        "message": message
    }), 200


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Retrieve full dashboard stats and JSON trends telemetry."""
    return jsonify(get_stats()), 200


# ==========================================
# Error Handlers
# ==========================================

@app.errorhandler(BadRequest)
def handle_bad_request(error):
    return jsonify({
        "error": "Bad Request",
        "message": error.description or "Request payload is invalid."
    }), 400


@app.errorhandler(FileNotFoundError)
def handle_file_not_found(error):
    return jsonify({
        "error": "Dataset Missing",
        "message": f"Critical server error: The malicious URLs CSV dataset file is missing. {str(error)}"
    }), 500


@app.errorhandler(Exception)
def handle_general_exception(error):
    return jsonify({
        "error": "Internal Server Error",
        "message": "An unexpected error occurred on the server.",
        "details": str(error)
    }), 500


if __name__ == '__main__':
    import sys

    # Use --dev flag for development mode, otherwise run production
    if '--dev' in sys.argv:
        print(" * Running in DEVELOPMENT mode (Flask built-in server)")
        app.run(host='127.0.0.1', port=5000, debug=True)
    else:
        from waitress import serve
        print("=" * 55)
        print("  WebShield - Production Server (Waitress)")
        print("=" * 55)
        print(f"  Serving on: http://127.0.0.1:5000")
        print(f"  Dataset:    {len(checker.blacklist) if checker else 0} malicious domains loaded")
        print(f"  Mode:       Production")
        print("=" * 55)
        serve(app, host='0.0.0.0', port=5000, threads=4)
