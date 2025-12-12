"""
Flask Dashboard Application
Displays honeypot attack data and statistics.
"""

import os
import sys
from flask import Flask, render_template, jsonify

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeypot.logger import AttackLogger

app = Flask(__name__)
logger = AttackLogger(log_dir=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs'))


@app.route('/')
def index():
    """Main dashboard page."""
    stats = logger.get_attack_statistics()
    return render_template('index.html', stats=stats)


@app.route('/api/stats')
def api_stats():
    """API endpoint for attack statistics."""
    stats = logger.get_attack_statistics()
    return jsonify(stats)


@app.route('/api/attacks')
def api_attacks():
    """API endpoint for all attacks."""
    attacks = logger.get_all_attacks()
    return jsonify(attacks)


@app.route('/api/attacks/<attack_type>')
def api_attacks_by_type(attack_type):
    """API endpoint for attacks by type."""
    attacks = logger.get_attacks_by_type(attack_type)
    return jsonify(attacks)


@app.route('/attacks')
def attacks_page():
    """Detailed attacks page."""
    attacks = logger.get_all_attacks()
    return render_template('attacks.html', attacks=attacks)


@app.route('/attackers')
def attackers_page():
    """Top attackers page."""
    stats = logger.get_attack_statistics()
    return render_template('attackers.html', stats=stats)


def run_dashboard(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask dashboard.
    
    Args:
        host: Host address to bind to
        port: Port number to listen on
        debug: Enable debug mode (WARNING: Never enable in production!)
    """
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    # Development mode only - debug=True should never be used in production
    run_dashboard(debug=True)
