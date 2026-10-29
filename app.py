import os
from flask import Flask, render_template, request, redirect, url_for, flash
import scanner.scanner as vuln_scanner
from scanner.target import validate_target

app = Flask(__name__)
# Set VULNSCAN_SECRET_KEY to keep sessions valid across restarts
app.secret_key = os.environ.get('VULNSCAN_SECRET_KEY') or os.urandom(32)

# Global variable for simplicity
scan_results = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_url = (request.form.get('target_url') or '').strip()
        if not target_url:
            flash('Please enter a valid URL', 'danger')
        elif (error := validate_target(target_url)):
            flash(error, 'danger')
        else:
            results = vuln_scanner.start_scan(target_url)
            global scan_results
            scan_results = results
            return redirect(url_for('results'))
    return render_template('index.html')

@app.route('/results')
def results():
    return render_template('results.html', results=scan_results)

@app.route('/guidance')
def guidance():
    return render_template('guidance.html', results=scan_results)

if __name__ == '__main__':
    # Never enable debug on a reachable host: the Werkzeug debugger allows code execution
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
