from flask import Flask, render_template, request, redirect, url_for, flash
import scanner.scanner as vuln_scanner

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key

# Global variable for simplicity
scan_results = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        if target_url:
            flash(f'Starting scan for {target_url}', 'info')
            results = vuln_scanner.start_scan(target_url)
            global scan_results
            scan_results = results
            return redirect(url_for('results'))
        else:
            flash('Please enter a valid URL', 'danger')
    return render_template('index.html')

@app.route('/results')
def results():
    return render_template('results.html', results=scan_results)

@app.route('/guidance')
def guidance():
    return render_template('guidance.html', results=scan_results)

if __name__ == '__main__':
    app.run(debug=True)
