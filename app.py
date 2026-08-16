# app.py
from flask import Flask, render_template, request
from crypto_analyzer import generate_report, ALGORITHM_DB
from scanner import scan_and_report
app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None

    if request.method == "POST":
        algo = request.form.get("algorithm", "")
        key_size_raw = request.form.get("key_size", "")

        try:
            key_size = int(key_size_raw)
            report = generate_report(algo, key_size)
            if "error" in report:
                error = report["error"]
                report = None
        except ValueError:
            error = "Key size must be a number."

    return render_template(
        "index.html",
        algorithms=list(ALGORITHM_DB.keys()),
        report=report,
        error=error
    )
@app.route("/scan", methods=["GET", "POST"])
def scan():
    results = None
    code_text = ""

    if request.method == "POST":
        code_text = request.form.get("code_text", "")
        if code_text.strip():
            results = scan_and_report(code_text)

    return render_template("scan.html", results=results, code_text=code_text)

if __name__ == "__main__":
    app.run(debug=True)