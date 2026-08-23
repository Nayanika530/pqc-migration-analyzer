# app.py
from flask import Flask, render_template, request, jsonify, session, Response
from crypto_analyzer import (
    generate_report, ALGORITHM_DB, calculate_harvest_risk,
    get_ai_explanation, chat_with_assistant
)
from scanner import (
    scan_and_report, generate_cbom, calculate_agility_score,
    generate_migration_roadmap, export_roadmap_as_markdown, generate_risk_forecast
)

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-later"


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/analyze")
def analyze():
    return render_template("analyze.html")


@app.route("/manual", methods=["GET", "POST"])
def manual():
    report = None
    error = None
    harvest_risk = None
    ai_explanation = None

    if request.method == "POST":
        algo = request.form.get("algorithm", "")
        key_size_raw = request.form.get("key_size", "")
        years_raw = request.form.get("years_secret", "")

        try:
            key_size = int(key_size_raw)
            report = generate_report(algo, key_size)
            if "error" in report:
                error = report["error"]
                report = None
            else:
                ai_explanation = get_ai_explanation(report)
                if years_raw.strip():
                    years_secret = int(years_raw)
                    harvest_risk = calculate_harvest_risk(algo, key_size, years_secret)
        except ValueError:
            error = "Key size and years must be numbers."

    return render_template(
        "manual.html",
        algorithms=list(ALGORITHM_DB.keys()),
        report=report,
        error=error,
        harvest_risk=harvest_risk,
        ai_explanation=ai_explanation
    )


@app.route("/scan", methods=["GET", "POST"])
def scan():
    results = None
    code_text = ""
    agility = None
    roadmap = None
    forecast = None

    if request.method == "POST":
        uploaded_file = request.files.get("code_file")

        if uploaded_file and uploaded_file.filename:
            code_text = uploaded_file.read().decode("utf-8", errors="ignore")
        else:
            code_text = request.form.get("code_text", "")

        if code_text.strip():
            results = scan_and_report(code_text)
            session["last_scan_results"] = results
            agility = calculate_agility_score(results)
            roadmap = generate_migration_roadmap(results)
            forecast = generate_risk_forecast(results)
            session["last_agility"] = agility
            session["last_roadmap"] = roadmap

    return render_template(
        "scan.html",
        results=results,
        code_text=code_text,
        agility=agility,
        roadmap=roadmap,
        forecast=forecast
    )


@app.route("/download-cbom")
def download_cbom():
    results = session.get("last_scan_results")
    if not results:
        return "No scan results available. Please run a scan first.", 400

    cbom = generate_cbom(results, source_name="pasted_code.py")
    response = jsonify(cbom)
    response.headers["Content-Disposition"] = "attachment; filename=cbom.json"
    return response


@app.route("/download-roadmap")
def download_roadmap():
    roadmap = session.get("last_roadmap")
    agility = session.get("last_agility")
    if not roadmap:
        return "No scan results available. Please run a scan first.", 400

    markdown_report = export_roadmap_as_markdown(roadmap, agility)
    return Response(
        markdown_report,
        mimetype="text/markdown",
        headers={"Content-Disposition": "attachment; filename=migration_report.md"}
    )


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json()
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"reply": "Please type a question."})

    reply = chat_with_assistant(user_message)
    return jsonify({"reply": reply})


if __name__ == "__main__":
    app.run(debug=True)