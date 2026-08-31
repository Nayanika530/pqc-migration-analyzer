# app.py
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, Response, redirect, url_for
from crypto_analyzer import (
    generate_report, ALGORITHM_DB, calculate_harvest_risk,
    get_ai_explanation, chat_with_assistant, scan_live_website
)
from scanner import (
    scan_and_report, generate_cbom, calculate_agility_score,
    generate_migration_roadmap, export_roadmap_as_markdown, generate_risk_forecast
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "pqc-analyzer-dev-secret-key-2026-replace-in-prod")

# ---- Qryptis: cursor-slider frontend ----
# Ordered list of Jinja partials included in the horizontal slide track.
# Add new slides by appending their path (relative to templates/).
QRYPTIS_SLIDES = [
    "qryptis/slides/slide_hero.html",
    "qryptis/slides/slide_threat.html",
    "qryptis/slides/slide_analyze.html",
    "qryptis/slides/slide_dashboard.html",
]


@app.route("/qryptis")
def qryptis():
    return render_template("qryptis/base.html", slides=QRYPTIS_SLIDES)


@app.context_processor
def inject_user():
    return dict(current_user=session.get("user"))


@app.route("/", methods=["GET", "POST"])
def home():
    # If the user is authenticated, render the main website
    if session.get("user"):
        return render_template("home.html")
    
    # If unauthenticated, present the login gateway at the same URL
    return login_handler()


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("home"))
    return login_handler()


def login_handler():
    error = None
    message = None
    next_url = request.args.get("next") or request.form.get("next") or url_for("home")

    if request.method == "POST":
        action_type = request.form.get("action_type", "signin")
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        full_name = request.form.get("full_name", "").strip()

        if action_type == "signup":
            if not username or not email or not password:
                error = "Please fill in all required fields."
            else:
                session["user"] = {
                    "username": username,
                    "email": email,
                    "name": full_name or username
                }
                return redirect(next_url or url_for("home"))
        else:
            login_identifier = request.form.get("login_identifier", "").strip() or request.form.get("username", "").strip() or request.form.get("email", "").strip()
            if not login_identifier or not password:
                error = "Please provide your username / email and password."
            else:
                name = login_identifier.split("@")[0].capitalize()
                session["user"] = {
                    "username": login_identifier,
                    "email": login_identifier if "@" in login_identifier else f"{login_identifier}@enterprise.org",
                    "name": name
                }
                return redirect(next_url or url_for("home"))

    return render_template("login.html", error=error, message=message, next_url=next_url)


@app.route("/login/sso/<provider>")
def sso_login(provider):
    provider_name = provider.capitalize()
    session["user"] = {
        "username": f"{provider}_analyst",
        "email": f"{provider}_user@enterprise.org",
        "name": f"{provider_name} Analyst",
        "provider": provider
    }
    next_url = request.args.get("next") or url_for("home")
    return redirect(next_url)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))


@app.route("/analyze")
def analyze():
    return render_template("analyze.html")


@app.route("/database")
def database():
    return render_template("database.html", algorithm_db=ALGORITHM_DB)


@app.route("/live-scan", methods=["GET", "POST"])
def live_scan():
    result = None

    if request.method == "POST":
        domain = request.form.get("domain", "")
        if domain.strip():
            result = scan_live_website(domain)

    return render_template("live_scan.html", result=result)


@app.route("/manual", methods=["GET", "POST"])
def manual():
    report = None
    error = None
    harvest_risk = None
    ai_explanation = None
    results = None
    agility = None
    roadmap = None
    forecast = None
    summary = None

    if request.method == "POST":
        algo = request.form.get("algorithm", "").strip()
        key_size_raw = request.form.get("key_size", "").strip()
        years_raw = request.form.get("years_secret", "").strip()

        if not algo or not key_size_raw:
            error = "Please specify both algorithm and key size."
        else:
            try:
                key_size = int(key_size_raw)
                if key_size <= 0:
                    error = "Key size must be a positive integer greater than 0."
                else:
                    report = generate_report(algo, key_size)
                    if "error" in report:
                        error = report["error"]
                        report = None
                    else:
                        ai_explanation = get_ai_explanation(report)
                        if years_raw:
                            try:
                                years_secret = int(years_raw)
                                if years_secret < 0:
                                    error = "Confidentiality requirement (years) cannot be negative."
                                else:
                                    harvest_risk = calculate_harvest_risk(algo, key_size, years_secret)
                            except ValueError:
                                error = "Confidentiality requirement must be a valid number of years."

                        if not error:
                            # Format as scan results so manual can render identical dashboard
                            finding_item = {
                                "line_number": 1,
                                "matched_text": f"{algo}.generate({key_size})" if algo in ["RSA", "DSA"] else f"{algo}.new(key, {key_size})",
                                "report": report,
                                "suggested_fix": report.get("recommended_replacement", "")
                            }
                            results = [finding_item]
                            session["last_scan_results"] = results
                            agility = calculate_agility_score(results)
                            roadmap = generate_migration_roadmap(results)
                            forecast = generate_risk_forecast(results)
                            session["last_agility"] = agility
                            session["last_roadmap"] = roadmap

                            counts = {"critical": 0, "deprecated": 0, "at_risk": 0, "safe": 0}
                            v = report.get("verdict", "")
                            if "DEPRECATED" in v:
                                counts["deprecated"] += 1
                            elif "CRITICAL" in v:
                                counts["critical"] += 1
                            elif "AT RISK" in v:
                                counts["at_risk"] += 1
                            else:
                                counts["safe"] += 1
                            summary = counts

            except ValueError:
                error = "Key size must be a valid number."

    return render_template(
        "manual.html",
        algorithms=list(ALGORITHM_DB.keys()),
        report=report,
        error=error,
        harvest_risk=harvest_risk,
        ai_explanation=ai_explanation,
        results=results,
        agility=agility,
        roadmap=roadmap,
        forecast=forecast,
        summary=summary
    )


@app.route("/scan", methods=["GET", "POST"])
def scan():
    results = None
    code_text = ""
    agility = None
    roadmap = None
    forecast = None
    summary = None
    filename = "pasted_code.py"

    if request.method == "POST":
        uploaded_file = request.files.get("code_file")

        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename
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

            # Compute verdict summary counts for the dashboard cards
            counts = {"critical": 0, "deprecated": 0, "at_risk": 0, "safe": 0}
            for r in results:
                v = r.get("report", {}).get("verdict", "")
                if "DEPRECATED" in v:
                    counts["deprecated"] += 1
                elif "CRITICAL" in v:
                    counts["critical"] += 1
                elif "AT RISK" in v:
                    counts["at_risk"] += 1
                else:
                    counts["safe"] += 1
            summary = counts

    return render_template(
        "scan.html",
        results=results,
        code_text=code_text,
        agility=agility,
        roadmap=roadmap,
        forecast=forecast,
        summary=summary,
        filename=filename,
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


@app.route("/api/scan", methods=["POST"])
def api_scan():
    code_text = ""
    filename = "pasted_code.py"

    if request.is_json:
        data = request.get_json()
        code_text = data.get("code", "")
        filename = data.get("filename", "pasted_code.py")
    else:
        uploaded_file = request.files.get("code_file")
        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename
            code_text = uploaded_file.read().decode("utf-8", errors="ignore")
        else:
            code_text = request.form.get("code_text", "")

    if not code_text.strip():
        return jsonify({"error": "No code provided to scan."}), 400

    results = scan_and_report(code_text)
    session["last_scan_results"] = results
    agility = calculate_agility_score(results)
    roadmap = generate_migration_roadmap(results)
    forecast = generate_risk_forecast(results)
    session["last_agility"] = agility
    session["last_roadmap"] = roadmap

    counts = {"critical": 0, "deprecated": 0, "at_risk": 0, "safe": 0}
    for r in results:
        v = r.get("report", {}).get("verdict", "")
        if "DEPRECATED" in v:
            counts["deprecated"] += 1
        elif "CRITICAL" in v:
            counts["critical"] += 1
        elif "AT RISK" in v:
            counts["at_risk"] += 1
        else:
            counts["safe"] += 1

    return jsonify({
        "success": True,
        "filename": filename,
        "results": results,
        "summary": counts,
        "agility": agility,
        "roadmap": roadmap,
        "forecast": forecast
    })


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json()
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"reply": "Please type a question."})

    reply = chat_with_assistant(user_message)
    return jsonify({"reply": reply})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)