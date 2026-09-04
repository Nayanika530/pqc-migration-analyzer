# app.py
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, Response, redirect, url_for
from crypto_analyzer import (
    generate_report, ALGORITHM_DB, NIST_STANDARDS_DB, calculate_harvest_risk,
    get_ai_explanation, chat_with_assistant, scan_live_website
)
from scanner import (
    scan_and_report, generate_cbom, calculate_agility_score,
    generate_migration_roadmap, export_roadmap_as_markdown, generate_risk_forecast
)
from inventory import GLOBAL_INVENTORY, parse_certificate_content
from dependency_graph import get_dependency_graph, get_all_dependency_graphs, build_codebase_dependency_graph
from migration_simulator import MigrationSimulator
from nist_benchmarks import get_all_benchmark_metrics, get_algorithm_metrics, NIST_ALGORITHM_METRICS
from master_migration_engine import MasterMigrationEngine
from evaluation import run_evaluation, StaticAnalysisEvaluator
from benchmark import run_full_statistical_benchmark, get_system_telemetry
import json

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


@app.route("/health")
@app.route("/ping")
def health():
    return jsonify({"status": "ok", "service": "qryptis-pqc-analyzer", "message": "heartbeat"}), 200


@app.route("/qryptis")
def qryptis():
    return render_template("qryptis/base.html", slides=QRYPTIS_SLIDES)


@app.context_processor
def inject_user():
    return dict(current_user=session.get("user"))


@app.route("/", methods=["GET", "POST"])
def home():
    # If the user is authenticated (including guest demo), render the main website
    if session.get("user"):
        return render_template("home.html")
    
    # If unauthenticated, present the login gateway at the root URL
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


def setup_demo_session():
    """Establish guest analyst session and pre-load canonical enterprise sample data."""
    # 1. Guarantee canonical 47-asset enterprise sample is loaded into unified inventory
    GLOBAL_INVENTORY.load_sample_inventory()

    # 2. Pre-load sample code scan results
    sample_file = os.path.join(os.path.dirname(__file__), "tests", "messy_sample.py")
    sample_code = ""
    if os.path.exists(sample_file):
        try:
            with open(sample_file, "r", encoding="utf-8") as f:
                sample_code = f.read()
        except Exception:
            pass

    if not sample_code:
        sample_code = (
            "from Crypto.PublicKey import RSA\n"
            "from Crypto.Cipher import DES3\n"
            "import hashlib\n\n"
            "# Legacy enterprise auth module\n"
            "key = RSA.generate(2048)\n"
            "cipher = DES3.new(b'1234567890123456', DES3.MODE_CBC)\n"
            "token_hash = hashlib.md5(b'session_secret').hexdigest()\n"
        )

    try:
        results = scan_and_report(sample_code)
        session["last_scan_results"] = [
            {
                "line_number": r["line_number"],
                "matched_text": r["matched_text"],
                "report": r["report"],
                "suggested_fix": r.get("suggested_fix", "")
            }
            for r in results
        ]
        session["last_agility"] = calculate_agility_score(results)
        session["last_roadmap"] = generate_migration_roadmap(results)
        session["demo_code"] = sample_code
    except Exception:
        pass

    # 3. Create guest user profile
    session["user"] = {
        "username": "guest_analyst",
        "email": "guest.analyst@qryptis.demo",
        "name": "Guest Analyst",
        "role": "Demo Guest Analyst",
        "is_guest": True,
        "provider": "guest_demo"
    }
    session["is_demo"] = True


@app.route("/demo")
@app.route("/login/demo")
def demo_login():
    setup_demo_session()
    next_url = request.args.get("next")
    # Avoid redirect loops to login/demo endpoints
    if not next_url or next_url in ["/login", "/login/demo", "/demo"]:
        target = request.args.get("target", "home")
        if target == "inventory":
            return redirect(url_for("inventory"))
        elif target == "analyze":
            return redirect(url_for("analyze"))
        elif target == "scan":
            return redirect(url_for("scan", view="results"))
        return redirect(url_for("home"))
    return redirect(next_url)


@app.route("/demo/reset")
def demo_reset():
    setup_demo_session()
    next_url = request.args.get("next") or request.referrer or url_for("inventory")
    return redirect(next_url)


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("is_demo", None)
    session.pop("demo_code", None)
    session.pop("last_scan_results", None)
    session.pop("last_agility", None)
    session.pop("last_roadmap", None)
    return redirect(url_for("home"))


@app.route("/analyze")
def analyze():
    return render_template("analyze.html")


@app.route("/database")
def database():
    return render_template("database.html", algorithm_db=ALGORITHM_DB, nist_standards=NIST_STANDARDS_DB)


@app.route("/api/standards")
def api_standards():
    return jsonify({
        "status": "success",
        "nist_pqc_standards": NIST_STANDARDS_DB,
        "recommendation": "NIST explicitly recommends organizations begin applying standardized PQC algorithms (FIPS 203, 204, 205) and preparing for Round 4 alternatives (HQC) now."
    })


@app.route("/inventory", methods=["GET", "POST"])
def inventory():
    msg = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "load_sample":
            GLOBAL_INVENTORY.load_sample_inventory()
            msg = "Loaded canonical 47-asset enterprise sample."
        elif action == "clear":
            GLOBAL_INVENTORY.clear()
            msg = "Inventory cleared."
        elif action == "add_website":
            domain = request.form.get("domain", "").strip()
            if domain:
                res = scan_live_website(domain)
                if not res.get("error"):
                    GLOBAL_INVENTORY.add_live_scan(res, target_name=domain)
                    msg = f"Ingested live TLS findings from {domain}."
                else:
                    msg = f"Error scanning domain: {res.get('error')}"
        elif action == "add_code":
            code_text = request.form.get("code", "")
            target_name = request.form.get("target_name", "Codebase").strip() or "Codebase"
            if code_text.strip():
                scan_res = scan_and_report(code_text)
                GLOBAL_INVENTORY.add_code_findings(scan_res["results"], target_name=target_name)
                msg = f"Ingested {len(scan_res['results'])} findings from {target_name}."
        elif action == "add_cert":
            cert_text = request.form.get("cert_text", "")
            filename = request.form.get("filename", "server.pem").strip() or "server.pem"
            if cert_text.strip():
                GLOBAL_INVENTORY.add_certificate(cert_text, filename=filename)
                msg = f"Ingested certificate findings from {filename}."

    summary = GLOBAL_INVENTORY.get_summary()
    assets = [a.to_dict() for a in GLOBAL_INVENTORY.assets]
    return render_template("inventory.html", summary=summary, assets=assets, message=msg)


@app.route("/api/inventory", methods=["GET"])
def api_inventory():
    summary = GLOBAL_INVENTORY.get_summary()
    return jsonify({
        "status": "success",
        "inventory": summary,
        "assets": [a.to_dict() for a in GLOBAL_INVENTORY.assets]
    })


@app.route("/api/inventory/load-sample", methods=["POST"])
def api_inventory_sample():
    GLOBAL_INVENTORY.load_sample_inventory()
    return jsonify({"status": "success", "message": "Sample 47-asset inventory loaded", "summary": GLOBAL_INVENTORY.get_summary()})


@app.route("/api/inventory/clear", methods=["POST"])
def api_inventory_clear():
    GLOBAL_INVENTORY.clear()
    return jsonify({"status": "success", "message": "Inventory cleared", "summary": GLOBAL_INVENTORY.get_summary()})


@app.route("/api/inventory/add-code", methods=["POST"])
def api_inventory_add_code():
    data = request.get_json(silent=True) or {}
    code_text = data.get("code", "") or request.form.get("code", "")
    target = data.get("target_name", "Codebase") or request.form.get("target_name", "Codebase")
    if not code_text.strip():
        return jsonify({"error": "Empty code payload"}), 400
    scan_res = scan_and_report(code_text)
    GLOBAL_INVENTORY.add_code_findings(scan_res["results"], target_name=target)
    return jsonify({"status": "success", "added": len(scan_res["results"]), "summary": GLOBAL_INVENTORY.get_summary()})


@app.route("/api/inventory/add-network", methods=["POST"])
def api_inventory_add_network():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "") or request.form.get("domain", "")
    if not domain.strip():
        return jsonify({"error": "Domain required"}), 400
    res = scan_live_website(domain)
    if res.get("error"):
        return jsonify({"error": res["error"]}), 400
    GLOBAL_INVENTORY.add_live_scan(res, target_name=domain)
    return jsonify({"status": "success", "domain": domain, "summary": GLOBAL_INVENTORY.get_summary()})


@app.route("/api/inventory/add-cert", methods=["POST"])
def api_inventory_add_cert():
    data = request.get_json(silent=True) or {}
    cert_text = data.get("cert_text", "") or request.form.get("cert_text", "")
    filename = data.get("filename", "server.pem") or request.form.get("filename", "server.pem")
    if not cert_text.strip():
        return jsonify({"error": "Certificate text required"}), 400
    GLOBAL_INVENTORY.add_certificate(cert_text, filename=filename)
    return jsonify({"status": "success", "filename": filename, "summary": GLOBAL_INVENTORY.get_summary()})


@app.route("/api/inventory/add-manual", methods=["POST"])
def api_inventory_add_manual():
    data = request.get_json(silent=True) or {}
    algo = data.get("algorithm") or request.form.get("algorithm", "RSA")
    key_size = int(data.get("key_size") or request.form.get("key_size", 2048))
    report = generate_report(algo, key_size)
    if "error" in report:
        return jsonify({"error": report["error"]}), 400
    GLOBAL_INVENTORY.add_manual_finding(report, target_name=f"Manual: {algo}-{key_size}")
    return jsonify({"status": "success", "algorithm": algo, "key_size": key_size, "summary": GLOBAL_INVENTORY.get_summary()})


@app.route("/api/inventory/export/cbom", methods=["GET"])
def api_inventory_export_cbom():
    cbom_data = GLOBAL_INVENTORY.export_cbom()
    json_bytes = json.dumps(cbom_data, indent=2).encode("utf-8")
    return Response(
        json_bytes,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=enterprise_cbom.json"}
    )


@app.route("/graph")
@app.route("/graph/<algo>")
def graph(algo="RSA-2048"):
    selected_algo = request.args.get("algo") or algo or "RSA-2048"
    graph_data = get_dependency_graph(selected_algo)
    all_graphs = get_all_dependency_graphs()
    return render_template("graph.html", graph=graph_data, all_graphs=all_graphs, selected_algo=selected_algo)


@app.route("/api/graph")
def api_graph_all():
    return jsonify({
        "status": "success",
        "graphs": get_all_dependency_graphs()
    })


@app.route("/api/graph/<algo>")
def api_graph_single(algo):
    graph_data = get_dependency_graph(algo)
    return jsonify({
        "status": "success",
        "graph": graph_data
    })


@app.route("/simulator", methods=["GET", "POST"])
def simulator():
    src = request.form.get("source", "RSA-2048") if request.method == "POST" else (request.args.get("src") or "RSA-2048")
    tgt = request.form.get("target", "ML-KEM-768") if request.method == "POST" else (request.args.get("tgt") or "ML-KEM-768")
    sim_result = MigrationSimulator.simulate(src, tgt)
    all_metrics = get_all_benchmark_metrics()
    return render_template("simulator.html", sim=sim_result, all_metrics=all_metrics, selected_src=src, selected_tgt=tgt)


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json(silent=True) or {}
    src = data.get("source", request.form.get("source", "RSA-2048"))
    tgt = data.get("target", request.form.get("target", "ML-KEM-768"))
    sim_result = MigrationSimulator.simulate(src, tgt)
    return jsonify({
        "status": "success",
        "simulation": sim_result
    })


@app.route("/lab")
def benchmark_lab():
    metrics = get_all_benchmark_metrics()
    return render_template("benchmark_lab.html", metrics=metrics)


@app.route("/api/benchmarks/matrix")
@app.route("/api/benchmark/matrix")
def api_benchmarks_matrix():
    return jsonify({
        "status": "success",
        "matrix": get_all_benchmark_metrics()
    })


@app.route("/plan")
def migration_plan():
    plan_data = MasterMigrationEngine.generate_plan()
    return render_template("migration_plan.html", plan=plan_data)


@app.route("/api/migration/plan")
@app.route("/api/migration-plan")
def api_migration_plan():
    plan_data = MasterMigrationEngine.generate_plan()
    return jsonify({
        "status": "success",
        "plan": plan_data
    })


@app.route("/evaluation")
def evaluation():
    metrics = run_evaluation()
    return render_template("evaluation.html", metrics=metrics)


@app.route("/api/evaluate")
def api_evaluate():
    metrics = run_evaluation()
    return jsonify({
        "status": "success",
        "evaluation": metrics
    })


@app.route("/api/benchmark/live")
def api_benchmark_live():
    rounds = int(request.args.get("rounds", 20))
    report = run_full_statistical_benchmark(rounds=rounds)
    return jsonify({
        "status": "success",
        "benchmark": report
    })


@app.route("/live-scan", methods=["GET", "POST"])
def live_scan():
    result = None
    ingested = False

    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        auto_ingest = request.form.get("auto_ingest", "true") == "true" or "ingest" in request.form
        if domain:
            result = scan_live_website(domain)
            if not result.get("error") and auto_ingest:
                GLOBAL_INVENTORY.add_live_scan(result, target_name=domain)
                ingested = True

    return render_template("live_scan.html", result=result, ingested=ingested)


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
    ingested = False

    if request.method == "POST":
        algo = request.form.get("algorithm", "").strip()
        key_size_raw = request.form.get("key_size", "").strip()
        years_raw = request.form.get("years_secret", "").strip()
        auto_ingest = request.form.get("auto_ingest", "true") == "true" or "ingest" in request.form

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
                            # Ingest into Unified Inventory
                            if auto_ingest:
                                GLOBAL_INVENTORY.add_manual_finding(report, target_name=f"Manual: {algo}-{key_size}")
                                ingested = True

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
        summary=summary,
        ingested=ingested
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

    if request.method == "GET" and session.get("is_demo"):
        code_text = session.get("demo_code", "")
        if request.args.get("view") == "results":
            results = session.get("last_scan_results")
            agility = session.get("last_agility")
            roadmap = session.get("last_roadmap")
            if results:
                forecast = generate_risk_forecast(results)
                summary = {
                    "critical": sum(1 for r in results if r.get("severity") == "CRITICAL"),
                    "high": sum(1 for r in results if r.get("severity") == "HIGH"),
                    "medium": sum(1 for r in results if r.get("severity") == "MEDIUM"),
                    "low": sum(1 for r in results if r.get("severity") == "LOW"),
                    "deprecated": sum(1 for r in results if "DEPRECATED" in r.get("report", {}).get("verdict", "")),
                    "at_risk": sum(1 for r in results if "AT RISK" in r.get("report", {}).get("verdict", "")),
                    "safe": sum(1 for r in results if "OK" in r.get("report", {}).get("verdict", "") or "SAFE" in r.get("report", {}).get("verdict", ""))
                }
                filename = "messy_sample.py"

    if request.method == "POST":
        uploaded_file = request.files.get("code_file")

        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename
            code_text = uploaded_file.read().decode("utf-8", errors="ignore")
        else:
            code_text = request.form.get("code_text", "")

        if code_text.strip():
            results = scan_and_report(code_text)
            # Store compact findings in session to keep cookie payload tiny (<400 bytes)
            session["last_scan_results"] = [
                {
                    "line_number": r["line_number"],
                    "matched_text": r["matched_text"],
                    "report": r["report"],
                    "suggested_fix": r.get("suggested_fix", "")
                }
                for r in results
            ]
            agility = calculate_agility_score(results)
            roadmap = generate_migration_roadmap(results)
            forecast = generate_risk_forecast(results)
            session["last_agility"] = agility
            session["last_roadmap"] = roadmap

            # Dynamically update unified inventory so it is the single source of truth
            if results:
                GLOBAL_INVENTORY.clear()
                GLOBAL_INVENTORY.add_code_findings(results, target_name=filename)

            # Compute severity and verdict counts for dashboard & findings
            counts = {
                "critical": sum(1 for r in results if r.get("severity") == "CRITICAL"),
                "high": sum(1 for r in results if r.get("severity") == "HIGH"),
                "medium": sum(1 for r in results if r.get("severity") == "MEDIUM"),
                "low": sum(1 for r in results if r.get("severity") == "LOW"),
                "deprecated": sum(1 for r in results if "DEPRECATED" in r.get("report", {}).get("verdict", "")),
                "at_risk": sum(1 for r in results if "AT RISK" in r.get("report", {}).get("verdict", "")),
                "safe": sum(1 for r in results if "OK" in r.get("report", {}).get("verdict", "") or "SAFE" in r.get("report", {}).get("verdict", ""))
            }
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
    cbom = GLOBAL_INVENTORY.export_cbom()
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
    session["last_scan_results"] = [
        {
            "line_number": r["line_number"],
            "matched_text": r["matched_text"],
            "report": r["report"],
            "suggested_fix": r.get("suggested_fix", "")
        }
        for r in results
    ]
    agility = calculate_agility_score(results)
    roadmap = generate_migration_roadmap(results)
    forecast = generate_risk_forecast(results)
    session["last_agility"] = agility
    session["last_roadmap"] = roadmap

    counts = {
        "critical": sum(1 for r in results if r.get("severity") == "CRITICAL"),
        "high": sum(1 for r in results if r.get("severity") == "HIGH"),
        "medium": sum(1 for r in results if r.get("severity") == "MEDIUM"),
        "low": sum(1 for r in results if r.get("severity") == "LOW"),
        "deprecated": sum(1 for r in results if "DEPRECATED" in r.get("report", {}).get("verdict", "")),
        "at_risk": sum(1 for r in results if "AT RISK" in r.get("report", {}).get("verdict", "")),
        "safe": sum(1 for r in results if "OK" in r.get("report", {}).get("verdict", "") or "SAFE" in r.get("report", {}).get("verdict", ""))
    }

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