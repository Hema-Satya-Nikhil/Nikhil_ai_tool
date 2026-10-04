"""Harmless local-only training fixture. Never binds to a non-loopback address."""
from __future__ import annotations

from flask import Flask, jsonify, make_response, request
from html import escape

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
_state = {"requests": 0}


@app.before_request
def count_local_request():
    _state["requests"] += 1


@app.after_request
def intentionally_weak_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    # Deliberately omits common security headers for local scanner exercises.
    return response


@app.get("/")
def index():
    response = make_response(
        "<!doctype html><title>Local BugHunter Lab</title>"
        "<h1>Harmless local assessment fixture</h1>"
        "<a href='/api/profile'>API profile</a>"
        "<a href='/upload'>Upload form</a>"
        "<a href='/search?q=demo'>Search</a>"
        "<a href='/lab-resource/test-1001'>Synthetic resource</a>"
        "<script src='/static/app.js'></script>"
        "<form action='/login' method='post'><input name='username'><input name='password' type='password'></form>"
    )
    response.set_cookie("sessionid", "LAB-ONLY-NOT-A-REAL-SESSION")
    return response


@app.get("/api/profile")
def profile():
    return jsonify({"name": "synthetic local test user", "role": "researcher"})


@app.get("/api/openapi.json")
def openapi():
    return jsonify({"openapi": "3.0.0", "info": {"title": "Local Lab API", "version": "1.0"}, "paths": {"/api/profile": {"get": {"summary": "Synthetic profile"}}}})


@app.get("/lab-resource/test-1001")
def test_resource():
    # Deliberately public synthetic training record. No real user data exists.
    return jsonify({"resource_id": "test-1001", "owner": "local-test-account-a", "label": "synthetic lab record"})


@app.get("/upload")
def upload_form():
    return "<title>Upload Lab</title><form action='/upload' method='post' enctype='multipart/form-data'><input type='file' name='document' accept='.txt,.pdf'></form>"


@app.post("/upload")
def upload_discard():
    uploaded = request.files.get("document")
    # File bytes are inspected only in memory and are not persisted. This route
    # exists solely to let researchers exercise a harmless local upload flow.
    size = len(uploaded.read(16 * 1024 + 1)) if uploaded else 0
    return jsonify({"accepted_for_lab": bool(uploaded), "bytes_seen": min(size, 16 * 1024), "persisted": False}), 200


@app.get("/search")
def search():
    value = escape(request.args.get("q", ""))
    if "'" in value:
        return "Synthetic SQLite error near quote (local training fixture)", 500
    return f"<title>Search</title><p>Search terms are rendered as text: {value}</p>"


@app.get("/sqli-lab")
def sqli_lab():
    # Synthetic response difference; no SQL parser or database is present.
    if "'" in request.args.get("q", ""):
        return "Synthetic SQLite error near quote (local training fixture)", 500
    return "Synthetic search response", 200


@app.get("/nosql-lab")
def nosql_lab():
    return jsonify({"filter": escape(request.args.get("filter", "")), "records": [{"id": "synthetic-1"}]})


@app.get("/command-lab")
def command_lab():
    # The parameter is never passed to an OS command or shell.
    return jsonify({"operation": escape(request.args.get("command", "status")), "result": "synthetic operation only"})


@app.get("/path-lab")
def path_lab():
    # The value is displayed as text only; no filesystem access occurs.
    return jsonify({"requested_name": escape(request.args.get("file", "sample.txt")), "file_read": False})


@app.get("/template-lab")
def template_lab():
    # Error text is static and synthetic; no expression is evaluated.
    return "Synthetic Jinja2.exceptions.TemplateSyntaxError fixture marker", 200, {"Content-Type": "text/plain"}


@app.get("/debug")
def debug_hint():
    return "Synthetic debug detail: local fixture only; no stack or secret data", 200, {"Content-Type": "text/plain"}


@app.get("/.well-known/security.txt")
def security_txt():
    return "Contact: mailto:security@example.invalid\nPolicy: /\n", 200, {"Content-Type": "text/plain"}


@app.get("/robots.txt")
def robots():
    sitemap_url = request.host_url.rstrip("/") + "/sitemap.xml"
    return f"User-agent: *\nAllow: /\nDisallow: /admin-lab\nSitemap: {sitemap_url}\n", 200, {"Content-Type": "text/plain"}


@app.get("/sitemap.xml")
def sitemap():
    profile_url = request.host_url.rstrip("/") + "/api/profile"
    return f"<urlset><url><loc>{escape(profile_url)}</loc></url></urlset>", 200, {"Content-Type": "application/xml"}


@app.get("/admin-lab")
def admin_hint():
    return "Synthetic lab route only", 200


@app.get("/__lab/status")
def lab_status():
    return jsonify({"requests_since_reset": _state["requests"], "data_is_synthetic": True, "uploads_persisted": False})


@app.post("/__lab/reset")
def reset_lab():
    _state["requests"] = 0
    return jsonify({"reset": True, "data_is_synthetic": True})


if __name__ == "__main__":
    # Hard-coded loopback bind; do not add a CLI option for external interfaces.
    app.run(host="127.0.0.1", port=5001, debug=False)
