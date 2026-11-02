"""Web app: enter a domain, find its subdomains from certificate logs, rank certificates by expiry."""
import os
import time
from collections import defaultdict, deque

from flask import Flask, abort, jsonify, render_template, request, Response

import scanner
from exporters import build_pdf, build_xlsx

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024

manager = scanner.JobManager(max_running=int(os.getenv("MAX_RUNNING_SCANS", "3")))
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_HOUR", "20"))
_hits = defaultdict(deque)


def _client_ip():
    if os.getenv("TRUST_PROXY", "0") == "1":
        return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    return request.remote_addr or "unknown"


def _rate_limited():
    now, q = time.time(), _hits[_client_ip()]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/api/scan")
def start_scan():
    body = request.get_json(silent=True) or {}
    try:
        domain = scanner.normalize_domain(str(body.get("domain", "")))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    if _rate_limited():
        return jsonify(error=f"Scan limit reached ({RATE_LIMIT} per hour). Try again later."), 429
    job = manager.start(domain, bool(body.get("deep")))
    if job is None:
        return jsonify(error="The server is busy with other scans. Try again in a minute."), 503
    return jsonify(id=job.id, domain=domain), 202


def _job_or_404(job_id):
    job = manager.get(job_id)
    if job is None:
        abort(404, description="Scan not found. Results are kept for one hour.")
    return job


@app.get("/api/scan/<job_id>")
def scan_status(job_id):
    return jsonify(_job_or_404(job_id).snapshot())


def _download(job_id, builder, mimetype, ext):
    job = _job_or_404(job_id)
    if job.phase != "done":
        abort(409, description="The scan is not finished yet.")
    snap = job.snapshot()
    return Response(builder(snap), mimetype=mimetype, headers={
        "Content-Disposition": f'attachment; filename="ssl-expiry-{snap["domain"]}.{ext}"'})


@app.get("/api/scan/<job_id>/export.xlsx")
def export_xlsx(job_id):
    return _download(job_id, build_xlsx,
                     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx")


@app.get("/api/scan/<job_id>/export.pdf")
def export_pdf(job_id):
    return _download(job_id, build_pdf, "application/pdf", "pdf")


@app.errorhandler(404)
@app.errorhandler(409)
def api_error(e):
    if request.path.startswith("/api/"):
        return jsonify(error=e.description), e.code
    return e


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")), debug=False)
