from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from flask import Flask, jsonify, render_template, request, send_file

ROOT = Path(__file__).resolve().parent
DEMO_DIR = ROOT / "demo_project"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".rs", ".cs", ".php", ".rb", ".yaml", ".yml", ".toml", ".ini", ".json", ".xml", ".txt", ".env.example", ".properties", ".conf", ".pem", ".crt"}
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

PATTERNS = [
    ("RSA", re.compile(r"\bRSA(?:_?(?:PUBLIC|PRIVATE)_KEY)?\b|rsaEncryption|\brsa\s*[:=]", re.I), "Key establishment / signature", "quantum-vulnerable"),
    ("ECDSA", re.compile(r"\bECDSA\b|ecdsawith|ecdsa-with", re.I), "Digital signature", "quantum-vulnerable"),
    ("ECC", re.compile(r"\b(?:ECC|ECDH|ECDHE|secp\d+[kr]?1|prime256v1|P-256|X25519)\b", re.I), "Key establishment", "quantum-vulnerable"),
    ("AES", re.compile(r"\bAES(?:[-_/ ]?(?:128|192|256))?\b|AES/GCM|AES/CBC", re.I), "Symmetric encryption", "symmetric-review"),
    ("TLS", re.compile(r"\bTLS(?:v?1\.[0-3])?\b|ssl_protocols|https://", re.I), "Transport security", "depends-on-suite"),
    ("X.509", re.compile(r"\bX\.?509\b|BEGIN CERTIFICATE|\.(?:crt|pem)\b|cert(?:ificate)?_file\s*[:=]", re.I), "Certificate / PKI", "depends-on-certificate-key"),
]
FILE_CONTEXT = [
    (re.compile(r"auth|login"), "Patient credentials", 5, 2, "Medium"),
    (re.compile(r"exchange|share"), "Patient record exchange", 15, 4, "High"),
    (re.compile(r"consent"), "Consent forms", 10, 3, "High"),
    (re.compile(r"vault|storage|crypt"), "Medical records", 15, 4, "High"),
    (re.compile(r"nginx|tls|transport"), "API traffic", 5, 2, "Medium"),
    (re.compile(r"cert"), "Identity certificates", 3, 1, "Medium"),
]
ROADMAP = [
    "Confirm discovery evidence, application owners, data lifetimes and dependencies.",
    "Prioritize critical, long-lived records and identify current crypto providers.",
    "Pilot purpose-matched PQC or hybrid options; check size, speed and vendor support.",
    "Validate legal and operational needs, plan migration, and rescan after releases.",
]

def file_context(filename: str) -> tuple[str, int, int, str]:
    for pattern, component, lifetime, migration, criticality in FILE_CONTEXT:
        if pattern.search(filename.lower()):
            return component, lifetime, migration, criticality
    return "General application data", 10, 2, "Medium"

def inspect_text(text: str, filename: str) -> list[dict]:
    found = []
    component, lifetime, migration, criticality = file_context(filename)
    for line_no, line in enumerate(text.splitlines(), 1):
        for name, pattern, purpose, quantum_status in PATTERNS:
            if not pattern.search(line):
                continue
            excerpt = line.strip()[:200]
            confidence = 0.95 if re.search(r"\w\s*(?:=|\()|BEGIN CERTIFICATE", excerpt) else 0.65
            found.append({"algorithm": name, "category": purpose, "purpose": purpose,
                          "quantum_status": quantum_status, "component": component,
                          "criticality": criticality, "migration_time_years": migration,
                          "confidence": confidence, "data_lifetime_years": lifetime,
                          "risk_basis": "Filename-based prototype estimate; confirm with data owners",
                          "evidence": {"file": filename, "line": line_no, "excerpt": excerpt}})
    return found

def assess(assets: list[dict], horizon_years: int = 12) -> dict:
    assessed = []
    public_key_families = {"RSA", "ECC", "ECDSA"}
    for i, asset in enumerate(assets):
        alg = asset["algorithm"]
        lifetime = asset.get("data_lifetime_years", 10)
        migration = asset.get("migration_time_years", 2)
        total_window = lifetime + migration
        mosca_triggered = total_window >= horizon_years
        if asset.get("confidence", 0) < 0.6 or alg in {"TLS", "X.509"}:
            priority = "Needs review"
        elif alg == "AES":
            priority = "Needs review" if re.search(r"AES[-_/ ]?128\b", asset["evidence"]["excerpt"], re.I) else "Low"
        elif alg in public_key_families and mosca_triggered:
            priority = "Critical" if asset.get("criticality") == "High" else "High"
        elif alg in public_key_families:
            priority = "Moderate"
        else:
            priority = "Low"
        score = {"Critical": 92, "High": 76, "Moderate": 54, "Needs review": 45, "Low": 24}[priority]
        assessed.append({**asset, "id": f"AQ-{i+1:03d}", "risk_score": score,
                         "priority": priority, "threat_horizon_years": horizon_years,
                         "mosca_total_years": total_window, "mosca_triggered": mosca_triggered,
                         "harvest_now_risk": alg in public_key_families and lifetime >= horizon_years})
    priorities = {p: sum(a["priority"] == p for a in assessed) for p in ("Critical", "High", "Moderate", "Low", "Needs review")}
    algorithms = sorted({a["algorithm"] for a in assessed})
    return {"assets": assessed,
            "summary": {"total": len(assessed),
                        "quantum_vulnerable": sum(a["quantum_status"] == "quantum-vulnerable" for a in assessed),
                        "critical": priorities["Critical"],
                        "average_risk": round(sum(a["risk_score"] for a in assessed) / len(assessed)) if assessed else 0,
                        "algorithms_detected": len(algorithms), "algorithms": algorithms,
                        "priorities": priorities,
                        "mosca_triggered": sum(a["mosca_triggered"] and a["algorithm"] in public_key_families for a in assessed),
                        "threat_horizon_years": horizon_years}}

def recommendations(assets: list[dict]) -> list[dict]:
    mapping = {
        "RSA": ("ML-KEM (FIPS 203) for key establishment; review signatures separately", "Key establishment / signature", "Pilot hybrid key establishment; RSA signature use needs a signature-specific plan."),
        "ECC": ("ML-KEM (FIPS 203)", "Key establishment", "Inventory ECDH use and evaluate hybrid transitions with protocol owners."),
        "ECDSA": ("ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)", "Digital signatures", "Compare signature size, performance, certificate lifecycle and legal validity needs."),
        "AES": ("Retain approved AES; review key size", "Symmetric encryption", "Check key sizes and key rotation; AES has a different quantum impact from public-key crypto."),
        "TLS": ("Hybrid/PQC-capable TLS", "Transport security", "Check negotiated cipher suites and client/server library support; a TLS label alone is not enough."),
        "X.509": ("PQC or hybrid certificates", "Certificates and PKI", "Inspect the certificate public key and coordinate with CA, PKI and vendor owners."),
    }
    output, seen = [], set()
    for asset in assets:
        alg = asset["algorithm"]
        if alg in mapping and alg not in seen:
            seen.add(alg)
            name, purpose, action = mapping[alg]
            output.append({"detected": alg, "recommendation": name, "purpose": purpose, "action": action})
    return output

def scan_paths(paths: list[tuple[str, bytes]], horizon_years: int = 12) -> dict:
    assets = []
    for filename, content in paths:
        text = content.decode("utf-8", errors="ignore")
        if "\x00" in text[:1000]:
            continue
        assets.extend(inspect_text(text, filename))
    result = assess(assets, horizon_years)
    result["recommendations"] = recommendations(result["assets"])
    result["roadmap"] = ROADMAP
    return result

def demo_scan(horizon_years: int = 12) -> dict:
    files = [(str(p.relative_to(ROOT)), p.read_bytes()) for p in DEMO_DIR.rglob("*") if p.is_file()]
    return scan_paths(files, horizon_years)

def read_zip(upload, horizon_years: int = 12) -> dict:
    if not upload or not upload.filename.lower().endswith(".zip"):
        raise ValueError("Choose a .zip archive.")
    raw = upload.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValueError("ZIP exceeds the 10 MB limit.")
    files, total_uncompressed = [], 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as e:
        raise ValueError("The uploaded file is not a valid ZIP.") from e
    with archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError("ZIP contains more than 500 entries.")
        for entry in entries:
            if entry.is_dir():
                continue
            name = entry.filename.replace("\\", "/")
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
                raise ValueError("ZIP contains an unsafe file path.")
            if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS or entry.file_size > MAX_FILE_BYTES:
                continue
            total_uncompressed += entry.file_size
            if total_uncompressed > MAX_UPLOAD_BYTES:
                raise ValueError("ZIP expands beyond the 10 MB inspection limit.")
            files.append((name, archive.read(entry)))
    return scan_paths(files, horizon_years)

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/api/demo")
def api_demo():
    z = max(1, min(50, request.args.get("z", default=12, type=int)))
    return jsonify({"project": "MediVault synthetic demo", **demo_scan(z)})

@app.post("/api/scan")
def api_scan():
    try:
        upload = request.files.get("file")
        if not upload:
            raise ValueError("Choose a .zip archive.")
        z = max(1, min(50, request.form.get("z", default=12, type=int)))
        return jsonify({"project": upload.filename, **read_zip(upload, z)})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/simulate")
def api_simulate():
    body = request.get_json(silent=True) or {}
    x = max(0, min(40, int(body.get("x", 15))))  # years of data lifetime
    y = max(0, min(20, int(body.get("y", 4))))   # years needed to migrate
    z = max(1, min(50, int(body.get("z", 12))))  # assumed threat horizon
    total = x + y
    return jsonify({"x_lifetime": x, "y_migration": y, "z_horizon": z,
                    "classical_x_plus_y": total, "quantum_z": z,
                    "window_coverage": min(100, round(total / z * 100)),
                    "gap": max(0, z-total), "mosca_triggered": total >= z,
                    "label": "Plan migration now" if total >= z else "Window remains before threat horizon",
                    "explanation": "Mosca-style planning rule: compare data lifetime (X) plus migration time (Y) with the assumed threat horizon (Z). This is a planning scenario, not a quantum-computer arrival prediction."})

@app.post("/api/assess")
def api_assess():
    body = request.get_json(silent=True) or {}
    z = max(1, min(50, int(body.get("z", 12))))
    assets = body.get("assets", [])
    result = assess(assets, z)
    result["project"] = body.get("project", "Current scan")
    result["recommendations"] = recommendations(result["assets"])
    result["roadmap"] = ROADMAP
    return jsonify(result)

@app.post("/api/report")
def api_report():
    body = request.get_json(silent=True) or demo_scan()
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        buff = io.BytesIO(); pdf = canvas.Canvas(buff, pagesize=letter)
        pdf.setTitle("AegisQ Prototype Assessment")
        pdf.setFillColorRGB(.03, .08, .15); pdf.rect(0, 0, 612, 792, fill=1, stroke=0)
        pdf.setFillColorRGB(.25, .8, .95); pdf.setFont("Helvetica-Bold", 20); pdf.drawString(42, 750, "AEGISQ | CRYPTO ASSESSMENT")
        pdf.setFillColorRGB(.86, .93, .97); pdf.setFont("Helvetica", 8)
        summary = body.get("summary", {})
        lines = [f"Project: {body.get('project', 'MediVault synthetic demo')}",
                 f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                 "Text-reference prototype; not binary scanning, enterprise coverage, or compliance certification.",
                 f"Assets {summary.get('total',0)} | PQ-vulnerable {summary.get('quantum_vulnerable',0)} | Critical {summary.get('critical',0)} | Z={summary.get('threat_horizon_years',12)} years",
                 "", "FINDINGS: ID | ALGORITHM | PRIORITY | X lifetime + Y migration vs Z | FILE:LINE"]
        for item in body.get("assets", [])[:35]:
            ev = item.get("evidence", {})
            lines.append(f"{item.get('id')} | {item.get('algorithm')} | {item.get('priority')} | {item.get('data_lifetime_years')}+{item.get('migration_time_years')} vs {item.get('threat_horizon_years')} | {ev.get('file')}:{ev.get('line')}")
        lines += ["", "METHOD", "Mosca-style indicator compares data lifetime + migration time against the user-selected Z horizon. Scores and filename-based component assumptions are planning aids only.", "", "PQC GUIDANCE"]
        for rec in body.get("recommendations", []):
            lines.append(f"{rec['detected']} -> {rec['recommendation']} ({rec['purpose']})")
        y = 722
        for line in lines:
            if y < 38:
                pdf.showPage(); pdf.setFillColorRGB(.03, .08, .15); pdf.rect(0, 0, 612, 792, fill=1, stroke=0); pdf.setFillColorRGB(.86, .93, .97); pdf.setFont("Helvetica", 8); y = 750
            pdf.drawString(42, y, line[:125]); y -= 15
        pdf.save(); buff.seek(0)
        return send_file(buff, mimetype="application/pdf", as_attachment=True, download_name="aegisq-assessment.pdf")
    except ImportError:
        return jsonify({"error": "PDF support is missing. Install requirements.txt first."}), 503

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Upload exceeds the 10 MB limit."}), 413

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
