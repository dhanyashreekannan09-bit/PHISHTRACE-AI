from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "phishtrace.db"
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="PHISHTRACE AI", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))

URL_RE = re.compile(r'''https?://[^\s<>\'"\\]+''', re.I)
IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
URGENT_TERMS = ["urgent", "immediately", "action required", "verify now", "account suspended", "account will be closed", "final warning", "confirm your account", "click here"]
CREDENTIAL_TERMS = ["password", "login", "sign in", "verify your account", "username", "credential", "one-time password", "otp"]
FINANCIAL_TERMS = ["invoice", "payment", "refund", "bank", "credit card", "transaction", "wire transfer", "billing"]
SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "gq", "tk"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db()
    conn.execute("""CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, source_type TEXT NOT NULL,
        title TEXT NOT NULL, risk_level TEXT NOT NULL, score INTEGER NOT NULL,
        summary TEXT NOT NULL, evidence_json TEXT NOT NULL, graph_json TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()


init_db()


def clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)\\]}")


def extract_urls(text: str) -> list[str]:
    found = []
    for raw in URL_RE.findall(text or ""):
        u = clean_url(raw)
        if u not in found:
            found.append(u)
    return found[:50]


def normalize_host(host: str) -> str:
    return (host or "").lower().strip(".").split(":")[0]


def count_terms(text: str, terms: list[str]) -> list[str]:
    lower = (text or "").lower()
    return [term for term in terms if term in lower]


def analyze_url(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    host = normalize_host(parsed.netloc)
    path_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    labels = host.split(".") if host else []
    tld = labels[-1] if len(labels) >= 2 else ""
    indicators = []
    score = 0

    def add(name: str, severity: str, points: int, detail: str) -> None:
        nonlocal score
        indicators.append({"name": name, "severity": severity, "points": points, "detail": detail})
        score += points

    if parsed.scheme.lower() != "https":
        add("Non-HTTPS URL", "medium", 10, "The URL does not use HTTPS.")
    if IP_HOST_RE.match(host):
        add("IP-address host", "high", 20, "The host is an IPv4 address rather than a conventional domain.")
    if len(url) > 120:
        add("Long URL", "medium", 8, f"The URL contains {len(url)} characters.")
    if "@" in parsed.netloc:
        add("Embedded user-info", "high", 20, "The authority section contains an @ symbol, which can obscure the actual destination.")
    if len(labels) >= 5:
        add("Deep subdomain structure", "medium", 10, f"The hostname contains {len(labels)} labels.")
    if host in SHORTENER_HOSTS:
        add("URL shortener", "medium", 12, "The hostname matches a commonly used URL-shortening service.")
    if tld in SUSPICIOUS_TLDS:
        add("Unusual top-level domain", "low", 7, f"The hostname uses the .{tld} TLD.")

    keywords = count_terms(path_query, CREDENTIAL_TERMS + FINANCIAL_TERMS)
    if keywords:
        add("Sensitive-action keywords", "medium", min(15, 5 * len(set(keywords))), "The URL path/query contains terms associated with account, credential, or financial actions.")

    login_terms = count_terms(path_query, ["login", "signin", "sign-in", "verify", "verification", "account", "password", "secure", "authenticate"])
    if login_terms:
        add("Login / verification path", "medium", min(15, 5 * len(set(login_terms))), "The URL path contains terms commonly associated with account login or verification workflows: " + ", ".join(login_terms[:5]) + ".")

    hostname_terms = count_terms(host, ["login", "verify", "verification", "secure", "account", "update", "support", "security"])
    if hostname_terms:
        add("Sensitive hostname keywords", "medium", 10, "The hostname contains account/security-related terms: " + ", ".join(hostname_terms[:5]) + ".")

    if any(token in url.lower() for token in ["%40", "%2f", "%3a", "%2e", "%3f", "%26"]):
        add("URL obfuscation pattern", "medium", 8, "The URL contains encoded characters that may obscure its visible structure.")
    if "%" in url:
        add("Encoded URL characters", "low", 4, "Percent-encoded characters are present.")

    return {"url": url, "host": host, "scheme": parsed.scheme, "path": parsed.path or "/", "query": parsed.query, "indicators": indicators, "score": min(score, 100)}


def parse_eml(data: bytes) -> dict[str, Any]:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    plain_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or filename:
            attachments.append({"filename": filename or "unnamed", "content_type": part.get_content_type(), "size": len(part.get_payload(decode=True) or b"")})
            continue
        try:
            content = part.get_content()
        except Exception:
            content = ""
        if part.get_content_type() == "text/plain":
            plain_parts.append(str(content))
        elif part.get_content_type() == "text/html":
            html_parts.append(str(content))
    body = "\n".join(plain_parts) or "\n".join(html_parts)
    headers = {
        "from": str(msg.get("From", "")), "to": str(msg.get("To", "")),
        "reply_to": str(msg.get("Reply-To", "")), "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")), "message_id": str(msg.get("Message-ID", "")),
        "received": [str(x) for x in msg.get_all("Received", [])],
        "authentication_results": [str(x) for x in msg.get_all("Authentication-Results", [])],
        "return_path": str(msg.get("Return-Path", "")),
    }
    return {"headers": headers, "body": body, "urls": extract_urls(body), "attachments": attachments}


def domain_from_address(value: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+)", value or "")
    return normalize_host(match.group(1)) if match else ""


def analyze_email(parsed: dict[str, Any]) -> dict[str, Any]:
    h, body = parsed["headers"], parsed["body"]
    combined = " ".join([h.get("subject", ""), body])
    indicators, score = [], 0

    def add(name: str, severity: str, points: int, detail: str) -> None:
        nonlocal score
        indicators.append({"name": name, "severity": severity, "points": points, "detail": detail})
        score += points

    urgent = count_terms(combined, URGENT_TERMS)
    if urgent:
        add("Urgency / pressure language", "medium", min(15, 5 * len(set(urgent))), f"Detected terms such as: {', '.join(urgent[:5])}.")
    creds = count_terms(combined, CREDENTIAL_TERMS)
    if creds:
        add("Credential-related language", "high", min(15, 5 * len(set(creds))), "The message references login, password, verification, or credentials.")
    financial = count_terms(combined, FINANCIAL_TERMS)
    if financial:
        add("Financial-action language", "medium", min(10, 5 * len(set(financial))), "The message contains payment, billing, banking, or transaction language.")

    sender_domain = domain_from_address(h.get("from", ""))
    reply_domain = domain_from_address(h.get("reply_to", ""))
    if sender_domain and reply_domain and sender_domain != reply_domain:
        add("Sender / Reply-To mismatch", "high", 20, f"Sender domain is {sender_domain}, while Reply-To uses {reply_domain}.")

    auth_text = " ".join(h.get("authentication_results", [])).lower()
    failed = [x for x in ["spf=fail", "dkim=fail", "dmarc=fail", "spf=softfail", "dkim=none", "dmarc=none"] if x in auth_text]
    if failed:
        add("Email authentication anomaly", "high", min(20, 7 * len(failed)), "Authentication-Results contains: " + ", ".join(failed) + ".")
    if parsed["urls"]:
        add("Embedded URL", "medium", 8, f"The email contains {len(parsed['urls'])} URL(s).")
    if parsed["attachments"]:
        add("Attachment present", "medium", 5, f"The message contains {len(parsed['attachments'])} attachment(s).")

    return {"headers": h, "body_preview": body[:1200], "urls": parsed["urls"], "attachments": parsed["attachments"], "indicators": indicators, "score": min(score, 100)}


def risk_label(score: int) -> str:
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "MINIMAL"


def build_graph(source_type: str, email_data: dict[str, Any] | None, url_data: list[dict[str, Any]]) -> dict[str, Any]:
    nodes, edges = [], []
    if source_type == "email" and email_data:
        sender = email_data["headers"].get("from") or "Unknown sender"
        nodes.append({"id": "email", "label": "Suspicious Email", "type": "email", "detail": sender})
        previous = "email"
        for i, u in enumerate(url_data[:8]):
            nid = f"url-{i}"
            nodes.append({"id": nid, "label": "URL", "type": "url", "detail": u["host"] or u["url"]})
            edges.append({"from": previous, "to": nid, "label": "contains"})
            previous = nid
            if u["host"]:
                did = f"domain-{i}"
                nodes.append({"id": did, "label": "Domain", "type": "domain", "detail": u["host"]})
                edges.append({"from": nid, "to": did, "label": "resolves to"})
    else:
        nodes.append({"id": "input-url", "label": "Submitted URL", "type": "url", "detail": url_data[0]["url"] if url_data else "N/A"})
        if url_data:
            nodes.append({"id": "domain-0", "label": "Domain", "type": "domain", "detail": url_data[0]["host"] or "Unknown"})
            edges.append({"from": "input-url", "to": "domain-0", "label": "hosted on"})
    return {"nodes": nodes, "edges": edges}


def make_summary(score: int, indicators: list[dict[str, Any]], source_type: str) -> str:
    label = risk_label(score)
    if not indicators:
        return f"The {source_type} produced no strong heuristic indicators. Treat the result as inconclusive."
    names = ", ".join(i["name"] for i in indicators[:3])
    return f"The investigation produced a {label.lower()} heuristic risk assessment. Key observed indicators: {names}. This is an automated triage result and should be validated with additional evidence."


def save_case(source_type: str, title: str, score: int, summary: str, evidence: dict, graph: dict) -> dict:
    case_id = "PT-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:6].upper()
    created = utc_now()
    conn = db()
    conn.execute("INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (case_id, created, source_type, title, risk_label(score), int(score), summary, json.dumps(evidence), json.dumps(graph)))
    conn.commit(); conn.close()
    return {"id": case_id, "created_at": created}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/health")
async def health():
    return {"status": "ok", "application": "PHISHTRACE AI", "version": "1.0.0"}


@app.get("/api/cases")
async def cases():
    conn = db()
    rows = conn.execute("SELECT id, created_at, source_type, title, risk_level, score, summary FROM cases ORDER BY created_at DESC LIMIT 25").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    conn = db(); row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone(); conn.close()
    if not row:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    data = dict(row)
    data["evidence"] = json.loads(data.pop("evidence_json") or "{}")
    data["graph"] = json.loads(data.pop("graph_json") or "{}")
    return data


@app.post("/api/investigate/url")
async def investigate_url(url: str = Form(...)):
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        return JSONResponse({"error": "Enter a full URL beginning with http:// or https://"}, status_code=400)
    result = analyze_url(url)
    summary = make_summary(result["score"], result["indicators"], "URL")
    graph = build_graph("url", None, [result])
    case = save_case("url", result["host"] or url, result["score"], summary, {"url": result}, graph)
    return {"case": case, "source_type": "url", "risk_level": risk_label(result["score"]), "score": result["score"], "summary": summary, "indicators": result["indicators"], "urls": [result], "graph": graph}


@app.post("/api/investigate/email")
async def investigate_email(file: UploadFile = File(...)):
    filename = file.filename or ""
    if not filename.lower().endswith(".eml"):
        return JSONResponse({"error": "For this version, upload an .eml email file."}, status_code=400)
    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        return JSONResponse({"error": "File is larger than the 5 MB demo limit."}, status_code=400)
    try:
        parsed = parse_eml(raw)
        email_result = analyze_email(parsed)
    except Exception as exc:
        return JSONResponse({"error": f"Could not parse the email file: {exc}"}, status_code=400)
    url_results = [analyze_url(u) for u in email_result["urls"]]
    all_indicators = list(email_result["indicators"])
    for ur in url_results: all_indicators.extend(ur["indicators"])
    total = min(100, email_result["score"] + min(35, sum(u["score"] for u in url_results)))
    summary = make_summary(total, all_indicators, "email")
    graph = build_graph("email", parsed, url_results)
    title = email_result["headers"].get("subject") or filename
    case = save_case("email", title, total, summary, {"email": email_result, "urls": url_results}, graph)
    return {"case": case, "source_type": "email", "risk_level": risk_label(total), "score": total, "summary": summary, "indicators": all_indicators, "email": email_result, "urls": url_results, "graph": graph}


def wrap_text(text: str, width: int = 95) -> list[str]:
    words = (text or "").split(); lines = []; current = ""
    for word in words:
        candidate = (current + " " + word).strip()
        if len(candidate) <= width: current = candidate
        else:
            if current: lines.append(current)
            current = word
    if current: lines.append(current)
    return lines


def evidence_indicators(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    # IMPORTANT: the original DB has no indicators_json column.
    # Indicators are stored inside evidence_json.
    result = []
    email = evidence.get("email")
    if isinstance(email, dict):
        result.extend(x for x in email.get("indicators", []) if isinstance(x, dict))
    url = evidence.get("url")
    if isinstance(url, dict):
        result.extend(x for x in url.get("indicators", []) if isinstance(x, dict))
    for item in evidence.get("urls", []):
        if isinstance(item, dict):
            result.extend(x for x in item.get("indicators", []) if isinstance(x, dict))
    return result


def recommendations() -> list[str]:
    return [
        "Do not enter credentials into suspicious pages.",
        "Do not execute or open unknown attachments.",
        "Validate suspicious domains through trusted channels.",
        "If credentials were submitted, change them through the legitimate service.",
        "Preserve the original email and headers for further investigation.",
    ]


def create_report(case_id: str, data: dict[str, Any], evidence: dict[str, Any], graph: dict[str, Any], path: Path) -> None:
    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    DARK = colors.HexColor("#08111B"); CYAN = colors.HexColor("#4DE1FF")
    RED = colors.HexColor("#FF5C7A"); YELLOW = colors.HexColor("#FFD166")
    GREEN = colors.HexColor("#45E0A8"); TEXT = colors.HexColor("#E8F0F7")
    MUTED = colors.HexColor("#8EA3B5"); BORDER = colors.HexColor("#243442")
    PANEL = colors.HexColor("#0D1823")

    def background():
        c.setFillColor(DARK); c.rect(0, 0, width, height, fill=1, stroke=0)
        c.setFillColor(CYAN); c.rect(0, height - 6, width, 6, fill=1, stroke=0)

    def header(subtitle: str | None = None):
        background(); c.setFillColor(TEXT); c.setFont("Helvetica-Bold", 22); c.drawString(45, height - 60, "PHISHTRACE AI")
        if subtitle:
            c.setFillColor(MUTED); c.setFont("Helvetica", 9); c.drawString(45, height - 78, subtitle)

    def footer():
        c.setFillColor(MUTED); c.setFont("Helvetica", 7)
        c.drawString(45, 25, "PHISHTRACE AI — DIGITAL FORENSIC INVESTIGATION")
        c.drawRightString(width - 45, 25, f"CASE {case_id}")

    def page() -> float:
        footer(); c.showPage(); header(f"CASE {case_id}"); return height - 100

    def section(title: str, y: float) -> float:
        if y < 80: y = page()
        c.setFillColor(CYAN); c.setFont("Helvetica-Bold", 11); c.drawString(45, y, title)
        c.setStrokeColor(BORDER); c.line(45, y - 6, width - 45, y - 6)
        return y - 25

    def box(x: float, y: float, w: float, h: float):
        c.setFillColor(PANEL); c.setStrokeColor(BORDER); c.roundRect(x, y, w, h, 8, fill=1, stroke=1)

    def text(text: Any, y: float, size=9, color=TEXT, x=50, chars=95, gap=13) -> float:
        c.setFont("Helvetica", size); c.setFillColor(color)
        for line in wrap_text(str(text), chars):
            if y < 55: y = page()
            c.drawString(x, y, line); y -= gap
        return y

    header("AI-POWERED PHISHING INVESTIGATION & DIGITAL FORENSICS")
    c.setFillColor(TEXT); c.setFont("Helvetica-Bold", 15); c.drawString(45, height - 135, "DIGITAL INVESTIGATION REPORT")
    box(45, height - 285, width - 90, 105)
    c.setFont("Helvetica-Bold", 9); c.setFillColor(CYAN)
    for x, y, label in [(60, -205, "CASE ID"), (60, -235, "CREATED"), (300, -205, "SOURCE"), (300, -235, "RISK LEVEL")]: c.drawString(x, height + y, label)
    c.setFont("Helvetica", 10); c.setFillColor(TEXT)
    c.drawString(60, height - 220, case_id); c.drawString(60, height - 250, str(data.get("created_at", "")))
    c.drawString(300, height - 220, str(data.get("source_type", "")).upper()); c.drawString(300, height - 250, str(data.get("risk_level", "")).upper())
    score = int(data.get("score") or 0); risk_color = RED if score >= 70 else YELLOW if score >= 40 else GREEN
    c.setFillColor(risk_color); c.setFont("Helvetica-Bold", 26); c.drawString(45, height - 330, f"{score}/100")
    c.setFont("Helvetica", 9); c.setFillColor(MUTED); c.drawString(45, height - 348, "RISK SCORE")

    y = section("EXECUTIVE SUMMARY", height - 395)
    summary_lines = wrap_text(data.get("summary") or "No summary available.", 92)
    h = max(65, 25 + len(summary_lines) * 13); box(45, y - h + 10, width - 90, h)
    ty = y - 22
    for line in summary_lines:
        c.setFont("Helvetica", 9); c.setFillColor(TEXT); c.drawString(55, ty, line); ty -= 13
    y -= h + 30

    indicators = evidence_indicators(evidence)
    y = section("EVIDENCE & INDICATORS", y)
    if not indicators: y = text("No suspicious indicators were detected.", y, color=MUTED)
    for item in indicators:
        if y < 105: y = section("EVIDENCE & INDICATORS", page())
        name = str(item.get("name", "Indicator")); severity = str(item.get("severity", "unknown")).upper(); points = item.get("points", 0)
        details = wrap_text(str(item.get("detail", "")), 86); h = max(55, 34 + len(details) * 12)
        box(45, y - h + 8, width - 90, h)
        c.setFont("Helvetica-Bold", 9); c.setFillColor(TEXT); c.drawString(55, y - 15, name)
        c.setFillColor(YELLOW); c.setFont("Helvetica-Bold", 8); c.drawRightString(width - 55, y - 15, f"{severity}  +{points}")
        dy = y - 31; c.setFont("Helvetica", 8); c.setFillColor(MUTED)
        for d in details: c.drawString(55, dy, d); dy -= 12
        y -= h + 12

    y = section("DIGITAL CRIME SCENE", y - 10)
    nodes = graph.get("nodes", [])
    if not nodes: y = text("No graph entities were recorded.", y, color=MUTED)
    for i, node in enumerate(nodes):
        if y < 110: y = section("DIGITAL CRIME SCENE", page())
        box(55, y - 42, width - 110, 32); c.setFont("Helvetica-Bold", 9); c.setFillColor(CYAN); c.drawString(65, y - 22, str(node.get("label", "ENTITY")).upper())
        detail = str(node.get("detail", "")); detail = detail[:77] + "..." if len(detail) > 80 else detail
        c.setFont("Helvetica", 8); c.setFillColor(TEXT); c.drawString(170, y - 22, detail); y -= 52
        if i < len(nodes) - 1: c.setFillColor(MUTED); c.setFont("Helvetica", 12); c.drawCentredString(width / 2, y + 8, "↓")

    y = section("INVESTIGATION TIMELINE", y - 10)
    timeline = ["CASE CREATED", "EMAIL / URL EVIDENCE PARSED", "URLS AND DOMAINS EXTRACTED", "HEURISTIC INDICATORS ANALYZED", "RISK ASSESSMENT CALCULATED", "INVESTIGATION REPORT GENERATED"]
    for n, step in enumerate(timeline, 1):
        if y < 75: y = section("INVESTIGATION TIMELINE", page())
        c.setFillColor(CYAN); c.circle(60, y, 5, fill=1, stroke=0); c.setFont("Helvetica-Bold", 9); c.setFillColor(TEXT); c.drawString(78, y - 3, f"{n:02d}  {step}"); y -= 25

    y = section("RECOMMENDATIONS", y - 10)
    for rec in recommendations():
        if y < 75: y = section("RECOMMENDATIONS", page())
        c.setFillColor(CYAN); c.circle(55, y + 2, 3, fill=1, stroke=0); y = text(rec, y, x=65, chars=90); y -= 4

    y = section("DISCLAIMER", y - 10)
    text("This report is an automated analytical assessment. Indicators are heuristic and should be validated by a qualified security analyst before taking incident-response action.", y, 8, MUTED)
    footer(); c.save()


@app.get("/api/cases/{case_id}/report")
async def report(case_id: str):
    conn = db(); row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone(); conn.close()
    if not row: return JSONResponse({"error": "Case not found"}, status_code=404)
    data = dict(row)
    try: evidence = json.loads(data.get("evidence_json") or "{}")
    except (TypeError, json.JSONDecodeError): evidence = {}
    try: graph = json.loads(data.get("graph_json") or "{}")
    except (TypeError, json.JSONDecodeError): graph = {}
    safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", case_id)
    path = REPORT_DIR / f"{safe_name}.pdf"
    try:
        create_report(case_id, data, evidence, graph, path)
    except Exception as exc:
        return JSONResponse({"error": f"PDF generation failed: {type(exc).__name__}: {exc}"}, status_code=500)
    return FileResponse(path, media_type="application/pdf", filename=path.name)
