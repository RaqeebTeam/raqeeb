"""FastAPI backend.  Run:  uvicorn app:app --reload   then open http://127.0.0.1:8000"""
import json
import time
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from predict import check_url

app = FastAPI(title="Raqeeb")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
REPORTS = Path("data/reports.jsonl")
CHECKS = Path("data/checks.jsonl")


class Report(BaseModel):
    url: str
    comment: str = ""


@app.get("/api/check")
def check(url: str = Query(..., min_length=3, max_length=2000), deep: bool = False):
    result = check_url(url, deep=deep)
    try:
        with CHECKS.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"url": url[:200], "label": result["label"], "color": result["color"],
                                "score": result["score"], "ts": time.time()}) + "\n")
    except OSError:
        pass
    return result


@app.post("/api/reset")
def reset():
    for f in (CHECKS, REPORTS):
        try:
            f.unlink(missing_ok=True)
        except OSError:
            f.write_text("", encoding="utf-8")
    return {"ok": True}


@app.get("/api/stats")
def stats():
    rows = []
    if CHECKS.exists():
        rows = [json.loads(l) for l in CHECKS.open(encoding="utf-8") if l.strip()]
    count = lambda lab: sum(1 for r in rows if r["label"] == lab)
    n_reports = sum(1 for _ in REPORTS.open(encoding="utf-8")) if REPORTS.exists() else 0
    return {"scanned": len(rows), "dangerous": count("Dangerous"), "suspicious": count("Suspicious"),
            "safe": count("Safe"), "reports": n_reports, "recent": rows[-8:][::-1]}


@app.post("/api/report")
def report(r: Report):
    with REPORTS.open("a") as f:
        f.write(json.dumps({"url": r.url[:2000], "comment": r.comment[:500], "ts": time.time()}) + "\n")
    return {"ok": True, "total_reports": sum(1 for _ in REPORTS.open())}


@app.get("/api/reports")
def reports():
    if not REPORTS.exists():
        return []
    return [json.loads(l) for l in REPORTS.open()][-50:]


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def home():
    return FileResponse("static/index.html")
