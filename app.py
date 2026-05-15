#!/usr/bin/env python3
"""
app.py  — NC AAMVA Forensic Tool v4.0  |  FastAPI backend
==========================================================
Endpoints:
  POST /api/analyse/text   — raw barcode string (JSON body)
  POST /api/analyse/image  — image file upload (multipart)
  GET  /                   — web UI
  GET  /api/health         — health check
"""
from __future__ import annotations

import io
import os
import sys
import json
import tempfile
import traceback
from pathlib import Path

# ── auto-install deps ──────────────────────────────────────────────────────────
import subprocess

def _install(pkg):
    subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"], check=False)

for dep in ["fastapi", "uvicorn[standard]", "python-multipart", "Pillow"]:
    try:
        __import__(dep.split("[")[0].replace("-","_"))
    except ImportError:
        _install(dep)

from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent))
from nc_aamva_engine import analyse, decode_image, FIELD_LABELS

# ── app setup ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="NC AAMVA Forensic Tool v4",
    description="Production-grade NC driver license barcode authentication",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

STATIC = Path(__file__).parent / "static"
STATIC.mkdir(exist_ok=True)

# ── request / response models ─────────────────────────────────────────────────
class TextRequest(BaseModel):
    barcode: str
    label:   str = "manual_input"

# ── helper ────────────────────────────────────────────────────────────────────
def _serialise(report) -> dict:
    d = report.to_dict()
    d["signals"] = [
        {
            "signal":       s["signal"],
            "passed":       s["passed"],
            "weight":       s["weight"],
            "is_hard_fail": s["is_hard_fail"],
            "detail":       s["detail"],
        }
        for s in d["signals"]
    ]
    return d

# ── routes ────────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "4.0.0"}

@app.post("/api/analyse/text")
async def analyse_text(req: TextRequest):
    """Analyse a raw barcode string (copy-paste or from decoder output)."""
    if not req.barcode or len(req.barcode) < 10:
        raise HTTPException(400, "Barcode string too short")
    try:
        report = analyse(req.barcode)
        return JSONResponse(_serialise(report))
    except Exception:
        raise HTTPException(500, traceback.format_exc())

@app.post("/api/analyse/image")
async def analyse_image(file: UploadFile = File(...)):
    """Upload a barcode image; decode and analyse."""
    suffix = Path(file.filename or "upload.jpg").suffix or ".jpg"
    data   = await file.read()
    if not data:
        raise HTTPException(400, "Empty file")
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        raw = decode_image(tmp_path)
        if not raw:
            return JSONResponse({"error": "No PDF417 barcode found in image", "verdict": "ERROR"})
        report = analyse(raw)
        result = _serialise(report)
        result["filename"] = file.filename
        return JSONResponse(result)
    except Exception:
        raise HTTPException(500, traceback.format_exc())
    finally:
        try: os.unlink(tmp_path)
        except: pass

@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = Path(__file__).parent / "templates" / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Template not found</h1>", status_code=500)

# ── run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"\n🔍  NC AAMVA Forensic Tool v4.0  —  http://localhost:{port}")
    print("    POST /api/analyse/text  |  POST /api/analyse/image  |  GET /")
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
